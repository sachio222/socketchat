//! Drawing. Four areas: chats on the left, messages in the middle, people
//! on the right, and a framed message box across the bottom with a help line
//! under it. Readable at 80 by 24.

use crossterm::event::KeyCode;
use ratatui::buffer::CellWidth;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;
use socketchat_core::client::Ended;
use socketchat_core::invite::hours_text;
use socketchat_core::keys::Key;
use socketchat_proto::msg::GroupId;
use unicode_segmentation::UnicodeSegmentation;

use crate::app::{about_lines, ended_hint, version_text, App, Focus, Hits, Modal};
use crate::commands::HELP;
use crate::theme::Theme;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupView {
    pub id: GroupId,
    pub name: String,
    pub unread: u32,
    pub is_dm: bool,
    /// Muted on this computer: no count, and the name is dim.
    pub muted: bool,
    /// Why this person is no longer in the room; `None` while they are.
    pub ended: Option<Ended>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineView {
    pub time: String,
    pub sender: String,
    pub text: String,
    pub notice: bool,
    pub mine: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberLine {
    pub key: Key,
    pub name: String,
    pub verified: bool,
    pub admin: bool,
    pub me: bool,
}

/// Everything the screen shows, gathered from the client before each draw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewModel {
    pub me: String,
    pub groups: Vec<GroupView>,
    pub lines: Vec<LineView>,
    pub members: Vec<MemberLine>,
    pub connected: bool,
    /// The open room's server, from `server_text`.
    pub server: Option<String>,
}

const SIDE: u16 = 20;

/// Cuts `s` to `w` characters, ending in an ellipsis when it was longer.
pub fn fit(s: &str, w: usize) -> String {
    let n = s.chars().count();
    if n <= w {
        s.to_string()
    } else if w == 0 {
        String::new()
    } else {
        // "Book…", not "Book …".
        let head: String = s.chars().take(w - 1).collect();
        format!("{}…", head.trim_end())
    }
}

#[cfg(test)]
thread_local! {
    /// Characters `wrap` has stepped over on this thread.
    static WRAP_STEPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Counts characters `wrap` steps over, for tests.
fn steps(n: usize) {
    #[cfg(test)]
    WRAP_STEPS.with(|c| c.set(c.get() + n));
    let _ = n;
}

/// Greedy word wrap by characters, in time that grows with the length of
/// `text`: a word longer than a row is cut into rows by slicing, never by
/// rebuilding the rest of the word.
fn wrap(text: &str, w: usize) -> Vec<String> {
    let w = w.max(1);
    let mut out = vec![];
    for para in text.split('\n') {
        let mut line = String::new();
        // Characters in `line`.
        let mut used = 0;
        for mut word in para.split(' ') {
            let mut n = word.chars().count();
            steps(n);
            while n > w {
                if used > 0 {
                    out.push(std::mem::take(&mut line));
                    used = 0;
                }
                let cut = word.char_indices().nth(w).map_or(word.len(), |(i, _)| i);
                steps(w);
                out.push(word[..cut].to_string());
                word = &word[cut..];
                n -= w;
            }
            if used > 0 && used + 1 + n > w {
                out.push(std::mem::take(&mut line));
                used = 0;
            }
            if used > 0 {
                line.push(' ');
                used += 1;
            }
            line.push_str(word);
            used += n;
        }
        out.push(line);
    }
    out
}

fn border(t: &Theme, focused: bool) -> Style {
    if focused {
        t.border_focus
    } else {
        t.border
    }
}

/// Wipes `r` for a box that sits over the screen, keeping the theme's
/// background under it.
fn clear(f: &mut Frame, r: Rect, t: &Theme) {
    f.render_widget(Clear, r);
    f.render_widget(Block::default().style(t.base), r);
}

fn help_line(app: &App, width: usize) -> &'static str {
    if let Some(m) = &app.modal {
        return match m {
            Modal::Verify { .. } => "Y they match · Esc close",
            Modal::ConfirmVideo { .. } => "Y send it · N cancel",
            Modal::ConfirmPhoto { .. } => "Y send it · N cancel",
            Modal::NewCertificate { .. } => "Y trust the new certificate · N keep the old one",
            Modal::Invite { .. } => "C copy an invite message · Esc close",
            Modal::Confirm { .. } => "Y yes · N no",
            Modal::Invites { .. } => "/cancel <number> stops a link · Esc close",
            Modal::Servers { .. } => "/forget <number> forgets a server · Esc close",
            Modal::Help { .. } => "Up/Down scroll · Esc close",
            _ => "Esc close",
        };
    }
    if app.switcher.is_some() {
        return "Type to filter · Enter open · Esc cancel";
    }
    // Tab completes only while a command is being typed, and the line says
    // so only when it fits.
    const COMPLETING: &str = "Enter run · Tab completes a command · /help lists them · Ctrl-C quit";
    if app.focus == Focus::Input
        && app.input.starts_with('/')
        && COMPLETING.chars().count() <= width
    {
        return COMPLETING;
    }
    match app.focus {
        Focus::Input => "Enter send · /help commands · Tab move · Ctrl-K switch chat · Ctrl-C quit",
        Focus::Groups => "Up/Down pick a chat · Tab move · Ctrl-K switch chat · Ctrl-C quit",
        Focus::Messages => "PgUp/PgDn or Up/Down scroll · Tab move · Ctrl-C quit",
        Focus::Members => "✓ verified · * admin · /verify <name> · Tab move",
    }
}

pub fn draw(f: &mut Frame, app: &App, vm: &ViewModel) {
    let area = f.area();
    let t = &app.theme;
    // The theme's background goes under everything, so the look does not
    // depend on the terminal's own.
    f.render_widget(Block::default().style(t.base), area);
    let input = input_lines(app, vm, area.width.saturating_sub(2) as usize);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(input.len() as u16 + 2),
            Constraint::Length(1),
        ])
        .split(area);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(SIDE),
            Constraint::Min(20),
            Constraint::Length(SIDE),
        ])
        .split(rows[0]);
    *app.hits.borrow_mut() = Hits {
        groups: cols[0],
        messages: cols[1],
        members: cols[2],
        input: rows[1],
        ..Hits::default()
    };

    draw_groups(f, app, vm, cols[0]);
    draw_messages(f, app, vm, cols[1]);
    draw_members(f, app, vm, cols[2]);

    draw_input(f, app, input, rows[1]);
    // A status message replaces the help line until the next key, so it is
    // seen without covering what the person types.
    let width = area.width as usize;
    let (text, style): (String, _) = match (&app.status, &app.hint) {
        (Some(st), _) => (st.clone(), t.warn),
        // Matching commands, as many as fit.
        (None, Some(cmds)) => {
            let mut s = String::new();
            for c in cmds {
                let add = if s.is_empty() { 0 } else { 2 } + c.chars().count();
                if s.chars().count() + add > width {
                    break;
                }
                if !s.is_empty() {
                    s.push_str("  ");
                }
                s.push_str(c);
            }
            (s, t.dim)
        }
        (None, None) => (help_line(app, width).to_string(), t.dim),
    };
    let text = text.as_str();
    let mut help = vec![Span::styled(fit(text, width), style)];
    // The version sits at the right edge when the help text keeps all of
    // its room beside it; a narrow window drops the version first.
    let version = version_text();
    let used = text.chars().count();
    if used + 2 + version.chars().count() <= width {
        let gap = width - used - version.chars().count();
        help.push(Span::raw(" ".repeat(gap)));
        help.push(Span::styled(version, t.dim));
    }
    f.render_widget(Paragraph::new(Line::from(help)), rows[2]);

    if app.switcher.is_some() {
        draw_switcher(f, app, vm, area);
    }
    if let Some(m) = &app.modal {
        draw_modal(f, app, m, area);
    }
}

/// Shown in the empty message box.
const COMMANDS_HINT: &str = "/ for commands";

/// The rows inside the message box, `w` characters wide: a hint naming
/// the open chat while it is empty, and what the person types once they
/// start. The hint for a room this person is no longer in wraps onto
/// more rows rather than being cut short.
fn input_lines(app: &App, vm: &ViewModel, w: usize) -> Vec<Line<'static>> {
    // Typed text and the hint both start after the "› " prompt's width.
    let start = 2.min(w);
    if !app.input.is_empty() {
        let room = w.saturating_sub(start + 1);
        let shown = shown_input(&app.input, room);
        let mut spans = vec![Span::raw("› "), Span::raw(shown)];
        // The grey suggestion, as much as fits after the typed text,
        // measured in the columns ratatui draws.
        if let Some(g) = app.ghost(vm) {
            let mut left = room.saturating_sub(input_columns(&app.input));
            let fits: String = drawn_clusters(&g)
                .into_iter()
                .take_while(|(_, w)| {
                    let ok = *w <= left;
                    left = left.saturating_sub(*w);
                    ok
                })
                .map(|(c, _)| c)
                .collect();
            if !fits.is_empty() {
                spans.push(Span::styled(fits, app.theme.dim));
            }
        }
        return vec![Line::from(spans)];
    }
    let (dim, room) = (app.theme.dim, app.theme.room);
    let avail = w - start;
    let open = vm.groups.iter().find(|g| Some(g.id) == app.selected);
    let mut rows: Vec<Vec<Span<'static>>> = match open {
        Some(GroupView {
            ended: Some(why), ..
        }) => wrap(ended_hint(*why), avail)
            .into_iter()
            .map(|l| vec![Span::styled(l, dim)])
            .collect(),
        Some(g) if g.is_dm => {
            let before = "Say hi to ";
            vec![vec![
                Span::styled(before, dim),
                Span::styled(fit(&g.name, avail.saturating_sub(before.len())), room),
            ]]
        }
        Some(g) => {
            let (before, tag) = ("What's on your mind? ", "#");
            vec![vec![
                Span::styled(before, dim),
                Span::styled(
                    format!(
                        "{tag}{}",
                        fit(&g.name, avail.saturating_sub(before.len() + tag.len()))
                    ),
                    room,
                ),
            ]]
        }
        None => vec![vec![Span::styled(
            fit(
                "Start a chat with /new <name>, or paste an invite with /join <link>",
                avail,
            ),
            dim,
        )]],
    };
    // "/ for commands" sits at the right end of the last row, if it fits.
    if let Some(last) = rows.last_mut() {
        let used: usize = last.iter().map(|s| s.content.chars().count()).sum();
        let cmd = COMMANDS_HINT.chars().count();
        if used + 2 + cmd <= avail {
            last.push(Span::raw(" ".repeat(avail - used - cmd)));
            last.push(Span::styled(COMMANDS_HINT, dim));
        }
    }
    rows.into_iter()
        .map(|mut spans| {
            spans.insert(0, Span::raw(" ".repeat(start)));
            Line::from(spans)
        })
        .collect()
}

/// `input` as the message box holds it: a pasted line break shows as ↵.
fn box_text(input: &str) -> String {
    input
        .chars()
        .map(|c| if c == '\n' { '↵' } else { c })
        .collect()
}

/// The clusters ratatui draws `text` as, each with the columns it takes.
/// This is the rule `Paragraph` follows: split into extended grapheme
/// clusters, draw nothing for a cluster holding a control character, and
/// size the rest with ratatui's own `CellWidth::cell_width`.
fn drawn_clusters(text: &str) -> Vec<(&str, usize)> {
    text.graphemes(true)
        .map(|g| {
            let shown = !g.contains(char::is_control);
            (
                g,
                if shown {
                    usize::from(g.cell_width())
                } else {
                    0
                },
            )
        })
        .collect()
}

/// What the message box shows of `input` in `room` columns. Text shows its
/// end; a command too long for the box shows its start, an ellipsis, and
/// its end. It is measured and cut in whole clusters at the widths ratatui
/// draws them, so no emoji, flag or accent pushes a command's end past the
/// edge or breaks in two.
fn shown_input(input: &str, room: usize) -> String {
    let text = box_text(input);
    let all = drawn_clusters(&text);
    let total: usize = all.iter().map(|(_, w)| w).sum();
    // As many clusters from the front, or from the back, as fit `cols`.
    let fit = |from_back: bool, cols: usize| {
        let mut used = 0;
        let fits = |(_, w): &&(&str, usize)| {
            used += w;
            used <= cols
        };
        if from_back {
            all.iter().rev().take_while(fits).count()
        } else {
            all.iter().take_while(fits).count()
        }
    };
    let join = |part: &[(&str, usize)]| part.iter().map(|(g, _)| *g).collect::<String>();
    if total <= room {
        text
    } else if input.starts_with('/') && room > 2 {
        let tail = (room - 1) / 2;
        let (mut head, mut tail) = (fit(false, room - 1 - tail), fit(true, tail));
        // A cluster that would join the ellipsis into one cluster, such as
        // a prepended mark before it or a lone accent after it, goes into
        // the hidden middle, so ratatui draws the clusters measured here.
        let joins = |a: &str, b: &str| format!("{a}{b}").graphemes(true).nth(1).is_none();
        while head > 0 && joins(all[head - 1].0, "…") {
            head -= 1;
        }
        while tail > 0 && joins("…", all[all.len() - tail].0) {
            tail -= 1;
        }
        format!("{}…{}", join(&all[..head]), join(&all[all.len() - tail..]))
    } else {
        join(&all[all.len() - fit(true, room)..])
    }
}

/// The columns `input` takes in the message box, as ratatui draws it.
fn input_columns(input: &str) -> usize {
    drawn_clusters(&box_text(input))
        .iter()
        .map(|(_, w)| w)
        .sum()
}

/// The framed message box, holding `lines` from [`input_lines`].
fn draw_input(f: &mut Frame, app: &App, lines: Vec<Line<'static>>, r: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border(&app.theme, app.focus == Focus::Input));
    let inner = block.inner(r);
    f.render_widget(block, r);
    let w = inner.width as usize;
    let start = 2.min(w);
    f.render_widget(Paragraph::new(lines), inner);
    if app.modal.is_none() && app.switcher.is_none() {
        // While empty, the cursor waits in the gap before the hint so it
        // never hides a letter; once typing starts it follows the text.
        let x = if app.input.is_empty() {
            start.saturating_sub(1)
        } else {
            start + input_columns(&app.input).min(w.saturating_sub(start + 1))
        };
        f.set_cursor_position((inner.x + x as u16, inner.y));
    }
}

fn draw_groups(f: &mut Frame, app: &App, vm: &ViewModel, r: Rect) {
    let t = &app.theme;
    let w = r.width.saturating_sub(2) as usize;
    let lines: Vec<Line> = vm
        .groups
        .iter()
        .map(|g| {
            let mark = if g.is_dm { "@" } else { "#" };
            // A muted room shows no count.
            let count = if g.unread > 0 && !g.muted {
                format!(" {}", g.unread.min(99))
            } else {
                String::new()
            };
            let ended = match g.ended {
                Some(Ended::Closed) => " (closed)",
                Some(Ended::Left) => " (left)",
                Some(Ended::Removed) => " (removed)",
                None => "",
            };
            let (count_w, ended_w) = (count.chars().count(), ended.chars().count());
            let name = fit(&g.name, w.saturating_sub(2 + ended_w + count_w));
            let pad = w.saturating_sub(2 + name.chars().count() + ended_w + count_w);
            let selected = Some(g.id) == app.selected;
            let style = if selected {
                t.selected
            } else if g.muted {
                t.dim
            } else if !count.is_empty() {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let ended_style = if selected { style } else { style.patch(t.dim) };
            Line::from(vec![
                Span::styled(format!("{mark} {name}"), style),
                Span::styled(ended, ended_style),
                Span::styled(format!("{}{count}", " ".repeat(pad)), style),
            ])
        })
        .collect();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border(t, app.focus == Focus::Groups))
        .title_style(t.title)
        .title(" Chats ");
    f.render_widget(Paragraph::new(lines).block(block), r);
}

fn draw_messages(f: &mut Frame, app: &App, vm: &ViewModel, r: Rect) {
    let t = &app.theme;
    let offline = if vm.connected { "" } else { "· offline " };
    let title = match vm.groups.iter().find(|g| Some(g.id) == app.selected) {
        Some(g) => {
            let name = fit(&g.name, r.width.saturating_sub(14) as usize);
            // The server goes first when the window is too narrow for it.
            let with = vm.server.as_ref().map(|s| format!(" {name} · {s} "));
            let room = r.width.saturating_sub(2) as usize;
            match with.filter(|w| w.chars().count() + offline.chars().count() <= room) {
                Some(w) => w,
                None => format!(" {name} "),
            }
        }
        None => " Socketchat ".into(),
    };
    let title = format!("{title}{offline}");
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border(t, app.focus == Focus::Messages))
        .title_style(t.title)
        .title(title);
    let inner = block.inner(r);
    f.render_widget(block, r);
    let w = inner.width as usize;
    let mut rows: Vec<Line> = vec![];
    if let Some(warn) = &app.warning {
        for l in wrap(warn, w) {
            rows.push(Line::from(Span::styled(l, t.banner)));
        }
    }
    if vm.groups.is_empty() {
        for t in [
            format!("Welcome, {}.", vm.me),
            String::new(),
            "No chats yet.".into(),
            "Start one with /new <name>,".into(),
            "or paste an invite with /join <link>.".into(),
        ] {
            rows.push(Line::from(t));
        }
        f.render_widget(Paragraph::new(rows), inner);
        return;
    }
    // Only the newest messages that fill the window at this scroll get
    // wrapped, however many are loaded.
    let need = (inner.height as usize).saturating_sub(rows.len()) + app.scroll as usize;
    let mut body: Vec<Line> = vec![];
    for l in &vm.lines[first_shown(&vm.lines, w, need)..] {
        let head = message_head(l);
        let style = if l.notice { t.notice } else { Style::default() };
        let pieces = message_rows(&head, l, w);
        for (i, piece) in pieces.into_iter().enumerate() {
            if i == 0 && !l.notice {
                let split = head.chars().count().min(piece.chars().count());
                // The time, then the name, then the text.
                let time_end = (l.time.chars().count() + 1).min(split);
                let part = |from: usize, to: usize| -> String {
                    piece.chars().skip(from).take(to - from).collect()
                };
                let (time_style, name_style) = if l.mine {
                    (t.time_mine, t.name_mine)
                } else {
                    (t.time_other, t.name_other)
                };
                body.push(Line::from(vec![
                    Span::styled(part(0, time_end), time_style),
                    Span::styled(part(time_end, split), name_style),
                    Span::raw(piece.chars().skip(split).collect::<String>()),
                ]));
            } else {
                body.push(Line::from(Span::styled(piece, style)));
            }
        }
    }
    let room = (inner.height as usize).saturating_sub(rows.len());
    let end = body.len().saturating_sub(app.scroll as usize);
    let start = end.saturating_sub(room);
    rows.extend(body[start..end].iter().cloned());
    f.render_widget(Paragraph::new(rows), inner);
}

/// The start of a message's first row: the time, then the sender's name,
/// or a dot for the app's own notices. [`draw_messages`] writes the same.
fn message_head(l: &LineView) -> String {
    if l.notice {
        format!("{} · ", l.time)
    } else {
        format!("{} {}: ", l.time, fit(&l.sender, 16))
    }
}

/// The rows a message takes at `w` characters wide, its first row
/// starting with `head`.
fn message_rows(head: &str, l: &LineView, w: usize) -> Vec<String> {
    let full = format!("{head}{}", l.text);
    // Continuation lines sit under the text, clear of the time and the
    // space after it.
    let indent = l.time.chars().count() + 1;
    let first = wrap(&full, w);
    match first.split_first() {
        Some((head_line, _)) if w > indent * 2 => {
            let used = head_line.chars().count();
            let rest: String = full.chars().skip(used).collect();
            let mut v = vec![head_line.clone()];
            for p in wrap(rest.trim_start(), w - indent) {
                if !p.is_empty() {
                    v.push(format!("{}{p}", " ".repeat(indent)));
                }
            }
            v
        }
        _ => first,
    }
}

/// The oldest of `lines` a draw needs: walking back from the newest, the
/// first message by which the rows reach `need`, the window's height plus
/// how far it is scrolled up. Older messages cannot reach the screen.
fn first_shown(lines: &[LineView], w: usize, need: usize) -> usize {
    let mut rows = 0;
    for (i, l) in lines.iter().enumerate().rev() {
        rows += message_rows(&message_head(l), l, w).len();
        if rows >= need {
            return i;
        }
    }
    0
}

fn draw_members(f: &mut Frame, app: &App, vm: &ViewModel, r: Rect) {
    let t = &app.theme;
    let w = r.width.saturating_sub(2) as usize;
    let lines: Vec<Line> = vm
        .members
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let v = if m.verified { "✓" } else { " " };
            let star = if m.admin { "*" } else { "" };
            let you = if m.me { " (you)" } else { "" };
            let name = fit(&m.name, w.saturating_sub(2 + star.len() + you.len()));
            let (mut mark, mut style) = if m.verified {
                (t.check, Style::default())
            } else {
                (t.warn, t.warn)
            };
            if app.focus == Focus::Members && i == app.member_cursor {
                mark = mark.patch(t.selected);
                style = style.patch(t.selected);
            }
            Line::from(vec![
                Span::styled(format!("{v} "), mark),
                Span::styled(format!("{name}{star}{you}"), style),
            ])
        })
        .collect();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border(t, app.focus == Focus::Members))
        .title_style(t.title)
        .title(" People ");
    f.render_widget(Paragraph::new(lines).block(block), r);
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

fn draw_switcher(f: &mut Frame, app: &App, vm: &ViewModel, area: Rect) {
    let r = centered(area, 40, 12);
    let mut lines = vec![Line::from(format!(
        "> {}",
        app.switcher.as_deref().unwrap_or("")
    ))];
    // The room Enter would open stands out.
    let pick = app.switcher_pick(vm);
    for g in app.switcher_matches(vm).iter().take(8) {
        let style = if Some(g.id) == pick {
            app.theme.selected
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(fit(&g.name, 36), style)));
    }
    clear(f, r, &app.theme);
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(app.theme.overlay)
                .title(" Switch to "),
        ),
        r,
    );
}

/// The QR code for `text` as rows of half-block characters.
pub fn qr_rows(text: &str) -> Vec<String> {
    match qrcode::QrCode::new(text.as_bytes()) {
        Ok(code) => code
            .render::<qrcode::render::unicode::Dense1x2>()
            .quiet_zone(true)
            .build()
            .lines()
            .map(String::from)
            .collect(),
        Err(_) => vec![],
    }
}

/// Under the command list: how to select text while the mouse is on.
const MOUSE_NOTE: &str = "To select text while the mouse is on, hold Shift as you drag (Option or Fn on a Mac), or type /mouse off.";

/// Width of the command column in the help box: the longest command and
/// one space.
const HELP_COLUMN: usize = 22;

/// Every row of the help box at `inner_w` characters wide. A description
/// too long for its row goes on under itself, never cut short.
fn help_rows(inner_w: usize, t: &Theme) -> Vec<Line<'static>> {
    let cyan = t.accent;
    let mut rows = vec![];
    for (c, d) in HELP {
        for (i, part) in wrap(d, inner_w.saturating_sub(HELP_COLUMN))
            .into_iter()
            .enumerate()
        {
            let head = if i == 0 { *c } else { "" };
            rows.push(Line::from(vec![
                Span::styled(format!("{head:<HELP_COLUMN$}"), cyan),
                Span::raw(part),
            ]));
        }
    }
    rows.push(Line::from(""));
    for part in wrap(MOUSE_NOTE, inner_w) {
        rows.push(Line::from(Span::styled(part, t.dim)));
    }
    rows
}

/// Lines of plain text, each wrapped to `w`.
fn wrapped(lines: &[String], w: usize) -> Vec<Line<'static>> {
    lines
        .iter()
        .flat_map(|l| wrap(l, w))
        .map(Line::from)
        .collect()
}

/// The rows of a scrolling box that fit in `max_h` rows of screen, frame
/// included, starting `offset` rows down. While rows below are hidden,
/// the last row says so. Tells `app` how far the box can scroll.
fn scroll_window(
    app: &App,
    all: Vec<Line<'static>>,
    offset: usize,
    max_h: usize,
) -> Vec<Line<'static>> {
    // Rows inside the box at most, with a frame above and below.
    let fits = max_h.saturating_sub(2).max(2);
    let max = all.len().saturating_sub(fits);
    app.box_scroll.set((max, fits));
    let top = offset.min(max);
    if top < max {
        let mut v: Vec<Line> = all[top..top + fits - 1].to_vec();
        v.push(Line::from(Span::styled("↓ more", app.theme.dim)));
        v
    } else {
        all[top..].to_vec()
    }
}

/// The buttons along the bottom edge of a box, each with the key it
/// stands for.
fn buttons(m: &Modal) -> &'static [(&'static str, KeyCode)] {
    match m {
        Modal::Confirm { .. } => &[
            ("[ Yes ]", KeyCode::Char('y')),
            ("[ No ]", KeyCode::Char('n')),
        ],
        Modal::Verify { .. } => &[
            ("[ They match ]", KeyCode::Char('y')),
            ("[ Close ]", KeyCode::Esc),
        ],
        Modal::ConfirmVideo { .. } | Modal::ConfirmPhoto { .. } => &[
            ("[ Send it ]", KeyCode::Char('y')),
            ("[ Cancel ]", KeyCode::Char('n')),
        ],
        Modal::NewCertificate { .. } => &[
            ("[ Trust the new one ]", KeyCode::Char('y')),
            ("[ Keep the old one ]", KeyCode::Char('n')),
        ],
        _ => &[("[ Close ]", KeyCode::Esc)],
    }
}

/// The line under an invite link: that a copy is under way, or whether
/// the invite is on the clipboard and that C copies it, with the C
/// standing out.
fn copy_line(copying: bool, copied: bool, t: &Theme) -> Line<'static> {
    if copying {
        return Line::from("Copying…");
    }
    let (before, after) = if copied {
        ("Copied. Press ", " to copy again.")
    } else {
        ("Press ", " to copy.")
    };
    Line::from(vec![
        Span::raw(before),
        Span::styled("C", t.accent.add_modifier(Modifier::BOLD)),
        Span::raw(after),
    ])
}

fn draw_modal(f: &mut Frame, app: &App, m: &Modal, area: Rect) {
    let width = area.width.saturating_sub(4).min(76);
    let inner_w = width.saturating_sub(2) as usize;
    let max_h = area.height.saturating_sub(2) as usize;
    // The row under the link that copies the invite, and its width.
    let mut copy_row: Option<(usize, usize)> = None;
    let (title, mut lines): (String, Vec<Line>) = match m {
        Modal::Confirm { question, .. } => (String::new(), wrapped(std::slice::from_ref(question), inner_w)),
        Modal::Invites { rows, offset } => (
            " Open invite links ".into(),
            scroll_window(app, wrapped(rows, inner_w), *offset, max_h),
        ),
        Modal::Servers { rows, offset } => (
            " Your servers ".into(),
            scroll_window(app, wrapped(rows, inner_w), *offset, max_h),
        ),
        Modal::Details { lines, offset } => (
            " Room details ".into(),
            scroll_window(app, wrapped(lines, inner_w), *offset, max_h),
        ),
        Modal::About => (" About ".into(), wrapped(&about_lines(), inner_w)),
        Modal::Help { offset } => (
            " Commands ".into(),
            scroll_window(app, help_rows(inner_w, &app.theme), *offset, max_h),
        ),
        Modal::Invite {
            link,
            hours,
            copied,
        } => {
            let mut v: Vec<Line> = wrap(
                &format!(
                    "Send this link to one person. It works once and expires in {}. Anyone who has it can ask to join.",
                    hours_text(*hours)
                ),
                inner_w,
            )
            .into_iter()
            .map(Line::from)
            .collect();
            v.push(Line::from(""));
            for l in wrap(link, inner_w) {
                v.push(Line::from(Span::styled(l, app.theme.accent)));
            }
            let line = copy_line(app.copying, *copied, &app.theme);
            copy_row = Some((v.len(), line.width()));
            v.push(line);
            (" Invite link ".into(), with_qr(v, link, area, inner_w, &app.theme))
        }
        Modal::NoInviteLink { why } => (" Invite link ".into(), wrapped(std::slice::from_ref(why), inner_w)),
        Modal::Verify { name, number, .. } => {
            let mut v: Vec<Line> = wrap(
                &format!("Compare these numbers with {name}, in person or on a call. If both screens match, nobody sits between you. Press Y if they match."),
                inner_w,
            )
            .into_iter()
            .map(Line::from)
            .collect();
            v.push(Line::from(""));
            let groups: Vec<&str> = number.split(' ').collect();
            for row in groups.chunks(4) {
                v.push(Line::from(Span::styled(row.join("  "), Style::default().add_modifier(Modifier::BOLD))));
            }
            let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
            (format!(" Check {} ", fit(name, 30)), with_qr(v, &digits, area, inner_w, &app.theme))
        }
        Modal::ConfirmVideo { path, .. } => (
            " Send this video? ".into(),
            wrap(
                &format!(
                    "{} may still hold the place it was filmed and the phone that made it. Socketchat removes this from photos but cannot remove it from videos. Send it anyway?",
                    fit(path.rsplit(['/', '\\']).next().unwrap_or(path), 40)
                ),
                inner_w,
            )
            .into_iter()
            .map(Line::from)
            .collect(),
        ),
        Modal::ConfirmPhoto { path, .. } => (
            " Send this photo? ".into(),
            wrap(
                &format!(
                    "{} may still hold the place it was taken and the phone that took it. Socketchat cannot remove this from this photo. Send it anyway?",
                    fit(path.rsplit(['/', '\\']).next().unwrap_or(path), 40)
                ),
                inner_w,
            )
            .into_iter()
            .map(Line::from)
            .collect(),
        ),
        Modal::NewCertificate {
            host,
            pinned,
            offered,
            ..
        } => {
            let mut v: Vec<Line> = wrap(
                &format!(
                    "This link names a different certificate for {} from the one Socketchat trusts. That happens when the server's operator sets it up again, and when someone sends a fake link.",
                    fit(host, 40)
                ),
                inner_w,
            )
            .into_iter()
            .map(Line::from)
            .collect();
            v.push(Line::from(""));
            let bold = Style::default().add_modifier(Modifier::BOLD);
            for (label, fpr) in [("Trusted now", pinned), ("In the link", offered)] {
                v.push(Line::from(label.to_string()));
                for l in wrap(fpr, inner_w) {
                    v.push(Line::from(Span::styled(l, bold)));
                }
            }
            v.push(Line::from(""));
            for l in wrap(
                "Press Y only if the operator told you they set the server up again. Nothing changes unless the new certificate works.",
                inner_w,
            ) {
                v.push(Line::from(l));
            }
            (" New server certificate ".into(), v)
        }
    };
    if lines.len() + 2 > max_h {
        lines.truncate(max_h.saturating_sub(2));
    }
    let lines_shown = lines.len();
    let r = centered(area, width, lines.len() as u16 + 2);
    clear(f, r, &app.theme);
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(app.theme.accent)
                .title_style(app.theme.title)
                .title(title),
        ),
        r,
    );
    let mut hits = app.hits.borrow_mut();
    hits.modal = Some(r);
    if let Some((row, w)) = copy_row.filter(|(row, _)| *row < lines_shown) {
        let at = Rect::new(r.x + 1, r.y + 1 + row as u16, w as u16, 1);
        hits.targets.push((at.intersection(r), KeyCode::Char('c')));
    }
    // Buttons sit on the bottom edge, at the right, when they fit.
    let bs = buttons(m);
    let total: u16 = bs.iter().map(|(l, _)| l.chars().count() as u16 + 1).sum();
    if r.height >= 3 && total + 3 <= r.width {
        let style = app.theme.accent.add_modifier(Modifier::BOLD);
        let mut x = r.x + r.width - 1 - total;
        let y = r.y + r.height - 1;
        for (label, code) in bs {
            let at = Rect::new(x, y, label.chars().count() as u16, 1);
            f.render_widget(Paragraph::new(Span::styled(*label, style)), at);
            hits.targets.push((at, *code));
            x += at.width + 1;
        }
    }
}

/// Adds a QR code under `lines` when the window has room, or a note saying
/// how to make room.
fn with_qr(
    mut lines: Vec<Line<'static>>,
    text: &str,
    area: Rect,
    inner_w: usize,
    t: &Theme,
) -> Vec<Line<'static>> {
    let qr = qr_rows(text);
    let qr_w = qr.first().map(|l| l.chars().count()).unwrap_or(0);
    let fits = qr_w <= inner_w && lines.len() + 1 + qr.len() + 2 <= area.height as usize;
    lines.push(Line::from(""));
    if fits {
        let pad = " ".repeat((inner_w - qr_w) / 2);
        // Exact RGB black on white: themes remap the named Black and White
        // (some to gray on gray), and cameras then fail to read the code.
        let ink = Style::default()
            .fg(ratatui::style::Color::Rgb(0, 0, 0))
            .bg(ratatui::style::Color::Rgb(255, 255, 255));
        for row in qr {
            lines.push(Line::from(vec![
                Span::raw(pad.clone()),
                Span::styled(row, ink),
            ]));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "Make the window larger to show a QR code.",
            t.dim,
        )));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn steps_of(f: impl FnOnce()) -> usize {
        WRAP_STEPS.with(|c| c.set(0));
        f();
        WRAP_STEPS.with(|c| c.get())
    }

    fn line(text: String) -> LineView {
        LineView {
            time: "09:14:05".into(),
            sender: "Mallory".into(),
            text,
            notice: false,
            mine: false,
        }
    }

    fn room(lines: Vec<LineView>) -> ViewModel {
        ViewModel {
            me: "Ada".into(),
            groups: vec![GroupView {
                id: GroupId([1; 16]),
                name: "Crew".into(),
                unread: 0,
                is_dm: false,
                muted: false,
                ended: None,
            }],
            lines,
            members: vec![],
            connected: true,
            server: None,
        }
    }

    fn screen(app: &App, vm: &ViewModel) -> Vec<String> {
        let mut t = Terminal::new(TestBackend::new(80, 24)).unwrap();
        t.draw(|f| draw(f, app, vm)).unwrap();
        let buf = t.backend().buffer().clone();
        (0..24)
            .map(|y| (0..80).map(|x| buf[(x, y)].symbol()).collect::<String>())
            .collect()
    }

    /// A word as long as the longest message wraps in time that grows with
    /// its length, not with its length squared.
    #[test]
    fn wrapping_one_long_word_steps_over_each_character_a_few_times() {
        let word = "x".repeat(16 * 1024);
        let n = steps_of(|| {
            let rows = wrap(&word, 38);
            assert_eq!(rows.len(), (16 * 1024usize).div_ceil(38));
            assert!(rows.iter().all(|r| r.chars().count() <= 38));
        });
        assert!(n <= 3 * 16 * 1024, "{n} steps for 16 KB");
    }

    /// 300 messages at the size limit, all one word: a draw wraps only the
    /// messages that can reach the screen.
    #[test]
    fn a_draw_wraps_only_the_messages_on_screen() {
        let vm = room((0..300).map(|_| line("x".repeat(16 * 1024))).collect());
        let mut app = App::new();
        app.selected = Some(GroupId([1; 16]));
        let n = steps_of(|| {
            screen(&app, &vm);
        });
        // Each wrap steps over a character about twice, a message is
        // wrapped twice to find its rows and twice more to draw them, and
        // the newest one fills the screen: room here for five such.
        let five = 5 * 8 * 16 * 1024;
        assert!(n <= five, "{n} steps for one screen");
        // Scrolled up a few pages, still only the messages near the window.
        app.scroll = 200;
        let n = steps_of(|| {
            screen(&app, &vm);
        });
        assert!(n <= five, "{n} steps scrolled up");
    }

    /// The window shows the same rows as wrapping every message would.
    #[test]
    fn scrolling_shows_the_same_rows_as_wrapping_everything() {
        let mut lines: Vec<LineView> = (0..40)
            .map(|i| line(format!("message {i} {}", "word ".repeat(i * 7))))
            .collect();
        lines[3].notice = true;
        lines[9].text = "a\nb\n\nc".into();
        let vm = room(lines);
        let mut app = App::new();
        app.selected = Some(GroupId([1; 16]));
        // At 80 by 24 the messages pane is 38 wide and 18 high, from
        // column 21 and row 1.
        let all: Vec<String> = vm
            .lines
            .iter()
            .flat_map(|l| message_rows(&message_head(l), l, 38))
            .collect();
        for scroll in [0u16, 1, 5, 17, 60, 200, 2000, u16::MAX] {
            app.scroll = scroll;
            let screen = screen(&app, &vm);
            let end = all.len().saturating_sub(scroll as usize);
            let want = &all[end.saturating_sub(18)..end];
            for y in 0..18 {
                let got: String = screen[y + 1].chars().skip(21).take(38).collect();
                let want = want.get(y).map(String::as_str).unwrap_or("");
                assert_eq!(got.trim_end(), want.trim_end(), "scroll {scroll}, row {y}");
            }
        }
    }

    /// Columns a string takes on a terminal, wide characters as two.
    fn columns(s: &str) -> usize {
        s.chars()
            .map(|c| match c {
                '文' | '😀' | '漢' => 2,
                _ => 1,
            })
            .sum()
    }

    /// The box sizes what it shows by terminal columns, so wide
    /// characters never push a command's end past the edge, at any width.
    #[test]
    fn the_box_fits_wide_characters_by_columns() {
        let inputs = [
            "/文a😀b文".to_string(),
            "/send 😀😀 /tmp/文文文/end".to_string(),
            "文文文文文文文文".to_string(),
            "a😀b😀c😀d".to_string(),
            format!("/send /tmp/{}/end.txt", "文".repeat(60)),
        ];
        for input in &inputs {
            for room in 0..=80 {
                let shown = shown_input(input, room);
                assert!(
                    columns(&shown) <= room,
                    "{input:?} at {room}: {shown:?} takes {} columns",
                    columns(&shown)
                );
            }
        }
        let wide = format!("/send /tmp/{}/end.txt", "文".repeat(60));
        let shown = shown_input(&wide, 75);
        assert!(shown.starts_with("/send /tmp/文"), "{shown}");
        assert!(shown.ends_with("/end.txt"), "{shown}");
        assert!(shown.contains('…'), "{shown}");
        assert_eq!(input_columns("文文a"), 5);
        assert_eq!(input_columns("a\nb"), 3, "a line break shows as one column");
    }

    /// What ratatui drew in a message box `width` columns wide holding
    /// `input`: the cells after the "› " prompt, one symbol each, with the
    /// blank cells at the end left off, and the cursor's column.
    fn drawn_box(input: &str, width: u16) -> (Vec<String>, u16) {
        let mut app = App::new();
        app.input = input.to_string();
        let vm = room(vec![]);
        let mut t = Terminal::new(TestBackend::new(width, 3)).unwrap();
        t.draw(|f| {
            let r = f.area();
            let lines = input_lines(&app, &vm, r.width.saturating_sub(2) as usize);
            draw_input(f, &app, lines, r);
        })
        .unwrap();
        let buf = t.backend().buffer().clone();
        // The row inside the frame, read the way TestBackend prints it: a
        // wide symbol hides the cells it covers.
        // The grey suggestion after the text is not the input, so the
        // reading stops where it starts.
        let mut cells = vec![];
        let mut x = 1;
        while x + 1 < width {
            let cell = &buf[(x, 1)];
            if x > 2 && app.theme.dim.fg.is_some_and(|c| cell.fg == c) {
                break;
            }
            let sym = cell.symbol();
            cells.push(sym.to_string());
            x += sym.cell_width().max(1);
        }
        let mut cells: Vec<String> = cells.into_iter().skip(2).collect();
        while cells.last().is_some_and(|c| c == " ") {
            cells.pop();
        }
        (cells, t.get_cursor_position().unwrap().x)
    }

    /// The clusters of `input` that ratatui puts in a cell: whole
    /// graphemes, less those with no width.
    fn drawable(input: &str) -> Vec<String> {
        input
            .graphemes(true)
            .filter(|g| !g.contains(char::is_control) && g.cell_width() > 0)
            .map(str::to_string)
            .collect()
    }

    /// Checks one input in boxes 3 to 120 columns wide against what ratatui
    /// drew: a command shows its start, an ellipsis and its end when it is
    /// too wide, its last cluster whole whenever two columns are left for
    /// the end, and never a broken cluster. The cursor sits right after the
    /// text when it all shows, and inside the box when it does not.
    fn check_drawn(input: &str) {
        let mut want = drawable(input);
        // Blank cells at the end are not read back, so spaces the input
        // ends with are left off here and counted for the cursor.
        let mut spaces = 0;
        while want.last().is_some_and(|c| c == " ") {
            want.pop();
            spaces += 1;
        }
        for width in 3..=120u16 {
            let room = (width as usize).saturating_sub(5);
            let (cells, cursor) = drawn_box(input, width);
            let at =
                |what: &str| format!("{input:?} in a box {width} wide: {what}, drew {cells:?}");
            let cut = cells.iter().position(|c| c == "…");
            let (head, tail) = match cut {
                Some(i) => (&cells[..i], &cells[i + 1..]),
                None => (&cells[..0], &cells[..]),
            };
            assert!(
                want.starts_with(head),
                "{}",
                at("the start is not the input's start")
            );
            assert!(
                want.ends_with(tail),
                "{}",
                at("the end is not the input's end")
            );
            if input.starts_with('/') && room >= 3 {
                if cut.is_some() {
                    assert_eq!(
                        head.first().map(String::as_str),
                        Some("/"),
                        "{}",
                        at("no /")
                    );
                } else {
                    assert_eq!(cells, want, "{}", at("not all of it, and no ellipsis"));
                }
            }
            if room >= 5 {
                assert_eq!(
                    tail.last(),
                    want.last(),
                    "{}",
                    at("the last cluster is missing")
                );
            }
            if room >= 17 && input.ends_with("/end.txt") {
                assert!(
                    cells.concat().ends_with("/end.txt"),
                    "{}",
                    at("no /end.txt")
                );
            }
            let used: u16 = cells.iter().map(|c| c.cell_width()).sum();
            let text_end = 1 + 2 + used;
            if width >= 5 && cells == want {
                let text_end = text_end + spaces;
                assert_eq!(
                    cursor,
                    text_end,
                    "{}",
                    at("the cursor is not after the text")
                );
            } else if width >= 5 {
                assert!(
                    cursor >= text_end && cursor + 1 < width,
                    "{}",
                    at("the cursor is off")
                );
            }
        }
    }

    const HEART: &str = "\u{2764}\u{FE0F}";
    const KEYCAP: &str = "1\u{FE0F}\u{20E3}";
    const FAMILY: &str = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466}";
    const FLAG: &str = "\u{1F1FA}\u{1F1F8}";
    const CJK: &str = "漢";
    const COMBINING: &str = "e\u{301}";
    const ZERO_WIDTH: &str = "\u{200B}";
    const ASCII: &str = "ab";

    /// Emoji that draw two columns from parts that count one, joined
    /// families, flags, Chinese, accents, zero-width characters and plain
    /// letters: a command made of any of them shows its end as drawn.
    #[test]
    fn the_box_shows_a_commands_end_as_ratatui_draws_it() {
        let pieces = [
            HEART, KEYCAP, FAMILY, FLAG, CJK, COMBINING, ZERO_WIDTH, ASCII,
        ];
        for piece in pieces {
            for n in [1, 2, 7, 60] {
                let run = piece.repeat(n);
                check_drawn(&format!("/send /tmp/{run}/end.txt"));
                check_drawn(&format!("/{run}"));
                check_drawn(&format!("/send {run}"));
            }
        }
        check_drawn(&format!("/send /tmp/{}/end.txt", HEART.repeat(60)));
        check_drawn(&format!(
            "/send {KEYCAP}#\u{FE0F}\u{20E3}{FAMILY} {FLAG}\u{1F1EF}\u{1F1F5}"
        ));
    }

    /// Mixes of the same pieces, and of pieces that join the ellipsis if
    /// cut beside it, from a fixed seed so a failure repeats.
    #[test]
    fn mixed_commands_show_their_end_as_ratatui_draws_it() {
        let pieces = [
            HEART,
            KEYCAP,
            FAMILY,
            FLAG,
            CJK,
            COMBINING,
            ZERO_WIDTH,
            ASCII,
            " ",
            "x",
            "\u{1F1EF}",                  // a lone regional indicator
            "\u{1F469}\u{200D}\u{1F4BB}", // a ZWJ pair
            "\u{200B}\u{301}",            // an accent with nothing to sit on
            "\u{600}\u{2028}",            // a prepended mark before a control
            "\u{2028}\u{301}",            // an accent after a control
            "\u{2060}",
            "\u{FEFF}",
            "ｶﾞ",
        ];
        let mut seed: u64 = 0x5eed_c4a7;
        let mut next = |n: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n as u64) as usize
        };
        for _ in 0..60 {
            let len = next(90);
            let mut input = String::from("/");
            for _ in 0..len {
                input.push_str(pieces[next(pieces.len())]);
            }
            input.push_str(pieces[next(8)]);
            if next(2) == 0 {
                input.push_str("/end.txt");
            }
            check_drawn(&input);
        }
    }

    /// A prepended mark just before the cut, or an accent with nothing to
    /// sit on just after it, would join the ellipsis into one cell; the cut
    /// moves past them instead.
    #[test]
    fn a_cut_never_joins_the_ellipsis() {
        // U+0600 holds on to what follows unless a control comes next;
        // U+2028 is a control that takes a column. Nothing in a lone
        // accent's cluster comes before it.
        check_drawn(&format!("/ab\u{600}\u{2028}{}end", "x".repeat(100)));
        check_drawn(&format!("/{}\u{2028}\u{301}ab", "x".repeat(100)));
        check_drawn(&format!(
            "/{}\u{2028}\u{301}{}",
            "x".repeat(100),
            CJK.repeat(9)
        ));
    }

    /// The cursor sits right after what is drawn, by ratatui's widths.
    #[test]
    fn the_cursor_follows_drawn_widths() {
        for (input, cols) in [
            (format!("{HEART}{HEART}a"), 5),
            (format!("{KEYCAP}a"), 3),
            (format!("{FAMILY}a"), 3),
            (format!("{FLAG}a"), 3),
            (format!("{COMBINING}{ZERO_WIDTH}a"), 2),
            ("漢a\nb".to_string(), 5),
        ] {
            assert_eq!(input_columns(&input), cols, "{input:?}");
            let (_, cursor) = drawn_box(&input, 80);
            assert_eq!(cursor, 1 + 2 + cols as u16, "{input:?}");
        }
    }

    /// The grey suggestion is measured in the columns ratatui draws, so a
    /// wide room name never runs past the room the box leaves.
    #[test]
    fn a_wide_suggestion_fits_the_box() {
        let mut vm = room(vec![]);
        vm.groups[0].name = "文字クラブ".into();
        let mut app = App::new();
        app.input = "/switch 文".into();
        assert_eq!(app.ghost(&vm).as_deref(), Some("字クラブ"));
        for width in 8..=40u16 {
            let inner = width as usize - 2;
            let room = inner.saturating_sub(3);
            let line = &input_lines(&app, &vm, inner)[0];
            let typed = input_columns(&app.input);
            let ghost: usize = line.spans[2..]
                .iter()
                .map(|s| {
                    drawn_clusters(&s.content)
                        .iter()
                        .map(|(_, w)| w)
                        .sum::<usize>()
                })
                .sum();
            assert!(
                typed > room || typed + ghost <= room,
                "box {width} wide: {typed} + {ghost} columns in {room}"
            );
            if typed + 2 <= room {
                assert!(ghost > 0, "box {width} wide: no suggestion");
            }
        }
    }
}
