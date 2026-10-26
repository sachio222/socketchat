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

use crate::app::{
    about_lines, ended_hint, keep_in_view, version_text, App, Focus, Hits, Modal, STATUS_HEADINGS,
};
use crate::commands::help_entries;
use crate::select::{cols_of, covered, Area, Join, TextArea, TextRow};
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
    /// A topic set or cleared, drawn in the topic's style. Also a notice.
    pub topic: bool,
    /// In an invite line, where in `text` the command to type sits, as a
    /// byte range: drawn in the command style, and copied as plain text.
    pub command: Option<std::ops::Range<usize>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberLine {
    pub key: Key,
    pub name: String,
    pub verified: bool,
    pub admin: bool,
    pub me: bool,
    /// Shows under the name of someone this person verified, with a
    /// different identity key, and is not verified.
    pub changed_key: bool,
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
    /// The open room's topic, cleaned, shown under its header.
    pub topic: Option<String>,
    /// While the message box holds `/invite`: what `/invite` takes for
    /// each person who shares a room with this person, people not in the
    /// open room first, for Tab and Up and Down.
    pub invite_names: Vec<String>,
    /// While the message box holds `/join`: what `/join` takes for each
    /// invite that waits, newest first, from [`crate::app::join_choices`].
    pub join_rooms: Vec<String>,
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
    wrap_joined(text, w).into_iter().map(|(r, _)| r).collect()
}

/// [`wrap`], with how each row follows the row before it: the first row
/// of each line of `text` starts a line, and the others follow at the
/// space the wrap took, or at nothing where it cut a word.
fn wrap_joined(text: &str, w: usize) -> Vec<(String, Join)> {
    let w = w.max(1);
    let mut out = vec![];
    for para in text.split('\n') {
        let mut line = String::new();
        // Characters in `line`, and how `line` follows the row before.
        let mut used = 0;
        let mut join = Join::Line;
        for mut word in para.split(' ') {
            let mut n = word.chars().count();
            steps(n);
            while n > w {
                if used > 0 {
                    out.push((std::mem::take(&mut line), join));
                    used = 0;
                    join = Join::Space;
                }
                let cut = word.char_indices().nth(w).map_or(word.len(), |(i, _)| i);
                steps(w);
                out.push((word[..cut].to_string(), join));
                word = &word[cut..];
                n -= w;
                join = Join::Cut;
            }
            if used > 0 && used + 1 + n > w {
                out.push((std::mem::take(&mut line), join));
                used = 0;
                join = Join::Space;
            }
            if used > 0 {
                line.push(' ');
                used += 1;
            }
            line.push_str(word);
            used += n;
        }
        out.push((line, join));
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
            Modal::Help { .. } => "Up/Down pick a command · Enter use it · Esc close",
            _ => "Esc close",
        };
    }
    if app.switcher.is_some() {
        return "Type to filter · Enter open · Esc cancel";
    }
    if app.focus == Focus::Input && app.recalling() {
        return "Up/Down your earlier lines in this room · Enter send · Ctrl-C quit";
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
        Focus::Messages if app.mouse => "Drag to copy · PgUp/PgDn or Up/Down scroll · Tab move",
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
        // The topic `/topic` put there is drawn as a topic, not a status.
        (Some(st), _) if app.topic_status.as_ref() == Some(st) => (st.clone(), t.topic),
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
        // A newer release takes the help line while nothing else needs
        // it: no box, no switcher, no command being typed.
        (None, None) => match &app.update_notice {
            Some(n)
                if app.modal.is_none()
                    && app.switcher.is_none()
                    && !(app.focus == Focus::Input && app.input.starts_with('/')) =>
            {
                (n.clone(), t.dim)
            }
            _ => (help_line(app, width).to_string(), t.dim),
        },
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
pub(crate) fn drawn_clusters(text: &str) -> Vec<(&str, usize)> {
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
    // The topic, cut to one row; `/details` shows all of it.
    if let Some(topic) = &vm.topic {
        rows.push(Line::from(Span::styled(
            fit(&format!("Topic: {topic}"), w),
            t.topic,
        )));
    }
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
    let first = first_shown(&vm.lines, w, need);
    let mut body: Vec<Line> = vec![];
    // The same rows as plain text, for selecting.
    let mut texts: Vec<TextRow> = vec![];
    for l in &vm.lines[first..] {
        let head = message_head(l);
        let style = match (l.topic, l.notice) {
            (true, _) => t.topic,
            (_, true) => t.notice,
            _ => Style::default(),
        };
        let pieces = message_text_rows(&head, l, w);
        texts.extend(pieces.iter().cloned());
        if let Some(at) = l.command.clone().filter(|_| l.notice && !l.topic) {
            for parts in command_parts(&head, &l.text, at, &pieces) {
                body.push(Line::from(
                    parts
                        .into_iter()
                        .map(|(text, cmd)| Span::styled(text, if cmd { t.command } else { style }))
                        .collect::<Vec<_>>(),
                ));
            }
            continue;
        }
        for (i, piece) in pieces.into_iter().map(|r| r.text).enumerate() {
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
    let above = rows.len() as u16;
    rows.extend(body[start..end].iter().cloned());
    f.render_widget(Paragraph::new(rows), inner);
    // Rows count up from the newest as negative numbers, so a selection
    // stays on its text as the messages scroll.
    let area = TextArea {
        rect: Rect {
            y: inner.y + above,
            height: (end - start) as u16,
            ..inner
        },
        top: start as i64 - body.len() as i64,
        more_above: start > 0 || first > 0,
        more_below: end < body.len(),
        width: w,
    };
    app.hits.borrow_mut().text = Some(area);
    paint_selection(f, app, Area::Messages, &area, &texts[start..end]);
}

/// Draws the part of `rows`, the rows of text on screen in `area`, that
/// the mouse has selected, in the theme's selection style.
fn paint_selection(f: &mut Frame, app: &App, which: Area, area: &TextArea, rows: &[TextRow]) {
    let Some((a, b)) = app.selection(which) else {
        return;
    };
    let r = area.rect;
    for (k, row) in rows.iter().enumerate().take(r.height as usize) {
        let Some((from, to)) = cols_of(area.top + k as i64, a, b) else {
            continue;
        };
        if let (_, Some((c0, c1))) = covered(row, from, to) {
            let c1 = c1.min(r.width as usize);
            if c0 < c1 {
                let cells = Rect::new(r.x + c0 as u16, r.y + k as u16, (c1 - c0) as u16, 1);
                f.buffer_mut().set_style(cells, app.theme.selected);
            }
        }
    }
}

/// Each of `rows`, the rows a notice takes on screen, cut where the
/// command at `at` in `text` starts and ends: its pieces, each marked when
/// it is part of the command. The rows hold the characters of the head and
/// the text in order, less the spaces where a row breaks and plus the
/// indent on the rows under the first, so the characters match up in turn.
fn command_parts(
    head: &str,
    text: &str,
    at: std::ops::Range<usize>,
    rows: &[TextRow],
) -> Vec<Vec<(String, bool)>> {
    let full: Vec<char> = head.chars().chain(text.chars()).collect();
    let (Some(before), Some(cmd)) = (text.get(..at.start), text.get(at.clone())) else {
        return rows.iter().map(|r| vec![(r.text.clone(), false)]).collect();
    };
    let from = head.chars().count() + before.chars().count();
    let to = from + cmd.chars().count();
    let mut p = 0;
    rows.iter()
        .map(|r| {
            let mut parts: Vec<(String, bool)> = vec![];
            for (k, c) in r.text.chars().enumerate() {
                let marked = if k < r.indent {
                    false
                } else {
                    while p < full.len() && full[p] != c {
                        p += 1;
                    }
                    p += 1;
                    (from..to).contains(&(p - 1))
                };
                match parts.last_mut() {
                    Some((s, m)) if *m == marked => s.push(c),
                    _ => parts.push((c.to_string(), marked)),
                }
            }
            parts
        })
        .collect()
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
#[cfg(test)]
fn message_rows(head: &str, l: &LineView, w: usize) -> Vec<String> {
    message_text_rows(head, l, w)
        .into_iter()
        .map(|r| r.text)
        .collect()
}

/// The rows a message takes at `w` characters wide, its first row
/// starting with `head`, each with how it follows the row above.
fn message_text_rows(head: &str, l: &LineView, w: usize) -> Vec<TextRow> {
    let full = format!("{head}{}", l.text);
    // Continuation lines sit under the text, clear of the time and the
    // space after it.
    let indent = l.time.chars().count() + 1;
    let first = wrap_joined(&full, w);
    let row = |text, indent, join| TextRow { text, indent, join };
    match first.split_first() {
        Some(((head_line, _), _)) if w > indent * 2 => {
            let used = head_line.chars().count();
            let rest: String = full.chars().skip(used).collect();
            let body = rest.trim_start();
            // What the head row ended at: a line break, a space, or the
            // middle of a word.
            let gap = &rest[..rest.len() - body.len()];
            let mut after_head = Some(if gap.contains('\n') {
                Join::Line
            } else if gap.is_empty() {
                Join::Cut
            } else {
                Join::Space
            });
            let mut v = vec![row(head_line.clone(), 0, Join::Line)];
            for (p, j) in wrap_joined(body, w - indent) {
                let join = after_head.take().unwrap_or(j);
                if !p.is_empty() {
                    v.push(row(format!("{}{p}", " ".repeat(indent)), indent, join));
                }
            }
            v
        }
        _ => first.into_iter().map(|(t, j)| row(t, 0, j)).collect(),
    }
}

/// The rows of the messages at `w` characters wide, newest last: at least
/// the newest `need`, or all of them when there are fewer.
pub(crate) fn message_body(vm: &ViewModel, w: usize, need: usize) -> Vec<TextRow> {
    vm.lines[first_shown(&vm.lines, w, need)..]
        .iter()
        .flat_map(|l| message_text_rows(&message_head(l), l, w))
        .collect()
}

/// The oldest of `lines` a draw needs: walking back from the newest, the
/// first message by which the rows reach `need`, the window's height plus
/// how far it is scrolled up. Older messages cannot reach the screen.
fn first_shown(lines: &[LineView], w: usize, need: usize) -> usize {
    let mut rows = 0;
    for (i, l) in lines.iter().enumerate().rev() {
        rows += message_text_rows(&message_head(l), l, w).len();
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
            let v = match (m.verified, m.changed_key) {
                (true, _) => "✓",
                (false, true) => "!",
                (false, false) => " ",
            };
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
        .title(match app.selected {
            Some(_) => people_title(&vm.members, r.width.saturating_sub(2) as usize),
            None => " People ".into(),
        });
    f.render_widget(Paragraph::new(lines).block(block), r);
}

/// The People pane's title, at most `room` columns wide: how many of the
/// people listed carry the verified mark, this person included, as the
/// list shows it, or "! check" while someone shows under the name of a
/// person verified earlier with a different key. A narrower pane gets a
/// shorter form, and one too narrow for any gets none.
pub fn people_title(members: &[MemberLine], room: usize) -> String {
    let verified = members.iter().filter(|m| m.verified).count();
    let n = members.len();
    let choices: Vec<String> = if members.iter().any(|m| m.changed_key) {
        vec![" People ! check ".into(), " ! check ".into(), " ! ".into()]
    } else if n == 0 {
        vec![" People ".into()]
    } else {
        vec![
            format!(" People {verified} of {n} ✓ "),
            format!(" People {verified}/{n} ✓ "),
            format!(" {verified}/{n} ✓ "),
        ]
    };
    choices
        .into_iter()
        .find(|t| t.chars().count() <= room)
        .unwrap_or_default()
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

/// The QR codes the screen may show for `text`, as rows of half-block
/// characters, best first: error correction level M, then level L, whose
/// code is smaller for a long text such as an invite's web address and
/// still reads well off a screen. A choice is empty when the text is too
/// long for a QR code at that level.
pub fn qr_choices(text: &str) -> Vec<Vec<String>> {
    [qrcode::EcLevel::M, qrcode::EcLevel::L]
        .into_iter()
        .map(|ec| qr_rows(text, ec))
        .collect()
}

/// The QR code for `text` at error correction level `ec`, as rows of
/// half-block characters.
fn qr_rows(text: &str, ec: qrcode::EcLevel) -> Vec<String> {
    match qrcode::QrCode::with_error_correction_level(text.as_bytes(), ec) {
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

/// Under the command list: how to select and copy text while the mouse
/// is on.
const MOUSE_NOTE: &str = "Drag over messages or the text in a box to copy it. To select with your terminal instead, hold Shift as you drag (Option or Fn on a Mac), or type /mouse off.";

/// The help box's rows for the keys, under the commands.
const KEYS_HELP: [(&str, &str); 5] = [
    ("/ then Enter", "open this list to pick a command"),
    (
        "/s then Up/Down",
        "step through the commands that start with /s",
    ),
    (
        "Tab or Up/Down",
        "step through the rooms or names that fit after /switch, /invite or /join",
    ),
    ("Up/Down", "bring back your earlier lines in this room"),
    (
        "Ctrl-C Ctrl-C",
        "quit; one Ctrl-C copies the text you selected",
    ),
];

/// Width of the command column in the help box: the longest command and
/// one space.
const HELP_COLUMN: usize = 22;

/// Every row of the help box at `inner_w` characters wide, as drawn and
/// as text: the commands in alphabetical order with row `pick`
/// highlighted, then the keys and a note on selecting text. A description
/// too long for its row goes on under itself, never cut short. Also gives
/// each command row's first line and how many lines it takes.
fn help_rows(inner_w: usize, t: &Theme, pick: usize) -> (Vec<Shown>, Vec<(usize, usize)>) {
    let cyan = t.accent;
    let desc_w = inner_w.saturating_sub(HELP_COLUMN);
    let mut rows = vec![];
    let mut layout = vec![];
    let entries = help_entries();
    let keys = KEYS_HELP.iter().map(|(c, d)| (*c, *d));
    for (n, (c, d)) in entries.into_iter().chain(keys).enumerate() {
        let lit = n == pick;
        let first = rows.len();
        for (i, (part, join)) in wrap_joined(d, desc_w).into_iter().enumerate() {
            let head = if i == 0 { c } else { "" };
            let head = format!("{head:<HELP_COLUMN$}");
            let text = TextRow {
                text: format!("{head}{part}"),
                indent: if i == 0 { 0 } else { HELP_COLUMN },
                join,
            };
            let line = if lit {
                Line::from(vec![
                    Span::styled(head, t.selected),
                    Span::styled(format!("{part:<desc_w$}"), t.selected),
                ])
            } else {
                Line::from(vec![Span::styled(head, cyan), Span::raw(part)])
            };
            rows.push((line, text));
        }
        if n < help_entries().len() {
            layout.push((first, rows.len() - first));
        }
    }
    rows.extend(plain_rows(&[String::new()], Style::default(), inner_w));
    rows.extend(plain_rows(&[MOUSE_NOTE.into()], t.dim, inner_w));
    (rows, layout)
}

/// A row of a box as drawn, and as text.
type Shown = (Line<'static>, TextRow);

/// Lines of text in `style`, each wrapped to `w`, as drawn and as text.
fn plain_rows(lines: &[String], style: Style, w: usize) -> Vec<(Line<'static>, TextRow)> {
    lines
        .iter()
        .flat_map(|l| wrap_joined(l, w))
        .map(|(r, join)| {
            (
                Line::from(Span::styled(r.clone(), style)),
                TextRow {
                    text: r,
                    indent: 0,
                    join,
                },
            )
        })
        .collect()
}

/// Every row of a box whose text the mouse can select, before it
/// scrolls, as drawn and as text; `None` for the other boxes.
pub(crate) fn box_rows(
    app: &App,
    m: &Modal,
    inner_w: usize,
) -> Option<Vec<(Line<'static>, TextRow)>> {
    let plain = Style::default();
    Some(match m {
        Modal::Invites { rows, .. } | Modal::Servers { rows, .. } => {
            plain_rows(rows, plain, inner_w)
        }
        // The topic line keeps the topic's style.
        Modal::Details { lines, .. } => lines
            .iter()
            .flat_map(|l| {
                let style = match l.starts_with("Topic: ") {
                    true => app.theme.topic,
                    false => plain,
                };
                plain_rows(std::slice::from_ref(l), style, inner_w)
            })
            .collect(),
        // Section headings stand out as box titles do.
        Modal::Status { lines, .. } => lines
            .iter()
            .flat_map(|l| {
                let style = match STATUS_HEADINGS.contains(&l.as_str()) {
                    true => app.theme.title,
                    false => plain,
                };
                plain_rows(std::slice::from_ref(l), style, inner_w)
            })
            .collect(),
        Modal::About => plain_rows(&about_lines(&app.updates), plain, inner_w),
        Modal::Help { pick, .. } => help_rows(inner_w, &app.theme, *pick).0,
        _ => return None,
    })
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
    // The help box's command row on each line, from the top.
    let mut help_lines: Vec<Option<usize>> = vec![];
    // The line the help box shows first, kept so its highlight shows.
    let mut help_top: Option<usize> = None;
    // The rows of a box whose text can be selected, and the drawn ones.
    let texts = box_rows(app, m, inner_w);
    let drawn =
        || -> Vec<Line<'static>> { texts.iter().flatten().map(|(l, _)| l.clone()).collect() };
    let (title, mut lines): (String, Vec<Line>) = match m {
        Modal::Confirm { question, .. } => (String::new(), wrapped(std::slice::from_ref(question), inner_w)),
        Modal::Invites { offset, .. } => (
            " Open invite links ".into(),
            scroll_window(app, drawn(), *offset, max_h),
        ),
        Modal::Servers { offset, .. } => (
            " Your servers ".into(),
            scroll_window(app, drawn(), *offset, max_h),
        ),
        Modal::Details { offset, .. } => {
            (" Room details ".into(), scroll_window(app, drawn(), *offset, max_h))
        }
        Modal::Status { offset, .. } => {
            (" Status ".into(), scroll_window(app, drawn(), *offset, max_h))
        }
        Modal::About => (" About ".into(), drawn()),
        Modal::Help { offset, pick } => {
            let (_, layout) = help_rows(inner_w, &app.theme, *pick);
            let all = drawn();
            // Scrolled so the highlighted command shows whole.
            let fits = max_h.saturating_sub(2).max(2);
            let max = all.len().saturating_sub(fits);
            let top = keep_in_view(&layout, (max, fits), *offset, *pick).min(max);
            let mut of_line = vec![None; all.len()];
            for (i, (first, count)) in layout.iter().enumerate() {
                for line in &mut of_line[*first..first + count] {
                    *line = Some(i);
                }
            }
            let shown = scroll_window(app, all, top, max_h);
            // The last line says "↓ more" while lines below are hidden.
            let picks = shown.len() - usize::from(top < max);
            help_lines = (0..picks).map(|i| of_line[top + i]).collect();
            help_top = Some(top);
            *app.help_layout.borrow_mut() = layout;
            (" Commands ".into(), shown)
        }
        Modal::Invite {
            link,
            hours,
            copied,
        } => {
            let mut v: Vec<Line> = wrap(
                &format!(
                    "Send this link to one person. It works once and expires in {}. Anyone who has it can ask to join. They can paste it into an open chat with /join. To invite someone you already share a room with, type /invite and their name.",
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
            // The code holds the web address, which a phone camera opens;
            // the text above stays the link to paste into a terminal.
            let web = socketchat_proto::to_web_link(link).unwrap_or_else(|| link.clone());
            (" Invite link ".into(), with_qr(v, &web, max_h, inner_w, &app.theme))
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
            (format!(" Check {} ", fit(name, 30)), with_qr(v, &digits, max_h, inner_w, &app.theme))
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
    // Where the box's text sits, for selecting it: the rows on screen,
    // less the one that says more lie below.
    if let Some(texts) = &texts {
        let (top, shown, max) = match m {
            Modal::Help { offset, .. }
            | Modal::Invites { offset, .. }
            | Modal::Servers { offset, .. }
            | Modal::Details { offset, .. }
            | Modal::Status { offset, .. } => {
                let (max, fits) = app.box_scroll.get();
                let top = help_top.unwrap_or(*offset).min(max);
                let shown = if top < max {
                    fits - 1
                } else {
                    texts.len() - top
                };
                (top, shown, max)
            }
            _ => (0, lines_shown, 0),
        };
        let area = TextArea {
            rect: Rect::new(
                r.x + 1,
                r.y + 1,
                r.width.saturating_sub(2),
                shown.min(lines_shown) as u16,
            ),
            top: top as i64,
            more_above: top > 0,
            more_below: top < max,
            width: inner_w,
        };
        app.hits.borrow_mut().box_text = Some(area);
        let rows: Vec<TextRow> = texts[top..].iter().map(|(_, t)| t.clone()).collect();
        paint_selection(f, app, Area::Box, &area, &rows);
    }
    let mut hits = app.hits.borrow_mut();
    hits.modal = Some(r);
    for (i, row) in help_lines.iter().enumerate().take(lines_shown) {
        if let Some(row) = row {
            let at = Rect::new(r.x + 1, r.y + 1 + i as u16, r.width.saturating_sub(2), 1);
            hits.help_rows.push((at, *row));
        }
    }
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

/// Adds a QR code under `lines` when the window has room for all of it,
/// or a note saying how to make room. A code with rows cut off cannot be
/// read, so the box shows the whole code or none.
fn with_qr(
    mut lines: Vec<Line<'static>>,
    text: &str,
    max_h: usize,
    inner_w: usize,
    t: &Theme,
) -> Vec<Line<'static>> {
    let width = |qr: &[String]| qr.first().map(|l| l.chars().count()).unwrap_or(0);
    // The box's frame takes two of its `max_h` rows, and a blank row sits
    // above the code.
    let fits = |qr: &Vec<String>| {
        !qr.is_empty() && width(qr) <= inner_w && lines.len() + 1 + qr.len() + 2 <= max_h
    };
    let qr = qr_choices(text).into_iter().find(fits);
    lines.push(Line::from(""));
    if let Some(qr) = qr {
        let qr_w = width(&qr);
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
            topic: false,
            command: None,
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
            topic: None,
            invite_names: vec![],
            join_rooms: vec![],
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
