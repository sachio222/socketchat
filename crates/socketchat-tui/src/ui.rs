//! Drawing. Four areas: chats on the left, messages in the middle, people
//! on the right, and a framed message box across the bottom with a help line
//! under it. Readable at 80 by 24.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;
use socketchat_core::client::Ended;
use socketchat_core::invite::hours_text;
use socketchat_core::keys::Key;
use socketchat_proto::msg::GroupId;

use crate::app::{ended_hint, App, Focus, Modal};
use crate::commands::HELP;

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

/// Greedy word wrap by characters.
fn wrap(text: &str, w: usize) -> Vec<String> {
    let w = w.max(1);
    let mut out = vec![];
    for para in text.split('\n') {
        let mut line = String::new();
        for word in para.split(' ') {
            let mut word = word.to_string();
            while word.chars().count() > w {
                if !line.is_empty() {
                    out.push(std::mem::take(&mut line));
                }
                let head: String = word.chars().take(w).collect();
                word = word.chars().skip(w).collect();
                out.push(head);
            }
            let need = line.chars().count() + usize::from(!line.is_empty()) + word.chars().count();
            if need > w && !line.is_empty() {
                out.push(std::mem::take(&mut line));
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(&word);
        }
        out.push(line);
    }
    out
}

fn border(focused: bool) -> Style {
    if focused {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

fn help_line(app: &App) -> &'static str {
    if let Some(m) = &app.modal {
        return match m {
            Modal::Verify { .. } => "Y they match · Esc close",
            Modal::ConfirmVideo { .. } => "Y send it · N cancel",
            Modal::NewCertificate { .. } => "Y trust the new certificate · N keep the old one",
            Modal::Invite { .. } => "C copy the link · Esc close",
            Modal::Confirm { .. } => "Y yes · N no",
            Modal::Invites { .. } => "/cancel <number> stops a link · Esc close",
            Modal::Help { .. } => "Up/Down scroll · Esc close",
            _ => "Esc close",
        };
    }
    if app.switcher.is_some() {
        return "Type to filter · Enter open · Esc cancel";
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

    draw_groups(f, app, vm, cols[0]);
    draw_messages(f, app, vm, cols[1]);
    draw_members(f, app, vm, cols[2]);

    draw_input(f, app, input, rows[1]);
    // A status message replaces the help line until the next key, so it is
    // seen without covering what the person types.
    let help = match &app.status {
        Some(st) => Span::styled(
            fit(st, area.width as usize),
            Style::default().fg(Color::Yellow),
        ),
        None => Span::styled(
            fit(help_line(app), area.width as usize),
            Style::default().fg(Color::DarkGray),
        ),
    };
    f.render_widget(Paragraph::new(help), rows[2]);

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
        let n = app.input.chars().count();
        let shown: String = app.input.chars().skip(n.saturating_sub(room)).collect();
        return vec![Line::from(vec![Span::raw("› "), Span::raw(shown)])];
    }
    let dim = Style::default().fg(Color::DarkGray);
    let room = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
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
            let (before, after) = ("What's on your mind, ", "?");
            vec![vec![
                Span::styled(before, dim),
                Span::styled(
                    fit(&g.name, avail.saturating_sub(before.len() + after.len())),
                    room,
                ),
                Span::styled(after, dim),
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

/// The framed message box, holding `lines` from [`input_lines`].
fn draw_input(f: &mut Frame, app: &App, lines: Vec<Line<'static>>, r: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border(app.focus == Focus::Input));
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
            start + app.input.chars().count().min(w.saturating_sub(start + 1))
        };
        f.set_cursor_position((inner.x + x as u16, inner.y));
    }
}

fn draw_groups(f: &mut Frame, app: &App, vm: &ViewModel, r: Rect) {
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
                Style::default().add_modifier(Modifier::REVERSED)
            } else if g.muted {
                Style::default().fg(Color::DarkGray)
            } else if !count.is_empty() {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let ended_style = if selected {
                style
            } else {
                style.fg(Color::DarkGray)
            };
            Line::from(vec![
                Span::styled(format!("{mark} {name}"), style),
                Span::styled(ended, ended_style),
                Span::styled(format!("{}{count}", " ".repeat(pad)), style),
            ])
        })
        .collect();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border(app.focus == Focus::Groups))
        .title(" Chats ");
    f.render_widget(Paragraph::new(lines).block(block), r);
}

fn draw_messages(f: &mut Frame, app: &App, vm: &ViewModel, r: Rect) {
    let title = match vm.groups.iter().find(|g| Some(g.id) == app.selected) {
        Some(g) => format!(" {} ", fit(&g.name, r.width.saturating_sub(14) as usize)),
        None => " socketchat ".into(),
    };
    let title = if vm.connected {
        title
    } else {
        format!("{title}· offline ")
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border(app.focus == Focus::Messages))
        .title(title);
    let inner = block.inner(r);
    f.render_widget(block, r);
    let w = inner.width as usize;
    let mut rows: Vec<Line> = vec![];
    if let Some(warn) = &app.warning {
        for l in wrap(warn, w) {
            rows.push(Line::from(Span::styled(
                l,
                Style::default().fg(Color::White).bg(Color::Red),
            )));
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
    let mut body: Vec<Line> = vec![];
    for l in &vm.lines {
        let (head, style) = if l.notice {
            (
                format!("{} · ", l.time),
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            )
        } else {
            (
                format!("{} {}: ", l.time, fit(&l.sender, 16)),
                Style::default(),
            )
        };
        let full = format!("{head}{}", l.text);
        // Continuation lines sit under the text, clear of the time and the
        // space after it.
        let indent = l.time.chars().count() + 1;
        let first = wrap(&full, w);
        let pieces: Vec<String> = match first.split_first() {
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
        };
        for (i, piece) in pieces.into_iter().enumerate() {
            if i == 0 && !l.notice {
                let split = head.chars().count().min(piece.chars().count());
                let (a, b): (String, String) = (
                    piece.chars().take(split).collect(),
                    piece.chars().skip(split).collect(),
                );
                let name_style = if l.mine {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::Cyan)
                };
                body.push(Line::from(vec![Span::styled(a, name_style), Span::raw(b)]));
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

fn draw_members(f: &mut Frame, app: &App, vm: &ViewModel, r: Rect) {
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
            let mut style = if m.verified {
                Style::default()
            } else {
                Style::default().fg(Color::Yellow)
            };
            if app.focus == Focus::Members && i == app.member_cursor {
                style = style.add_modifier(Modifier::REVERSED);
            }
            Line::from(Span::styled(format!("{v} {name}{star}{you}"), style))
        })
        .collect();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border(app.focus == Focus::Members))
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
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(fit(&g.name, 36), style)));
    }
    f.render_widget(Clear, r);
    f.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" Switch to ")),
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

/// Width of the command column in the help box: the longest command and
/// one space.
const HELP_COLUMN: usize = 22;

/// Every row of the help box at `inner_w` characters wide. A description
/// too long for its row goes on under itself, never cut short.
fn help_rows(inner_w: usize) -> Vec<Line<'static>> {
    let cyan = Style::default().fg(Color::Cyan);
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
        v.push(Line::from(Span::styled(
            "↓ more",
            Style::default().fg(Color::DarkGray),
        )));
        v
    } else {
        all[top..].to_vec()
    }
}

fn draw_modal(f: &mut Frame, app: &App, m: &Modal, area: Rect) {
    let width = area.width.saturating_sub(4).min(76);
    let inner_w = width.saturating_sub(2) as usize;
    let max_h = area.height.saturating_sub(2) as usize;
    let (title, mut lines): (String, Vec<Line>) = match m {
        Modal::Confirm { question, .. } => (String::new(), wrapped(std::slice::from_ref(question), inner_w)),
        Modal::Invites { rows, offset } => (
            " Open invite links ".into(),
            scroll_window(app, wrapped(rows, inner_w), *offset, max_h),
        ),
        Modal::Details { lines } => (" Room details ".into(), wrapped(lines, inner_w)),
        Modal::Help { offset } => (
            " Commands ".into(),
            scroll_window(app, help_rows(inner_w), *offset, max_h),
        ),
        Modal::Invite { link, hours } => {
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
                v.push(Line::from(Span::styled(l, Style::default().fg(Color::Cyan))));
            }
            (" Invite link ".into(), with_qr(v, link, area, inner_w))
        }
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
            (format!(" Check {} ", fit(name, 30)), with_qr(v, &digits, area, inner_w))
        }
        Modal::ConfirmVideo { path } => (
            " Send this video? ".into(),
            wrap(
                &format!(
                    "{} may still hold the place it was filmed and the phone that made it. socketchat removes this from photos but cannot remove it from videos. Send it anyway?",
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
                    "This link names a different certificate for {} from the one socketchat trusts. That happens when the server's operator sets it up again, and when someone sends a fake link.",
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
    let r = centered(area, width, lines.len() as u16 + 2);
    f.render_widget(Clear, r);
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(title),
        ),
        r,
    );
}

/// Adds a QR code under `lines` when the window has room, or a note saying
/// how to make room.
fn with_qr(
    mut lines: Vec<Line<'static>>,
    text: &str,
    area: Rect,
    inner_w: usize,
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
            .fg(Color::Rgb(0, 0, 0))
            .bg(Color::Rgb(255, 255, 255));
        for row in qr {
            lines.push(Line::from(vec![
                Span::raw(pad.clone()),
                Span::styled(row, ink),
            ]));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "Make the window larger to show a QR code.",
            Style::default().fg(Color::DarkGray),
        )));
    }
    lines
}
