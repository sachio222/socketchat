//! Drawing. Four areas: chats on the left, messages in the middle, people
//! on the right, and a framed message box across the bottom with a help line
//! under it. Readable at 80 by 24.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;
use socketchat_core::invite::hours_text;
use socketchat_core::keys::Key;
use socketchat_proto::msg::GroupId;

use crate::app::{App, Focus, Modal};
use crate::commands::HELP;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupView {
    pub id: GroupId,
    pub name: String,
    pub unread: u32,
    pub is_dm: bool,
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
        s.chars().take(w - 1).chain(std::iter::once('…')).collect()
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
            Modal::Invite { .. } => "C copy the link · Esc close",
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
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(3),
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

    draw_input(f, app, vm, rows[1]);
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
        draw_modal(f, m, area);
    }
}

/// Shown in the empty message box.
const COMMANDS_HINT: &str = "/ for commands";

/// The framed message box: a hint naming the open chat while it is empty,
/// and what the person types once they start.
fn draw_input(f: &mut Frame, app: &App, vm: &ViewModel, r: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border(app.focus == Focus::Input));
    let inner = block.inner(r);
    f.render_widget(block, r);
    let w = inner.width as usize;
    // Typed text and the hint both start after the "› " prompt's width.
    let start = 2.min(w);
    let line = if app.input.is_empty() {
        let dim = Style::default().fg(Color::DarkGray);
        let room = Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD);
        let avail = w - start;
        let open = vm.groups.iter().find(|g| Some(g.id) == app.selected);
        let mut spans: Vec<Span> = match open {
            Some(g) if g.is_dm => {
                let before = "Say hi to ";
                vec![
                    Span::styled(before, dim),
                    Span::styled(fit(&g.name, avail.saturating_sub(before.len())), room),
                ]
            }
            Some(g) => {
                let (before, after) = ("What's on your mind, ", "?");
                vec![
                    Span::styled(before, dim),
                    Span::styled(
                        fit(&g.name, avail.saturating_sub(before.len() + after.len())),
                        room,
                    ),
                    Span::styled(after, dim),
                ]
            }
            None => vec![Span::styled(
                fit(
                    "Start a chat with /new <name>, or paste an invite with /join <link>",
                    avail,
                ),
                dim,
            )],
        };
        let used: usize = spans.iter().map(|s| s.content.chars().count()).sum();
        let cmd = COMMANDS_HINT.chars().count();
        if used + 2 + cmd <= avail {
            spans.push(Span::raw(" ".repeat(avail - used - cmd)));
            spans.push(Span::styled(COMMANDS_HINT, dim));
        }
        spans.insert(0, Span::raw(" ".repeat(start)));
        Line::from(spans)
    } else {
        let room = w.saturating_sub(start + 1);
        let n = app.input.chars().count();
        let shown: String = app.input.chars().skip(n.saturating_sub(room)).collect();
        Line::from(vec![Span::raw("› "), Span::raw(shown)])
    };
    f.render_widget(Paragraph::new(line), inner);
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
            let count = if g.unread > 0 {
                format!(" {}", g.unread.min(99))
            } else {
                String::new()
            };
            let name = fit(&g.name, w.saturating_sub(2 + count.chars().count()));
            let pad = w.saturating_sub(2 + name.chars().count() + count.chars().count());
            let text = format!("{mark} {name}{}{count}", " ".repeat(pad));
            let style = if Some(g.id) == app.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else if g.unread > 0 {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Line::from(Span::styled(text, style))
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
    for (i, g) in app.switcher_matches(vm).iter().take(8).enumerate() {
        let style = if i == 0 {
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

fn draw_modal(f: &mut Frame, m: &Modal, area: Rect) {
    let width = area.width.saturating_sub(4).min(76);
    let inner_w = width.saturating_sub(2) as usize;
    let (title, mut lines): (String, Vec<Line>) = match m {
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
        Modal::Help => (
            " Commands ".into(),
            HELP.iter()
                .map(|(c, d)| Line::from(vec![Span::styled(format!("{c:<22}"), Style::default().fg(Color::Cyan)), Span::raw(fit(d, inner_w.saturating_sub(22)))]))
                .collect(),
        ),
    };
    let max_h = area.height.saturating_sub(2) as usize;
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
