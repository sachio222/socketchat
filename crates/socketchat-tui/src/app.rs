//! The screen's state and what each key does. No drawing, no network:
//! keys go in, actions come out, and the run loop carries them out.

use std::cell::{Cell, RefCell};
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::{Position, Rect};
use socketchat_core::client::{Ended, RoomDetails, ServerState, ServerView};
use socketchat_core::invite::hours_text;
use socketchat_core::keys::Key;
use socketchat_core::sanitize::{direction_char, single_spaced, MAX_TEXT_BYTES};
use socketchat_proto::msg::GroupId;
use socketchat_proto::Token;

use crate::commands::{command_words, parse_command, Command};
use crate::theme::{Theme, THEMES};
use crate::ui::{GroupView, ViewModel};

pub use socketchat_proto::invite_message;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Focus {
    Groups,
    Messages,
    Members,
    Input,
}

impl Focus {
    fn next(self) -> Focus {
        match self {
            Focus::Input => Focus::Groups,
            Focus::Groups => Focus::Messages,
            Focus::Messages => Focus::Members,
            Focus::Members => Focus::Input,
        }
    }

    fn prev(self) -> Focus {
        match self {
            Focus::Input => Focus::Members,
            Focus::Groups => Focus::Input,
            Focus::Messages => Focus::Groups,
            Focus::Members => Focus::Messages,
        }
    }
}

/// The status line after sending a file: a photo says it was cleaned, so
/// the person knows the app removed its location and device data.
pub fn sent_file_status(offer: &socketchat_core::files::FileOffer) -> Option<String> {
    offer.metadata_removed().then(|| {
        format!(
            "Sent {} with its location and device data removed.",
            offer.name
        )
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Modal {
    Invite {
        link: String,
        /// Hours until the link expires, as the server set them.
        hours: u64,
        /// Whether the invite is on the clipboard, as far as Socketchat
        /// can tell.
        copied: bool,
    },
    /// What `/invite` says instead of a link it cannot make, and why.
    NoInviteLink { why: String },
    Verify {
        name: String,
        key: Key,
        number: String,
    },
    /// A video to send to `group`, the room open when the box opened.
    ConfirmVideo { group: GroupId, path: String },
    /// A photo Socketchat cannot clean, to send to `group`, the room open
    /// when the box opened: HEIC, TIFF, camera raw, or one too big or too
    /// damaged to clean.
    ConfirmPhoto { group: GroupId, path: String },
    /// A link names a server already in use, with a different certificate.
    /// Fingerprints are shown as text, ready to compare.
    NewCertificate {
        link: String,
        host: String,
        pinned: String,
        offered: String,
    },
    /// A question answered with y or n; `yes` runs on y.
    Confirm { question: String, yes: Box<Action> },
    /// The person's open invite links, one row each, numbered for
    /// `/cancel`, scrolled down by `offset` rows.
    Invites { rows: Vec<String>, offset: usize },
    /// The servers this profile knows, one row each, numbered for
    /// `/forget`, scrolled down by `offset` rows.
    Servers { rows: Vec<String>, offset: usize },
    /// A room's details, scrolled down by `offset` rows.
    Details { lines: Vec<String>, offset: usize },
    /// The version, what socketchat is and where to find it.
    About,
    /// The command list, scrolled down by `offset` rows.
    Help { offset: usize },
}

impl Modal {
    /// Whether this box asks a question that y answers yes.
    pub fn is_question(&self) -> bool {
        matches!(
            self,
            Modal::Confirm { .. }
                | Modal::Verify { .. }
                | Modal::ConfirmVideo { .. }
                | Modal::ConfirmPhoto { .. }
                | Modal::NewCertificate { .. }
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Send(GroupId, String),
    Command(Command),
    Select(GroupId),
    /// Send this video, or this photo that cannot be cleaned, as it is, to
    /// this room.
    ConfirmVideo(GroupId, String),
    /// Join with this link, trusting the certificate it names.
    AcceptCertificate(String),
    MarkVerified(Key),
    /// Put this text on the terminal's clipboard.
    Copy(String),
    /// Vote yes on closing this room, which asks the other admins when
    /// nobody has yet.
    CloseRoom(GroupId),
    LeaveRoom(GroupId),
    /// Delete this room's messages from this computer.
    ClearRoom(GroupId),
    /// Delete every room on this server, and the server, from this
    /// computer.
    ForgetServer(i64),
    Quit,
}

/// What `/leave` does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaveStep {
    /// Show the room's newest messages first: this many are unread.
    ShowUnseen(u32),
    /// Ask before leaving.
    Confirm,
}

/// `/leave` shows unread messages once before it asks to leave, since
/// leaving deletes them.
pub fn leave_step(unseen: u32, shown_already: bool) -> LeaveStep {
    if unseen > 0 && !shown_already {
        LeaveStep::ShowUnseen(unseen)
    } else {
        LeaveStep::Confirm
    }
}

/// One row of the `/invites` box.
pub fn invite_row(n: usize, label: &str, hours: u64) -> String {
    format!("{n}. {label}: expires in {}", hours_text(hours))
}

/// One row of the `/servers` box and of `socketchat servers`.
pub fn server_row(n: usize, s: &ServerView) -> String {
    let rooms = match s.rooms {
        0 => "no rooms".to_string(),
        1 => "1 room".to_string(),
        r => format!("{r} rooms"),
    };
    let state = match &s.state {
        ServerState::Connected => "connected".to_string(),
        ServerState::Unreachable(why) => format!("could not reach: {why}"),
        ServerState::NotYet => "not connected yet".to_string(),
    };
    let here = if s.new_rooms {
        " (new rooms go here)"
    } else {
        ""
    };
    format!("{n}. {}: {rooms}, {state}{here}", s.text)
}

/// What forgetting `server` deletes, and that the server is not told:
/// the question `/forget` and `socketchat servers --forget` ask. `leave`
/// says how to leave a room from where the question shows, like "/leave".
pub fn forget_warning(server: &str, rooms: usize, leave: &str) -> String {
    let not_told =
        "The server is not told, so others there still see you as a member until an admin removes you.";
    match rooms {
        0 => format!(
            "Forget {server}? You have no rooms there. Its certificate and your account key leave this computer, and the server is not told."
        ),
        1 => format!(
            "Forget {server}? Its 1 room leaves this computer, with its messages and keys. {not_told} If the server still works, {leave} that room first."
        ),
        n => format!(
            "Forget {server}? Its {n} rooms leave this computer, with their messages and keys. {not_told} If the server still works, {leave} its rooms first."
        ),
    }
}

/// The question `/forget` asks before it deletes a server's rooms.
pub fn forget_question(server: &str, rooms: usize) -> String {
    format!(
        "{} Press y to forget it or n to keep it.",
        forget_warning(server, rooms, "/leave")
    )
}

/// What forgetting a server with `rooms` rooms says once it is done.
pub fn forgot_text(server: &str, rooms: usize) -> String {
    match rooms {
        0 => format!("Forgot {server}."),
        1 => format!("Forgot {server}. Its 1 room is deleted from this computer."),
        n => format!("Forgot {server}. Its {n} rooms are deleted from this computer."),
    }
}

/// The lines of the `/about` box: the version, one sentence on what
/// socketchat is, the project link and the license.
pub fn about_lines() -> Vec<String> {
    let license = env!("CARGO_PKG_LICENSE")
        .replace(" OR ", " or ")
        .replace("Apache-", "Apache ");
    vec![
        version_text(),
        String::new(),
        "Socketchat is encrypted chat with a server you run yourself. The server passes messages along but cannot read them.".into(),
        String::new(),
        env!("CARGO_PKG_REPOSITORY").into(),
        format!("License: {license}"),
    ]
}

/// "socketchat 0.5.1", from the version in Cargo.toml.
pub fn version_text() -> String {
    format!("socketchat {}", env!("CARGO_PKG_VERSION"))
}

/// The lines of the `/details` box. `name` is the room's name as the list
/// shows it; `server_dates` says whether the server can say when a room
/// was made; `date` writes a time as YYYY-MM-DD.
pub fn details_lines(
    d: &RoomDetails,
    name: &str,
    server_dates: bool,
    date: &dyn Fn(u64) -> String,
) -> Vec<String> {
    let created = match (d.created_unix, server_dates) {
        (Some(t), _) => date(t),
        (None, true) => "not known (the server did not answer)".into(),
        (None, false) => "not known (this server runs an older version)".into(),
    };
    let mut lines = vec![
        format!("Name: {name}"),
        format!("Server: {}", d.server),
        format!("Admins: {}", d.admins.join(", ")),
        format!("Members: {}", d.size),
        format!("Created: {created}"),
        format!("You joined: {}", date(d.joined_unix)),
        format!("Muted: {}", if d.muted { "yes" } else { "no" }),
    ];
    if let Some(c) = d.close.as_ref().filter(|c| c.yes > 0 && !c.kept) {
        lines.push(format!("Closing: {} of {} admins agree", c.yes, c.needed));
    }
    lines
}

/// The message box's hint while a room this person is no longer in is
/// open.
pub fn ended_hint(why: Ended) -> &'static str {
    match why {
        Ended::Closed => {
            "This room was closed. Its messages leave this computer when you open another room."
        }
        Ended::Removed => {
            "You are no longer in this room. Its messages leave this computer when you open another room."
        }
        Ended::Left => {
            "You left this room. Its messages leave this computer when you open another room."
        }
    }
}

/// A room name or typed text as `/switch` compares them: one plain space
/// between words, whatever spacing the name was kept with, and lower case.
fn fold(name: &str) -> String {
    single_spaced(name).to_lowercase()
}

/// The rooms `/switch <text>` can mean, best first: those whose name is
/// the text (ignoring case and spacing), then the others whose name starts
/// with it, in list order, or else, when none does, those whose name
/// contains it. Enter opens the first, and Tab and the grey suggestion
/// after the cursor go through them in this order. Nothing typed matches
/// every room.
fn ranked<'a>(text: &str, groups: &'a [GroupView]) -> Vec<&'a GroupView> {
    let t = fold(text);
    let names: Vec<(String, &GroupView)> = groups.iter().map(|g| (fold(&g.name), g)).collect();
    let exact = names.iter().filter(|(n, _)| *n == t);
    let starts = names.iter().filter(|(n, _)| *n != t && n.starts_with(&t));
    let first: Vec<&GroupView> = exact.chain(starts).map(|(_, g)| *g).collect();
    if !first.is_empty() {
        return first;
    }
    names
        .iter()
        .filter(|(n, _)| n.contains(&t))
        .map(|(_, g)| *g)
        .collect()
}

/// The room `/switch <text>` opens: the first of [`ranked`].
pub fn pick_room<'a>(text: &str, groups: &'a [GroupView]) -> Option<&'a GroupView> {
    ranked(text, groups).into_iter().next()
}

/// What follows `/switch` in the message box, or `None` when the box holds
/// something else.
fn switch_text(input: &str) -> Option<&str> {
    match input.strip_prefix("/switch")? {
        "" => Some(""),
        rest if rest.starts_with(' ') => Some(rest.trim_start()),
        _ => None,
    }
}

/// Where Tab is in a run of presses on a command word or a `/theme` name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TabCycle {
    /// Text before the word being completed: empty, or `/theme `.
    head: &'static str,
    /// The word as typed before the first Tab.
    typed: String,
    /// The match the last press picked; `None` before the first pick.
    idx: Option<usize>,
}

/// What one Tab does to a command word or theme name.
struct TabStep {
    text: String,
    cycle: Option<TabCycle>,
    hint: Option<Vec<String>>,
    status: Option<String>,
}

/// The words `typed` can grow into: command words in `HELP` order, or
/// theme names.
fn word_matches(head: &str, typed: &str) -> Vec<String> {
    if head.is_empty() {
        command_words()
            .into_iter()
            .filter(|c| c.starts_with(typed))
            .map(String::from)
            .collect()
    } else {
        let t = typed.to_lowercase();
        THEMES
            .iter()
            .filter(|n| n.starts_with(&t))
            .map(|n| n.to_string())
            .collect()
    }
}

fn common_prefix(words: &[String]) -> String {
    let mut p: Vec<char> = words[0].chars().collect();
    for w in &words[1..] {
        let n = p
            .iter()
            .zip(w.chars())
            .take_while(|(a, b)| **a == *b)
            .count();
        p.truncate(n);
    }
    p.into_iter().collect()
}

/// What `new` adds after `input`, ignoring case; `None` when it adds nothing.
fn added_after(input: &str, new: &str) -> Option<String> {
    let n = input.chars().count();
    (new.chars().count() > n && new.to_lowercase().starts_with(&input.to_lowercase()))
        .then(|| new.chars().skip(n).collect())
}

fn no_room(text: &str) -> String {
    format!("No room called {text}. Type /switch to see them all.")
}

#[derive(Debug)]
pub struct App {
    pub focus: Focus,
    pub selected: Option<GroupId>,
    pub input: String,
    /// Lines scrolled up from the newest message.
    pub scroll: u16,
    pub switcher: Option<String>,
    pub modal: Option<Modal>,
    pub status: Option<String>,
    pub warning: Option<String>,
    pub member_cursor: usize,
    /// While Tab completes a room name: the text typed before the first
    /// Tab, the index in its matches that Tab last picked, and that room,
    /// which Enter opens even when another room shows the same name.
    pub completion: Option<(String, usize, GroupId)>,
    /// While Tab completes a command word or theme name.
    pub tab_cycle: Option<TabCycle>,
    /// Commands to list on the help line after a Tab with several matches.
    pub hint: Option<Vec<String>>,
    /// The links the last `/invites` box listed; `/cancel <n>` takes the
    /// nth. A cancelled link keeps its number and becomes `None`.
    pub invite_tokens: Vec<Option<Token>>,
    /// The servers the last `/servers` box listed; `/forget <n>` takes the
    /// nth. A forgotten server keeps its number and becomes `None`.
    pub server_ids: Vec<Option<i64>>,
    /// Set as a scrolling box (help or invite links) is drawn: the
    /// furthest it can scroll, and how many rows it shows at once.
    pub(crate) box_scroll: Cell<(usize, usize)>,
    /// The screen's colors.
    pub theme: Theme,
    /// Whether clicks and the scroll wheel work. Off, the terminal selects
    /// text as usual.
    pub mouse: bool,
    /// A copy to the clipboard is under way; the invite box says so.
    pub copying: bool,
    pub(crate) hits: RefCell<Hits>,
    /// The box on screen and when it first showed there. A click read
    /// before then was meant for something else, so it never presses the
    /// box's buttons.
    shown: Option<(Modal, Instant)>,
}

/// The room Tab picked, while the text still shows its name.
fn tab_pick(
    comp: &Option<(String, usize, GroupId)>,
    text: &str,
    vm: &ViewModel,
) -> Option<GroupId> {
    let (_, _, id) = comp.as_ref()?;
    vm.groups
        .iter()
        .find(|g| g.id == *id && single_spaced(&g.name) == single_spaced(text))
        .map(|g| g.id)
}

/// Rows one turn of the scroll wheel moves.
const WHEEL_ROWS: usize = 3;

/// Where the last draw put what a click can reach.
#[derive(Clone, Debug, Default)]
pub(crate) struct Hits {
    pub groups: Rect,
    pub messages: Rect,
    pub members: Rect,
    pub input: Rect,
    /// The open box, if one is on screen.
    pub modal: Option<Rect>,
    /// The box's buttons and other clickable lines, each with the key a
    /// click on it stands for.
    pub targets: Vec<(Rect, KeyCode)>,
}

/// Whether `a` and `b` are the same box on screen: a box that scrolled or
/// noted a copy is still the one that opened.
fn same_box(a: &Modal, b: &Modal) -> bool {
    a == b
        || matches!(
            (a, b),
            (Modal::Help { .. }, Modal::Help { .. })
                | (Modal::Invites { .. }, Modal::Invites { .. })
                | (Modal::Servers { .. }, Modal::Servers { .. })
                | (Modal::Details { .. }, Modal::Details { .. })
                | (Modal::Invite { .. }, Modal::Invite { .. })
        )
}

/// The row of `r`'s inside that `y` falls on, if it falls inside.
fn row_in(r: Rect, x: u16, y: u16) -> Option<usize> {
    let inner = Rect {
        x: r.x.saturating_add(1),
        y: r.y.saturating_add(1),
        width: r.width.saturating_sub(2),
        height: r.height.saturating_sub(2),
    };
    inner
        .contains(Position { x, y })
        .then(|| (y - inner.y) as usize)
}

/// Up, Down, PgUp and PgDn move a scrolling box's `offset`, at most to
/// `max`; a page is the rows it shows, less one.
fn scrolled(offset: usize, code: KeyCode, (max, rows): (usize, usize)) -> Option<usize> {
    let page = rows.saturating_sub(1).max(1);
    let next = match code {
        KeyCode::Up => offset.saturating_sub(1),
        KeyCode::Down => offset + 1,
        KeyCode::PageUp => offset.saturating_sub(page),
        KeyCode::PageDown => offset + page,
        _ => return None,
    };
    Some(next.min(max))
}

/// Pasted text as the message box keeps it: line breaks as `\n`, tabs as
/// spaces, and none of the control or direction characters a sent message
/// loses, so the box shows what will be sent.
fn pasted(text: &str) -> String {
    text.replace("\r\n", "\n")
        .chars()
        .filter_map(|c| match c {
            '\n' | '\r' => Some('\n'),
            '\t' => Some(' '),
            c if c.is_control() || direction_char(c) => None,
            c => Some(c),
        })
        .collect()
}

/// Whether `line` holds spacing that could hide part of it: two spaces in
/// a row, or any blank character other than a plain space.
fn hidden_spacing(line: &str) -> bool {
    line.contains("  ") || line.chars().any(|c| c.is_whitespace() && c != ' ')
}

/// `text` cut to at most `room` bytes, on a character boundary.
fn cut_to(text: &str, room: usize) -> &str {
    let mut end = room.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> App {
        App {
            focus: Focus::Input,
            selected: None,
            input: String::new(),
            scroll: 0,
            switcher: None,
            modal: None,
            status: None,
            warning: None,
            member_cursor: 0,
            completion: None,
            tab_cycle: None,
            hint: None,
            invite_tokens: Vec::new(),
            server_ids: Vec::new(),
            box_scroll: Cell::new((0, 0)),
            theme: Theme::default(),
            mouse: true,
            copying: false,
            hits: RefCell::new(Hits::default()),
            shown: None,
        }
    }

    /// Notes that the screen was drawn at `now`, so a click knows whether
    /// the box under it was showing yet.
    pub fn drawn(&mut self, now: Instant) {
        match &self.modal {
            Some(m) if self.shown.as_ref().is_some_and(|(s, _)| same_box(s, m)) => {}
            Some(m) => self.shown = Some((m.clone(), now)),
            None => self.shown = None,
        }
    }

    /// What a click or the scroll wheel does. `at` is when the terminal
    /// sent it. A click on a box's button acts like that button's key, and
    /// only once the box was on screen before the click.
    pub fn handle_mouse(&mut self, m: MouseEvent, at: Instant, vm: &ViewModel) -> Vec<Action> {
        let (x, y) = (m.column, m.row);
        let up = match m.kind {
            MouseEventKind::ScrollUp => Some(true),
            MouseEventKind::ScrollDown => Some(false),
            _ => None,
        };
        if let Some(up) = up {
            let (max, _) = self.box_scroll.get();
            let step = |offset: usize| {
                if up {
                    offset.saturating_sub(WHEEL_ROWS)
                } else {
                    (offset + WHEEL_ROWS).min(max)
                }
            };
            match &mut self.modal {
                Some(
                    Modal::Help { offset }
                    | Modal::Invites { offset, .. }
                    | Modal::Servers { offset, .. }
                    | Modal::Details { offset, .. },
                ) => *offset = step(*offset),
                Some(_) => {}
                None if self.switcher.is_some() => {}
                None if up => self.scroll = self.scroll.saturating_add(WHEEL_ROWS as u16),
                None => self.scroll = self.scroll.saturating_sub(WHEEL_ROWS as u16),
            }
            return vec![];
        }
        if m.kind != MouseEventKind::Down(MouseButton::Left) {
            return vec![];
        }
        let hits = self.hits.borrow().clone();
        if self.modal.is_some() {
            let fresh = self.shown.as_ref().is_some_and(|(_, since)| at >= *since);
            let pressed = hits
                .targets
                .iter()
                .find(|(r, _)| r.contains(Position { x, y }))
                .map(|(_, code)| *code);
            return match pressed {
                Some(code) if fresh => self.handle_key(KeyEvent::new(code, KeyModifiers::NONE), vm),
                _ => vec![],
            };
        }
        if self.switcher.is_some() {
            return vec![];
        }
        self.status = None;
        self.hint = None;
        self.tab_cycle = None;
        self.completion = None;
        let at = Position { x, y };
        if hits.groups.contains(at) {
            self.focus = Focus::Groups;
            if let Some(g) = row_in(hits.groups, x, y).and_then(|i| vm.groups.get(i)) {
                return vec![Action::Select(g.id)];
            }
        } else if hits.messages.contains(at) {
            self.focus = Focus::Messages;
        } else if hits.members.contains(at) {
            self.focus = Focus::Members;
            if let Some(i) = row_in(hits.members, x, y).filter(|i| *i < vm.members.len()) {
                self.member_cursor = i;
            }
        } else if hits.input.contains(at) {
            self.focus = Focus::Input;
        }
        vec![]
    }

    /// The room Enter in the switcher opens, which the switcher highlights.
    pub fn switcher_pick(&self, vm: &ViewModel) -> Option<GroupId> {
        let q = self.switcher.as_deref().unwrap_or("");
        tab_pick(&self.completion, q, vm).or_else(|| pick_room(q, &vm.groups).map(|g| g.id))
    }

    /// Chats whose names contain the switcher's text, in list order.
    pub fn switcher_matches<'a>(&self, vm: &'a ViewModel) -> Vec<&'a crate::ui::GroupView> {
        let q = fold(self.switcher.as_deref().unwrap_or(""));
        vm.groups
            .iter()
            .filter(|g| fold(&g.name).contains(&q))
            .collect()
    }

    /// The room name Tab puts in place of `typed`: each further Tab moves
    /// to the next match and wraps round.
    fn complete(&mut self, typed: &str, vm: &ViewModel) -> Option<String> {
        let (typed, next) = match self.completion.take() {
            Some((t, i, _)) => (t, i + 1),
            None => (typed.to_string(), 0),
        };
        let matches = ranked(&typed, &vm.groups);
        if matches.is_empty() {
            self.status = Some(no_room(&typed));
            return None;
        }
        let i = next % matches.len();
        // One plain space between words, so the command it makes runs.
        let (name, id) = (single_spaced(&matches[i].name), matches[i].id);
        self.completion = Some((typed, i, id));
        Some(name)
    }

    /// What Tab does to the command word (or `/theme` name) being typed;
    /// `None` when the box holds something else.
    fn tab_step(&self, forward: bool) -> Option<TabStep> {
        let (head, typed, idx) = match &self.tab_cycle {
            Some(c) => (c.head, c.typed.clone(), c.idx),
            None => {
                let i = self.input.as_str();
                if i.starts_with('/') && !i.contains(char::is_whitespace) {
                    ("", i.to_string(), None)
                } else {
                    let r = i
                        .strip_prefix("/theme ")
                        .filter(|r| !r.contains(char::is_whitespace))?;
                    ("/theme ", r.to_string(), None)
                }
            }
        };
        let fresh = self.tab_cycle.is_none();
        let words = word_matches(head, &typed);
        let step = |text: String, cycle, hint, status| TabStep {
            text,
            cycle,
            hint,
            status,
        };
        if words.is_empty() {
            let what = if head.is_empty() { "command" } else { "theme" };
            return Some(step(
                self.input.clone(),
                None,
                None,
                Some(format!("No {what} starts with {typed}")),
            ));
        }
        let cycle = |idx| TabCycle {
            head,
            typed: typed.clone(),
            idx,
        };
        if fresh && head.is_empty() {
            if words.len() == 1 {
                return Some(step(format!("{} ", words[0]), None, None, None));
            }
            let p = common_prefix(&words);
            let text = if p.chars().count() > typed.chars().count() {
                p
            } else {
                self.input.clone()
            };
            return Some(step(text, Some(cycle(None)), Some(words), None));
        }
        let n = words.len();
        let i = match (idx, forward) {
            (None, true) => 0,
            (None, false) => n - 1,
            (Some(i), true) => (i + 1) % n,
            (Some(i), false) => (i + n - 1) % n,
        };
        let hint = head.is_empty().then(|| words.clone());
        Some(step(
            format!("{head}{}", words[i]),
            Some(cycle(Some(i))),
            hint,
            None,
        ))
    }

    /// The whole text a Tab (or Right arrow) would put in the message box
    /// when it adds to what is typed.
    fn ghost_target(&self, vm: &ViewModel) -> Option<String> {
        if self.modal.is_some() || self.switcher.is_some() || self.focus != Focus::Input {
            return None;
        }
        let new = if let Some(now) = switch_text(&self.input) {
            let (typed, next) = match &self.completion {
                Some((t, i, _)) => (t.clone(), i + 1),
                None => (now.to_string(), 0),
            };
            let rooms = ranked(&typed, &vm.groups);
            if rooms.is_empty() {
                return None;
            }
            format!("/switch {}", single_spaced(&rooms[next % rooms.len()].name))
        } else {
            self.tab_step(true)?.text
        };
        added_after(&self.input, &new).map(|_| new)
    }

    /// The grey suggestion drawn after the cursor: display only, never part
    /// of the message box until accepted.
    pub fn ghost(&self, vm: &ViewModel) -> Option<String> {
        added_after(&self.input, &self.ghost_target(vm)?)
    }

    /// Keys while a box is open. `None` passes the key on to the message
    /// box: typing over the invite list or a question closes it and goes
    /// on as typing.
    fn modal_key(&mut self, m: Modal, k: KeyEvent) -> Option<Vec<Action>> {
        // Shift makes a capital Y; Ctrl or Alt with y is not an answer.
        let plain = (k.modifiers - KeyModifiers::SHIFT).is_empty();
        let yes = plain && matches!(k.code, KeyCode::Char('y' | 'Y'));
        let typing = plain && matches!(k.code, KeyCode::Char(_));
        let act = match (m, yes) {
            (Modal::Help { offset }, _) => match scrolled(offset, k.code, self.box_scroll.get()) {
                Some(offset) => {
                    self.modal = Some(Modal::Help { offset });
                    return Some(vec![]);
                }
                None => None,
            },
            (Modal::Details { lines, offset }, _) => {
                match scrolled(offset, k.code, self.box_scroll.get()) {
                    Some(offset) => {
                        self.modal = Some(Modal::Details { lines, offset });
                        return Some(vec![]);
                    }
                    None => None,
                }
            }
            (Modal::Invites { rows, offset }, _) => {
                if let Some(offset) = scrolled(offset, k.code, self.box_scroll.get()) {
                    self.modal = Some(Modal::Invites { rows, offset });
                    return Some(vec![]);
                }
                if typing {
                    self.modal = None;
                    return None;
                }
                None
            }
            (Modal::Servers { rows, offset }, _) => {
                if let Some(offset) = scrolled(offset, k.code, self.box_scroll.get()) {
                    self.modal = Some(Modal::Servers { rows, offset });
                    return Some(vec![]);
                }
                if typing {
                    self.modal = None;
                    return None;
                }
                None
            }
            (Modal::Confirm { yes, .. }, true) => Some(*yes),
            (Modal::Verify { key, .. }, true) => Some(Action::MarkVerified(key)),
            (Modal::ConfirmVideo { group, path }, true) => Some(Action::ConfirmVideo(group, path)),
            (Modal::ConfirmPhoto { group, path }, true) => Some(Action::ConfirmVideo(group, path)),
            (Modal::NewCertificate { link, .. }, true) => Some(Action::AcceptCertificate(link)),
            // The first key answers, and anything but y is no: a stray y
            // later in a word must not confirm. Other letters go on into
            // the message box.
            (m, false) if m.is_question() => {
                self.modal = None;
                let no = matches!(k.code, KeyCode::Char('n' | 'N'));
                return if typing && !no { None } else { Some(vec![]) };
            }
            (Modal::Invite { link, .. }, _) if matches!(k.code, KeyCode::Char('c' | 'C')) => {
                return Some(vec![Action::Copy(invite_message(&link))]);
            }
            _ => None,
        };
        if act.is_some()
            || matches!(
                k.code,
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('n' | 'N')
            )
        {
            self.modal = None;
        }
        Some(act.into_iter().collect())
    }

    pub fn handle_key(&mut self, k: KeyEvent, vm: &ViewModel) -> Vec<Action> {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && k.code == KeyCode::Char('c') {
            return vec![Action::Quit];
        }
        // A status message stays on the help line until the next key.
        self.status = None;
        // Tab runs on through a command word; any other key ends the run.
        if !matches!(k.code, KeyCode::Tab | KeyCode::BackTab) {
            self.tab_cycle = None;
        }
        self.hint = None;
        // Each Tab moves on to the next room name; any other key ends that,
        // and Enter opens the room Tab picked.
        let picked = if k.code == KeyCode::Tab {
            None
        } else {
            self.completion.take()
        };
        if let Some(m) = self.modal.clone() {
            if let Some(acts) = self.modal_key(m, k) {
                return acts;
            }
        }
        if let Some(q) = self.switcher.clone() {
            match k.code {
                KeyCode::Esc => self.switcher = None,
                KeyCode::Backspace => {
                    if let Some(q) = &mut self.switcher {
                        q.pop();
                    }
                }
                KeyCode::Char(c) if !ctrl => {
                    if let Some(q) = &mut self.switcher {
                        q.push(c);
                    }
                }
                KeyCode::Tab => {
                    if let Some(name) = self.complete(&q, vm) {
                        self.switcher = Some(name);
                    }
                }
                KeyCode::Enter => {
                    let pick = tab_pick(&picked, &q, vm)
                        .or_else(|| pick_room(&q, &vm.groups).map(|g| g.id));
                    self.switcher = None;
                    return pick.map(Action::Select).into_iter().collect();
                }
                _ => {}
            }
            return vec![];
        }
        match k.code {
            KeyCode::Char('k') if ctrl => {
                self.switcher = Some(String::new());
            }
            KeyCode::Tab if switch_text(&self.input).is_some() => {
                let typed = switch_text(&self.input).unwrap_or("").to_string();
                if let Some(name) = self.complete(&typed, vm) {
                    self.input = format!("/switch {name}");
                }
            }
            KeyCode::Tab | KeyCode::BackTab if self.tab_step(k.code == KeyCode::Tab).is_some() => {
                if let Some(st) = self.tab_step(k.code == KeyCode::Tab) {
                    self.input = st.text;
                    self.tab_cycle = st.cycle;
                    self.hint = st.hint;
                    self.status = st.status;
                }
            }
            KeyCode::Right if self.ghost_target(vm).is_some() => {
                if let Some(t) = self.ghost_target(vm) {
                    self.input = t;
                }
            }
            KeyCode::Tab => self.focus = self.focus.next(),
            KeyCode::BackTab => self.focus = self.focus.prev(),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_add(5),
            KeyCode::PageDown => self.scroll = self.scroll.saturating_sub(5),
            KeyCode::Up | KeyCode::Down if self.focus == Focus::Groups => {
                let i = vm.groups.iter().position(|g| Some(g.id) == self.selected);
                let n = vm.groups.len();
                if n > 0 {
                    let next = match (i, k.code) {
                        (None, _) => 0,
                        (Some(i), KeyCode::Up) => (i + n - 1) % n,
                        (Some(i), _) => (i + 1) % n,
                    };
                    return vec![Action::Select(vm.groups[next].id)];
                }
            }
            KeyCode::Up | KeyCode::Down if self.focus == Focus::Members => {
                let n = vm.members.len().max(1);
                self.member_cursor = match k.code {
                    KeyCode::Up => (self.member_cursor + n - 1) % n,
                    _ => (self.member_cursor + 1) % n,
                };
            }
            KeyCode::Up if self.focus == Focus::Messages => {
                self.scroll = self.scroll.saturating_add(1)
            }
            KeyCode::Down if self.focus == Focus::Messages => {
                self.scroll = self.scroll.saturating_sub(1)
            }
            KeyCode::Esc => {
                self.input.clear();
                self.status = None;
                self.warning = None;
            }
            KeyCode::Backspace => {
                self.focus = Focus::Input;
                self.input.pop();
            }
            KeyCode::Char(c) if !ctrl => {
                self.focus = Focus::Input;
                if self.input.len() + c.len_utf8() <= MAX_TEXT_BYTES {
                    self.input.push(c);
                } else {
                    self.status = Some(
                        "The message box is full at 16 KB, the most one message holds.".into(),
                    );
                }
            }
            KeyCode::Enter => {
                let raw = std::mem::take(&mut self.input);
                let line = raw.trim();
                if line.is_empty() {
                    return vec![];
                }
                self.status = None;
                // A command runs only as one line at the start of the box
                // with single spaces between its words, so every part of it
                // shows.
                let refused = if !line.starts_with('/') {
                    None
                } else if raw.contains('\n') {
                    Some("A command fits on one line. Remove the line breaks to run it.")
                } else if !raw.starts_with('/') {
                    Some("Remove the spaces before the / to run the command.")
                } else if hidden_spacing(line) {
                    Some("Remove the extra spaces to run the command.")
                } else {
                    None
                };
                if let Some(why) = refused {
                    self.status = Some(why.into());
                    self.input = raw;
                    return vec![];
                }
                let ended = vm
                    .groups
                    .iter()
                    .find(|g| Some(g.id) == self.selected)
                    .and_then(|g| g.ended);
                if line.starts_with('/') {
                    match parse_command(line) {
                        Ok(Command::Switch(None)) => self.switcher = Some(String::new()),
                        Ok(Command::Switch(Some(text))) => match tab_pick(&picked, &text, vm)
                            .or_else(|| pick_room(&text, &vm.groups).map(|g| g.id))
                        {
                            Some(id) => return vec![Action::Select(id)],
                            None => {
                                self.input = line.to_string();
                                self.status = Some(no_room(&text));
                            }
                        },
                        Ok(c) => return vec![Action::Command(c)],
                        Err(e) => {
                            self.input = line.to_string();
                            self.status = Some(e);
                        }
                    }
                } else if let Some(why) = ended {
                    // Nobody would get it: say why, and keep the words.
                    self.input = line.to_string();
                    self.status = Some(ended_hint(why).into());
                } else if let Some(g) = self.selected {
                    self.scroll = 0;
                    return vec![Action::Send(g, line.to_string())];
                } else {
                    self.input = line.to_string();
                    self.status = Some("Pick a chat first, or start one with /new <name>.".into());
                }
            }
            _ => {}
        }
        vec![]
    }

    /// A paste, which the terminal hands over as one piece of text. It
    /// goes into the message box as typed text, line breaks included, and
    /// nothing is sent or run until Enter. An open box closes first; a
    /// question it asked counts as answered no.
    pub fn handle_paste(&mut self, text: &str) -> Vec<Action> {
        self.status = None;
        self.completion = None;
        self.tab_cycle = None;
        self.hint = None;
        let text = pasted(text);
        if let Some(q) = &mut self.switcher {
            q.push_str(&text.replace('\n', " "));
            return vec![];
        }
        self.modal = None;
        self.focus = Focus::Input;
        // The box holds at most what one message can carry.
        let fits = cut_to(&text, MAX_TEXT_BYTES.saturating_sub(self.input.len()));
        if fits.len() < text.len() {
            self.status = Some("The paste was cut to 16 KB, the most one message holds.".into());
        }
        self.input.push_str(fits);
        vec![]
    }
}
