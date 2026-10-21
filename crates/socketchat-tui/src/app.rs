//! The screen's state and what each key does. No drawing, no network:
//! keys go in, actions come out, and the run loop carries them out.

use std::cell::Cell;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use socketchat_core::client::{Ended, RoomDetails};
use socketchat_core::invite::hours_text;
use socketchat_core::keys::Key;
use socketchat_proto::msg::GroupId;
use socketchat_proto::Token;

use crate::commands::{parse_command, Command};
use crate::ui::{GroupView, ViewModel};

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
    },
    Verify {
        name: String,
        key: Key,
        number: String,
    },
    ConfirmVideo {
        path: String,
    },
    /// A link names a server already in use, with a different certificate.
    /// Fingerprints are shown as text, ready to compare.
    NewCertificate {
        link: String,
        host: String,
        pinned: String,
        offered: String,
    },
    /// A question answered with y or n; `yes` runs on y.
    Confirm {
        question: String,
        yes: Box<Action>,
    },
    /// The person's open invite links, one row each, numbered for
    /// `/cancel`, scrolled down by `offset` rows.
    Invites {
        rows: Vec<String>,
        offset: usize,
    },
    Details {
        lines: Vec<String>,
    },
    /// The command list, scrolled down by `offset` rows.
    Help {
        offset: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Send(GroupId, String),
    Command(Command),
    Select(GroupId),
    ConfirmVideo(String),
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

/// The room `/switch <text>` opens: the one whose name is the text
/// (ignoring case), else the first in list order whose name starts with
/// it, else the first whose name contains it.
pub fn pick_room<'a>(text: &str, groups: &'a [GroupView]) -> Option<&'a GroupView> {
    let t = text.trim().to_lowercase();
    let name = |g: &GroupView| g.name.to_lowercase();
    groups
        .iter()
        .find(|g| name(g) == t)
        .or_else(|| groups.iter().find(|g| name(g).starts_with(&t)))
        .or_else(|| groups.iter().find(|g| name(g).contains(&t)))
}

/// The rooms Tab cycles through for `text`, in list order: names that
/// start with it (ignoring case), or else names that contain it. Nothing
/// typed matches every room.
fn completions<'a>(text: &str, groups: &'a [GroupView]) -> Vec<&'a GroupView> {
    let t = text.to_lowercase();
    let starts: Vec<&GroupView> = groups
        .iter()
        .filter(|g| g.name.to_lowercase().starts_with(&t))
        .collect();
    if !starts.is_empty() {
        return starts;
    }
    groups
        .iter()
        .filter(|g| g.name.to_lowercase().contains(&t))
        .collect()
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
    /// The links the last `/invites` box listed; `/cancel <n>` takes the
    /// nth. A cancelled link keeps its number and becomes `None`.
    pub invite_tokens: Vec<Option<Token>>,
    /// Set as a scrolling box (help or invite links) is drawn: the
    /// furthest it can scroll, and how many rows it shows at once.
    pub(crate) box_scroll: Cell<(usize, usize)>,
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
        .find(|g| g.id == *id && g.name == text.trim())
        .map(|g| g.id)
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
            invite_tokens: Vec::new(),
            box_scroll: Cell::new((0, 0)),
        }
    }

    /// The room Enter in the switcher opens, which the switcher highlights.
    pub fn switcher_pick(&self, vm: &ViewModel) -> Option<GroupId> {
        let q = self.switcher.as_deref().unwrap_or("");
        tab_pick(&self.completion, q, vm).or_else(|| pick_room(q, &vm.groups).map(|g| g.id))
    }

    /// Chats whose names contain the switcher's text, in list order.
    pub fn switcher_matches<'a>(&self, vm: &'a ViewModel) -> Vec<&'a crate::ui::GroupView> {
        let q = self.switcher.as_deref().unwrap_or("").to_lowercase();
        vm.groups
            .iter()
            .filter(|g| g.name.to_lowercase().contains(&q))
            .collect()
    }

    /// The room name Tab puts in place of `typed`: each further Tab moves
    /// to the next match and wraps round.
    fn complete(&mut self, typed: &str, vm: &ViewModel) -> Option<String> {
        let (typed, next) = match self.completion.take() {
            Some((t, i, _)) => (t, i + 1),
            None => (typed.to_string(), 0),
        };
        let matches = completions(&typed, &vm.groups);
        if matches.is_empty() {
            self.status = Some(no_room(&typed));
            return None;
        }
        let i = next % matches.len();
        let (name, id) = (matches[i].name.clone(), matches[i].id);
        self.completion = Some((typed, i, id));
        Some(name)
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
            (Modal::Confirm { yes, .. }, true) => Some(*yes),
            // Anything but y is no: a stray y later in a word must not
            // confirm. Other letters go on into the message box.
            (Modal::Confirm { .. }, false) => {
                self.modal = None;
                let no = matches!(k.code, KeyCode::Char('n' | 'N'));
                return if typing && !no { None } else { Some(vec![]) };
            }
            (Modal::Verify { key, .. }, true) => Some(Action::MarkVerified(key)),
            (Modal::ConfirmVideo { path }, true) => Some(Action::ConfirmVideo(path)),
            (Modal::NewCertificate { link, .. }, true) => Some(Action::AcceptCertificate(link)),
            (Modal::Invite { link, .. }, _) if matches!(k.code, KeyCode::Char('c' | 'C')) => {
                self.status = Some("Link copied. Paste it to the person you are inviting.".into());
                return Some(vec![Action::Copy(link)]);
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
                self.input.push(c);
            }
            KeyCode::Enter => {
                let line = std::mem::take(&mut self.input);
                let line = line.trim();
                if line.is_empty() {
                    return vec![];
                }
                self.status = None;
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
}
