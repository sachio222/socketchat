//! The screen's state and what each key does. No drawing, no network:
//! keys go in, actions come out, and the run loop carries them out.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use socketchat_core::keys::Key;
use socketchat_proto::msg::GroupId;

use crate::commands::{parse_command, Command};
use crate::ui::ViewModel;

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
    Help,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Send(GroupId, String),
    Command(Command),
    Select(GroupId),
    ConfirmVideo(String),
    MarkVerified(Key),
    /// Put this text on the terminal's clipboard.
    Copy(String),
    Quit,
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
        }
    }

    /// Chats whose names contain the switcher's text, in list order.
    pub fn switcher_matches<'a>(&self, vm: &'a ViewModel) -> Vec<&'a crate::ui::GroupView> {
        let q = self.switcher.as_deref().unwrap_or("").to_lowercase();
        vm.groups
            .iter()
            .filter(|g| g.name.to_lowercase().contains(&q))
            .collect()
    }

    pub fn handle_key(&mut self, k: KeyEvent, vm: &ViewModel) -> Vec<Action> {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && k.code == KeyCode::Char('c') {
            return vec![Action::Quit];
        }
        if let Some(m) = &self.modal {
            let yes = matches!(k.code, KeyCode::Char('y' | 'Y'));
            let act = match (m, yes) {
                (Modal::Verify { key, .. }, true) => Some(Action::MarkVerified(*key)),
                (Modal::ConfirmVideo { path }, true) => Some(Action::ConfirmVideo(path.clone())),
                (Modal::Invite { link, .. }, _) if matches!(k.code, KeyCode::Char('c' | 'C')) => {
                    self.status =
                        Some("Link copied. Paste it to the person you are inviting.".into());
                    return vec![Action::Copy(link.clone())];
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
            return act.into_iter().collect();
        }
        if let Some(q) = &mut self.switcher {
            match k.code {
                KeyCode::Esc => self.switcher = None,
                KeyCode::Backspace => {
                    q.pop();
                }
                KeyCode::Char(c) if !ctrl => q.push(c),
                KeyCode::Enter => {
                    let pick = self.switcher_matches(vm).first().map(|g| g.id);
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
                if line.starts_with('/') {
                    match parse_command(line) {
                        Ok(c) => return vec![Action::Command(c)],
                        Err(e) => {
                            self.input = line.to_string();
                            self.status = Some(e);
                        }
                    }
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
