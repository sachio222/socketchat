//! The live screen: draws, reads keys, and carries out what they ask.

use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{self, Event as TermEvent, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use socketchat_core::client::{Client, Event, GroupSummary, Verification};
use socketchat_core::close::{close_needed, CloseOutcome};
use socketchat_core::keys::{fingerprint_text, Key};
use socketchat_core::CoreError;
use socketchat_proto::msg::GroupId;
use socketchat_proto::InviteLink;
use tokio::sync::mpsc;

use crate::app::{
    details_lines, ended_hint, invite_row, leave_step, sent_file_status, Action, App, LeaveStep,
    Modal,
};
use crate::commands::Command;
use crate::ui::{draw, fit, GroupView, LineView, MemberLine, ViewModel};

/// How often the screen checks in with the server when nothing arrives.
const IDLE_SYNC: Duration = Duration::from_secs(5);

/// A request to a server that waits for the next draw, so the screen says
/// it is asking instead of standing still.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pending {
    Details(GroupId),
    Invites,
}

struct Screen {
    client: Client,
    app: App,
    quit: bool,
    /// The status line says the connection dropped; the next good sync
    /// clears it.
    offline_note: bool,
    /// The room whose unread messages `/leave` has shown, so the next
    /// `/leave` asks to leave.
    leave_shown: Option<GroupId>,
    /// Rooms whose "closed" status the `Left` event that follows keeps.
    closed_note: HashSet<GroupId>,
    pending: Option<Pending>,
}

/// What the status line says when an action fails because the connection
/// dropped. The app reconnects on its own at the next sync.
const OFFLINE_NOTE: &str = "Lost the connection to the server. socketchat is reconnecting.";

/// The status line while a request waits for the server.
const ASKING: &str = "Asking the server…";

fn local_time(unix: u64) -> String {
    clock_time(unix, &chrono::Local)
}

/// The time of day `unix` falls on in `tz`, as a 24-hour clock with
/// seconds (HH:MM:SS).
fn clock_time<Tz: chrono::TimeZone>(unix: u64, tz: &Tz) -> String
where
    Tz::Offset: std::fmt::Display,
{
    chrono::DateTime::from_timestamp(unix as i64, 0)
        .map(|t| t.with_timezone(tz).format("%H:%M:%S").to_string())
        .unwrap_or_default()
}

/// The local date `unix` falls on, as YYYY-MM-DD.
fn local_date(unix: u64) -> String {
    chrono::DateTime::from_timestamp(unix as i64, 0)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%Y-%m-%d")
                .to_string()
        })
        .unwrap_or_default()
}

fn expand(path: &str) -> PathBuf {
    match (path.strip_prefix("~/"), directories::BaseDirs::new()) {
        (Some(rest), Some(b)) => b.home_dir().join(rest),
        _ => PathBuf::from(path),
    }
}

/// Puts text on the clipboard through the terminal (OSC 52), which works
/// in most terminals and over SSH.
fn copy_to_clipboard(text: &str) {
    let b64 = to_base64(text.as_bytes());
    let mut out = std::io::stdout();
    let _ = write!(out, "\x1b]52;c;{b64}\x07");
    let _ = out.flush();
}

fn to_base64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// The room an event is about, if it is about one.
fn event_group(e: &Event) -> Option<GroupId> {
    match e {
        Event::Joined { group, .. }
        | Event::JoinRequestHandled { group }
        | Event::Message { group, .. }
        | Event::MembersChanged { group }
        | Event::GroupRenamed { group }
        | Event::NameChanged { group, .. }
        | Event::Left { group, .. }
        | Event::FileOffered { group, .. }
        | Event::Extension { group, .. }
        | Event::CloseVote { group, .. }
        | Event::Closed { group, .. } => Some(*group),
        Event::Warning(_) | Event::Disconnected | Event::Reconnected => None,
    }
}

impl Screen {
    fn new(client: Client) -> Screen {
        Screen {
            client,
            app: App::new(),
            quit: false,
            offline_note: false,
            leave_shown: None,
            closed_note: HashSet::new(),
            pending: None,
        }
    }

    /// A room's name as the list shows it: a direct chat without a name
    /// goes by the other people in it.
    fn shown_name(&self, g: &GroupSummary) -> String {
        if !g.name.is_empty() {
            return g.name.clone();
        }
        let others = self
            .client
            .members(g.id)
            .into_iter()
            .filter(|m| !m.me)
            .map(|m| m.name)
            .collect::<Vec<_>>()
            .join(", ");
        if !others.is_empty() {
            others
        } else if g.ended.is_some() && g.is_dm {
            "Direct chat".into()
        } else {
            "(waiting for people)".into()
        }
    }

    fn summary(&self, g: GroupId) -> Option<GroupSummary> {
        self.client.groups().into_iter().find(|x| x.id == g)
    }

    /// The name of room `g` for a status line.
    fn room_name(&self, g: GroupId) -> String {
        self.summary(g)
            .map(|s| self.shown_name(&s))
            .unwrap_or_else(|| "this room".into())
    }

    /// The open room, if this person is still in it.
    fn live_room(&self) -> Result<GroupId, String> {
        let g = self.app.selected.ok_or("Open a chat first.")?;
        match self.summary(g).and_then(|s| s.ended) {
            Some(why) => Err(ended_hint(why).into()),
            None => Ok(g),
        }
    }

    fn view(&self) -> ViewModel {
        let groups: Vec<GroupView> = self
            .client
            .groups()
            .into_iter()
            .map(|g| GroupView {
                id: g.id,
                name: self.shown_name(&g),
                unread: g.unseen,
                is_dm: g.is_dm,
                muted: g.muted,
                ended: g.ended,
            })
            .collect();
        let (lines, members) = match self.app.selected {
            Some(g) => (
                self.client
                    .messages(g, 300)
                    .into_iter()
                    .map(|l| LineView {
                        time: local_time(l.sent_unix),
                        mine: l.sender_key.is_some() && l.sender_key == self.client.my_group_key(g),
                        sender: l.sender,
                        text: l.text,
                        notice: l.notice,
                    })
                    .collect(),
                self.client
                    .members(g)
                    .into_iter()
                    .map(|m| MemberLine {
                        key: m.key,
                        name: m.name,
                        verified: m.verified,
                        admin: m.admin,
                        me: m.me,
                    })
                    .collect(),
            ),
            None => (vec![], vec![]),
        };
        ViewModel {
            me: self.client.display_name().to_string(),
            groups,
            lines,
            members,
            connected: self.client.connected(),
        }
    }

    /// Marks the open room's messages seen: they are on screen.
    fn mark_seen(&mut self, g: GroupId) {
        if let Err(e) = self.client.mark_seen(g) {
            self.app.status.get_or_insert(e.to_string());
        }
    }

    /// Opens room `g`. Ended rooms that are read go from this computer,
    /// except the one now open.
    fn select(&mut self, g: GroupId) {
        if self.app.selected != Some(g) {
            // A warning is about the room it came with.
            self.app.warning = None;
            self.leave_shown = None;
        }
        self.app.selected = Some(g);
        self.app.scroll = 0;
        self.mark_seen(g);
        self.client.purge_read(Some(g));
    }

    /// Marks the open room seen when its newest line is on screen.
    fn seen_if_at_bottom(&mut self) {
        let Some(g) = self.app.selected else {
            return;
        };
        if self.app.scroll == 0 && self.summary(g).is_some_and(|s| s.unseen > 0) {
            self.mark_seen(g);
        }
    }

    /// Opens the first room this person is still in, or else the first
    /// room listed.
    fn select_first(&mut self) {
        let groups = self.client.groups();
        let first = groups
            .iter()
            .find(|g| g.ended.is_none())
            .or(groups.first())
            .map(|g| g.id);
        self.app.selected = None;
        match first {
            Some(g) => self.select(g),
            None => {
                self.client.purge_read(None);
            }
        }
    }

    /// The member called `name` in the open chat. `name#abcd` picks one of
    /// several people with the same name by the start of their key.
    fn member(&self, name: &str) -> Result<Key, String> {
        let g = self.app.selected.ok_or("Open a chat first.")?;
        let (name, tag) = match name.rsplit_once('#') {
            Some((n, t)) if t.len() >= 2 && t.chars().all(|c| c.is_ascii_hexdigit()) => {
                (n, Some(t.to_lowercase()))
            }
            _ => (name, None),
        };
        let hits: Vec<_> = self
            .client
            .members(g)
            .into_iter()
            .filter(|m| !m.me && m.name.eq_ignore_ascii_case(name.trim()))
            .filter(|m| {
                tag.as_ref().is_none_or(|t| {
                    let hex: String = m.key.0.iter().map(|b| format!("{b:02x}")).collect();
                    hex.starts_with(t.as_str())
                })
            })
            .collect();
        match hits.len() {
            1 => Ok(hits[0].key),
            0 => Err(format!("Nobody called {name} is in this chat.")),
            _ => Err(format!(
                "More than one person here is called {name}. Add the start of their key, like {name}#{}.",
                hits[0].key.0[..2].iter().map(|b| format!("{b:02x}")).collect::<String>()
            )),
        }
    }

    fn on_event(&mut self, e: Event) {
        let about = event_group(&e);
        match e {
            Event::Joined {
                group,
                verification,
            } => {
                self.select(group);
                if let Verification::Unverified { reason } = verification {
                    self.app.warning = Some(format!(
                        "You joined, but the invite could not be checked: {reason}. Compare safety numbers with /verify before you trust anyone here."
                    ));
                } else {
                    self.app.status =
                        Some("You joined. The person who invited you is verified.".into());
                }
            }
            Event::Left { group, name } => {
                // "Closed" already said why.
                if !self.closed_note.remove(&group) {
                    let text = if name.is_empty() {
                        "You are no longer in that chat.".into()
                    } else {
                        format!("You are no longer in {name}.")
                    };
                    self.tell(group, text);
                }
            }
            Event::Closed { group, name, by } => {
                self.closed_note.insert(group);
                let name = if name.is_empty() {
                    "this room".to_string()
                } else {
                    name
                };
                self.tell(group, format!("{by} closed {name}."));
            }
            Event::CloseVote { group, .. } if Some(group) == self.app.selected => {
                // The vote's notice is the newest notice in the room.
                if let Some(l) = self
                    .client
                    .messages(group, 20)
                    .into_iter()
                    .rev()
                    .find(|l| l.notice)
                {
                    self.app.status = Some(l.text);
                }
            }
            Event::Warning(w) => self.app.status = Some(w),
            Event::NameChanged { old, new, .. } => {
                self.app.status = Some(format!("{old} is now called {new}."));
            }
            _ => {}
        }
        let groups = self.client.groups();
        let open = self
            .app
            .selected
            .filter(|g| groups.iter().any(|x| x.id == *g));
        match open {
            // What arrived for the open room is on screen, unless the
            // person has scrolled up.
            Some(g) if about == Some(g) && self.app.scroll == 0 => self.mark_seen(g),
            Some(_) => {}
            // The open room is gone from this computer.
            None => self.select_first(),
        }
    }

    /// Says how room `g` ended: on the open room, which stays on screen,
    /// as a warning that stays until the person moves on; otherwise on
    /// the status line.
    fn tell(&mut self, g: GroupId, text: String) {
        if Some(g) == self.app.selected && self.summary(g).is_some() {
            self.app.warning = Some(text);
        } else {
            self.app.status = Some(text);
        }
    }

    /// Handles the events an action queued at once, so its own status is
    /// the one that shows. Returns the warnings among them.
    fn take_events(&mut self) -> Vec<String> {
        let mut said = Vec::new();
        for ev in self.client.take_events() {
            match ev {
                Event::Warning(w) => said.push(w),
                ev => self.on_event(ev),
            }
        }
        said
    }

    /// Shows `status` after any warnings the action raised.
    fn say_after_events(&mut self, status: String) {
        let mut said = self.take_events();
        said.push(status);
        self.app.status = Some(said.join(" "));
    }

    /// Shows an action's error on the status line.
    fn report(&mut self, r: Result<(), String>) {
        if let Err(e) = r {
            if self.client.connected() {
                self.app.status = Some(e);
            } else {
                self.app.status = Some(OFFLINE_NOTE.into());
                self.offline_note = true;
            }
        }
    }

    async fn act(&mut self, a: Action) {
        // `/leave` shows new lines once; anything else in between, and the
        // next `/leave` checks again.
        if matches!(&a, Action::Send(..) | Action::Command(_))
            && a != Action::Command(Command::Leave)
        {
            self.leave_shown = None;
        }
        let r: Result<(), String> = match a {
            Action::Quit => {
                self.quit = true;
                Ok(())
            }
            Action::Select(g) => {
                self.select(g);
                Ok(())
            }
            Action::Copy(text) => {
                copy_to_clipboard(&text);
                Ok(())
            }
            Action::Send(g, text) => match self.client.send_text(g, &text).await {
                Ok(()) => Ok(()),
                Err(e) => {
                    // Nothing was sent: give the words back to edit or retry.
                    if self.app.input.is_empty() {
                        self.app.input = text;
                    }
                    Err(e.to_string())
                }
            },
            Action::ConfirmVideo(path) => match self.app.selected {
                Some(g) => self
                    .client
                    .send_file(g, &expand(&path), true)
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
                None => Err("Open a chat first.".into()),
            },
            Action::AcceptCertificate(link) => self.join(&link, true).await,
            Action::MarkVerified(key) => match self.app.selected {
                Some(g) => self
                    .client
                    .mark_verified(g, &key)
                    .map(|_| self.app.status = Some("Marked as verified.".into()))
                    .map_err(|e| e.to_string()),
                None => Ok(()),
            },
            Action::CloseRoom(g) => self.close_room(g).await,
            Action::LeaveRoom(g) => {
                let room = self.room_name(g);
                match self.client.leave(g).await {
                    Ok(()) => {
                        self.say_after_events(format!(
                            "You left {room}. Its messages are deleted from this computer."
                        ));
                        Ok(())
                    }
                    Err(e) => Err(e.to_string()),
                }
            }
            Action::ClearRoom(g) => {
                let room = self.room_name(g);
                match self.client.clear_history(g) {
                    Ok(()) => {
                        self.app.scroll = 0;
                        // An ended room goes from the list with its messages.
                        if self.summary(g).is_none() {
                            self.select_first();
                        }
                        self.say_after_events(format!(
                            "Deleted {room}'s messages from this computer."
                        ));
                        Ok(())
                    }
                    Err(e) => Err(e.to_string()),
                }
            }
            Action::Command(c) => self.command(c).await,
        };
        self.report(r);
    }

    /// Votes yes on closing room `g` and says where the request stands.
    async fn close_room(&mut self, g: GroupId) -> Result<(), String> {
        let room = self.room_name(g);
        let said = match self.client.vote_close(g, true).await {
            Ok(CloseOutcome::Closed) => {
                self.say_after_events(format!("Closed {room}."));
                // The status says it; the room's hint says the rest.
                self.app.warning = None;
                return Ok(());
            }
            Ok(CloseOutcome::Waiting { yes, needed }) => {
                format!("Asked. {yes} of {needed} admins agree so far.")
            }
            Ok(CloseOutcome::Kept) => {
                "This room stays open: too few admins agreed to close it.".into()
            }
            Err(e) => return Err(e.to_string()),
        };
        self.say_after_events(said);
        Ok(())
    }

    /// Uses an invite link. A link with a new certificate for a server in
    /// use opens a box that asks first; `new_certificate` is the answer.
    async fn join(&mut self, link: &str, new_certificate: bool) -> Result<(), String> {
        let parsed: InviteLink = link
            .parse()
            .map_err(|x: socketchat_proto::LinkError| x.to_string())?;
        let r = if new_certificate {
            self.client.join_new_certificate(&parsed).await
        } else {
            self.client.join(&parsed).await
        };
        let st = match r {
            Ok(st) => st,
            Err(CoreError::NewCertificate {
                host,
                pinned,
                offered,
                ..
            }) => {
                self.app.modal = Some(Modal::NewCertificate {
                    link: link.to_string(),
                    host: socketchat_core::sanitize::clean_name(&host),
                    pinned: fingerprint_text(&pinned),
                    offered: fingerprint_text(&offered),
                });
                return Ok(());
            }
            Err(e) => return Err(e.to_string()),
        };
        self.say_after_events(match st {
            socketchat_core::client::JoinStatus::Registered => {
                "You are on the server. Start a chat with /new <name>.".into()
            }
            socketchat_core::client::JoinStatus::Waiting { for_name } => {
                format!("Asked to join. Waiting for {for_name}.")
            }
        });
        Ok(())
    }

    async fn command(&mut self, c: Command) -> Result<(), String> {
        let sel = self.app.selected;
        let live = self.live_room();
        let need = || live.clone();
        let e = |e: CoreError| e.to_string();
        match c {
            Command::Quit => self.quit = true,
            Command::Help => self.app.modal = Some(Modal::Help { offset: 0 }),
            // The keys open the switcher or the room before this is reached.
            Command::Switch(_) => {}
            Command::Invite { dm } => {
                let (link, expires_unix) = if dm {
                    self.client.invite(None, true).await.map_err(e)?
                } else {
                    self.client.invite(Some(need()?), false).await.map_err(e)?
                };
                self.app.modal = Some(Modal::Invite {
                    link: link.to_string(),
                    hours: self.client.hours_until(expires_unix),
                });
            }
            Command::Join(link) => self.join(&link, false).await?,
            Command::New(name) => {
                let g = self.client.create_group(&name).await.map_err(e)?;
                self.select(g);
            }
            Command::Dm(name) => {
                let shared = need()?;
                let k = self.member(&name)?;
                let g = self.client.dm(shared, &k).await.map_err(e)?;
                self.app.status = Some(format!("Asked {name} to open a direct chat."));
                self.select(g);
            }
            Command::Send(path) => {
                match self.client.send_file(need()?, &expand(&path), false).await {
                    Err(CoreError::VideoNeedsConfirm) => {
                        self.app.modal = Some(Modal::ConfirmVideo { path })
                    }
                    r => {
                        if let Some(said) = sent_file_status(&r.map_err(e)?) {
                            self.app.status = Some(said);
                        }
                    }
                }
            }
            Command::Save { file, dir } => {
                let g = need()?;
                let offer = self
                    .client
                    .files(g)
                    .into_iter()
                    .rev()
                    .find(|f| f.name == file)
                    .ok_or_else(|| format!("No file called {file} in this chat."))?;
                let dir = match dir {
                    Some(d) => expand(&d),
                    None => directories::UserDirs::new()
                        .and_then(|u| u.download_dir().map(PathBuf::from))
                        .unwrap_or_else(|| PathBuf::from(".")),
                };
                let saved = self.client.save_file(g, offer.id, &dir).await.map_err(e)?;
                self.app.status = Some(format!("Saved to {}", saved.display()));
            }
            Command::Verify(name) => {
                let g = need()?;
                let k = self.member(&name)?;
                let number = self.client.safety_number(g, &k).ok_or_else(|| {
                    format!("{name} has not shared their identity yet. Try again in a moment.")
                })?;
                self.app.modal = Some(Modal::Verify {
                    name,
                    key: k,
                    number,
                });
            }
            Command::Rename { name, new } => {
                let g = need()?;
                let k = self.member(&name)?;
                self.client.rename_local(g, &k, &new).map_err(e)?;
            }
            Command::Name(new) => self.client.set_display_name(&new).await.map_err(e)?,
            Command::Kick(name) => {
                let g = need()?;
                let k = self.member(&name)?;
                self.client.remove_member(g, &k).await.map_err(e)?;
            }
            Command::Admin(name) => {
                let g = need()?;
                let k = self.member(&name)?;
                self.client.make_admin(g, &k).await.map_err(e)?;
            }
            Command::Leave => {
                let g = need()?;
                let room = self.room_name(g);
                let unseen = self.summary(g).map(|s| s.unseen).unwrap_or(0);
                match leave_step(unseen, self.leave_shown == Some(g)) {
                    LeaveStep::ShowUnseen(n) => {
                        // Leaving deletes them: show them first.
                        self.leave_shown = Some(g);
                        self.select(g);
                        let messages = if n == 1 { "message" } else { "messages" };
                        self.app.status = Some(format!(
                            "You have {n} new {messages} in {room}. Read them, then type /leave again to leave."
                        ));
                    }
                    LeaveStep::Confirm => {
                        self.app.modal = Some(Modal::Confirm {
                            question: format!("Leave {room}? Its messages and files list are deleted from this computer. Press y to leave or n to stay."),
                            yes: Box::new(Action::LeaveRoom(g)),
                        });
                    }
                }
            }
            Command::Title(name) => self.client.rename_room(need()?, &name).await.map_err(e)?,
            Command::Close => {
                let g = need()?;
                let room = self.room_name(g);
                let members = self.client.members(g);
                if !members.iter().any(|m| m.me && m.admin) {
                    return Err("Only admins can close this room.".into());
                }
                let admins = members.iter().filter(|m| m.admin).count();
                let open = self.client.close_state(g).filter(|c| c.yes > 0 && !c.kept);
                let question = match open {
                    // This admin already said yes: say where it stands.
                    Some(c) if c.my_vote == Some(true) => {
                        self.app.status = Some(format!(
                            "Asked. {} of {} admins agree so far.",
                            c.yes, c.needed
                        ));
                        return Ok(());
                    }
                    Some(c) => format!(
                        "{} asked to close {room}. Agree? Press y to agree or n to cancel.",
                        c.asked_by
                    ),
                    None if admins <= 1 => format!("Close {room}? Everyone is removed, and each app deletes the room's messages once they are read. Press y to close or n to keep it."),
                    None => format!(
                        "Ask the other admins to close {room}? It closes when {} of {admins} admins agree. Press y to ask or n to cancel.",
                        close_needed(admins)
                    ),
                };
                self.app.modal = Some(Modal::Confirm {
                    question,
                    yes: Box::new(Action::CloseRoom(g)),
                });
            }
            Command::Keep => {
                let g = need()?;
                let room = self.room_name(g);
                self.client.vote_close(g, false).await.map_err(e)?;
                self.say_after_events(format!("You said to keep {room} open."));
            }
            Command::Invites => {
                self.pending = Some(Pending::Invites);
                self.app.status = Some(ASKING.into());
            }
            Command::Cancel(n) => {
                let slot = n
                    .checked_sub(1)
                    .and_then(|i| self.app.invite_tokens.get(i).map(|t| (i, *t)))
                    .ok_or("Type /invites first, then /cancel with a number from that list.")?;
                let (i, token) = match slot {
                    (i, Some(token)) => (i, token),
                    (_, None) => return Err("That link is already cancelled.".into()),
                };
                self.client.cancel_invite(token).await.map_err(e)?;
                // The numbers stay as the box showed them.
                self.app.invite_tokens[i] = None;
                self.app.status = Some("Cancelled. That link no longer works.".into());
            }
            Command::Mute | Command::Unmute => {
                let g = need()?;
                let room = self.room_name(g);
                let mute = c == Command::Mute;
                self.client.set_muted(g, mute).map_err(e)?;
                self.app.status = Some(if mute {
                    format!("Muted {room}. New messages there no longer show a count.")
                } else {
                    format!("Unmuted {room}.")
                });
            }
            Command::Details => {
                self.pending = Some(Pending::Details(need()?));
                self.app.status = Some(ASKING.into());
            }
            Command::Clear => {
                let g = sel.ok_or("Open a chat first.")?;
                let room = self.room_name(g);
                self.app.modal = Some(Modal::Confirm {
                    question: format!("Delete {room}'s messages from this computer? Other members keep theirs. Press y to delete or n to keep them."),
                    yes: Box::new(Action::ClearRoom(g)),
                });
            }
        }
        Ok(())
    }

    /// Makes the request that waited for a draw, and shows its box.
    async fn run_pending(&mut self) {
        let Some(p) = self.pending.take() else {
            return;
        };
        let r = match p {
            Pending::Invites => self.show_invites().await,
            Pending::Details(g) => self.show_details(g).await,
        };
        if self.app.status.as_deref() == Some(ASKING) {
            self.app.status = None;
        }
        self.report(r);
    }

    async fn show_invites(&mut self) -> Result<(), String> {
        let list = self.client.invites().await.map_err(|e| e.to_string())?;
        // A server that could not be asked says so on the status line.
        let said = self.take_events();
        if !said.is_empty() {
            self.app.status = Some(said.join(" "));
        }
        self.app.invite_tokens = list.iter().map(|i| Some(i.token)).collect();
        let rows = if list.is_empty() {
            vec!["You have no open invite links.".into()]
        } else {
            list.iter()
                .enumerate()
                .map(|(i, v)| {
                    invite_row(
                        i + 1,
                        &fit(&v.label, 40),
                        self.client.hours_until(v.expires_unix),
                    )
                })
                .collect()
        };
        self.app.modal = Some(Modal::Invites { rows, offset: 0 });
        Ok(())
    }

    async fn show_details(&mut self, g: GroupId) -> Result<(), String> {
        let name = self.room_name(g);
        let d = self.client.details(g).await.map_err(|e| e.to_string())?;
        let server_dates = self.client.protocol_for(g).is_some_and(|p| p >= 2);
        self.app.modal = Some(Modal::Details {
            lines: details_lines(&d, &name, server_dates, &local_date),
        });
        Ok(())
    }

    async fn sync(&mut self) {
        let r = self.client.sync().await;
        // A dropped connection is routine (the server closes idle ones):
        // the header shows it, and this sync has already reconnected or
        // will at the next one, so the note about it goes once it is back.
        if self.offline_note && self.client.connected() {
            self.offline_note = false;
            if self.app.status.as_deref() == Some(OFFLINE_NOTE) {
                self.app.status = None;
            }
        }
        if let Err(e) = r {
            self.app.status = Some(e.to_string());
        }
        for ev in self.client.take_events() {
            self.on_event(ev);
        }
    }

    /// On the way out: ended rooms that are read go from this computer.
    fn finish(&mut self) {
        self.client.purge_read(None);
    }
}

/// Reads keys on a plain thread and hands them to the async loop.
fn key_reader() -> mpsc::UnboundedReceiver<Option<KeyEvent>> {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || loop {
        match event::poll(Duration::from_millis(200)) {
            Ok(true) => match event::read() {
                Ok(TermEvent::Key(k)) if k.kind == KeyEventKind::Press => {
                    if tx.send(Some(k)).is_err() {
                        return;
                    }
                }
                // A resize only needs a redraw.
                Ok(TermEvent::Resize(..)) if tx.send(None).is_err() => return,
                _ => {}
            },
            Ok(false) if tx.is_closed() => return,
            Ok(false) => {}
            Err(_) => return,
        }
    });
    rx
}

/// Opens the chat screen and runs it until the person quits.
pub async fn run(client: Client) -> std::io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let result = run_inner(client).await;
    disable_raw_mode()?;
    execute!(std::io::stdout(), LeaveAlternateScreen)?;
    result
}

async fn run_inner(client: Client) -> std::io::Result<()> {
    let mut term = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
    let mut s = Screen::new(client);
    s.select_first();
    let exit_after_draw = std::env::var_os("SOCKETCHAT_EXIT_AFTER_DRAW").is_some();
    let mut keys = key_reader();
    let mut first = true;
    loop {
        let vm = s.view();
        term.draw(|f| draw(f, &s.app, &vm))?;
        if exit_after_draw {
            return Ok(());
        }
        // The screen now says it is asking; the answer draws next.
        if s.pending.is_some() {
            s.run_pending().await;
            continue;
        }
        if first {
            first = false;
            s.sync().await;
            continue;
        }
        tokio::select! {
            k = keys.recv() => match k {
                Some(Some(k)) => {
                    for a in s.app.handle_key(k, &vm) {
                        s.act(a).await;
                    }
                    // Scrolled back down: the newest lines are on screen.
                    s.seen_if_at_bottom();
                }
                Some(None) => {}
                None => {
                    s.finish();
                    return Ok(());
                }
            },
            _ = s.client.wait(IDLE_SYNC) => s.sync().await,
        }
        if s.quit {
            s.finish();
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{clock_time, to_base64, Action, Screen};
    use crate::app::Modal;
    use crate::commands::Command;
    use socketchat_core::client::{Client, Ended};
    use socketchat_proto::msg::GroupId;

    #[tokio::test]
    async fn text_that_fails_to_send_goes_back_in_the_box() {
        let dir = tempfile::tempdir().unwrap();
        let client = Client::create_profile(dir.path(), "test passphrase", "Ada")
            .await
            .unwrap();
        let mut s = Screen::new(client);
        s.act(Action::Send(GroupId([1; 16]), "hello there".into()))
            .await;
        assert_eq!(s.app.input, "hello there");
        assert!(s.app.status.is_some());
    }

    #[test]
    fn chat_times_show_seconds_on_a_24_hour_clock() {
        // 2026-10-19 21:04:05 UTC, shown two hours east of UTC.
        let tz = chrono::FixedOffset::east_opt(2 * 3600).unwrap();
        assert_eq!(clock_time(1_792_443_845, &tz), "23:04:05");
        let utc = chrono::FixedOffset::east_opt(0).unwrap();
        assert_eq!(clock_time(1_792_443_845, &utc), "21:04:05");
        assert_eq!(clock_time(9, &utc), "00:00:09");
    }

    #[test]
    fn base64_matches_known_values() {
        assert_eq!(to_base64(b""), "");
        assert_eq!(to_base64(b"f"), "Zg==");
        assert_eq!(to_base64(b"fo"), "Zm8=");
        assert_eq!(to_base64(b"foo"), "Zm9v");
        assert_eq!(to_base64(b"socketchat://x"), "c29ja2V0Y2hhdDovL3g=");
    }

    // ---------- against a real server ----------

    use socketchat_testkit::{passphrase, settle, TestClient, TestServer};

    /// A screen for a new profile with an account on `s`. The profile's
    /// folder lives as long as the screen's test.
    async fn screen(s: &TestServer, name: &str) -> (Screen, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut client = Client::create_profile(dir.path(), passphrase(), name)
            .await
            .unwrap();
        client.join(&s.server_invite()).await.unwrap();
        (Screen::new(client), dir)
    }

    /// Ada's room "Room", with Bo (on a screen) in it.
    async fn room_with_bo(s: &TestServer) -> (GroupId, TestClient, Screen, tempfile::TempDir) {
        let mut a = TestClient::new(s, "Ada").await;
        let g = a.create_group("Room").await.unwrap();
        let (mut bo, dir) = screen(s, "Bo").await;
        let link = a.invite(Some(g), false).await.unwrap().0;
        bo.client.join(&link).await.unwrap();
        for _ in 0..4 {
            a.sync().await.unwrap();
            bo.sync().await;
        }
        assert!(bo.client.groups().iter().any(|x| x.id == g), "Bo is in");
        (g, a, bo, dir)
    }

    fn row(s: &Screen, g: GroupId) -> Option<crate::ui::GroupView> {
        s.view().groups.into_iter().find(|x| x.id == g)
    }

    #[tokio::test]
    async fn a_closed_room_stays_listed_until_another_room_opens() {
        let srv = TestServer::start().await;
        let (g, mut a, mut bo, _dir) = room_with_bo(&srv).await;
        let other = bo.client.create_group("Other").await.unwrap();
        bo.act(Action::Select(g)).await;
        a.vote_close(g, true).await.unwrap();
        for _ in 0..3 {
            bo.sync().await;
        }
        // On the open room, the news stays in the warning until Bo moves on.
        assert_eq!(bo.app.warning.as_deref(), Some("Ada closed Room."));
        let closed = row(&bo, g).expect("listed while unread or open");
        assert_eq!(closed.ended, Some(Ended::Closed));
        assert_eq!(bo.app.selected, Some(g), "it stays open to read");
        assert_eq!(closed.unread, 0, "the open room counts as read");
        bo.act(Action::Select(other)).await;
        assert!(row(&bo, g).is_none(), "read and closed: gone");
        settle(&mut [&mut a]).await;
    }

    #[tokio::test]
    async fn leave_asks_first_and_says_the_messages_are_deleted() {
        let srv = TestServer::start().await;
        let (g, _a, mut bo, _dir) = room_with_bo(&srv).await;
        bo.act(Action::Select(g)).await;
        bo.act(Action::Command(Command::Leave)).await;
        let Some(Modal::Confirm { question, yes }) = bo.app.modal.take() else {
            panic!("no question: {:?}", bo.app.status);
        };
        assert_eq!(
            question,
            "Leave Room? Its messages and files list are deleted from this computer. Press y to leave or n to stay."
        );
        assert_eq!(*yes, Action::LeaveRoom(g));
        bo.act(*yes).await;
        assert_eq!(
            bo.app.status.as_deref(),
            Some("You left Room. Its messages are deleted from this computer.")
        );
        assert!(row(&bo, g).is_none());
        assert_eq!(bo.app.selected, None);
    }

    #[tokio::test]
    async fn only_admin_closes_after_a_yes() {
        let srv = TestServer::start().await;
        let (g, a, mut bo, _dir) = room_with_bo(&srv).await;
        drop(a);
        // Bo made his own room, where he is the only admin.
        let mine = bo.client.create_group("Mine").await.unwrap();
        bo.act(Action::Select(mine)).await;
        bo.act(Action::Command(Command::Close)).await;
        let Some(Modal::Confirm { question, yes }) = bo.app.modal.take() else {
            panic!("no question: {:?}", bo.app.status);
        };
        assert_eq!(question, "Close Mine? Everyone is removed, and each app deletes the room's messages once they are read. Press y to close or n to keep it.");
        bo.act(*yes).await;
        assert_eq!(bo.app.status.as_deref(), Some("Closed Mine."));
        // The closed room stays open, saying so, until Bo moves on.
        assert_eq!(bo.app.selected, Some(mine));
        assert_eq!(row(&bo, mine).unwrap().ended, Some(Ended::Closed));
        assert_eq!(bo.app.warning, None, "his own close needs no warning");
        bo.act(Action::Select(g)).await;
        assert!(row(&bo, mine).is_none(), "gone once another room opens");
        // Bo is not an admin in Ada's room.
        bo.act(Action::Command(Command::Close)).await;
        assert_eq!(
            bo.app.status.as_deref(),
            Some("Only admins can close this room.")
        );
        assert!(bo.app.modal.is_none());
    }

    #[tokio::test]
    async fn other_admins_are_asked_and_the_vote_shows() {
        let srv = TestServer::start().await;
        let (g, mut a, mut bo, _dir) = room_with_bo(&srv).await;
        let bk = bo.client.my_group_key(g).unwrap();
        a.make_admin(g, &bk).await.unwrap();
        for _ in 0..3 {
            bo.sync().await;
        }
        bo.act(Action::Select(g)).await;
        bo.act(Action::Command(Command::Close)).await;
        let Some(Modal::Confirm { question, yes }) = bo.app.modal.take() else {
            panic!("no question: {:?}", bo.app.status);
        };
        assert_eq!(question, "Ask the other admins to close Room? It closes when 2 of 2 admins agree. Press y to ask or n to cancel.");
        bo.act(*yes).await;
        assert_eq!(
            bo.app.status.as_deref(),
            Some("Asked. 1 of 2 admins agree so far.")
        );
        a.sync().await.unwrap();
        a.vote_close(g, false).await.unwrap();
        for _ in 0..3 {
            bo.sync().await;
        }
        assert!(
            bo.app
                .status
                .as_deref()
                .is_some_and(|s| s.starts_with("Ada wants to keep this room open.")),
            "{:?}",
            bo.app.status
        );
    }

    #[tokio::test]
    async fn mute_hides_the_count_and_unread_comes_from_the_store() {
        let srv = TestServer::start().await;
        let (g, mut a, mut bo, _dir) = room_with_bo(&srv).await;
        let other = bo.client.create_group("Other").await.unwrap();
        bo.act(Action::Select(other)).await;
        a.send_text(g, "one").await.unwrap();
        a.send_text(g, "two").await.unwrap();
        for _ in 0..3 {
            bo.sync().await;
        }
        assert!(row(&bo, g).unwrap().unread >= 2);
        bo.act(Action::Select(g)).await;
        assert_eq!(row(&bo, g).unwrap().unread, 0, "opening marks it seen");
        bo.act(Action::Command(Command::Mute)).await;
        assert_eq!(
            bo.app.status.as_deref(),
            Some("Muted Room. New messages there no longer show a count.")
        );
        assert!(row(&bo, g).unwrap().muted);
        bo.act(Action::Command(Command::Unmute)).await;
        assert_eq!(bo.app.status.as_deref(), Some("Unmuted Room."));
        assert!(!row(&bo, g).unwrap().muted);
    }

    #[tokio::test]
    async fn invites_list_and_cancel_by_number() {
        let srv = TestServer::start().await;
        let (g, _a, mut bo, _dir) = room_with_bo(&srv).await;
        bo.act(Action::Select(g)).await;
        bo.act(Action::Command(Command::Cancel(1))).await;
        assert_eq!(
            bo.app.status.as_deref(),
            Some("Type /invites first, then /cancel with a number from that list.")
        );
        bo.act(Action::Command(Command::Invites)).await;
        assert_eq!(bo.app.status.as_deref(), Some("Asking the server…"));
        bo.run_pending().await;
        assert_eq!(
            bo.app.modal,
            Some(Modal::Invites {
                rows: vec!["You have no open invite links.".into()],
                offset: 0,
            })
        );
        bo.app.modal = None;
        bo.client.invite(Some(g), false).await.unwrap();
        bo.act(Action::Command(Command::Invites)).await;
        bo.run_pending().await;
        let Some(Modal::Invites { rows, .. }) = bo.app.modal.take() else {
            panic!("no list: {:?}", bo.app.status);
        };
        assert_eq!(rows.len(), 1);
        assert!(rows[0].starts_with("1. Room: expires in "), "{rows:?}");
        bo.act(Action::Command(Command::Cancel(2))).await;
        assert_eq!(
            bo.app.status.as_deref(),
            Some("Type /invites first, then /cancel with a number from that list.")
        );
        bo.act(Action::Command(Command::Cancel(1))).await;
        assert_eq!(
            bo.app.status.as_deref(),
            Some("Cancelled. That link no longer works.")
        );
        assert!(bo.client.invites().await.unwrap().is_empty());
        bo.act(Action::Command(Command::Cancel(1))).await;
        assert_eq!(
            bo.app.status.as_deref(),
            Some("That link is already cancelled.")
        );
    }

    #[tokio::test]
    async fn removal_from_the_open_room_stays_on_it() {
        let srv = TestServer::start().await;
        let (g, mut a, mut bo, _dir) = room_with_bo(&srv).await;
        bo.client.create_group("Other").await.unwrap();
        bo.act(Action::Select(g)).await;
        bo.app.input = "half a thou".into();
        let bk = bo.client.my_group_key(g).unwrap();
        a.remove_member(g, &bk).await.unwrap();
        for _ in 0..3 {
            bo.sync().await;
        }
        assert_eq!(bo.app.selected, Some(g), "no jump to another room");
        assert_eq!(row(&bo, g).unwrap().ended, Some(Ended::Removed));
        assert_eq!(bo.app.input, "half a thou");
        assert_eq!(
            bo.app.warning.as_deref(),
            Some("You are no longer in Room.")
        );
        // The screen shows the ended hint, and Enter keeps the words.
        let vm = bo.view();
        let acts = bo.app.handle_key(
            crossterm::event::KeyEvent::new(
                crossterm::event::KeyCode::Enter,
                crossterm::event::KeyModifiers::NONE,
            ),
            &vm,
        );
        assert!(acts.is_empty(), "{acts:?}");
        assert_eq!(bo.app.input, "half a thou");
        // Moving on clears the warning and deletes the read room.
        let other = row_named(&bo, "Other");
        bo.act(Action::Select(other)).await;
        assert_eq!(bo.app.warning, None);
        assert!(row(&bo, g).is_none());
    }

    fn row_named(s: &Screen, name: &str) -> GroupId {
        s.view()
            .groups
            .into_iter()
            .find(|x| x.name == name)
            .unwrap()
            .id
    }

    #[tokio::test]
    async fn leave_shows_lines_that_arrived_while_scrolled_up() {
        let srv = TestServer::start().await;
        let (g, mut a, mut bo, _dir) = room_with_bo(&srv).await;
        bo.act(Action::Select(g)).await;
        bo.app.scroll = 3;
        a.send_text(g, "one").await.unwrap();
        a.send_text(g, "two").await.unwrap();
        for _ in 0..3 {
            bo.sync().await;
        }
        assert_eq!(row(&bo, g).unwrap().unread, 2, "not on screen: unread");
        bo.act(Action::Command(Command::Leave)).await;
        assert_eq!(
            bo.app.status.as_deref(),
            Some("You have 2 new messages in Room. Read them, then type /leave again to leave.")
        );
        assert_eq!(bo.app.scroll, 0, "scrolled to the newest");
        assert!(bo.app.modal.is_none());
        // Anything else in between: /leave shows new lines again first.
        bo.app.scroll = 3;
        a.send_text(g, "three").await.unwrap();
        for _ in 0..3 {
            bo.sync().await;
        }
        bo.act(Action::Command(Command::Mute)).await;
        bo.act(Action::Command(Command::Leave)).await;
        assert_eq!(
            bo.app.status.as_deref(),
            Some("You have 1 new message in Room. Read them, then type /leave again to leave.")
        );
        bo.act(Action::Command(Command::Leave)).await;
        assert!(
            matches!(bo.app.modal, Some(Modal::Confirm { .. })),
            "{:?}",
            bo.app.status
        );
    }

    #[tokio::test]
    async fn details_show_after_the_server_answers() {
        let srv = TestServer::start().await;
        let (g, _a, mut bo, _dir) = room_with_bo(&srv).await;
        bo.act(Action::Select(g)).await;
        bo.act(Action::Command(Command::Details)).await;
        assert_eq!(bo.app.status.as_deref(), Some("Asking the server…"));
        assert!(bo.app.modal.is_none(), "the box waits for the next draw");
        bo.run_pending().await;
        assert_eq!(bo.app.status, None);
        let Some(Modal::Details { lines }) = bo.app.modal.take() else {
            panic!("no details: {:?}", bo.app.status);
        };
        assert_eq!(lines[0], "Name: Room");
        assert_eq!(lines[1], "Admins: Ada");
        assert_eq!(lines[2], "Members: 2");
        assert!(
            lines[3].starts_with("Created: 20") && lines[3].len() == "Created: 2026-10-20".len(),
            "{lines:?}"
        );
        assert_eq!(lines[5], "Muted: no");
    }

    #[tokio::test]
    async fn an_ended_room_refuses_commands_that_need_the_room() {
        let srv = TestServer::start().await;
        let (g, mut a, mut bo, _dir) = room_with_bo(&srv).await;
        let other = bo.client.create_group("Other").await.unwrap();
        bo.act(Action::Select(other)).await;
        // Bo is removed with a message he has not read.
        a.send_text(g, "one").await.unwrap();
        for _ in 0..3 {
            bo.sync().await;
        }
        let bk = bo.client.my_group_key(g).unwrap();
        a.remove_member(g, &bk).await.unwrap();
        for _ in 0..3 {
            bo.sync().await;
        }
        let removed = row(&bo, g).expect("listed while unread");
        assert_eq!(removed.ended, Some(Ended::Removed));
        assert!(removed.unread >= 1);
        bo.act(Action::Select(g)).await;
        assert_eq!(row(&bo, g).unwrap().unread, 0, "open: read, still listed");
        bo.act(Action::Command(Command::Mute)).await;
        assert_eq!(
            bo.app.status.as_deref(),
            Some("You are no longer in this room. Its messages leave this computer when you open another room.")
        );
        bo.act(Action::Command(Command::Clear)).await;
        let Some(Modal::Confirm { question, yes }) = bo.app.modal.take() else {
            panic!("no question: {:?}", bo.app.status);
        };
        assert_eq!(question, "Delete Room's messages from this computer? Other members keep theirs. Press y to delete or n to keep them.");
        bo.act(*yes).await;
        assert!(row(&bo, g).is_none(), "cleared: the ended room is gone");
        assert_eq!(
            bo.app.status.as_deref(),
            Some("Deleted Room's messages from this computer.")
        );
    }
}
