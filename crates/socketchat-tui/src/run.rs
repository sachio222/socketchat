//! The live screen: draws, reads keys, and carries out what they ask.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command as Process, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event as TermEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use socketchat_core::client::{server_text, Client, Event, GroupSummary, Verification};
use socketchat_core::close::{close_needed, CloseOutcome};
use socketchat_core::keys::{fingerprint_text, Key};
use socketchat_core::sanitize::same_name;
use socketchat_core::CoreError;
use socketchat_proto::msg::GroupId;
use socketchat_proto::InviteLink;
use tokio::sync::mpsc;

use crate::app::{
    details_lines, ended_hint, forget_question, forgot_text, invite_message, invite_row,
    leave_step, sent_file_status, server_row, Action, App, LeaveStep, Modal,
};
use crate::commands::Command;
use crate::theme::{pick_theme, Theme, ThemeName, THEMES};
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
    /// Warnings about rooms joined while the person was busy with another,
    /// shown when each room opens.
    joined_warning: HashMap<GroupId, String>,
    /// Puts text on the clipboard with the system's clipboard program and
    /// says whether it worked. It may take a while, so it runs beside the
    /// screen and its answer comes back on `copies`.
    clipboard: Clipboard,
    /// Asks the terminal itself to copy, for when no program could.
    terminal_copy: fn(&str),
    /// Where copies that finished report back, and where the screen hears
    /// them.
    copies: (
        mpsc::UnboundedSender<Copied>,
        mpsc::UnboundedReceiver<Copied>,
    ),
    /// Copies started that have not reported back yet.
    copies_running: usize,
}

/// A program that puts text on the clipboard, shared with the thread that
/// runs it.
type Clipboard = std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// How a copy to the clipboard went.
#[derive(Debug)]
struct Copied {
    text: String,
    ok: bool,
    /// The person pressed C, so the status line says how it went.
    asked: bool,
}

/// What the status line says when an action fails because the connection
/// to `server` dropped. The app reconnects on its own at the next sync.
fn offline_note(server: Option<String>) -> String {
    let server = server.unwrap_or_else(|| "the server".into());
    format!("{OFFLINE_LEAD}{server}. Socketchat is reconnecting.")
}

const OFFLINE_LEAD: &str = "Lost the connection to ";

/// How an error about a server that could not be reached starts; the
/// status line adds where to see every server.
const UNREACHABLE_LEAD: &str = "Could not reach ";

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

/// The programs that put text on this system's clipboard, to try in
/// order, for an `os` as `std::env::consts::OS` names it and whether a
/// Wayland or X11 display is set.
fn clipboard_tools(
    os: &str,
    wayland: bool,
    x11: bool,
) -> Vec<(&'static str, &'static [&'static str])> {
    match os {
        "macos" => vec![("pbcopy", &[])],
        "windows" => vec![("clip.exe", &[])],
        _ => {
            let mut v: Vec<(&'static str, &'static [&'static str])> = vec![];
            if wayland {
                v.push(("wl-copy", &[]));
            }
            if x11 {
                v.push(("xclip", &["-selection", "clipboard"]));
                v.push(("xsel", &["--clipboard", "--input"]));
            }
            v
        }
    }
}

/// The longest a clipboard program may take before the screen moves on.
const CLIPBOARD_WAIT: Duration = Duration::from_millis(500);

/// Gives `text` to `program` on its standard input, and says whether it
/// finished well within [`CLIPBOARD_WAIT`]. A program that is missing
/// fails at once.
fn pipe_to(program: &str, args: &[&str], text: &str) -> bool {
    let Ok(mut child) = Process::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let wrote = child
        .stdin
        .take()
        .is_some_and(|mut i| i.write_all(text.as_bytes()).is_ok());
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return wrote && status.success(),
            Ok(None) if start.elapsed() < CLIPBOARD_WAIT => {
                std::thread::sleep(Duration::from_millis(10))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

/// Puts text on the clipboard with the system's own clipboard program, and
/// says whether that worked.
fn copy_to_clipboard(text: &str) -> bool {
    let tools = clipboard_tools(
        std::env::consts::OS,
        std::env::var_os("WAYLAND_DISPLAY").is_some(),
        std::env::var_os("DISPLAY").is_some(),
    );
    tools.iter().any(|(p, args)| pipe_to(p, args, text))
}

/// Asks the terminal to copy `text` (OSC 52), which works in many
/// terminals and over SSH, but nothing says whether it did, so that counts
/// as not copied. It writes to the screen, so only the screen's own task
/// calls it, between draws.
fn osc52_copy(text: &str) {
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

/// How the status line starts when it says a room was joined.
const JOINED_LEAD: &str = "You joined";

/// The warning for a join whose invite could not be checked.
fn unverified_join(reason: &str) -> String {
    format!("You joined, but the invite could not be checked: {reason}. Compare safety numbers with /verify before you trust anyone here.")
}

/// The room an event is about, if it is about one.
fn event_group(e: &Event) -> Option<GroupId> {
    match e {
        Event::Joined { group, .. }
        | Event::InviteConfirmed { group, .. }
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
            joined_warning: HashMap::new(),
            clipboard: std::sync::Arc::new(copy_to_clipboard),
            terminal_copy: osc52_copy,
            copies: mpsc::unbounded_channel(),
            copies_running: 0,
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
            server: self.app.selected.and_then(|g| self.client.room_server(g)),
        }
    }

    /// Marks the open room's messages seen: they are on screen.
    fn mark_seen(&mut self, g: GroupId) {
        if let Err(e) = self.client.mark_seen(g) {
            self.app.status.get_or_insert(e.to_string());
        }
    }

    /// Whether the person is busy with the open room: words in the message
    /// box, a box on screen or the switcher open. Nothing that arrives from
    /// a server opens another room then.
    fn busy(&self) -> bool {
        !self.app.input.trim().is_empty() || self.app.modal.is_some() || self.app.switcher.is_some()
    }

    /// Opens room `g`. Ended rooms that are read go from this computer,
    /// except the one now open.
    fn select(&mut self, g: GroupId) {
        if self.app.selected != Some(g) {
            // A warning is about the room it came with.
            self.app.warning = self.joined_warning.remove(&g);
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
            // Names kept before they were single-spaced still match.
            .filter(|m| !m.me && same_name(name, &m.name))
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
            // Words in the message box, or a box on screen, belong to the
            // open room: the new room waits until the person opens it.
            Event::Joined {
                group,
                verification,
            } if self.busy() => {
                let room = self.room_name(group);
                let joined = match self.summary(group) {
                    Some(s) if s.is_dm => format!("{JOINED_LEAD} a direct chat with {room}"),
                    _ => format!("{JOINED_LEAD} {room}"),
                };
                self.app.status = Some(match verification {
                    Verification::Unverified { reason } => {
                        self.joined_warning.insert(group, unverified_join(&reason));
                        format!("{joined}, but the invite could not be checked. Open {room} to see what to do.")
                    }
                    Verification::Waiting { inviter } => {
                        format!("{joined}. Waiting for {inviter} to confirm this invite.")
                    }
                    Verification::Verified => {
                        format!("{joined}. The person who invited you is verified.")
                    }
                });
            }
            Event::Joined {
                group,
                verification,
            } => {
                self.select(group);
                match verification {
                    Verification::Unverified { reason } => {
                        self.app.warning = Some(unverified_join(&reason));
                    }
                    Verification::Waiting { inviter } => {
                        self.app.status = Some(format!(
                            "You joined. Waiting for {inviter} to confirm this invite."
                        ));
                    }
                    Verification::Verified => {
                        self.app.status =
                            Some("You joined. The person who invited you is verified.".into());
                    }
                }
            }
            Event::InviteConfirmed { inviter, .. } => {
                self.app.status = Some(format!(
                    "{inviter} confirmed this invite and is now verified."
                ));
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
            // A note that follows a join adds to the line naming the room.
            Event::Warning(w) => {
                self.app.status = Some(match self.app.status.take() {
                    Some(s) if s.starts_with(JOINED_LEAD) => format!("{s} {w}"),
                    _ => w,
                })
            }
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
            // The open room is gone from this computer. Words typed for it,
            // or a box about it, never move to another room: that waits.
            None if !self.busy() => self.select_first(),
            None => {}
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
            if e.starts_with(UNREACHABLE_LEAD) {
                self.app.status = Some(format!("{e} Type /servers to see your servers."));
            } else if self.client.connected() {
                self.app.status = Some(e);
            } else {
                self.app.status = Some(offline_note(self.client.dropped_server()));
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
                self.start_copy(text, true);
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
            // The room the question was asked in, whatever is open now.
            Action::ConfirmVideo(g, path) => self
                .client
                .send_file(g, &expand(&path), true)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string()),
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
            Action::ForgetServer(id) => self.forget_server(id),
            Action::Command(c) => self.command(c).await,
        };
        self.report(r);
    }

    /// Starts putting `text` on the clipboard beside the screen, which goes
    /// on drawing and reading keys; [`Screen::copied`] takes the answer.
    /// `asked` says the person pressed C.
    fn start_copy(&mut self, text: String, asked: bool) {
        self.copies_running += 1;
        self.app.copying = true;
        let clipboard = self.clipboard.clone();
        let tx = self.copies.0.clone();
        tokio::task::spawn_blocking(move || {
            let ok = clipboard(&text);
            let _ = tx.send(Copied { text, ok, asked });
        });
    }

    /// Shows how a copy went: the invite box's line under the link, and
    /// the status line when the person pressed C. With no clipboard
    /// program, it asks the terminal to copy.
    fn copied(&mut self, c: Copied) {
        if !c.ok {
            (self.terminal_copy)(&c.text);
        }
        self.copies_running = self.copies_running.saturating_sub(1);
        self.app.copying = self.copies_running > 0;
        if let Some(Modal::Invite { link, copied, .. }) = &mut self.app.modal {
            if invite_message(link) == c.text {
                *copied = c.ok;
            }
        }
        if c.asked {
            self.app.status = Some(if c.ok {
                "Invite copied. Paste it to the person you are inviting.".into()
            } else {
                "Asked your terminal to copy the invite. If pasting finds nothing, select the link and copy it.".into()
            });
        }
    }

    /// Deletes server `id` and its rooms from this computer. A room on it
    /// that was open makes way for another.
    fn forget_server(&mut self, id: i64) -> Result<(), String> {
        let Some(s) = self.client.servers(None).into_iter().find(|s| s.id == id) else {
            return Err("That server is already forgotten.".into());
        };
        let rooms = self.client.forget_server(id).map_err(|e| e.to_string())?;
        for slot in &mut self.app.server_ids {
            if *slot == Some(id) {
                *slot = None;
            }
        }
        if self.app.selected.is_some_and(|g| self.summary(g).is_none()) {
            self.app.warning = None;
            self.select_first();
        }
        self.say_after_events(forgot_text(&s.text, rooms));
        Ok(())
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
                port,
                pinned,
                offered,
            }) => {
                self.app.modal = Some(Modal::NewCertificate {
                    link: link.to_string(),
                    host: server_text(&host, port),
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
            Command::About => self.app.modal = Some(Modal::About),
            Command::Theme(None) => {
                self.app.status = Some(format!(
                    "Theme: {}. Choices: {}. Type /theme {} to switch.",
                    self.app.theme.name.as_str(),
                    THEMES.join(", "),
                    match self.app.theme.name {
                        ThemeName::Phosphor => ThemeName::Classic,
                        ThemeName::Classic => ThemeName::Phosphor,
                    }
                    .as_str()
                ));
            }
            Command::Theme(Some(want)) => match ThemeName::parse(&want) {
                Some(name) => {
                    self.client.set_theme(name.as_str()).map_err(e)?;
                    self.app.theme = Theme::new(name, self.app.theme.support);
                    self.app.status = Some(format!("Theme: {}.", name.as_str()));
                }
                None => {
                    self.app.status = Some(format!(
                        "There is no theme called {}. Choices: {}.",
                        fit(&want, 20),
                        THEMES.join(", ")
                    ));
                }
            },
            Command::Mouse(None) => {
                self.app.status = Some(if self.app.mouse {
                    "Mouse on. To select text, hold Shift as you drag (Option or Fn on a Mac), or type /mouse off.".into()
                } else {
                    "Mouse off. Type /mouse on to click and scroll.".into()
                });
            }
            Command::Mouse(Some(on)) => {
                self.client.set_mouse(on).map_err(e)?;
                self.app.mouse = on;
                self.app.status = Some(if on {
                    "Mouse on. To select text, hold Shift as you drag (Option or Fn on a Mac)."
                        .into()
                } else {
                    "Mouse off. Your terminal selects text again. Type /mouse on to click and scroll.".into()
                });
            }
            // The keys open the switcher or the room before this is reached.
            Command::Switch(_) => {}
            Command::Invite { dm } => {
                let made = if dm {
                    self.client.invite(None, true).await
                } else {
                    self.client.invite(Some(need()?), false).await
                };
                let (link, expires_unix) = match made {
                    // The box says why there is no link, and what to ask for.
                    Err(why @ CoreError::InviteHost { .. }) => {
                        self.app.modal = Some(Modal::NoInviteLink {
                            why: why.to_string(),
                        });
                        return Ok(());
                    }
                    made => made.map_err(e)?,
                };
                let link = link.to_string();
                // On the clipboard soon after the box opens, ready to paste.
                self.start_copy(invite_message(&link), false);
                self.app.modal = Some(Modal::Invite {
                    link,
                    hours: self.client.hours_until(expires_unix),
                    copied: false,
                });
            }
            Command::Join(link) => self.join(&link, false).await?,
            Command::New(name) => {
                let g = match self.client.new_room_server(sel) {
                    Some(server) => self.client.create_group_at(server, &name).await,
                    None => self.client.create_group(&name).await,
                }
                .map_err(e)?;
                self.select(g);
                if let Some(server) = self.client.room_server(g) {
                    self.app.status = Some(format!("Made {name} on {server}."));
                }
            }
            Command::Dm(name) => {
                let shared = need()?;
                let k = self.member(&name)?;
                let g = self.client.dm(shared, &k).await.map_err(e)?;
                self.app.status = Some(format!("Asked {name} to open a direct chat."));
                self.select(g);
            }
            Command::Send(path) => {
                let group = need()?;
                match self.client.send_file(group, &expand(&path), false).await {
                    Err(CoreError::VideoNeedsConfirm) => {
                        self.app.modal = Some(Modal::ConfirmVideo { group, path })
                    }
                    Err(CoreError::PhotoNeedsConfirm) => {
                        self.app.modal = Some(Modal::ConfirmPhoto { group, path })
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
                let files = self.client.shared_files(g);
                let picked = crate::commands::pick_file(&files, &file, local_time)?;
                let dir = match dir {
                    Some(d) => expand(&d),
                    None => directories::UserDirs::new()
                        .and_then(|u| u.download_dir().map(PathBuf::from))
                        .unwrap_or_else(|| PathBuf::from(".")),
                };
                let saved = self
                    .client
                    .save_file(g, picked.offer.id, &dir)
                    .await
                    .map_err(e)?;
                let whose = match picked.mine {
                    true => "your".to_string(),
                    false => format!("{}'s", picked.from),
                };
                self.app.status = Some(format!(
                    "Saved {whose} {} to {}",
                    picked.offer.name,
                    saved.display()
                ));
            }
            Command::Verify(name) => {
                let g = need()?;
                let k = self.member(&name)?;
                let number = self.client.safety_number(g, &k).ok_or_else(|| {
                    format!("{name} has not shared their identity in this chat yet.")
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
                        let (messages, them) = if n == 1 {
                            ("message", "it")
                        } else {
                            ("messages", "them")
                        };
                        self.app.status = Some(format!(
                            "You have {n} new {messages} in {room}. Read {them}, then type /leave again to leave."
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
            Command::Servers => {
                let list = self.client.servers(sel);
                self.app.server_ids = list.iter().map(|s| Some(s.id)).collect();
                let rows = if list.is_empty() {
                    vec!["You have no servers yet. Join one with /join <link>.".into()]
                } else {
                    list.iter()
                        .enumerate()
                        .map(|(i, s)| server_row(i + 1, s))
                        .collect()
                };
                self.app.modal = Some(Modal::Servers { rows, offset: 0 });
            }
            Command::Forget(n) => {
                let id = n
                    .checked_sub(1)
                    .and_then(|i| self.app.server_ids.get(i).copied())
                    .ok_or("Type /servers first, then /forget with a number from that list.")?
                    .ok_or("That server is already forgotten.")?;
                let s = self
                    .client
                    .servers(sel)
                    .into_iter()
                    .find(|s| s.id == id)
                    .ok_or("That server is already forgotten.")?;
                self.app.modal = Some(Modal::Confirm {
                    question: forget_question(&s.text, s.rooms),
                    yes: Box::new(Action::ForgetServer(id)),
                });
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
            offset: 0,
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
            if self
                .app
                .status
                .as_deref()
                .is_some_and(|s| s.starts_with(OFFLINE_LEAD))
            {
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

/// What the terminal sends the chat screen.
enum Input {
    /// A key, and when it was read.
    Key(KeyEvent, Instant),
    /// Pasted text, all of it at once.
    Paste(String),
    /// A click or a turn of the scroll wheel, and when it was read.
    Mouse(MouseEvent, Instant),
    /// The window changed size.
    Redraw,
    /// Reading the terminal failed with a panic, whose message this is.
    Failed(String),
}

/// The input a terminal event carries, read at `at`. Mouse moves and
/// releases carry none, so they never cost a redraw.
fn input_of(ev: TermEvent, at: Instant) -> Option<Input> {
    match ev {
        TermEvent::Key(k) if k.kind == KeyEventKind::Press => Some(Input::Key(k, at)),
        TermEvent::Paste(text) => Some(Input::Paste(text)),
        TermEvent::Mouse(m)
            if matches!(
                m.kind,
                MouseEventKind::Down(MouseButton::Left)
                    | MouseEventKind::ScrollUp
                    | MouseEventKind::ScrollDown
            ) =>
        {
            Some(Input::Mouse(m, at))
        }
        TermEvent::Resize(..) => Some(Input::Redraw),
        _ => None,
    }
}

/// What one look at the terminal found.
enum Read {
    /// Input for the chat screen.
    Got(Input),
    /// Nothing yet, or nothing the screen uses.
    Nothing,
    /// The terminal can no longer be read.
    Stop,
}

/// One look at the terminal, waiting at most 200 ms for something.
fn read_terminal() -> Read {
    match event::poll(Duration::from_millis(200)) {
        // A failed read is skipped, as before.
        Ok(true) => match event::read()
            .ok()
            .and_then(|ev| input_of(ev, Instant::now()))
        {
            Some(i) => Read::Got(i),
            None => Read::Nothing,
        },
        Ok(false) => Read::Nothing,
        Err(_) => Read::Stop,
    }
}

/// Reads keys, pastes and the mouse on a plain thread and hands them to the async
/// loop.
fn key_reader() -> mpsc::UnboundedReceiver<Input> {
    reader(read_terminal)
}

/// Runs `next` on a plain thread until it stops or nobody listens, and
/// hands what it reads to the async loop. A panic there ends the reading
/// with [`Input::Failed`].
fn reader(mut next: impl FnMut() -> Read + Send + 'static) -> mpsc::UnboundedReceiver<Input> {
    let (tx, rx) = mpsc::unbounded_channel();
    let spawned = std::thread::Builder::new()
        .name("socketchat-keys".into())
        .spawn(move || {
            let read = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| loop {
                match next() {
                    Read::Got(i) => {
                        if tx.send(i).is_err() {
                            return;
                        }
                    }
                    Read::Nothing if tx.is_closed() => return,
                    Read::Nothing => {}
                    Read::Stop => return,
                }
            }));
            if let Err(p) = read {
                let why = p
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| p.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "it panicked".into());
                let _ = tx.send(Input::Failed(why));
            }
        });
    // With no thread, the channel closes at once and the screen ends.
    drop(spawned);
    rx
}

/// The error the chat screen ends with when reading keys failed.
fn keys_failed(why: &str) -> std::io::Error {
    std::io::Error::other(format!(
        "The chat screen stopped because reading the keyboard failed: {why}"
    ))
}

/// The system's requests to stop: SIGTERM, and SIGHUP when the terminal
/// closes. Either ends the chat screen the way quitting does, so the
/// terminal goes back to normal. Other systems have none.
struct StopSignals {
    #[cfg(unix)]
    term: tokio::signal::unix::Signal,
    #[cfg(unix)]
    hup: tokio::signal::unix::Signal,
}

impl StopSignals {
    /// Starts listening. From here on these signals no longer end the
    /// program at once.
    fn new() -> std::io::Result<StopSignals> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            Ok(StopSignals {
                term: signal(SignalKind::terminate())?,
                hup: signal(SignalKind::hangup())?,
            })
        }
        #[cfg(not(unix))]
        Ok(StopSignals {})
    }

    /// Waits for the next request to stop.
    async fn recv(&mut self) {
        #[cfg(unix)]
        tokio::select! {
            _ = self.term.recv() => {}
            _ = self.hup.recv() => {}
        }
        #[cfg(not(unix))]
        std::future::pending::<()>().await
    }
}

/// The question on screen, and when it first showed there. Keys typed
/// before then, while the app was busy, were meant for something else, so
/// they never answer it.
#[derive(Default)]
struct Asked(Option<(Modal, Instant)>);

impl Asked {
    /// Notes what the screen shows after a draw at `now`.
    fn shown(&mut self, modal: &Option<Modal>, now: Instant) {
        match modal {
            Some(m) if m.is_question() => {
                if self.0.as_ref().map(|(q, _)| q) != Some(m) {
                    self.0 = Some((m.clone(), now));
                }
            }
            _ => self.0 = None,
        }
    }

    /// Whether a key read at `at` came before the open question showed.
    fn stale(&self, at: Instant) -> bool {
        matches!(&self.0, Some((_, shown)) if at < *shown)
    }
}

/// Puts the chat screen on the terminal's other screen and asks the
/// terminal to mark pastes, so a paste arrives as text and never as keys.
/// A terminal that cannot mark pastes still gets the chat screen.
fn screen_on(w: &mut impl Write) -> std::io::Result<()> {
    execute!(w, EnterAlternateScreen)?;
    let _ = execute!(w, EnableBracketedPaste);
    Ok(())
}

/// Undoes [`screen_on`], and turns mouse capture off whether or not it
/// was on, so the shell gets plain text selection back.
fn screen_off(w: &mut impl Write) -> std::io::Result<()> {
    let _ = execute!(w, DisableBracketedPaste);
    let _ = execute!(w, DisableMouseCapture);
    execute!(w, LeaveAlternateScreen)
}

/// Turns mouse capture on or off: on, clicks and the wheel come to the
/// chat screen; off, the terminal selects text as usual.
fn set_mouse_capture(w: &mut impl Write, on: bool) -> std::io::Result<()> {
    if on {
        execute!(w, EnableMouseCapture)
    } else {
        execute!(w, DisableMouseCapture)
    }
}

/// Whether `k` is Ctrl-C, which quits at any time.
fn quits(k: &KeyEvent) -> bool {
    k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL)
}

/// Whether the chat screen holds the terminal: raw mode, on the other
/// screen.
static RAW: AtomicBool = AtomicBool::new(false);

/// Gives the terminal back to the shell: normal mode, no mouse capture,
/// no paste marking, main screen. It does nothing when the chat screen
/// does not hold the terminal, so calling it twice is safe.
fn restore_terminal() {
    if RAW.swap(false, Ordering::SeqCst) {
        let _ = disable_raw_mode();
        let _ = screen_off(&mut std::io::stdout());
        // Panics beside the screen, held back while it was up.
        for message in take_deferred() {
            eprintln!("{message}");
        }
    }
}

tokio::task_local! {
    /// Set while the chat screen's own task runs; tasks it spawns, such as
    /// network tasks, do not have it.
    static SCREEN: ();
}

/// Whether the code panicking now runs on the chat screen itself, which
/// then stops, rather than in a task beside it while the screen goes on.
fn screen_owns_this_panic() -> bool {
    SCREEN.try_with(|_| ()).is_ok()
}

/// The terminal, held for the chat screen. Dropping it gives the terminal
/// back, whether the screen returns, fails or panics.
struct RawTerminal;

/// Panic messages from beside the chat screen, held back while it holds
/// the terminal so they never print over it.
static DEFERRED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Takes the panic messages held back so far.
fn take_deferred() -> Vec<String> {
    std::mem::take(&mut *DEFERRED.lock().unwrap_or_else(|e| e.into_inner()))
}

/// Sets the panic hook the chat screen needs, once per program. A panic
/// on the chat screen gives the terminal back first, so its message stays
/// readable. A panic beside it, in a network task or the thread that reads
/// keys, while the screen holds the terminal is kept until the terminal is
/// back, then printed on standard error.
fn install_panic_hook() {
    static HOOK: std::sync::Once = std::sync::Once::new();
    HOOK.call_once(|| {
        let show = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if screen_owns_this_panic() {
                restore_terminal();
                show(info)
            } else if RAW.load(Ordering::SeqCst) {
                let thread = std::thread::current();
                let name = thread.name().unwrap_or("<unnamed>");
                DEFERRED
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(format!("thread '{name}' {info}"));
            } else {
                show(info)
            }
        }));
    });
}

impl RawTerminal {
    fn take() -> std::io::Result<RawTerminal> {
        install_panic_hook();
        RAW.store(true, Ordering::SeqCst);
        let held = RawTerminal;
        enable_raw_mode()?;
        screen_on(&mut std::io::stdout())?;
        Ok(held)
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        restore_terminal();
    }
}

/// Runs `f` as the chat screen: a panic inside it gives the terminal back.
async fn on_screen<F: std::future::Future>(f: F) -> F::Output {
    SCREEN.scope((), f).await
}

/// Opens the chat screen and runs it until the person quits.
pub async fn run(client: Client) -> std::io::Result<()> {
    let held = RawTerminal::take()?;
    let result = on_screen(run_inner(client)).await;
    drop(held);
    result
}

async fn run_inner(client: Client) -> std::io::Result<()> {
    let mut term = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
    let mut s = Screen::new(client);
    s.app.theme = pick_theme(
        s.client.theme().ok().flatten().as_deref(),
        std::env::var("SOCKETCHAT_THEME").ok().as_deref(),
        std::env::var("COLORTERM").ok().as_deref(),
    );
    s.app.mouse = s.client.mouse().ok().flatten().unwrap_or(true);
    let mut capturing = false;
    s.select_first();
    let exit_after_draw = std::env::var_os("SOCKETCHAT_EXIT_AFTER_DRAW").is_some();
    let mut stop = StopSignals::new()?;
    let mut keys = key_reader();
    let mut first = true;
    let mut asked = Asked::default();
    loop {
        let vm = s.view();
        term.draw(|f| draw(f, &s.app, &vm))?;
        let now = Instant::now();
        asked.shown(&s.app.modal, now);
        s.app.drawn(now);
        if capturing != s.app.mouse {
            set_mouse_capture(term.backend_mut(), s.app.mouse)?;
            capturing = s.app.mouse;
        }
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
                // Typed before the open question showed: not its answer.
                // Ctrl-C still quits.
                Some(Input::Key(k, at)) if asked.stale(at) && !quits(&k) => {}
                Some(Input::Key(k, _)) => {
                    for a in s.app.handle_key(k, &vm) {
                        s.act(a).await;
                    }
                    // Scrolled back down: the newest lines are on screen.
                    s.seen_if_at_bottom();
                }
                Some(Input::Paste(text)) => {
                    for a in s.app.handle_paste(&text) {
                        s.act(a).await;
                    }
                }
                // Clicked before the open question showed: not its answer.
                Some(Input::Mouse(_, at)) if asked.stale(at) => {}
                Some(Input::Mouse(m, at)) => {
                    for a in s.app.handle_mouse(m, at, &vm) {
                        s.act(a).await;
                    }
                    s.seen_if_at_bottom();
                }
                Some(Input::Redraw) => {}
                // The screen cannot go on without keys: end with an error,
                // so the program exits with a failure and says why.
                Some(Input::Failed(why)) => {
                    s.finish();
                    return Err(keys_failed(&why));
                }
                None => {
                    s.finish();
                    return Ok(());
                }
            },
            // The system asked the app to stop, or the terminal closed.
            _ = stop.recv() => {
                s.finish();
                return Ok(());
            }
            Some(c) = s.copies.1.recv() => s.copied(c),
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

    /// Tests that change whether the chat screen holds the terminal take
    /// turns.
    static TERMINAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A panic or an error on the chat screen still gives the shell back
    /// its normal terminal.
    #[test]
    fn the_terminal_is_restored_when_the_screen_panics() {
        use std::sync::atomic::Ordering;
        let _turn = TERMINAL.lock().unwrap_or_else(|e| e.into_inner());
        super::RAW.store(true, Ordering::SeqCst);
        let r = std::panic::catch_unwind(|| {
            let _held = super::RawTerminal;
            panic!("a bug on the chat screen");
        });
        assert!(r.is_err());
        assert!(!super::RAW.load(Ordering::SeqCst), "raw mode was left on");
    }

    /// A panic beside the chat screen, in a network task or the thread
    /// that reads keys, would print over the screen. Its message waits
    /// until the terminal is back to normal.
    #[test]
    fn a_panic_beside_the_screen_waits_until_the_terminal_is_back() {
        use std::sync::atomic::Ordering;
        let _turn = TERMINAL.lock().unwrap_or_else(|e| e.into_inner());
        super::install_panic_hook();
        super::RAW.store(true, Ordering::SeqCst);
        let r = std::thread::Builder::new()
            .name("beside".into())
            .spawn(|| panic!("a bug beside the screen"))
            .unwrap()
            .join();
        assert!(r.is_err());
        let held = super::take_deferred();
        super::restore_terminal();
        assert!(
            held.iter()
                .any(|m| m.contains("a bug beside the screen") && m.contains("'beside'")),
            "{held:?}"
        );
    }

    /// A panic in the thread that reads keys ends the chat screen with an
    /// error, instead of looking like the person quit.
    #[tokio::test]
    async fn a_panic_reading_keys_reaches_the_screen() {
        let mut rx = super::reader(|| panic!("the key reader broke"));
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("the reader answers");
        match got {
            Some(super::Input::Failed(why)) => assert_eq!(why, "the key reader broke"),
            Some(_) => panic!("some other input"),
            None => panic!("the screen heard nothing, as when keys end"),
        }
        let e = super::keys_failed("the key reader broke");
        assert_eq!(
            e.to_string(),
            "The chat screen stopped because reading the keyboard failed: the key reader broke"
        );
    }

    /// SIGTERM, or SIGHUP when the terminal closes, reaches the chat
    /// screen, which then gives the terminal back as quitting does, instead
    /// of ending the program with the terminal still in raw mode.
    #[cfg(unix)]
    #[tokio::test]
    async fn stop_signals_reach_the_screen() {
        let mut stop = super::StopSignals::new().unwrap();
        for sig in ["-HUP", "-TERM"] {
            let sent = std::process::Command::new("kill")
                .args([sig, &std::process::id().to_string()])
                .status()
                .unwrap();
            assert!(sent.success());
            tokio::time::timeout(std::time::Duration::from_secs(5), stop.recv())
                .await
                .unwrap_or_else(|_| panic!("{sig} never arrived"));
        }
    }

    /// A panic in a task the screen started, such as a network task, does
    /// not give the terminal back while the screen goes on using it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_a_panic_on_the_screen_gives_the_terminal_back() {
        assert!(!super::screen_owns_this_panic(), "outside the screen");
        super::on_screen(async {
            assert!(super::screen_owns_this_panic(), "on the screen");
            let other = tokio::spawn(async { super::screen_owns_this_panic() });
            assert!(!other.await.unwrap(), "a task the screen spawned");
            let blocking = tokio::task::spawn_blocking(super::screen_owns_this_panic);
            assert!(!blocking.await.unwrap(), "a blocking task");
        })
        .await;
    }

    #[test]
    fn clipboard_programs_match_the_system() {
        let names = |os, w, x| -> Vec<&str> {
            super::clipboard_tools(os, w, x)
                .into_iter()
                .map(|(p, _)| p)
                .collect()
        };
        assert_eq!(names("macos", false, false), ["pbcopy"]);
        assert_eq!(names("windows", false, false), ["clip.exe"]);
        assert_eq!(names("linux", true, true), ["wl-copy", "xclip", "xsel"]);
        assert_eq!(names("linux", false, true), ["xclip", "xsel"]);
        assert!(names("linux", false, false).is_empty(), "OSC 52 only");
        // A program that is not there is not available, and fails at once.
        let t = std::time::Instant::now();
        assert!(!super::pipe_to("socketchat-no-such-program", &[], "x"));
        assert!(t.elapsed() < super::CLIPBOARD_WAIT);
    }

    #[test]
    fn base64_matches_known_values() {
        assert_eq!(to_base64(b""), "");
        assert_eq!(to_base64(b"f"), "Zg==");
        assert_eq!(to_base64(b"fo"), "Zm8=");
        assert_eq!(to_base64(b"foo"), "Zm9v");
        assert_eq!(to_base64(b"socketchat://x"), "c29ja2V0Y2hhdDovL3g=");
    }

    /// Keys typed while the app worked, before a question was on screen,
    /// were meant for something else: they cannot answer it.
    #[test]
    fn keys_typed_before_a_question_showed_do_not_answer_it() {
        use std::time::{Duration, Instant};
        let ms = Duration::from_millis;
        let t0 = Instant::now();
        let mut asked = super::Asked::default();
        asked.shown(&None, t0);
        assert!(!asked.stale(t0), "no question open");
        let video = Some(Modal::ConfirmVideo {
            group: GroupId([1; 16]),
            path: "x".into(),
        });
        asked.shown(&video, t0 + ms(10));
        assert!(asked.stale(t0), "typed before the question showed");
        assert!(!asked.stale(t0 + ms(20)), "typed after it showed");
        // Drawn again while still open: it keeps the time it first showed.
        asked.shown(&video, t0 + ms(30));
        assert!(!asked.stale(t0 + ms(20)));
        assert!(asked.stale(t0 + ms(5)));
        let cert = Some(Modal::NewCertificate {
            link: "l".into(),
            host: "h".into(),
            pinned: "p".into(),
            offered: "o".into(),
        });
        asked.shown(&cert, t0 + ms(40));
        assert!(asked.stale(t0 + ms(35)), "a new question starts fresh");
        let leave = Some(Modal::Confirm {
            question: "Leave?".into(),
            yes: Box::new(Action::Quit),
        });
        asked.shown(&leave, t0 + ms(50));
        assert!(asked.stale(t0 + ms(45)));
        for m in [Some(Modal::Help { offset: 0 }), None] {
            asked.shown(&m, t0 + ms(60));
            assert!(!asked.stale(t0), "{m:?} asks nothing");
        }
    }

    /// The chat screen turns on bracketed paste, so a paste arrives as one
    /// piece of text and not as keys, and turns it off on the way out.
    #[test]
    fn the_screen_takes_pastes_as_text() {
        let mut on = Vec::new();
        super::screen_on(&mut on).unwrap();
        let on = String::from_utf8(on).unwrap();
        assert!(on.contains("\u{1b}[?2004h"), "{on:?}");
        let mut off = Vec::new();
        super::screen_off(&mut off).unwrap();
        let off = String::from_utf8(off).unwrap();
        assert!(off.contains("\u{1b}[?2004l"), "{off:?}");
        let paste = crossterm::event::Event::Paste("a\n/kick Bo".into());
        assert!(matches!(
            super::input_of(paste, std::time::Instant::now()),
            Some(super::Input::Paste(t)) if t == "a\n/kick Bo"
        ));
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
    async fn theme_command_shows_switches_and_saves() {
        use crate::theme::ThemeName;
        let srv = TestServer::start().await;
        let (_g, _a, mut bo, _dir) = room_with_bo(&srv).await;
        assert_eq!(bo.app.theme.name, ThemeName::Phosphor);
        assert_eq!(bo.client.theme().unwrap(), None);
        bo.act(Action::Command(Command::Theme(None))).await;
        assert_eq!(
            bo.app.status.as_deref(),
            Some("Theme: phosphor. Choices: phosphor, classic. Type /theme classic to switch.")
        );
        bo.act(Action::Command(Command::Theme(Some("classic".into()))))
            .await;
        assert_eq!(bo.app.status.as_deref(), Some("Theme: classic."));
        assert_eq!(bo.app.theme.name, ThemeName::Classic);
        assert_eq!(bo.client.theme().unwrap().as_deref(), Some("classic"));
        bo.act(Action::Command(Command::Theme(Some("neon".into()))))
            .await;
        assert_eq!(
            bo.app.status.as_deref(),
            Some("There is no theme called neon. Choices: phosphor, classic.")
        );
        assert_eq!(bo.app.theme.name, ThemeName::Classic);
        bo.act(Action::Command(Command::Theme(Some("Phosphor".into()))))
            .await;
        assert_eq!(bo.app.theme.name, ThemeName::Phosphor);
        assert_eq!(bo.client.theme().unwrap().as_deref(), Some("phosphor"));
    }

    #[tokio::test]
    async fn phosphor_after_classic_keeps_the_terminals_colors() {
        use crate::theme::{ColorSupport, Theme, ThemeName};
        let srv = TestServer::start().await;
        let (_g, _a, mut bo, _dir) = room_with_bo(&srv).await;
        let first = Theme::phosphor(ColorSupport::TrueColor);
        bo.app.theme = first.clone();
        bo.act(Action::Command(Command::Theme(Some("classic".into()))))
            .await;
        assert_eq!(bo.app.theme.name, ThemeName::Classic);
        bo.act(Action::Command(Command::Theme(Some("phosphor".into()))))
            .await;
        assert_eq!(
            bo.app.theme, first,
            "phosphor after classic must match the phosphor the app started with"
        );
    }

    #[tokio::test]
    async fn mouse_off_is_saved_for_this_profile() {
        let srv = TestServer::start().await;
        let (_g, _a, mut bo, _dir) = room_with_bo(&srv).await;
        assert!(bo.app.mouse, "on unless the person turned it off");
        assert_eq!(bo.client.mouse().unwrap(), None);
        bo.act(Action::Command(Command::Mouse(Some(false)))).await;
        assert!(!bo.app.mouse);
        assert_eq!(bo.client.mouse().unwrap(), Some(false));
        assert_eq!(
            bo.app.status.as_deref(),
            Some(
                "Mouse off. Your terminal selects text again. Type /mouse on to click and scroll."
            )
        );
        bo.act(Action::Command(Command::Mouse(None))).await;
        assert_eq!(
            bo.app.status.as_deref(),
            Some("Mouse off. Type /mouse on to click and scroll.")
        );
        bo.act(Action::Command(Command::Mouse(Some(true)))).await;
        assert!(bo.app.mouse);
        assert_eq!(bo.client.mouse().unwrap(), Some(true));
        assert_eq!(
            bo.app.status.as_deref(),
            Some("Mouse on. To select text, hold Shift as you drag (Option or Fn on a Mac).")
        );
    }

    /// The chat screen's mouse setting turns capture on and off, and
    /// giving the terminal back always turns it off. On Windows the console
    /// is switched through its own calls, with nothing written, so the
    /// escape codes are checked on the other systems.
    #[test]
    #[cfg(not(windows))]
    fn mouse_capture_follows_the_setting_and_ends_on_exit() {
        let written = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut out = Vec::new();
            f(&mut out);
            String::from_utf8(out).unwrap()
        };
        let on = written(&|w| super::set_mouse_capture(w, true).unwrap());
        assert!(on.contains("\u{1b}[?1000h"), "{on:?}");
        let off = written(&|w| super::set_mouse_capture(w, false).unwrap());
        assert!(off.contains("\u{1b}[?1000l"), "{off:?}");
        let released = written(&|w| super::screen_off(w).unwrap());
        assert!(released.contains("\u{1b}[?1000l"), "{released:?}");
        assert!(released.contains("\u{1b}[?1049l"), "{released:?}");
        assert!(released.contains("\u{1b}[?2004l"), "{released:?}");
    }

    /// A screen whose clipboard records what it is given and answers
    /// `works`.
    fn fake_clipboard(
        s: &mut Screen,
        works: bool,
    ) -> std::sync::Arc<std::sync::Mutex<Vec<String>>> {
        let got = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let g = got.clone();
        s.clipboard = std::sync::Arc::new(move |t: &str| {
            g.lock().unwrap().push(t.to_string());
            works
        });
        s.terminal_copy = |_| {};
        got
    }

    #[tokio::test]
    async fn invite_copies_as_the_box_opens() {
        let srv = TestServer::start().await;
        let (g, _a, mut bo, _dir) = room_with_bo(&srv).await;
        bo.act(Action::Select(g)).await;
        for works in [true, false] {
            let got = fake_clipboard(&mut bo, works);
            bo.act(Action::Command(Command::Invite { dm: false })).await;
            copy_done(&mut bo).await;
            let Some(Modal::Invite { link, copied, .. }) = bo.app.modal.clone() else {
                panic!("no invite box: {:?}", bo.app.status);
            };
            assert_eq!(copied, works);
            assert_eq!(
                *got.lock().unwrap(),
                vec![crate::app::invite_message(&link)]
            );
            // C copies again and the box says how that went.
            let got = fake_clipboard(&mut bo, true);
            for a in bo.app.handle_key(
                crossterm::event::KeyEvent::new(
                    crossterm::event::KeyCode::Char('c'),
                    crossterm::event::KeyModifiers::NONE,
                ),
                &bo.view(),
            ) {
                bo.act(a).await;
            }
            copy_done(&mut bo).await;
            assert_eq!(got.lock().unwrap().len(), 1);
            assert!(matches!(
                bo.app.modal,
                Some(Modal::Invite { copied: true, .. })
            ));
            bo.app.modal = None;
        }
    }

    /// A server address apps refuse makes no invite link: the invite box
    /// says why and what the server's owner can change, and nothing is
    /// copied.
    #[tokio::test]
    async fn invite_explains_a_server_address_apps_refuse() {
        let srv = TestServer::start().await;
        let (g, _a, mut bo, _dir) = room_with_bo(&srv).await;
        bo.act(Action::Select(g)).await;
        let id = bo.client.test_server_of(g);
        bo.client.test_store_server_host(id, "bücher.example");
        let got = fake_clipboard(&mut bo, true);
        bo.act(Action::Command(Command::Invite { dm: false })).await;
        let Some(Modal::NoInviteLink { why }) = bo.app.modal.clone() else {
            panic!("{:?} {:?}", bo.app.modal, bo.app.status);
        };
        assert!(why.contains("bücher.example"), "{why}");
        assert!(why.contains("public_host"), "{why}");
        assert!(got.lock().unwrap().is_empty(), "nothing to copy");
    }

    /// Waits for the copy under way to finish, and shows how it went, as
    /// the chat screen does when the answer arrives.
    async fn copy_done(s: &mut Screen) {
        let c = s.copies.1.recv().await.expect("a copy finishes");
        s.copied(c);
    }

    /// A clipboard program that takes `ms` to finish, as one waiting on a
    /// slow display server does.
    fn slow_clipboard(s: &mut Screen, ms: u64) {
        s.clipboard = std::sync::Arc::new(move |_: &str| {
            std::thread::sleep(std::time::Duration::from_millis(ms));
            true
        });
        s.terminal_copy = |_| {};
    }

    /// The clipboard program runs beside the screen: the invite box opens
    /// at once saying it is copying, and says copied when the program is
    /// done.
    #[tokio::test]
    async fn copying_an_invite_never_holds_up_the_screen() {
        let srv = TestServer::start().await;
        let (g, _a, mut bo, _dir) = room_with_bo(&srv).await;
        bo.act(Action::Select(g)).await;
        slow_clipboard(&mut bo, 1500);
        bo.app.status = None;
        let t = std::time::Instant::now();
        bo.act(Action::Command(Command::Invite { dm: false })).await;
        assert!(
            t.elapsed() < std::time::Duration::from_millis(1000),
            "the screen waited {:?} for the clipboard",
            t.elapsed()
        );
        assert!(
            matches!(bo.app.modal, Some(Modal::Invite { copied: false, .. })),
            "{:?}",
            bo.app.modal
        );
        let shown = |s: &Screen| {
            let mut t =
                ratatui::Terminal::new(ratatui::backend::TestBackend::new(100, 50)).unwrap();
            let vm = s.view();
            t.draw(|f| crate::ui::draw(f, &s.app, &vm)).unwrap();
            let buf = t.backend().buffer().clone();
            buf.content().iter().map(|c| c.symbol()).collect::<String>()
        };
        assert!(shown(&bo).contains("Copying…"));
        copy_done(&mut bo).await;
        assert!(!bo.app.copying);
        assert!(matches!(
            bo.app.modal,
            Some(Modal::Invite { copied: true, .. })
        ));
        assert!(shown(&bo).contains("Copied. Press C to copy again."));
        // The copy said nothing on the status line: the box shows it.
        assert_eq!(bo.app.status, None);
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

    /// /verify on a member whose join is not confirmed yet says they have
    /// not shared their identity in this chat.
    #[tokio::test]
    async fn verify_on_a_member_who_has_not_shared_their_identity() {
        let srv = TestServer::start().await;
        let (g, mut a, mut bo, _dir) = room_with_bo(&srv).await;
        let bk = bo.client.my_group_key(g).unwrap();
        a.make_admin(g, &bk).await.unwrap();
        let link = a.invite(Some(g), false).await.unwrap().0;
        for _ in 0..3 {
            a.sync().await.unwrap();
            bo.sync().await;
        }
        // Ada is away, so Cy's join waits for her and his name stays
        // hidden; Bo, an admin, lets him in.
        drop(a);
        let mut c = TestClient::profile_only("Cy").await;
        c.join(&link).await.unwrap();
        for _ in 0..3 {
            bo.sync().await;
            c.sync().await.unwrap();
        }
        let ck = c.my_group_key(g).unwrap();
        let cy = bo
            .client
            .members(g)
            .into_iter()
            .find(|m| m.key == ck)
            .expect("Cy is in");
        assert!(cy.name.starts_with("someone ("), "{}", cy.name);
        bo.act(Action::Select(g)).await;
        bo.act(Action::Command(Command::Verify(cy.name.clone())))
            .await;
        assert_eq!(
            bo.app.status,
            Some(format!(
                "{} has not shared their identity in this chat yet.",
                cy.name
            ))
        );
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
            Some("You have 1 new message in Room. Read it, then type /leave again to leave.")
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
        let Some(Modal::Details { lines, .. }) = bo.app.modal.take() else {
            panic!("no details: {:?}", bo.app.status);
        };
        assert_eq!(lines[0], "Name: Room");
        assert_eq!(lines[1], format!("Server: {}", srv.addr()));
        assert_eq!(lines[2], "Admins: Ada");
        assert_eq!(lines[3], "Members: 2");
        assert!(
            lines[4].starts_with("Created: 20") && lines[4].len() == "Created: 2026-10-20".len(),
            "{lines:?}"
        );
        assert_eq!(lines[6], "Muted: no");
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

    /// Ada's room with Bo on a screen and Mo, who has the same kind of
    /// access as Ada.
    async fn room_with_bo_and_mo(
        s: &TestServer,
    ) -> (GroupId, TestClient, TestClient, Screen, tempfile::TempDir) {
        let (g, mut a, mut bo, dir) = room_with_bo(s).await;
        let mut mo = TestClient::new(s, "Mo").await;
        mo.join(&a.invite(Some(g), false).await.unwrap().0)
            .await
            .unwrap();
        for _ in 0..4 {
            a.sync().await.unwrap();
            mo.sync().await.unwrap();
            bo.sync().await;
        }
        (g, a, mo, bo, dir)
    }

    #[tokio::test]
    async fn save_refuses_a_name_two_files_share_and_names_each_sender() {
        let srv = TestServer::start().await;
        let (g, mut a, mut mo, mut bo, _dir) = room_with_bo_and_mo(&srv).await;
        bo.act(Action::Select(g)).await;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("setup.sh");
        std::fs::write(&p, b"from Ada").unwrap();
        a.send_file(g, &p, false).await.unwrap();
        a.sync().await.unwrap();
        std::fs::write(&p, b"from Mo").unwrap();
        mo.send_file(g, &p, false).await.unwrap();
        for _ in 0..3 {
            bo.sync().await;
        }
        let out = tempfile::tempdir().unwrap();
        let folder = Some(out.path().display().to_string());
        let save = |file: &str| Command::Save {
            file: file.into(),
            dir: folder.clone(),
        };
        let err = bo.command(save("setup.sh")).await.unwrap_err();
        assert!(err.contains("Ada") && err.contains("Mo"), "{err}");
        assert!(
            err.contains("setup.sh:1") && err.contains("setup.sh:2"),
            "{err}"
        );
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
        // The one Ada sent, picked by its number.
        bo.command(save("setup.sh:1")).await.unwrap();
        let status = bo.app.status.clone().unwrap();
        assert!(status.starts_with("Saved Ada's setup.sh to "), "{status}");
        let saved = out.path().join("setup.sh");
        assert_eq!(std::fs::read(&saved).unwrap(), b"from Ada");
        bo.command(save("setup.sh:2")).await.unwrap();
        assert!(bo
            .app
            .status
            .clone()
            .unwrap()
            .starts_with("Saved Mo's setup.sh"));
        assert_eq!(
            std::fs::read(out.path().join("setup (1).sh")).unwrap(),
            b"from Mo"
        );
        assert!(bo.command(save("setup.sh:3")).await.is_err());
    }

    /// A file whose own name looks like a numbered pick cannot stand in for
    /// the file that pick names.
    #[tokio::test]
    async fn a_name_shaped_like_a_pick_is_refused_too() {
        let srv = TestServer::start().await;
        let (g, mut a, mut mo, mut bo, _dir) = room_with_bo_and_mo(&srv).await;
        bo.act(Action::Select(g)).await;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.txt");
        std::fs::write(&p, b"from Ada").unwrap();
        a.send_file(g, &p, false).await.unwrap();
        a.send_file(g, &p, false).await.unwrap();
        // Names lose ':' on the way, so this arrives as "a.txt1".
        let q = d.path().join("a.txt:1");
        std::fs::write(&q, b"from Mo").unwrap();
        mo.send_file(g, &q, false).await.unwrap();
        for _ in 0..3 {
            bo.sync().await;
        }
        let out = tempfile::tempdir().unwrap();
        bo.command(Command::Save {
            file: "a.txt:1".into(),
            dir: Some(out.path().display().to_string()),
        })
        .await
        .unwrap();
        assert_eq!(
            std::fs::read(out.path().join("a.txt")).unwrap(),
            b"from Ada"
        );
    }

    #[tokio::test]
    async fn a_single_file_saves_by_name_and_says_who_sent_it() {
        let srv = TestServer::start().await;
        let (g, mut a, mut bo, _dir) = room_with_bo(&srv).await;
        bo.act(Action::Select(g)).await;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("notes.txt");
        std::fs::write(&p, b"hello").unwrap();
        a.send_file(g, &p, false).await.unwrap();
        for _ in 0..3 {
            bo.sync().await;
        }
        let out = tempfile::tempdir().unwrap();
        bo.command(Command::Save {
            file: "notes.txt".into(),
            dir: Some(out.path().display().to_string()),
        })
        .await
        .unwrap();
        let status = bo.app.status.clone().unwrap();
        assert!(status.starts_with("Saved Ada's notes.txt to "), "{status}");
        let err = bo
            .command(Command::Save {
                file: "other.txt".into(),
                dir: None,
            })
            .await
            .unwrap_err();
        assert_eq!(err, "No file called other.txt in this chat.");
    }

    #[tokio::test]
    async fn a_photo_that_cannot_be_cleaned_asks_like_a_video() {
        let srv = TestServer::start().await;
        let (g, _a, mut bo, _dir) = room_with_bo(&srv).await;
        bo.act(Action::Select(g)).await;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("raw.dng");
        std::fs::write(&p, b"II*\0\x08\0\0\0 camera raw").unwrap();
        let path = p.display().to_string();
        bo.command(Command::Send(path.clone())).await.unwrap();
        assert_eq!(bo.app.modal, Some(Modal::ConfirmPhoto { group: g, path }));
    }

    /// Ada's room "Room" on a screen, with each of `names` in it as a
    /// test client.
    async fn ada_with(
        s: &TestServer,
        names: &[&str],
    ) -> (GroupId, Screen, Vec<TestClient>, tempfile::TempDir) {
        let (mut ada, dir) = screen(s, "Ada").await;
        let g = ada.client.create_group("Room").await.unwrap();
        let mut others = vec![];
        for name in names {
            let mut c = TestClient::new(s, name).await;
            let link = ada.client.invite(Some(g), false).await.unwrap().0;
            c.join(&link).await.unwrap();
            for _ in 0..4 {
                ada.sync().await;
                c.sync().await.unwrap();
            }
            others.push(c);
        }
        ada.act(Action::Select(g)).await;
        (g, ada, others, dir)
    }

    /// Names kept with two spaces in a row or a wide space, as an earlier
    /// release kept them, still answer to the name typed with one space.
    #[tokio::test]
    async fn kick_finds_a_member_whose_name_has_odd_spacing() {
        let srv = TestServer::start().await;
        let (g, mut ada, others, _dir) = ada_with(&srv, &["Mal", "Ken"]).await;
        for (c, stored, typed) in [
            (&others[0], "Mal  lory", "Mal lory"),
            (&others[1], "Ken\u{3000}ji", "Ken ji"),
        ] {
            let key = c.my_group_key(g).unwrap();
            ada.client.test_store_member_name(g, key, stored);
            assert!(ada.client.members(g).iter().any(|m| m.name == stored));
            let r = ada.command(Command::Kick(typed.into())).await;
            assert_eq!(r, Ok(()), "{stored:?}");
            assert!(
                !ada.client.members(g).iter().any(|m| m.key == key),
                "{stored:?} is still in the room"
            );
        }
    }

    /// Answers the open box with y, as a key press does.
    async fn press_y(s: &mut Screen) {
        let vm = s.view();
        let y = crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('y'),
            crossterm::event::KeyModifiers::NONE,
        );
        for a in s.app.handle_key(y, &vm) {
            s.act(a).await;
        }
    }

    /// A photo that cannot be cleaned waits for y. A room joined in the
    /// background meanwhile, as a direct chat someone starts with you is,
    /// never changes where y sends it.
    #[tokio::test]
    async fn a_photo_question_sends_to_its_own_room_after_a_background_join() {
        use socketchat_core::client::{Event, Verification};
        let srv = TestServer::start().await;
        let (g, _a, mut bo, _dir) = room_with_bo(&srv).await;
        let other = bo.client.create_group("Other").await.unwrap();
        bo.act(Action::Select(g)).await;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("raw.dng");
        std::fs::write(&p, b"II*\0\x08\0\0\0 camera raw").unwrap();
        let path = p.display().to_string();

        bo.command(Command::Send(path.clone())).await.unwrap();
        assert!(matches!(bo.app.modal, Some(Modal::ConfirmPhoto { .. })));
        bo.on_event(Event::Joined {
            group: other,
            verification: Verification::Verified,
        });
        press_y(&mut bo).await;
        assert_eq!(bo.client.shared_files(other).len(), 0, "sent to Other");
        assert_eq!(bo.client.shared_files(g).len(), 1, "{:?}", bo.app.status);
        assert_eq!(bo.app.selected, Some(g), "the open room stays open");

        // However the open room changes under the question, y answers for
        // the room it was asked in.
        bo.command(Command::Send(path)).await.unwrap();
        assert!(matches!(bo.app.modal, Some(Modal::ConfirmPhoto { .. })));
        bo.app.selected = Some(other);
        press_y(&mut bo).await;
        assert_eq!(bo.client.shared_files(other).len(), 0, "sent to Other");
        assert_eq!(bo.client.shared_files(g).len(), 2, "{:?}", bo.app.status);
    }

    /// Words half typed in the message box stay with the room they were
    /// typed for: a room joined in the background is named on the status
    /// line instead of opening.
    #[tokio::test]
    async fn a_background_join_waits_while_the_message_box_has_text() {
        use socketchat_core::client::{Event, Verification};
        let srv = TestServer::start().await;
        let (g, _a, mut bo, _dir) = room_with_bo(&srv).await;
        let other = bo.client.create_group("Other").await.unwrap();
        bo.act(Action::Select(g)).await;
        bo.app.input = "half a thou".into();
        bo.on_event(Event::Joined {
            group: other,
            verification: Verification::Waiting {
                inviter: "Ada".into(),
            },
        });
        assert_eq!(bo.app.selected, Some(g));
        assert_eq!(bo.app.input, "half a thou");
        assert_eq!(
            bo.app.status.as_deref(),
            Some("You joined Other. Waiting for Ada to confirm this invite.")
        );

        // A join that could not be checked says so, and its warning shows
        // once the room opens.
        bo.on_event(Event::Joined {
            group: other,
            verification: Verification::Unverified {
                reason: "the link was changed".into(),
            },
        });
        assert_eq!(bo.app.selected, Some(g));
        assert_eq!(bo.app.warning, None, "no warning on the wrong room");
        assert_eq!(
            bo.app.status.as_deref(),
            Some("You joined Other, but the invite could not be checked. Open Other to see what to do.")
        );
        // The note that comes with such a join adds to that line.
        bo.on_event(Event::Warning(socketchat_core::client::HIDDEN_NAME.into()));
        assert_eq!(
            bo.app.status.as_deref(),
            Some("You joined Other, but the invite could not be checked. Open Other to see what to do. Your name stays hidden there until you mark someone verified.")
        );
        bo.act(Action::Select(other)).await;
        assert!(
            bo.app
                .warning
                .as_deref()
                .is_some_and(|w| w.contains("the link was changed")),
            "{:?}",
            bo.app.warning
        );

        // With an empty message box and no box open, the room opens.
        bo.act(Action::Select(g)).await;
        bo.app.input.clear();
        bo.on_event(Event::Joined {
            group: other,
            verification: Verification::Verified,
        });
        assert_eq!(bo.app.selected, Some(other));
        assert_eq!(
            bo.app.status.as_deref(),
            Some("You joined. The person who invited you is verified.")
        );
    }

    #[tokio::test]
    async fn servers_list_and_forget_by_number() {
        let (s1, s2) = (TestServer::start().await, TestServer::start().await);
        let (n1, n2) = (s1.addr().to_string(), s2.addr().to_string());
        let (mut ada, _dir) = screen(&s1, "Ada").await;
        let old = ada.client.create_group("Old crew").await.unwrap();
        ada.client.join(&s2.server_invite()).await.unwrap();

        // New rooms follow the open room, and say where they went.
        ada.act(Action::Select(old)).await;
        ada.act(Action::Command(Command::New("Side room".into())))
            .await;
        assert_eq!(
            ada.app.status.as_deref(),
            Some(format!("Made Side room on {n1}.").as_str())
        );
        assert_eq!(ada.view().server, Some(n1.clone()));
        ada.sync().await;
        ada.act(Action::Command(Command::Servers)).await;
        let Some(Modal::Servers { rows, .. }) = ada.app.modal.take() else {
            panic!("no list: {:?}", ada.app.status);
        };
        assert_eq!(
            rows,
            [
                format!("1. {n1}: 2 rooms, connected (new rooms go here)"),
                format!("2. {n2}: no rooms, connected"),
            ]
        );

        // The first server stops: errors name it.
        s1.handle.shutdown();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        ada.client.test_drop_connections();
        let open = ada.app.selected.unwrap();
        ada.act(Action::Send(open, "anyone?".into())).await;
        assert_eq!(
            ada.app.status.as_deref(),
            Some(
                format!(
                    "Could not reach {n1}: connection refused. Type /servers to see your servers."
                )
                .as_str()
            )
        );
        ada.act(Action::Command(Command::Servers)).await;
        let Some(Modal::Servers { rows, .. }) = ada.app.modal.take() else {
            panic!("no list: {:?}", ada.app.status);
        };
        assert_eq!(
            rows[0],
            format!("1. {n1}: 2 rooms, could not reach: connection refused (new rooms go here)")
        );

        // Forgetting it asks first, then deletes its rooms here.
        ada.act(Action::Command(Command::Forget(1))).await;
        let Some(Modal::Confirm { question, yes }) = ada.app.modal.take() else {
            panic!("no question: {:?}", ada.app.status);
        };
        assert_eq!(question, crate::app::forget_question(&n1, 2));
        ada.act(*yes).await;
        assert_eq!(
            ada.app.status.as_deref(),
            Some(format!("Forgot {n1}. Its 2 rooms are deleted from this computer.").as_str())
        );
        assert!(ada.view().groups.is_empty());
        assert_eq!(ada.app.selected, None);
        ada.act(Action::Command(Command::Forget(1))).await;
        assert_eq!(
            ada.app.status.as_deref(),
            Some("That server is already forgotten.")
        );
        ada.act(Action::Command(Command::Forget(5))).await;
        assert_eq!(
            ada.app.status.as_deref(),
            Some("Type /servers first, then /forget with a number from that list.")
        );

        // What is left: the second server, where new rooms now go. Its
        // connection was dropped too, and the next sync makes it again.
        ada.sync().await;
        ada.act(Action::Command(Command::Servers)).await;
        let Some(Modal::Servers { rows, .. }) = ada.app.modal.take() else {
            panic!("no list: {:?}", ada.app.status);
        };
        assert_eq!(
            rows,
            [format!("1. {n2}: no rooms, connected (new rooms go here)")]
        );
        ada.act(Action::Command(Command::New("Fresh".into()))).await;
        assert_eq!(
            ada.app.status.as_deref(),
            Some(format!("Made Fresh on {n2}.").as_str())
        );
    }
}
