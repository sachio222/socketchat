//! The live screen: draws, reads keys, and carries out what they ask.

use std::collections::HashMap;
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
use socketchat_core::client::{Client, Event, Verification};
use socketchat_core::keys::{fingerprint_text, Key};
use socketchat_core::CoreError;
use socketchat_proto::msg::GroupId;
use socketchat_proto::InviteLink;
use tokio::sync::mpsc;

use crate::app::{sent_file_status, Action, App, Modal};
use crate::commands::Command;
use crate::ui::{draw, GroupView, LineView, MemberLine, ViewModel};

/// How often the screen checks in with the server when nothing arrives.
const IDLE_SYNC: Duration = Duration::from_secs(5);

struct Screen {
    client: Client,
    app: App,
    unread: HashMap<GroupId, u32>,
    quit: bool,
    /// The status line says the connection dropped; the next good sync
    /// clears it.
    offline_note: bool,
}

/// What the status line says when an action fails because the connection
/// dropped. The app reconnects on its own at the next sync.
const OFFLINE_NOTE: &str = "Lost the connection to the server. socketchat is reconnecting.";

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

impl Screen {
    fn view(&self) -> ViewModel {
        let groups: Vec<GroupView> = self
            .client
            .groups()
            .into_iter()
            .filter(|g| !g.left)
            .map(|g| {
                let name = if g.name.is_empty() {
                    self.client
                        .members(g.id)
                        .into_iter()
                        .filter(|m| !m.me)
                        .map(|m| m.name)
                        .collect::<Vec<_>>()
                        .join(", ")
                } else {
                    g.name
                };
                let name = if name.is_empty() {
                    "(waiting for people)".to_string()
                } else {
                    name
                };
                GroupView {
                    id: g.id,
                    unread: self.unread.get(&g.id).copied().unwrap_or(0),
                    name,
                    is_dm: g.is_dm,
                }
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

    fn select(&mut self, g: GroupId) {
        self.app.selected = Some(g);
        self.app.scroll = 0;
        self.unread.remove(&g);
    }

    fn select_first(&mut self) {
        let first = self
            .client
            .groups()
            .into_iter()
            .find(|g| !g.left)
            .map(|g| g.id);
        self.app.selected = None;
        if let Some(g) = first {
            self.select(g);
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
        match e {
            Event::Message { group, .. } | Event::FileOffered { group, .. } => {
                if Some(group) != self.app.selected {
                    *self.unread.entry(group).or_default() += 1;
                }
            }
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
                if Some(group) == self.app.selected {
                    self.select_first();
                }
                self.app.status = Some(if name.is_empty() {
                    "You are no longer in that chat.".into()
                } else {
                    format!("You are no longer in {name}.")
                });
            }
            Event::Warning(w) => self.app.status = Some(w),
            Event::NameChanged { old, new, .. } => {
                self.app.status = Some(format!("{old} is now called {new}."));
            }
            _ => {}
        }
        if self.app.selected.is_none() {
            self.select_first();
        }
    }

    async fn act(&mut self, a: Action) {
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
            Action::Command(c) => self.command(c).await,
        };
        if let Err(e) = r {
            if self.client.connected() {
                self.app.status = Some(e);
            } else {
                self.app.status = Some(OFFLINE_NOTE.into());
                self.offline_note = true;
            }
        }
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
        let mut said: Vec<String> = Vec::new();
        for ev in self.client.take_events() {
            match ev {
                Event::Warning(w) => said.push(w),
                ev => self.on_event(ev),
            }
        }
        said.push(match st {
            socketchat_core::client::JoinStatus::Registered => {
                "You are on the server. Start a chat with /new <name>.".into()
            }
            socketchat_core::client::JoinStatus::Waiting { for_name } => {
                format!("Asked to join. Waiting for {for_name}.")
            }
        });
        self.app.status = Some(said.join(" "));
        Ok(())
    }

    async fn command(&mut self, c: Command) -> Result<(), String> {
        let sel = self.app.selected;
        let need = || sel.ok_or_else(|| "Open a chat first.".to_string());
        let e = |e: CoreError| e.to_string();
        match c {
            Command::Quit => self.quit = true,
            Command::Help => self.app.modal = Some(Modal::Help),
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
                let k = self.member(&name)?;
                let g = self.client.dm(need()?, &k).await.map_err(e)?;
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
                let k = self.member(&name)?;
                let number = self.client.safety_number(need()?, &k).ok_or_else(|| {
                    format!("{name} has not shared their identity yet. Try again in a moment.")
                })?;
                self.app.modal = Some(Modal::Verify {
                    name,
                    key: k,
                    number,
                });
            }
            Command::Rename { name, new } => {
                let k = self.member(&name)?;
                self.client.rename_local(need()?, &k, &new).map_err(e)?;
            }
            Command::Name(new) => self.client.set_display_name(&new).await.map_err(e)?,
            Command::Kick(name) => {
                let k = self.member(&name)?;
                self.client.remove_member(need()?, &k).await.map_err(e)?;
            }
            Command::Admin(name) => {
                let k = self.member(&name)?;
                self.client.make_admin(need()?, &k).await.map_err(e)?;
            }
            Command::Leave => {
                self.client.leave(need()?).await.map_err(e)?;
                self.app.status =
                    Some("Leaving. You are out once another member's app confirms it.".into());
            }
        }
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
    let mut s = Screen {
        client,
        app: App::new(),
        unread: HashMap::new(),
        quit: false,
        offline_note: false,
    };
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
                }
                Some(None) => {}
                None => return Ok(()),
            },
            _ = s.client.wait(IDLE_SYNC) => s.sync().await,
        }
        if s.quit {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{clock_time, to_base64, Action, App, HashMap, Screen};
    use socketchat_core::client::Client;
    use socketchat_proto::msg::GroupId;

    #[tokio::test]
    async fn text_that_fails_to_send_goes_back_in_the_box() {
        let dir = tempfile::tempdir().unwrap();
        let client = Client::create_profile(dir.path(), "test passphrase", "Ada")
            .await
            .unwrap();
        let mut s = Screen {
            client,
            app: App::new(),
            unread: HashMap::new(),
            quit: false,
            offline_note: false,
        };
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
}
