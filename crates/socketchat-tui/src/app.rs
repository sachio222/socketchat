//! The screen's state and what each key does. No drawing, no network:
//! keys go in, actions come out, and the run loop carries them out.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::{Position, Rect};
use socketchat_core::client::{
    Ended, InviteSent, Link, RoomDetails, ServerState, ServerView, StatusView,
};
use socketchat_core::invite::hours_text;
use socketchat_core::keys::{fingerprint_text, Key};
use socketchat_core::sanitize::{direction_char, single_spaced, MAX_TEXT_BYTES};
use socketchat_core::settings::{every, WhoCanInvite, WhoCanSetTopic};
use socketchat_proto::msg::{FileId, GroupId};
use socketchat_proto::Token;

use crate::commands::{command_of, command_words, help_entries, parse_command, Command};
use crate::select::{ordered, picked, Area, Spot, TextArea};
use crate::theme::{Theme, THEMES};
use crate::ui::{box_rows, line_at_row, message_body, GroupView, LineView, ViewModel};

pub use socketchat_proto::invite_message;

mod dropped;
pub(crate) use dropped::{cleaned_status, not_sent, sendable};
pub use dropped::{dropped_paths, Attachment, DropKind};

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
    /// The server, the connection, this profile, the open room and the
    /// app, from [`status_lines`], scrolled down by `offset` rows.
    Status { lines: Vec<String>, offset: usize },
    /// The version, what socketchat is and where to find it.
    About,
    /// The command list, scrolled down by `offset` rows, with row `pick`
    /// of [`help_entries`] highlighted.
    Help { offset: usize, pick: usize },
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

/// What `/invite <name>` says once the invite is on its way. `open` says
/// the invite is to the room on screen.
pub fn invite_sent_status(s: &InviteSent, open: bool) -> String {
    let (to, says) = if open {
        (String::new(), "This room".to_string())
    } else {
        (format!(" to {}", s.room), s.room.clone())
    };
    let sent = match s.wait_secs {
        None => format!("Invited {}{to} through {}.", s.name, s.via),
        Some(n) => format!(
            "{} limits fast posting, so {} gets the invite in {}.",
            s.via,
            s.name,
            seconds_text(n)
        ),
    };
    format!("{sent} {says} says when they join.")
}

fn seconds_text(n: u64) -> String {
    if n == 1 {
        "1 second".into()
    } else {
        format!("{n} seconds")
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
    /// Send the files dropped in the message box to this room, then the
    /// words around them.
    SendDrop(GroupId),
    /// Save this file from this room in the default folder: a click on
    /// the line that says someone sent it.
    SaveFile(GroupId, FileId),
    /// Join with this link, trusting the certificate it names.
    AcceptCertificate(String),
    MarkVerified(Key),
    /// Put this text on the terminal's clipboard.
    Copy(String),
    /// Put this text, which the person selected with the mouse, on the
    /// clipboard, and say on the status line how that went.
    CopySelected(String),
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
/// socketchat is, the project link, the license and `updates`, which says
/// whether the update check is on (see [`update_about`]).
pub fn about_lines(updates: &str) -> Vec<String> {
    let license = env!("CARGO_PKG_LICENSE")
        .replace(" OR ", " or ")
        .replace("Apache-", "Apache ");
    let mut lines = vec![
        version_text(),
        String::new(),
        "Socketchat is end-to-end encrypted chat with a server you run yourself. The server passes messages along but cannot read them. It still sees timing, message sizes, IP addresses and how many people are in each room.".into(),
        String::new(),
        env!("CARGO_PKG_REPOSITORY").into(),
        format!("License: {license}"),
    ];
    if !updates.is_empty() {
        lines.push(String::new());
        lines.push(updates.to_string());
    }
    lines
}

/// What `/about` says about the update check: whether it is on, and when
/// GitHub last answered, as `when` writes a time.
pub fn update_about(
    s: &socketchat_core::update::UpdateState,
    env_off: bool,
    when: &dyn Fn(u64) -> String,
) -> String {
    if env_off {
        format!(
            "Update check: off for this run, because {} is set.",
            socketchat_core::update::OFF_VAR
        )
    } else if !s.on {
        "Update check: off. Type /updates on to turn it on.".into()
    } else {
        match s.answered_unix {
            Some(t) => format!("Update check: on, once a day. Last checked {}.", when(t)),
            None => "Update check: on, once a day. Not checked yet.".into(),
        }
    }
}

/// The local date and time of `unix`, as "YYYY-MM-DD at HH:MM".
pub fn local_date_time(unix: u64) -> String {
    chrono::DateTime::from_timestamp(unix as i64, 0)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%Y-%m-%d at %H:%M")
                .to_string()
        })
        .unwrap_or_default()
}

/// The local date `unix` falls on, as YYYY-MM-DD.
pub fn local_date(unix: u64) -> String {
    chrono::DateTime::from_timestamp(unix as i64, 0)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%Y-%m-%d")
                .to_string()
        })
        .unwrap_or_default()
}

/// The line a room shows once to say it is end-to-end encrypted.
pub fn encryption_text(
    state: &socketchat_core::client::JoinCheck,
    is_dm: bool,
    others_verified: bool,
) -> String {
    use socketchat_core::client::JoinCheck;
    let who = match state {
        JoinCheck::Checked if is_dm => " Only the two of you can read this chat.".to_string(),
        JoinCheck::Checked => " Only the people in the People list can read this room.".to_string(),
        // Someone verified in another room shows verified here as well.
        JoinCheck::Waiting { inviter } if others_verified => format!(
            " Waiting for {inviter} to confirm your invite, so {inviter} is not verified yet."
        ),
        JoinCheck::Waiting { inviter } => format!(
            " Waiting for {inviter} to confirm your invite, so nobody here is verified yet."
        ),
        JoinCheck::Unchecked => String::new(),
    };
    format!(
        "End-to-end encrypted.{who} The server passes messages along but cannot read them. /details says what it can see."
    )
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
    let topic = match &d.topic {
        Some(t) => t.words(&date(t.set_unix)),
        None => "Topic: none".into(),
    };
    let mut lines = vec![
        format!("Name: {name}"),
        format!("Server: {}", d.server),
        topic,
        format!("Admins: {}", d.admins.join(", ")),
        format!("Members: {}", d.size),
        format!("Created: {created}"),
        format!("You joined: {}", date(d.joined_unix)),
        format!("Muted: {}", if d.muted { "yes" } else { "no" }),
    ];
    lines.extend(room_settings_lines(
        d.invite,
        d.slow_secs,
        d.topic_who,
        d.server_members_invite,
    ));
    if d.server_enforces == Some(false) {
        lines.push(OLD_SERVER_SETTINGS.into());
    }
    if let Some(c) = d.close.as_ref().filter(|c| c.yes > 0 && !c.kept) {
        lines.push(format!("Closing: {} of {} admins agree", c.yes, c.needed));
    }
    lines.push(String::new());
    lines.extend(
        encryption_lines(d.post_quantum)
            .into_iter()
            .map(String::from),
    );
    lines
}

/// The Encryption section of `/details`, for a room whose suite is
/// post-quantum or not. Each claim matches SECURITY.md.
pub fn encryption_lines(post_quantum: bool) -> [&'static str; 4] {
    [
        "Encryption: end-to-end, MLS (RFC 9420)",
        if post_quantum {
            "Post-quantum: yes for messages and files (ML-KEM-768 + X25519). Signatures and the link to the server are not post-quantum yet."
        } else {
            "Post-quantum: no. This room uses the standard suite (0x0001)."
        },
        "The server cannot see: messages, files, names, room name, topic.",
        "The server sees: when messages move, message sizes in 256-byte blocks, file sizes, IP addresses, a random key for each member, which of them are admins, and the room's settings.",
    ]
}

/// A room's settings as `/details` and `/status` show them: as
/// [`settings_lines`] has them, unless the server's own rule on inviting,
/// `server_members_invite`, is stricter than the room's, when the line
/// says whose rule it is.
fn room_settings_lines(
    invite: WhoCanInvite,
    slow_secs: u32,
    topic: WhoCanSetTopic,
    server_members_invite: Option<bool>,
) -> Vec<String> {
    let mut settings = settings_lines(invite, slow_secs, topic);
    if server_members_invite == Some(false) && invite == WhoCanInvite::Anyone {
        settings[0] =
            "Who can invite: admins only, because this server lets only admins invite people"
                .into();
    }
    settings
}

/// What `/status` says about the app that the client does not know: the
/// theme in use, whether the mouse is on, and the update check from
/// [`update_status`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppStatus {
    pub theme: String,
    pub mouse: bool,
    pub updates: String,
}

/// The section headings of the `/status` box.
pub const STATUS_HEADINGS: [&str; 4] = ["Connection", "You", "This room", "App"];

/// The lines of the `/status` box and of `socketchat status`: a heading for
/// each section, then one fact a line. `room` is the open room's name as
/// the list shows it; `when` writes a time as a date and a time of day.
pub fn status_lines(
    s: &StatusView,
    room: Option<&str>,
    app: &AppStatus,
    when: &dyn Fn(u64) -> String,
) -> Vec<String> {
    let [connection, you, this_room, app_heading] = STATUS_HEADINGS;
    let mut lines = vec![connection.to_string()];
    match &s.server {
        None => lines.push("Server: none yet".into()),
        Some(server) => {
            lines.push(format!("Server: {}", server.host));
            lines.push(format!("Port: {}", server.port));
            lines.push(match &server.link {
                Link::Connected { since_unix, .. } => {
                    format!("State: connected since {}", when(*since_unix))
                }
                Link::Lost => "State: connection lost; reconnecting".into(),
                Link::Unreachable(why) => format!("State: could not reach: {why}"),
                Link::NotYet => "State: not connected yet".into(),
            });
            if let Link::Connected { protocol, .. } = server.link {
                lines.push(format!("Protocol: {protocol}"));
            }
            lines.push(format!(
                "Certificate fingerprint: {}",
                fingerprint_text(&server.cert_fpr)
            ));
            match server.members_invite {
                Some(true) => lines.push("Inviting into rooms: each room's setting decides".into()),
                Some(false) => lines
                    .push("Inviting into rooms: admins only, in every room on this server".into()),
                None => {}
            }
        }
    }
    if s.other_servers > 0 {
        lines.push(format!("Other servers: {}", s.other_servers));
    }
    lines.push(String::new());
    lines.push(you.into());
    lines.push(format!("Name: {}", s.name));
    lines.push(format!(
        "Your half of each safety number: {}",
        s.safety_digits
    ));
    if let Some(server) = &s.server {
        lines.push(format!("Rooms on this server: {}", server.rooms));
    }
    if let (Some(r), Some(name)) = (&s.room, room) {
        lines.push(String::new());
        lines.push(this_room.into());
        lines.push(format!("Name: {name}"));
        lines.push(format!(
            "Kind: {}",
            if r.is_dm { "direct chat" } else { "group chat" }
        ));
        lines.push(format!("Members: {}, {} verified", r.members, r.verified));
        lines.push(format!("Admins: {}", r.admins));
        lines.push(format!(
            "Your role: {}",
            if r.admin { "admin" } else { "member" }
        ));
        let server = s.server.as_ref();
        lines.extend(room_settings_lines(
            r.invite,
            r.slow_secs,
            r.topic_who,
            server.and_then(|s| s.members_invite),
        ));
        let old = server
            .is_some_and(|s| matches!(s.link, Link::Connected { protocol, .. } if protocol < 3));
        if old {
            lines.push(OLD_SERVER_SETTINGS.into());
        }
        lines.push(format!(
            "Has a topic: {}",
            if r.topic { "yes" } else { "no" }
        ));
        let [encryption, post_quantum, ..] = encryption_lines(r.post_quantum);
        lines.push(encryption.into());
        lines.push(format!("Suite: {}", r.suite));
        lines.push(post_quantum.into());
    }
    lines.push(String::new());
    lines.push(app_heading.into());
    lines.push(format!("Version: {}", env!("CARGO_PKG_VERSION")));
    lines.push(app.updates.clone());
    lines.push(format!("Theme: {}", app.theme));
    lines.push(format!("Mouse: {}", if app.mouse { "on" } else { "off" }));
    lines.push(String::new());
    lines.push("/details lists what the server can and cannot see in each room.".into());
    lines
}

/// What `/status` says about the update check: what `/about` says (see
/// [`update_about`]), and the newest release GitHub named when it last
/// answered.
pub fn update_status(
    s: &socketchat_core::update::UpdateState,
    env_off: bool,
    when: &dyn Fn(u64) -> String,
) -> String {
    let said = update_about(s, env_off, when);
    match (&s.latest, s.answered_unix) {
        (Some(v), Some(_)) if s.on && !env_off => {
            format!("{said} The newest release then was {v}.")
        }
        _ => said,
    }
}

/// Said in a room's details when its server is from before 0.5.2.
pub const OLD_SERVER_SETTINGS: &str =
    "This server runs an older version of Socketchat, so it can't enforce who can invite or slow mode.";

/// A room's settings, one line each, as `/details` and `/settings` show
/// them.
pub fn settings_lines(invite: WhoCanInvite, slow_secs: u32, topic: WhoCanSetTopic) -> Vec<String> {
    let who = match invite {
        WhoCanInvite::Admins => "admins only",
        WhoCanInvite::Anyone => "anyone in the room",
    };
    let slow = match slow_secs {
        0 => "off".to_string(),
        n => format!(
            "one message {} for each member who isn't an admin",
            every(n)
        ),
    };
    let topic = match topic {
        WhoCanSetTopic::Admins => "admins only",
        WhoCanSetTopic::Anyone => "anyone in the room",
    };
    vec![
        format!("Who can invite: {who}"),
        format!("Slow mode: {slow}"),
        format!("Who can set the topic: {topic}"),
    ]
}

/// The status line while a message waits because the room limits fast
/// posting.
pub fn held_line(wait_secs: u64) -> String {
    let when = match wait_secs {
        1 => "1 second".to_string(),
        n => format!("{n} seconds"),
    };
    format!("{HELD_LEAD} {when}.")
}

/// How [`held_line`] starts.
pub const HELD_LEAD: &str = "This room limits fast posting; sending in";

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
    ranked_at(text, groups.iter().map(|g| g.name.as_str()))
        .into_iter()
        .map(|i| &groups[i])
        .collect()
}

/// The places in `names` that `text` can mean, best first, by the rule
/// [`ranked`] follows for rooms.
fn ranked_at<'a>(text: &str, names: impl Iterator<Item = &'a str>) -> Vec<usize> {
    let t = fold(text);
    let names: Vec<(usize, String)> = names.map(fold).enumerate().collect();
    let exact = names.iter().filter(|(_, n)| *n == t);
    let starts = names.iter().filter(|(_, n)| *n != t && n.starts_with(&t));
    let first: Vec<usize> = exact.chain(starts).map(|(i, _)| *i).collect();
    if !first.is_empty() {
        return first;
    }
    names
        .iter()
        .filter(|(_, n)| n.contains(&t))
        .map(|(i, _)| *i)
        .collect()
}

/// What `/join` takes for each invite in `waiting`, each a number and a
/// room, oldest first: newest first, one plain space between words, and
/// each room name once, since `/join` with a name two invites share lists
/// both by number. A room whose name is a number goes by the invite's own
/// number, which `/join` reads before any room name.
pub fn join_choices(waiting: &[(u64, String)]) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for (number, room) in waiting.iter().rev() {
        let room = single_spaced(room);
        if out.iter().any(|o| fold(o) == fold(&room)) {
            continue;
        }
        if room.bytes().all(|b| b.is_ascii_digit()) {
            out.push(number.to_string());
        } else {
            out.push(room);
        }
    }
    out
}

/// The command whose word Tab, Up and Down complete after it, `/invite `,
/// `/save ` or `/join `, and the word as typed, when the message box holds
/// one of them. After `/invite` that is one name, or a quoted name that
/// may hold spaces; a name and a room, or `--dm`, is not completed. After
/// `/save` it is one file name, or a quoted one; a name and a folder is
/// not completed. After `/join` it is any room name, but not a link.
fn arg_typed(input: &str) -> Option<(&'static str, String)> {
    if let Some(rest) = input.strip_prefix("/save ") {
        let typed = match rest.strip_prefix('"') {
            Some(q) => {
                let q = q.strip_suffix('"').unwrap_or(q);
                if q.contains('"') {
                    return None;
                }
                q
            }
            None if rest.contains(char::is_whitespace) => return None,
            None => rest,
        };
        return Some(("/save ", typed.to_string()));
    }
    if let Some(rest) = input.strip_prefix("/invite ") {
        let typed = match rest.strip_prefix('"') {
            Some(q) => {
                let q = q.strip_suffix('"').unwrap_or(q);
                if q.contains('"') {
                    return None;
                }
                q
            }
            None if rest.contains(char::is_whitespace) || rest.starts_with('-') => return None,
            None => rest,
        };
        return Some(("/invite ", typed.to_string()));
    }
    let rest = input.strip_prefix("/join ")?;
    (!rest.contains("://")).then(|| ("/join ", rest.to_string()))
}

/// What can follow `head` for `typed`, best first: the names `/invite`
/// takes, a name with spaces in quotes, the files `/save` takes, newest
/// first, or the rooms `/join` takes.
fn arg_choices(head: &str, typed: &str, vm: &ViewModel) -> Vec<String> {
    if head == "/save " {
        // Matched on the name, without the quotes `/save` reads.
        let names: Vec<String> = vm.save_files.iter().map(|f| f.replace('"', "")).collect();
        return ranked_at(typed, names.iter().map(String::as_str))
            .into_iter()
            .map(|i| vm.save_files[i].clone())
            .collect();
    }
    let all: Vec<&str> = if head == "/invite " {
        // A quote cannot be typed inside a name: `/invite` reads it as
        // the start or end of one.
        vm.invite_names
            .iter()
            .map(String::as_str)
            .filter(|n| !n.contains('"'))
            .collect()
    } else {
        vm.join_rooms.iter().map(String::as_str).collect()
    };
    ranked_at(typed, all.iter().copied())
        .into_iter()
        .map(|i| {
            let n = single_spaced(all[i]);
            if head == "/invite " && n.contains(' ') {
                format!("\"{n}\"")
            } else {
                n
            }
        })
        .collect()
}

/// What the status line says when nothing can follow `head` for `typed`.
fn no_arg(head: &str, typed: &str) -> String {
    match (head, typed.is_empty()) {
        ("/save ", true) => "No one has sent a file in this chat yet.".into(),
        ("/save ", false) => format!("No file called {typed} in this chat."),
        ("/invite ", true) => "Nobody else shares a room with you yet.".into(),
        ("/invite ", false) => format!("Nobody called {typed} shares a room with you."),
        (_, true) => "No invite waits for you.".into(),
        (_, false) => format!("No invite to {typed} waits for you."),
    }
}

/// The next match after `idx` (`forward`) or the one before, going round
/// `n` matches; with no match picked yet, the first or the last.
fn step_at(idx: Option<usize>, forward: bool, n: usize) -> usize {
    match (idx, forward) {
        (None, true) => 0,
        (None, false) => n - 1,
        (Some(i), true) => (i + 1) % n,
        (Some(i), false) => (i + n - 1) % n,
    }
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

/// Where Tab, Shift-Tab, Up and Down are in the names after `/invite`,
/// the files after `/save` or the rooms after `/join`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgCycle {
    /// `/invite `, `/save ` or `/join `.
    head: &'static str,
    /// The word as typed before the first press.
    typed: String,
    /// The match the last press picked.
    idx: usize,
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

/// The most lines Up and Down keep for one room.
const EARLIER_LINES: usize = 100;

/// Where Up and Down are in a room's earlier lines.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Recall {
    group: GroupId,
    /// The line in the message box, counted from the oldest.
    at: usize,
    /// What the box held before the first Up; Down past the newest line
    /// gives it back.
    draft: String,
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
    /// The topic `/topic` put on the status line. While the status line
    /// still shows exactly this, it is drawn in the topic's own style, not
    /// as the app's words.
    pub topic_status: Option<String>,
    pub warning: Option<String>,
    pub member_cursor: usize,
    /// While Tab completes a room name: the text typed before the first
    /// Tab, the index in its matches that Tab last picked, and that room,
    /// which Enter opens even when another room shows the same name.
    pub completion: Option<(String, usize, GroupId)>,
    /// While Tab completes a command word or theme name.
    pub tab_cycle: Option<TabCycle>,
    /// While Tab, Shift-Tab, Up or Down complete a name after `/invite`
    /// or a room after `/join`.
    pub arg_cycle: Option<ArgCycle>,
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
    /// "Socketchat 0.5.2 is out. Run socketchat update." while a newer
    /// release is out; the help line shows it.
    pub update_notice: Option<String>,
    /// What `/about` says about the update check.
    pub updates: String,
    pub(crate) hits: RefCell<Hits>,
    /// Where each row of [`help_entries`] fell in the help box at the last
    /// draw: its first line and how many lines it took.
    pub(crate) help_layout: RefCell<Vec<(usize, usize)>>,
    /// A press of the left button in text, and the selection a drag from
    /// it made.
    drag: Option<Drag>,
    /// The box on screen and when it first showed there. A click read
    /// before then was meant for something else, so it never presses the
    /// box's buttons.
    shown: Option<(Modal, Instant)>,
    /// What this person sent or ran in each room, oldest first, for Up and
    /// Down. Kept in memory only and never saved: it can hold invite links
    /// and words the person later cleared.
    earlier: HashMap<GroupId, Vec<String>>,
    /// Set while Up and Down show an earlier line.
    recall: Option<Recall>,
    /// When the first of two Ctrl-C presses came; a second one within
    /// [`QUIT_WINDOW`] quits.
    quit_armed: Option<Instant>,
    /// Files dropped on the window, waiting in the message box.
    attachments: Vec<Attachment>,
}

/// How long after one Ctrl-C a second one quits.
pub const QUIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(2);

/// The status line after one Ctrl-C.
pub const QUIT_AGAIN: &str = "Press Ctrl-C again to quit.";

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
    /// Each line of a command in the help box, with that command's row of
    /// [`help_entries`].
    pub help_rows: Vec<(Rect, usize)>,
    /// The messages' rows of text, for selecting them.
    pub text: Option<TextArea>,
    /// The open box's rows of text, when the mouse can select them.
    pub box_text: Option<TextArea>,
}

/// The first line the help box shows so that all of row `pick` shows,
/// moving from `offset` as little as it can. `layout` holds each row's
/// first line and line count, and `(max, fits)` the furthest the box
/// scrolls and the lines it shows; while lines below are hidden, the last
/// of them says so.
pub(crate) fn keep_in_view(
    layout: &[(usize, usize)],
    (max, fits): (usize, usize),
    offset: usize,
    pick: usize,
) -> usize {
    let Some(&(first, count)) = layout.get(pick) else {
        return offset;
    };
    let offset = offset.min(max);
    let shown = if offset < max {
        fits.saturating_sub(1)
    } else {
        fits
    };
    if first < offset {
        first
    } else if first + count > offset + shown {
        (first + count)
            .saturating_sub(fits.saturating_sub(1))
            .min(max)
    } else {
        offset
    }
}

/// A press of the left button in text, and where a drag from it went.
#[derive(Clone, Debug)]
struct Drag {
    area: Area,
    /// Where the press came, and where the pointer is now.
    anchor: Spot,
    head: Spot,
    /// The pointer moved with the button down: a selection, not a click.
    moved: bool,
    /// The button is still down.
    held: bool,
    /// The cell the pointer was last seen on.
    at: (u16, u16),
    /// What the text under the selection was when the press came: for
    /// the messages, the open room, how many there were and the newest;
    /// for a box, the box, scrolled to the top.
    under: (Option<GroupId>, usize, Option<LineView>, Option<Modal>),
    /// The width the rows were wrapped to.
    width: usize,
    /// The help box's row the press came on when it was already picked:
    /// a release with no drag uses it.
    use_row: Option<usize>,
}

/// A box as a selection in it sees it: scrolling leaves the text where
/// it was, so the scroll is left out.
fn unscrolled(m: &Option<Modal>) -> Option<Modal> {
    m.clone().map(|m| match m {
        Modal::Help { .. } => Modal::Help { offset: 0, pick: 0 },
        Modal::Invites { rows, .. } => Modal::Invites { rows, offset: 0 },
        Modal::Servers { rows, .. } => Modal::Servers { rows, offset: 0 },
        Modal::Details { lines, .. } => Modal::Details { lines, offset: 0 },
        Modal::Status { lines, .. } => Modal::Status { lines, offset: 0 },
        m => m,
    })
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
                | (Modal::Status { .. }, Modal::Status { .. })
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
            topic_status: None,
            warning: None,
            member_cursor: 0,
            completion: None,
            tab_cycle: None,
            arg_cycle: None,
            hint: None,
            invite_tokens: Vec::new(),
            server_ids: Vec::new(),
            box_scroll: Cell::new((0, 0)),
            theme: Theme::default(),
            mouse: true,
            copying: false,
            update_notice: None,
            updates: String::new(),
            hits: RefCell::new(Hits::default()),
            help_layout: RefCell::new(vec![]),
            drag: None,
            shown: None,
            earlier: HashMap::new(),
            recall: None,
            quit_armed: None,
            attachments: Vec::new(),
        }
    }

    /// Keeps `line`, just sent or run in the open room, for Up and Down.
    /// A line the same as the one before it is kept once.
    fn remember(&mut self, line: &str) {
        let Some(g) = self.selected else {
            return;
        };
        let lines = self.earlier.entry(g).or_default();
        if lines.last().map(String::as_str) != Some(line) {
            lines.push(line.to_string());
            if lines.len() > EARLIER_LINES {
                lines.remove(0);
            }
        }
    }

    /// Up (`back`) or Down in the message box: the open room's earlier
    /// lines, and after the newest, what the box held before.
    fn recall_step(&mut self, back: bool) {
        let Some(g) = self.selected else {
            return;
        };
        let Some(lines) = self.earlier.get(&g).filter(|l| !l.is_empty()) else {
            return;
        };
        let next = match (self.recall.take().filter(|r| r.group == g), back) {
            (None, true) => Some(Recall {
                group: g,
                at: lines.len() - 1,
                draft: std::mem::take(&mut self.input),
            }),
            (None, false) => None,
            (Some(r), true) => Some(Recall {
                at: r.at.saturating_sub(1),
                ..r
            }),
            (Some(r), false) if r.at + 1 < lines.len() => Some(Recall { at: r.at + 1, ..r }),
            (Some(r), false) => {
                self.input = r.draft;
                None
            }
        };
        if let Some(line) = next.as_ref().and_then(|r| lines.get(r.at)) {
            self.input = line.clone();
        }
        self.recall = next;
    }

    /// Whether Up and Down go through command words: the box holds a slash
    /// and at least one letter that this person typed, not a line Up
    /// brought back, and some command starts with them. While Tab goes
    /// through command words, what was typed before the first Tab counts.
    fn steps_commands(&self) -> bool {
        if self.focus != Focus::Input || self.recalling() {
            return false;
        }
        let typed = match &self.tab_cycle {
            Some(c) if c.head.is_empty() => c.typed.as_str(),
            Some(_) => return false,
            None => self.input.as_str(),
        };
        typed.len() > 1
            && typed.starts_with('/')
            && !typed.contains(char::is_whitespace)
            && !word_matches("", typed).is_empty()
    }

    /// Puts the next command word (`forward`) or the one before in the
    /// box, from those that start with what was typed, going round.
    fn step_word(&mut self, forward: bool) {
        let (typed, idx) = match &self.tab_cycle {
            Some(c) if c.head.is_empty() => (c.typed.clone(), c.idx),
            _ => (self.input.clone(), None),
        };
        let words = word_matches("", &typed);
        let n = words.len();
        let i = match (idx, forward) {
            (None, true) => 0,
            (None, false) => n - 1,
            (Some(i), true) => (i + 1) % n,
            (Some(i), false) => (i + n - 1) % n,
        };
        self.input = words[i].clone();
        self.hint = Some(words);
        self.tab_cycle = Some(TabCycle {
            head: "",
            typed,
            idx: Some(i),
        });
    }

    /// The help box with row `pick` highlighted, scrolled so all of it
    /// shows; the last command shows the end of the box.
    fn help_at(&self, offset: usize, pick: usize) -> Modal {
        let (max, fits) = self.box_scroll.get();
        let offset = if pick + 1 == help_entries().len() {
            max
        } else {
            keep_in_view(&self.help_layout.borrow(), (max, fits), offset, pick)
        };
        Modal::Help { offset, pick }
    }

    /// After PgUp or PgDn moved the help box to `offset`: the highlighted
    /// row, moved to the nearest row that shows whole when it no longer
    /// does.
    fn help_pick_in_view(&self, offset: usize, pick: usize) -> usize {
        let layout = self.help_layout.borrow();
        let (max, fits) = self.box_scroll.get();
        let shown = if offset < max {
            fits.saturating_sub(1)
        } else {
            fits
        };
        let whole =
            |(first, count): &(usize, usize)| *first >= offset && first + count <= offset + shown;
        if layout.get(pick).is_none_or(whole) {
            return pick;
        }
        let rows = layout.iter().enumerate().filter(|(_, r)| whole(r));
        let near = if layout[pick].0 < offset {
            rows.map(|(i, _)| i).next()
        } else {
            rows.map(|(i, _)| i).next_back()
        };
        near.unwrap_or(pick)
    }

    /// Enter on row `pick` of the help box: the box closes, and its command
    /// runs as if typed, or goes in the message box when it needs more.
    fn use_help_row(&mut self, pick: usize, vm: &ViewModel) -> Vec<Action> {
        self.modal = None;
        self.focus = Focus::Input;
        let Some((usage, _)) = help_entries().get(pick).copied() else {
            return vec![];
        };
        let cmd = command_of(usage);
        if !usage.contains('<') && parse_command(&cmd).is_ok() {
            self.input = cmd;
            self.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), vm)
        } else {
            self.input = format!("{cmd} ");
            vec![]
        }
    }

    /// Whether the message box shows an earlier line Up or Down brought
    /// back.
    pub fn recalling(&self) -> bool {
        self.recall
            .as_ref()
            .is_some_and(|r| Some(r.group) == self.selected)
    }

    /// Drops what this person sent or ran in room `g`, as `/leave` and
    /// `/clear` do.
    pub fn forget_earlier(&mut self, g: GroupId) {
        self.earlier.remove(&g);
        if self.recall.as_ref().is_some_and(|r| r.group == g) {
            self.recall = None;
        }
    }

    /// Drops the earlier lines of every room not in `rooms`, as `/forget`
    /// does for the rooms it deletes.
    pub fn keep_earlier_of(&mut self, rooms: &[GroupId]) {
        let gone: Vec<GroupId> = self
            .earlier
            .keys()
            .filter(|g| !rooms.contains(g))
            .copied()
            .collect();
        for g in gone {
            self.forget_earlier(g);
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
        // Off, the terminal keeps the mouse for selecting text.
        if !self.mouse {
            return vec![];
        }
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
            if let Some(Modal::Help { offset, pick }) = self.modal {
                // The wheel moves the highlight, stopping at the ends.
                let last = help_entries().len().saturating_sub(1);
                let pick = if up {
                    pick.saturating_sub(1)
                } else {
                    (pick + 1).min(last)
                };
                self.modal = Some(self.help_at(offset, pick));
                return vec![];
            }
            match &mut self.modal {
                Some(
                    Modal::Invites { offset, .. }
                    | Modal::Servers { offset, .. }
                    | Modal::Details { offset, .. }
                    | Modal::Status { offset, .. },
                ) => *offset = step(*offset),
                Some(_) => {}
                None if self.switcher.is_some() => {}
                None if up => self.scroll = self.scroll.saturating_add(WHEEL_ROWS as u16),
                None => self.scroll = self.scroll.saturating_sub(WHEEL_ROWS as u16),
            }
            return vec![];
        }
        match m.kind {
            MouseEventKind::Drag(MouseButton::Left) => {
                self.drag_to(x, y);
                return vec![];
            }
            MouseEventKind::Up(MouseButton::Left) => return self.let_go(x, y, vm),
            MouseEventKind::Down(MouseButton::Left) => {}
            _ => return vec![],
        }
        // A new press ends the last selection.
        self.drag = None;
        let hits = self.hits.borrow().clone();
        if self.modal.is_some() {
            let fresh = self.shown.as_ref().is_some_and(|(_, since)| at >= *since);
            // A click on a command in the help box picks it; a click on the
            // one already picked uses it, as Enter does.
            let row = hits
                .help_rows
                .iter()
                .find(|(r, _)| r.contains(Position { x, y }))
                .map(|(_, i)| *i);
            if let (Some(Modal::Help { offset, pick }), Some(i), true) =
                (self.modal.clone(), row, fresh)
            {
                if i != pick {
                    self.modal = Some(Modal::Help { offset, pick: i });
                }
                self.press(Area::Box, hits.box_text, x, y, vm);
                // A release with no drag uses the row already picked.
                if let Some(d) = &mut self.drag {
                    d.use_row = (i == pick).then_some(i);
                }
                return vec![];
            }
            let pressed = hits
                .targets
                .iter()
                .find(|(r, _)| r.contains(Position { x, y }))
                .map(|(_, code)| *code);
            return match pressed {
                Some(code) if fresh => self.handle_key(KeyEvent::new(code, KeyModifiers::NONE), vm),
                Some(_) => vec![],
                None => {
                    if hits.modal.is_some_and(|r| r.contains(Position { x, y })) {
                        self.press(Area::Box, hits.box_text, x, y, vm);
                    }
                    vec![]
                }
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
            self.press(Area::Messages, hits.text, x, y, vm);
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

    /// What the selection holds the text under: see [`Drag::under`].
    fn under(&self, vm: &ViewModel) -> (Option<GroupId>, usize, Option<LineView>, Option<Modal>) {
        (
            self.selected,
            vm.lines.len(),
            vm.lines.last().cloned(),
            unscrolled(&self.modal),
        )
    }

    /// A press of the left button at `(x, y)` in `area`'s text, which a
    /// drag turns into a selection.
    fn press(&mut self, which: Area, area: Option<TextArea>, x: u16, y: u16, vm: &ViewModel) {
        let Some(area) = area else {
            return;
        };
        if let Some((spot, _)) = area.spot(x, y) {
            self.drag = Some(Drag {
                area: which,
                anchor: spot,
                head: spot,
                moved: false,
                held: true,
                at: (x, y),
                under: self.under(vm),
                width: area.width,
                use_row: None,
            });
        }
    }

    /// Where the selection's text sits on screen, as the last draw put it.
    fn area_of(&self, which: Area) -> Option<TextArea> {
        let hits = self.hits.borrow();
        match which {
            Area::Messages => hits.text,
            Area::Box => hits.box_text,
        }
    }

    /// The pointer moved to `(x, y)` with the button down: the selection
    /// grows or shrinks to it, and past the top or bottom of the text it
    /// scrolls one row.
    fn drag_to(&mut self, x: u16, y: u16) {
        let Some(d) = self.drag.as_ref().filter(|d| d.held) else {
            return;
        };
        let Some(area) = self.area_of(d.area) else {
            return;
        };
        let Some((spot, side)) = area.spot(x, y) else {
            return;
        };
        let which = d.area;
        if let Some(d) = &mut self.drag {
            d.head = spot;
            d.moved = true;
            d.at = (x, y);
        }
        match (which, side) {
            (Area::Messages, -1) if area.more_above => self.scroll = self.scroll.saturating_add(1),
            (Area::Messages, 1) if area.more_below => self.scroll = self.scroll.saturating_sub(1),
            // The help box keeps its highlighted command in view, so the
            // highlight moves to the next command past the edge, and the
            // box scrolls to show it.
            (Area::Box, -1 | 1) if matches!(self.modal, Some(Modal::Help { .. })) => {
                let Some(Modal::Help { offset, .. }) = self.modal else {
                    return;
                };
                let (top, bottom) = (
                    area.top as usize,
                    area.top as usize + area.rect.height as usize,
                );
                let layout = self.help_layout.borrow().clone();
                let last = layout.len().saturating_sub(1);
                let pick = if side < 0 {
                    layout.iter().rposition(|(first, _)| *first < top)
                } else {
                    layout
                        .iter()
                        .position(|(first, count)| first + count > bottom)
                        .or(Some(last))
                };
                if let Some(pick) = pick {
                    self.modal = Some(self.help_at(offset, pick));
                }
            }
            (Area::Box, -1 | 1) => {
                let (max, _) = self.box_scroll.get();
                if let Some(
                    Modal::Invites { offset, .. }
                    | Modal::Servers { offset, .. }
                    | Modal::Details { offset, .. }
                    | Modal::Status { offset, .. },
                ) = &mut self.modal
                {
                    *offset = match side {
                        -1 => offset.saturating_sub(1),
                        _ => (*offset + 1).min(max),
                    };
                }
            }
            _ => {}
        }
    }

    /// The button came up at `(x, y)`: a drag copies what it selected.
    /// A click with no drag on the line that says someone sent a file
    /// saves it, and elsewhere does nothing more.
    fn let_go(&mut self, x: u16, y: u16, vm: &ViewModel) -> Vec<Action> {
        let Some(d) = self.drag.as_ref().filter(|d| d.held) else {
            return vec![];
        };
        if !d.moved {
            let use_row = d.use_row;
            let file = self.file_clicked(d, vm);
            self.drag = None;
            return match (use_row, file) {
                (Some(i), _) => self.use_help_row(i, vm),
                (None, Some(a)) => vec![a],
                (None, None) => vec![],
            };
        }
        let spot = self.area_of(d.area).and_then(|a| a.spot(x, y));
        if let Some(d) = &mut self.drag {
            d.held = false;
            if let Some((spot, _)) = spot {
                d.head = spot;
            }
        }
        match self.selected_text(vm) {
            Some(text) if !text.is_empty() => vec![Action::CopySelected(text)],
            _ => vec![],
        }
    }

    /// What a click with no drag, `d`, does to the line under it: on one
    /// that says someone sent a file, saves the file.
    fn file_clicked(&self, d: &Drag, vm: &ViewModel) -> Option<Action> {
        if d.area != Area::Messages {
            return None;
        }
        let g = self.selected?;
        // On the text's rows, not the blank space above them.
        let (spot, 0) = self.area_of(Area::Messages)?.spot(d.at.0, d.at.1)? else {
            return None;
        };
        let line = vm.lines.get(line_at_row(vm, d.width, spot.row)?)?;
        line.file
            .filter(|_| !line.mine)
            .map(|id| Action::SaveFile(g, id))
    }

    /// The two ends of the selection in `which`, if one is made there.
    pub(crate) fn selection(&self, which: Area) -> Option<(Spot, Spot)> {
        self.drag
            .as_ref()
            .filter(|d| d.moved && d.area == which)
            .map(|d| (d.anchor, d.head))
    }

    /// The text the mouse has selected, as it will be copied: what the
    /// screen shows, with a line the screen wrapped as one line and the
    /// indent under a message's first line left out.
    pub fn selected_text(&self, vm: &ViewModel) -> Option<String> {
        let d = self.drag.as_ref().filter(|d| d.moved)?;
        let (start, end) = ordered(d.anchor, d.head);
        Some(match d.area {
            Area::Messages => {
                // Rows count back from the newest, which is -1.
                let rows = message_body(vm, d.width, start.row.unsigned_abs() as usize);
                let n = rows.len() as i64;
                picked(
                    rows.iter().enumerate().map(|(i, r)| (i as i64 - n, r)),
                    start,
                    end,
                )
            }
            Area::Box => {
                let rows = box_rows(self, self.modal.as_ref()?, d.width)?;
                picked(
                    rows.iter().enumerate().map(|(i, (_, r))| (i as i64, r)),
                    start,
                    end,
                )
            }
        })
    }

    /// Whether the button is held with the pointer past the top or bottom
    /// of the selected text, where more rows can scroll into view.
    pub fn drag_scrolling(&self) -> bool {
        let Some(d) = self.drag.as_ref().filter(|d| d.held && d.moved) else {
            return false;
        };
        let Some(area) = self.area_of(d.area) else {
            return false;
        };
        match area.spot(d.at.0, d.at.1) {
            Some((_, -1)) => area.more_above,
            Some((_, 1)) => area.more_below,
            _ => false,
        }
    }

    /// While the button is held past the top or bottom of the selected
    /// text, scrolls one row further, as moving the pointer there does.
    pub fn drag_tick(&mut self) {
        if let Some((x, y)) = self
            .drag
            .as_ref()
            .filter(|_| self.drag_scrolling())
            .map(|d| d.at)
        {
            self.drag_to(x, y);
        }
    }

    /// Keeps the selection only while the text under it stays in place:
    /// new messages, another room, another box or a window of another
    /// width end it.
    pub fn keep_selection(&mut self, vm: &ViewModel) {
        let Some(d) = &self.drag else {
            return;
        };
        let under = self.under(vm);
        let width = self.area_of(d.area).map(|a| a.width);
        let same = match d.area {
            Area::Messages => d.under.0 == under.0 && d.under.1 == under.1 && d.under.2 == under.2,
            Area::Box => d.under.3 == under.3,
        };
        if !same || width != Some(d.width) {
            self.drag = None;
        }
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

    /// The room name Tab puts in place of `typed`: each further Tab (or
    /// Down, `forward`) moves to the next match, and Shift-Tab or Up to the
    /// one before, going round.
    fn complete(&mut self, typed: &str, vm: &ViewModel, forward: bool) -> Option<String> {
        let (typed, idx) = match self.completion.take() {
            Some((t, i, _)) => (t, Some(i)),
            None => (typed.to_string(), None),
        };
        let matches = ranked(&typed, &vm.groups);
        if matches.is_empty() {
            self.status = Some(no_room(&typed));
            return None;
        }
        let i = step_at(idx, forward, matches.len());
        // One plain space between words, so the command it makes runs.
        let (name, id) = (single_spaced(&matches[i].name), matches[i].id);
        self.completion = Some((typed, i, id));
        Some(name)
    }

    /// Whether Tab and Shift-Tab, or with `spaced` Up and Down, go
    /// through the rooms after `/switch`, the names after `/invite`, the
    /// files after `/save` or the rooms after `/join`. Up and Down need the space after the command
    /// word: before it they go through command words.
    fn completes_args(&self, spaced: bool) -> bool {
        let switch = match spaced {
            true => self.input.starts_with("/switch "),
            false => switch_text(&self.input).is_some(),
        };
        switch || self.arg_cycle.is_some() || arg_typed(&self.input).is_some()
    }

    /// Puts the next room, name or file (`forward`) after `/switch`,
    /// `/invite`, `/save` or `/join` in the message box, or the one before, from those that
    /// fit what was typed, going round; or says on the status line that
    /// none does.
    fn step_arg(&mut self, vm: &ViewModel, forward: bool) {
        if self.arg_cycle.is_none() {
            if let Some(now) = switch_text(&self.input) {
                let now = now.to_string();
                if let Some(name) = self.complete(&now, vm, forward) {
                    self.input = format!("/switch {name}");
                }
                return;
            }
        }
        let (head, typed, idx) = match self.arg_cycle.take() {
            Some(c) => (c.head, c.typed, Some(c.idx)),
            None => match arg_typed(&self.input) {
                Some((head, typed)) => (head, typed, None),
                None => return,
            },
        };
        let choices = arg_choices(head, &typed, vm);
        if choices.is_empty() {
            self.status = Some(no_arg(head, &typed));
            return;
        }
        let i = step_at(idx, forward, choices.len());
        self.input = format!("{head}{}", choices[i]);
        self.arg_cycle = Some(ArgCycle {
            head,
            typed,
            idx: i,
        });
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
        } else if let Some((head, typed, next)) = match &self.arg_cycle {
            Some(c) => Some((c.head, c.typed.clone(), c.idx + 1)),
            None => arg_typed(&self.input).map(|(h, t)| (h, t, 0)),
        } {
            let choices = arg_choices(head, &typed, vm);
            if choices.is_empty() {
                return None;
            }
            format!("{head}{}", choices[next % choices.len()])
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
    fn modal_key(&mut self, m: Modal, k: KeyEvent, vm: &ViewModel) -> Option<Vec<Action>> {
        // Shift makes a capital Y; Ctrl or Alt with y is not an answer.
        let plain = (k.modifiers - KeyModifiers::SHIFT).is_empty();
        let yes = plain && matches!(k.code, KeyCode::Char('y' | 'Y'));
        let typing = plain && matches!(k.code, KeyCode::Char(_));
        let act = match (m, yes) {
            // Up and Down move the highlight, going round; PgUp and PgDn
            // scroll a page and bring it along; Enter uses the command.
            (Modal::Help { offset, pick }, _) => {
                let n = help_entries().len();
                let next = match k.code {
                    KeyCode::Up => Some(self.help_at(offset, (pick + n - 1) % n)),
                    KeyCode::Down => Some(self.help_at(offset, (pick + 1) % n)),
                    KeyCode::PageUp | KeyCode::PageDown => {
                        scrolled(offset, k.code, self.box_scroll.get()).map(|offset| Modal::Help {
                            offset,
                            pick: self.help_pick_in_view(offset, pick),
                        })
                    }
                    KeyCode::Enter => return Some(self.use_help_row(pick, vm)),
                    _ => None,
                };
                if let Some(m) = next {
                    self.modal = Some(m);
                    return Some(vec![]);
                }
                None
            }
            (Modal::Details { lines, offset }, _) => {
                match scrolled(offset, k.code, self.box_scroll.get()) {
                    Some(offset) => {
                        self.modal = Some(Modal::Details { lines, offset });
                        return Some(vec![]);
                    }
                    None => None,
                }
            }
            (Modal::Status { lines, offset }, _) => {
                match scrolled(offset, k.code, self.box_scroll.get()) {
                    Some(offset) => {
                        self.modal = Some(Modal::Status { lines, offset });
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

    /// Until when a second Ctrl-C quits, after a first one.
    pub fn quit_deadline(&self) -> Option<Instant> {
        self.quit_armed.map(|t| t + QUIT_WINDOW)
    }

    /// At `now`, past the time for a second Ctrl-C: the next one asks
    /// again, and the status line no longer says to press it.
    pub fn quit_expire(&mut self, now: Instant) {
        if self.quit_deadline().is_some_and(|end| now > end) {
            self.quit_armed = None;
            if self.status.as_deref() == Some(QUIT_AGAIN) {
                self.status = None;
            }
        }
    }

    pub fn handle_key(&mut self, k: KeyEvent, vm: &ViewModel) -> Vec<Action> {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        // Ctrl-C quits on the second press, as in other terminal apps, so
        // one meant to copy does not close the app. With text selected,
        // the first copies it.
        if ctrl && k.code == KeyCode::Char('c') {
            if self
                .quit_deadline()
                .is_some_and(|end| Instant::now() <= end)
            {
                return vec![Action::Quit];
            }
            if let Some(text) = self.selected_text(vm) {
                self.drag = None;
                self.quit_armed = None;
                return vec![Action::CopySelected(text)];
            }
            self.quit_armed = Some(Instant::now());
            self.status = Some(QUIT_AGAIN.into());
            return vec![];
        }
        self.quit_armed = None;
        // A status message stays on the help line until the next key.
        self.status = None;
        // Any key ends a selection.
        self.drag = None;
        self.tidy_attachments(!matches!(k.code, KeyCode::Up | KeyCode::Down));
        // Up and Down go on through earlier lines; any other key makes what
        // the box holds the new draft.
        if !matches!(k.code, KeyCode::Up | KeyCode::Down) {
            self.recall = None;
        }
        let tabs = matches!(k.code, KeyCode::Tab | KeyCode::BackTab);
        let up_down = matches!(k.code, KeyCode::Up | KeyCode::Down);
        // After `/switch `, `/invite `, `/save ` or `/join `, Tab, Shift-Tab,
        // Up and Down go through the rooms, names or files that fit; Up and Down only
        // while the box holds what this person typed, not an earlier line.
        let arg_step = self.modal.is_none()
            && self.switcher.is_none()
            && ((tabs && self.completes_args(false))
                || (up_down
                    && self.focus == Focus::Input
                    && !self.recalling()
                    && self.completes_args(true)));
        // After a slash and a letter, Up and Down go through the commands
        // as Tab does.
        let word_step = up_down && !arg_step && self.steps_commands();
        // Tab runs on through a command word; any other key ends the run.
        if !tabs && !word_step {
            self.tab_cycle = None;
        }
        if !arg_step {
            self.arg_cycle = None;
        }
        self.hint = None;
        // Each Tab moves on to the next room name; any other key ends that,
        // and Enter opens the room Tab picked.
        let picked = if k.code == KeyCode::Tab || arg_step {
            None
        } else {
            self.completion.take()
        };
        if let Some(m) = self.modal.clone() {
            if let Some(acts) = self.modal_key(m, k, vm) {
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
                    if let Some(name) = self.complete(&q, vm, true) {
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
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down if arg_step => {
                self.step_arg(vm, matches!(k.code, KeyCode::Tab | KeyCode::Down))
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
            KeyCode::Up | KeyCode::Down if word_step => self.step_word(k.code == KeyCode::Down),
            KeyCode::Up | KeyCode::Down if self.focus == Focus::Input => {
                self.recall_step(k.code == KeyCode::Up)
            }
            KeyCode::Esc => {
                self.input.clear();
                self.status = None;
                self.warning = None;
            }
            KeyCode::Backspace => {
                self.focus = Focus::Input;
                if !self.backspace_attachment() {
                    self.input.pop();
                }
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
                // A path to a file here never goes out as a message.
                if let Some(acts) = self.enter_paths() {
                    return acts;
                }
                if let Some(acts) = self.enter_attachments(vm) {
                    return acts;
                }
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
                // A slash alone opens the list of commands.
                if line == "/" {
                    return vec![Action::Command(Command::Help)];
                }
                // Letters only one command starts with mean that command:
                // it runs, or goes in the box to type the rest.
                let only = match parse_command(line) {
                    Err(e) if e.starts_with("There is no") && !line.contains(' ') => {
                        Some(word_matches("", line)).filter(|m| m.len() == 1)
                    }
                    _ => None,
                };
                let line = match only.as_ref().map(|m| m[0].as_str()) {
                    Some(word) if crate::commands::needs_more(word) => {
                        self.input = format!("{word} ");
                        return vec![];
                    }
                    Some(word) => word,
                    None => line,
                };
                if line.starts_with('/') {
                    match parse_command(line) {
                        Ok(Command::Switch(None)) => {
                            self.remember(line);
                            self.switcher = Some(String::new());
                        }
                        Ok(Command::Switch(Some(text))) => match tab_pick(&picked, &text, vm)
                            .or_else(|| pick_room(&text, &vm.groups).map(|g| g.id))
                        {
                            Some(id) => {
                                self.remember(line);
                                return vec![Action::Select(id)];
                            }
                            None => {
                                self.input = line.to_string();
                                self.status = Some(no_room(&text));
                            }
                        },
                        Ok(c) => {
                            self.remember(line);
                            return vec![Action::Command(c)];
                        }
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
                    self.remember(line);
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
    /// question it asked counts as answered no. A paste of nothing but
    /// paths is a drop, as the `dropped` module tells.
    pub fn handle_paste(&mut self, text: &str) -> Vec<Action> {
        self.status = None;
        self.drag = None;
        self.tidy_attachments(true);
        self.recall = None;
        self.completion = None;
        self.tab_cycle = None;
        self.arg_cycle = None;
        self.hint = None;
        // Files dropped on the window, wherever they land.
        if let Some(acts) = self.paste_files(text) {
            return acts;
        }
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
