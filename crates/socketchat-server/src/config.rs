//! `socketchat-server.toml`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::ServerError;

pub const CONFIG_FILE: &str = "socketchat-server.toml";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Address and port to listen on.
    pub listen: SocketAddr,
    /// Name or address people use to reach this server. Invite links carry it.
    pub public_host: String,
    /// Where the database, certificate and file chunks live.
    pub data_dir: PathBuf,
    /// Days the server keeps messages and files nobody has fetched.
    pub retention_days: u32,
    /// Largest file anyone can send, in megabytes.
    pub max_file_mb: u64,
    /// Hours an invite link stays valid.
    pub invite_ttl_hours: u32,
    /// Whether people with an account here can bring new people onto the
    /// server: make server invites, and register an account for whoever
    /// joins through one of their room links.
    pub members_make_accounts: bool,
    /// Whether members who are not admins may bring people into rooms at
    /// all. When false, every room is admins-only for invite links and
    /// adds, whatever its own setting says. When true, each room decides.
    pub members_can_invite_to_rooms: bool,
    /// The one switch files from before 0.5.2 had for both of the above.
    /// Read, applied to them by [`Config::from_toml`], never written.
    #[serde(skip_serializing)]
    #[doc(hidden)]
    pub members_can_invite: Option<bool>,
    /// Refuse groups that use the post-quantum draft suite.
    pub require_standard_suite: bool,
    /// Most connections served at once.
    pub max_connections: usize,
    /// Most connections from one address at once. An IPv6 address counts
    /// by its /64 network. One address may be a whole office or school
    /// behind one router.
    pub max_per_ip: usize,
    /// Largest frame, in bytes, a connection may send before it signs in.
    /// A larger one closes the connection.
    pub max_frame_before_sign_in: usize,
    /// Megabytes (of 1,000,000 bytes) that all connections not yet signed
    /// in may hold at once in frames they have only partly sent. A
    /// connection that would go over is closed.
    pub max_buffered_before_sign_in_mb: usize,
    /// New accounts that the room links one account makes may register in
    /// one invite window: the link lifetime rounded up to whole days, plus
    /// a day. Each room link the account makes counts once, used or not;
    /// links made past this, or by a connection with no account, still let
    /// people into the room but register no account.
    pub max_accounts_from_room_links: u32,
    /// Megabytes of messages one room may hold on the server, waiting for
    /// members to fetch them.
    pub max_room_messages_mb: u64,
    /// Megabytes of files one room may hold on the server.
    pub max_room_files_mb: u64,
    /// Megabytes of files one member of a room may hold on the server.
    pub max_member_files_mb: u64,
    /// Invitations (MLS Welcomes) one room may have waiting for people who
    /// have not opened them yet.
    pub max_room_welcomes: u32,
    /// Megabytes of messages, files and invitations the whole server may
    /// hold.
    pub max_stored_mb: u64,
    /// Messages one member who is not an admin can post in a room in a
    /// quick burst before the steady pace applies. 0 turns the limit off.
    pub rate_burst_messages: u32,
    /// Seconds each member waits for one more message once the burst is
    /// spent.
    pub rate_seconds_per_message: u32,
    /// Kilobytes (of 1,000 bytes) one member can post in a room in a burst.
    /// Never less than one message of the largest size.
    pub rate_burst_kb: u32,
    /// Kilobytes a second each member gets back once the burst is spent.
    pub rate_kb_per_second: u32,
    /// How long a connection may wait before Hello, before signing in and
    /// between requests.
    /// Not read from the file; tests shorten it.
    #[serde(skip)]
    #[doc(hidden)]
    pub timing: Timing,
    /// Highest protocol this server speaks. Not read from the file; tests
    /// set it to 1 to stand in for a 0.4.0 server.
    #[serde(skip)]
    #[doc(hidden)]
    pub protocol_max: u16,
    /// A pause before the server checks a group change, outside the
    /// database lock. Not read from the file; tests use it to make two
    /// changes overlap, and can change it while the server runs.
    #[serde(skip)]
    #[doc(hidden)]
    pub commit_check_delay: CheckDelay,
    /// Holds one group change's check, outside the database lock, until a
    /// test lets it go. Not read from the file; tests use it to make a
    /// change land while another is being checked, without guessing how
    /// long the check takes.
    #[serde(skip)]
    #[doc(hidden)]
    pub commit_check_hold: CheckHold,
    /// Holds the check of one new room's tree, outside the database lock,
    /// until a test lets it go. Not read from the file; tests use it to
    /// ask for other things while a new room is being checked.
    #[serde(skip)]
    #[doc(hidden)]
    pub new_room_check_hold: CheckHold,
    /// Holds one post after it is written and the database lock is let
    /// go, before the server answers it. Not read from the file; tests use
    /// it to ask for other things between a write and its answer.
    #[serde(skip)]
    #[doc(hidden)]
    pub post_written_hold: CheckHold,
}

/// A pause that every copy of one [`Config`] shares, so a test can turn it
/// on or off while the server runs. Zero unless a test sets it.
#[doc(hidden)]
#[derive(Clone, Debug, Default)]
pub struct CheckDelay(std::sync::Arc<std::sync::atomic::AtomicU64>);

impl CheckDelay {
    /// Sets the pause for every copy of this config.
    pub fn set(&self, d: Duration) {
        let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        self.0.store(ms, std::sync::atomic::Ordering::Relaxed);
    }

    /// The pause in force now.
    pub fn get(&self) -> Duration {
        Duration::from_millis(self.0.load(std::sync::atomic::Ordering::Relaxed))
    }
}

impl PartialEq for CheckDelay {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

/// A hold at one point in the server, outside the database lock, which
/// every copy of one [`Config`] shares: the check of a group change, the
/// check of a new room, or a post between its write and its answer. A test
/// arms it with [`CheckHold::hold_next`], waits with
/// [`HeldCheck::reached`] until a request has stopped there, does what
/// must happen meanwhile, then lets it go with [`HeldCheck::release`], or
/// by dropping the [`HeldCheck`] if the test fails first. Other requests
/// pass straight through. Off unless a test arms it; the server then pays
/// one atomic load each time a request passes.
///
/// A held check goes on by itself after [`HOLD_LIMIT`], and
/// [`HeldCheck::release`] then fails the test. A server that makes other
/// requests wait on a held check can stall every worker thread, timers
/// included, so without the limit such a test would hang, not fail.
#[doc(hidden)]
#[derive(Clone, Debug, Default)]
pub struct CheckHold(std::sync::Arc<HoldInner>);

#[derive(Debug, Default)]
struct HoldInner {
    armed: std::sync::atomic::AtomicBool,
    state: std::sync::Mutex<HoldState>,
    released: std::sync::Condvar,
    reached: tokio::sync::Notify,
}

#[derive(Debug, Default)]
struct HoldState {
    catch_next: bool,
    released: bool,
    expired: bool,
}

/// Longest a check stays held. Far past anything a passing test spends
/// while holding one; a request that gets no answer for 5 seconds fails
/// the test connection before this.
#[doc(hidden)]
pub const HOLD_LIMIT: Duration = Duration::from_secs(30);

impl CheckHold {
    /// Stops the next request to reach the hold until it is released.
    #[must_use = "dropping the hold releases it at once"]
    pub fn hold_next(&self) -> HeldCheck {
        let mut st = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        st.catch_next = true;
        st.released = false;
        st.expired = false;
        self.0
            .armed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        HeldCheck(self.clone())
    }

    /// Called by the server on a blocking thread at the hold's point: waits
    /// there if a test asked to hold this one.
    pub(crate) fn pass(&self) {
        if !self.0.armed.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let mut st = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        if !st.catch_next {
            return;
        }
        st.catch_next = false;
        self.0.reached.notify_one();
        let until = std::time::Instant::now() + HOLD_LIMIT;
        while !st.released {
            let left = until.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                st.expired = true;
                return;
            }
            st = self
                .0
                .released
                .wait_timeout(st, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}

/// A test's hand on the server, not a setting: any two compare equal.
impl PartialEq for CheckHold {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

/// The hold [`CheckHold::hold_next`] set. Releasing or dropping it lets
/// the held check go on.
#[doc(hidden)]
#[derive(Debug)]
pub struct HeldCheck(CheckHold);

impl HeldCheck {
    /// Returns once a request has stopped at the hold.
    /// Panics after a minute, so a request that never comes fails the test
    /// instead of hanging it.
    pub async fn reached(&self) {
        tokio::time::timeout(Duration::from_secs(60), self.0 .0.reached.notified())
            .await
            .expect("no request reached the hold within a minute");
    }

    /// Lets the held check go on. Panics if it went on by itself after
    /// [`HOLD_LIMIT`]: something the test did meanwhile waited on it.
    pub fn release(self) {
        let expired = self
            .0
             .0
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .expired;
        assert!(
            !expired,
            "the check was held {HOLD_LIMIT:?} and went on by itself: something waited on it"
        );
    }
}

impl Drop for HeldCheck {
    fn drop(&mut self) {
        let inner = &self.0 .0;
        let mut st = inner.state.lock().unwrap_or_else(|e| e.into_inner());
        st.catch_next = false;
        st.released = true;
        inner
            .armed
            .store(false, std::sync::atomic::Ordering::SeqCst);
        inner.released.notify_all();
    }
}

/// Most connections one address may hold at once, unless the config says
/// otherwise. An IPv6 address counts by its /64 network, which one host
/// usually holds whole. One address may be a whole office or school behind
/// one router, so this is generous; `max_connections` bounds the total.
pub const MAX_PER_IP: usize = 256;

/// Seconds a client gets to say Hello once TLS is up.
pub const HELLO_DEADLINE: Duration = Duration::from_secs(10);

/// A connection that sends no request for this long is closed. Clients
/// reconnect when they next need the server.
pub const IDLE_LIMIT: Duration = Duration::from_secs(5 * 60);

/// Largest frame a connection may send before it signs in, unless the
/// config says otherwise.
pub const MAX_FRAME_BEFORE_SIGN_IN: usize = 8 * 1024;

/// The smallest `max_frame_before_sign_in` the server uses, whatever the
/// config says, so the requests that sign in always fit. Each connection
/// also holds this much outside the shared budget, so a spent budget
/// refuses only larger frames, never a sign-in.
pub const SIGN_IN_FRAME_FLOOR: usize = 1024;

/// Megabytes all connections not yet signed in may hold in partly sent
/// frames, unless the config says otherwise.
pub const MAX_BUFFERED_BEFORE_SIGN_IN_MB: usize = 8;

/// A connection that has not signed in this long after it connected is
/// closed, whatever it sends.
pub const SIGN_IN_LIMIT: Duration = Duration::from_secs(60);

/// Accounts one account's room links may register per invite window,
/// unless the config says otherwise: 20 new people a day, with room to
/// spare for links that go unused and for direct messages.
pub const MAX_ACCOUNTS_FROM_ROOM_LINKS: u32 = 100;

/// Storage limits, unless the config says otherwise. Megabytes are
/// 1,000,000 bytes.
pub const MAX_ROOM_MESSAGES_MB: u64 = 200;
pub const MAX_ROOM_FILES_MB: u64 = 4_000;
pub const MAX_MEMBER_FILES_MB: u64 = 4_000;
pub const MAX_ROOM_WELCOMES: u32 = 100;
pub const MAX_STORED_MB: u64 = 8_000;

/// How fast one member who is not an admin can post in one room, unless
/// the config says otherwise. Matrix's server allows each sender a burst
/// of 10 messages, then one every 5 seconds, and counts invites and joins
/// on their own. Socketchat counts everything a member posts in a room,
/// and the app posts on its own when someone joins: about eight posts for
/// each person a member brings in (the link's details, the add, then the
/// inviter's name, the room's name and the app's version, twice). A burst
/// of 30 lets a member bring in three people at once and still chat; the
/// steady pace stays one message every 5 seconds, so a flood slows to 12
/// messages a minute. Admins are not held. The byte allowance lets
/// through one message of the largest size (about 1 MB) and thousands of
/// short texts; after it, 10 KB a second is still dozens of short texts a
/// second, so only large messages ever meet it.
pub const RATE_BURST_MESSAGES: u32 = 30;
pub const RATE_SECONDS_PER_MESSAGE: u32 = 5;
pub const RATE_BURST_KB: u32 = 2_000;
pub const RATE_KB_PER_SECOND: u32 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    pub hello: Duration,
    pub sign_in: Duration,
    pub idle: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            hello: HELLO_DEADLINE,
            sign_in: SIGN_IN_LIMIT,
            idle: IDLE_LIMIT,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: SocketAddr::from(([0, 0, 0, 0], socketchat_proto::DEFAULT_PORT)),
            public_host: "localhost".into(),
            data_dir: PathBuf::from("."),
            retention_days: 30,
            max_file_mb: 100,
            invite_ttl_hours: 24,
            members_make_accounts: true,
            members_can_invite_to_rooms: true,
            members_can_invite: None,
            require_standard_suite: false,
            max_connections: 1000,
            max_per_ip: MAX_PER_IP,
            max_frame_before_sign_in: MAX_FRAME_BEFORE_SIGN_IN,
            max_buffered_before_sign_in_mb: MAX_BUFFERED_BEFORE_SIGN_IN_MB,
            max_accounts_from_room_links: MAX_ACCOUNTS_FROM_ROOM_LINKS,
            max_room_messages_mb: MAX_ROOM_MESSAGES_MB,
            max_room_files_mb: MAX_ROOM_FILES_MB,
            max_member_files_mb: MAX_MEMBER_FILES_MB,
            max_room_welcomes: MAX_ROOM_WELCOMES,
            max_stored_mb: MAX_STORED_MB,
            rate_burst_messages: RATE_BURST_MESSAGES,
            rate_seconds_per_message: RATE_SECONDS_PER_MESSAGE,
            rate_burst_kb: RATE_BURST_KB,
            rate_kb_per_second: RATE_KB_PER_SECOND,
            timing: Timing::default(),
            protocol_max: socketchat_proto::PROTOCOL_VERSION,
            commit_check_delay: CheckDelay::default(),
            commit_check_hold: CheckHold::default(),
            new_room_check_hold: CheckHold::default(),
            post_written_hold: CheckHold::default(),
        }
    }
}

impl Config {
    /// Reads `socketchat-server.toml` from a data directory.
    pub fn load(data_dir: &Path) -> Result<Config, ServerError> {
        Self::load_file(&data_dir.join(CONFIG_FILE))
    }

    pub fn load_file(path: &Path) -> Result<Config, ServerError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ServerError::Config(format!("{}: {e}", path.display())))?;
        Self::from_toml(&text).map_err(|e| ServerError::Config(format!("{}: {e}", path.display())))
    }

    /// Reads a config file's text. The old `members_can_invite` switch
    /// still holds what it held before 0.5.2: false keeps members from
    /// making accounts and from inviting into rooms. It never loosens a
    /// new key set beside it.
    pub fn from_toml(text: &str) -> Result<Config, toml::de::Error> {
        let mut cfg: Config = toml::from_str(text)?;
        if let Some(old) = cfg.members_can_invite.take() {
            cfg.members_make_accounts &= old;
            cfg.members_can_invite_to_rooms &= old;
        }
        Ok(cfg)
    }

    pub fn save(&self) -> Result<(), ServerError> {
        let text = toml::to_string_pretty(self).map_err(|e| ServerError::Config(e.to_string()))?;
        crate::perms::write_private(&self.data_dir.join(CONFIG_FILE), text.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Operators set the per-address limit in the config file, and a saved
    /// config writes it out so they can see it.
    #[test]
    fn max_per_ip_round_trips_through_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
            data_dir: dir.path().to_path_buf(),
            ..Config::default()
        };
        assert_eq!(cfg.max_per_ip, 256);
        cfg.save().unwrap();
        let text = std::fs::read_to_string(dir.path().join(CONFIG_FILE)).unwrap();
        assert!(text.contains("max_per_ip = 256"), "{text}");
        std::fs::write(
            dir.path().join(CONFIG_FILE),
            text.replace("max_per_ip = 256", "max_per_ip = 7"),
        )
        .unwrap();
        assert_eq!(Config::load(dir.path()).unwrap().max_per_ip, 7);
        // A file from before the key existed gets the default.
        let old: Config = toml::from_str("retention_days = 3").unwrap();
        assert_eq!(old.max_per_ip, 256);
    }

    /// The limits for connections not yet signed in are in the file, with
    /// their defaults, and an operator's values are read back.
    #[test]
    fn sign_in_limits_round_trip_through_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
            data_dir: dir.path().to_path_buf(),
            ..Config::default()
        };
        assert_eq!(cfg.max_frame_before_sign_in, 8192);
        assert_eq!(cfg.max_buffered_before_sign_in_mb, 8);
        cfg.save().unwrap();
        let text = std::fs::read_to_string(dir.path().join(CONFIG_FILE)).unwrap();
        assert!(text.contains("max_frame_before_sign_in = 8192"), "{text}");
        assert!(
            text.contains("max_buffered_before_sign_in_mb = 8"),
            "{text}"
        );
        std::fs::write(
            dir.path().join(CONFIG_FILE),
            text.replace(
                "max_frame_before_sign_in = 8192",
                "max_frame_before_sign_in = 4096",
            )
            .replace(
                "max_buffered_before_sign_in_mb = 8",
                "max_buffered_before_sign_in_mb = 32",
            ),
        )
        .unwrap();
        let back = Config::load(dir.path()).unwrap();
        assert_eq!(back.max_frame_before_sign_in, 4096);
        assert_eq!(back.max_buffered_before_sign_in_mb, 32);
        // A file from before the keys existed gets the defaults.
        let old: Config = toml::from_str("retention_days = 3").unwrap();
        assert_eq!(old.max_frame_before_sign_in, 8192);
        assert_eq!(old.max_buffered_before_sign_in_mb, 8);
        assert_eq!(old.timing.sign_in, SIGN_IN_LIMIT);
    }

    /// The abuse and storage limits are in the file with their defaults,
    /// an operator's values are read back, and an old file gets the
    /// defaults.
    #[test]
    fn abuse_and_storage_limits_round_trip_through_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
            data_dir: dir.path().to_path_buf(),
            ..Config::default()
        };
        let defaults = [
            ("max_accounts_from_room_links", 100),
            ("max_room_messages_mb", 200),
            ("max_room_files_mb", 4000),
            ("max_member_files_mb", 4000),
            ("max_room_welcomes", 100),
            ("max_stored_mb", 8000),
        ];
        cfg.save().unwrap();
        let mut text = std::fs::read_to_string(dir.path().join(CONFIG_FILE)).unwrap();
        for (key, value) in defaults {
            let line = format!("{key} = {value}");
            assert!(text.contains(&line), "{line} missing from {text}");
            text = text.replace(&line, &format!("{key} = {}", value + 1));
        }
        std::fs::write(dir.path().join(CONFIG_FILE), text).unwrap();
        let back = Config::load(dir.path()).unwrap();
        assert_eq!(back.max_accounts_from_room_links, 101);
        assert_eq!(back.max_room_messages_mb, 201);
        assert_eq!(back.max_room_files_mb, 4001);
        assert_eq!(back.max_member_files_mb, 4001);
        assert_eq!(back.max_room_welcomes, 101);
        assert_eq!(back.max_stored_mb, 8001);
        let old: Config = toml::from_str("retention_days = 3").unwrap();
        assert_eq!(old.max_accounts_from_room_links, 100);
        assert_eq!(old.max_room_messages_mb, 200);
        assert_eq!(old.max_room_files_mb, 4000);
        assert_eq!(old.max_member_files_mb, 4000);
        assert_eq!(old.max_room_welcomes, 100);
        assert_eq!(old.max_stored_mb, 8000);
        assert_eq!(old.commit_check_delay.get(), Duration::ZERO);
    }

    /// The pace limits are in the file with their defaults, an operator's
    /// values are read back, and a file from before them gets the defaults.
    #[test]
    fn rate_limits_round_trip_through_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
            data_dir: dir.path().to_path_buf(),
            ..Config::default()
        };
        cfg.save().unwrap();
        let mut text = std::fs::read_to_string(dir.path().join(CONFIG_FILE)).unwrap();
        for (key, value) in [
            ("rate_burst_messages", 30),
            ("rate_seconds_per_message", 5),
            ("rate_burst_kb", 2000),
            ("rate_kb_per_second", 10),
        ] {
            let line = format!("{key} = {value}");
            assert!(text.contains(&line), "{line} missing from {text}");
            text = text.replace(&line, &format!("{key} = {}", value + 1));
        }
        std::fs::write(dir.path().join(CONFIG_FILE), text).unwrap();
        let back = Config::load(dir.path()).unwrap();
        assert_eq!(back.rate_burst_messages, 31);
        assert_eq!(back.rate_seconds_per_message, 6);
        assert_eq!(back.rate_burst_kb, 2001);
        assert_eq!(back.rate_kb_per_second, 11);
        let old: Config = toml::from_str("retention_days = 3").unwrap();
        assert_eq!(old.rate_burst_messages, 30);
        assert_eq!(old.rate_seconds_per_message, 5);
    }

    /// A file from before 0.5.2 that set `members_can_invite = false`
    /// keeps both things it stopped: members bringing new accounts onto
    /// the server, and members bringing people into rooms.
    #[test]
    fn the_old_member_invite_switch_still_holds_both() {
        let old = Config::from_toml("members_can_invite = false").unwrap();
        assert!(!old.members_make_accounts);
        assert!(!old.members_can_invite_to_rooms);
        let old_on = Config::from_toml("members_can_invite = true").unwrap();
        assert!(old_on.members_make_accounts);
        assert!(old_on.members_can_invite_to_rooms);
        // The old switch never loosens a new key set beside it.
        let mixed =
            Config::from_toml("members_can_invite = true\nmembers_can_invite_to_rooms = false")
                .unwrap();
        assert!(mixed.members_make_accounts);
        assert!(!mixed.members_can_invite_to_rooms);
        let rooms = Config::from_toml("members_can_invite_to_rooms = false").unwrap();
        assert!(rooms.members_make_accounts);
        assert!(!rooms.members_can_invite_to_rooms);
        let accounts = Config::from_toml("members_make_accounts = false").unwrap();
        assert!(!accounts.members_make_accounts);
        assert!(accounts.members_can_invite_to_rooms);
        let d = Config::default();
        assert!(d.members_make_accounts && d.members_can_invite_to_rooms);
    }

    /// Saving writes the new keys with what the old one meant, and never
    /// the old one.
    #[test]
    fn a_saved_config_keeps_the_old_switch_in_the_new_keys() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(CONFIG_FILE), "members_can_invite = false\n").unwrap();
        let mut cfg = Config::load(dir.path()).unwrap();
        cfg.data_dir = dir.path().to_path_buf();
        cfg.save().unwrap();
        let text = std::fs::read_to_string(dir.path().join(CONFIG_FILE)).unwrap();
        assert!(text.contains("members_make_accounts = false"), "{text}");
        assert!(
            text.contains("members_can_invite_to_rooms = false"),
            "{text}"
        );
        assert!(!text.contains("members_can_invite ="), "{text}");
        let back = Config::load(dir.path()).unwrap();
        assert!(!back.members_make_accounts && !back.members_can_invite_to_rooms);
    }
}
