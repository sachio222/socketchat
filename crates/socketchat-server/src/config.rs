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
    /// Whether members, not only admins, can make invite links.
    pub members_can_invite: bool,
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
            members_can_invite: true,
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
            timing: Timing::default(),
            protocol_max: socketchat_proto::PROTOCOL_VERSION,
            commit_check_delay: CheckDelay::default(),
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
        toml::from_str(&text).map_err(|e| ServerError::Config(format!("{}: {e}", path.display())))
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
}
