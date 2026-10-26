//! The client's local data, encrypted at rest.
//!
//! One SQLCipher file holds everything: the app's own tables and OpenMLS's
//! group state. The key comes from the person's passphrase through Argon2id
//! with a random salt kept beside the file, together with the Argon2id
//! settings it was made with. Neither is secret.
//!
//! On Unix the profile folder is for its owner only (see `perms`).
//!
//! One app at a time opens a profile: the store holds an operating-system
//! lock on a file in the profile folder for as long as it is open.

use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};
use zeroize::Zeroizing;

use crate::keys::{GroupId, Key, KeyPair};
use crate::provider::{Provider, Storage};
use crate::CoreError;
use socketchat_proto::Token;

pub const DB_FILE: &str = "socketchat.db";
pub const SALT_FILE: &str = "salt";
/// Held locked while an app has the profile open.
pub const LOCK_FILE: &str = "lock";

/// Argon2id settings for new profiles: RFC 9106's second recommended
/// option (64 MiB, 3 passes, 4 lanes), for machines that cannot spare its
/// first (2 GiB). An Apple M1 Max derives the key in 0.09 s; a Raspberry
/// Pi Zero 2 W, with 512 MB and four 1 GHz Cortex-A53 cores, should take
/// 1.3 to 2 seconds, since this crate fills the lanes one after another. Each
/// profile stores the settings it was made with, so raising these later
/// never locks anyone out.
const ARGON_MEM_KIB: u32 = 64 * 1024;
const ARGON_PASSES: u32 = 3;
const ARGON_LANES: u32 = 4;

/// The settings of profiles whose salt file is a bare salt, made before
/// the settings were stored: OWASP's minimum, 19 MiB, 2 passes, 1 lane.
/// These never change.
const FIRST_MEM_KIB: u32 = 19 * 1024;
const FIRST_PASSES: u32 = 2;
const FIRST_LANES: u32 = 1;

/// The salt file starts with these bytes when it also holds the Argon2id
/// settings: `sckdf`, then format version 1. New numbers in the same
/// layout need no new version: 0.4.0 and later read any settings within
/// the limits below. Only a new layout gets a new version byte.
const KDF_MAGIC: &[u8; 6] = b"sckdf\x01";
const SALT_LEN: usize = 16;
/// The longest salt file: the magic, three settings and the salt.
const SALT_FILE_MAX: usize = KDF_MAGIC.len() + 12 + SALT_LEN;

/// The most a salt file may ask for: 256 MiB of memory, 16 passes, 8
/// lanes. Anything above, or less than 8 KiB of memory per lane (Argon2's
/// own floor), means the file was damaged or tampered with: opening the
/// profile with it could take hours, or run a 512 MB Raspberry Pi Zero 2 W
/// out of memory.
const MAX_MEM_KIB: u32 = 256 * 1024;
const MAX_PASSES: u32 = 16;
const MAX_LANES: u32 = 8;

/// Argon2id settings and salt for one profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Kdf {
    mem_kib: u32,
    passes: u32,
    lanes: u32,
    salt: [u8; SALT_LEN],
}

impl Kdf {
    fn new() -> Kdf {
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        Kdf {
            mem_kib: ARGON_MEM_KIB,
            passes: ARGON_PASSES,
            lanes: ARGON_LANES,
            salt,
        }
    }

    /// The salt file: [`KDF_MAGIC`], memory in KiB, passes and lanes as
    /// big-endian u32, then the salt.
    fn encode(&self) -> Vec<u8> {
        let mut v = KDF_MAGIC.to_vec();
        for n in [self.mem_kib, self.passes, self.lanes] {
            v.extend_from_slice(&n.to_be_bytes());
        }
        v.extend_from_slice(&self.salt);
        v
    }

    /// Reads a salt file. A bare 16-byte salt comes from a profile made
    /// before the settings were stored, which used the first settings.
    fn decode(b: &[u8]) -> Result<Kdf, CoreError> {
        let bad = || CoreError::Storage("the profile's salt file is damaged".into());
        if b.len() == SALT_LEN {
            return Ok(Kdf {
                mem_kib: FIRST_MEM_KIB,
                passes: FIRST_PASSES,
                lanes: FIRST_LANES,
                salt: b.try_into().map_err(|_| bad())?,
            });
        }
        let rest = b.strip_prefix(KDF_MAGIC.as_slice()).ok_or_else(bad)?;
        if rest.len() != 12 + SALT_LEN {
            return Err(bad());
        }
        let n = |i: usize| u32::from_be_bytes(rest[i..i + 4].try_into().expect("4 bytes"));
        let (mem_kib, passes, lanes) = (n(0), n(4), n(8));
        let sane = (1..=MAX_PASSES).contains(&passes)
            && (1..=MAX_LANES).contains(&lanes)
            && (8 * lanes..=MAX_MEM_KIB).contains(&mem_kib);
        if !sane {
            return Err(bad());
        }
        Ok(Kdf {
            mem_kib,
            passes,
            lanes,
            salt: rest[12..].try_into().map_err(|_| bad())?,
        })
    }
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS profile (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    identity BLOB NOT NULL,
    display_name TEXT NOT NULL,
    created_unix INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    cert_fpr BLOB NOT NULL,
    account_key BLOB,
    UNIQUE (host, port)
);
CREATE TABLE IF NOT EXISTS groups (
    id BLOB PRIMARY KEY,
    server_id INTEGER NOT NULL REFERENCES servers(id),
    group_key BLOB NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    is_dm INTEGER NOT NULL DEFAULT 0,
    left_group INTEGER NOT NULL DEFAULT 0,
    last_seq INTEGER NOT NULL DEFAULT 0,
    last_update_unix INTEGER NOT NULL DEFAULT 0,
    joined_unix INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS members (
    group_id BLOB NOT NULL,
    group_key BLOB NOT NULL,
    identity BLOB,
    display_name TEXT NOT NULL DEFAULT '',
    local_name TEXT,
    verified INTEGER NOT NULL DEFAULT 0,
    joined_seq INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (group_id, group_key)
);
CREATE TABLE IF NOT EXISTS trusted (
    identity BLOB PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS messages (
    group_id BLOB NOT NULL,
    seq INTEGER NOT NULL,
    sender_group_key BLOB,
    kind INTEGER NOT NULL,
    body TEXT NOT NULL,
    sent_unix INTEGER NOT NULL,
    PRIMARY KEY (group_id, seq)
);
CREATE TABLE IF NOT EXISTS vouchers (
    group_id BLOB NOT NULL,
    token BLOB NOT NULL,
    voucher BLOB NOT NULL,
    secret BLOB,
    PRIMARY KEY (group_id, token)
);
CREATE TABLE IF NOT EXISTS invites_made (
    token BLOB PRIMARY KEY,
    server_id INTEGER NOT NULL,
    group_id BLOB,
    expires_unix INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
    id BLOB PRIMARY KEY,
    group_id BLOB NOT NULL,
    offer BLOB NOT NULL,
    state INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS pending_joins (
    token BLOB PRIMARY KEY,
    server_id INTEGER NOT NULL,
    link TEXT NOT NULL,
    group_key BLOB NOT NULL,
    lodged_unix INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS expected_joiners (
    group_id BLOB NOT NULL,
    group_key BLOB NOT NULL,
    PRIMARY KEY (group_id, group_key)
);
CREATE TABLE IF NOT EXISTS extensions (
    group_id BLOB NOT NULL,
    seq INTEGER NOT NULL,
    sender_group_key BLOB,
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL,
    version INTEGER NOT NULL,
    body BLOB NOT NULL,
    summary TEXT,
    sent_unix INTEGER NOT NULL,
    PRIMARY KEY (group_id, seq)
);
CREATE TABLE IF NOT EXISTS owed_proofs (
    group_id BLOB NOT NULL,
    token BLOB NOT NULL,
    proof BLOB NOT NULL,
    PRIMARY KEY (group_id, token)
);
CREATE TABLE IF NOT EXISTS ended_names (
    group_id BLOB NOT NULL,
    group_key BLOB NOT NULL,
    name TEXT NOT NULL,
    PRIMARY KEY (group_id, group_key)
);
CREATE TABLE IF NOT EXISTS close_votes (
    group_id BLOB NOT NULL,
    close_id BLOB NOT NULL,
    voter BLOB NOT NULL,
    yes INTEGER NOT NULL,
    at_unix INTEGER NOT NULL,
    PRIMARY KEY (group_id, close_id, voter)
);
CREATE TABLE IF NOT EXISTS close_kept (
    group_id BLOB NOT NULL,
    close_id BLOB NOT NULL,
    PRIMARY KEY (group_id, close_id)
);
CREATE TABLE IF NOT EXISTS owed_reposts (
    group_id BLOB PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS held_profiles (
    group_id BLOB PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS awaited_inviters (
    group_id BLOB PRIMARY KEY,
    group_key BLOB NOT NULL,
    identity BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS topics (
    group_id BLOB PRIMARY KEY,
    topic BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS ended_rooms (
    group_id BLOB PRIMARY KEY,
    name TEXT NOT NULL,
    is_dm INTEGER NOT NULL,
    why INTEGER NOT NULL,
    ended_unix INTEGER NOT NULL,
    seen_seq INTEGER NOT NULL
);
";

/// Tables holding a room's state while someone is in it, each keyed by
/// `group_id`. Ending the room deletes its rows in every one of them at once.
pub const ROOM_STATE_TABLES: &[&str] = &[
    "members",
    "vouchers",
    "files",
    "owed_proofs",
    "expected_joiners",
    "close_votes",
    "close_kept",
    "awaited_inviters",
    "owed_reposts",
    "held_profiles",
    "topics",
    // Server links have no `group_id`, so ending a room leaves them be.
    "invites_made",
];

/// Tables holding a room's history, each keyed by `group_id`. An ended
/// room keeps these until they are read, then loses them with its
/// `ended_rooms` row. `ended_names` keeps the names of the people whose
/// lines are still here, once the room's `members` rows are gone.
pub const ROOM_HISTORY_TABLES: &[&str] = &["messages", "extensions", "ended_names"];

/// OpenMLS's tables holding a group's state and secrets, keyed by
/// `group_id` in the storage codec (see [`openmls_key`]).
pub const OPENMLS_GROUP_TABLES: &[&str] = &[
    "openmls_group_data",
    "openmls_epoch_keys_pairs",
    "openmls_own_leaf_nodes",
    "openmls_proposals",
];

/// How OpenMLS's storage writes a group ID in its `group_id` columns.
fn openmls_key(g: &GroupId) -> Result<Vec<u8>, CoreError> {
    use openmls_sqlite_storage::Codec as _;
    crate::provider::JsonCodec::to_vec(&openmls::group::GroupId::from_slice(&g.0))
        .map_err(|e| CoreError::Storage(e.to_string()))
}

/// Deletes a room's state inside `tx`: its rows in every
/// [`ROOM_STATE_TABLES`] table, everything OpenMLS holds for it (`mls` is
/// its key there, from [`openmls_key`]) and its `groups` row.
fn delete_state(tx: &rusqlite::Transaction, g: &GroupId, mls: &[u8]) -> Result<(), CoreError> {
    for table in ROOM_STATE_TABLES {
        tx.execute(
            &format!("DELETE FROM {table} WHERE group_id = ?1"),
            [g.0.as_slice()],
        )?;
    }
    for table in OPENMLS_GROUP_TABLES {
        tx.execute(&format!("DELETE FROM {table} WHERE group_id = ?1"), [mls])?;
    }
    tx.execute("DELETE FROM groups WHERE id = ?1", [g.0.as_slice()])?;
    Ok(())
}

/// A `Closed` message this app knows of in a room: one it remembers from
/// someone else, or its own while it closes the room itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Closing {
    pub close_id: [u8; 16],
    /// Who sent it: this member's own key while it closes the room itself.
    pub by: Key,
    /// This app's own `Closed` for `close_id` went out.
    pub posted: bool,
    /// This app stopped trying to finish this close, and said so.
    pub gave_up: bool,
}

/// How many times [`Store::checkpoint`] tries before it gives up.
const CHECKPOINT_TRIES: usize = 3;

/// Who this person is on this device.
#[derive(Clone, Debug)]
pub struct Profile {
    pub identity: KeyPair,
    pub display_name: String,
}

pub struct Store {
    conn: Connection,
    dir: PathBuf,
    /// Locked for as long as this store is open; dropping it unlocks.
    _lock: std::fs::File,
    /// What opening changed or could not change, for the person to read.
    notes: Vec<String>,
    /// The next checkpoint reports a busy log, for tests.
    #[cfg(feature = "test-hooks")]
    busy_next_checkpoint: std::cell::Cell<bool>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn derive_key(passphrase: &str, kdf: &Kdf) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let params = Params::new(kdf.mem_kib, kdf.passes, kdf.lanes, Some(32))
        .map_err(|e| CoreError::Other(e.to_string()))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), &kdf.salt, key.as_mut())
        .map_err(|e| CoreError::Other(e.to_string()))?;
    Ok(key)
}

/// Opens the database file with the raw key. Returns `WrongPassphrase` when
/// the key does not decrypt it; nothing is written in that case.
fn open_keyed(path: &Path, key: &[u8; 32]) -> Result<Connection, CoreError> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA cipher_log_level = NONE;")?;
    let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", hex(key)));
    conn.execute_batch(&pragma)?;
    // Deleted rows are overwritten, not just marked free. SQLCipher does
    // this already when a key is set; saying so keeps it on regardless.
    conn.execute_batch("PRAGMA secure_delete = ON;")?;
    if conn
        .query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })
        .is_err()
    {
        return Err(CoreError::WrongPassphrase);
    }
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")?;
    Ok(conn)
}

/// A `messages` row read as seq, sender, kind, body and sent time.
fn message_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<MessageRow> {
    Ok(MessageRow {
        seq: r.get::<_, i64>(0)? as u64,
        sender: key_col(r.get(1)?),
        kind: r.get(2)?,
        body: r.get(3)?,
        sent_unix: r.get::<_, i64>(4)? as u64,
    })
}

/// Columns added after the first release, for profiles made before them.
const ADDED_COLUMNS: &[(&str, &str, &str)] = &[
    ("vouchers", "mine", "INTEGER NOT NULL DEFAULT 0"),
    ("vouchers", "mac_key", "BLOB"),
    ("vouchers", "seal_key", "BLOB"),
    ("vouchers", "request_key", "BLOB"),
    ("members", "app_version", "TEXT"),
    ("groups", "announced_version", "TEXT"),
    ("groups", "seen_seq", "INTEGER NOT NULL DEFAULT 0"),
    ("groups", "muted", "INTEGER NOT NULL DEFAULT 0"),
    ("groups", "closing", "BLOB"),
    ("profile", "theme", "TEXT"),
    ("profile", "mouse", "INTEGER"),
    // The update check: 0 when the person turned it off, when the app last
    // asked GitHub, when GitHub last answered and the release it named.
    ("profile", "update_check", "INTEGER"),
    ("profile", "update_asked_unix", "INTEGER"),
    ("profile", "update_answered_unix", "INTEGER"),
    ("profile", "update_latest", "TEXT"),
    ("pending_joins", "key_package_refs", "BLOB"),
    ("vouchers", "joiner", "BLOB"),
    ("files", "sender_group_key", "BLOB"),
    ("files", "added_unix", "INTEGER NOT NULL DEFAULT 0"),
    // The server an ended room was on, so forgetting that server finds
    // it. Rooms that ended before this column have none.
    ("ended_rooms", "server_id", "INTEGER"),
];

fn migrate(conn: &Connection) -> Result<(), CoreError> {
    conn.execute_batch(SCHEMA)?;
    for (table, column, decl) in ADDED_COLUMNS {
        let has: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2)",
            params![table, column],
            |r| r.get(0),
        )?;
        if !has {
            // A column and its start value arrive together, or neither does
            // and the next open tries again.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl};"))?;
            if *column == "seen_seq" {
                // History from before seen marks counts as read, once.
                tx.execute_batch("UPDATE groups SET seen_seq = last_seq;")?;
            }
            tx.commit()?;
        }
    }
    Ok(())
}

/// How long [`lock`] keeps trying a taken lock before it says another app
/// has the profile, and how long it waits between tries.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_millis(500);
const LOCK_RETRY: std::time::Duration = std::time::Duration::from_millis(10);

/// Takes the profile's lock, or says another app has it.
///
/// A taken lock is tried again for up to [`LOCK_WAIT`] before the answer is
/// "in use". When this process starts a program, the program holds a copy of
/// every open file until it has started, the lock of a profile that has just
/// closed included, and for that moment the lock still looks taken. Nothing
/// on this side can stop the copy. Another app that has the profile open is
/// still refused, only up to half a second later.
fn lock(dir: &Path) -> Result<std::fs::File, CoreError> {
    let f = crate::perms::private_options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(LOCK_FILE))?;
    let start = std::time::Instant::now();
    loop {
        match f.try_lock() {
            Ok(()) => return Ok(f),
            Err(std::fs::TryLockError::WouldBlock) if start.elapsed() < LOCK_WAIT => {
                std::thread::sleep(LOCK_RETRY);
            }
            Err(std::fs::TryLockError::WouldBlock) => return Err(CoreError::ProfileInUse),
            Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
        }
    }
}

/// The connection OpenMLS keeps its state on.
fn provider_conn(path: &Path, key: &[u8; 32]) -> Result<Connection, CoreError> {
    open_keyed(path, key)
}

fn provider(path: &Path, key: &[u8; 32]) -> Result<Provider, CoreError> {
    let conn = provider_conn(path, key)?;
    let mut storage = Storage::new(conn);
    storage
        .run_migrations()
        .map_err(|e| CoreError::Storage(e.to_string()))?;
    Ok(Provider::new(storage))
}

/// Whether `dir` holds a profile: a database with something in it. A salt
/// file beside an empty database, or beside none, is a profile whose making
/// stopped before anything was stored; no passphrase opens it, and making a
/// profile there starts over.
pub fn has_profile(dir: &Path) -> bool {
    #[cfg(feature = "test-hooks")]
    crate::keep_test_hooks_marker();
    let size = |name: &str| std::fs::metadata(dir.join(name)).map_or(0, |m| m.len());
    size(DB_FILE) > 0 || size(&format!("{DB_FILE}-wal")) > 0
}

/// The name a salt file is written under until it is complete.
fn salt_new_name() -> String {
    format!("{SALT_FILE}.new")
}

#[cfg(test)]
thread_local! {
    /// The point where this thread's next `Store::create` stops, as if the
    /// app were killed there: "salt" before the salt file gets its name,
    /// "key" while deriving the key, "aside" after the first file is moved
    /// aside.
    static CRASH_AT: std::cell::Cell<&'static str> = const { std::cell::Cell::new("") };
}

/// Stops here when a test asked to crash at `at`.
#[cfg(test)]
fn crash_point(at: &'static str) -> Result<(), CoreError> {
    if CRASH_AT.get() == at {
        CRASH_AT.set("");
        return Err(CoreError::Other(format!("stopped at {at}")));
    }
    Ok(())
}

#[cfg(not(test))]
fn crash_point(_at: &'static str) -> Result<(), CoreError> {
    Ok(())
}

/// Before a new profile is made in `dir`, which holds none: moves aside
/// what a create that stopped part way left, a `salt.new` file or an empty
/// database beside a salt file in Socketchat's format, and says so. Nothing is deleted. A salt
/// file without a database may be waiting for it, and a file named `salt`
/// in another format is someone else's; both are refused and left alone.
fn set_aside_unfinished(dir: &Path, report: &mut crate::perms::Report) -> Result<(), CoreError> {
    let there = |name: &str| std::fs::symlink_metadata(dir.join(name)).is_ok();
    let db = dir.join(DB_FILE);
    let salt = dir.join(SALT_FILE);
    let mut names = Vec::new();
    // A salt file being written goes under this name until it is complete,
    // so whatever is left here was never a whole salt file.
    let salt_new = salt_new_name();
    if there(&salt_new) {
        names.push(salt_new);
    }
    if there(SALT_FILE) {
        if !there(DB_FILE) {
            return Err(CoreError::Other(format!(
                "The profile folder holds a salt file, {}, without its database, {DB_FILE}. Put the database back, or move the salt file aside to make a new profile here.",
                salt.display()
            )));
        }
        let ours = crate::perms::read_bounded(&salt, SALT_FILE_MAX + 1)
            .ok()
            .is_some_and(|b| Kdf::decode(&b).is_ok());
        if !ours {
            return Err(CoreError::Other(format!(
                "The profile folder {} holds a file named {SALT_FILE} that is not a Socketchat salt file, beside an empty {}. Socketchat left both as they are; move them aside to make a new profile here.",
                dir.display(),
                db.display()
            )));
        }
        // The salt file first and the database last: stopped part way,
        // this leaves an empty database with or without our salt file,
        // which the next create finishes.
        names.extend([
            SALT_FILE.to_string(),
            format!("{DB_FILE}-journal"),
            format!("{DB_FILE}-wal"),
            format!("{DB_FILE}-shm"),
            DB_FILE.to_string(),
        ]);
    }
    if names.is_empty() {
        return Ok(());
    }
    let stamp = crate::now_unix();
    let mut moved = Vec::new();
    for name in names {
        let from = dir.join(&name);
        if std::fs::symlink_metadata(&from).is_err() {
            continue;
        }
        let mut aside = format!("{name}.unfinished-{stamp}");
        let mut n = 1;
        while std::fs::symlink_metadata(dir.join(&aside)).is_ok() {
            aside = format!("{name}.unfinished-{stamp}-{n}");
            n += 1;
        }
        std::fs::rename(&from, dir.join(&aside))?;
        moved.push(aside);
        crash_point("aside")?;
    }
    report.note(format!(
        "Socketchat moved an unfinished profile aside, as {}, and made a new one in its place.",
        moved.join(", ")
    ));
    Ok(())
}

impl Store {
    /// Makes a new, empty profile store in `dir`.
    pub fn create(dir: &Path, passphrase: &str) -> Result<(Store, Provider), CoreError> {
        if passphrase.is_empty() {
            return Err(CoreError::Other("A passphrase cannot be empty.".into()));
        }
        Self::create_unchecked(dir, passphrase)
    }

    /// [`Store::create`] without the empty-passphrase check: how 0.5.0
    /// made profiles, kept for tests of the profiles it left behind.
    #[cfg(feature = "test-hooks")]
    pub fn create_with_any_passphrase(
        dir: &Path,
        passphrase: &str,
    ) -> Result<(Store, Provider), CoreError> {
        Self::create_unchecked(dir, passphrase)
    }

    fn create_unchecked(dir: &Path, passphrase: &str) -> Result<(Store, Provider), CoreError> {
        let db = dir.join(DB_FILE);
        if has_profile(dir) {
            return Err(CoreError::ProfileExists);
        }
        let mut report = crate::perms::Report::default();
        crate::perms::create_private_dir(dir)?;
        crate::perms::guard_dir(dir, &mut report)?;
        let lock = lock(dir)?;
        if has_profile(dir) {
            return Err(CoreError::ProfileExists);
        }
        set_aside_unfinished(dir, &mut report)?;
        // The empty database first, then the salt file, then the key: a
        // create stopped at any point leaves an empty database alone or
        // beside its salt file, which the next create finishes, and never a
        // salt file without a database, which means a database is missing.
        // No passphrase opens an empty database (see `has_profile`).
        crate::perms::touch_private(&db, &mut report)?;
        let kdf = Kdf::new();
        // Written in full under another name, then renamed: the salt file
        // is either missing or whole, even after a power cut.
        let salt_new = dir.join(salt_new_name());
        crate::perms::write_private(&salt_new, &kdf.encode())?;
        crash_point("salt")?;
        std::fs::rename(&salt_new, dir.join(SALT_FILE))?;
        crate::perms::sync_dir(dir);
        crash_point("key")?;
        let key = derive_key(passphrase, &kdf)?;
        let conn = open_keyed(&db, &key)?;
        migrate(&conn)?;
        let p = provider(&db, &key)?;
        Ok((
            Store {
                conn,
                dir: dir.to_path_buf(),
                _lock: lock,
                notes: report.lines(dir),
                #[cfg(feature = "test-hooks")]
                busy_next_checkpoint: std::cell::Cell::new(false),
            },
            p,
        ))
    }

    /// Opens the profile store in `dir` with the person's passphrase.
    pub fn open(dir: &Path, passphrase: &str) -> Result<(Store, Provider), CoreError> {
        let db = dir.join(DB_FILE);
        let salt_path = dir.join(SALT_FILE);
        if !has_profile(dir) {
            return Err(CoreError::NoProfile);
        }
        if std::fs::symlink_metadata(&salt_path).is_err() {
            return Err(CoreError::Other(format!(
                "The profile's salt file, {}, is missing. Nothing can open {} without it; if you moved it, put it back.",
                salt_path.display(),
                db.display()
            )));
        }
        let mut report = crate::perms::Report::default();
        crate::perms::guard_dir(dir, &mut report)?;
        let lock = lock(dir)?;
        crate::perms::narrow_profile_files(dir, &mut report);
        let salt = crate::perms::read_bounded(&salt_path, SALT_FILE_MAX + 1).map_err(|e| {
            if crate::perms::is_link(&e) {
                CoreError::Storage("the profile's salt file is a link to another place".into())
            } else {
                e.into()
            }
        })?;
        let kdf = Kdf::decode(&salt)?;
        let key = derive_key(passphrase, &kdf)?;
        let conn = open_keyed(&db, &key)?;
        migrate(&conn)?;
        let p = provider(&db, &key)?;
        Ok((
            Store {
                conn,
                dir: dir.to_path_buf(),
                _lock: lock,
                notes: report.lines(dir),
                #[cfg(feature = "test-hooks")]
                busy_next_checkpoint: std::cell::Cell::new(false),
            },
            p,
        ))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// What opening changed or could not change, for the person to read.
    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn profile(&self) -> Result<Option<Profile>, CoreError> {
        let row: Option<(Vec<u8>, String)> = self
            .conn
            .query_row(
                "SELECT identity, display_name FROM profile WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((id, display_name)) => Ok(Some(Profile {
                identity: postcard::from_bytes(&id)?,
                display_name,
            })),
        }
    }

    /// The colors this person picked for the chat screen, if they did.
    pub fn theme(&self) -> Result<Option<String>, CoreError> {
        Ok(self
            .conn
            .query_row("SELECT theme FROM profile WHERE id = 1", [], |r| r.get(0))
            .optional()?
            .flatten())
    }

    pub fn set_theme(&self, theme: &str) -> Result<(), CoreError> {
        self.conn
            .execute("UPDATE profile SET theme = ?1 WHERE id = 1", params![theme])?;
        Ok(())
    }

    /// Whether the chat screen takes mouse clicks, if this person said.
    pub fn mouse(&self) -> Result<Option<bool>, CoreError> {
        Ok(self
            .conn
            .query_row("SELECT mouse FROM profile WHERE id = 1", [], |r| r.get(0))
            .optional()?
            .flatten())
    }

    pub fn set_mouse(&self, on: bool) -> Result<(), CoreError> {
        self.conn
            .execute("UPDATE profile SET mouse = ?1 WHERE id = 1", params![on])?;
        Ok(())
    }

    /// What the profile remembers about the update check.
    pub fn update_state(&self) -> Result<crate::update::UpdateState, CoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT update_check, update_asked_unix, update_answered_unix, update_latest
                 FROM profile WHERE id = 1",
                [],
                |r| {
                    Ok(crate::update::UpdateState {
                        on: r.get::<_, Option<bool>>(0)?.unwrap_or(true),
                        asked_unix: r.get::<_, Option<i64>>(1)?.map(|t| t.max(0) as u64),
                        answered_unix: r.get::<_, Option<i64>>(2)?.map(|t| t.max(0) as u64),
                        latest: r.get(3)?,
                    })
                },
            )
            .optional()?;
        Ok(row.unwrap_or_default())
    }

    pub fn set_update_check(&self, on: bool) -> Result<(), CoreError> {
        self.conn.execute(
            "UPDATE profile SET update_check = ?1 WHERE id = 1",
            params![on],
        )?;
        Ok(())
    }

    /// Notes that the app asked GitHub at `unix`.
    pub fn set_update_asked(&self, unix: u64) -> Result<(), CoreError> {
        self.conn.execute(
            "UPDATE profile SET update_asked_unix = ?1 WHERE id = 1",
            params![unix as i64],
        )?;
        Ok(())
    }

    /// Notes that GitHub answered at `unix`, naming `latest`.
    pub fn set_update_answer(&self, unix: u64, latest: &str) -> Result<(), CoreError> {
        self.conn.execute(
            "UPDATE profile SET update_answered_unix = ?1, update_latest = ?2 WHERE id = 1",
            params![unix as i64, latest],
        )?;
        Ok(())
    }

    pub fn set_profile(&self, p: &Profile) -> Result<(), CoreError> {
        let id = Zeroizing::new(postcard::to_stdvec(&p.identity)?);
        self.conn.execute(
            "INSERT INTO profile (id, identity, display_name, created_unix) VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET identity = excluded.identity, display_name = excluded.display_name",
            params![id.as_slice(), p.display_name, crate::now_unix() as i64],
        )?;
        Ok(())
    }
}

/// An invite link's voucher as one member holds it.
#[derive(Clone, Debug)]
pub struct StoredVoucher {
    /// The voucher, postcard-encoded.
    pub voucher: Vec<u8>,
    /// Checks a join request's signature (see `keys::join_request_ok`).
    pub request_key: Key,
    /// Seals the voucher for the joiner.
    pub seal_key: [u8; 32],
    /// The invite secret itself: only on the link maker's own rows.
    pub secret: Option<[u8; 32]>,
}

/// A server this client talks to.
#[derive(Clone, Debug)]
pub struct ServerRow {
    pub id: i64,
    pub host: String,
    pub port: u16,
    pub cert_fpr: [u8; 32],
    pub account: Option<KeyPair>,
}

/// A group this client belongs to.
#[derive(Clone, Debug)]
pub struct GroupRow {
    pub id: GroupId,
    pub server_id: i64,
    pub key: KeyPair,
    pub name: String,
    pub is_dm: bool,
    pub left: bool,
    pub last_seq: u64,
    pub last_update_unix: u64,
    pub joined_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberRow {
    pub key: Key,
    pub identity: Option<Key>,
    pub display_name: String,
    pub local_name: Option<String>,
    pub verified: bool,
    pub joined_seq: u64,
    /// The app version this member said they run; `None` if they never said.
    pub app_version: Option<String>,
}

/// A stored extension message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionRecord {
    pub seq: u64,
    pub sender: Option<Key>,
    pub namespace: String,
    pub kind: String,
    pub version: u16,
    pub body: Vec<u8>,
    pub summary: Option<String>,
    pub sent_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageRow {
    pub seq: u64,
    pub sender: Option<Key>,
    pub kind: i64,
    pub body: String,
    pub sent_unix: u64,
}

/// A room this person is no longer in whose messages are still here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndedRow {
    pub id: GroupId,
    pub name: String,
    pub is_dm: bool,
    /// Why it ended, as the client numbers it.
    pub why: i64,
    pub ended_unix: u64,
}

/// A join this client lodged and is waiting on.
#[derive(Clone, Debug)]
pub struct PendingJoin {
    pub token: Token,
    pub server_id: i64,
    pub link: String,
    pub key: KeyPair,
    pub lodged_unix: u64,
    /// Hash references of the KeyPackages lodged for this join (see
    /// `invite::KeyPackages`). Empty for a join lodged before 0.5.0.
    pub key_package_refs: Vec<Vec<u8>>,
}

fn key_col(v: Option<Vec<u8>>) -> Option<Key> {
    v.and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .map(Key)
}

fn kp_col(b: &[u8]) -> rusqlite::Result<KeyPair> {
    postcard::from_bytes(b).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(e))
    })
}

fn kp_bytes(k: &KeyPair) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(postcard::to_stdvec(k).expect("a key pair always encodes"))
}

impl Store {
    /// Adds a server or returns the existing row's ID.
    pub fn add_server(&self, host: &str, port: u16, cert_fpr: &[u8; 32]) -> Result<i64, CoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO servers (host, port, cert_fpr) VALUES (?1, ?2, ?3)",
            params![host, port, cert_fpr.as_slice()],
        )?;
        Ok(self.conn.query_row(
            "SELECT id FROM servers WHERE host = ?1 AND port = ?2",
            params![host, port],
            |r| r.get(0),
        )?)
    }

    /// The pinned certificate fingerprint for a server address, if known.
    pub fn server_pin(&self, host: &str, port: u16) -> Result<Option<[u8; 32]>, CoreError> {
        let fpr: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT cert_fpr FROM servers WHERE host = ?1 AND port = ?2",
                params![host, port],
                |r| r.get(0),
            )
            .optional()?;
        Ok(fpr.and_then(|f| f.try_into().ok()))
    }

    /// Pins a new certificate fingerprint for a known server address.
    pub fn set_server_pin(
        &self,
        host: &str,
        port: u16,
        cert_fpr: &[u8; 32],
    ) -> Result<(), CoreError> {
        self.conn.execute(
            "UPDATE servers SET cert_fpr = ?1 WHERE host = ?2 AND port = ?3",
            params![cert_fpr.as_slice(), host, port],
        )?;
        Ok(())
    }

    pub fn set_account(&self, server_id: i64, account: &KeyPair) -> Result<(), CoreError> {
        self.conn.execute(
            "UPDATE servers SET account_key = ?1 WHERE id = ?2",
            params![kp_bytes(account).as_slice(), server_id],
        )?;
        Ok(())
    }

    pub fn servers(&self) -> Result<Vec<ServerRow>, CoreError> {
        let mut st = self
            .conn
            .prepare("SELECT id, host, port, cert_fpr, account_key FROM servers ORDER BY id")?;
        let rows = st.query_map([], |r| {
            let fpr: Vec<u8> = r.get(3)?;
            let acct: Option<Vec<u8>> = r.get(4)?;
            Ok(ServerRow {
                id: r.get(0)?,
                host: r.get(1)?,
                port: r.get(2)?,
                cert_fpr: fpr.try_into().unwrap_or([0; 32]),
                account: match acct {
                    Some(b) => Some(kp_col(&b)?),
                    None => None,
                },
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Adds a room this person is now in. A room they were in before and
    /// whose history is still here stops being an ended room and keeps its
    /// seen mark.
    pub fn add_group(&self, g: &GroupRow) -> Result<(), CoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO groups (id, server_id, group_key, name, is_dm, last_seq, last_update_unix, joined_unix, seen_seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
                     COALESCE((SELECT seen_seq FROM ended_rooms WHERE group_id = ?1), 0))",
            params![
                g.id.0.as_slice(),
                g.server_id,
                kp_bytes(&g.key).as_slice(),
                g.name,
                g.is_dm,
                g.last_seq as i64,
                g.last_update_unix as i64,
                g.joined_unix as i64
            ],
        )?;
        tx.execute(
            "DELETE FROM ended_rooms WHERE group_id = ?1",
            [g.id.0.as_slice()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn groups(&self) -> Result<Vec<GroupRow>, CoreError> {
        let mut st = self.conn.prepare(
            "SELECT id, server_id, group_key, name, is_dm, left_group, last_seq, last_update_unix, joined_unix
             FROM groups ORDER BY joined_unix, id",
        )?;
        let rows = st.query_map([], |r| {
            let id: Vec<u8> = r.get(0)?;
            let key: Vec<u8> = r.get(2)?;
            Ok(GroupRow {
                id: GroupId(id.try_into().unwrap_or([0; 16])),
                server_id: r.get(1)?,
                key: kp_col(&key)?,
                name: r.get(3)?,
                is_dm: r.get(4)?,
                left: r.get(5)?,
                last_seq: r.get::<_, i64>(6)? as u64,
                last_update_unix: r.get::<_, i64>(7)? as u64,
                joined_unix: r.get::<_, i64>(8)? as u64,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn set_group_name(&self, g: &GroupId, name: &str) -> Result<(), CoreError> {
        self.conn.execute(
            "UPDATE groups SET name = ?1 WHERE id = ?2",
            params![name, g.0.as_slice()],
        )?;
        Ok(())
    }

    /// Keeps a room's topic as it came, signature and all, so it can be
    /// passed on to someone who joins. An empty text keeps that the topic
    /// was cleared.
    pub fn set_topic(&self, g: &GroupId, t: &crate::appmsg::Topic) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO topics (group_id, topic) VALUES (?1, ?2)",
            params![g.0.as_slice(), postcard::to_stdvec(t)?],
        )?;
        Ok(())
    }

    /// A room's topic as last set, or `None` when this app never learned
    /// one. One that does not read counts as none.
    pub fn topic(&self, g: &GroupId) -> Result<Option<crate::appmsg::Topic>, CoreError> {
        let b: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT topic FROM topics WHERE group_id = ?1",
                [g.0.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(b.and_then(|b| postcard::from_bytes(&b).ok()))
    }

    pub fn set_last_seq(&self, g: &GroupId, seq: u64) -> Result<(), CoreError> {
        self.conn.execute(
            "UPDATE groups SET last_seq = max(last_seq, ?1) WHERE id = ?2",
            params![seq as i64, g.0.as_slice()],
        )?;
        Ok(())
    }

    /// Moves the seen mark up to `seq`. It never moves back.
    pub fn set_seen_seq(&self, g: &GroupId, seq: u64) -> Result<(), CoreError> {
        self.conn.execute(
            "UPDATE groups SET seen_seq = max(seen_seq, ?1) WHERE id = ?2",
            params![seq as i64, g.0.as_slice()],
        )?;
        Ok(())
    }

    /// Marks every stored line of a room as seen, whether the room is live
    /// or ended.
    pub fn mark_seen(&self, g: &GroupId) -> Result<(), CoreError> {
        self.conn.execute(
            "UPDATE groups SET seen_seq = max(seen_seq,
                 COALESCE((SELECT max(seq) FROM messages WHERE group_id = groups.id), 0))
             WHERE id = ?1",
            params![g.0.as_slice()],
        )?;
        self.conn.execute(
            "UPDATE ended_rooms SET seen_seq = max(seen_seq,
                 COALESCE((SELECT max(seq) FROM messages WHERE group_id = ended_rooms.group_id), 0))
             WHERE group_id = ?1",
            params![g.0.as_slice()],
        )?;
        Ok(())
    }

    /// Moves the seen mark of a live or ended room up to `seq`. It never
    /// moves back.
    pub fn mark_seen_upto(&self, g: &GroupId, seq: u64) -> Result<(), CoreError> {
        self.set_seen_seq(g, seq)?;
        self.conn.execute(
            "UPDATE ended_rooms SET seen_seq = max(seen_seq, ?1) WHERE group_id = ?2",
            params![seq as i64, g.0.as_slice()],
        )?;
        Ok(())
    }

    /// The seen mark of a live or ended room.
    pub fn seen_mark(&self, g: &GroupId) -> Result<u64, CoreError> {
        let n: i64 = self.conn.query_row(
            "SELECT COALESCE(
                 (SELECT seen_seq FROM groups WHERE id = ?1),
                 (SELECT seen_seq FROM ended_rooms WHERE group_id = ?1),
                 0)",
            params![g.0.as_slice()],
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }

    /// Stored lines newer than the room's seen mark: the live room's, or
    /// the ended room's.
    pub fn unseen(&self, g: &GroupId) -> Result<u32, CoreError> {
        let n: i64 = self.conn.query_row(
            "SELECT count(*) FROM messages
             WHERE group_id = ?1 AND seq > COALESCE(
                 (SELECT seen_seq FROM groups WHERE id = ?1),
                 (SELECT seen_seq FROM ended_rooms WHERE group_id = ?1),
                 0)",
            params![g.0.as_slice()],
            |r| r.get(0),
        )?;
        Ok(n.min(i64::from(u32::MAX)) as u32)
    }

    pub fn set_muted(&self, g: &GroupId, muted: bool) -> Result<(), CoreError> {
        self.conn.execute(
            "UPDATE groups SET muted = ?1 WHERE id = ?2",
            params![muted, g.0.as_slice()],
        )?;
        Ok(())
    }

    pub fn is_muted(&self, g: &GroupId) -> Result<bool, CoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT muted FROM groups WHERE id = ?1",
                params![g.0.as_slice()],
                |r| r.get(0),
            )
            .unwrap_or(false))
    }

    pub fn set_last_update(&self, g: &GroupId, unix: u64) -> Result<(), CoreError> {
        self.conn.execute(
            "UPDATE groups SET last_update_unix = ?1 WHERE id = ?2",
            params![unix as i64, g.0.as_slice()],
        )?;
        Ok(())
    }

    pub fn set_is_dm(&self, g: &GroupId) -> Result<(), CoreError> {
        self.conn.execute(
            "UPDATE groups SET is_dm = 1 WHERE id = ?1",
            [g.0.as_slice()],
        )?;
        Ok(())
    }

    /// Marks a room as left the way 0.4.0 did, keeping everything. Opening
    /// the profile deletes such a room with all its history.
    pub fn set_left(&self, g: &GroupId) -> Result<(), CoreError> {
        self.conn.execute(
            "UPDATE groups SET left_group = 1 WHERE id = ?1",
            [g.0.as_slice()],
        )?;
        Ok(())
    }

    /// Adds a member or updates the fields given.
    pub fn upsert_member(
        &self,
        g: &GroupId,
        key: &Key,
        joined_seq: Option<u64>,
    ) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT INTO members (group_id, group_key, joined_seq) VALUES (?1, ?2, ?3)
             ON CONFLICT(group_id, group_key) DO NOTHING",
            params![
                g.0.as_slice(),
                key.0.as_slice(),
                joined_seq.unwrap_or(0) as i64
            ],
        )?;
        Ok(())
    }

    pub fn set_member_profile(
        &self,
        g: &GroupId,
        key: &Key,
        identity: &Key,
        display_name: &str,
    ) -> Result<(), CoreError> {
        self.upsert_member(g, key, None)?;
        self.conn.execute(
            "UPDATE members SET identity = ?1, display_name = ?2 WHERE group_id = ?3 AND group_key = ?4",
            params![identity.0.as_slice(), display_name, g.0.as_slice(), key.0.as_slice()],
        )?;
        Ok(())
    }

    pub fn set_local_name(
        &self,
        g: &GroupId,
        key: &Key,
        name: Option<&str>,
    ) -> Result<(), CoreError> {
        self.conn.execute(
            "UPDATE members SET local_name = ?1 WHERE group_id = ?2 AND group_key = ?3",
            params![name, g.0.as_slice(), key.0.as_slice()],
        )?;
        Ok(())
    }

    pub fn remove_member(&self, g: &GroupId, key: &Key) -> Result<(), CoreError> {
        self.conn.execute(
            "DELETE FROM members WHERE group_id = ?1 AND group_key = ?2",
            params![g.0.as_slice(), key.0.as_slice()],
        )?;
        Ok(())
    }

    pub fn members(&self, g: &GroupId) -> Result<Vec<MemberRow>, CoreError> {
        let mut st = self.conn.prepare(
            "SELECT m.group_key, m.identity, m.display_name, m.local_name, m.joined_seq,
                    (m.identity IS NOT NULL AND EXISTS(SELECT 1 FROM trusted t WHERE t.identity = m.identity)),
                    m.app_version
             FROM members m WHERE m.group_id = ?1 ORDER BY m.joined_seq, m.group_key",
        )?;
        let rows = st.query_map([g.0.as_slice()], |r| {
            Ok(MemberRow {
                key: key_col(Some(r.get(0)?)).unwrap_or(Key([0; 32])),
                identity: key_col(r.get(1)?),
                display_name: r.get(2)?,
                local_name: r.get(3)?,
                joined_seq: r.get::<_, i64>(4)? as u64,
                verified: r.get(5)?,
                app_version: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Records the app version a member said they run. Returns whether it
    /// differs from what was stored.
    pub fn set_member_app_version(
        &self,
        g: &GroupId,
        key: &Key,
        version: &str,
    ) -> Result<bool, CoreError> {
        let n = self.conn.execute(
            "UPDATE members SET app_version = ?3
             WHERE group_id = ?1 AND group_key = ?2 AND app_version IS NOT ?3",
            params![g.0.as_slice(), key.0.as_slice(), version],
        )?;
        Ok(n > 0)
    }

    /// The version this client last announced in a group, if any.
    pub fn announced_version(&self, g: &GroupId) -> Result<Option<String>, CoreError> {
        Ok(self.conn.query_row(
            "SELECT announced_version FROM groups WHERE id = ?1",
            [g.0.as_slice()],
            |r| r.get(0),
        )?)
    }

    pub fn set_announced_version(&self, g: &GroupId, version: &str) -> Result<(), CoreError> {
        self.conn.execute(
            "UPDATE groups SET announced_version = ?1 WHERE id = ?2",
            params![version, g.0.as_slice()],
        )?;
        Ok(())
    }

    pub fn add_extension(
        &self,
        g: &GroupId,
        seq: u64,
        sender: Option<&Key>,
        e: &crate::appmsg::Extension,
        sent_unix: u64,
    ) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO extensions
                 (group_id, seq, sender_group_key, namespace, kind, version, body, summary, sent_unix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                g.0.as_slice(),
                seq as i64,
                sender.map(|k| k.0.to_vec()),
                e.namespace,
                e.kind,
                e.version,
                e.body,
                e.summary,
                sent_unix as i64
            ],
        )?;
        Ok(())
    }

    /// Up to `limit` extension messages with a sequence above `after_seq`,
    /// oldest first.
    pub fn extensions(
        &self,
        g: &GroupId,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<ExtensionRecord>, CoreError> {
        let mut st = self.conn.prepare(
            "SELECT seq, sender_group_key, namespace, kind, version, body, summary, sent_unix
             FROM extensions WHERE group_id = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
        )?;
        let rows = st.query_map(
            params![
                g.0.as_slice(),
                after_seq.min(i64::MAX as u64) as i64,
                limit as i64
            ],
            |r| {
                Ok(ExtensionRecord {
                    seq: r.get::<_, i64>(0)? as u64,
                    sender: key_col(r.get(1)?),
                    namespace: r.get(2)?,
                    kind: r.get(3)?,
                    version: r.get(4)?,
                    body: r.get(5)?,
                    summary: r.get(6)?,
                    sent_unix: r.get::<_, i64>(7)? as u64,
                })
            },
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn trust(&self, identity: &Key) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO trusted (identity) VALUES (?1)",
            [identity.0.as_slice()],
        )?;
        Ok(())
    }

    pub fn is_trusted(&self, identity: &Key) -> Result<bool, CoreError> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM trusted WHERE identity = ?1)",
            [identity.0.as_slice()],
            |r| r.get(0),
        )?)
    }

    pub fn add_message(
        &self,
        g: &GroupId,
        seq: u64,
        sender: Option<&Key>,
        kind: i64,
        body: &str,
        sent_unix: u64,
    ) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO messages (group_id, seq, sender_group_key, kind, body, sent_unix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                g.0.as_slice(),
                seq as i64,
                sender.map(|k| k.0.to_vec()),
                kind,
                body,
                sent_unix as i64
            ],
        )?;
        Ok(())
    }

    /// A sequence number for a notice this app writes itself after reading
    /// the log up to `last_seq`: past the log and past every stored line,
    /// so it never replaces one, such as this person's own line that the
    /// log has not given back yet.
    pub fn notice_seq(&self, g: &GroupId, last_seq: u64) -> Result<u64, CoreError> {
        let stored: i64 = self.conn.query_row(
            "SELECT COALESCE(max(seq), 0) FROM messages WHERE group_id = ?1",
            [g.0.as_slice()],
            |r| r.get(0),
        )?;
        Ok(last_seq.max(stored as u64) + 1)
    }

    /// The first `limit` messages after `after`, oldest first.
    pub fn messages_after(
        &self,
        g: &GroupId,
        after: u64,
        limit: usize,
    ) -> Result<Vec<MessageRow>, CoreError> {
        let mut st = self.conn.prepare(
            "SELECT seq, sender_group_key, kind, body, sent_unix FROM messages
             WHERE group_id = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
        )?;
        let rows = st.query_map(
            params![g.0.as_slice(), after as i64, limit as i64],
            message_row,
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The newest `limit` messages, oldest first.
    pub fn messages(&self, g: &GroupId, limit: usize) -> Result<Vec<MessageRow>, CoreError> {
        let mut st = self.conn.prepare(
            "SELECT seq, sender_group_key, kind, body, sent_unix FROM (
                 SELECT * FROM messages WHERE group_id = ?1 ORDER BY seq DESC LIMIT ?2
             ) ORDER BY seq",
        )?;
        let rows = st.query_map(params![g.0.as_slice(), limit as i64], message_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Keeps a voucher. The first one stored for a token stays: a later
    /// message about the same token never replaces it. `secret` is set only
    /// for links this client made.
    pub fn save_voucher(
        &self,
        g: &GroupId,
        token: &Token,
        v: &StoredVoucher,
    ) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO vouchers (group_id, token, voucher, secret, mine, request_key, seal_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                g.0.as_slice(),
                token.0.as_slice(),
                v.voucher,
                v.secret.as_ref().map(|s| s.as_slice()),
                v.secret.is_some(),
                v.request_key.0.as_slice(),
                v.seal_key.as_slice()
            ],
        )?;
        Ok(())
    }

    /// Remembers an invite link this client made. `group` is `None` for a
    /// server link.
    pub fn save_invite_made(
        &self,
        token: &Token,
        server_id: i64,
        group: Option<&GroupId>,
        expires_unix: u64,
    ) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO invites_made (token, server_id, group_id, expires_unix)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                token.0.as_slice(),
                server_id,
                group.map(|g| g.0.as_slice()),
                expires_unix as i64
            ],
        )?;
        Ok(())
    }

    /// The links this client made on a server: token, room (`None` for a
    /// server link) and expiry.
    pub fn invites_made_on(
        &self,
        server_id: i64,
    ) -> Result<Vec<(Token, Option<GroupId>, u64)>, CoreError> {
        let mut st = self.conn.prepare(
            "SELECT token, group_id, expires_unix FROM invites_made WHERE server_id = ?1",
        )?;
        let rows = st.query_map([server_id], |r| {
            let t: Vec<u8> = r.get(0)?;
            let g: Option<Vec<u8>> = r.get(1)?;
            Ok((
                Token(t.try_into().unwrap_or([0; 16])),
                g.map(|g| GroupId(g.try_into().unwrap_or([0; 16]))),
                r.get::<_, i64>(2)? as u64,
            ))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The server holding a link this client made: from the links it
    /// recorded, else from the room of a voucher it made.
    pub fn invite_server(&self, token: &Token) -> Result<Option<i64>, CoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT server_id FROM invites_made WHERE token = ?1
                 UNION ALL
                 SELECT g.server_id FROM vouchers v JOIN groups g ON g.id = v.group_id
                 WHERE v.token = ?1 AND v.mine = 1",
                [token.0.as_slice()],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Drops the record of a link, keeping its voucher.
    pub fn drop_invite_made(&self, token: &Token) -> Result<(), CoreError> {
        self.conn.execute(
            "DELETE FROM invites_made WHERE token = ?1",
            [token.0.as_slice()],
        )?;
        Ok(())
    }

    /// Forgets a link this client made, and the voucher kept for it. Only
    /// for a link the server has just cancelled, which nobody used.
    pub fn forget_invite(&self, token: &Token) -> Result<(), CoreError> {
        self.conn.execute(
            "DELETE FROM invites_made WHERE token = ?1",
            [token.0.as_slice()],
        )?;
        self.conn.execute(
            "DELETE FROM vouchers WHERE token = ?1 AND mine = 1",
            [token.0.as_slice()],
        )?;
        Ok(())
    }

    /// The stored voucher for a token. Rows from before the keys were split
    /// out hold only the secret; their keys are derived from it, and they
    /// never count as this client's own. A member's row from before join
    /// requests were signed holds no key to check them with, so it reads as
    /// no voucher.
    pub fn voucher(&self, g: &GroupId, token: &Token) -> Result<Option<StoredVoucher>, CoreError> {
        type Row = (
            Vec<u8>,
            Option<Vec<u8>>,
            bool,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        );
        let row: Option<Row> = self
            .conn
            .query_row(
                "SELECT voucher, secret, mine, request_key, seal_key FROM vouchers
                 WHERE group_id = ?1 AND token = ?2",
                params![g.0.as_slice(), token.0.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        let Some((voucher, secret, mine, request_key, seal_key)) = row else {
            return Ok(None);
        };
        let b32 = |b: Option<Vec<u8>>| b.and_then(|b| <[u8; 32]>::try_from(b).ok());
        let secret = b32(secret);
        let (request_key, seal_key) = match (b32(request_key), b32(seal_key), secret) {
            (Some(r), Some(s), _) => (Key(r), s),
            (_, _, Some(sec)) => (
                crate::keys::invite_signing_key(&sec).public(),
                crate::keys::voucher_seal_key(&sec),
            ),
            _ => return Ok(None),
        };
        Ok(Some(StoredVoucher {
            voucher,
            request_key,
            seal_key,
            secret: if mine { secret } else { None },
        }))
    }

    /// Keeps a file offer with the key of the member who sent it.
    pub fn add_file(
        &self,
        g: &GroupId,
        offer: &crate::files::FileOffer,
        sender: Option<&Key>,
        added_unix: u64,
    ) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO files (id, group_id, offer, sender_group_key, added_unix)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                offer.id.0.as_slice(),
                g.0.as_slice(),
                postcard::to_stdvec(offer)?,
                sender.map(|k| k.0.to_vec()),
                added_unix as i64
            ],
        )?;
        Ok(())
    }

    /// Files offered in a group, oldest first.
    pub fn files(&self, g: &GroupId) -> Result<Vec<crate::files::FileOffer>, CoreError> {
        Ok(self
            .files_with_senders(g)?
            .into_iter()
            .map(|(offer, _, _)| offer)
            .collect())
    }

    /// Files offered in a group, oldest first, each with its sender's key
    /// (none for files kept before senders were) and when it arrived.
    #[allow(clippy::type_complexity)]
    pub fn files_with_senders(
        &self,
        g: &GroupId,
    ) -> Result<Vec<(crate::files::FileOffer, Option<Key>, u64)>, CoreError> {
        let mut st = self.conn.prepare(
            "SELECT offer, sender_group_key, added_unix FROM files
             WHERE group_id = ?1 ORDER BY rowid",
        )?;
        let rows = st.query_map([g.0.as_slice()], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                key_col(r.get(1)?),
                r.get::<_, i64>(2)? as u64,
            ))
        })?;
        let mut out = vec![];
        for row in rows {
            let (b, sender, at) = row?;
            out.push((postcard::from_bytes(&b)?, sender, at));
        }
        Ok(out)
    }

    pub fn save_pending_join(&self, p: &PendingJoin) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO pending_joins
                 (token, server_id, link, group_key, lodged_unix, key_package_refs)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                p.token.0.as_slice(),
                p.server_id,
                p.link,
                kp_bytes(&p.key).as_slice(),
                p.lodged_unix as i64,
                postcard::to_stdvec(&p.key_package_refs)?
            ],
        )?;
        Ok(())
    }

    pub fn pending_joins(&self) -> Result<Vec<PendingJoin>, CoreError> {
        let mut st = self
            .conn
            .prepare("SELECT token, server_id, link, group_key, lodged_unix, key_package_refs FROM pending_joins")?;
        let rows = st.query_map([], |r| {
            let t: Vec<u8> = r.get(0)?;
            let k: Vec<u8> = r.get(3)?;
            let refs: Option<Vec<u8>> = r.get(5)?;
            Ok(PendingJoin {
                token: Token(t.try_into().unwrap_or([0; 16])),
                server_id: r.get(1)?,
                link: r.get(2)?,
                key: kp_col(&k)?,
                lodged_unix: r.get::<_, i64>(4)? as u64,
                key_package_refs: refs
                    .and_then(|b| postcard::from_bytes(&b).ok())
                    .unwrap_or_default(),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn delete_pending_join(&self, token: &Token) -> Result<(), CoreError> {
        self.conn.execute(
            "DELETE FROM pending_joins WHERE token = ?1",
            [token.0.as_slice()],
        )?;
        Ok(())
    }

    /// Remembers that the person behind `key` holds a link this client made,
    /// so their identity earns a verified mark once they introduce it.
    pub fn expect_joiner(&self, g: &GroupId, key: &Key) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO expected_joiners (group_id, group_key) VALUES (?1, ?2)",
            params![g.0.as_slice(), key.0.as_slice()],
        )?;
        Ok(())
    }

    /// Remembers an invite proof this member owes a group, until it is sent.
    pub fn owe_proof(&self, g: &GroupId, token: &Token, proof: &[u8; 32]) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO owed_proofs (group_id, token, proof) VALUES (?1, ?2, ?3)",
            params![g.0.as_slice(), token.0.as_slice(), proof.as_slice()],
        )?;
        Ok(())
    }

    /// Invite proofs this member still owes a group.
    pub fn owed_proofs(&self, g: &GroupId) -> Result<Vec<(Token, [u8; 32])>, CoreError> {
        let mut st = self
            .conn
            .prepare("SELECT token, proof FROM owed_proofs WHERE group_id = ?1")?;
        let rows = st.query_map([g.0.as_slice()], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (t, p) = row?;
            if let (Ok(t), Ok(p)) = (t.try_into(), p.try_into()) {
                out.push((Token(t), p));
            }
        }
        Ok(out)
    }

    /// Groups this member owes an invite proof.
    pub fn groups_owing_proofs(&self) -> Result<Vec<GroupId>, CoreError> {
        let mut st = self
            .conn
            .prepare("SELECT DISTINCT group_id FROM owed_proofs")?;
        let rows = st.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for g in rows {
            if let Ok(g) = g?.try_into() {
                out.push(GroupId(g));
            }
        }
        Ok(out)
    }

    /// Marks an owed invite proof as sent.
    pub fn paid_proof(&self, g: &GroupId, token: &Token) -> Result<(), CoreError> {
        self.conn.execute(
            "DELETE FROM owed_proofs WHERE group_id = ?1 AND token = ?2",
            params![g.0.as_slice(), token.0.as_slice()],
        )?;
        Ok(())
    }

    /// Drops every proof owed to a group this member is no longer in.
    pub fn forget_proofs(&self, g: &GroupId) -> Result<(), CoreError> {
        self.conn.execute(
            "DELETE FROM owed_proofs WHERE group_id = ?1",
            [g.0.as_slice()],
        )?;
        Ok(())
    }

    /// Records that this person is no longer in a room, with its name,
    /// kind and seen mark, before its state is deleted. A room whose
    /// ending stops part way is finished from this row the next time the
    /// profile opens.
    pub fn begin_end(&self, g: &GroupId, why: i64, ended_unix: u64) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO ended_rooms (group_id, name, is_dm, why, ended_unix, seen_seq, server_id)
             SELECT id, name, is_dm, ?2, ?3, seen_seq, server_id FROM groups WHERE id = ?1",
            params![g.0.as_slice(), why, ended_unix as i64],
        )?;
        Ok(())
    }

    /// Makes the next [`Store::checkpoint`] find the log busy, as another
    /// reader holding it would.
    #[cfg(feature = "test-hooks")]
    pub fn test_busy_next_checkpoint(&self) {
        self.busy_next_checkpoint.set(true);
    }

    /// Whether a room has an `ended_rooms` row.
    pub fn is_ended(&self, g: &GroupId) -> Result<bool, CoreError> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM ended_rooms WHERE group_id = ?1)",
            [g.0.as_slice()],
            |r| r.get(0),
        )?)
    }

    /// Deletes a room's state in one transaction. First, while the room
    /// still has lines, it keeps in `ended_names` the names of the people
    /// whose lines are still here and of `me` (this member's key in the
    /// room). Then it deletes the
    /// room's rows in every [`ROOM_STATE_TABLES`] table, everything OpenMLS
    /// still holds for the group in [`OPENMLS_GROUP_TABLES`], and its
    /// `groups` row with this member's private key for it. History stays.
    pub fn end_room(&self, g: &GroupId, me: &Key) -> Result<(), CoreError> {
        let mls = openmls_key(g)?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT OR REPLACE INTO ended_names (group_id, group_key, name)
             SELECT group_id, group_key, COALESCE(local_name, display_name) FROM members
             WHERE group_id = ?1 AND COALESCE(local_name, display_name) <> ''
               AND EXISTS(SELECT 1 FROM messages WHERE group_id = ?1)
               AND (group_key = ?2
                    OR group_key IN (SELECT sender_group_key FROM messages WHERE group_id = ?1)
                    OR group_key IN (SELECT sender_group_key FROM extensions WHERE group_id = ?1))",
            params![g.0.as_slice(), me.0.as_slice()],
        )?;
        delete_state(&tx, g, &mls)?;
        tx.commit()?;
        Ok(())
    }

    /// The name kept for someone whose lines are still here after the room
    /// ended.
    pub fn ended_name(&self, g: &GroupId, key: &Key) -> Result<Option<String>, CoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT name FROM ended_names WHERE group_id = ?1 AND group_key = ?2",
                params![g.0.as_slice(), key.0.as_slice()],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Whether OpenMLS keeps any row for a group in [`OPENMLS_GROUP_TABLES`].
    pub fn has_openmls_rows(&self, g: &GroupId) -> Result<bool, CoreError> {
        let mls = openmls_key(g)?;
        for table in OPENMLS_GROUP_TABLES {
            let has: bool = self.conn.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE group_id = ?1)"),
                [mls.as_slice()],
                |r| r.get(0),
            )?;
            if has {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Deletes everything left of an ended room in one transaction: first
    /// whatever its ending had not deleted yet (as [`Store::end_room`]
    /// does), then its history and its `ended_rooms` row. An ended room
    /// never loses its marker while its keys are still here.
    pub fn delete_room(&self, g: &GroupId) -> Result<(), CoreError> {
        let mls = openmls_key(g)?;
        let tx = self.conn.unchecked_transaction()?;
        delete_state(&tx, g, &mls)?;
        for table in ROOM_HISTORY_TABLES {
            tx.execute(
                &format!("DELETE FROM {table} WHERE group_id = ?1"),
                [g.0.as_slice()],
            )?;
        }
        tx.execute(
            "DELETE FROM ended_rooms WHERE group_id = ?1",
            [g.0.as_slice()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Deletes a server and everything this profile keeps for it, in one
    /// transaction: each of its rooms as [`Store::delete_room`] deletes
    /// one (keys, group state, history, files list, proofs, closing state),
    /// rooms there that ended and wait to be read, with their history, the
    /// joins waiting there, the links made there, and the server's row with
    /// its pinned certificate and account key. Returns the rooms deleted.
    /// Nothing on any other server changes. An ended room recorded without
    /// its server stays until it is read or expires.
    pub fn forget_server(&self, server_id: i64) -> Result<Vec<GroupId>, CoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let rooms: Vec<GroupId> = {
            let mut st = tx.prepare(
                "SELECT id FROM groups WHERE server_id = ?1
                 UNION SELECT group_id FROM ended_rooms WHERE server_id = ?1",
            )?;
            let rows = st.query_map([server_id], |r| r.get::<_, Vec<u8>>(0))?;
            let mut out = Vec::new();
            for id in rows {
                if let Ok(id) = <[u8; 16]>::try_from(id?) {
                    out.push(GroupId(id));
                }
            }
            out
        };
        for g in &rooms {
            delete_state(&tx, g, &openmls_key(g)?)?;
            for table in ROOM_HISTORY_TABLES {
                tx.execute(
                    &format!("DELETE FROM {table} WHERE group_id = ?1"),
                    [g.0.as_slice()],
                )?;
            }
            tx.execute(
                "DELETE FROM ended_rooms WHERE group_id = ?1",
                [g.0.as_slice()],
            )?;
        }
        for table in ["pending_joins", "invites_made"] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE server_id = ?1"),
                [server_id],
            )?;
        }
        tx.execute("DELETE FROM servers WHERE id = ?1", [server_id])?;
        tx.commit()?;
        Ok(rooms)
    }

    /// Deletes a live room's history on this computer in one transaction,
    /// with its files list and the keys to those files (the lines that
    /// offered them go too) and its topic. [`Store::checkpoint`] then
    /// clears the old copies out of the log.
    pub fn clear_history(&self, g: &GroupId) -> Result<(), CoreError> {
        let tx = self.conn.unchecked_transaction()?;
        for table in ROOM_HISTORY_TABLES.iter().chain(&["files", "topics"]) {
            tx.execute(
                &format!("DELETE FROM {table} WHERE group_id = ?1"),
                [g.0.as_slice()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Copies the write-ahead log into the database and empties it, so the
    /// old copies of deleted rows it held are gone from the disk too. Fails
    /// when another connection keeps the log in use through every try.
    pub fn checkpoint(&self) -> Result<(), CoreError> {
        #[cfg(feature = "test-hooks")]
        let busy = self.busy_next_checkpoint.take();
        #[cfg(not(feature = "test-hooks"))]
        let busy = false;
        for _ in 0..CHECKPOINT_TRIES {
            if busy {
                break;
            }
            let busy: i64 = self
                .conn
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
            if busy == 0 {
                return Ok(());
            }
        }
        Err(CoreError::Storage(
            "deleted data is still in the profile's log file, because the profile was busy".into(),
        ))
    }

    /// Rooms this person is no longer in whose history is still here,
    /// oldest ending first.
    pub fn ended_rooms(&self) -> Result<Vec<EndedRow>, CoreError> {
        let mut st = self.conn.prepare(
            "SELECT group_id, name, is_dm, why, ended_unix FROM ended_rooms
             ORDER BY ended_unix, group_id",
        )?;
        let rows = st.query_map([], |r| {
            let id: Vec<u8> = r.get(0)?;
            Ok(EndedRow {
                id: GroupId(id.try_into().unwrap_or([0; 16])),
                name: r.get(1)?,
                is_dm: r.get(2)?,
                why: r.get(3)?,
                ended_unix: r.get::<_, i64>(4)? as u64,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Names of the tables still holding rows for a room: `groups` first,
    /// then [`ROOM_STATE_TABLES`], [`ROOM_HISTORY_TABLES`] and `ended_rooms`.
    pub fn traces(&self, g: &GroupId) -> Result<Vec<&'static str>, CoreError> {
        let mut out = Vec::new();
        let tables = std::iter::once(("groups", "id"))
            .chain(ROOM_STATE_TABLES.iter().map(|t| (*t, "group_id")))
            .chain(ROOM_HISTORY_TABLES.iter().map(|t| (*t, "group_id")))
            .chain(std::iter::once(("ended_rooms", "group_id")));
        for (table, column) in tables {
            let has: bool = self.conn.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {column} = ?1)"),
                [g.0.as_slice()],
                |r| r.get(0),
            )?;
            if has {
                out.push(table);
            }
        }
        Ok(out)
    }

    /// Keeps an admin's vote on a request to close. A newer vote from the
    /// same voter replaces the older and keeps the time of the first.
    pub fn add_close_vote(
        &self,
        g: &GroupId,
        close_id: &[u8; 16],
        voter: &Key,
        yes: bool,
        at_unix: u64,
    ) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT INTO close_votes (group_id, close_id, voter, yes, at_unix)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(group_id, close_id, voter) DO UPDATE SET yes = excluded.yes",
            params![
                g.0.as_slice(),
                close_id.as_slice(),
                voter.0.as_slice(),
                yes,
                at_unix as i64
            ],
        )?;
        Ok(())
    }

    /// A room's votes on closing it, in the order they first arrived.
    pub fn close_votes(&self, g: &GroupId) -> Result<Vec<crate::close::Vote>, CoreError> {
        let mut st = self.conn.prepare(
            "SELECT close_id, voter, yes, at_unix FROM close_votes
             WHERE group_id = ?1 ORDER BY rowid",
        )?;
        let rows = st.query_map([g.0.as_slice()], |r| {
            let id: Vec<u8> = r.get(0)?;
            let voter: Vec<u8> = r.get(1)?;
            Ok((id, voter, r.get::<_, bool>(2)?, r.get::<_, i64>(3)? as u64))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, voter, yes, at_unix) = row?;
            if let (Ok(close_id), Some(voter)) = (id.try_into(), key_col(Some(voter))) {
                out.push(crate::close::Vote {
                    close_id,
                    voter,
                    yes,
                    at_unix,
                });
            }
        }
        Ok(out)
    }

    /// Records a `Closed` message this app knows of. Stored in
    /// `groups.closing` as the 16-byte request ID, the 32-byte key, then
    /// one byte of flags: 1 for posted, 2 for gave up.
    pub fn set_closing(&self, g: &GroupId, c: &Closing) -> Result<(), CoreError> {
        let mut blob = c.close_id.to_vec();
        blob.extend_from_slice(&c.by.0);
        blob.push(u8::from(c.posted) | (u8::from(c.gave_up) << 1));
        self.conn.execute(
            "UPDATE groups SET closing = ?1 WHERE id = ?2",
            params![blob, g.0.as_slice()],
        )?;
        Ok(())
    }

    /// Records that a request to close was kept: it never closes the room.
    pub fn add_kept_close(&self, g: &GroupId, close_id: &[u8; 16]) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO close_kept (group_id, close_id) VALUES (?1, ?2)",
            params![g.0.as_slice(), close_id.as_slice()],
        )?;
        Ok(())
    }

    /// The requests to close a room that were kept.
    pub fn kept_closes(&self, g: &GroupId) -> Result<Vec<[u8; 16]>, CoreError> {
        let mut st = self
            .conn
            .prepare("SELECT close_id FROM close_kept WHERE group_id = ?1")?;
        let rows = st.query_map([g.0.as_slice()], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            if let Ok(id) = <[u8; 16]>::try_from(row?) {
                out.push(id);
            }
        }
        Ok(out)
    }

    /// Forgets the `Closed` message this app knew of in a room.
    pub fn clear_closing(&self, g: &GroupId) -> Result<(), CoreError> {
        self.conn.execute(
            "UPDATE groups SET closing = NULL WHERE id = ?1",
            [g.0.as_slice()],
        )?;
        Ok(())
    }

    /// The `Closed` message this app knows of in a room, if any.
    pub fn closing(&self, g: &GroupId) -> Result<Option<Closing>, CoreError> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT closing FROM groups WHERE id = ?1",
                [g.0.as_slice()],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        Ok(blob.and_then(|b| {
            Some(Closing {
                close_id: b.get(..16)?.try_into().ok()?,
                by: key_col(Some(b.get(16..48)?.to_vec()))?,
                posted: b.get(48).is_some_and(|f| f & 1 != 0),
                gave_up: b.get(48).is_some_and(|f| f & 2 != 0),
            })
        }))
    }

    /// Records the key that joined with a link this client made. The first
    /// key recorded for `token` stays.
    pub fn set_voucher_joiner(
        &self,
        g: &GroupId,
        token: &Token,
        key: &Key,
    ) -> Result<(), CoreError> {
        self.conn.execute(
            "UPDATE vouchers SET joiner = ?3
             WHERE group_id = ?1 AND token = ?2 AND mine = 1 AND joiner IS NULL",
            params![g.0.as_slice(), token.0.as_slice(), key.0.as_slice()],
        )?;
        Ok(())
    }

    /// The key that joined with a link this client made, once an add for
    /// it was seen.
    pub fn voucher_joiner(&self, g: &GroupId, token: &Token) -> Result<Option<Key>, CoreError> {
        let k: Option<Option<Vec<u8>>> = self
            .conn
            .query_row(
                "SELECT joiner FROM vouchers WHERE group_id = ?1 AND token = ?2 AND mine = 1",
                params![g.0.as_slice(), token.0.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(key_col(k.flatten()))
    }

    /// Links this client made in a group that nobody has joined with yet.
    pub fn unjoined_vouchers(&self, g: &GroupId) -> Result<Vec<Token>, CoreError> {
        let mut st = self.conn.prepare(
            "SELECT token FROM vouchers
             WHERE group_id = ?1 AND mine = 1 AND secret IS NOT NULL AND joiner IS NULL",
        )?;
        let rows = st.query_map([g.0.as_slice()], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for t in rows {
            if let Ok(t) = t?.try_into() {
                out.push(Token(t));
            }
        }
        Ok(out)
    }

    /// Forgets the secret of a link this client made once its joiner has
    /// proved they hold it, so no later proof for it counts.
    pub fn drop_voucher_secret(&self, g: &GroupId, token: &Token) -> Result<(), CoreError> {
        self.conn.execute(
            "UPDATE vouchers SET secret = NULL WHERE group_id = ?1 AND token = ?2",
            params![g.0.as_slice(), token.0.as_slice()],
        )?;
        Ok(())
    }

    /// Remembers that this member owes a room its profile, after someone
    /// joined, until it is posted.
    pub fn owe_repost(&self, g: &GroupId) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO owed_reposts (group_id) VALUES (?1)",
            [g.0.as_slice()],
        )?;
        Ok(())
    }

    /// Marks a room's owed profile as posted.
    pub fn paid_repost(&self, g: &GroupId) -> Result<(), CoreError> {
        self.conn.execute(
            "DELETE FROM owed_reposts WHERE group_id = ?1",
            [g.0.as_slice()],
        )?;
        Ok(())
    }

    /// Rooms this member owes its profile.
    pub fn owed_reposts(&self) -> Result<Vec<GroupId>, CoreError> {
        let mut st = self.conn.prepare("SELECT group_id FROM owed_reposts")?;
        let rows = st.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for g in rows {
            if let Ok(g) = g?.try_into() {
                out.push(GroupId(g));
            }
        }
        Ok(out)
    }

    /// Keeps this member's profile and app version out of a room until its
    /// join is confirmed or the person marks someone there verified.
    pub fn hold_profile(&self, g: &GroupId) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO held_profiles (group_id) VALUES (?1)",
            [g.0.as_slice()],
        )?;
        Ok(())
    }

    /// Lets this member's profile go out in a room.
    pub fn release_profile(&self, g: &GroupId) -> Result<(), CoreError> {
        self.conn.execute(
            "DELETE FROM held_profiles WHERE group_id = ?1",
            [g.0.as_slice()],
        )?;
        Ok(())
    }

    /// Whether this member's profile is kept out of a room.
    pub fn profile_held(&self, g: &GroupId) -> Result<bool, CoreError> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM held_profiles WHERE group_id = ?1)",
            [g.0.as_slice()],
            |r| r.get(0),
        )?)
    }

    /// Remembers whose confirmation a join waits for: the inviter's key in
    /// the group and the identity that signed the invite.
    pub fn await_inviter(&self, g: &GroupId, key: &Key, identity: &Key) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO awaited_inviters (group_id, group_key, identity)
             VALUES (?1, ?2, ?3)",
            params![g.0.as_slice(), key.0.as_slice(), identity.0.as_slice()],
        )?;
        Ok(())
    }

    /// The inviter's key in the group and their identity, while the join
    /// waits for them to confirm it.
    pub fn awaited_inviter(&self, g: &GroupId) -> Result<Option<(Key, Key)>, CoreError> {
        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT group_key, identity FROM awaited_inviters WHERE group_id = ?1",
                [g.0.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.and_then(|(k, i)| Some((key_col(Some(k))?, key_col(Some(i))?))))
    }

    /// Stops waiting for an inviter's confirmation in a group.
    pub fn clear_awaited_inviter(&self, g: &GroupId) -> Result<(), CoreError> {
        self.conn.execute(
            "DELETE FROM awaited_inviters WHERE group_id = ?1",
            [g.0.as_slice()],
        )?;
        Ok(())
    }

    /// A name this person goes by in any room: the one set on this device,
    /// else the one they gave.
    pub fn name_of_identity(&self, identity: &Key) -> Result<Option<String>, CoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT COALESCE(NULLIF(local_name, ''), display_name) FROM members
                 WHERE identity = ?1 AND (COALESCE(local_name, '') != '' OR display_name != '')
                 LIMIT 1",
                [identity.0.as_slice()],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// True once, the first time the expected joiner introduces themselves.
    pub fn take_expected_joiner(&self, g: &GroupId, key: &Key) -> Result<bool, CoreError> {
        let n = self.conn.execute(
            "DELETE FROM expected_joiners WHERE group_id = ?1 AND group_key = ?2",
            params![g.0.as_slice(), key.0.as_slice()],
        )?;
        Ok(n > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;
    use crate::suite::{group_create_config, SUITE};
    use openmls::prelude::MlsGroup;
    use openmls_traits::OpenMlsProvider;
    use sha2::{Digest, Sha256};

    fn snapshot(dir: &Path) -> Vec<(String, [u8; 32])> {
        let mut v: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .map(|p| {
                (
                    p.file_name().unwrap().to_string_lossy().to_string(),
                    Sha256::digest(std::fs::read(&p).unwrap()).into(),
                )
            })
            .collect();
        v.sort();
        v
    }

    #[test]
    fn create_then_open() {
        let d = tempfile::tempdir().unwrap();
        let id = KeyPair::generate();
        {
            let (s, _p) = Store::create(d.path(), "pass phrase").unwrap();
            s.set_profile(&Profile {
                identity: id.clone(),
                display_name: "Ada".into(),
            })
            .unwrap();
        }
        let (s, _p) = Store::open(d.path(), "pass phrase").unwrap();
        let prof = s.profile().unwrap().unwrap();
        assert_eq!(prof.display_name, "Ada");
        assert_eq!(prof.identity.public(), id.public());
    }

    #[test]
    fn create_twice_refused() {
        let d = tempfile::tempdir().unwrap();
        drop(Store::create(d.path(), "x").unwrap());
        assert!(matches!(
            Store::create(d.path(), "x"),
            Err(CoreError::ProfileExists)
        ));
    }

    #[test]
    fn wrong_passphrase_is_error_and_file_unchanged() {
        let d = tempfile::tempdir().unwrap();
        {
            let (s, _p) = Store::create(d.path(), "right").unwrap();
            s.set_profile(&Profile {
                identity: KeyPair::generate(),
                display_name: "B".into(),
            })
            .unwrap();
        }
        let before = snapshot(d.path());
        assert!(matches!(
            Store::open(d.path(), "wrong"),
            Err(CoreError::WrongPassphrase)
        ));
        assert_eq!(snapshot(d.path()), before);
        assert!(Store::open(d.path(), "right").is_ok());
    }

    #[test]
    fn file_has_no_sqlite_header() {
        let d = tempfile::tempdir().unwrap();
        {
            let (s, _p) = Store::create(d.path(), "k").unwrap();
            s.set_profile(&Profile {
                identity: KeyPair::generate(),
                display_name: "Secret Name".into(),
            })
            .unwrap();
        }
        let bytes = std::fs::read(d.path().join(DB_FILE)).unwrap();
        assert!(!bytes.starts_with(b"SQLite format 3"));
        assert!(!bytes.windows(11).any(|w| w == b"Secret Name"));
    }

    #[test]
    fn openmls_group_survives_reopen() {
        let d = tempfile::tempdir().unwrap();
        let me = KeyPair::generate();
        let gid = {
            let (_s, p) = Store::create(d.path(), "k").unwrap();
            let g = MlsGroup::new(
                &p,
                &me,
                &group_create_config(SUITE, &[me.public()]),
                me.credential(),
            )
            .unwrap();
            g.group_id().clone()
        };
        let (_s, p) = Store::open(d.path(), "k").unwrap();
        let g = MlsGroup::load(p.storage(), &gid)
            .unwrap()
            .expect("group reloads");
        assert_eq!(g.ciphersuite(), SUITE);
    }

    #[test]
    fn room_from_before_padding_pads_after_reopen() {
        use crate::suite::tests::{create_config_0_5_1, wire_len};
        use crate::suite::{group_join_config, load_group, PADDING_BLOCK};
        let d = tempfile::tempdir().unwrap();
        let me = KeyPair::generate();
        let gid = {
            let (_s, p) = Store::create(d.path(), "k").unwrap();
            let g = MlsGroup::new(
                &p,
                &me,
                &create_config_0_5_1(SUITE, &[me.public()]),
                me.credential(),
            )
            .unwrap();
            g.group_id().clone()
        };
        {
            let (_s, p) = Store::open(d.path(), "k").unwrap();
            let mut g = load_group(p.storage(), &gid)
                .unwrap()
                .expect("group reloads");
            assert_eq!(g.configuration(), &group_join_config());
            assert_eq!(wire_len(&p, &me, &mut g, 1), wire_len(&p, &me, &mut g, 160));
        }
        let (_s, p) = Store::open(d.path(), "k").unwrap();
        let g = MlsGroup::load(p.storage(), &gid).unwrap().unwrap();
        assert_eq!(g.configuration().padding_size(), PADDING_BLOCK);
    }

    /// Writes a profile keyed with `params`, its salt file in the stored
    /// form: `sckdf` and version byte 1, memory in KiB, passes and lanes as
    /// big-endian u32, then the salt.
    fn profile_with_params(dir: &Path, pass: &str, m: u32, t: u32, p: u32) {
        let salt = [7u8; 16];
        let mut file = b"sckdf\x01".to_vec();
        for v in [m, t, p] {
            file.extend_from_slice(&v.to_be_bytes());
        }
        file.extend_from_slice(&salt);
        std::fs::write(dir.join(SALT_FILE), file).unwrap();
        let params = Params::new(m, t, p, Some(32)).unwrap();
        let mut key = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(pass.as_bytes(), &salt, &mut key)
            .unwrap();
        let conn = open_keyed(&dir.join(DB_FILE), &key).unwrap();
        conn.execute_batch(SCHEMA).unwrap();
    }

    #[test]
    fn profile_with_other_stored_kdf_params_opens() {
        let d = tempfile::tempdir().unwrap();
        profile_with_params(d.path(), "pass phrase", 8 * 1024, 3, 1);
        assert!(Store::open(d.path(), "pass phrase").is_ok());
        assert!(matches!(
            Store::open(d.path(), "wrong"),
            Err(CoreError::WrongPassphrase)
        ));
    }

    /// Profiles made by 0.4.0 and 0.5.0 store 19 MiB, 2 passes and 1 lane,
    /// and keep opening after new profiles get stronger settings.
    #[test]
    fn profile_from_0_5_0_settings_opens() {
        let d = tempfile::tempdir().unwrap();
        profile_with_params(d.path(), "pass phrase", 19 * 1024, 2, 1);
        assert!(Store::open(d.path(), "pass phrase").is_ok());
        assert!(matches!(
            Store::open(d.path(), "wrong"),
            Err(CoreError::WrongPassphrase)
        ));
    }

    /// A bare 16-byte salt comes from a profile made before the settings
    /// were stored. Those profiles used 19 MiB, 2 passes and 1 lane, and
    /// still open with exactly those, whatever new profiles get.
    #[test]
    fn profile_with_bare_salt_opens_with_the_first_settings() {
        let d = tempfile::tempdir().unwrap();
        let salt = [5u8; 16];
        std::fs::write(d.path().join(SALT_FILE), salt).unwrap();
        let params = Params::new(19 * 1024, 2, 1, Some(32)).unwrap();
        let mut key = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(b"k", &salt, &mut key)
            .unwrap();
        open_keyed(&d.path().join(DB_FILE), &key)
            .unwrap()
            .execute_batch(SCHEMA)
            .unwrap();
        assert!(Store::open(d.path(), "k").is_ok());
    }

    #[test]
    fn salt_file_asking_too_much_is_damaged() {
        let file = |m: u32, t: u32, p: u32| {
            let mut f = KDF_MAGIC.to_vec();
            for v in [m, t, p] {
                f.extend_from_slice(&v.to_be_bytes());
            }
            f.extend_from_slice(&[1; SALT_LEN]);
            f
        };
        // 256 MiB at most: a 512 MB Raspberry Pi Zero 2 W must survive a
        // changed salt file.
        assert_eq!(MAX_MEM_KIB, 256 * 1024);
        assert!(Kdf::decode(&file(256 * 1024, MAX_PASSES, MAX_LANES)).is_ok());
        assert!(Kdf::decode(&file(64, 1, 8)).is_ok());
        for (m, t, p) in [
            (256 * 1024 + 1, 2, 1),
            (1 << 20, 2, 1),
            (19 * 1024, MAX_PASSES + 1, 1),
            (19 * 1024, u32::MAX, 1),
            (19 * 1024, 2, MAX_LANES + 1),
            (63, 2, 8),
            (19 * 1024, 0, 1),
            (19 * 1024, 2, 0),
            // 64 GiB of memory, and a million passes.
            (64 * 1024 * 1024, 2, 1),
            (u32::MAX, 2, 1),
            (19 * 1024, 1_000_000, 1),
            (19 * 1024, 2, u32::MAX),
        ] {
            let err = Kdf::decode(&file(m, t, p)).unwrap_err();
            assert_eq!(
                err.to_string(),
                "local storage: the profile's salt file is damaged",
                "m={m} t={t} p={p}"
            );
        }
    }

    /// A salt file that is cut short, too long, empty or of an unknown
    /// format version is damaged, never read with guessed settings.
    #[test]
    fn salt_file_cut_or_of_unknown_format_is_damaged() {
        let mut good = KDF_MAGIC.to_vec();
        for v in [19 * 1024u32, 2, 1] {
            good.extend_from_slice(&v.to_be_bytes());
        }
        good.extend_from_slice(&[1; SALT_LEN]);
        assert!(Kdf::decode(&good).is_ok());
        let mut v2 = good.clone();
        v2[5] = 2;
        let mut long = good.clone();
        long.push(0);
        let mut other_magic = good.clone();
        other_magic[0] = b'S';
        for bad in [
            Vec::new(),
            vec![1; SALT_LEN - 1],
            vec![1; SALT_LEN + 1],
            good[..good.len() - 1].to_vec(),
            KDF_MAGIC.to_vec(),
            long,
            v2,
            other_magic,
        ] {
            let err = Kdf::decode(&bad).unwrap_err();
            assert_eq!(
                err.to_string(),
                "local storage: the profile's salt file is damaged",
                "{bad:?}"
            );
        }
    }

    /// New profiles get RFC 9106's second recommended Argon2id settings:
    /// 64 MiB, 3 passes, 4 lanes. The salt file records them in format 1,
    /// which 0.4.0 and 0.5.0 also read.
    #[test]
    fn new_profile_stores_its_kdf_params() {
        let d = tempfile::tempdir().unwrap();
        drop(Store::create(d.path(), "k").unwrap());
        let file = std::fs::read(d.path().join(SALT_FILE)).unwrap();
        assert!(file.starts_with(b"sckdf\x01"), "{file:?}");
        assert_eq!(&file[6..10], &(64u32 * 1024).to_be_bytes());
        assert_eq!(&file[10..14], &3u32.to_be_bytes());
        assert_eq!(&file[14..18], &4u32.to_be_bytes());
        assert_eq!(file.len(), 34);
        // Within what any reader accepts, so 0.5.0 opens it too.
        let kdf = Kdf::decode(&file).unwrap();
        assert_eq!((kdf.mem_kib, kdf.passes, kdf.lanes), (64 * 1024, 3, 4));
        let key = derive_key("k", &kdf).unwrap();
        assert!(open_keyed(&d.path().join(DB_FILE), &key).is_ok());
    }

    /// A profile an earlier release made with an empty passphrase still
    /// opens with it.
    #[test]
    fn profile_with_an_empty_passphrase_still_opens() {
        let d = tempfile::tempdir().unwrap();
        profile_with_params(d.path(), "", 19 * 1024, 2, 1);
        assert!(Store::open(d.path(), "").is_ok());
        assert!(matches!(
            Store::open(d.path(), "x"),
            Err(CoreError::WrongPassphrase)
        ));
    }

    /// A salt file in Socketchat's format, with settings cheap to test.
    fn valid_salt_file() -> Vec<u8> {
        let mut salt = KDF_MAGIC.to_vec();
        for v in [8 * 1024u32, 1, 1] {
            salt.extend_from_slice(&v.to_be_bytes());
        }
        salt.extend_from_slice(&[3; SALT_LEN]);
        salt
    }

    /// The names in `dir`, sorted.
    fn names_in(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    /// An empty database beside a salt file is what a create that stopped
    /// part way leaves. No passphrase opens it. Making a profile there
    /// moves both aside, never deletes them, says so, and starts over.
    #[test]
    fn an_unfinished_profile_is_moved_aside_and_made_again() {
        let d = tempfile::tempdir().unwrap();
        let salt = valid_salt_file();
        std::fs::write(d.path().join(SALT_FILE), &salt).unwrap();
        std::fs::write(d.path().join(DB_FILE), b"").unwrap();
        for pass in ["anything", "k", ""] {
            assert!(
                matches!(Store::open(d.path(), pass), Err(CoreError::NoProfile)),
                "pass={pass:?}"
            );
        }
        assert_eq!(std::fs::metadata(d.path().join(DB_FILE)).unwrap().len(), 0);
        assert!(!has_profile(d.path()));

        let (s, _p) = Store::create(d.path(), "k").unwrap();
        let moved: Vec<String> = names_in(d.path())
            .into_iter()
            .filter(|n| n.contains(".unfinished-"))
            .collect();
        assert_eq!(moved.len(), 2, "{:?}", names_in(d.path()));
        let salt_aside = moved.iter().find(|n| n.starts_with("salt.")).unwrap();
        assert_eq!(std::fs::read(d.path().join(salt_aside)).unwrap(), salt);
        assert!(moved.iter().any(|n| n.starts_with("socketchat.db.")));
        assert!(
            s.notes()
                .iter()
                .any(|l| l.contains("moved") && l.contains(salt_aside.as_str())),
            "{:?}",
            s.notes()
        );
        drop(s);
        assert!(has_profile(d.path()));
        assert!(Store::open(d.path(), "k").is_ok());
        assert!(matches!(
            Store::open(d.path(), "anything"),
            Err(CoreError::WrongPassphrase)
        ));
    }

    /// A create stopped while it derives the key, or while it moves an
    /// unfinished profile aside, leaves a folder the next create finishes.
    #[test]
    fn a_create_stopped_at_any_point_is_finished_by_the_next() {
        for at in ["salt", "key", "aside"] {
            let d = tempfile::tempdir().unwrap();
            if at == "aside" {
                std::fs::write(d.path().join(SALT_FILE), valid_salt_file()).unwrap();
                std::fs::write(d.path().join(DB_FILE), b"").unwrap();
            }
            CRASH_AT.set(at);
            let stopped = Store::create(d.path(), "k").err().expect("stopped");
            assert_eq!(stopped.to_string(), format!("stopped at {at}"));
            assert!(!has_profile(d.path()), "{at}");
            if at == "salt" {
                // Written in full under another name, never half under
                // its own.
                assert!(
                    !d.path().join(SALT_FILE).exists(),
                    "{:?}",
                    names_in(d.path())
                );
                let new = std::fs::read(d.path().join(format!("{SALT_FILE}.new"))).unwrap();
                assert!(Kdf::decode(&new).is_ok());
            }
            let (s, _p) = Store::create(d.path(), "k")
                .unwrap_or_else(|e| panic!("{at}: {e} in {:?}", names_in(d.path())));
            drop(s);
            assert!(Store::open(d.path(), "k").is_ok(), "{at}");
        }
    }

    /// A salt file with no database may wait for its database (a restore,
    /// a sync, a database moved aside). Making a profile there is refused,
    /// names the salt file and leaves it as it is.
    #[test]
    fn a_salt_file_without_its_database_is_kept() {
        let d = tempfile::tempdir().unwrap();
        let salt = valid_salt_file();
        std::fs::write(d.path().join(SALT_FILE), &salt).unwrap();
        assert!(matches!(
            Store::open(d.path(), "k"),
            Err(CoreError::NoProfile)
        ));
        let err = Store::create(d.path(), "k").err().expect("refused");
        let said = err.to_string();
        assert!(said.contains("without its database"), "{said}");
        assert!(
            said.contains(&d.path().join(SALT_FILE).display().to_string()),
            "{said}"
        );
        assert_eq!(std::fs::read(d.path().join(SALT_FILE)).unwrap(), salt);
        assert!(!d.path().join(DB_FILE).exists());
    }

    /// A file named `salt` that is not Socketchat's, beside an empty
    /// database, belongs to someone else: both stay as they are.
    #[test]
    fn a_file_named_salt_that_is_not_ours_is_left_alone() {
        let d = tempfile::tempdir().unwrap();
        let other = b"not a socketchat salt file\n".to_vec();
        std::fs::write(d.path().join(SALT_FILE), &other).unwrap();
        std::fs::write(d.path().join(DB_FILE), b"").unwrap();
        let err = Store::create(d.path(), "k").err().expect("refused");
        assert!(err.to_string().contains("salt"), "{err}");
        assert_eq!(std::fs::read(d.path().join(SALT_FILE)).unwrap(), other);
        assert_eq!(std::fs::metadata(d.path().join(DB_FILE)).unwrap().len(), 0);
        assert_eq!(names_in(d.path()), vec!["lock", "salt", "socketchat.db"]);
    }

    /// A database whose salt file is gone says so, since nothing opens it
    /// without the salt.
    #[test]
    fn a_database_without_its_salt_file_says_so() {
        let d = tempfile::tempdir().unwrap();
        drop(Store::create(d.path(), "k").unwrap());
        std::fs::rename(d.path().join(SALT_FILE), d.path().join("kept")).unwrap();
        let err = Store::open(d.path(), "k").err().expect("refused");
        let said = err.to_string();
        assert!(said.contains("salt file"), "{said}");
        assert!(said.contains("missing"), "{said}");
        assert!(!said.contains("socketchat join"), "{said}");
    }

    /// The salt file is read only as a real file, and only as far as the
    /// longest salt file can go.
    #[cfg(unix)]
    #[test]
    fn salt_file_is_never_read_through_a_link() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("p");
        drop(Store::create(&dir, "k").unwrap());
        let moved = d.path().join("salt-elsewhere");
        std::fs::rename(dir.join(SALT_FILE), &moved).unwrap();
        std::os::unix::fs::symlink(&moved, dir.join(SALT_FILE)).unwrap();
        let err = Store::open(&dir, "k").err().expect("refused");
        assert_eq!(
            err.to_string(),
            "local storage: the profile's salt file is a link to another place"
        );
    }

    #[test]
    fn a_long_salt_file_is_damaged() {
        let d = tempfile::tempdir().unwrap();
        drop(Store::create(d.path(), "k").unwrap());
        let mut file = std::fs::read(d.path().join(SALT_FILE)).unwrap();
        file.resize(1 << 20, 0);
        std::fs::write(d.path().join(SALT_FILE), file).unwrap();
        let err = Store::open(d.path(), "k").err().expect("refused");
        assert_eq!(
            err.to_string(),
            "local storage: the profile's salt file is damaged"
        );
    }

    /// An empty passphrase never makes a profile, whatever front end
    /// passes it.
    #[test]
    fn create_refuses_an_empty_passphrase() {
        let d = tempfile::tempdir().unwrap();
        let err = Store::create(d.path(), "").err().expect("refused");
        assert_eq!(err.to_string(), "A passphrase cannot be empty.");
        assert!(!d.path().join(DB_FILE).exists());
        assert!(!d.path().join(SALT_FILE).exists());
    }

    #[test]
    fn open_without_profile_is_no_profile() {
        let d = tempfile::tempdir().unwrap();
        assert!(matches!(
            Store::open(d.path(), "k"),
            Err(CoreError::NoProfile)
        ));
    }

    #[test]
    fn secure_delete_is_on() {
        let d = tempfile::tempdir().unwrap();
        let (s, _p) = Store::create(d.path(), "k").unwrap();
        let on: i64 = s
            .conn()
            .query_row("PRAGMA secure_delete", [], |r| r.get(0))
            .unwrap();
        assert_eq!(on, 1);
        drop(s);
        let (s, _p) = Store::open(d.path(), "k").unwrap();
        let on: i64 = s
            .conn()
            .query_row("PRAGMA secure_delete", [], |r| r.get(0))
            .unwrap();
        assert_eq!(on, 1);
    }

    /// The raw key of the profile in `dir`, made with passphrase `pass`.
    fn key_of(dir: &Path, pass: &str) -> Zeroizing<[u8; 32]> {
        let kdf = Kdf::decode(&std::fs::read(dir.join(SALT_FILE)).unwrap()).unwrap();
        derive_key(pass, &kdf).unwrap()
    }

    #[test]
    fn secure_delete_is_on_for_openmls_too() {
        let d = tempfile::tempdir().unwrap();
        drop(Store::create(d.path(), "k").unwrap());
        let conn = provider_conn(&d.path().join(DB_FILE), &key_of(d.path(), "k")).unwrap();
        let on: i64 = conn
            .query_row("PRAGMA secure_delete", [], |r| r.get(0))
            .unwrap();
        assert_eq!(on, 1);
    }

    #[test]
    fn checkpoint_reports_a_blocked_log() {
        let d = tempfile::tempdir().unwrap();
        let (s, _p) = Store::create(d.path(), "k").unwrap();
        s.conn()
            .busy_timeout(std::time::Duration::from_millis(20))
            .unwrap();
        let reader = open_keyed(&d.path().join(DB_FILE), &key_of(d.path(), "k")).unwrap();
        s.trust(&Key([1; 32])).unwrap();
        reader.execute_batch("BEGIN;").unwrap();
        let _: i64 = reader
            .query_row("SELECT count(*) FROM trusted", [], |r| r.get(0))
            .unwrap();
        s.trust(&Key([2; 32])).unwrap();
        assert!(s.checkpoint().is_err(), "a reader holds the log");
        reader.execute_batch("COMMIT;").unwrap();
        s.checkpoint().unwrap();
        let wal = std::fs::metadata(d.path().join(format!("{DB_FILE}-wal"))).unwrap();
        assert_eq!(wal.len(), 0);
    }

    #[test]
    fn old_profile_starts_with_history_seen() {
        let conn = old_groups_table();
        migrate(&conn).unwrap();
        let seen: i64 = conn
            .query_row("SELECT seen_seq FROM groups", [], |r| r.get(0))
            .unwrap();
        assert_eq!(seen, 7);
        // A second run does not move it again.
        conn.execute("UPDATE groups SET last_seq = 9", []).unwrap();
        migrate(&conn).unwrap();
        let seen: i64 = conn
            .query_row("SELECT seen_seq FROM groups", [], |r| r.get(0))
            .unwrap();
        assert_eq!(seen, 7);
    }

    /// A 0.4.0 groups table with one room whose log was read up to 7.
    fn old_groups_table() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE servers (
                 id INTEGER PRIMARY KEY, host TEXT NOT NULL, port INTEGER NOT NULL,
                 cert_fpr BLOB NOT NULL, account_key BLOB, UNIQUE (host, port));
             INSERT INTO servers (id, host, port, cert_fpr) VALUES (1, 'h', 1, x'00');
             CREATE TABLE groups (
                 id BLOB PRIMARY KEY,
                 server_id INTEGER NOT NULL REFERENCES servers(id),
                 group_key BLOB NOT NULL,
                 name TEXT NOT NULL DEFAULT '',
                 is_dm INTEGER NOT NULL DEFAULT 0,
                 left_group INTEGER NOT NULL DEFAULT 0,
                 last_seq INTEGER NOT NULL DEFAULT 0,
                 last_update_unix INTEGER NOT NULL DEFAULT 0,
                 joined_unix INTEGER NOT NULL);
             INSERT INTO groups (id, server_id, group_key, last_seq, joined_unix)
                 VALUES (x'01', 1, x'00', 7, 1);",
        )
        .unwrap();
        conn
    }

    #[test]
    fn seen_mark_column_and_its_start_value_arrive_together() {
        let conn = old_groups_table();
        // The first run stops after adding seen_seq, before it is set.
        conn.execute_batch(
            "CREATE TRIGGER stop BEFORE UPDATE ON groups
             BEGIN SELECT RAISE(ABORT, 'stopped for a test'); END;",
        )
        .unwrap();
        assert!(migrate(&conn).is_err());
        conn.execute_batch("DROP TRIGGER stop;").unwrap();
        migrate(&conn).unwrap();
        let seen: i64 = conn
            .query_row("SELECT seen_seq FROM groups", [], |r| r.get(0))
            .unwrap();
        assert_eq!(seen, 7);
    }

    #[test]
    fn notice_slot_is_above_every_stored_line() {
        let d = tempfile::tempdir().unwrap();
        let (s, _p) = Store::create(d.path(), "k").unwrap();
        s.conn
            .execute_batch(
                "INSERT INTO servers (id, host, port, cert_fpr) VALUES (1, 'h', 1, x'00');
                 INSERT INTO groups (id, server_id, group_key, last_seq, joined_unix)
                     VALUES (x'01010101010101010101010101010101', 1, x'00', 4, 1);",
            )
            .unwrap();
        let g = GroupId([1; 16]);
        // An empty room: the slot follows the log.
        assert_eq!(s.notice_seq(&g, 4).unwrap(), 5);
        // This person's own line at 5, posted but not yet read back.
        s.add_message(&g, 5, Some(&Key([2; 32])), 0, "mine", 1)
            .unwrap();
        let slot = s.notice_seq(&g, 4).unwrap();
        assert_eq!(slot, 6);
        s.add_message(&g, slot, None, 1, "notice", 1).unwrap();
        let bodies: Vec<String> = s
            .messages(&g, 10)
            .unwrap()
            .into_iter()
            .map(|m| m.body)
            .collect();
        assert_eq!(bodies, ["mine", "notice"]);
        // A log read further than any stored line still wins.
        assert_eq!(s.notice_seq(&g, 9).unwrap(), 10);
    }
}
