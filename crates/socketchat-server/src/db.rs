//! The server's SQLite database. One file, WAL mode.
//!
//! It holds random keys, random IDs, encrypted bytes and timestamps. Nothing
//! here links an account to a group or to the invite that created it, or to
//! the invites it made: `invite_quota` and `link_quota` keep only a count
//! and a day.
//!
//! A group invite names the mailbox that made it, so a member's open links
//! can be counted, and the links and the joins waiting on them can be
//! cancelled when that member leaves. The name is cleared when the join
//! completes, so once someone is in, no record links them to their inviter.
//!
//! `retired_keys` holds a SHA-256 hash of each group key that left a room,
//! so it cannot sign up again while the room lasts. The rows go with the
//! room.
//!
//! Secure delete is on: SQLite overwrites deleted rows and cleared fields
//! with zeros instead of leaving them in free pages.

use std::path::Path;

use rusqlite::Connection;
use socketchat_core::provider::JsonCodec;

use crate::ServerError;

pub const DB_FILE: &str = "server.db";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS accounts (
    key BLOB PRIMARY KEY,
    created_unix INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS invites (
    token BLOB PRIMARY KEY,
    group_id BLOB,
    expires_unix INTEGER NOT NULL,
    uses_left INTEGER NOT NULL,
    account_used INTEGER NOT NULL DEFAULT 0,
    maker BLOB
);
CREATE TABLE IF NOT EXISTS mailboxes (
    key BLOB PRIMARY KEY,
    group_id BLOB,
    joined_seq INTEGER,
    cursor INTEGER NOT NULL DEFAULT 0,
    created_unix INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS mailboxes_group ON mailboxes(group_id);
CREATE TABLE IF NOT EXISTS groups (
    id BLOB PRIMARY KEY,
    epoch INTEGER NOT NULL,
    next_seq INTEGER NOT NULL DEFAULT 1,
    created_unix INTEGER NOT NULL,
    log_bytes INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS log (
    group_id BLOB NOT NULL,
    seq INTEGER NOT NULL,
    mls BLOB NOT NULL,
    created_unix INTEGER NOT NULL,
    PRIMARY KEY (group_id, seq)
);
CREATE TABLE IF NOT EXISTS joins (
    token BLOB PRIMARY KEY,
    group_id BLOB NOT NULL,
    mailbox BLOB NOT NULL,
    key_package BLOB,
    mac BLOB,
    lodged_unix INTEGER
);
CREATE TABLE IF NOT EXISTS welcomes (
    mailbox BLOB NOT NULL,
    welcome BLOB NOT NULL,
    voucher BLOB NOT NULL,
    created_unix INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
    id BLOB PRIMARY KEY,
    group_id BLOB NOT NULL,
    size INTEGER NOT NULL,
    chunks INTEGER NOT NULL DEFAULT 0,
    complete INTEGER NOT NULL DEFAULT 0,
    uploader BLOB NOT NULL,
    created_unix INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS invite_quota (
    account BLOB PRIMARY KEY,
    since_unix INTEGER NOT NULL,
    used INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS files_group ON files(group_id);
CREATE INDEX IF NOT EXISTS files_uploader ON files(uploader);
CREATE INDEX IF NOT EXISTS welcomes_mailbox ON welcomes(mailbox);
CREATE TABLE IF NOT EXISTS link_quota (
    account BLOB PRIMARY KEY,
    since_unix INTEGER NOT NULL,
    used INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS file_done (
    file_id BLOB NOT NULL,
    mailbox BLOB NOT NULL,
    PRIMARY KEY (file_id, mailbox)
);
CREATE TABLE IF NOT EXISTS retired_keys (
    hash BLOB NOT NULL,
    group_id BLOB NOT NULL,
    PRIMARY KEY (hash, group_id)
);
CREATE INDEX IF NOT EXISTS retired_keys_group ON retired_keys(group_id);
";

/// Copies the write-ahead log into the database file and empties it, so old
/// copies of deleted rows and cleared invite makers do not stay in the log
/// file. A reader holding the log makes this a no-op until the next call;
/// the sweep runs it every hour.
pub fn checkpoint(conn: &Connection) {
    let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
}

pub fn open(data_dir: &Path) -> Result<Connection, ServerError> {
    // SQLite gives its -wal and -shm files the mode of this one.
    crate::perms::touch_private(&data_dir.join(DB_FILE))?;
    let mut conn = Connection::open(data_dir.join(DB_FILE))?;
    conn.execute_batch(
        "PRAGMA cipher_log_level = NONE; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA journal_size_limit = 0;",
    )?;
    // Overwrite deleted rows and cleared fields with zeros, so they do not
    // linger in free pages for anyone who copies the file.
    conn.execute_batch("PRAGMA secure_delete = ON;")?;
    conn.execute_batch(SCHEMA)?;
    // Databases made before invites named their maker.
    let has_maker: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('invites') WHERE name = 'maker')",
        [],
        |r| r.get(0),
    )?;
    if !has_maker {
        conn.execute_batch("ALTER TABLE invites ADD COLUMN maker BLOB;")?;
    }
    conn.execute_batch("CREATE INDEX IF NOT EXISTS invites_maker ON invites(maker);")?;
    // Databases made before rooms kept a total of their messages' bytes.
    let has_log_bytes: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('groups') WHERE name = 'log_bytes')",
        [],
        |r| r.get(0),
    )?;
    if !has_log_bytes {
        let t = conn.transaction()?;
        t.execute_batch("ALTER TABLE groups ADD COLUMN log_bytes INTEGER NOT NULL DEFAULT 0;")?;
        t.execute(
            "UPDATE groups SET log_bytes = (
                 SELECT COALESCE(SUM(length(mls) + ?1), 0) FROM log WHERE log.group_id = groups.id)",
            [crate::quota::ENTRY_ROW as i64],
        )?;
        t.commit()?;
    }
    // Unused room links whose maker has left the room go here. Later
    // departures delete their own links, so after the first open this
    // finds nothing.
    conn.execute(
        "DELETE FROM invites WHERE group_id IS NOT NULL AND uses_left > 0 AND maker IS NOT NULL
             AND NOT EXISTS (SELECT 1 FROM mailboxes m
                 WHERE m.key = invites.maker AND m.group_id = invites.group_id
                   AND m.joined_seq IS NOT NULL)",
        [],
    )?;
    let mut storage = openmls_sqlite_storage::SqliteStorageProvider::<JsonCodec, _>::new(&mut conn);
    storage
        .run_migrations()
        .map_err(|e| ServerError::Db(e.to_string()))?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deleted rows and cleared invite makers are overwritten on disk, not
    /// left in free pages where someone who copies the file could read them.
    #[test]
    fn deleted_data_is_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let db = open(dir.path()).unwrap();
        let on: i64 = db
            .query_row("PRAGMA secure_delete", [], |r| r.get(0))
            .unwrap();
        assert_eq!(on, 1);
        // Delete a recognizable value and look for it in the files. It is
        // larger than a page, so its pages go to the free list when deleted.
        let marker = b"invite-maker-marker-7f3a";
        let big: Vec<u8> = marker.repeat(1000);
        db.execute(
            "INSERT INTO invites (token, group_id, expires_unix, uses_left, maker) VALUES (x'02', NULL, 9, 1, ?1)",
            [big.as_slice()],
        )
        .unwrap();
        db.execute("UPDATE invites SET maker = NULL WHERE token = x'02'", [])
            .unwrap();
        db.execute("DELETE FROM invites WHERE token = x'02'", [])
            .unwrap();
        db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        drop(db);
        for name in [DB_FILE, "server.db-wal"] {
            let Ok(bytes) = std::fs::read(dir.path().join(name)) else {
                continue;
            };
            assert!(
                !bytes.windows(marker.len()).any(|w| w == marker),
                "{name} still holds a deleted value"
            );
        }
    }

    /// Opening the database deletes unused room links whose maker is no
    /// longer in that room.
    #[test]
    fn open_drops_unused_links_of_members_who_left() {
        let dir = tempfile::tempdir().unwrap();
        let db = open(dir.path()).unwrap();
        db.execute_batch(
            "INSERT INTO mailboxes (key, group_id, joined_seq, created_unix) VALUES (x'aa', x'01', 1, 0);
             INSERT INTO mailboxes (key, group_id, joined_seq, created_unix) VALUES (x'cc', x'01', NULL, 0);
             INSERT INTO invites (token, group_id, expires_unix, uses_left, maker) VALUES (x'10', x'01', 9, 1, x'aa');
             INSERT INTO invites (token, group_id, expires_unix, uses_left, maker) VALUES (x'11', x'01', 9, 1, x'bb');
             INSERT INTO invites (token, group_id, expires_unix, uses_left, maker) VALUES (x'12', x'01', 9, 1, x'cc');
             INSERT INTO invites (token, group_id, expires_unix, uses_left, maker) VALUES (x'13', NULL, 9, 1, NULL);",
        )
        .unwrap();
        drop(db);
        let db = open(dir.path()).unwrap();
        let mut st = db
            .prepare("SELECT token FROM invites ORDER BY token")
            .unwrap();
        let left: Vec<Vec<u8>> = st
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(left, vec![vec![0x10], vec![0x13]]);
    }

    /// A key hash is kept per room it left.
    #[test]
    fn a_retired_key_is_kept_per_room() {
        let dir = tempfile::tempdir().unwrap();
        let db = open(dir.path()).unwrap();
        db.execute_batch(
            "INSERT INTO retired_keys (hash, group_id) VALUES (x'aa', x'01');
             INSERT INTO retired_keys (hash, group_id) VALUES (x'aa', x'02');",
        )
        .unwrap();
        let n: i64 = db
            .query_row("SELECT COUNT(*) FROM retired_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2);
    }

    /// A database from before rooms kept a total of their messages' bytes
    /// gains it, counted from the log already there.
    #[test]
    fn old_database_counts_its_rooms_messages() {
        let dir = tempfile::tempdir().unwrap();
        let old = Connection::open(dir.path().join(DB_FILE)).unwrap();
        old.execute_batch(
            "CREATE TABLE groups (
                id BLOB PRIMARY KEY,
                epoch INTEGER NOT NULL,
                next_seq INTEGER NOT NULL DEFAULT 1,
                created_unix INTEGER NOT NULL
            );
            CREATE TABLE log (
                group_id BLOB NOT NULL,
                seq INTEGER NOT NULL,
                mls BLOB NOT NULL,
                created_unix INTEGER NOT NULL,
                PRIMARY KEY (group_id, seq)
            );
            INSERT INTO groups (id, epoch, next_seq, created_unix) VALUES (x'01', 0, 3, 0);
            INSERT INTO groups (id, epoch, next_seq, created_unix) VALUES (x'02', 0, 1, 0);
            INSERT INTO log (group_id, seq, mls, created_unix) VALUES (x'01', 1, zeroblob(100), 0);
            INSERT INTO log (group_id, seq, mls, created_unix) VALUES (x'01', 2, zeroblob(36), 0);",
        )
        .unwrap();
        drop(old);
        let db = open(dir.path()).unwrap();
        let bytes = |id: u8| -> i64 {
            db.query_row(
                "SELECT log_bytes FROM groups WHERE id = ?1",
                [vec![id]],
                |r| r.get(0),
            )
            .unwrap()
        };
        let row = crate::quota::ENTRY_ROW as i64;
        assert_eq!(bytes(1), 136 + 2 * row);
        assert_eq!(bytes(2), 0);
        drop(db);
        // Opening again counts nothing twice.
        let db = open(dir.path()).unwrap();
        let again: i64 = db
            .query_row("SELECT log_bytes FROM groups WHERE id = x'01'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(again, 136 + 2 * row);
    }

    #[test]
    fn old_database_gains_the_maker_column() {
        let dir = tempfile::tempdir().unwrap();
        let old = Connection::open(dir.path().join(DB_FILE)).unwrap();
        old.execute_batch(
            "CREATE TABLE invites (
                token BLOB PRIMARY KEY,
                group_id BLOB,
                expires_unix INTEGER NOT NULL,
                uses_left INTEGER NOT NULL,
                account_used INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO invites (token, group_id, expires_unix, uses_left) VALUES (x'01', NULL, 9, 1);",
        )
        .unwrap();
        drop(old);
        let db = open(dir.path()).unwrap();
        let maker: Option<Vec<u8>> = db
            .query_row("SELECT maker FROM invites WHERE token = x'01'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(maker, None);
        // Opening again leaves it as it is.
        drop(db);
        open(dir.path()).unwrap();
    }

    /// The checkpoint empties the write-ahead log of rows deleted since, so
    /// a copy of the data directory taken while the server runs holds none.
    #[test]
    fn checkpoint_clears_deleted_rows_from_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let db = open(dir.path()).unwrap();
        let marker = b"wal-maker-marker-91c2";
        db.execute(
            "INSERT INTO invites (token, group_id, expires_unix, uses_left, maker) VALUES (x'03', NULL, 9, 1, ?1)",
            [marker.repeat(1000).as_slice()],
        )
        .unwrap();
        db.execute("UPDATE invites SET maker = NULL WHERE token = x'03'", [])
            .unwrap();
        db.execute("DELETE FROM invites WHERE token = x'03'", [])
            .unwrap();
        checkpoint(&db);
        for name in [DB_FILE, "server.db-wal"] {
            let Ok(bytes) = std::fs::read(dir.path().join(name)) else {
                continue;
            };
            assert!(!bytes.windows(marker.len()).any(|w| w == marker), "{name}");
        }
    }
}
