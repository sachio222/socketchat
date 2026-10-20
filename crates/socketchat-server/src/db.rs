//! The server's SQLite database. One file, WAL mode.
//!
//! It holds random keys, random IDs, encrypted bytes and timestamps. Nothing
//! here links an account to a group or to the invite that created it, or to
//! the invites it made: `invite_quota` keeps only a count and a day.
//!
//! An unused group invite names the mailbox that made it, so a member's
//! open links can be counted. The name is cleared when someone uses the
//! link, so no record ever links an inviter to the person who joined.
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
    created_unix INTEGER NOT NULL
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
CREATE TABLE IF NOT EXISTS file_done (
    file_id BLOB NOT NULL,
    mailbox BLOB NOT NULL,
    PRIMARY KEY (file_id, mailbox)
);
";

pub fn open(data_dir: &Path) -> Result<Connection, ServerError> {
    let mut conn = Connection::open(data_dir.join(DB_FILE))?;
    conn.execute_batch(
        "PRAGMA cipher_log_level = NONE; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;",
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
}
