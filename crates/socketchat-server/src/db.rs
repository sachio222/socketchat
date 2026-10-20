//! The server's SQLite database. One file, WAL mode.
//!
//! It holds random keys, random IDs, encrypted bytes and timestamps. Nothing
//! here links an account to a group or to the invite that created it, or to
//! the invites it made: `invite_quota` keeps only a count and a day.

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
    account_used INTEGER NOT NULL DEFAULT 0
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
    conn.execute_batch(SCHEMA)?;
    let mut storage = openmls_sqlite_storage::SqliteStorageProvider::<JsonCodec, _>::new(&mut conn);
    storage
        .run_migrations()
        .map_err(|e| ServerError::Db(e.to_string()))?;
    Ok(conn)
}
