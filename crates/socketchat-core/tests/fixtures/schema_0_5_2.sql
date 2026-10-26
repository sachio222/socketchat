-- The tables of a profile made by Socketchat 0.5.2: its SCHEMA, then
-- its ADDED_COLUMNS, as a 0.5.2 app leaves them.
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
ALTER TABLE vouchers ADD COLUMN mine INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vouchers ADD COLUMN mac_key BLOB;
ALTER TABLE vouchers ADD COLUMN seal_key BLOB;
ALTER TABLE vouchers ADD COLUMN request_key BLOB;
ALTER TABLE members ADD COLUMN app_version TEXT;
ALTER TABLE groups ADD COLUMN announced_version TEXT;
ALTER TABLE groups ADD COLUMN seen_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE groups ADD COLUMN muted INTEGER NOT NULL DEFAULT 0;
ALTER TABLE groups ADD COLUMN closing BLOB;
ALTER TABLE profile ADD COLUMN theme TEXT;
ALTER TABLE profile ADD COLUMN mouse INTEGER;
ALTER TABLE profile ADD COLUMN update_check INTEGER;
ALTER TABLE profile ADD COLUMN update_asked_unix INTEGER;
ALTER TABLE profile ADD COLUMN update_answered_unix INTEGER;
ALTER TABLE profile ADD COLUMN update_latest TEXT;
ALTER TABLE pending_joins ADD COLUMN key_package_refs BLOB;
ALTER TABLE vouchers ADD COLUMN joiner BLOB;
ALTER TABLE files ADD COLUMN sender_group_key BLOB;
ALTER TABLE files ADD COLUMN added_unix INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ended_rooms ADD COLUMN server_id INTEGER;
