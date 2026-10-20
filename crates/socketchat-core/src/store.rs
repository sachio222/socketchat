//! The client's local data, encrypted at rest.
//!
//! One SQLCipher file holds everything: the app's own tables and OpenMLS's
//! group state. The key comes from the person's passphrase through Argon2id
//! with a random salt kept beside the file. The salt is not secret.

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

/// Argon2id settings: OWASP's recommended minimum (19 MiB, 2 passes), so a
/// Raspberry Pi opens a profile in well under a second.
const ARGON_MEM_KIB: u32 = 19 * 1024;
const ARGON_PASSES: u32 = 2;

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
";

/// Who this person is on this device.
#[derive(Clone, Debug)]
pub struct Profile {
    pub identity: KeyPair,
    pub display_name: String,
}

pub struct Store {
    conn: Connection,
    dir: PathBuf,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let params = Params::new(ARGON_MEM_KIB, ARGON_PASSES, 1, Some(32))
        .map_err(|e| CoreError::Other(e.to_string()))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
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

fn provider(path: &Path, key: &[u8; 32]) -> Result<Provider, CoreError> {
    let conn = open_keyed(path, key)?;
    let mut storage = Storage::new(conn);
    storage
        .run_migrations()
        .map_err(|e| CoreError::Storage(e.to_string()))?;
    Ok(Provider::new(storage))
}

impl Store {
    /// Makes a new, empty profile store in `dir`.
    pub fn create(dir: &Path, passphrase: &str) -> Result<(Store, Provider), CoreError> {
        let db = dir.join(DB_FILE);
        if db.exists() || dir.join(SALT_FILE).exists() {
            return Err(CoreError::ProfileExists);
        }
        std::fs::create_dir_all(dir)?;
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        std::fs::write(dir.join(SALT_FILE), salt)?;
        let key = derive_key(passphrase, &salt)?;
        let conn = open_keyed(&db, &key)?;
        conn.execute_batch(SCHEMA)?;
        let p = provider(&db, &key)?;
        Ok((
            Store {
                conn,
                dir: dir.to_path_buf(),
            },
            p,
        ))
    }

    /// Opens the profile store in `dir` with the person's passphrase.
    pub fn open(dir: &Path, passphrase: &str) -> Result<(Store, Provider), CoreError> {
        let db = dir.join(DB_FILE);
        let salt_path = dir.join(SALT_FILE);
        if !db.exists() || !salt_path.exists() {
            return Err(CoreError::NoProfile);
        }
        let salt = std::fs::read(salt_path)?;
        let key = derive_key(passphrase, &salt)?;
        let conn = open_keyed(&db, &key)?;
        conn.execute_batch(SCHEMA)?;
        let p = provider(&db, &key)?;
        Ok((
            Store {
                conn,
                dir: dir.to_path_buf(),
            },
            p,
        ))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageRow {
    pub seq: u64,
    pub sender: Option<Key>,
    pub kind: i64,
    pub body: String,
    pub sent_unix: u64,
}

/// A join this client lodged and is waiting on.
#[derive(Clone, Debug)]
pub struct PendingJoin {
    pub token: Token,
    pub server_id: i64,
    pub link: String,
    pub key: KeyPair,
    pub lodged_unix: u64,
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

    pub fn add_group(&self, g: &GroupRow) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT INTO groups (id, server_id, group_key, name, is_dm, last_seq, last_update_unix, joined_unix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
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

    pub fn set_last_seq(&self, g: &GroupId, seq: u64) -> Result<(), CoreError> {
        self.conn.execute(
            "UPDATE groups SET last_seq = max(last_seq, ?1) WHERE id = ?2",
            params![seq as i64, g.0.as_slice()],
        )?;
        Ok(())
    }

    pub fn set_last_update(&self, g: &GroupId, unix: u64) -> Result<(), CoreError> {
        self.conn.execute(
            "UPDATE groups SET last_update_unix = ?1 WHERE id = ?2",
            params![unix as i64, g.0.as_slice()],
        )?;
        Ok(())
    }

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
                    (m.identity IS NOT NULL AND EXISTS(SELECT 1 FROM trusted t WHERE t.identity = m.identity))
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
            })
        })?;
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

    /// The newest `limit` messages, oldest first.
    pub fn messages(&self, g: &GroupId, limit: usize) -> Result<Vec<MessageRow>, CoreError> {
        let mut st = self.conn.prepare(
            "SELECT seq, sender_group_key, kind, body, sent_unix FROM (
                 SELECT * FROM messages WHERE group_id = ?1 ORDER BY seq DESC LIMIT ?2
             ) ORDER BY seq",
        )?;
        let rows = st.query_map(params![g.0.as_slice(), limit as i64], |r| {
            Ok(MessageRow {
                seq: r.get::<_, i64>(0)? as u64,
                sender: key_col(r.get(1)?),
                kind: r.get(2)?,
                body: r.get(3)?,
                sent_unix: r.get::<_, i64>(4)? as u64,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn save_voucher(
        &self,
        g: &GroupId,
        token: &Token,
        voucher: &[u8],
        secret: &[u8; 32],
    ) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO vouchers (group_id, token, voucher, secret) VALUES (?1, ?2, ?3, ?4)",
            params![g.0.as_slice(), token.0.as_slice(), voucher, secret.as_slice()],
        )?;
        Ok(())
    }

    /// The stored voucher bytes and invite secret for a token.
    pub fn voucher(
        &self,
        g: &GroupId,
        token: &Token,
    ) -> Result<Option<(Vec<u8>, [u8; 32])>, CoreError> {
        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT voucher, secret FROM vouchers WHERE group_id = ?1 AND token = ?2",
                params![g.0.as_slice(), token.0.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.and_then(|(v, s)| s.try_into().ok().map(|s| (v, s))))
    }

    pub fn save_pending_join(&self, p: &PendingJoin) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO pending_joins (token, server_id, link, group_key, lodged_unix)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                p.token.0.as_slice(),
                p.server_id,
                p.link,
                kp_bytes(&p.key).as_slice(),
                p.lodged_unix as i64
            ],
        )?;
        Ok(())
    }

    pub fn pending_joins(&self) -> Result<Vec<PendingJoin>, CoreError> {
        let mut st = self
            .conn
            .prepare("SELECT token, server_id, link, group_key, lodged_unix FROM pending_joins")?;
        let rows = st.query_map([], |r| {
            let t: Vec<u8> = r.get(0)?;
            let k: Vec<u8> = r.get(3)?;
            Ok(PendingJoin {
                token: Token(t.try_into().unwrap_or([0; 16])),
                server_id: r.get(1)?,
                link: r.get(2)?,
                key: kp_col(&k)?,
                lodged_unix: r.get::<_, i64>(4)? as u64,
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
    fn open_without_profile_is_no_profile() {
        let d = tempfile::tempdir().unwrap();
        assert!(matches!(
            Store::open(d.path(), "k"),
            Err(CoreError::NoProfile)
        ));
    }
}
