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

use crate::keys::KeyPair;
use crate::provider::{Provider, Storage};
use crate::CoreError;

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
CREATE TABLE IF NOT EXISTS pending (
    group_id BLOB NOT NULL,
    kind TEXT NOT NULL,
    payload BLOB NOT NULL
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
