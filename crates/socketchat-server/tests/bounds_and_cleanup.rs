//! What the server bounds, clears and keeps private: fetches past the end
//! of a log, deleted data in the write-ahead log, file permissions, and
//! Welcomes for people who were removed.

mod common;

use common::*;
use openmls::prelude::*;
use socketchat_core::suite::SUITE;
use socketchat_proto::msg::{Request, Response};
use socketchat_server::{init, make_server_invite, Config, Server, ServerHandle};

struct Env {
    d: tempfile::TempDir,
    h: ServerHandle,
}

async fn env() -> Env {
    let d = tempfile::tempdir().unwrap();
    init(d.path(), "localhost").unwrap();
    let mut cfg = Config::load(d.path()).unwrap();
    cfg.listen = "127.0.0.1:0".parse().unwrap();
    let h = Server::start(cfg).await.unwrap();
    Env { d, h }
}

impl Env {
    async fn person(&self) -> Person {
        Person::new(self.h.addr, self.h.cert_fpr).await
    }
    async fn admin(&self) -> Person {
        let mut a = self.person().await;
        let inv = make_server_invite(self.d.path()).unwrap().token;
        assert_eq!(a.create_group(inv, SUITE).await, Response::Ok);
        a
    }
    async fn member(&self, admin: &mut Person) -> Person {
        let mut b = self.person().await;
        let t = admin.invite().await;
        assert_eq!(b.redeem_mailbox(t).await, Response::Ok);
        let r = admin.add(b.key_package(), t).await;
        assert!(matches!(r, Response::Posted { .. }), "{r:?}");
        b.join_from_welcome(admin.gid.unwrap()).await;
        b
    }
    fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.d.path().join("server.db")).unwrap()
    }
}

fn leaf_of(g: &MlsGroup, k: &socketchat_core::keys::KeyPair) -> LeafNodeIndex {
    g.members()
        .find(|m| m.signature_key == k.public().0)
        .unwrap()
        .index
}

async fn remove(admin: &mut Person, who: &Person) {
    let idx = leaf_of(admin.group.as_ref().unwrap(), &who.key);
    let (c, _, _) = admin
        .group
        .as_mut()
        .unwrap()
        .remove_members(&admin.prov, &admin.key, &[idx])
        .unwrap();
    let r = admin.post(ser(&c), None).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
    admin.settle(&r);
}

/// A newcomer never gets entries from before they joined, whatever `after`
/// they ask from.
#[tokio::test]
async fn fetch_after_a_huge_value_stays_past_the_join() {
    let e = env().await;
    let mut a = e.admin().await;
    let m = a
        .group
        .as_mut()
        .unwrap()
        .create_message(&a.prov, &a.key, b"before bob")
        .unwrap();
    assert!(matches!(
        a.post(ser(&m), None).await,
        Response::Posted { .. }
    ));
    let mut b = e.member(&mut a).await;
    let joined = b.last_seq;
    assert!(joined >= 1);
    for after in [u64::MAX, 1 << 63, (1 << 63) - 1] {
        let r = b
            .conn
            .req(Request::Fetch {
                group: b.gid.unwrap(),
                after,
                limit: 500,
            })
            .await;
        let Response::Entries(es) = r else {
            panic!("{r:?}")
        };
        assert!(
            es.iter().all(|x| x.seq > joined),
            "after {after}: {:?}",
            es.iter().map(|x| x.seq).collect::<Vec<_>>()
        );
    }
}

/// Deleted rows do not stay in the write-ahead log of a running server.
#[tokio::test]
async fn ending_a_room_clears_the_write_ahead_log() {
    let e = env().await;
    let mut a = e.admin().await;
    let t = a.invite().await;
    let mut b = e.person().await;
    assert_eq!(b.redeem_mailbox(t).await, Response::Ok);
    let r = a.add(b.key_package(), t).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
    b.join_from_welcome(a.gid.unwrap()).await;
    remove(&mut a, &b).await;
    let r = a
        .conn
        .req(Request::LastLeave {
            group: a.gid.unwrap(),
        })
        .await;
    assert_eq!(r, Response::Ok);
    for name in ["server.db", "server.db-wal"] {
        let Ok(bytes) = std::fs::read(e.d.path().join(name)) else {
            continue;
        };
        assert!(
            !bytes.windows(16).any(|w| w == t.0.as_slice()),
            "{name} still holds the deleted link"
        );
    }
}

/// A Welcome for someone removed before they fetched it goes with the
/// removal.
#[tokio::test]
async fn removing_a_joiner_deletes_their_welcome() {
    let e = env().await;
    let mut a = e.admin().await;
    let t = a.invite().await;
    let mut c = e.person().await;
    assert_eq!(c.redeem_mailbox(t).await, Response::Ok);
    let r = a.add(c.key_package(), t).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
    let held = |e: &Env| -> i64 {
        e.db()
            .query_row("SELECT COUNT(*) FROM welcomes", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(held(&e), 1);
    remove(&mut a, &c).await;
    assert_eq!(held(&e), 0, "the removal leaves the Welcome behind");
}

/// Ending the room leaves no Welcome behind, even one for a person removed
/// before they fetched it.
#[tokio::test]
async fn ending_a_room_deletes_welcomes_for_removed_joiners() {
    let e = env().await;
    let mut a = e.admin().await;
    let t = a.invite().await;
    let mut c = e.person().await;
    assert_eq!(c.redeem_mailbox(t).await, Response::Ok);
    let r = a.add(c.key_package(), t).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
    remove(&mut a, &c).await;
    let r = a
        .conn
        .req(Request::LastLeave {
            group: a.gid.unwrap(),
        })
        .await;
    assert_eq!(r, Response::Ok);
    let n: i64 = e
        .db()
        .query_row("SELECT COUNT(*) FROM welcomes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
}

#[cfg(unix)]
mod perms {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(p: &std::path::Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    fn assert_private(dir: &std::path::Path) {
        assert_eq!(mode(dir), 0o700, "{}", dir.display());
        for name in [
            "server.db",
            "server.db-wal",
            "server.db-shm",
            "key.der",
            "cert.der",
            "socketchat-server.toml",
        ] {
            let p = dir.join(name);
            if p.exists() {
                assert_eq!(mode(&p), 0o600, "{}", p.display());
            }
        }
    }

    /// `init` makes a private directory even under a permissive umask-free
    /// parent, and a running server keeps its files private.
    #[tokio::test]
    async fn init_makes_a_private_data_directory() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("data");
        init(&dir, "localhost").unwrap();
        assert_private(&dir);
        let mut cfg = Config::load(&dir).unwrap();
        cfg.listen = "127.0.0.1:0".parse().unwrap();
        let h = Server::start(cfg).await.unwrap();
        assert_private(&dir);
        drop(h);
    }

    /// A directory made by an older release is tightened when the server
    /// starts, chunk folders included.
    #[tokio::test]
    async fn start_tightens_an_open_data_directory() {
        let d = tempfile::tempdir().unwrap();
        init(d.path(), "localhost").unwrap();
        let files = d.path().join("files").join("ab");
        std::fs::create_dir_all(&files).unwrap();
        std::fs::write(files.join("0"), b"x").unwrap();
        let set = |p: &std::path::Path, m| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap()
        };
        set(d.path(), 0o755);
        set(&d.path().join("files"), 0o755);
        set(&files, 0o755);
        set(&files.join("0"), 0o644);
        for n in ["server.db", "cert.der", "key.der", "socketchat-server.toml"] {
            set(&d.path().join(n), 0o644);
        }
        let mut cfg = Config::load(d.path()).unwrap();
        cfg.listen = "127.0.0.1:0".parse().unwrap();
        let _h = Server::start(cfg).await.unwrap();
        assert_private(d.path());
        assert_eq!(mode(&d.path().join("files")), 0o700);
        assert_eq!(mode(&files), 0o700);
        assert_eq!(mode(&files.join("0")), 0o600);
    }
}
