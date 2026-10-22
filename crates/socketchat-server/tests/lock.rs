//! A slow check of one group change must not hold up anyone else's
//! requests, and racing changes still settle one at a time.

mod common;

use std::time::{Duration, Instant};

use common::*;
use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use socketchat_core::keys::KeyPair;
use socketchat_core::suite::{capabilities, group_create_config, FALLBACK_SUITE, SUITE};
use socketchat_proto::msg::{Request, Response};
use socketchat_server::{init, make_server_invite, Config, Server, ServerHandle};

struct Env {
    d: tempfile::TempDir,
    h: ServerHandle,
}

async fn env_with(f: impl FnOnce(&mut Config)) -> Env {
    let d = tempfile::tempdir().unwrap();
    init(d.path(), "localhost").unwrap();
    let mut cfg = Config::load(d.path()).unwrap();
    cfg.listen = "127.0.0.1:0".parse().unwrap();
    f(&mut cfg);
    let h = Server::start(cfg).await.unwrap();
    Env { d, h }
}

impl Env {
    async fn person(&self) -> Person {
        Person::new(self.h.addr, self.h.cert_fpr).await
    }
    async fn admin(&self, suite: Ciphersuite) -> Person {
        let mut a = self.person().await;
        let inv = make_server_invite(self.d.path()).unwrap().token;
        assert_eq!(a.create_group(inv, suite).await, Response::Ok);
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

fn key_packages(prov: &OpenMlsRustCrypto, n: usize) -> Vec<KeyPackage> {
    (0..n)
        .map(|_| {
            let k = KeyPair::generate();
            KeyPackage::builder()
                .leaf_node_capabilities(capabilities())
                .build(FALLBACK_SUITE, prov, &k, k.credential())
                .unwrap()
                .key_package()
                .clone()
        })
        .collect()
}

/// A chat message from `p` in its own room.
fn message(p: &mut Person, text: &[u8]) -> Vec<u8> {
    let (prov, key) = (&p.prov, &p.key);
    let m = p
        .group
        .as_mut()
        .unwrap()
        .create_message(prov, key, text)
        .unwrap();
    ser(&m)
}

/// While the server checks a commit that adds thousands of people, a
/// member of another room fetches and sends without waiting for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_commit_does_not_hold_up_other_rooms() {
    let e = env_with(|_| {}).await;
    let mut a = e.admin(FALLBACK_SUITE).await;
    // People nobody invited: the server checks the whole commit, then
    // refuses it.
    let n: usize = std::env::var("LOCK_TEST_ADDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2500);
    let kps = key_packages(&a.prov, n);
    let (prov, key) = (&a.prov, &a.key);
    let (commit, _, _) = a
        .group
        .as_mut()
        .unwrap()
        .add_members(prov, key, &kps)
        .unwrap();
    let commit = ser(&commit);
    eprintln!("commit adding {n}: {} bytes", commit.len());

    let mut b = e.admin(SUITE).await;
    let first = message(&mut b, b"before");
    assert!(matches!(b.post(first, None).await, Response::Posted { .. }));
    let bg = b.gid.unwrap();

    let t0 = Instant::now();
    let big = tokio::spawn(async move {
        let r = a.post(commit, None).await;
        (r, t0.elapsed())
    });
    tokio::time::sleep(Duration::from_millis(30)).await;

    let t1 = Instant::now();
    let fetched = b
        .conn
        .req(Request::Fetch {
            group: bg,
            after: 0,
            limit: 10,
        })
        .await;
    let fetch_wait = t1.elapsed();
    let next = message(&mut b, b"during");
    let t2 = Instant::now();
    let sent = b.post(next, None).await;
    let send_wait = t2.elapsed();
    let (r, took) = big.await.unwrap();
    eprintln!(
        "commit answered after {took:?} ({r:?}); fetch waited {fetch_wait:?}, send waited {send_wait:?}"
    );
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    assert!(
        matches!(fetched, Response::Entries(ref es) if es.len() == 1),
        "{fetched:?}"
    );
    assert!(matches!(sent, Response::Posted { .. }), "{sent:?}");
    assert!(
        took > Duration::from_millis(150),
        "the commit took only {took:?}; raise LOCK_TEST_ADDS so it measures something"
    );
    assert!(
        fetch_wait < Duration::from_millis(100) && send_wait < Duration::from_millis(100),
        "another room waited {fetch_wait:?} to fetch and {send_wait:?} to send behind one commit ({took:?})"
    );
}

/// A new room's tree with thousands of members is refused without holding
/// up another account's sign-in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_new_room_does_not_hold_up_others() {
    let e = env_with(|_| {}).await;
    let prov = OpenMlsRustCrypto::default();
    let me = KeyPair::generate();
    let mut g = MlsGroup::new(
        &prov,
        &me,
        &group_create_config(FALLBACK_SUITE, &[me.public()]),
        me.credential(),
    )
    .unwrap();
    let kps = key_packages(&prov, 2500);
    g.add_members(&prov, &me, &kps).unwrap();
    g.merge_pending_commit(&prov).unwrap();
    let gi = ser(&g.export_group_info(prov.crypto(), &me, false).unwrap());
    let tree = g.export_ratchet_tree().tls_serialize_detached().unwrap();

    let mut x = e.person().await;
    let acct = KeyPair::generate();
    let inv = make_server_invite(e.d.path()).unwrap().token;
    let ch = x.conn.challenge().await;
    assert_eq!(
        x.conn
            .req(Request::RegisterAccount {
                token: inv,
                key: acct.public(),
                sig: auth_sig(&acct, &ch)
            })
            .await,
        Response::Ok
    );
    let mut y = Raw::connect(e.h.addr, e.h.cert_fpr).await;
    y.hello().await;
    let yk = KeyPair::generate();
    let yinv = make_server_invite(e.d.path()).unwrap().token;
    let ych = y.challenge().await;
    assert_eq!(
        y.req(Request::RegisterAccount {
            token: yinv,
            key: yk.public(),
            sig: auth_sig(&yk, &ych)
        })
        .await,
        Response::Ok
    );

    let t0 = Instant::now();
    let big = tokio::spawn(async move {
        let r = x
            .conn
            .req(Request::CreateGroup {
                group_info: gi,
                ratchet_tree: tree,
            })
            .await;
        (r, t0.elapsed())
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    let t1 = Instant::now();
    let r = y
        .req(Request::Prove {
            key: yk.public(),
            sig: auth_sig(&yk, &ych),
        })
        .await;
    let waited = t1.elapsed();
    let (br, took) = big.await.unwrap();
    eprintln!("new room answered {br:?} after {took:?}; sign-in waited {waited:?}");
    assert_eq!(r, Response::Ok);
    assert!(matches!(br, Response::Refused(_)), "{br:?}");
    assert!(
        waited < Duration::from_millis(100),
        "a sign-in waited {waited:?} behind one new room ({took:?})"
    );
}

/// The tree an app sends for a new room is a small part of the 16 KB the
/// server takes, on either suite.
#[test]
fn new_room_trees_from_apps_are_small() {
    for suite in [SUITE, FALLBACK_SUITE] {
        let prov = OpenMlsRustCrypto::default();
        let me = KeyPair::generate();
        let g = MlsGroup::new(
            &prov,
            &me,
            &group_create_config(suite, &[me.public()]),
            me.credential(),
        )
        .unwrap();
        let tree = g.export_ratchet_tree().tls_serialize_detached().unwrap();
        eprintln!("{suite:?}: a new room's tree is {} bytes", tree.len());
        assert!(tree.len() * 4 < 16 * 1024, "{suite:?}: {}", tree.len());
    }
}

/// Two commits for one epoch, checked at the same time: one is taken, the
/// other hears the room moved on, and the log and epoch move once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_changes_racing_for_one_epoch_cannot_both_win() {
    let e = env_with(|c| c.commit_check_delay.set(Duration::from_millis(300))).await;
    let mut a = e.admin(SUITE).await;
    let mut b = e.member(&mut a).await;
    let gid = a.gid.unwrap();
    let epoch_before: i64 = e
        .db()
        .query_row("SELECT epoch FROM groups", [], |r| r.get(0))
        .unwrap();
    let log_before: i64 = e
        .db()
        .query_row("SELECT COUNT(*) FROM log", [], |r| r.get(0))
        .unwrap();
    let update = |p: &mut Person| {
        let (prov, key) = (&p.prov, &p.key);
        let bundle = p
            .group
            .as_mut()
            .unwrap()
            .self_update(prov, key, LeafNodeParameters::default())
            .unwrap();
        ser(bundle.commit())
    };
    let ca = update(&mut a);
    let cb = update(&mut b);
    let ta = tokio::spawn(async move {
        let r = a.post(ca, None).await;
        (a, r)
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let rb = b.post(cb, None).await;
    let (_a, ra) = ta.await.unwrap();
    let posted = [&ra, &rb]
        .iter()
        .filter(|r| matches!(r, Response::Posted { .. }))
        .count();
    let conflicts = [&ra, &rb]
        .iter()
        .filter(|r| matches!(r, Response::Conflict { .. }))
        .count();
    assert_eq!((posted, conflicts), (1, 1), "{ra:?} {rb:?}");
    let epoch_after: i64 = e
        .db()
        .query_row(
            "SELECT epoch FROM groups WHERE id = ?1",
            [gid.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    let log_after: i64 = e
        .db()
        .query_row("SELECT COUNT(*) FROM log", [], |r| r.get(0))
        .unwrap();
    assert_eq!(epoch_after, epoch_before + 1);
    assert_eq!(log_after, log_before + 1);
}

/// A request to leave that arrives while a commit is being checked does
/// not make that commit lose: the commit did not depend on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_leave_request_during_a_check_does_not_undo_a_commit() {
    let e = env_with(|c| c.commit_check_delay.set(Duration::from_millis(300))).await;
    let mut a = e.admin(SUITE).await;
    let mut b = e.member(&mut a).await;
    let (prov, key) = (&a.prov, &a.key);
    let update = a
        .group
        .as_mut()
        .unwrap()
        .self_update(prov, key, LeafNodeParameters::default())
        .unwrap();
    let commit = ser(update.commit());
    let ta = tokio::spawn(async move {
        let r = a.post(commit, None).await;
        (a, r)
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (prov, key) = (&b.prov, &b.key);
    let leave = b.group.as_mut().unwrap().leave_group(prov, key).unwrap();
    let rb = b.post(ser(&leave), None).await;
    let (_a, ra) = ta.await.unwrap();
    assert!(matches!(rb, Response::Posted { .. }), "{rb:?}");
    assert!(matches!(ra, Response::Posted { .. }), "{ra:?}");
}

/// A commit whose sender is removed while it is being checked is not
/// written: it hears that the room moved on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_commit_whose_sender_is_removed_during_its_check_loses() {
    let e = env_with(|_| {}).await;
    let mut a = e.admin(FALLBACK_SUITE).await;
    let gid = a.gid.unwrap();
    let mut b = e.person().await;
    let t = a.invite().await;
    assert_eq!(b.redeem_mailbox(t).await, Response::Ok);
    let kp = KeyPackage::builder()
        .leaf_node_capabilities(capabilities())
        .build(FALLBACK_SUITE, &b.prov, &b.key, b.key.credential())
        .unwrap()
        .key_package()
        .clone();
    let r = a.add(kp, t).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
    b.join_from_welcome(gid).await;
    // A slow commit from b: it adds many people.
    let kps = key_packages(&b.prov, 2000);
    let (prov, key) = (&b.prov, &b.key);
    let (slow, _, _) = b
        .group
        .as_mut()
        .unwrap()
        .add_members(prov, key, &kps)
        .unwrap();
    let slow = ser(&slow);
    let bkey = b.key.public();
    let tb = tokio::spawn(async move { b.post(slow, None).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    let idx = a
        .g()
        .members()
        .find(|m| m.signature_key == bkey.0)
        .unwrap()
        .index;
    let (prov, key) = (&a.prov, &a.key);
    let (c, _, _) = a
        .group
        .as_mut()
        .unwrap()
        .remove_members(prov, key, &[idx])
        .unwrap();
    let ra = a.post(ser(&c), None).await;
    let rb = tb.await.unwrap();
    assert!(matches!(ra, Response::Posted { .. }), "{ra:?}");
    assert!(matches!(rb, Response::Conflict { .. }), "{rb:?}");
    let still_there: bool = e
        .db()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM mailboxes WHERE key = ?1 AND group_id = ?2)",
            [bkey.0.as_slice(), gid.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!still_there);
}
