//! A slow check of one group change must not hold up anyone else's
//! requests, and racing changes still settle one at a time.

mod common;

use common::*;
use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use socketchat_core::keys::KeyPair;
use socketchat_core::suite::{capabilities, group_create_config, FALLBACK_SUITE, SUITE};
use socketchat_proto::msg::{ClientFrame, Push, Request, Response, ServerFrame};
use socketchat_server::config::CheckHold;
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

/// While the server checks a commit that adds hundreds of people, a member
/// of another room fetches and sends without waiting for it. The commit is
/// held in its check, outside the database lock, until both are answered:
/// were the lock held through the check, they could not be.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_commit_does_not_hold_up_other_rooms() {
    let hold = CheckHold::default();
    let e = env_with(|c| c.commit_check_hold = hold.clone()).await;
    let mut a = e.admin(FALLBACK_SUITE).await;
    // People nobody invited: the server checks the whole commit, then
    // refuses it.
    let kps = key_packages(&a.prov, 500);
    let (prov, key) = (&a.prov, &a.key);
    let (commit, _, _) = a
        .group
        .as_mut()
        .unwrap()
        .add_members(prov, key, &kps)
        .unwrap();
    let commit = ser(&commit);

    let mut b = e.admin(SUITE).await;
    let first = message(&mut b, b"before");
    assert!(matches!(b.post(first, None).await, Response::Posted { .. }));
    let bg = b.gid.unwrap();

    let held = hold.hold_next();
    let big = tokio::spawn(async move { a.post(commit, None).await });
    held.reached().await;
    // A request stuck behind the held commit fails the test: the test
    // connection gives up on it, or, if it stalls the server's threads,
    // the hold runs out and `release` says so.
    let fetched = b
        .conn
        .req(Request::Fetch {
            group: bg,
            after: 0,
            limit: 10,
        })
        .await;
    let next = message(&mut b, b"during");
    let sent = b.post(next, None).await;
    held.release();
    let r = big.await.unwrap();
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    assert!(
        matches!(fetched, Response::Entries(ref es) if es.len() == 1),
        "{fetched:?}"
    );
    assert!(matches!(sent, Response::Posted { .. }), "{sent:?}");
}

/// A new room's tree, as large as the server takes, is checked without
/// holding up anyone else: while its check is held, outside the database
/// lock, another account signs in and a member of another room posts. The
/// tree holds more than its creator, so the check ends in a refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_new_room_does_not_hold_up_others() {
    let hold = CheckHold::default();
    let e = env_with(|c| c.new_room_check_hold = hold.clone()).await;
    let prov = OpenMlsRustCrypto::default();
    let me = KeyPair::generate();
    let mut g = MlsGroup::new(
        &prov,
        &me,
        &group_create_config(FALLBACK_SUITE, &[me.public()]),
        me.credential(),
    )
    .unwrap();
    let kps = key_packages(&prov, NEW_ROOM_MEMBERS);
    g.add_members(&prov, &me, &kps).unwrap();
    g.merge_pending_commit(&prov).unwrap();
    let gi = ser(&g.export_group_info(prov.crypto(), &me, false).unwrap());
    let tree = g.export_ratchet_tree().tls_serialize_detached().unwrap();
    eprintln!(
        "a new room of {} has a {} byte tree",
        NEW_ROOM_MEMBERS + 1,
        tree.len()
    );
    // Within the 16 KB the server takes, so the whole tree is checked.
    assert!(tree.len() <= 16 * 1024, "{}", tree.len());

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
    let mut b = e.admin(SUITE).await;

    let held = hold.hold_next();
    let big = tokio::spawn(async move {
        x.conn
            .req(Request::CreateGroup {
                group_info: gi,
                ratchet_tree: tree,
            })
            .await
    });
    held.reached().await;
    // A request stuck behind the held new room fails the test: the test
    // connection gives up on it, or, if it stalls the server's threads,
    // the hold runs out and `release` says so.
    let signed_in = y
        .req(Request::Prove {
            key: yk.public(),
            sig: auth_sig(&yk, &ych),
        })
        .await;
    let next = message(&mut b, b"during");
    let sent = b.post(next, None).await;
    held.release();
    let br = big.await.unwrap();
    assert_eq!(signed_in, Response::Ok);
    assert!(matches!(sent, Response::Posted { .. }), "{sent:?}");
    assert!(
        matches!(br, Response::Refused(ref why) if why.contains("only its creator")),
        "{br:?}"
    );
}

/// Members besides the creator in the large new room: about as many as
/// fit in the 16 KB the server takes.
const NEW_ROOM_MEMBERS: usize = 70;

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

/// Two commits for one epoch, one written while the other is still being
/// checked: the first written is taken, the other hears the room moved on,
/// and the log and epoch move once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_changes_racing_for_one_epoch_cannot_both_win() {
    let hold = CheckHold::default();
    let e = env_with(|c| c.commit_check_hold = hold.clone()).await;
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
    // a's commit is read and held in its check while b's is checked and
    // written.
    let held = hold.hold_next();
    let ta = tokio::spawn(async move {
        let r = a.post(ca, None).await;
        (a, r)
    });
    held.reached().await;
    let rb = b.post(cb, None).await;
    held.release();
    let (_a, ra) = ta.await.unwrap();
    assert!(matches!(rb, Response::Posted { .. }), "{rb:?}");
    assert!(matches!(ra, Response::Conflict { .. }), "{ra:?}");
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
    let hold = CheckHold::default();
    let e = env_with(|c| c.commit_check_hold = hold.clone()).await;
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
    let held = hold.hold_next();
    let ta = tokio::spawn(async move {
        let r = a.post(commit, None).await;
        (a, r)
    });
    held.reached().await;
    let (prov, key) = (&b.prov, &b.key);
    let leave = b.group.as_mut().unwrap().leave_group(prov, key).unwrap();
    let rb = b.post(ser(&leave), None).await;
    held.release();
    let (_a, ra) = ta.await.unwrap();
    assert!(matches!(rb, Response::Posted { .. }), "{rb:?}");
    assert!(matches!(ra, Response::Posted { .. }), "{ra:?}");
}

/// A commit whose sender is removed while it is being checked is not
/// written: it hears that the room moved on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_commit_whose_sender_is_removed_during_its_check_loses() {
    let hold = CheckHold::default();
    let e = env_with(|c| c.commit_check_hold = hold.clone()).await;
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
    // A commit from b that adds people. The hold, not the commit's size,
    // keeps it in its check until a's removal is written.
    let kps = key_packages(&b.prov, 3);
    let (prov, key) = (&b.prov, &b.key);
    let (adds, _, _) = b
        .group
        .as_mut()
        .unwrap()
        .add_members(prov, key, &kps)
        .unwrap();
    let adds = ser(&adds);
    let bkey = b.key.public();
    let held = hold.hold_next();
    let tb = tokio::spawn(async move { b.post(adds, None).await });
    held.reached().await;
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
    held.release();
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

/// Frames `p` gets until the answer to request `id`: whether an entry
/// with exactly `mls` was pushed before it, and the answer.
async fn pushed_before_answer(p: &mut Person, id: u32, mls: &[u8]) -> (bool, Response) {
    let mut pushed = false;
    loop {
        match p.conn.recv().await.expect("connection closed") {
            ServerFrame::Push(Push::Entry { entry, .. }) if entry.mls == mls => pushed = true,
            ServerFrame::Push(_) => {}
            ServerFrame::Resp { id: rid, body } if rid == id => return (pushed, body),
            other => panic!("unexpected {other:?}"),
        }
    }
}

/// A member removed by a commit hears the commit before the server answers
/// anything it asks once the commit is written, so an app told it is no
/// longer a member already holds the commit that removed it, and knows who
/// did.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_member_hears_its_removal_before_a_refusal() {
    let hold = CheckHold::default();
    let e = env_with(|c| c.post_written_hold = hold.clone()).await;
    let mut a = e.admin(SUITE).await;
    let mut b = e.member(&mut a).await;
    let gid = a.gid.unwrap();
    let bkey = b.key.public();
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
    let removal = ser(&c);
    let sent = removal.clone();
    // The removal is written and the lock let go; its answer waits.
    let held = hold.hold_next();
    let ta = tokio::spawn(async move { a.post(sent, None).await });
    held.reached().await;
    b.conn
        .send(&ClientFrame::Req {
            id: 9001,
            body: Request::Fetch {
                group: gid,
                after: 0,
                limit: 10,
            },
        })
        .await;
    let (pushed, answer) = pushed_before_answer(&mut b, 9001, &removal).await;
    held.release();
    let ra = ta.await.unwrap();
    assert!(matches!(ra, Response::Posted { .. }), "{ra:?}");
    assert!(matches!(answer, Response::Refused(_)), "{answer:?}");
    assert!(pushed, "the refusal came before the removal that caused it");
}

/// A message is pushed to the room before the server answers anything
/// asked once it is written: a member never reads past a message it was
/// not yet sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_is_pushed_before_later_answers() {
    let hold = CheckHold::default();
    let e = env_with(|c| c.post_written_hold = hold.clone()).await;
    let mut a = e.admin(SUITE).await;
    let mut b = e.member(&mut a).await;
    let gid = a.gid.unwrap();
    let text = message(&mut a, b"hello");
    let sent = text.clone();
    let held = hold.hold_next();
    let ta = tokio::spawn(async move { a.post(sent, None).await });
    held.reached().await;
    b.conn
        .send(&ClientFrame::Req {
            id: 9002,
            body: Request::Fetch {
                group: gid,
                after: 0,
                limit: 100,
            },
        })
        .await;
    let (pushed, answer) = pushed_before_answer(&mut b, 9002, &text).await;
    held.release();
    let ra = ta.await.unwrap();
    assert!(matches!(ra, Response::Posted { .. }), "{ra:?}");
    assert!(
        matches!(answer, Response::Entries(ref es) if es.iter().any(|x| x.mls == text)),
        "{answer:?}"
    );
    assert!(pushed, "the fetch answered with a message not yet pushed");
}
