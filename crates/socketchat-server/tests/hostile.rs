//! Clients that misbehave on purpose: floods, oversized replies, junk join
//! requests, silent connections, broken writes and account minting.

mod common;

use std::collections::HashSet;
use std::time::Duration;

use common::*;
use openmls::prelude::tls_codec::Serialize as _;
use openmls_rust_crypto::OpenMlsRustCrypto;
use socketchat_core::invite::key_package_blob;
use socketchat_core::keys::KeyPair;
use socketchat_core::suite::SUITE;
use socketchat_proto::msg::{to_frame, ClientFrame, Request, Response, ServerFrame};
use socketchat_proto::{Token, MAX_FRAME};
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

async fn env() -> Env {
    env_with(|_| {}).await
}

impl Env {
    async fn raw(&self) -> Raw {
        let mut c = Raw::connect(self.h.addr, self.h.cert_fpr).await;
        c.hello().await;
        c
    }
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

/// A KeyPackage list encoded the way clients send it.
fn blob(parts: &[Vec<u8>]) -> Vec<u8> {
    to_frame(&parts.to_vec()).unwrap()[4..].to_vec()
}

// ---------- Replies a client never reads ----------

#[tokio::test]
async fn unread_replies_stay_bounded() {
    let e = env().await;
    let mut c = e.raw().await;
    let mut batch = Vec::new();
    for id in 0..10_000u32 {
        batch.extend(
            to_frame(&ClientFrame::Req {
                id,
                body: Request::Challenge,
            })
            .unwrap(),
        );
    }
    // About 2 million requests, and not one reply read.
    let flood = tokio::spawn(async move {
        for _ in 0..200 {
            if c.send_raw(&batch).await.is_err() {
                break;
            }
        }
        c
    });
    let mut most = 0;
    for _ in 0..150 {
        most = most.max(e.h.queued_frames());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // The flood stalls only its own connection.
    let mut other = e.raw().await;
    other.challenge().await;
    flood.abort();
    assert!(most > 0, "the flood never filled the queue");
    assert!(most <= 64, "{most} replies queued for one connection");
}

// ---------- Fetch replies over 1 MiB ----------

#[tokio::test]
async fn big_entries_come_back_across_fetches() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let gid = a.gid.unwrap();
    let mut seqs = Vec::new();
    for fill in [1u8, 2] {
        let ga = a.group.as_mut().unwrap();
        let m = ga
            .create_message(&a.prov, &a.key, &vec![fill; 700_000])
            .unwrap();
        let Response::Posted { seq } = a.post(ser(&m), None).await else {
            panic!()
        };
        seqs.push(seq);
    }
    let mut after = b.last_seq;
    let mut got = Vec::new();
    for _ in 0..3 {
        let r = b
            .conn
            .req(Request::Fetch {
                group: gid,
                after,
                limit: 500,
            })
            .await;
        let Response::Entries(es) = r else {
            panic!("{r:?}")
        };
        assert!(es.len() <= 1, "{} entries in one reply", es.len());
        if let Some(last) = es.last() {
            after = last.seq;
        }
        got.extend(es.into_iter().map(|e| e.seq));
    }
    assert_eq!(got, seqs);
    // The connection is still up.
    let r = b.conn.req(Request::Members { group: gid }).await;
    assert!(matches!(r, Response::Members(_)), "{r:?}");
}

#[tokio::test]
async fn post_refuses_message_too_large_to_fetch() {
    let e = env().await;
    let mut a = e.admin().await;
    let r = a.post(vec![0u8; MAX_FRAME - 200], None).await;
    assert!(
        matches!(r, Response::Refused(ref s) if s.contains("too large")),
        "{r:?}"
    );
}

// ---------- Junk join requests ----------

async fn lodge(e: &Env, a: &mut Person, make: impl FnOnce(&Person) -> Vec<u8>) -> Response {
    let mut c = e.person().await;
    let t = a.invite().await;
    assert_eq!(c.redeem_mailbox(t).await, Response::Ok);
    let key_package = make(&c);
    c.conn
        .req(Request::RedeemInvite {
            token: t,
            key_package,
            mac: [0; 32],
        })
        .await
}

#[tokio::test]
async fn junk_join_blobs_refused() {
    let e = env().await;
    let mut a = e.admin().await;
    let kp = |p: &Person| p.key_package().tls_serialize_detached().unwrap();

    let r = lodge(&e, &mut a, |_| vec![0u8; 60_000]).await;
    assert!(matches!(r, Response::Refused(_)), "60 KB junk: {r:?}");
    let r = lodge(&e, &mut a, |_| vec![1, 2, 3]).await;
    assert!(matches!(r, Response::Refused(_)), "short junk: {r:?}");
    let r = lodge(&e, &mut a, |_| blob(&[vec![7u8; 3000], vec![8u8; 300]])).await;
    assert!(matches!(r, Response::Refused(_)), "a list of junk: {r:?}");
    let r = lodge(&e, &mut a, |p| blob(&[kp(p), kp(p), kp(p)])).await;
    assert!(matches!(r, Response::Refused(_)), "three packages: {r:?}");
    let r = lodge(&e, &mut a, |_| {
        let other = KeyPair::generate();
        key_package_blob(&OpenMlsRustCrypto::default(), &other).unwrap()
    })
    .await;
    assert!(
        matches!(r, Response::Refused(_)),
        "someone else's key: {r:?}"
    );

    let r = lodge(&e, &mut a, |p| key_package_blob(&p.prov, &p.key).unwrap()).await;
    assert_eq!(r, Response::JoinLodged);
    let r = lodge(&e, &mut a, |p| blob(&[kp(p)])).await;
    assert_eq!(r, Response::JoinLodged);
}

#[tokio::test]
async fn many_pending_joins_come_back_in_pages() {
    const N: usize = 380;
    // More joins than one room may have waiting by default.
    let e = env_with(|c| c.max_room_welcomes = 1000).await;
    let mut a = e.admin().await;
    let gid = a.gid.unwrap();
    let mut j = e.raw().await;
    let ch = j.challenge().await;
    let prov = OpenMlsRustCrypto::default();
    for _ in 0..N {
        let t = a.invite().await;
        let k = KeyPair::generate();
        let r = j
            .req(Request::RegisterMailbox {
                token: Some(t),
                key: k.public(),
                sig: auth_sig(&k, &ch),
            })
            .await;
        assert_eq!(r, Response::Ok);
        let r = j
            .req(Request::RedeemInvite {
                token: t,
                key_package: key_package_blob(&prov, &k).unwrap(),
                mac: [0; 32],
            })
            .await;
        assert_eq!(r, Response::JoinLodged);
    }
    let db = e.db();
    let mut seen: HashSet<Token> = HashSet::new();
    let mut pages = 0;
    loop {
        let r = a
            .conn
            .req(Request::PendingJoins {
                group: gid,
                after: None,
            })
            .await;
        let Response::Joins(js) = r else {
            panic!("{r:?}")
        };
        if js.is_empty() {
            break;
        }
        pages += 1;
        let frame = to_frame(&ServerFrame::Resp {
            id: 1,
            body: Response::Joins(js.clone()),
        });
        assert!(frame.is_ok(), "page over the frame limit");
        // Members act on what they got; handled requests leave the list.
        for jr in js {
            assert!(seen.insert(jr.token), "a request came back twice");
            db.execute(
                "DELETE FROM joins WHERE token = ?1",
                [jr.token.0.as_slice()],
            )
            .unwrap();
        }
    }
    assert_eq!(seen.len(), N);
    assert!(pages >= 2, "{pages} pages");
}

// ---------- Silent and idle connections ----------

#[tokio::test]
async fn silent_connection_closed_before_hello() {
    let e = env_with(|c| c.timing.hello = Duration::from_millis(300)).await;
    let mut c = Raw::connect(e.h.addr, e.h.cert_fpr).await;
    let started = std::time::Instant::now();
    assert_eq!(c.recv().await, None);
    assert!(started.elapsed() < Duration::from_secs(3));
    // Saying Hello in time is enough; the deadline does not apply after.
    let mut ok = e.raw().await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    ok.challenge().await;
}

#[tokio::test]
async fn idle_connection_closed() {
    let e = env_with(|c| c.timing.idle = Duration::from_millis(500)).await;
    // Requests keep a connection open.
    let mut busy = e.raw().await;
    for _ in 0..6 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        busy.challenge().await;
    }
    // Silence closes it.
    let mut quiet = e.raw().await;
    quiet.challenge().await;
    let started = std::time::Instant::now();
    assert_eq!(quiet.recv().await, None);
    assert!(started.elapsed() < Duration::from_secs(3));
}

// ---------- A failed request must not lock everyone out ----------

#[tokio::test]
async fn database_lock_survives_a_failed_request() {
    let e = env().await;
    let mut a = e.admin().await;
    let gid = a.gid.unwrap();
    let db = e.db();
    db.execute_batch("ALTER TABLE log RENAME TO log_hidden;")
        .unwrap();
    a.conn
        .send(&ClientFrame::Req {
            id: 999,
            body: Request::Fetch {
                group: gid,
                after: 0,
                limit: 10,
            },
        })
        .await;
    let _ = a.conn.recv().await;
    db.execute_batch("ALTER TABLE log_hidden RENAME TO log;")
        .unwrap();
    // Everyone else is still served.
    let mut c = e.raw().await;
    let ch = c.challenge().await;
    let r = c
        .req(Request::Prove {
            key: a.key.public(),
            sig: auth_sig(&a.key, &ch),
        })
        .await;
    assert_eq!(r, Response::Ok);
}

// ---------- A failed write leaves nothing half done ----------

#[tokio::test]
async fn failed_commit_leaves_group_unchanged() {
    let e = env().await;
    let mut a = e.admin().await;
    let _b = e.member(&mut a).await;
    let db = e.db();
    db.execute_batch(
        "CREATE TRIGGER no_log BEFORE INSERT ON log BEGIN SELECT RAISE(ABORT, 'test'); END;",
    )
    .unwrap();
    let ga = a.group.as_mut().unwrap();
    let (c, _, _) = ga
        .self_update(
            &a.prov,
            &a.key,
            openmls::prelude::LeafNodeParameters::default(),
        )
        .unwrap()
        .into_contents();
    let bytes = ser(&c);
    let r = a.post(bytes.clone(), None).await;
    assert!(matches!(r, Response::Error(_)), "{r:?}");
    db.execute_batch("DROP TRIGGER no_log;").unwrap();
    // The same commit goes through once the write works.
    let r = a.post(bytes, None).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
}

#[tokio::test]
async fn failed_group_create_leaves_nothing() {
    let e = env().await;
    let db = e.db();
    let count = |db: &rusqlite::Connection| -> i64 {
        db.query_row("SELECT count(*) FROM openmls_group_data", [], |r| r.get(0))
            .unwrap()
    };
    let before = count(&db);
    db.execute_batch(
        "CREATE TRIGGER no_group BEFORE INSERT ON groups BEGIN SELECT RAISE(ABORT, 'test'); END;",
    )
    .unwrap();
    let mut a = e.person().await;
    let inv = make_server_invite(e.d.path()).unwrap().token;
    let r = a.create_group(inv, SUITE).await;
    assert!(matches!(r, Response::Error(_)), "{r:?}");
    assert_eq!(count(&db), before, "group state left behind");
    db.execute_batch("DROP TRIGGER no_group;").unwrap();
    assert_eq!(a.create_only(SUITE).await, Response::Ok);
}

// ---------- Account minting ----------

#[tokio::test]
async fn spent_group_invite_registers_no_new_account() {
    let e = env().await;
    let mut a = e.admin().await;
    let t = a.invite().await;
    let mut c = e.person().await;
    assert_eq!(c.redeem_mailbox(t).await, Response::Ok);

    // Someone else holding the link gets no account from it.
    let mut d = e.raw().await;
    let k = KeyPair::generate();
    let ch = d.challenge().await;
    let r = d
        .req(Request::RegisterAccount {
            token: t,
            key: k.public(),
            sig: auth_sig(&k, &ch),
        })
        .await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");

    // The person who redeemed it may register one account, once.
    for (i, want_ok) in [(0, true), (1, false)] {
        let k = KeyPair::generate();
        let ch = c.conn.challenge().await;
        let r = c
            .conn
            .req(Request::RegisterAccount {
                token: t,
                key: k.public(),
                sig: auth_sig(&k, &ch),
            })
            .await;
        assert_eq!(r == Response::Ok, want_ok, "try {i}: {r:?}");
    }
}

#[tokio::test]
async fn unused_group_invite_registers_one_account() {
    let e = env().await;
    let mut a = e.admin().await;
    let t = a.invite().await;
    let mut x = e.raw().await;
    let ch = x.challenge().await;
    let acct = KeyPair::generate();
    let r = x
        .req(Request::RegisterAccount {
            token: t,
            key: acct.public(),
            sig: auth_sig(&acct, &ch),
        })
        .await;
    assert_eq!(r, Response::Ok);
    let mb = KeyPair::generate();
    let r = x
        .req(Request::RegisterMailbox {
            token: Some(t),
            key: mb.public(),
            sig: auth_sig(&mb, &ch),
        })
        .await;
    assert_eq!(r, Response::Ok);
    let again = KeyPair::generate();
    let r = x
        .req(Request::RegisterAccount {
            token: t,
            key: again.public(),
            sig: auth_sig(&again, &ch),
        })
        .await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
}

#[tokio::test]
async fn server_invites_from_members_are_limited() {
    let e = env().await;
    let mut a = e.admin().await;
    for i in 0..5 {
        let r = a.conn.req(Request::CreateInvite { group: None }).await;
        assert!(matches!(r, Response::Invite { .. }), "invite {i}: {r:?}");
    }
    let r = a.conn.req(Request::CreateInvite { group: None }).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    // Group invites are not counted.
    a.invite().await;
    // Once the earlier links have expired, more can be made.
    e.h.advance_clock(2 * 24 * 3600);
    let r = a.conn.req(Request::CreateInvite { group: None }).await;
    assert!(matches!(r, Response::Invite { .. }), "{r:?}");
}
