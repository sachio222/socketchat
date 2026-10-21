//! Protocol 2 beside protocol 1, the invite list and cancel, and room
//! creation time.

mod common;

use common::*;
use socketchat_core::suite::SUITE;
use socketchat_proto::msg::{GroupId, InviteInfo, Request, Response, ServerFrame};
use socketchat_proto::Token;
use socketchat_server::{init, make_server_invite, Config, Server, ServerHandle};

const GONE: &str = "that link was already used, has expired or was cancelled";

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
    async fn person(&self) -> Person {
        Person::new(self.h.addr, self.h.cert_fpr).await
    }
    async fn raw(&self) -> Raw {
        Raw::connect(self.h.addr, self.h.cert_fpr).await
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
}

/// Makes a group invite and returns its token and expiry.
async fn make_invite(p: &mut Person) -> (Token, u64) {
    match p.conn.req(Request::CreateInvite { group: p.gid }).await {
        Response::Invite {
            token,
            expires_unix,
        } => (token, expires_unix),
        r => panic!("{r:?}"),
    }
}

async fn list(p: &mut Person, server_tokens: Vec<Token>) -> Vec<InviteInfo> {
    match p.conn.req(Request::ListInvites { server_tokens }).await {
        Response::Invites(v) => v,
        r => panic!("{r:?}"),
    }
}

fn sorted(mut v: Vec<InviteInfo>) -> Vec<InviteInfo> {
    v.sort_by_key(|i| i.token.0);
    v
}

#[tokio::test]
async fn hello_1_and_2_are_both_served() {
    let e = env().await;
    let mut c = e.raw().await;
    assert_eq!(
        c.hello_as(1).await,
        Some(ServerFrame::HelloOk { version: 1 })
    );
    let mut c = e.raw().await;
    assert_eq!(
        c.hello_as(2).await,
        Some(ServerFrame::HelloOk { version: 2 })
    );
}

#[tokio::test]
async fn hello_3_gets_mismatch_naming_2() {
    let e = env().await;
    let mut c = e.raw().await;
    assert_eq!(
        c.hello_as(3).await,
        Some(ServerFrame::VersionMismatch { server: 2 })
    );
    assert_eq!(c.recv().await, None);
}

#[tokio::test]
async fn protocol_1_connection_refuses_protocol_2_request() {
    let e = env().await;
    let mut c = e.raw().await;
    assert_eq!(
        c.hello_as(1).await,
        Some(ServerFrame::HelloOk { version: 1 })
    );
    assert_eq!(
        c.req(Request::ListInvites {
            server_tokens: vec![]
        })
        .await,
        Response::Refused("this server needs a newer app for that".into())
    );
    assert!(matches!(
        c.req(Request::Challenge).await,
        Response::Challenge(_)
    ));
}

#[tokio::test]
async fn server_capped_at_1_answers_2_with_mismatch_1() {
    let e = env_with(|c| c.protocol_max = 1).await;
    let mut c = e.raw().await;
    assert_eq!(
        c.hello_as(2).await,
        Some(ServerFrame::VersionMismatch { server: 1 })
    );
    assert_eq!(c.recv().await, None);
    let mut c = e.raw().await;
    assert_eq!(
        c.hello_as(1).await,
        Some(ServerFrame::HelloOk { version: 1 })
    );
}

#[tokio::test]
async fn list_invites_shows_only_my_open_links() {
    let e = env().await;
    let mut ada = e.admin().await;
    let mut bo = e.member(&mut ada).await;
    let (a1, x1) = make_invite(&mut ada).await;
    let (a2, x2) = make_invite(&mut ada).await;
    let (b1, _) = make_invite(&mut bo).await;
    let gid = ada.gid;
    let want = |v: &[(Token, u64)]| {
        sorted(
            v.iter()
                .map(|&(token, expires_unix)| InviteInfo {
                    token,
                    group: gid,
                    expires_unix,
                })
                .collect(),
        )
    };
    let got = sorted(list(&mut ada, vec![]).await);
    assert_eq!(got, want(&[(a1, x1), (a2, x2)]));
    assert!(got.iter().all(|i| i.token != b1));
    // Once one is redeemed it drops off.
    let mut cy = e.person().await;
    assert_eq!(cy.redeem_mailbox(a1).await, Response::Ok);
    let got = list(&mut ada, vec![]).await;
    assert_eq!(got, want(&[(a2, x2)]));
    // Oldest expiry first is the order; Bo sees his own one.
    let got = list(&mut bo, vec![]).await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].token, b1);
}

#[tokio::test]
async fn server_invites_listed_only_by_token() {
    let e = env().await;
    let mut ada = e.admin().await;
    let (token, expires_unix) = match ada.conn.req(Request::CreateInvite { group: None }).await {
        Response::Invite {
            token,
            expires_unix,
        } => (token, expires_unix),
        r => panic!("{r:?}"),
    };
    assert_eq!(list(&mut ada, vec![]).await, vec![]);
    assert_eq!(
        list(&mut ada, vec![token]).await,
        vec![InviteInfo {
            token,
            group: None,
            expires_unix
        }]
    );
    // An unknown token shows nothing.
    assert_eq!(list(&mut ada, vec![Token([7; 16])]).await, vec![]);
    // A redeemed one drops off.
    let mut newcomer = e.person().await;
    assert_eq!(newcomer.create_group(token, SUITE).await, Response::Ok);
    assert_eq!(list(&mut ada, vec![token]).await, vec![]);
}

#[tokio::test]
async fn list_invites_takes_at_most_100_tokens() {
    let e = env().await;
    let mut ada = e.admin().await;
    let r = ada
        .conn
        .req(Request::ListInvites {
            server_tokens: vec![Token([1; 16]); 101],
        })
        .await;
    assert_eq!(
        r,
        Response::Refused("ask about at most 100 links at a time".into())
    );
    let r = ada
        .conn
        .req(Request::ListInvites {
            server_tokens: vec![Token([1; 16]); 100],
        })
        .await;
    assert_eq!(r, Response::Invites(vec![]));
}

#[tokio::test]
async fn cancel_invite_then_redeem_is_refused() {
    let e = env().await;
    let mut ada = e.admin().await;
    let (t, _) = make_invite(&mut ada).await;
    assert_eq!(
        ada.conn.req(Request::CancelInvite { token: t }).await,
        Response::Ok
    );
    assert_eq!(list(&mut ada, vec![]).await, vec![]);
    let mut c = e.person().await;
    let r = c.redeem_mailbox(t).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    assert_eq!(
        ada.conn.req(Request::CancelInvite { token: t }).await,
        Response::Refused(GONE.into())
    );
}

#[tokio::test]
async fn cancel_server_invite_needs_an_account_and_keeps_the_quota() {
    let e = env().await;
    let mut ada = e.admin().await;
    let token = match ada.conn.req(Request::CreateInvite { group: None }).await {
        Response::Invite { token, .. } => token,
        r => panic!("{r:?}"),
    };
    // A connection with no proof cannot cancel it.
    let mut anon = e.raw().await;
    anon.hello().await;
    assert_eq!(
        anon.req(Request::CancelInvite { token }).await,
        Response::Refused(GONE.into())
    );
    assert_eq!(
        ada.conn.req(Request::CancelInvite { token }).await,
        Response::Ok
    );
    let mut c = e.person().await;
    // Registering with a cancelled link is refused.
    let acct = socketchat_core::keys::KeyPair::generate();
    let ch = c.conn.challenge().await;
    let r = c
        .conn
        .req(Request::RegisterAccount {
            token,
            key: acct.public(),
            sig: auth_sig(&acct, &ch),
        })
        .await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    // The quota stays spent: four more fit, the sixth is refused (one used
    // by the admin's own invite when the group was made does not count).
    let mut made = 1;
    loop {
        match ada.conn.req(Request::CreateInvite { group: None }).await {
            Response::Invite { .. } => made += 1,
            Response::Refused(_) => break,
            r => panic!("{r:?}"),
        }
        assert!(made <= 5, "quota not enforced");
    }
    assert_eq!(made, 5);
}

#[tokio::test]
async fn cancel_needs_the_maker() {
    let e = env().await;
    let mut ada = e.admin().await;
    let mut bo = e.member(&mut ada).await;
    let (t, _) = make_invite(&mut ada).await;
    assert_eq!(
        bo.conn.req(Request::CancelInvite { token: t }).await,
        Response::Refused(GONE.into())
    );
    let mut c = e.person().await;
    assert_eq!(c.redeem_mailbox(t).await, Response::Ok);
}

#[tokio::test]
async fn group_created_returns_creation_time() {
    let e = env().await;
    let mut ada = e.admin().await;
    let gid: GroupId = ada.gid.unwrap();
    let r = ada.conn.req(Request::GroupCreated { group: gid }).await;
    let Response::GroupCreated { created_unix } = r else {
        panic!("{r:?}")
    };
    let db = rusqlite::Connection::open(e.d.path().join("server.db")).unwrap();
    let row: i64 = db
        .query_row(
            "SELECT created_unix FROM groups WHERE id = ?1",
            [gid.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(created_unix, row as u64);
    assert!(created_unix > 1_700_000_000);
    // Someone who is not a member is refused.
    let mut out = e.person().await;
    assert_eq!(
        out.conn.req(Request::GroupCreated { group: gid }).await,
        Response::Refused("you are not a member of this group".into())
    );
}

fn count(db: &rusqlite::Connection, table: &str, gid: GroupId) -> i64 {
    let col = if table == "groups" { "id" } else { "group_id" };
    db.query_row(
        &format!("SELECT count(*) FROM {table} WHERE {col} = ?1"),
        [gid.0.as_slice()],
        |r| r.get(0),
    )
    .unwrap()
}

fn mls_group_loads(db: &rusqlite::Connection, gid: GroupId) -> bool {
    use openmls::prelude::{GroupId as MlsGid, PublicGroup};
    let storage = openmls_sqlite_storage::SqliteStorageProvider::<
        socketchat_core::provider::JsonCodec,
        &rusqlite::Connection,
    >::new(db);
    PublicGroup::load(&storage, &MlsGid::from_slice(&gid.0))
        .unwrap()
        .is_some()
}

#[tokio::test]
async fn last_leave_deletes_everything() {
    let e = env().await;
    let mut ada = e.admin().await;
    let gid = ada.gid.unwrap();
    let _open = make_invite(&mut ada).await;
    let Response::File(f) = ada
        .conn
        .req(Request::FileBegin {
            group: gid,
            size: 3,
        })
        .await
    else {
        panic!("no file")
    };
    assert_eq!(
        ada.conn
            .req(Request::FileChunk {
                file: f,
                index: 0,
                data: vec![1, 2, 3]
            })
            .await,
        Response::Ok
    );
    let db = rusqlite::Connection::open(e.d.path().join("server.db")).unwrap();
    db.execute(
        "INSERT INTO log (group_id, seq, mls, created_unix) VALUES (?1, 1, x'00', 1)",
        [gid.0.as_slice()],
    )
    .unwrap();
    db.execute(
        "INSERT INTO joins (token, group_id, mailbox) VALUES (x'07', ?1, x'08')",
        [gid.0.as_slice()],
    )
    .unwrap();
    let chunks =
        e.d.path()
            .join("files")
            .join(f.0.iter().map(|b| format!("{b:02x}")).collect::<String>());
    assert!(chunks.exists());
    for t in ["groups", "log", "mailboxes", "invites", "joins", "files"] {
        assert!(count(&db, t, gid) > 0, "{t} starts empty");
    }
    assert!(mls_group_loads(&db, gid));

    assert_eq!(
        ada.conn.req(Request::LastLeave { group: gid }).await,
        Response::Ok
    );
    for t in ["groups", "log", "mailboxes", "invites", "joins", "files"] {
        assert_eq!(count(&db, t, gid), 0, "{t}");
    }
    assert!(!chunks.exists());
    assert!(!mls_group_loads(&db, gid));
}

#[tokio::test]
async fn last_leave_refused_while_others_remain() {
    let e = env().await;
    let mut ada = e.admin().await;
    let mut bo = e.member(&mut ada).await;
    let gid = ada.gid.unwrap();
    let why = Response::Refused("other people are still in this group".into());
    assert_eq!(ada.conn.req(Request::LastLeave { group: gid }).await, why);
    assert_eq!(bo.conn.req(Request::LastLeave { group: gid }).await, why);
    let db = rusqlite::Connection::open(e.d.path().join("server.db")).unwrap();
    assert_eq!(count(&db, "groups", gid), 1);
    assert!(mls_group_loads(&db, gid));
    // A stranger is not a member at all.
    let mut out = e.person().await;
    assert_eq!(
        out.conn.req(Request::LastLeave { group: gid }).await,
        Response::Refused("you are not a member of this group".into())
    );
}

#[tokio::test]
async fn sweep_deletes_group_with_no_members() {
    let e = env().await;
    let ada = e.admin().await;
    let gid = ada.gid.unwrap();
    let db = rusqlite::Connection::open(e.d.path().join("server.db")).unwrap();
    assert_eq!(count(&db, "groups", gid), 1);
    // A group that still has a member survives the sweep.
    e.h.sweep_now();
    assert_eq!(count(&db, "groups", gid), 1);
    db.execute(
        "DELETE FROM mailboxes WHERE group_id = ?1",
        [gid.0.as_slice()],
    )
    .unwrap();
    e.h.sweep_now();
    assert_eq!(count(&db, "groups", gid), 0);
    assert_eq!(count(&db, "log", gid), 0);
    assert!(!mls_group_loads(&db, gid));
}

#[tokio::test]
async fn last_leave_needs_protocol_2() {
    let e = env().await;
    let ada = e.admin().await;
    let gid = ada.gid.unwrap();
    // The same account's keys on a protocol-1 connection are refused by
    // the version check before anything runs.
    let mut c = e.raw().await;
    assert_eq!(
        c.hello_as(1).await,
        Some(ServerFrame::HelloOk { version: 1 })
    );
    assert_eq!(
        c.req(Request::LastLeave { group: gid }).await,
        Response::Refused("this server needs a newer app for that".into())
    );
    let db = rusqlite::Connection::open(e.d.path().join("server.db")).unwrap();
    assert_eq!(count(&db, "groups", gid), 1);
}
