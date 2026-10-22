mod common;

use common::*;
use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;
use socketchat_core::suite::{group_context_extensions, FALLBACK_SUITE, SUITE};
use socketchat_proto::msg::{Push, Request, Response, ServerFrame};
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
    async fn person(&self) -> Person {
        Person::new(self.h.addr, self.h.cert_fpr).await
    }
    async fn admin(&self) -> Person {
        let mut a = self.person().await;
        let inv = make_server_invite(self.d.path()).unwrap().token;
        assert_eq!(a.create_group(inv, SUITE).await, Response::Ok);
        a
    }
    /// A member added by `admin`, already joined.
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

fn members_of(r: Response) -> Vec<socketchat_proto::msg::MemberInfo> {
    match r {
        Response::Members(m) => m,
        r => panic!("{r:?}"),
    }
}

#[tokio::test]
async fn create_group_requires_account() {
    let e = env().await;
    let mut p = e.person().await;
    let ch = p.conn.challenge().await;
    let r = p
        .conn
        .req(Request::RegisterMailbox {
            token: None,
            key: p.key.public(),
            sig: auth_sig(&p.key, &ch),
        })
        .await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    let r = p.create_only(SUITE).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
}

#[tokio::test]
async fn create_group_rejects_wrong_suite() {
    let e = env_with(|c| c.require_standard_suite = true).await;
    let mut a = e.person().await;
    let inv = make_server_invite(e.d.path()).unwrap().token;
    let r = a.create_group(inv, SUITE).await;
    assert!(
        matches!(r, Response::Refused(ref s) if s.contains("suite")),
        "{r:?}"
    );
    let mut b = e.person().await;
    let inv = make_server_invite(e.d.path()).unwrap().token;
    assert_eq!(b.create_group(inv, FALLBACK_SUITE).await, Response::Ok);
}

#[tokio::test]
async fn admin_add_accepted_and_welcome_delivered() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.person().await;
    let t = a.invite().await;
    assert_eq!(b.redeem_mailbox(t).await, Response::Ok);
    let r = a.add(b.key_package(), t).await;
    assert!(matches!(r, Response::Posted { seq: 1 }), "{r:?}");
    // Bob's connection got the Welcome pushed.
    match b.conn.recv().await {
        Some(ServerFrame::Push(Push::Welcome(w))) => assert_eq!(w.mailbox, b.key.public()),
        f => panic!("{f:?}"),
    }
    b.join_from_welcome(a.gid.unwrap()).await;
    assert_eq!(b.g().epoch(), a.g().epoch());
    let ms = members_of(
        a.conn
            .req(Request::Members {
                group: a.gid.unwrap(),
            })
            .await,
    );
    assert_eq!(ms.len(), 2);
    // The redeemed token is spent.
    let mut c = e.person().await;
    let r = c.redeem_mailbox(t).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
}

#[tokio::test]
async fn non_admin_add_refused() {
    let e = env_with(|c| c.members_can_invite = false).await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let mut c = e.person().await;
    let t = a.invite().await;
    assert_eq!(c.redeem_mailbox(t).await, Response::Ok);
    let r = b.add(c.key_package(), t).await;
    assert!(
        matches!(r, Response::Refused(ref s) if s.contains("admin")),
        "{r:?}"
    );
}

#[tokio::test]
async fn self_update_by_member_accepted() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let g = b.group.as_mut().unwrap();
    let (c, _, _) = g
        .self_update(&b.prov, &b.key, LeafNodeParameters::default())
        .unwrap()
        .into_contents();
    let r = b.post(ser(&c), None).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
    b.settle(&r);
    a.catch_up().await;
    assert_eq!(a.g().epoch(), b.g().epoch());
}

#[tokio::test]
async fn stale_commit_gets_conflict() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let ga = a.group.as_mut().unwrap();
    let (c1, _, _) = ga
        .self_update(&a.prov, &a.key, LeafNodeParameters::default())
        .unwrap()
        .into_contents();
    let gb = b.group.as_mut().unwrap();
    let (c2, _, _) = gb
        .self_update(&b.prov, &b.key, LeafNodeParameters::default())
        .unwrap()
        .into_contents();
    let r1 = a.post(ser(&c1), None).await;
    assert!(matches!(r1, Response::Posted { .. }), "{r1:?}");
    a.settle(&r1);
    let r2 = b.post(ser(&c2), None).await;
    let Response::Conflict { epoch } = r2 else {
        panic!("{r2:?}")
    };
    assert_eq!(epoch, a.g().epoch().as_u64());
    b.settle(&r2);
    b.catch_up().await;
    assert_eq!(b.g().epoch(), a.g().epoch());
}

#[tokio::test]
async fn self_remove_proposal_then_commit_accepted() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let gb = b.group.as_mut().unwrap();
    let leave = gb.leave_group(&b.prov, &b.key).unwrap();
    let r = b.post(ser(&leave), None).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
    a.catch_up().await;
    let ga = a.group.as_mut().unwrap();
    let (c, _, _) = ga.commit_to_pending_proposals(&a.prov, &a.key).unwrap();
    let r = a.post(ser(&c), None).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
    a.settle(&r);
    let ms = members_of(
        a.conn
            .req(Request::Members {
                group: a.gid.unwrap(),
            })
            .await,
    );
    assert_eq!(ms.len(), 1);
    // Bob's mailbox is gone from the group.
    let r = b
        .conn
        .req(Request::Fetch {
            group: a.gid.unwrap(),
            after: 0,
            limit: 10,
        })
        .await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
}

#[tokio::test]
async fn non_self_remove_proposal_refused() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let gb = b.group.as_mut().unwrap();
    let (p, _) = gb
        .propose_remove_member(&b.prov, &b.key, LeafNodeIndex::new(0))
        .unwrap();
    let r = b.post(ser(&p), None).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
}

#[tokio::test]
async fn last_admin_leave_must_promote_longest_standing() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let mut c = e.member(&mut a).await;
    b.catch_up().await;
    // Alice, the only admin, leaves.
    let ga = a.group.as_mut().unwrap();
    let leave = ga.leave_group(&a.prov, &a.key).unwrap();
    assert!(matches!(
        a.post(ser(&leave), None).await,
        Response::Posted { .. }
    ));
    b.catch_up().await;
    c.catch_up().await;
    // Carol promotes herself: refused, Bob joined first.
    let cc = c.group.as_mut().unwrap();
    let bundle = cc
        .commit_builder()
        .propose_group_context_extensions(group_context_extensions(&[c.key.public()]))
        .unwrap()
        .load_psks(c.prov.storage())
        .unwrap()
        .build(c.prov.rand(), c.prov.crypto(), &c.key, |_| true)
        .unwrap()
        .stage_commit(&c.prov)
        .unwrap();
    let (msg, _, _) = bundle.into_messages();
    let r = c.post(ser(&msg), None).await;
    assert!(
        matches!(r, Response::Refused(ref s) if s.contains("admin")),
        "{r:?}"
    );
    c.settle(&r);
    // Carol promotes Bob: accepted.
    let cc = c.group.as_mut().unwrap();
    let bundle = cc
        .commit_builder()
        .propose_group_context_extensions(group_context_extensions(&[b.key.public()]))
        .unwrap()
        .load_psks(c.prov.storage())
        .unwrap()
        .build(c.prov.rand(), c.prov.crypto(), &c.key, |_| true)
        .unwrap()
        .stage_commit(&c.prov)
        .unwrap();
    let (msg, _, _) = bundle.into_messages();
    let r = c.post(ser(&msg), None).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
    c.settle(&r);
    let ms = members_of(
        b.conn
            .req(Request::Members {
                group: a.gid.unwrap(),
            })
            .await,
    );
    assert_eq!(ms.len(), 2);
}

#[tokio::test]
async fn last_admin_leave_without_promotion_refused() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let ga = a.group.as_mut().unwrap();
    let leave = ga.leave_group(&a.prov, &a.key).unwrap();
    assert!(matches!(
        a.post(ser(&leave), None).await,
        Response::Posted { .. }
    ));
    b.catch_up().await;
    let gb = b.group.as_mut().unwrap();
    let (c, _, _) = gb.commit_to_pending_proposals(&b.prov, &b.key).unwrap();
    let r = b.post(ser(&c), None).await;
    assert!(
        matches!(r, Response::Refused(ref s) if s.contains("admin")),
        "{r:?}"
    );
}

#[tokio::test]
async fn private_message_from_non_member_refused() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut c = e.person().await;
    let t = a.invite().await;
    assert_eq!(c.redeem_mailbox(t).await, Response::Ok);
    // Carol has a mailbox for the group but was never added.
    let ga = a.group.as_mut().unwrap();
    let m = ga.create_message(&a.prov, &a.key, b"hi").unwrap();
    c.gid = a.gid;
    let r = c.post(ser(&m), None).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    let r = c
        .conn
        .req(Request::Fetch {
            group: a.gid.unwrap(),
            after: 0,
            limit: 10,
        })
        .await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
}

#[tokio::test]
async fn entries_deleted_after_all_ack() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let gid = a.gid.unwrap();
    let ga = a.group.as_mut().unwrap();
    let m = ga.create_message(&a.prov, &a.key, b"hello").unwrap();
    let Response::Posted { seq } = a.post(ser(&m), None).await else {
        panic!()
    };
    let db = rusqlite::Connection::open(e.d.path().join("server.db")).unwrap();
    let count = |db: &rusqlite::Connection| -> i64 {
        db.query_row(
            "SELECT count(*) FROM log WHERE seq <= ?1",
            [seq as i64],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert!(count(&db) > 0);
    assert_eq!(
        a.conn.req(Request::Ack { group: gid, seq }).await,
        Response::Ok
    );
    assert!(count(&db) > 0, "Bob has not acknowledged yet");
    assert_eq!(
        b.conn.req(Request::Ack { group: gid, seq }).await,
        Response::Ok
    );
    assert_eq!(count(&db), 0);
}

#[tokio::test]
async fn push_reaches_connected_member() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let ga = a.group.as_mut().unwrap();
    let m = ga.create_message(&a.prov, &a.key, b"pushed").unwrap();
    let bytes = ser(&m);
    let Response::Posted { seq } = a.post(bytes.clone(), None).await else {
        panic!()
    };
    loop {
        match b.conn.recv().await {
            Some(ServerFrame::Push(Push::Entry { group, entry })) if entry.seq == seq => {
                assert_eq!(group, a.gid.unwrap());
                assert_eq!(entry.mls, bytes);
                break;
            }
            Some(ServerFrame::Push(_)) => continue,
            f => panic!("{f:?}"),
        }
    }
}

#[tokio::test]
async fn garbage_post_refused() {
    let e = env().await;
    let mut a = e.admin().await;
    let r = a.post(vec![1, 2, 3], None).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    let _ = a.g().export_ratchet_tree().tls_serialize_detached();
    let _ = a.prov.storage();
}

#[tokio::test]
async fn member_add_allowed_when_members_can_invite() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let mut c = e.person().await;
    let t = a.invite().await;
    assert_eq!(c.redeem_mailbox(t).await, Response::Ok);
    let r = b.add(c.key_package(), t).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
}

#[tokio::test]
async fn member_cannot_remove_others_even_when_members_can_invite() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let gb = b.group.as_mut().unwrap();
    let (c, _, _) = gb
        .remove_members(&b.prov, &b.key, &[LeafNodeIndex::new(0)])
        .unwrap();
    let r = b.post(ser(&c), None).await;
    assert!(
        matches!(r, Response::Refused(ref s) if s.contains("admin")),
        "{r:?}"
    );
}

// ---------- after someone leaves or is removed ----------

fn leaf_of(g: &MlsGroup, k: &socketchat_core::keys::KeyPair) -> LeafNodeIndex {
    g.members()
        .find(|m| m.signature_key == k.public().0)
        .unwrap()
        .index
}

/// `admin` gives the admin role to `member` as well.
async fn share_admin(admin: &mut Person, member: &mut Person) {
    let bundle = admin
        .group
        .as_mut()
        .unwrap()
        .commit_builder()
        .propose_group_context_extensions(group_context_extensions(&[
            admin.key.public(),
            member.key.public(),
        ]))
        .unwrap()
        .load_psks(admin.prov.storage())
        .unwrap()
        .build(admin.prov.rand(), admin.prov.crypto(), &admin.key, |_| true)
        .unwrap()
        .stage_commit(&admin.prov)
        .unwrap();
    let (msg, _, _) = bundle.into_messages();
    let r = admin.post(ser(&msg), None).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
    admin.settle(&r);
    member.catch_up().await;
}

/// `admin` removes `who` from the group.
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

/// A person who comes back with `who`'s group key on a new connection.
async fn with_key_of(e: &Env, who: &Person) -> Person {
    let mut p = e.person().await;
    p.key = who.key.clone();
    p
}

#[tokio::test]
async fn removed_members_links_stop_working() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let t = b.invite().await;
    remove(&mut a, &b).await;
    let mut c = e.person().await;
    let r = c.redeem_mailbox(t).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
}

#[tokio::test]
async fn links_of_a_member_who_left_stop_working() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let t = b.invite().await;
    let gb = b.group.as_mut().unwrap();
    let leave = gb.leave_group(&b.prov, &b.key).unwrap();
    let r = b.post(ser(&leave), None).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
    a.catch_up().await;
    let ga = a.group.as_mut().unwrap();
    let (c, _, _) = ga.commit_to_pending_proposals(&a.prov, &a.key).unwrap();
    let r = a.post(ser(&c), None).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
    a.settle(&r);
    let mut c = e.person().await;
    let r = c.redeem_mailbox(t).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
}

#[tokio::test]
async fn removed_key_cannot_register_again() {
    let e = env().await;
    let mut a = e.admin().await;
    let b = e.member(&mut a).await;
    remove(&mut a, &b).await;
    // A link from an admin still in the room does not take the old key.
    let t = a.invite().await;
    let mut back = with_key_of(&e, &b).await;
    let r = back.redeem_mailbox(t).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    // The link still works for a fresh key.
    let mut c = e.person().await;
    assert_eq!(c.redeem_mailbox(t).await, Response::Ok);
}

/// A removed admin cannot come back through a link they made while in the
/// room, with their old key or a new one.
#[tokio::test]
async fn removed_admin_cannot_come_back_through_their_own_link() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    share_admin(&mut a, &mut b).await;
    let t = b.invite().await;
    remove(&mut a, &b).await;
    let mut back = with_key_of(&e, &b).await;
    let r = back.redeem_mailbox(t).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    let mut fresh = e.person().await;
    let r = fresh.redeem_mailbox(t).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
}

/// Removing one member leaves everyone else's links working.
#[tokio::test]
async fn other_links_outlive_a_removal() {
    let e = env().await;
    let mut a = e.admin().await;
    let b = e.member(&mut a).await;
    let mut c = e.member(&mut a).await;
    let ta = a.invite().await;
    let tc = c.invite().await;
    remove(&mut a, &b).await;
    c.catch_up().await;
    let mut d = e.person().await;
    assert_eq!(d.redeem_mailbox(ta).await, Response::Ok);
    let r = a.add(d.key_package(), ta).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
    c.catch_up().await;
    let mut f = e.person().await;
    assert_eq!(f.redeem_mailbox(tc).await, Response::Ok);
    let r = c.add(f.key_package(), tc).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
}

/// When a room goes, the server forgets the keys of the people who left it.
#[tokio::test]
async fn ending_a_room_forgets_who_left_it() {
    let e = env().await;
    let mut a = e.admin().await;
    let b = e.member(&mut a).await;
    remove(&mut a, &b).await;
    let db = rusqlite::Connection::open(e.d.path().join("server.db")).unwrap();
    let held = |db: &rusqlite::Connection| -> i64 {
        db.query_row("SELECT COUNT(*) FROM retired_keys", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(held(&db), 1);
    let r = a
        .conn
        .req(Request::LastLeave {
            group: a.gid.unwrap(),
        })
        .await;
    assert_eq!(r, Response::Ok);
    assert_eq!(held(&db), 0);
}

/// `p` redeems `t` and lodges a KeyPackage, as a joiner's app does.
async fn redeem_and_lodge(p: &mut Person, t: socketchat_proto::Token) -> KeyPackage {
    assert_eq!(p.redeem_mailbox(t).await, Response::Ok);
    let kp = p.key_package();
    let bundle = socketchat_proto::msg::to_frame(&vec![kp.tls_serialize_detached().unwrap()])
        .unwrap()[4..]
        .to_vec();
    let r = p
        .conn
        .req(Request::RedeemInvite {
            token: t,
            key_package: bundle,
            mac: [0; 32],
        })
        .await;
    assert_eq!(r, Response::JoinLodged);
    kp
}

/// Whether the server still knows `p`'s key when it signs in again.
async fn known(p: &mut Person) -> bool {
    let ch = p.conn.challenge().await;
    let r = p
        .conn
        .req(Request::Prove {
            key: p.key.public(),
            sig: auth_sig(&p.key, &ch),
        })
        .await;
    r == Response::Ok
}

/// Carol asked to join through Bo's link, then Bo was removed. Nobody can
/// complete that join afterwards, and the server forgets Carol's waiting
/// mailbox.
#[tokio::test]
async fn waiting_join_through_a_removed_members_link_is_dropped() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let t = b.invite().await;
    let mut c = e.person().await;
    let kp = redeem_and_lodge(&mut c, t).await;
    remove(&mut a, &b).await;
    let r = a
        .conn
        .req(Request::PendingJoins {
            group: a.gid.unwrap(),
            after: None,
        })
        .await;
    assert_eq!(r, Response::Joins(vec![]));
    let r = a.add(kp, t).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    assert!(!known(&mut c).await);
}

/// The same holds when the link expired while the join waited and the
/// hourly sweep ran in between.
#[tokio::test]
async fn waiting_join_outlives_its_links_expiry_and_still_drops() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let t = b.invite().await;
    let mut c = e.person().await;
    let kp = redeem_and_lodge(&mut c, t).await;
    e.h.advance_clock(2 * 24 * 3600);
    e.h.sweep_now();
    remove(&mut a, &b).await;
    let r = a.add(kp, t).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    assert!(!known(&mut c).await);
}

/// One commit that adds the joiner and removes the link's maker still
/// delivers the joiner's Welcome.
#[tokio::test]
async fn adding_the_joiner_while_removing_the_maker_delivers_the_welcome() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let t = b.invite().await;
    let mut c = e.person().await;
    let kp = redeem_and_lodge(&mut c, t).await;
    let idx = leaf_of(a.group.as_ref().unwrap(), &b.key);
    let bundle = a
        .group
        .as_mut()
        .unwrap()
        .commit_builder()
        .propose_adds([kp])
        .propose_removals([idx])
        .load_psks(a.prov.storage())
        .unwrap()
        .build(a.prov.rand(), a.prov.crypto(), &a.key, |_| true)
        .unwrap()
        .stage_commit(&a.prov)
        .unwrap();
    let (commit, welcome, _) = bundle.into_messages();
    let r = a
        .post(
            ser(&commit),
            Some(socketchat_proto::msg::WelcomeOut {
                token: t,
                welcome: ser(&welcome.unwrap()),
                voucher: b"v".to_vec(),
            }),
        )
        .await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
    a.settle(&r);
    c.join_from_welcome(a.gid.unwrap()).await;
}
