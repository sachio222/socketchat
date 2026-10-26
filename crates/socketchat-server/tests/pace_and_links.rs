//! Edges of the posting pace and of who may still bring people in: leave
//! requests, links from members who can no longer invite, zero rates and
//! admins' own budget.

mod common;

use common::*;
use openmls_traits::OpenMlsProvider;
use socketchat_core::appmsg::AppMsg;
use socketchat_core::settings::{RoomSettings, WhoCanInvite};
use socketchat_core::suite::{group_context_extensions, SUITE};
use socketchat_proto::msg::{Key, Response};
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
    /// The same data on a new server with its config changed by `f`, as an
    /// operator who edits the file and restarts would.
    async fn restart_with(self, f: impl FnOnce(&mut Config)) -> Env {
        self.h.shutdown();
        let mut cfg = Config::load(self.d.path()).unwrap();
        cfg.listen = "127.0.0.1:0".parse().unwrap();
        f(&mut cfg);
        let h = Server::start(cfg).await.unwrap();
        Env { d: self.d, h }
    }
}

async fn say(p: &mut Person, text: &str) -> Response {
    let m = AppMsg::Text { body: text.into() }.encode();
    let out = p
        .group
        .as_mut()
        .unwrap()
        .create_message(&p.prov, &p.key, &m)
        .unwrap();
    p.post(ser(&out), None).await
}

fn posted(r: &Response) -> bool {
    matches!(r, Response::Posted { .. })
}

async fn set_rules(p: &mut Person, admins: &[Key], s: RoomSettings) -> Response {
    let g = p.group.as_mut().unwrap();
    let bundle = g
        .commit_builder()
        .propose_group_context_extensions(group_context_extensions(admins, &s))
        .unwrap()
        .load_psks(p.prov.storage())
        .unwrap()
        .build(p.prov.rand(), p.prov.crypto(), &p.key, |_| true)
        .unwrap()
        .stage_commit(&p.prov)
        .unwrap();
    let (msg, _, _) = bundle.into_messages();
    let r = p.post(ser(&msg), None).await;
    p.settle(&r);
    r
}

/// Posts `n` requests to leave from `p`, each with `aad` bytes of extra
/// data, and counts the ones the server took.
async fn leaves(p: &mut Person, n: usize, aad: usize) -> usize {
    let mut ok = 0;
    for i in 0..n {
        let g = p.group.as_mut().unwrap();
        g.set_aad(vec![i as u8; aad]);
        let m = g.leave_group(&p.prov, &p.key).unwrap();
        if posted(&p.post(ser(&m), None).await) {
            ok += 1;
        }
    }
    p.group.as_mut().unwrap().set_aad(vec![]);
    ok
}

/// A member held by slow mode can still ask to leave, once an epoch, at
/// the size apps send it; nothing larger and nothing more goes in.
#[tokio::test]
async fn one_request_to_leave_goes_in_while_held_and_no_more() {
    let e = env_with(|_| {}).await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let mut c = e.member(&mut a).await;
    let me = a.key.public();
    assert!(posted(
        &set_rules(&mut a, &[me], RoomSettings::new(WhoCanInvite::Anyone, 3600)).await
    ));
    b.catch_up().await;
    c.catch_up().await;
    assert!(posted(&say(&mut b, "one").await));
    assert!(matches!(
        say(&mut b, "two").await,
        Response::SlowDown { .. }
    ));
    assert_eq!(leaves(&mut b, 20, 0).await, 1, "one honest leave, no more");
    assert!(posted(&say(&mut c, "one").await));
    assert_eq!(leaves(&mut c, 20, 400_000).await, 0, "large leaves");
    assert_eq!(leaves(&mut c, 3, 0).await, 1, "the honest one after");
}

/// An admin made a link, then was made a plain member of an admins-only
/// room: the link no longer lets anyone in.
#[tokio::test]
async fn a_former_admins_link_stops_working_in_an_admins_only_room() {
    let e = env_with(|_| {}).await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let (ka, kb) = (a.key.public(), b.key.public());
    assert!(posted(
        &set_rules(
            &mut a,
            &[ka, kb],
            RoomSettings::new(WhoCanInvite::Admins, 0)
        )
        .await
    ));
    b.catch_up().await;
    let t = b.invite().await;
    assert!(posted(
        &set_rules(&mut a, &[ka], RoomSettings::new(WhoCanInvite::Admins, 0)).await
    ));
    let mut c = e.person().await;
    let r = c.redeem_mailbox(t).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
}

/// A member's link made before the operator let only admins invite stops
/// working once the server starts with that rule.
#[tokio::test]
async fn the_server_rule_covers_links_made_before_it() {
    let e = env_with(|_| {}).await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let members_link = b.invite().await;
    let admins_link = a.invite().await;
    let e = e
        .restart_with(|c| c.members_can_invite_to_rooms = false)
        .await;
    let mut c = e.person().await;
    let r = c.redeem_mailbox(members_link).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    let mut d = e.person().await;
    assert_eq!(d.redeem_mailbox(admins_link).await, Response::Ok);
}

/// 0 for the byte refill means no byte limit, as 0 for the burst means no
/// message limit.
#[tokio::test]
async fn zero_kb_per_second_means_no_byte_limit() {
    let e = env_with(|c| {
        c.rate_kb_per_second = 0;
        c.rate_burst_messages = 1000;
    })
    .await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let body = "x".repeat(200_000);
    for i in 0..30 {
        let r = say(&mut b, &body).await;
        assert!(posted(&r), "{i}: {r:?}");
    }
}

/// 0 seconds a message means no message limit.
#[tokio::test]
async fn zero_seconds_per_message_means_no_message_limit() {
    let e = env_with(|c| {
        c.rate_seconds_per_message = 0;
        c.rate_burst_messages = 2;
    })
    .await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    for i in 0..20 {
        let r = say(&mut b, &format!("{i}")).await;
        assert!(posted(&r), "{i}: {r:?}");
    }
}

/// Admins get ten times a member's budget, not an endless one, and the
/// room's slow mode never holds them.
#[tokio::test]
async fn admins_get_ten_times_the_pace_and_no_slow_mode() {
    let e = env_with(|c| {
        c.rate_burst_messages = 2;
        c.rate_seconds_per_message = 60;
    })
    .await;
    let mut a = e.admin().await;
    let me = a.key.public();
    assert!(posted(
        &set_rules(&mut a, &[me], RoomSettings::new(WhoCanInvite::Anyone, 3600)).await
    ));
    // The settings change was one post; 19 more fit the burst of 20.
    for i in 0..19 {
        let r = say(&mut a, &format!("admin {i}")).await;
        assert!(posted(&r), "{i}: {r:?}");
    }
    let r = say(&mut a, "one too many").await;
    let Response::SlowDown { retry_after_ms } = r else {
        panic!("{r:?}")
    };
    // An admin's refill is ten times a member's: one every 6 seconds.
    assert!(
        (5_000..=6_000).contains(&retry_after_ms),
        "{retry_after_ms}"
    );
}

/// A post refused for another reason after the pace check spends nothing.
#[tokio::test]
async fn a_change_refused_later_spends_no_pace() {
    let e = env_with(|c| {
        c.rate_burst_messages = 1;
        c.rate_seconds_per_message = 600;
    })
    .await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let t = a.invite().await;
    // Cy never redeems the link, so Bo's add is refused.
    let c = e.person().await;
    let r = b.add(c.key_package(), t).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    let r = say(&mut b, "still one left").await;
    assert!(posted(&r), "{r:?}");
}
