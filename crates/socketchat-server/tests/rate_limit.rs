//! How fast one member can post in a room: a burst, then a steady pace,
//! counted per member key per room, plus a room's own slow mode.

mod common;

use common::*;
use openmls_traits::OpenMlsProvider;
use socketchat_core::appmsg::AppMsg;
use socketchat_core::settings::{RoomSettings, WhoCanInvite};
use socketchat_core::suite::{admins_from, group_context_extensions, SUITE};
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

/// Posts one encrypted text from `p`.
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

fn wait_ms(r: &Response) -> u32 {
    match r {
        Response::SlowDown { retry_after_ms } => *retry_after_ms,
        r => panic!("expected SlowDown, got {r:?}"),
    }
}

/// The defaults operators get: a burst of 30, then Matrix's one every 5
/// seconds.
#[test]
fn defaults_follow_matrix() {
    let c = Config::default();
    assert_eq!(c.rate_burst_messages, 30);
    assert_eq!(c.rate_seconds_per_message, 5);
}

#[tokio::test]
async fn a_burst_passes_then_the_next_waits_then_refill_lets_it_go() {
    let e = env_with(|c| {
        c.rate_burst_messages = 3;
        c.rate_seconds_per_message = 5;
    })
    .await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    for i in 0..3 {
        let r = say(&mut b, &format!("hi {i}")).await;
        assert!(posted(&r), "{i}: {r:?}");
    }
    let r = say(&mut b, "one too many").await;
    let ms = wait_ms(&r);
    assert!((4_000..=5_000).contains(&ms), "{ms}");
    e.h.advance_clock(5);
    let r = say(&mut b, "now").await;
    assert!(posted(&r), "{r:?}");
    let r = say(&mut b, "and again").await;
    assert!(wait_ms(&r) > 0);
}

/// Admins get a larger pace than members: the app posts on its own for
/// every person an admin brings in. Past ten times a member's burst they
/// are held too (see pace_and_links.rs).
#[tokio::test]
async fn admins_post_past_a_members_burst() {
    let e = env_with(|c| {
        c.rate_burst_messages = 2;
        c.rate_seconds_per_message = 60;
    })
    .await;
    let mut a = e.admin().await;
    for i in 0..10 {
        assert!(posted(&say(&mut a, &format!("admin {i}")).await));
    }
}

/// An app on protocol 2 cannot read `SlowDown`; it hears the wait in
/// words.
#[tokio::test]
async fn an_older_app_hears_the_wait_in_words() {
    let e = env_with(|c| {
        c.rate_burst_messages = 1;
        c.rate_seconds_per_message = 5;
    })
    .await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    assert!(posted(&say(&mut b, "first").await));
    // The same member on a second connection that said Hello as 0.5.1.
    let mut old = Raw::connect(e.h.addr, e.h.cert_fpr).await;
    assert!(matches!(
        old.hello_as(2).await,
        Some(socketchat_proto::msg::ServerFrame::HelloOk { version: 2 })
    ));
    let ch = old.challenge().await;
    assert_eq!(
        old.req(Request::Prove {
            key: b.key.public(),
            sig: auth_sig(&b.key, &ch),
        })
        .await,
        Response::Ok
    );
    let m = AppMsg::Text { body: "x".into() }.encode();
    let out = b
        .group
        .as_mut()
        .unwrap()
        .create_message(&b.prov, &b.key, &m)
        .unwrap();
    let r = old
        .req(Request::Post {
            group: b.gid.unwrap(),
            mls: ser(&out),
            welcome: None,
        })
        .await;
    assert!(
        matches!(r, Response::Refused(ref s) if s.contains("limits fast posting") && s.contains("5 seconds")),
        "{r:?}"
    );
}

/// One member's flood never holds up another member's messages, anyone's
/// leave, or an admin's removal.
#[tokio::test]
async fn a_flood_from_one_member_never_holds_up_anyone_else() {
    let e = env_with(|c| {
        c.rate_burst_messages = 5;
        c.rate_seconds_per_message = 60;
    })
    .await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let mut c = e.member(&mut a).await;
    let mut d = e.member(&mut a).await;
    b.catch_up().await;
    c.catch_up().await;
    d.catch_up().await;
    let mut refused = 0;
    for i in 0..40 {
        let r = say(&mut b, &format!("spam {i}")).await;
        if matches!(r, Response::SlowDown { .. }) {
            refused += 1;
        }
    }
    assert_eq!(refused, 35);
    let started = std::time::Instant::now();
    assert!(posted(&say(&mut c, "still talking").await));
    assert!(posted(&say(&mut a, "me too").await));
    assert!(posted(&say(&mut d, "and me").await));
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    // Bo, out of messages, can still leave.
    let leave = b
        .group
        .as_mut()
        .unwrap()
        .leave_group(&b.prov, &b.key)
        .unwrap();
    let r = b.post(ser(&leave), None).await;
    assert!(posted(&r), "{r:?}");
    // Dee floods too; the admin removes her with no wait.
    for i in 0..10 {
        let _ = say(&mut d, &format!("more {i}")).await;
    }
    a.catch_up().await;
    let dee = a
        .g()
        .members()
        .find(|m| m.signature_key == d.key.public().0)
        .unwrap()
        .index;
    let (commit, _, _) = a
        .group
        .as_mut()
        .unwrap()
        .remove_members(&a.prov, &a.key, &[dee])
        .unwrap();
    let r = a.post(ser(&commit), None).await;
    assert!(posted(&r), "{r:?}");
    a.settle(&r);
}

/// Bytes count too: a member who sends large messages runs out of bytes
/// before messages. One message of the largest size always fits.
#[tokio::test]
async fn large_messages_count_their_bytes() {
    let e = env_with(|c| {
        c.rate_burst_messages = 100;
        c.rate_seconds_per_message = 1;
        c.rate_burst_kb = 1_100;
        c.rate_kb_per_second = 10;
    })
    .await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let big = "x".repeat(600_000);
    assert!(posted(&say(&mut b, &big).await));
    let ms = wait_ms(&say(&mut b, &big).await);
    // About 100 KB short at 10 KB a second.
    assert!((5_000..=20_000).contains(&ms), "{ms}");
    assert!(posted(&say(&mut b, "small still fits").await));
}

/// A burst of 0 turns the limit off.
#[tokio::test]
async fn a_burst_of_zero_turns_the_limit_off() {
    let e = env_with(|c| c.rate_burst_messages = 0).await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    for i in 0..30 {
        assert!(posted(&say(&mut b, &format!("{i}")).await));
    }
}

/// `p` sets the room's slow mode, keeping its admins.
async fn set_slow(p: &mut Person, secs: u32) -> Response {
    let admins = admins_from(p.group.as_ref().unwrap().extensions());
    let g = p.group.as_mut().unwrap();
    let bundle = g
        .commit_builder()
        .propose_group_context_extensions(group_context_extensions(
            &admins,
            &RoomSettings::new(WhoCanInvite::Anyone, secs),
        ))
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

/// Slow mode holds each member who is not an admin to one message per
/// period, stricter than the server's own pace; admins are not held by
/// either.
#[tokio::test]
async fn slow_mode_holds_members_and_not_admins() {
    let e = env_with(|c| {
        c.rate_burst_messages = 10;
        c.rate_seconds_per_message = 5;
    })
    .await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    assert!(posted(&set_slow(&mut a, 30).await));
    b.catch_up().await;
    assert!(posted(&say(&mut b, "one").await));
    let ms = wait_ms(&say(&mut b, "two").await);
    assert!((29_000..=30_000).contains(&ms), "{ms}");
    for i in 0..3 {
        assert!(posted(&say(&mut a, &format!("admin {i}")).await));
    }
    e.h.advance_clock(30);
    assert!(posted(&say(&mut b, "two, later").await));
    // Off again: back to the server's own pace.
    assert!(posted(&set_slow(&mut a, 0).await));
    b.catch_up().await;
    assert!(posted(&say(&mut b, "three").await));
    assert!(posted(&say(&mut b, "four").await));
}

/// The server's pace still applies inside a slow mode looser than it.
#[tokio::test]
async fn the_stricter_limit_wins() {
    let e = env_with(|c| {
        c.rate_burst_messages = 2;
        c.rate_seconds_per_message = 60;
    })
    .await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    assert!(posted(&set_slow(&mut a, 1).await));
    b.catch_up().await;
    assert!(posted(&say(&mut b, "one").await));
    e.h.advance_clock(1);
    assert!(posted(&say(&mut b, "two").await));
    e.h.advance_clock(1);
    let ms = wait_ms(&say(&mut b, "three").await);
    assert!(ms > 50_000, "{ms}");
}

/// A member cannot turn slow mode off for themselves.
#[tokio::test]
async fn slow_mode_cannot_be_lifted_by_a_member() {
    let e = env_with(|_| {}).await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    assert!(posted(&set_slow(&mut a, 60).await));
    b.catch_up().await;
    let r = set_slow(&mut b, 0).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    assert!(posted(&say(&mut b, "one").await));
    assert!(wait_ms(&say(&mut b, "two").await) > 0);
}
