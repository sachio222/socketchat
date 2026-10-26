//! What the app does while a room holds a member back: it encrypts
//! nothing until the room allows it, so every message after the wait still
//! opens for everyone; a held text never reaches people who were not in
//! the room when it was typed; and settings a server cannot keep are
//! refused.

use socketchat_core::client::{Event, SendOutcome};
use socketchat_core::settings::WhoCanInvite;
use socketchat_proto::msg::GroupId;
use socketchat_testkit::{drain, settle, TestClient, TestServer};

fn texts(c: &TestClient, g: GroupId) -> Vec<String> {
    c.messages(g, 500)
        .into_iter()
        .filter(|l| !l.notice)
        .map(|l| format!("{}: {}", l.sender, l.text))
        .collect()
}

/// Ada's room "Room" with Bo in it, in slow mode of 600 seconds. Bo has
/// sent his one message for this period, then Ada added Cy, so Bo's app
/// owes Cy his profile while the room holds him.
async fn bo_held_and_owing(s: &TestServer) -> (GroupId, TestClient, TestClient, TestClient) {
    let mut a = TestClient::new(s, "Ada").await;
    let g = a.create_group("Room").await.unwrap();
    let mut b = TestClient::new(s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    a.set_slow_mode(g, 600).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    s.handle.advance_clock(601);
    b.advance_clock(601);
    assert_eq!(b.send_text(g, "first").await.unwrap(), SendOutcome::Sent);
    let mut c = TestClient::new(s, "Cy").await;
    c.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    for _ in 0..3 {
        a.sync().await.unwrap();
        c.sync().await.unwrap();
    }
    (g, a, b, c)
}

/// Bo's app syncs `syncs` times while held, then sends "after" once the
/// room allows it. Returns what Ada reads.
async fn after_held_syncs(syncs: usize) -> Vec<String> {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = bo_held_and_owing(&s).await;
    for _ in 0..syncs {
        b.sync().await.unwrap();
    }
    s.handle.advance_clock(601);
    b.advance_clock(601);
    b.sync().await.unwrap();
    s.handle.advance_clock(601);
    b.advance_clock(601);
    let _ = b.send_text(g, "after").await.unwrap();
    for _ in 0..3 {
        a.sync().await.unwrap();
        c.sync().await.unwrap();
    }
    let _ = drain(&mut a).await;
    texts(&a, g)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_message_after_a_few_held_syncs_arrives() {
    let t = after_held_syncs(10).await;
    assert!(t.contains(&"Bo: after".to_string()), "{t:?}");
}

/// More held syncs than OpenMLS lets a sender's keys run ahead in one
/// epoch: the message after the wait still opens for everyone.
#[tokio::test(flavor = "multi_thread")]
async fn a_message_after_many_held_syncs_still_arrives() {
    let t = after_held_syncs(1100).await;
    assert!(t.contains(&"Bo: after".to_string()), "{t:?}");
}

/// While the room holds Bo, his syncs and his typing encrypt nothing.
#[tokio::test]
async fn a_held_member_encrypts_nothing() {
    let s = TestServer::start().await;
    let (g, _a, mut b, _c) = bo_held_and_owing(&s).await;
    b.sync().await.unwrap();
    let before = b.test_encrypted();
    for _ in 0..5 {
        b.sync().await.unwrap();
    }
    assert!(matches!(
        b.send_text(g, "waits").await.unwrap(),
        SendOutcome::Held { .. }
    ));
    b.sync().await.unwrap();
    assert_eq!(b.test_encrypted(), before);
}

/// A server on protocol 2 stands in for one from before 0.5.2: it cannot
/// keep room settings, so the app refuses to set them.
#[tokio::test]
async fn settings_refused_on_protocol_2_server() {
    let s = TestServer::start_with(|c| c.protocol_max = 2).await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Room").await.unwrap();
    let want = "This server runs an older version of Socketchat, so it can't keep this setting. Ask the person who runs it to update.";
    let e = a
        .set_who_can_invite(g, WhoCanInvite::Admins)
        .await
        .unwrap_err();
    assert_eq!(e.to_string(), want);
    let e = a.set_slow_mode(g, 30).await.unwrap_err();
    assert_eq!(e.to_string(), want);
    // The defaults need nothing from the server.
    a.set_slow_mode(g, 0).await.unwrap();
}

/// A held text waits for the people who were in the room when it was
/// typed: once someone joins or leaves, it is not sent, and the app hands
/// it back.
#[tokio::test]
async fn a_held_text_is_not_sent_to_a_changed_room() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Room").await.unwrap();
    let mut b = TestClient::new(&s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    a.set_slow_mode(g, 60).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    s.handle.advance_clock(61);
    b.advance_clock(61);
    assert_eq!(b.send_text(g, "one").await.unwrap(), SendOutcome::Sent);
    assert!(matches!(
        b.send_text(g, "only for Ada").await.unwrap(),
        SendOutcome::Held { .. }
    ));
    let _ = drain(&mut b).await;
    let mut c = TestClient::new(&s, "Cy").await;
    c.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    for _ in 0..3 {
        a.sync().await.unwrap();
        c.sync().await.unwrap();
    }
    s.handle.advance_clock(61);
    b.advance_clock(61);
    b.sync().await.unwrap();
    assert_eq!(b.held(g), 0);
    let ev = drain(&mut b).await;
    assert!(
        ev.iter().any(|e| matches!(
            e,
            Event::NotSent { group, text } if *group == g && text == "only for Ada"
        )),
        "{ev:?}"
    );
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert!(!texts(&c, g).contains(&"Bo: only for Ada".to_string()));
    assert!(!texts(&a, g).contains(&"Bo: only for Ada".to_string()));
}

/// A member's link, used before the operator let only admins invite, is
/// not completed by an admin's app afterwards.
#[tokio::test]
async fn an_admin_does_not_complete_a_members_link_under_the_server_rule() {
    let mut s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Room").await.unwrap();
    let mut b = TestClient::new(&s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let link = b.invite(Some(g), false).await.unwrap().0;
    settle(&mut [&mut a, &mut b]).await;
    // Bo goes away, so only Ada's app could add Dee.
    drop(b);
    let mut d = TestClient::profile_only("Dee").await;
    d.join(&link).await.unwrap();
    s.restart_with(|c| c.members_can_invite_to_rooms = false)
        .await;
    for _ in 0..3 {
        a.sync().await.unwrap();
        d.sync().await.unwrap();
    }
    assert_eq!(a.members(g).len(), 2, "{:?}", a.members(g));
}

/// The same link used after the server took up the rule is refused.
#[tokio::test]
async fn a_members_link_is_refused_once_the_server_rule_is_on() {
    let mut s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Room").await.unwrap();
    let mut b = TestClient::new(&s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let link = b.invite(Some(g), false).await.unwrap().0;
    s.restart_with(|c| c.members_can_invite_to_rooms = false)
        .await;
    let mut d = TestClient::profile_only("Dee").await;
    assert!(d.join(&link).await.is_err());
    for _ in 0..3 {
        a.sync().await.unwrap();
        b.sync().await.unwrap();
    }
    assert_eq!(a.members(g).len(), 2);
}
