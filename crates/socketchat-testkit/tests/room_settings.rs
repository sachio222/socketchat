//! A room's own settings from the apps' side: who can bring people in,
//! slow mode, and how apps hold a message the server says came too fast.

use socketchat_core::client::{Event, SendOutcome};
use socketchat_core::settings::{RoomSettings, WhoCanInvite};
use socketchat_core::CoreError;
use socketchat_proto::msg::GroupId;
use socketchat_testkit::{drain, settle, TestClient, TestServer};

fn texts(c: &TestClient, g: GroupId) -> Vec<String> {
    c.messages(g, 200)
        .into_iter()
        .filter(|l| !l.notice)
        .map(|l| format!("{}: {}", l.sender, l.text))
        .collect()
}

fn notices(c: &TestClient, g: GroupId) -> Vec<String> {
    c.messages(g, 200)
        .into_iter()
        .filter(|l| l.notice)
        .map(|l| l.text)
        .collect()
}

fn warnings(events: &[Event]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Warning(w) => Some(w.clone()),
            _ => None,
        })
        .collect()
}

/// Ada's room with Bo and Cy in it; Ada is its only admin. Events so far
/// are drained.
async fn trio(s: &TestServer) -> (GroupId, TestClient, TestClient, TestClient) {
    let mut a = TestClient::new(s, "Ada").await;
    let g = a.create_group("Room").await.unwrap();
    let mut b = TestClient::new(s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let mut c = TestClient::new(s, "Cy").await;
    c.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    for x in [&mut a, &mut b, &mut c] {
        drain(x).await;
    }
    (g, a, b, c)
}

fn settings_of(c: &TestClient, g: GroupId) -> RoomSettings {
    c.room_settings(g).expect("in the room")
}

#[tokio::test]
async fn a_new_room_lets_anyone_invite_with_no_slow_mode() {
    let s = TestServer::start().await;
    let (g, mut a, _b, _c) = trio(&s).await;
    assert_eq!(settings_of(&a, g), RoomSettings::default());
    let d = a.details(g).await.unwrap();
    assert_eq!(d.invite, WhoCanInvite::Anyone);
    assert_eq!(d.slow_secs, 0);
    assert_eq!(d.server_enforces, Some(true));
}

#[tokio::test]
async fn admin_lets_only_admins_invite_and_everyone_sees_it() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    a.set_who_can_invite(g, WhoCanInvite::Admins).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    for x in [&mut a, &mut b, &mut c] {
        assert_eq!(settings_of(x, g).invite, WhoCanInvite::Admins);
        assert_eq!(x.details(g).await.unwrap().invite, WhoCanInvite::Admins);
        assert!(warnings(&drain(x).await).is_empty());
    }
    assert!(notices(&a, g).contains(&"You let only admins invite people to this room.".into()));
    for x in [&b, &c] {
        assert!(
            notices(x, g).contains(&"Ada let only admins invite people to this room.".into()),
            "{:?}",
            notices(x, g)
        );
    }
    a.set_who_can_invite(g, WhoCanInvite::Anyone).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert_eq!(settings_of(&b, g).invite, WhoCanInvite::Anyone);
    assert!(notices(&b, g).contains(&"Ada let anyone in the room invite people.".into()));
}

#[tokio::test]
async fn a_member_cannot_change_the_settings() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, _c) = trio(&s).await;
    let e = b
        .set_who_can_invite(g, WhoCanInvite::Admins)
        .await
        .unwrap_err();
    assert_eq!(
        e.to_string(),
        "Only admins can change this room's settings."
    );
    let e = b.set_slow_mode(g, 30).await.unwrap_err();
    assert_eq!(
        e.to_string(),
        "Only admins can change this room's settings."
    );
    a.sync().await.unwrap();
    assert_eq!(settings_of(&a, g), RoomSettings::default());
}

#[tokio::test]
async fn in_an_admins_only_room_a_member_cannot_make_a_link() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    a.set_who_can_invite(g, WhoCanInvite::Admins).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    let e = b.invite(Some(g), false).await.unwrap_err();
    assert_eq!(e.to_string(), "In this room only admins can invite people.");
    // An admin's link still brings someone in.
    let mut d = TestClient::new(&s, "Dee").await;
    d.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b, &mut c, &mut d]).await;
    assert_eq!(b.members(g).len(), 4);
    assert_eq!(settings_of(&d, g).invite, WhoCanInvite::Admins);
}

/// A member's change to the settings that reaches the log past the server
/// changes nothing in any app.
#[tokio::test]
async fn a_forged_settings_change_is_refused_by_every_app() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    let epoch = a.epoch(g);
    let forged = b
        .test_unchecked_settings(g, &RoomSettings::new(WhoCanInvite::Admins, 60))
        .unwrap();
    b.test_drop_pending_commit(g);
    socketchat_testkit::append_to_log(&s, g, &forged);
    for x in [&mut a, &mut c] {
        x.sync().await.unwrap();
        x.sync().await.unwrap();
        assert_eq!(x.epoch(g), epoch);
        assert_eq!(settings_of(x, g), RoomSettings::default());
        let w = warnings(&drain(x).await);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("no right"), "{w:?}");
    }
}

/// Nor can a member turn off an admin's settings that way.
#[tokio::test]
async fn a_forged_change_cannot_lift_slow_mode() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    a.set_slow_mode(g, 60).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    let forged = b
        .test_unchecked_settings(g, &RoomSettings::default())
        .unwrap();
    b.test_drop_pending_commit(g);
    socketchat_testkit::append_to_log(&s, g, &forged);
    for x in [&mut a, &mut c] {
        x.sync().await.unwrap();
        assert_eq!(settings_of(x, g).slow_secs, 60);
    }
}

/// In an admins-only room, a member's add that gets past the server is
/// refused by every app.
#[tokio::test]
async fn a_members_add_in_an_admins_only_room_is_refused_by_apps() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    a.set_who_can_invite(g, WhoCanInvite::Admins).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    let epoch = a.epoch(g);
    let add = b
        .test_unchecked_add(g, &socketchat_testkit::forged_key_package_blob())
        .unwrap();
    b.test_drop_pending_commit(g);
    socketchat_testkit::append_to_log(&s, g, &add);
    for x in [&mut a, &mut c] {
        x.sync().await.unwrap();
        assert_eq!(x.epoch(g), epoch);
        assert_eq!(x.members(g).len(), 3);
        assert!(warnings(&drain(x).await)[0].contains("no right"));
    }
}

/// A former admin's change, made after their removal, is ignored.
#[tokio::test]
async fn a_removed_admins_late_change_is_ignored() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    let bk = b.my_group_key(g).unwrap();
    a.make_admin(g, &bk).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    // Bo's app makes its change against the room as it was; Ada removes
    // him first.
    let late = b
        .test_unchecked_settings(g, &RoomSettings::new(WhoCanInvite::Admins, 0))
        .unwrap();
    a.remove_member(g, &bk).await.unwrap();
    settle(&mut [&mut a, &mut c]).await;
    socketchat_testkit::append_to_log(&s, g, &late);
    for x in [&mut a, &mut c] {
        x.sync().await.unwrap();
        assert_eq!(settings_of(x, g), RoomSettings::default());
        assert_eq!(x.members(g).len(), 2);
    }
}

/// The settings stay when an admin is made and when the last admin leaves.
#[tokio::test]
async fn settings_survive_admin_changes() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    a.set_who_can_invite(g, WhoCanInvite::Admins).await.unwrap();
    a.set_slow_mode(g, 20).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    let ck = c.my_group_key(g).unwrap();
    a.make_admin(g, &ck).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    let want = RoomSettings::new(WhoCanInvite::Admins, 20);
    assert_eq!(settings_of(&b, g), want);
    a.leave(g).await.unwrap();
    c.leave(g).await.unwrap();
    for _ in 0..4 {
        b.sync().await.unwrap();
    }
    let ms = b.members(g);
    assert_eq!(ms.len(), 1, "{ms:?}");
    assert!(ms[0].admin);
    assert_eq!(settings_of(&b, g), want);
}

/// While someone's app predates settings, no setting can change, and the
/// admin hears who is holding it up.
#[tokio::test]
async fn settings_wait_for_everyones_app() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Room").await.unwrap();
    let mut b = TestClient::new(&s, "Bo").await;
    b.test_old_capabilities(true);
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let e = a
        .set_who_can_invite(g, WhoCanInvite::Admins)
        .await
        .unwrap_err();
    assert_eq!(
        e.to_string(),
        "Everyone here needs Socketchat 0.5.2 or later, opened once since updating, before this setting can change. Not ready yet: Bo."
    );
    assert_eq!(settings_of(&a, g), RoomSettings::default());
    // Bo updates: his app refreshes its keys with the new capabilities on
    // its own, and then the change goes.
    b.test_old_capabilities(false);
    settle(&mut [&mut a, &mut b]).await;
    a.set_who_can_invite(g, WhoCanInvite::Admins).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(settings_of(&b, g).invite, WhoCanInvite::Admins);
}

/// A server on protocol 2 stands in for a 0.5.1 server: the details say it
/// cannot enforce the settings.
#[tokio::test]
async fn details_say_when_the_server_is_too_old_to_enforce() {
    let s = TestServer::start_with(|c| c.protocol_max = 2).await;
    let (g, mut a, _b, _c) = trio(&s).await;
    let d = a.details(g).await.unwrap();
    assert_eq!(d.server_enforces, Some(false));
}

// ---------- posting too fast ----------

/// Ada's room "Room" with Bo in it, on a server that allows a burst of
/// two posts, then one every 5 seconds. Bo's join used his burst.
async fn tight_pair() -> (TestServer, GroupId, TestClient, TestClient) {
    let s = TestServer::start_with(|c| {
        c.rate_burst_messages = 2;
        c.rate_seconds_per_message = 5;
    })
    .await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Room").await.unwrap();
    let mut b = TestClient::new(&s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    (s, g, a, b)
}

/// The server limits fast posting; the app holds what was refused and
/// sends it, in order, once allowed. Nothing is lost, and the app's own
/// posts wait without a word.
#[tokio::test]
async fn messages_past_the_limit_wait_and_go_in_order() {
    let (s, g, mut a, mut b) = tight_pair().await;
    assert!(warnings(&drain(&mut b).await).is_empty());
    let r = b.send_text(g, "one").await.unwrap();
    let SendOutcome::Held { wait_secs } = r else {
        panic!("{r:?}")
    };
    assert!((1..=5).contains(&wait_secs), "{wait_secs}");
    let r = b.send_text(g, "two").await.unwrap();
    assert!(matches!(r, SendOutcome::Held { .. }), "{r:?}");
    assert!(texts(&b, g).is_empty());
    assert_eq!(b.held(g), 2);
    for _ in 0..4 {
        s.handle.advance_clock(5);
        b.advance_clock(5);
        b.sync().await.unwrap();
    }
    assert_eq!(texts(&b, g), vec!["Bo: one", "Bo: two"]);
    assert_eq!(b.held(g), 0);
    a.sync().await.unwrap();
    assert_eq!(texts(&a, g), vec!["Bo: one", "Bo: two"]);
    assert!(warnings(&drain(&mut b).await).is_empty());
}

/// A message typed while others wait goes behind them, never ahead.
#[tokio::test]
async fn a_new_message_waits_behind_held_ones() {
    let (s, g, _a, mut b) = tight_pair().await;
    assert!(matches!(
        b.send_text(g, "one").await.unwrap(),
        SendOutcome::Held { .. }
    ));
    s.handle.advance_clock(60);
    b.advance_clock(60);
    // The server would take it now, but "one" goes first.
    assert!(matches!(
        b.send_text(g, "two").await.unwrap(),
        SendOutcome::Sent
    ));
    assert_eq!(texts(&b, g), vec!["Bo: one", "Bo: two"]);
}

/// Admins get ten times a member's pace, so an admin can bring several
/// people in at once where a member could not: with a member's burst of
/// 6, four joins and a dozen texts take about 46 of Ada's 60.
#[tokio::test]
async fn an_admin_brings_several_people_in_at_once() {
    let s = TestServer::start_with(|c| {
        c.rate_burst_messages = 6;
        c.rate_seconds_per_message = 600;
    })
    .await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Room").await.unwrap();
    let mut b = TestClient::new(&s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let mut others = Vec::new();
    for n in ["Cy", "Dee", "Eli"] {
        let mut c = TestClient::new(&s, n).await;
        c.join(&a.invite(Some(g), false).await.unwrap().0)
            .await
            .unwrap();
        others.push(c);
    }
    let mut all: Vec<&mut TestClient> = vec![&mut a, &mut b];
    all.extend(others.iter_mut());
    settle(&mut all).await;
    assert_eq!(a.members(g).len(), 5);
    for _ in 0..12 {
        assert_eq!(
            a.send_text(g, "admin talking").await.unwrap(),
            SendOutcome::Sent
        );
    }
}

/// Slow mode: a member waits between posts, an admin does not, and the
/// app's own messages after a join wait quietly with no warnings.
#[tokio::test]
async fn slow_mode_holds_members_quietly() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    a.set_slow_mode(g, 30).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert_eq!(settings_of(&b, g).slow_secs, 30);
    assert!(notices(&b, g).contains(
        &"Ada turned on slow mode: one message every 30 seconds for each member who isn't an admin."
            .into()
    ));
    s.handle.advance_clock(31);
    b.advance_clock(31);
    assert!(matches!(
        b.send_text(g, "first").await.unwrap(),
        SendOutcome::Sent
    ));
    let r = b.send_text(g, "second").await.unwrap();
    let SendOutcome::Held { wait_secs } = r else {
        panic!("{r:?}")
    };
    assert!((29..=30).contains(&wait_secs), "{wait_secs}");
    assert!(matches!(
        a.send_text(g, "admins are not held").await.unwrap(),
        SendOutcome::Sent
    ));
    s.handle.advance_clock(30);
    b.advance_clock(30);
    b.sync().await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    let t = texts(&c, g);
    assert!(t.contains(&"Bo: second".to_string()), "{t:?}");
    // Someone joins: everyone's app owes them a profile, which waits for
    // the slow mode without a word.
    let mut d = TestClient::new(&s, "Dee").await;
    d.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b, &mut c, &mut d]).await;
    for x in [&mut b, &mut c, &mut d] {
        let w = warnings(&drain(x).await);
        assert!(w.is_empty(), "{w:?}");
    }
    for _ in 0..3 {
        s.handle.advance_clock(31);
        for x in [&mut a, &mut b, &mut c, &mut d] {
            x.advance_clock(31);
        }
        settle(&mut [&mut a, &mut b, &mut c, &mut d]).await;
    }
    let names: Vec<String> = d.members(g).into_iter().map(|m| m.name).collect();
    for n in ["Ada", "Bo", "Cy"] {
        assert!(names.contains(&n.to_string()), "{names:?}");
    }
    a.set_slow_mode(g, 0).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert!(notices(&b, g).contains(&"Ada turned off slow mode.".into()));
}

#[tokio::test]
async fn slow_mode_takes_seconds_up_to_six_hours() {
    let s = TestServer::start().await;
    let (g, mut a, _b, _c) = trio(&s).await;
    let e = a.set_slow_mode(g, 6 * 3600 + 1).await.unwrap_err();
    assert!(matches!(e, CoreError::Other(_)), "{e:?}");
    assert_eq!(
        e.to_string(),
        "Slow mode can be at most 21600 seconds (6 hours)."
    );
    a.set_slow_mode(g, 6 * 3600).await.unwrap();
}

// ---------- the server's own rule ----------

/// A server whose operator lets only admins invite into rooms keeps every
/// room admins-only, says so in the details, and tells an admin who asks
/// for anyone.
#[tokio::test]
async fn a_server_that_lets_only_admins_invite_says_so() {
    let s = TestServer::start_with(|c| c.members_can_invite_to_rooms = false).await;
    let (g, mut a, mut b, _c) = trio(&s).await;
    let d = a.details(g).await.unwrap();
    assert_eq!(d.invite, WhoCanInvite::Anyone);
    assert_eq!(d.server_members_invite, Some(false));
    let e = a
        .set_who_can_invite(g, WhoCanInvite::Anyone)
        .await
        .unwrap_err();
    assert_eq!(
        e.to_string(),
        "This server lets only admins invite people into its rooms, so this room stays admins-only."
    );
    // Admins only is fine, and back to anyone is refused the same way.
    a.set_who_can_invite(g, WhoCanInvite::Admins).await.unwrap();
    assert!(a.set_who_can_invite(g, WhoCanInvite::Anyone).await.is_err());
    assert_eq!(settings_of(&a, g).invite, WhoCanInvite::Admins);
    // A member's link is refused by the server.
    b.sync().await.unwrap();
    assert!(b.invite(Some(g), false).await.is_err());
}

/// On the default the server leaves it to each room.
#[tokio::test]
async fn by_default_the_server_leaves_it_to_the_room() {
    let s = TestServer::start().await;
    let (g, mut a, _b, _c) = trio(&s).await;
    assert_eq!(
        a.details(g).await.unwrap().server_members_invite,
        Some(true)
    );
    a.set_who_can_invite(g, WhoCanInvite::Admins).await.unwrap();
    a.set_who_can_invite(g, WhoCanInvite::Anyone).await.unwrap();
}

/// A server too old to say leaves the details silent on it.
#[tokio::test]
async fn an_older_server_says_nothing_about_its_rule() {
    let s = TestServer::start_with(|c| c.protocol_max = 2).await;
    let (g, mut a, _b, _c) = trio(&s).await;
    assert_eq!(a.details(g).await.unwrap().server_members_invite, None);
}
