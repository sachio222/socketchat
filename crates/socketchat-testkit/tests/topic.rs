//! A room's topic, as IRC's /topic sets it: one line every member sees,
//! sent encrypted, taken only from someone allowed to set it at that point
//! in the room, cleaned before it is shown, and deleted with the room.

use socketchat_core::appmsg::{AppMsg, Topic};
use socketchat_core::client::{Event, SendOutcome};
use socketchat_core::settings::{RoomSettings, WhoCanSetTopic};
use socketchat_proto::msg::GroupId;
use socketchat_testkit::{append_to_log, drain, settle, TestClient, TestServer};

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

/// The topic as an app holds it, or "" for none.
fn topic_of(c: &TestClient, g: GroupId) -> String {
    c.topic(g).map(|t| t.text).unwrap_or_default()
}

/// The topic lines in a room, as "setter: text".
fn topic_lines(c: &TestClient, g: GroupId) -> Vec<String> {
    c.messages(g, 200)
        .into_iter()
        .filter(|l| l.topic)
        .map(|l| format!("{}: {}", l.sender, l.text))
        .collect()
}

fn notices(c: &TestClient, g: GroupId) -> Vec<String> {
    c.messages(g, 200)
        .into_iter()
        .filter(|l| l.notice && !l.topic)
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

/// A topic signed with `c`'s own key in `g`.
fn signed_by(c: &TestClient, g: GroupId, text: &str) -> Topic {
    let kp = c.test_group_key_pair(g).expect("in the room");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Topic::new(&kp, g, text, now)
}

#[tokio::test]
async fn an_admin_sets_the_topic_and_everyone_sees_it() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    a.set_topic(g, "Piranesi, chapters 1 to 5").await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    let ak = a.my_group_key(g).unwrap();
    for x in [&a, &b, &c] {
        let t = x.topic(g).expect("a topic");
        assert_eq!(t.text, "Piranesi, chapters 1 to 5");
        assert_eq!(t.by_key, ak);
        assert_eq!(t.by, "Ada");
        assert_eq!(topic_lines(x, g), vec!["Ada: Piranesi, chapters 1 to 5"]);
    }
    assert!(a.topic(g).unwrap().mine);
    assert!(!b.topic(g).unwrap().mine);
    // A newcomer learns it on joining, with the time it was set and who
    // set it.
    let mut d = TestClient::new(&s, "Dee").await;
    d.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b, &mut c, &mut d]).await;
    let t = d.topic(g).expect("the newcomer has it");
    assert_eq!(t.text, "Piranesi, chapters 1 to 5");
    assert_eq!(t.by_key, ak);
    assert_eq!(t.set_unix, b.topic(g).unwrap().set_unix);
    assert_eq!(topic_lines(&d, g), vec!["Ada: Piranesi, chapters 1 to 5"]);
    // Passing it on to Dee told the others nothing new.
    assert_eq!(topic_lines(&b, g).len(), 1);
    // Cleared, it is gone everywhere, and a line says so.
    a.clear_topic(g).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c, &mut d]).await;
    for x in [&a, &b, &c, &d] {
        assert_eq!(x.topic(g), None);
        assert_eq!(topic_lines(x, g).last().unwrap(), "Ada: ");
    }
    let e = a.clear_topic(g).await.unwrap_err();
    assert_eq!(e.to_string(), "This room has no topic.");
}

#[tokio::test]
async fn a_member_cannot_set_the_topic_in_an_admins_only_topic_room() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, _c) = trio(&s).await;
    assert_eq!(
        b.room_settings(g).unwrap().topic,
        WhoCanSetTopic::Admins,
        "admins only by default, like IRC's +t"
    );
    let e = b.set_topic(g, "Mine now").await.unwrap_err();
    assert_eq!(e.to_string(), "Only admins can set this room's topic.");
    let e = b.clear_topic(g).await.unwrap_err();
    assert_eq!(e.to_string(), "Only admins can set this room's topic.");
    let e = b
        .set_who_can_set_topic(g, WhoCanSetTopic::Anyone)
        .await
        .unwrap_err();
    assert_eq!(
        e.to_string(),
        "Only admins can change this room's settings."
    );
    a.sync().await.unwrap();
    assert_eq!(a.topic(g), None);
}

#[tokio::test]
async fn after_settings_topic_anyone_a_member_can() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    a.set_who_can_set_topic(g, WhoCanSetTopic::Anyone)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert_eq!(b.room_settings(g).unwrap().topic, WhoCanSetTopic::Anyone);
    assert!(notices(&a, g).contains(&"You let anyone in the room set the topic.".into()));
    assert!(
        notices(&b, g).contains(&"Ada let anyone in the room set the topic.".into()),
        "{:?}",
        notices(&b, g)
    );
    b.set_topic(g, "Bo was here").await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    for x in [&a, &b, &c] {
        assert_eq!(topic_of(x, g), "Bo was here");
        assert_eq!(x.topic(g).unwrap().by_key, b.my_group_key(g).unwrap());
    }
    // Back to admins only: Bo's next topic is refused, and his earlier
    // one stays.
    a.set_who_can_set_topic(g, WhoCanSetTopic::Admins)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert!(notices(&c, g).contains(&"Ada let only admins set the topic.".into()));
    assert!(b.set_topic(g, "Again").await.is_err());
    assert_eq!(topic_of(&c, g), "Bo was here");
}

/// A member's topic that skips their own app's check reaches the log, and
/// every app ignores it.
#[tokio::test]
async fn a_members_topic_is_ignored_by_every_app() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    let forged = signed_by(&b, g, "Forged by Bo");
    b.test_send_app(g, &AppMsg::Topic(forged)).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    for x in [&a, &c] {
        assert_eq!(x.topic(g), None);
        assert!(topic_lines(x, g).is_empty());
    }
}

/// Bo was an admin. His app wrote a topic for the room as it stood; Ada
/// removed him before it reached the log. Every app judges it by the room
/// at that point, where Bo is gone.
#[tokio::test]
async fn a_topic_from_a_pre_change_admin_who_was_just_removed_is_ignored() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    let bk = b.my_group_key(g).unwrap();
    a.make_admin(g, &bk).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    let late_topic = AppMsg::Topic(signed_by(&b, g, "Late"));
    let late = b.test_encrypt_app(g, &late_topic).unwrap();
    a.remove_member(g, &bk).await.unwrap();
    settle(&mut [&mut a, &mut c]).await;
    append_to_log(&s, g, &late);
    for x in [&mut a, &mut c] {
        x.sync().await.unwrap();
        assert_eq!(x.topic(g), None);
        assert!(topic_lines(x, g).is_empty());
    }
}

/// A topic that names someone else as its setter is ignored, whether it
/// says it is new or passed on.
#[tokio::test]
async fn a_topic_cannot_name_someone_else_as_its_setter() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    a.set_who_can_set_topic(g, WhoCanSetTopic::Anyone)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    let ak = a.my_group_key(g).unwrap();
    for repost in [false, true] {
        let mut t = signed_by(&b, g, "Ada says send me your password");
        t.set_by = ak;
        t.repost = repost;
        b.test_send_app(g, &AppMsg::Topic(t)).await.unwrap();
    }
    settle(&mut [&mut a, &mut b, &mut c]).await;
    for x in [&a, &c] {
        assert_eq!(x.topic(g), None);
    }
}

/// A topic passed on for a newcomer never replaces the one a member has.
#[tokio::test]
async fn a_passed_on_topic_never_replaces_the_current_one() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    let bk = b.my_group_key(g).unwrap();
    a.make_admin(g, &bk).await.unwrap();
    a.set_topic(g, "Current").await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    let mut old = signed_by(&b, g, "Old");
    old.repost = true;
    b.test_send_app(g, &AppMsg::Topic(old)).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    for x in [&a, &b, &c] {
        assert_eq!(topic_of(x, g), "Current");
    }
}

/// While the room holds a member back, a topic is refused before anything
/// is encrypted, as every post is.
#[tokio::test]
async fn a_held_topic_is_not_encrypted_while_held() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    a.set_who_can_set_topic(g, WhoCanSetTopic::Anyone)
        .await
        .unwrap();
    a.set_slow_mode(g, 600).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    s.handle.advance_clock(601);
    b.advance_clock(601);
    assert_eq!(b.send_text(g, "first").await.unwrap(), SendOutcome::Sent);
    let before = b.test_encrypted();
    let e = b.set_topic(g, "Too soon").await.unwrap_err();
    assert!(
        e.to_string()
            .starts_with("This room limits fast posting; try again in"),
        "{e}"
    );
    assert_eq!(b.test_encrypted(), before);
    // Once the room allows it, the topic goes.
    s.handle.advance_clock(601);
    b.advance_clock(601);
    b.set_topic(g, "In time").await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert_eq!(topic_of(&a, g), "In time");
}

#[tokio::test]
async fn a_long_or_hostile_topic_is_refused_or_made_inert() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    let e = a.set_topic(g, &"x".repeat(1000)).await.unwrap_err();
    assert_eq!(
        e.to_string(),
        "A topic can be at most 300 characters. This one has 1000."
    );
    let e = a.set_topic(g, " \u{200B}\u{3164}\n").await.unwrap_err();
    assert_eq!(
        e.to_string(),
        "A topic needs at least one character you can see. To remove the topic, use /topic --clear."
    );
    a.set_topic(g, &"x".repeat(300)).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert_eq!(topic_of(&b, g).chars().count(), 300);
    // An app that skips the cap: every receiver cuts it to 300.
    let long = signed_by(&a, g, &"y".repeat(1000));
    a.test_send_app(g, &AppMsg::Topic(long)).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert_eq!(topic_of(&b, g), "y".repeat(300));
    // Escape codes, direction overrides, invisible characters and line
    // breaks all arrive inert, on one line.
    let raw = "\x1b[2J\x1b]0;owned\x07Meet\u{202E}gnp.exe\u{200B}\nat\r\nnoon\u{3164}";
    let hostile = signed_by(&a, g, raw);
    a.test_send_app(g, &AppMsg::Topic(hostile)).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    for x in [&b, &c] {
        assert_eq!(topic_of(x, g), "[2J]0;ownedMeetgnp.exe at noon");
        let line = topic_lines(x, g).pop().unwrap();
        assert!(!line.chars().any(char::is_control), "{line:?}");
    }
}

#[tokio::test]
async fn leaving_clearing_and_forgetting_delete_the_topic() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    a.set_topic(g, "Here today").await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert!(b.test_traces(g).contains(&"topics"));
    // /clear: the room stays, its topic goes from this computer.
    b.clear_history(g).unwrap();
    assert_eq!(b.topic(g), None);
    assert!(!b.test_traces(g).contains(&"topics"));
    // /leave.
    c.leave(g).await.unwrap();
    settle(&mut [&mut a, &mut c]).await;
    assert_eq!(c.topic(g), None);
    assert!(!c.test_traces(g).contains(&"topics"));
    // /forget.
    let server = a.test_server_of(g);
    a.forget_server(server).unwrap();
    assert!(a.test_traces(g).is_empty(), "{:?}", a.test_traces(g));
}

#[tokio::test]
async fn the_topic_stays_after_the_app_opens_again() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, _c) = trio(&s).await;
    a.set_topic(g, "Kept on disk").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let b = b.reopen().await;
    assert_eq!(topic_of(&b, g), "Kept on disk");
}

/// Bo's app is 0.5.1: it knows no topics and no settings. The room keeps
/// working for him, and he sees no topic.
#[tokio::test]
async fn an_app_up_to_0_5_1_in_the_room_keeps_working() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Room").await.unwrap();
    let mut b = TestClient::new(&s, "Bo").await;
    b.test_old_capabilities(true);
    b.test_announce_version("0.5.1");
    b.test_reads_like_0_5_1(true);
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    drain(&mut b).await;
    a.set_topic(g, "For the new apps").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(b.topic(g), None);
    assert!(warnings(&drain(&mut b).await).is_empty());
    assert_eq!(
        b.send_text(g, "still here").await.unwrap(),
        SendOutcome::Sent
    );
    a.sync().await.unwrap();
    assert!(a
        .messages(g, 50)
        .iter()
        .any(|l| l.sender == "Bo" && l.text == "still here"));
    assert_eq!(topic_of(&a, g), "For the new apps");
    // Letting anyone set it is a setting, so it waits for Bo's app.
    let e = a
        .set_who_can_set_topic(g, WhoCanSetTopic::Anyone)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("Not ready yet: Bo."), "{e}");
    assert_eq!(a.room_settings(g).unwrap(), RoomSettings::default());
}

/// On a server from before 0.5.2, the topic works, as it is only a
/// message; letting anyone set it is a setting the server cannot keep.
#[tokio::test]
async fn an_older_server_carries_the_topic_but_not_the_setting() {
    let s = TestServer::start_with(|c| c.protocol_max = 2).await;
    let (g, mut a, mut b, _c) = trio(&s).await;
    a.set_topic(g, "Works anywhere").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(topic_of(&b, g), "Works anywhere");
    let e = a
        .set_who_can_set_topic(g, WhoCanSetTopic::Anyone)
        .await
        .unwrap_err();
    assert_eq!(
        e.to_string(),
        "This server runs an older version of Socketchat, so it can't keep this setting. Ask the person who runs it to update."
    );
}
