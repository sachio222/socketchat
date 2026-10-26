//! Inviting someone you already share a room with to another room:
//! `/invite <name>`, taken up with `/join <room>`.

use socketchat_core::add::{self, Answer, Context, ADD_TTL_SECS};
use socketchat_core::appmsg::AppMsg;
use socketchat_core::client::{Event, RoomInvite, Verification};
use socketchat_core::settings::WhoCanInvite;
use socketchat_proto::msg::GroupId;
use socketchat_testkit::{settle, TestClient, TestServer};

/// A version after 0.5.2, which knows this kind of invite.
const NEW: &str = "0.5.3";

/// A person with an account on `s`, whose app says it runs `NEW`.
async fn person(s: &TestServer, name: &str) -> TestClient {
    let mut c = TestClient::profile_only(name).await;
    c.test_announce_version(NEW);
    c.join(&s.server_invite()).await.unwrap();
    c
}

/// Ada made Book club and brought Bo in with a link; Ada also made
/// Climbing Saturdays, where Bo is not.
async fn setup(s: &TestServer) -> (TestClient, TestClient, GroupId, GroupId) {
    let mut a = person(s, "Ada").await;
    let book = a.create_group("Book club").await.unwrap();
    let mut b = person(s, "Bo").await;
    b.join(&a.invite(Some(book), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let climb = a.create_group("Climbing Saturdays").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    a.take_events();
    b.take_events();
    (a, b, book, climb)
}

/// Brings `who` into `room`, made by `admin`, with a link.
async fn bring(admin: &mut TestClient, who: &mut TestClient, room: GroupId) {
    who.join(&admin.invite(Some(room), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [admin, who]).await;
}

fn invited(ev: &[Event]) -> Vec<RoomInvite> {
    ev.iter()
        .filter_map(|e| match e {
            Event::Invited(r) => Some(r.clone()),
            _ => None,
        })
        .collect()
}

fn notices(c: &TestClient, g: GroupId) -> Vec<String> {
    c.messages(g, 200)
        .into_iter()
        .filter(|l| l.notice)
        .map(|l| l.text)
        .collect()
}

fn in_room(c: &TestClient, g: GroupId) -> bool {
    c.groups().iter().any(|x| x.id == g && x.ended.is_none())
}

fn names(c: &TestClient, g: GroupId) -> Vec<String> {
    c.members(g).into_iter().map(|m| m.name).collect()
}

fn sent(c: &TestClient, g: GroupId, kind: &str) -> usize {
    c.test_sent_kinds(g).iter().filter(|k| *k == kind).count()
}

/// The one invite Bo's app holds.
fn only_invite(b: &TestClient) -> RoomInvite {
    let r = b.room_invites();
    assert_eq!(r.len(), 1, "{r:?}");
    r[0].clone()
}

/// Joins the one invite waiting.
async fn accept_only(b: &mut TestClient) -> RoomInvite {
    let r = only_invite(b);
    b.accept_invite(&r).await.unwrap();
    r
}

#[tokio::test]
async fn invite_someone_from_another_room() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    let sent_to = a.invite_member(climb, "Bo").await.unwrap();
    assert_eq!(sent_to.name, "Bo");
    assert_eq!(sent_to.via, "Book club");
    settle(&mut [&mut a, &mut b]).await;

    // Bo's app says so in Book club, and nothing about Bo goes to the new
    // room until he joins.
    let ev = b.take_events();
    let got = invited(&ev);
    assert_eq!(got.len(), 1, "{ev:?}");
    let r = &got[0];
    assert_eq!(r.from_name, "Ada");
    assert_eq!(r.via, book);
    assert_eq!(r.via_name, "Book club");
    assert_eq!(r.room, "Climbing Saturdays");
    assert_eq!(r.server, None, "Bo already uses this server");
    assert_eq!(only_invite(&b), *r);
    assert!(
        notices(&b, book).contains(
            &"Ada invites you to Climbing Saturdays. Type /join Climbing Saturdays to join."
                .to_string()
        ),
        "{:?}",
        notices(&b, book)
    );
    assert!(!in_room(&b, climb));
    assert_eq!(sent(&b, book, "AddAnswer"), 0, "nothing goes before /join");
    assert_eq!(names(&a, climb), ["Ada"]);

    let picked = b.find_invite(Some("climbing  saturdays")).unwrap();
    assert_eq!(picked, *r);
    b.accept_invite(&picked).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert!(in_room(&b, climb));
    assert!(b.room_invites().is_empty());
    let ev = b.take_events();
    assert!(
        ev.iter().any(|e| matches!(e, Event::Joined { group, verification: Verification::Verified } if *group == climb)),
        "Bo verified Ada when he joined Book club: {ev:?}"
    );
    assert_eq!(names(&a, climb), ["Ada", "Bo"]);
    assert!(
        notices(&a, climb).contains(&"Bo accepted your invite and joined.".to_string()),
        "{:?}",
        notices(&a, climb)
    );
    assert_eq!(
        b.groups().iter().find(|g| g.id == climb).unwrap().name,
        "Climbing Saturdays"
    );
    assert!(
        !notices(&b, climb).iter().any(|n| n.contains("as Ada said")),
        "the name matched"
    );
    b.send_text(climb, "hi all").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert!(a.messages(climb, 50).iter().any(|l| l.text == "hi all"));
    // The invite token went with the add.
    assert!(a
        .invites()
        .await
        .unwrap()
        .iter()
        .all(|i| i.group != Some(climb)));
}

#[tokio::test]
async fn an_invite_to_a_new_server_names_it() {
    let s1 = TestServer::start().await;
    let s2 = TestServer::start().await;
    let (mut a, mut b, book, _) = setup(&s1).await;
    a.join(&s2.server_invite()).await.unwrap();
    let far_server = a
        .servers(None)
        .into_iter()
        .find(|v| v.text.ends_with(&s2.addr().port().to_string()))
        .unwrap();
    let far = a.create_group_at(far_server.id, "Far room").await.unwrap();
    a.invite_member(far, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let r = only_invite(&b);
    assert_eq!(r.room, "Far room");
    assert_eq!(r.server.as_deref(), Some(far_server.text.as_str()));
    let line = format!(
        "Ada invites you to Far room, on {}, a server you have not used. Type /join Far room to join.",
        far_server.text
    );
    assert!(notices(&b, book).contains(&line), "{:?}", notices(&b, book));
    accept_only(&mut b).await;
    settle(&mut [&mut a, &mut b]).await;
    assert!(in_room(&b, far));
    assert_eq!(names(&a, far), ["Ada", "Bo"]);
}

#[tokio::test]
async fn several_invites_are_numbered_in_the_order_they_came() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    let mut c = person(&s, "Cy").await;
    bring(&mut a, &mut c, book).await;
    // Cy has a room with the same name.
    let other = c.create_group("Climbing Saturdays").await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert_eq!(
        b.find_invite(None).unwrap_err().to_string(),
        "No invite waits for you. To use a link, type /join and the link."
    );
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    // One invite: /join alone takes it.
    assert_eq!(b.find_invite(None).unwrap().from_name, "Ada");
    c.invite_member(other, "Bo").await.unwrap();
    settle(&mut [&mut b, &mut c]).await;
    let all = b.room_invites();
    assert_eq!(
        all.iter()
            .map(|r| (r.number, r.from_name.as_str()))
            .collect::<Vec<_>>(),
        [(1, "Ada"), (2, "Cy")]
    );
    assert_eq!(
        b.find_invite(None).unwrap_err().to_string(),
        "More than one invite waits for you: 1. Climbing Saturdays from Ada (verified), 2. Climbing Saturdays from Cy. Type /join 1 or /join 2."
    );
    assert_eq!(
        b.find_invite(Some("Climbing Saturdays"))
            .unwrap_err()
            .to_string(),
        "More than one invite waits for Climbing Saturdays: 1. from Ada (verified), 2. from Cy. Type /join 1 or /join 2."
    );
    let ada = b.find_invite(Some("1")).unwrap();
    assert_eq!(ada.from_name, "Ada");
    assert_eq!(
        b.find_invite(Some("Hikes")).unwrap_err().to_string(),
        "No invite to Hikes waits for you."
    );
    assert_eq!(
        b.find_invite(Some("7")).unwrap_err().to_string(),
        "No invite numbered 7 or to a room called 7 waits for you."
    );
    b.accept_invite(&ada).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert!(in_room(&b, climb));
    assert!(!in_room(&b, other));
    // Cy's invite keeps its number.
    assert_eq!(b.find_invite(Some("2")).unwrap().from_name, "Cy");
    assert_eq!(b.find_invite(None).unwrap().from_name, "Cy");
}

#[tokio::test]
async fn the_advised_number_cannot_be_captured_by_a_room_name() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    let mut c = person(&s, "Cy").await;
    bring(&mut a, &mut c, book).await;
    let decoy = c.create_group("Climbing Saturdays").await.unwrap();
    let trap = c.create_group("Climbing Saturdays from Ada").await.unwrap();
    // A room called "1", for the number Ada's invite gets.
    let one = c.create_group("1").await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    c.invite_member(decoy, "Bo").await.unwrap();
    c.invite_member(trap, "Bo").await.unwrap();
    c.invite_member(one, "Bo").await.unwrap();
    for _ in 0..2 {
        settle(&mut [&mut b, &mut c]).await;
    }
    assert_eq!(b.room_invites().len(), 4, "{:?}", b.room_invites());
    let number_of = |room: &str| {
        b.room_invites()
            .into_iter()
            .find(|r| r.room == room && r.from_name == "Cy")
            .unwrap()
            .number
    };
    let (decoy_n, one_n) = (number_of("Climbing Saturdays"), number_of("1"));
    let advice = b
        .find_invite(Some("Climbing Saturdays"))
        .unwrap_err()
        .to_string();
    assert_eq!(
        advice,
        format!("More than one invite waits for Climbing Saturdays: 1. from Ada (verified), {decoy_n}. from Cy. Type /join 1 or /join {decoy_n}.")
    );
    // The advised number is Ada's, whatever the rooms are called: a bare
    // number names an invite before it names a room.
    let got = b.find_invite(Some("1")).unwrap();
    assert_eq!(
        (got.from_name.as_str(), got.room.as_str()),
        ("Ada", "Climbing Saturdays")
    );
    assert_ne!(one_n, 1);
    assert_eq!(
        b.find_invite(Some(&one_n.to_string())).unwrap().room,
        "1",
        "the room called 1 is joined by its own number"
    );
    // A room name holding "from" is only ever that room.
    assert_eq!(
        b.find_invite(Some("Climbing Saturdays from Ada"))
            .unwrap()
            .from_name,
        "Cy"
    );
}

#[tokio::test]
async fn a_late_offer_does_not_lock_the_inviter_out_for_a_day() {
    let s = TestServer::start().await;
    let (mut a, mut b, _book, climb) = setup(&s).await;
    a.invite_member(climb, "Bo").await.unwrap();
    // Bo's app gives its key while Ada's app is closed.
    settle(&mut [&mut b]).await;
    let wait = socketchat_core::client::ADD_OFFER_WAIT_SECS;
    b.advance_clock(wait + 60);
    a.advance_clock(wait + 60);
    settle(&mut [&mut b]).await;
    // Ada opens the app again, past the time Bo's app waits for her offer.
    for _ in 0..2 {
        settle(&mut [&mut a, &mut b]).await;
    }
    assert!(b.room_invites().is_empty());
    assert!(
        notices(&a, climb).contains(
            &"Your invite to Bo ran out before it reached them. Invite them again with /invite Bo."
                .to_string()
        ),
        "{:?}",
        notices(&a, climb)
    );
    assert_eq!(
        sent(&a, _book, "AddOffer"),
        0,
        "no offer goes once Bo's app stopped waiting"
    );
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(b.room_invites().len(), 1);
}

#[tokio::test]
async fn an_invite_whose_key_has_not_come_can_be_sent_again() {
    let s = TestServer::start().await;
    let (mut a, mut b, _book, climb) = setup(&s).await;
    // Bo's app is closed for a while.
    a.invite_member(climb, "Bo").await.unwrap();
    assert!(a.invite_member(climb, "Bo").await.is_err(), "still waiting");
    a.advance_clock(socketchat_core::client::ADD_OFFER_WAIT_SECS + 60);
    b.advance_clock(socketchat_core::client::ADD_OFFER_WAIT_SECS + 60);
    a.sync().await.unwrap();
    // The first invite still waits for Bo's app, so nothing ended...
    assert_eq!(notices(&a, climb), ["Invite sent to Bo."]);
    // ...but a new one replaces it.
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(b.room_invites().len(), 1, "one invite reaches Bo");
    accept_only(&mut b).await;
    settle(&mut [&mut a, &mut b]).await;
    assert!(in_room(&b, climb));
    assert!(a
        .invites()
        .await
        .unwrap()
        .iter()
        .all(|i| i.group != Some(climb)));
}

#[tokio::test]
async fn an_invite_to_someone_whose_app_was_closed_still_arrives() {
    let s = TestServer::start().await;
    let (mut a, mut b, _book, climb) = setup(&s).await;
    a.invite_member(climb, "Bo").await.unwrap();
    // Bo's app opens three hours later, while Ada's is open.
    a.advance_clock(3 * 3600);
    b.advance_clock(3 * 3600);
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(b.room_invites().len(), 1);
}

#[tokio::test]
async fn a_room_whose_name_holds_from_is_found_whole() {
    let s = TestServer::start().await;
    let (mut a, mut b, _book, _) = setup(&s).await;
    let notes = a.create_group("Notes from Ada").await.unwrap();
    a.invite_member(notes, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(
        b.find_invite(Some("Notes from Ada")).unwrap().room,
        "Notes from Ada"
    );
}

#[tokio::test]
async fn while_waiting_the_inviter_hears_it_once() {
    let s = TestServer::start().await;
    let (mut a, mut b, _book, climb) = setup(&s).await;
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let again = a.invite_member(climb, "Bo").await.unwrap_err().to_string();
    assert_eq!(
        again,
        "You already invited Bo to this room. This room says when they join."
    );
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(b.room_invites().len(), 1);
    assert_eq!(notices(&a, climb), ["Invite sent to Bo."]);
}

#[tokio::test]
async fn an_invite_nobody_takes_ends_after_24_hours() {
    let s = TestServer::start().await;
    let (mut a, mut b, _book, climb) = setup(&s).await;
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let r = only_invite(&b);
    a.advance_clock(ADD_TTL_SECS + 60);
    b.advance_clock(ADD_TTL_SECS + 60);
    assert_eq!(
        b.accept_invite(&r).await.unwrap_err().to_string(),
        "That invite expired."
    );
    settle(&mut [&mut a, &mut b]).await;
    assert!(b.room_invites().is_empty());
    assert!(!in_room(&b, climb));
    assert!(
        notices(&a, climb).contains(&"Bo didn't join Climbing Saturdays.".to_string()),
        "{:?}",
        notices(&a, climb)
    );
    assert!(a
        .invites()
        .await
        .unwrap()
        .iter()
        .all(|i| i.group != Some(climb)));
}

#[tokio::test]
async fn each_invite_works_once() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let r = accept_only(&mut b).await;
    settle(&mut [&mut a, &mut b]).await;
    assert!(in_room(&b, climb));
    assert_eq!(
        b.accept_invite(&r).await.unwrap_err().to_string(),
        "That invite is no longer open."
    );
    // Bo's answer, sent once more, adds nothing and changes nothing.
    let yes = b
        .test_sent_msgs(book)
        .into_iter()
        .rev()
        .find(|m| matches!(m, AppMsg::AddAnswer { .. }))
        .expect("Bo's answer");
    let epoch = a.epoch(climb);
    b.test_send_app(book, &yes).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(a.epoch(climb), epoch);
    assert_eq!(names(&a, climb), ["Ada", "Bo"]);
    let joined = notices(&a, climb)
        .iter()
        .filter(|n| n.contains("accepted your invite"))
        .count();
    assert_eq!(joined, 1);
}

#[tokio::test]
async fn two_invites_to_one_room_add_once() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    let mut c = person(&s, "Cy").await;
    bring(&mut a, &mut c, book).await;
    bring(&mut a, &mut c, climb).await;
    settle(&mut [&mut a, &mut b, &mut c]).await;
    a.invite_member(climb, "Bo").await.unwrap();
    c.invite_member(climb, "Bo").await.unwrap();
    for _ in 0..2 {
        settle(&mut [&mut a, &mut b, &mut c]).await;
    }
    let both = b.room_invites();
    assert_eq!(both.len(), 2, "{both:?}");
    b.accept_invite(&both[0]).await.unwrap();
    // The other invite is for a room Bo is already joining.
    let err = b.accept_invite(&both[1]).await.unwrap_err().to_string();
    assert_eq!(err, "You are already joining Climbing Saturdays.");
    for _ in 0..4 {
        settle(&mut [&mut a, &mut b, &mut c]).await;
    }
    assert_eq!(a.members(climb).len(), 3, "Ada, Cy and one Bo");
    b.send_text(climb, "hi").await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert!(a.messages(climb, 50).iter().any(|l| l.text == "hi"));
}

#[tokio::test]
async fn admins_only_room_refuses_a_member_before_anything_is_sent() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    let mut c = person(&s, "Cy").await;
    bring(&mut a, &mut c, book).await;
    bring(&mut a, &mut c, climb).await;
    a.set_who_can_invite(climb, WhoCanInvite::Admins)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    let err = c.invite_member(climb, "Bo").await.unwrap_err().to_string();
    assert_eq!(err, "In this room only admins can invite people.");
    assert_eq!(sent(&c, book, "AddAsk"), 0);
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert!(b.room_invites().is_empty());

    // Past the app's own check, the server refuses the link it needs.
    c.test_skip_add_checks(true);
    let err = c.invite_member(climb, "Bo").await.unwrap_err().to_string();
    assert!(err.contains("only admins can make invite links"), "{err}");
    assert_eq!(sent(&c, book, "AddAsk"), 0);
}

#[tokio::test]
async fn a_room_that_turns_admins_only_stops_a_waiting_invite() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    let mut c = person(&s, "Cy").await;
    bring(&mut a, &mut c, book).await;
    bring(&mut a, &mut c, climb).await;
    // Bo's app tells Cy his name.
    settle(&mut [&mut a, &mut b, &mut c]).await;
    c.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut c, &mut b]).await;
    accept_only(&mut b).await;
    // Before Cy's app reads Bo's answer, Ada lets only admins invite.
    a.set_who_can_invite(climb, WhoCanInvite::Admins)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert!(!in_room(&b, climb));
    assert_eq!(names(&a, climb), ["Ada", "Cy"]);
    assert!(
        notices(&c, climb).contains(
            &"Bo accepted your invite, but in this room only admins can add people now."
                .to_string()
        ),
        "{:?}",
        notices(&c, climb)
    );
}

#[tokio::test]
async fn the_server_still_refuses_a_members_add_in_an_admins_only_room() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    let mut c = person(&s, "Cy").await;
    bring(&mut a, &mut c, book).await;
    bring(&mut a, &mut c, climb).await;
    settle(&mut [&mut a, &mut b, &mut c]).await;
    c.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut c, &mut b]).await;
    accept_only(&mut b).await;
    a.set_who_can_invite(climb, WhoCanInvite::Admins)
        .await
        .unwrap();
    // Cy's app skips its own check and commits anyway.
    c.test_skip_add_checks(true);
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert!(!in_room(&b, climb));
    assert_eq!(names(&a, climb), ["Ada", "Cy"]);
    let n = notices(&c, climb);
    assert!(
        n.iter().any(|t| t
            .starts_with("Bo accepted your invite, but Socketchat could not add them:")
            && t.contains("only admins can add people")),
        "{n:?}"
    );
}

#[tokio::test]
async fn a_name_two_people_share_is_refused_until_picked() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    // Another Bo, in another room.
    let mut b2 = person(&s, "Bo").await;
    let hikes = a.create_group("Hikes").await.unwrap();
    bring(&mut a, &mut b2, hikes).await;
    let err = a.invite_member(climb, "Bo").await.unwrap_err().to_string();
    let tag = |g| {
        let k = a
            .members(g)
            .into_iter()
            .find(|m| m.name == "Bo")
            .unwrap()
            .key;
        format!("Bo#{:02x}{:02x}", k.0[0], k.0[1])
    };
    let (t1, t2) = (tag(book), tag(hikes));
    assert_eq!(
        err,
        format!("More than one person called Bo shares a room with you: {t1} (verified) in Book club and {t2} (verified) in Hikes. Type /invite {t1} or /invite {t2}.")
    );
    assert_eq!(sent(&a, book, "AddAsk") + sent(&a, hikes, "AddAsk"), 0);
    let to = a.invite_member(climb, &t2).await.unwrap();
    assert_eq!(to.via, "Hikes");
    settle(&mut [&mut a, &mut b, &mut b2]).await;
    assert!(b.room_invites().is_empty());
    assert_eq!(b2.room_invites().len(), 1);
}

#[tokio::test]
async fn the_invite_line_tags_an_inviter_whose_name_another_member_shares() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    // A second Ada in Book club.
    let mut a2 = person(&s, "Ada").await;
    bring(&mut a, &mut a2, book).await;
    settle(&mut [&mut a, &mut b, &mut a2]).await;
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let k = a.my_group_key(book).unwrap();
    let tagged = format!("Ada#{:02x}{:02x}", k.0[0], k.0[1]);
    let r = only_invite(&b);
    assert_eq!(r.from_name, tagged);
    assert!(
        notices(&b, book)
            .iter()
            .any(|n| n.starts_with(&format!("{tagged} invites you to Climbing Saturdays."))),
        "{:?}",
        notices(&b, book)
    );
}

#[tokio::test]
async fn the_same_person_in_two_rooms_is_one_person() {
    let s = TestServer::start().await;
    let (mut a, mut b, _book, climb) = setup(&s).await;
    let hikes = a.create_group("Hikes").await.unwrap();
    bring(&mut a, &mut b, hikes).await;
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(b.room_invites().len(), 1);
}

#[tokio::test]
async fn nobody_by_that_name() {
    let s = TestServer::start().await;
    let (mut a, _b, _book, climb) = setup(&s).await;
    assert_eq!(
        a.invite_member(climb, "Zed").await.unwrap_err().to_string(),
        "Nobody called Zed shares a room with you."
    );
}

#[tokio::test]
async fn someone_already_in_the_room() {
    let s = TestServer::start().await;
    let (mut a, mut b, _book, climb) = setup(&s).await;
    bring(&mut a, &mut b, climb).await;
    assert_eq!(
        a.invite_member(climb, "Bo").await.unwrap_err().to_string(),
        "Bo is already in Climbing Saturdays."
    );
}

#[tokio::test]
async fn not_into_a_direct_chat() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, _) = setup(&s).await;
    let mut c = person(&s, "Cy").await;
    bring(&mut a, &mut c, book).await;
    let bk = b.my_group_key(book).unwrap();
    let dm = a.dm(book, &bk).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert_eq!(
        a.invite_member(dm, "Cy").await.unwrap_err().to_string(),
        "This is a direct chat for two people. To invite people, start a room with /new."
    );
}

#[tokio::test]
async fn an_app_on_0_5_2_or_older_is_refused_up_front() {
    for old in ["0.5.1", "0.5.2"] {
        let s = TestServer::start().await;
        let mut a = person(&s, "Ada").await;
        let book = a.create_group("Book club").await.unwrap();
        let mut b = TestClient::profile_only("Bo").await;
        b.test_announce_version(old);
        b.join(&s.server_invite()).await.unwrap();
        bring(&mut a, &mut b, book).await;
        let climb = a.create_group("Climbing Saturdays").await.unwrap();
        assert_eq!(
            a.invite_member(climb, "Bo").await.unwrap_err().to_string(),
            "Bo's app is too old for this kind of invite. Send them a link with /invite.",
            "{old}"
        );
        assert_eq!(sent(&a, book, "AddAsk"), 0);
    }
}

#[tokio::test]
async fn an_app_that_cannot_read_the_steps_carries_on() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    // Bo's app says a new version but reads like 0.5.2.
    b.test_reads_like_0_5_2(true);
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let ev = b.take_events();
    assert!(!ev.iter().any(|e| matches!(e, Event::Warning(_))), "{ev:?}");
    assert!(b.room_invites().is_empty());
    a.send_text(book, "still here").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert!(b.messages(book, 50).iter().any(|l| l.text == "still here"));
}

#[tokio::test]
async fn removal_from_the_shared_room_ends_the_invite() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let r = only_invite(&b);
    let bk = b.my_group_key(book).unwrap();
    a.remove_member(book, &bk).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert!(b.room_invites().is_empty());
    assert!(b.accept_invite(&r).await.is_err());
    assert!(!in_room(&b, climb));
    assert!(
        notices(&a, climb)
            .contains(&"Bo is no longer in Book club, so your invite to them ended.".to_string()),
        "{:?}",
        notices(&a, climb)
    );
}

#[tokio::test]
async fn leaving_the_shared_room_cancels_the_invite_link() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    let mut c = person(&s, "Cy").await;
    bring(&mut a, &mut c, book).await;
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert!(a
        .invites()
        .await
        .unwrap()
        .iter()
        .any(|i| i.group == Some(climb)));
    a.leave(book).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert!(
        notices(&a, climb)
            .contains(&"You are no longer in Book club, so your invite to Bo ended.".to_string()),
        "{:?}",
        notices(&a, climb)
    );
    assert!(a
        .invites()
        .await
        .unwrap()
        .iter()
        .all(|i| i.group != Some(climb)));
    assert!(b.room_invites().is_empty());
}

#[tokio::test]
async fn a_join_that_never_comes_says_so() {
    let s = TestServer::start().await;
    let (mut a, mut b, _book, climb) = setup(&s).await;
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    accept_only(&mut b).await;
    // Ada's app never runs again, and the invite runs out.
    b.advance_clock(ADD_TTL_SECS + 2 * 3600);
    b.sync().await.unwrap();
    let ev = b.take_events();
    assert!(
        ev.contains(&Event::Warning(
            "Ada did not add you to Climbing Saturdays.".into()
        )),
        "{ev:?}"
    );
    assert!(!in_room(&b, climb));
    b.sync().await.unwrap();
    assert!(b.take_events().is_empty(), "said once");
}

#[tokio::test]
async fn a_verified_mark_carries_over_for_the_inviter_only() {
    let s = TestServer::start().await;
    let (mut a, mut b, _book, climb) = setup(&s).await;
    // Cy is in Climbing Saturdays and has never checked Bo.
    let mut c = person(&s, "Cy").await;
    bring(&mut a, &mut c, climb).await;
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    accept_only(&mut b).await;
    settle(&mut [&mut a, &mut b, &mut c]).await;
    let bo = |x: &TestClient| {
        x.members(climb)
            .into_iter()
            .find(|m| m.name == "Bo")
            .unwrap()
    };
    // Ada's app checked Bo's link proof in Book club.
    assert!(bo(&a).verified);
    assert!(!bo(&c).verified, "the invite marks nobody verified for Cy");
}

#[tokio::test]
async fn an_unchecked_join_keeps_the_profile_out_of_the_room() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    // Cy is already in Climbing Saturdays.
    let mut c = person(&s, "Cy").await;
    bring(&mut a, &mut c, climb).await;
    // Dee came into Book club through Bo's link, so she never verified Ada.
    let mut d = person(&s, "Dee").await;
    d.join(&b.invite(Some(book), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b, &mut d]).await;
    a.invite_member(climb, "Dee").await.unwrap();
    settle(&mut [&mut a, &mut d]).await;
    let r = only_invite(&d);
    assert!(!r.from_verified);
    assert!(
        notices(&d, book).contains(
            &"Ada invites you to Climbing Saturdays. You have not verified Ada. Type /join Climbing Saturdays to join."
                .to_string()
        ),
        "{:?}",
        notices(&d, book)
    );
    d.accept_invite(&r).await.unwrap();
    for _ in 0..2 {
        settle(&mut [&mut a, &mut c, &mut d]).await;
    }
    assert!(in_room(&d, climb));
    let ev = d.take_events();
    assert!(
        ev.iter().any(|e| matches!(e, Event::Joined { group, verification: Verification::Unverified { .. } } if *group == climb)),
        "{ev:?}"
    );
    assert!(
        ev.contains(&Event::Warning(socketchat_core::client::HIDDEN_NAME.into())),
        "{ev:?}"
    );
    assert!(!names(&c, climb).contains(&"Dee".to_string()));
    assert!(!names(&a, climb).contains(&"Dee".to_string()));
    let dee = a
        .members(climb)
        .into_iter()
        .find(|m| m.name != "Ada" && m.name != "Cy")
        .unwrap();
    assert!(!dee.verified);
}

#[tokio::test]
async fn a_room_called_something_else_says_so() {
    let s = TestServer::start().await;
    let (mut a, mut b, _book, climb) = setup(&s).await;
    a.test_add_offer_name(Some("Picnic"));
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(only_invite(&b).room, "Picnic");
    accept_only(&mut b).await;
    settle(&mut [&mut a, &mut b]).await;
    assert!(in_room(&b, climb));
    assert!(
        notices(&b, climb).contains(
            &"This room is called Climbing Saturdays, not Picnic as Ada said.".to_string()
        ),
        "{:?}",
        notices(&b, climb)
    );
}

// ---------- what a hostile member of the shared room can do ----------

fn seen_bytes(c: &TestClient) -> Vec<Vec<u8>> {
    c.test_app_seen()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn other_members_never_see_the_room_or_its_token() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    let mut c = person(&s, "Cy").await;
    bring(&mut a, &mut c, book).await;
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    accept_only(&mut b).await;
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert!(in_room(&b, climb));
    let seen = seen_bytes(&c);
    assert!(seen.iter().any(|m| m[0] == 14), "Cy saw the invite go by");
    for m in &seen {
        assert!(!contains(m, b"Climbing"), "room name");
        assert!(!contains(m, &climb.0), "room ID");
        assert!(
            !contains(m, &b.my_group_key(climb).unwrap().0),
            "Bo's key there"
        );
    }
    assert!(c.room_invites().is_empty());
}

#[tokio::test]
async fn another_member_cannot_pose_as_the_inviter() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    let mut c = person(&s, "Cy").await;
    bring(&mut a, &mut c, book).await;
    let trap = c.create_group("Trap").await.unwrap();
    a.invite_member(climb, "Bo").await.unwrap();
    // Bo's app answers the ask with its key before Ada's offer arrives.
    settle(&mut [&mut b, &mut c]).await;
    let mut ask = None;
    let mut key = None;
    for m in seen_bytes(&c) {
        match AppMsg::decode(&m) {
            Some(AppMsg::AddAsk { ask: id, .. }) => ask = Some(id),
            Some(AppMsg::AddKey { key: k, .. }) => key = Some(k),
            _ => {}
        }
    }
    let (ask, key) = (ask.unwrap(), key.unwrap());
    let (ak, bk, ck) = (
        a.my_group_key(book).unwrap(),
        b.my_group_key(book).unwrap(),
        c.my_group_key(book).unwrap(),
    );
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let offer = add::Offer {
        room_name: "Climbing Saturdays".into(),
        group: trap,
        host: s.addr().ip().to_string(),
        port: s.addr().port(),
        cert_fpr: s.fpr(),
        token: socketchat_proto::Token([1; 16]),
        adder_key: c.my_group_key(trap).unwrap(),
        expires_unix: socketchat_core::now_unix() + 3600,
    };
    for from in [ak, ck] {
        let cx = Context {
            via: &book,
            ask: &ask,
            from: &from,
            to: &bk,
        };
        let sealed = add::seal_offer(&crypto, &key, &cx, &offer).unwrap();
        c.test_send_app(
            book,
            &AppMsg::AddOffer {
                to: bk,
                ask,
                sealed,
            },
        )
        .await
        .unwrap();
    }
    settle(&mut [&mut b, &mut c]).await;
    assert!(b.room_invites().is_empty(), "nothing from Cy counts");
    settle(&mut [&mut a, &mut b, &mut c]).await;
    let r = only_invite(&b);
    assert_eq!(r.room, "Climbing Saturdays");
    assert_eq!(r.from_name, "Ada");
}

#[tokio::test]
async fn another_member_cannot_answer_for_the_person_invited() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    let mut c = person(&s, "Cy").await;
    bring(&mut a, &mut c, book).await;
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert_eq!(b.room_invites().len(), 1);
    let mut ask = None;
    let mut reply = None;
    for m in seen_bytes(&c) {
        if let Some(AppMsg::AddAsk {
            ask: id, reply_key, ..
        }) = AppMsg::decode(&m)
        {
            ask = Some(id);
            reply = Some(reply_key);
        }
    }
    let (ask, reply) = (ask.unwrap(), reply.unwrap());
    let (ak, bk, ck) = (
        a.my_group_key(book).unwrap(),
        b.my_group_key(book).unwrap(),
        c.my_group_key(book).unwrap(),
    );
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let kps = socketchat_testkit::forged_key_package_blob();
    for from in [bk, ck] {
        let cx = Context {
            via: &book,
            ask: &ask,
            from: &from,
            to: &ak,
        };
        let sealed = add::seal_answer(
            &crypto,
            &reply,
            &cx,
            &Answer {
                key_packages: kps.clone(),
            },
        )
        .unwrap();
        c.test_send_app(
            book,
            &AppMsg::AddAnswer {
                to: ak,
                ask,
                sealed,
            },
        )
        .await
        .unwrap();
    }
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert_eq!(names(&a, climb), ["Ada"], "nobody added without Bo's /join");
    assert_eq!(notices(&a, climb), ["Invite sent to Bo."]);
    accept_only(&mut b).await;
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(names(&a, climb), ["Ada", "Bo"]);
}

#[tokio::test]
async fn a_flood_of_invites_is_capped_and_an_unanswered_one_quiets_its_sender() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    let mut c = person(&s, "Cy").await;
    bring(&mut a, &mut c, book).await;
    let bk = b.my_group_key(book).unwrap();
    let ask_bo = || {
        let kp = add::new_key_pair(&openmls_rust_crypto::RustCrypto::default()).unwrap();
        AppMsg::AddAsk {
            to: bk,
            ask: add::new_ask(),
            reply_key: kp.public,
        }
    };
    // Cy asks Bo many times over and never follows up.
    for _ in 0..5 {
        c.test_send_app(book, &ask_bo()).await.unwrap();
    }
    settle(&mut [&mut b, &mut c]).await;
    assert_eq!(
        sent(&b, book, "AddKey"),
        3,
        "three open asks from Cy at most"
    );
    // Asks that never bring an offer go after 10 minutes.
    b.advance_clock(11 * 60);
    settle(&mut [&mut b, &mut c]).await;
    c.test_send_app(book, &ask_bo()).await.unwrap();
    settle(&mut [&mut b, &mut c]).await;
    assert_eq!(sent(&b, book, "AddKey"), 4, "room for Cy again");

    // An invite Bo lets run out quiets Ada's next one for an hour.
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(b.room_invites().len(), 1);
    a.advance_clock(ADD_TTL_SECS + 60);
    b.advance_clock(ADD_TTL_SECS + 60);
    settle(&mut [&mut a, &mut b]).await;
    assert!(b.room_invites().is_empty());
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert!(b.room_invites().is_empty(), "quiet for an hour");
}

#[tokio::test]
async fn a_join_to_a_server_that_does_not_answer_leaves_no_trace() {
    let s = TestServer::start().await;
    let (mut a, mut b, _book, climb) = setup(&s).await;
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    a.test_add_offer_port(Some(closed));
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let before = b.servers(None).len();
    let r = only_invite(&b);
    assert!(b.accept_invite(&r).await.is_err());
    assert_eq!(b.servers(None).len(), before, "no server kept for it");
    assert!(!in_room(&b, climb));
}

#[tokio::test]
async fn a_key_that_cannot_seal_ends_the_invite_once() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    b.test_reads_like_0_5_2(true);
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let ask = seen_bytes(&b)
        .iter()
        .find_map(|m| match AppMsg::decode(m) {
            Some(AppMsg::AddAsk { ask, .. }) => Some(ask),
            _ => None,
        })
        .unwrap();
    let ak = a.my_group_key(book).unwrap();
    b.test_send_app(
        book,
        &AppMsg::AddKey {
            to: ak,
            ask,
            key: vec![0; 32],
            offer_by: socketchat_core::now_unix() + 3600,
        },
    )
    .await
    .unwrap();
    a.take_events();
    for _ in 0..3 {
        settle(&mut [&mut a, &mut b]).await;
    }
    let ev = a.take_events();
    assert!(!ev.iter().any(|e| matches!(e, Event::Warning(_))), "{ev:?}");
    assert!(
        notices(&a, climb).contains(
            &"Bo's app sent a key Socketchat cannot use, so your invite to them ended.".to_string()
        ),
        "{:?}",
        notices(&a, climb)
    );
    assert!(a
        .invites()
        .await
        .unwrap()
        .iter()
        .all(|i| i.group != Some(climb)));
}

#[tokio::test]
async fn slow_mode_in_the_shared_room_holds_each_step() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    let mut c = person(&s, "Cy").await;
    bring(&mut a, &mut c, book).await;
    bring(&mut a, &mut c, climb).await;
    settle(&mut [&mut a, &mut b, &mut c]).await;
    a.set_slow_mode(book, 2).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    c.send_text(book, "hello").await.unwrap();
    let to = c.invite_member(climb, "Bo").await.unwrap();
    assert!(to.wait_secs.is_some_and(|w| w > 0 && w <= 2), "{to:?}");
    assert_eq!(sent(&c, book, "AddAsk"), 0, "nothing went yet");
    for _ in 0..20 {
        if !b.room_invites().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        settle(&mut [&mut b, &mut c]).await;
    }
    assert_eq!(b.room_invites().len(), 1);
}

/// The decoder and the sealing take any bytes without failing hard.
#[test]
fn the_steps_take_noise() {
    use rand_core::{OsRng, RngCore};
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let kp = add::new_key_pair(&crypto).unwrap();
    let k = socketchat_core::keys::Key([1; 32]);
    let g = GroupId([2; 16]);
    let ask = [3; 16];
    let cx = Context {
        via: &g,
        ask: &ask,
        from: &k,
        to: &k,
    };
    for i in 0..5000 {
        let mut b = vec![0u8; (i % 300) + 1];
        OsRng.fill_bytes(&mut b);
        b[0] = 14 + (i as u8 % 4);
        let _ = AppMsg::decode(&b);
        let s = add::Sealed {
            enc: b.iter().copied().cycle().take(32).collect(),
            ct: b.clone(),
        };
        assert!(add::open_offer(&crypto, &kp.private, &cx, &s).is_none());
        assert!(add::open_answer(&crypto, &kp.private, &cx, &s).is_none());
    }
}

/// A released 0.5.2 app cannot read the steps, whatever this build says.
#[test]
fn a_0_5_2_app_never_passes_the_version_check() {
    assert!(!add::knows_add(Some("0.5.2")));
    assert!(add::knows_add(Some(NEW)));
}

/// The invite line in the room it came through, as kept.
fn invite_notice(c: &TestClient, g: GroupId) -> socketchat_core::client::ChatLine {
    c.messages(g, 200)
        .into_iter()
        .find(|l| l.notice && l.text.contains(" invites you to "))
        .expect("an invite line")
}

#[tokio::test]
async fn the_invite_line_marks_the_command_to_type() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    // The line as it arrived, and as the room keeps it.
    let ev = b.take_events();
    let live = ev
        .iter()
        .find_map(|e| match e {
            Event::Message { group, line } if *group == book && line.notice => Some(line.clone()),
            _ => None,
        })
        .expect("the line arrived as a message");
    let kept = invite_notice(&b, book);
    for line in [&live, &kept] {
        assert_eq!(
            line.text,
            "Ada invites you to Climbing Saturdays. Type /join Climbing Saturdays to join."
        );
        let at = line.command.clone().expect("the command is marked");
        assert_eq!(&line.text[at], "/join Climbing Saturdays");
    }
    // Other lines carry no command.
    assert!(b
        .messages(book, 200)
        .iter()
        .filter(|l| l.text != kept.text)
        .all(|l| l.command.is_none()));
}

#[tokio::test]
async fn the_command_is_marked_whatever_the_room_is_called() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, _) = setup(&s).await;
    let odd = a.create_group("Type /join 2 to join").await.unwrap();
    a.invite_member(odd, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let line = invite_notice(&b, book);
    let at = line.command.clone().expect("the command is marked");
    assert_eq!(&line.text[at.clone()], "/join Type /join 2 to join");
    assert_eq!(&line.text[at.end..], " to join.");
}

#[tokio::test]
async fn invite_names_lists_who_shares_a_room_with_you() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    assert_eq!(a.invite_names(Some(climb)), ["Bo"]);
    assert_eq!(b.invite_names(Some(book)), ["Ada"], "never yourself");
    let mut c = person(&s, "Cy").await;
    bring(&mut a, &mut c, climb).await;
    settle(&mut [&mut a, &mut b, &mut c]).await;
    // People not in the room come first.
    assert_eq!(a.invite_names(Some(climb)), ["Bo", "Cy"]);
    assert_eq!(a.invite_names(Some(book)), ["Cy", "Bo"]);
    assert_eq!(a.invite_names(None), ["Bo", "Cy"]);
}

#[tokio::test]
async fn invite_names_tags_two_people_who_share_a_name() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    let mut b2 = person(&s, "bo").await;
    let hikes = a.create_group("Hikes").await.unwrap();
    bring(&mut a, &mut b2, hikes).await;
    settle(&mut [&mut a, &mut b, &mut b2]).await;
    let tag = |g, name: &str| {
        let k = a
            .members(g)
            .into_iter()
            .find(|m| m.name == name)
            .unwrap()
            .key;
        format!("{name}#{:02x}{:02x}", k.0[0], k.0[1])
    };
    let (t1, t2) = (tag(book, "Bo"), tag(hikes, "bo"));
    let mut want = vec![t1.clone(), t2.clone()];
    want.sort_by_key(|t| t.to_lowercase());
    assert_eq!(a.invite_names(Some(climb)), want);
    // Each one names one person, as /invite takes it.
    assert!(a.someone_named(&t1) && a.someone_named(&t2));
    a.invite_member(climb, &t2).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut b2]).await;
    assert!(b.room_invites().is_empty());
    assert_eq!(b2.room_invites().len(), 1);
}

#[tokio::test]
async fn the_people_a_name_could_mean_say_who_you_verified() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    // Cy made Hikes and brought in Ada and another Bo, whom Ada never
    // verified. Ada brought the first Bo in herself, so she verified him.
    let mut c = person(&s, "Cy").await;
    let hikes = c.create_group("Hikes").await.unwrap();
    bring(&mut c, &mut a, hikes).await;
    let mut b2 = person(&s, "Bo").await;
    bring(&mut c, &mut b2, hikes).await;
    settle(&mut [&mut a, &mut b, &mut b2, &mut c]).await;
    let tag = |g, verified: bool| {
        let m = a.members(g).into_iter().find(|m| m.name == "Bo").unwrap();
        assert_eq!(m.verified, verified);
        format!("Bo#{:02x}{:02x}", m.key.0[0], m.key.0[1])
    };
    let (t1, t2) = (tag(book, true), tag(hikes, false));
    let err = a.invite_member(climb, "Bo").await.unwrap_err().to_string();
    assert_eq!(
        err,
        format!("More than one person called Bo shares a room with you: {t1} (verified) in Book club and {t2} in Hikes. Type /invite {t1} or /invite {t2}.")
    );
}

#[tokio::test]
async fn the_inviter_room_keeps_a_line_that_the_invite_went() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    let mut c = person(&s, "Cy").await;
    bring(&mut a, &mut c, climb).await;
    a.take_events();
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    // Kept with the room's lines, as a plain notice.
    let line = a
        .messages(climb, 200)
        .into_iter()
        .find(|l| l.text == "Invite sent to Bo.")
        .unwrap_or_else(|| panic!("{:?}", notices(&a, climb)));
    assert!(line.notice && line.command.is_none() && line.sender_key.is_none());
    assert!(a.take_events().iter().any(|e| matches!(
        e,
        Event::Message { group, line } if *group == climb && line.text == "Invite sent to Bo."
    )));
    // Only on the inviter's screen, and only in the room invited to.
    assert!(!notices(&a, book)
        .iter()
        .any(|n| n.starts_with("Invite sent")));
    assert!(!notices(&c, climb)
        .iter()
        .any(|n| n.starts_with("Invite sent")));
    assert!(!notices(&b, book)
        .iter()
        .any(|n| n.starts_with("Invite sent")));
}

#[tokio::test]
async fn the_invite_sent_line_names_a_picked_person_by_tag() {
    let s = TestServer::start().await;
    let (mut a, mut b, _book, climb) = setup(&s).await;
    let mut b2 = person(&s, "Bo").await;
    let hikes = a.create_group("Hikes").await.unwrap();
    bring(&mut a, &mut b2, hikes).await;
    let k = a
        .members(hikes)
        .into_iter()
        .find(|m| m.name == "Bo")
        .unwrap()
        .key;
    let t2 = format!("Bo#{:02x}{:02x}", k.0[0], k.0[1]);
    a.invite_member(climb, &t2).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut b2]).await;
    assert!(
        notices(&a, climb).contains(&format!("Invite sent to {t2}.")),
        "{:?}",
        notices(&a, climb)
    );
}

/// The invite lines in room `g`.
fn invite_lines(c: &TestClient, g: GroupId) -> Vec<String> {
    c.messages(g, 200)
        .into_iter()
        .filter(|l| l.command.is_some())
        .map(|l| l.text)
        .collect()
}

const CLIMB_LINE: &str =
    "Ada invites you to Climbing Saturdays. Type /join Climbing Saturdays to join.";

#[tokio::test]
async fn an_invite_shows_in_the_room_open_on_screen() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    let mine = b.create_group("Bo's notes").await.unwrap();
    b.set_open_room(Some(mine)).unwrap();
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    // Where Bo is looking, named the same way, and nowhere else.
    assert_eq!(invite_lines(&b, mine), [CLIMB_LINE]);
    assert!(invite_lines(&b, book).is_empty());
    // Opening the room it came through shows no second copy.
    b.set_open_room(Some(book)).unwrap();
    assert!(invite_lines(&b, book).is_empty());
    assert_eq!(invite_lines(&b, mine), [CLIMB_LINE]);
    accept_only(&mut b).await;
    settle(&mut [&mut a, &mut b]).await;
    assert!(in_room(&b, climb));
}

#[tokio::test]
async fn an_invite_in_the_open_room_it_came_through_shows_once() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    b.set_open_room(Some(book)).unwrap();
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    b.set_open_room(Some(book)).unwrap();
    assert_eq!(invite_lines(&b, book), [CLIMB_LINE]);
}

#[tokio::test]
async fn an_invite_that_came_while_the_screen_was_closed_moves_to_the_room_it_opens() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    let mine = b.create_group("Bo's notes").await.unwrap();
    // No chat screen: the line waits in the room it came through, where
    // `socketchat sync` and `socketchat log` find it.
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(invite_lines(&b, book), [CLIMB_LINE]);
    assert_eq!(b.groups().iter().find(|g| g.id == book).unwrap().unseen, 1);
    // The chat screen opens on another room: the line moves there, once.
    b.take_events();
    b.set_open_room(Some(mine)).unwrap();
    assert_eq!(invite_lines(&b, mine), [CLIMB_LINE]);
    assert!(invite_lines(&b, book).is_empty());
    assert_eq!(b.groups().iter().find(|g| g.id == book).unwrap().unseen, 0);
    assert!(b.take_events().iter().any(|e| matches!(
        e,
        Event::Message { group, line } if *group == mine && line.command.is_some()
    )));
    b.set_open_room(Some(book)).unwrap();
    b.set_open_room(Some(mine)).unwrap();
    assert_eq!(invite_lines(&b, mine), [CLIMB_LINE]);
    assert!(invite_lines(&b, book).is_empty());
}

#[tokio::test]
async fn a_screen_that_opens_on_the_room_it_came_through_keeps_the_line_there() {
    let s = TestServer::start().await;
    let (mut a, mut b, book, climb) = setup(&s).await;
    let mine = b.create_group("Bo's notes").await.unwrap();
    a.invite_member(climb, "Bo").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    b.set_open_room(Some(book)).unwrap();
    b.set_open_room(Some(mine)).unwrap();
    assert_eq!(invite_lines(&b, book), [CLIMB_LINE]);
    assert!(invite_lines(&b, mine).is_empty());
}
