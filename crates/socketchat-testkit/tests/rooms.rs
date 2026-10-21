use socketchat_core::appmsg::AppMsg;
use socketchat_core::client::{Ended, Event, KEEP_UNSEEN_SECS};
use socketchat_proto::msg::GroupId;
use socketchat_testkit::{drain, settle, TestClient, TestServer};
use std::time::{SystemTime, UNIX_EPOCH};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Ada makes the room "Room"; Bo joins from her link.
async fn pair(s: &TestServer) -> (GroupId, TestClient, TestClient) {
    let mut a = TestClient::new(s, "Ada").await;
    let g = a.create_group("Room").await.unwrap();
    let mut b = TestClient::new(s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    (g, a, b)
}

/// Ada's room with Bo and Cy in it. Only Ada is an admin.
async fn trio(s: &TestServer) -> (GroupId, TestClient, TestClient, TestClient) {
    let (g, mut a, mut b) = pair(s).await;
    let mut c = TestClient::new(s, "Cy").await;
    c.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    (g, a, b, c)
}

fn summary(c: &TestClient, g: GroupId) -> socketchat_core::client::GroupSummary {
    c.groups().into_iter().find(|x| x.id == g).expect("room")
}

fn newest_seq(c: &TestClient, g: GroupId) -> u64 {
    c.messages(g, 500).last().map(|l| l.seq).unwrap_or(0)
}

#[tokio::test]
async fn unseen_counts_until_marked_seen() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    b.mark_seen(g).unwrap();
    a.send_text(g, "one").await.unwrap();
    a.send_text(g, "two").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(summary(&b, g).unseen, 2);
    b.mark_seen(g).unwrap();
    assert_eq!(summary(&b, g).unseen, 0);
    let b = b.reopen().await;
    assert_eq!(summary(&b, g).unseen, 0);
}

#[tokio::test]
async fn unseen_survives_a_restart() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    b.mark_seen(g).unwrap();
    a.send_text(g, "one").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let b = b.reopen().await;
    assert_eq!(summary(&b, g).unseen, 1);
}

#[tokio::test]
async fn own_send_counts_as_seen() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    b.mark_seen(g).unwrap();
    a.send_text(g, "one").await.unwrap();
    a.send_text(g, "two").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(summary(&b, g).unseen, 2);
    b.send_text(g, "hello").await.unwrap();
    assert_eq!(summary(&b, g).unseen, 0);
}

#[tokio::test]
async fn mute_is_local_and_persists() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    assert!(!summary(&b, g).muted);
    let before = newest_seq(&a, g);
    b.set_muted(g, true).unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(newest_seq(&a, g), before);
    assert!(summary(&b, g).muted);
    assert!(!summary(&a, g).muted);
    let mut b = b.reopen().await;
    assert!(summary(&b, g).muted);
    assert!(b.details(g).await.unwrap().muted);
    b.set_muted(g, false).unwrap();
    assert!(!summary(&b, g).muted);
}

#[tokio::test]
async fn admin_renames_room_for_everyone() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    a.rename_room(g, "Book club").await.unwrap();
    assert_eq!(summary(&a, g).name, "Book club");
    assert!(a
        .messages(g, 50)
        .iter()
        .any(|l| l.notice && l.text == "You renamed this room to Book club."));
    settle(&mut [&mut a, &mut b, &mut c]).await;
    for m in [&b, &c] {
        assert_eq!(summary(m, g).name, "Book club");
        assert!(m
            .messages(g, 50)
            .iter()
            .any(|l| l.notice && l.text == "Ada renamed this room to Book club."));
    }
}

#[tokio::test]
async fn rename_needs_a_visible_name() {
    let s = TestServer::start().await;
    let (g, mut a, _b) = pair(&s).await;
    let err = a.rename_room(g, " \u{200b} ").await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "A room name needs at least one visible character."
    );
    assert_eq!(summary(&a, g).name, "Room");
}

#[tokio::test]
async fn member_cannot_rename() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    let err = b.rename_room(g, "Mine").await.unwrap_err();
    assert_eq!(err.to_string(), "Only admins can rename this room.");
    assert_eq!(summary(&b, g).name, "Room");
    b.test_send_app(
        g,
        &AppMsg::GroupName {
            name: "Mine".into(),
        },
    )
    .await
    .unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert_eq!(summary(&a, g).name, "Room");
    assert_eq!(summary(&c, g).name, "Room");
}

#[tokio::test]
async fn newcomer_learns_name_from_any_member() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    let mut d = TestClient::new(&s, "Di").await;
    d.join(&b.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    // Ada stays offline: only Bo, who is not an admin, can tell Di the name.
    settle(&mut [&mut b, &mut d]).await;
    assert_eq!(summary(&d, g).name, "Room");
    drain(&mut a).await;
}

#[tokio::test]
async fn details_show_admins_size_and_created() {
    let s = TestServer::start().await;
    let start = unix_now();
    let (g, mut a, mut b, mut c) = trio(&s).await;
    let d = b.details(g).await.unwrap();
    assert_eq!(d.name, "Room");
    assert_eq!(d.admins, vec!["Ada".to_string()]);
    assert_eq!(d.size, 3);
    assert!(!d.muted);
    let created = d.created_unix.expect("protocol 2 server says");
    assert!(
        created >= start && created <= unix_now(),
        "{start} <= {created}"
    );
    assert!(d.joined_unix >= start);
    let da = a.details(g).await.unwrap();
    assert_eq!(da.created_unix, Some(created));
    drain(&mut c).await;
}

#[tokio::test]
async fn details_on_protocol_1_server_have_no_created_date() {
    let s = TestServer::start_with(|c| c.protocol_max = 1).await;
    let (g, mut a, _b) = pair(&s).await;
    let d = a.details(g).await.unwrap();
    assert_eq!(d.created_unix, None);
    assert_eq!(d.admins, vec!["Ada".to_string()]);
    assert_eq!(d.size, 2);
}

fn texts(c: &TestClient, g: GroupId) -> Vec<String> {
    c.messages(g, 500).into_iter().map(|l| l.text).collect()
}

fn listed(c: &TestClient, g: GroupId) -> bool {
    c.groups().iter().any(|x| x.id == g)
}

/// Ada sends "one" and "two", Bo fetches them without reading them, then
/// Ada removes Bo.
async fn removed_with_unread(s: &TestServer) -> (GroupId, TestClient, TestClient) {
    let (g, mut a, mut b) = pair(s).await;
    a.send_text(g, "one").await.unwrap();
    a.send_text(g, "two").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let bk = b.my_group_key(g).unwrap();
    a.remove_member(g, &bk).await.unwrap();
    b.sync().await.unwrap();
    (g, a, b)
}

#[tokio::test]
async fn leave_deletes_history_keys_and_group_state() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    a.send_text(g, "hello").await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert!(texts(&b, g).contains(&"hello".to_string()));
    let bk = b.my_group_key(g).unwrap();
    b.mark_seen(g).unwrap();
    drain(&mut b).await;
    b.leave(g).await.unwrap();
    assert!(b.test_traces(g).is_empty(), "{:?}", b.test_traces(g));
    assert!(!listed(&b, g));
    assert!(b.messages(g, 100).is_empty());
    let ev = drain(&mut b).await;
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Left { group } if *group == g)),
        "{ev:?}"
    );
    settle(&mut [&mut a, &mut c]).await;
    for m in [&a, &c] {
        let ms = m.members(g);
        assert_eq!(ms.len(), 2, "{}", m.display_name());
        assert!(ms.iter().all(|x| x.key != bk));
    }
    // Still gone after the profile opens again.
    let b = b.reopen().await;
    assert!(b.test_traces(g).is_empty(), "{:?}", b.test_traces(g));
    assert!(!listed(&b, g));
}

#[tokio::test]
async fn removed_member_keeps_unread_until_read() {
    let s = TestServer::start().await;
    let (g, _a, mut b) = removed_with_unread(&s).await;
    let ev = drain(&mut b).await;
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Left { group } if *group == g)),
        "{ev:?}"
    );
    let sum = summary(&b, g);
    assert_eq!(sum.ended, Some(Ended::Removed));
    assert!(sum.left);
    assert_eq!(sum.name, "Room");
    assert!(sum.unseen >= 2, "{}", sum.unseen);
    assert_eq!(b.test_traces(g), vec!["messages", "ended_rooms"]);
    let t = texts(&b, g);
    assert!(t.contains(&"one".to_string()) && t.contains(&"two".to_string()));
    // Unread history survives a restart.
    let mut b = b.reopen().await;
    assert_eq!(b.test_traces(g), vec!["messages", "ended_rooms"]);
    assert_eq!(summary(&b, g).ended, Some(Ended::Removed));
    b.mark_seen(g).unwrap();
    assert_eq!(summary(&b, g).unseen, 0);
    assert_eq!(b.purge_read(None), vec![g]);
    assert!(b.test_traces(g).is_empty(), "{:?}", b.test_traces(g));
    assert!(!listed(&b, g));
}

#[tokio::test]
async fn purge_read_keeps_the_open_room() {
    let s = TestServer::start().await;
    let (g, _a, mut b) = removed_with_unread(&s).await;
    b.mark_seen(g).unwrap();
    assert!(b.purge_read(Some(g)).is_empty());
    assert_eq!(b.test_traces(g), vec!["messages", "ended_rooms"]);
    assert!(listed(&b, g));
    assert_eq!(b.purge_read(None), vec![g]);
    assert!(b.test_traces(g).is_empty(), "{:?}", b.test_traces(g));
    assert!(!listed(&b, g));
}

#[tokio::test]
async fn unread_history_of_ended_room_goes_after_30_days() {
    let s = TestServer::start().await;
    let (g, _a, mut b) = removed_with_unread(&s).await;
    assert!(b.purge_read(None).is_empty());
    b.advance_clock(KEEP_UNSEEN_SECS - 60);
    assert!(b.purge_read(None).is_empty());
    assert!(listed(&b, g));
    b.advance_clock(120);
    assert_eq!(b.purge_read(Some(g)), vec![g]);
    assert!(b.test_traces(g).is_empty(), "{:?}", b.test_traces(g));
    assert!(!listed(&b, g));
}

#[tokio::test]
async fn ended_room_cannot_send() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = removed_with_unread(&s).await;
    settle(&mut [&mut a]).await;
    let before = newest_seq(&a, g);
    let mine = texts(&b, g);
    assert!(b.send_text(g, "still here?").await.is_err());
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(newest_seq(&a, g), before);
    assert_eq!(texts(&b, g), mine);
}

#[tokio::test]
async fn rooms_left_before_0_5_are_purged_on_open() {
    let s = TestServer::start().await;
    let (g, _a, b) = pair(&s).await;
    assert!(b.test_traces(g).contains(&"mls"));
    b.test_mark_left_0_4_0(g);
    let b = b.reopen().await;
    assert!(b.test_traces(g).is_empty(), "{:?}", b.test_traces(g));
    assert!(!listed(&b, g));
}

#[tokio::test]
async fn clear_history_keeps_membership() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    a.send_text(g, "one").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert!(texts(&b, g).contains(&"one".to_string()));
    let before = newest_seq(&a, g);
    b.clear_history(g).unwrap();
    assert!(b.messages(g, 100).is_empty());
    assert_eq!(summary(&b, g).ended, None);
    assert!(a.messages(g, 100).iter().any(|l| l.text == "one"));
    a.send_text(g, "two").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(texts(&b, g), vec!["two".to_string()]);
    assert!(newest_seq(&a, g) > before);
}

#[tokio::test]
async fn invited_back_after_removal_is_a_live_room_again() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = removed_with_unread(&s).await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let rows: Vec<_> = b.groups().into_iter().filter(|x| x.id == g).collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].ended, None);
    assert!(!rows[0].left);
    // The lines Bo never read are still there, and stay after a purge.
    b.mark_seen(g).unwrap();
    assert!(b.purge_read(None).is_empty());
    assert!(texts(&b, g).contains(&"one".to_string()));
    assert!(!b.test_traces(g).contains(&"ended_rooms"));
    a.send_text(g, "welcome back").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert!(texts(&b, g).contains(&"welcome back".to_string()));
}

#[tokio::test]
async fn ending_cut_short_is_finished_on_open() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    a.send_text(g, "one").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    b.test_cut_short_ending(g, Ended::Left);
    let b = b.reopen().await;
    assert_eq!(b.test_traces(g), vec!["messages", "ended_rooms"]);
    let rows: Vec<_> = b.groups().into_iter().filter(|x| x.id == g).collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].ended, Some(Ended::Left));
    assert!(texts(&b, g).contains(&"one".to_string()));
}
