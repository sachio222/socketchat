use socketchat_core::appmsg::AppMsg;
use socketchat_core::client::{Ended, Event, KEEP_UNSEEN_SECS};
use socketchat_core::close::{CloseOutcome, CLOSE_ASK_SECS};
use socketchat_core::net::NetError;
use socketchat_core::CoreError;
use socketchat_proto::msg::{Entry, GroupId, Push};
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
async fn theme_choice_is_local_and_persists() {
    let s = TestServer::start().await;
    let (_g, a, b) = pair(&s).await;
    assert_eq!(b.theme().unwrap(), None);
    b.set_theme("classic").unwrap();
    assert_eq!(b.theme().unwrap().as_deref(), Some("classic"));
    assert_eq!(a.theme().unwrap(), None);
    let b = b.reopen().await;
    assert_eq!(b.theme().unwrap().as_deref(), Some("classic"));
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
            .any(|e| matches!(e, Event::Left { group, name } if *group == g && name == "Room")),
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
            .any(|e| matches!(e, Event::Left { group, name } if *group == g && name == "Room")),
        "{ev:?}"
    );
    let sum = summary(&b, g);
    assert_eq!(sum.ended, Some(Ended::Removed));
    assert!(sum.left);
    assert_eq!(sum.name, "Room");
    assert!(sum.unseen >= 2, "{}", sum.unseen);
    assert_eq!(
        b.test_traces(g),
        vec!["messages", "ended_names", "ended_rooms"]
    );
    let t = texts(&b, g);
    assert!(t.contains(&"one".to_string()) && t.contains(&"two".to_string()));
    // Unread history survives a restart.
    let mut b = b.reopen().await;
    assert_eq!(
        b.test_traces(g),
        vec!["messages", "ended_names", "ended_rooms"]
    );
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
    assert_eq!(
        b.test_traces(g),
        vec!["messages", "ended_names", "ended_rooms"]
    );
    assert!(listed(&b, g));
    assert_eq!(b.purge_read(None), vec![g]);
    assert!(b.test_traces(g).is_empty(), "{:?}", b.test_traces(g));
    assert!(!listed(&b, g));
}

/// Only history tables, never keys or group state.
fn history_only(traces: &[&str]) -> bool {
    traces.contains(&"ended_rooms")
        && traces
            .iter()
            .all(|t| ["messages", "ended_names", "ended_rooms"].contains(t))
}

#[tokio::test]
async fn removed_with_nothing_unread_stays_until_purge() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    b.mark_seen(g).unwrap();
    let bk = b.my_group_key(g).unwrap();
    a.remove_member(g, &bk).await.unwrap();
    b.sync().await.unwrap();
    // Keys go at once; the room stays, listed as ended, until a purge.
    assert!(history_only(&b.test_traces(g)), "{:?}", b.test_traces(g));
    let sum = summary(&b, g);
    assert_eq!(sum.ended, Some(Ended::Removed));
    assert_eq!(sum.unseen, 0);
    assert!(b.purge_read(Some(g)).is_empty(), "the open room stays");
    assert_eq!(b.purge_read(None), vec![g]);
    assert!(b.test_traces(g).is_empty(), "{:?}", b.test_traces(g));
    assert!(!listed(&b, g));
}

#[tokio::test]
async fn closed_with_nothing_unread_stays_until_purge() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    a.vote_close(g, true).await.unwrap();
    b.sync().await.unwrap();
    b.mark_seen(g).unwrap();
    assert!(history_only(&b.test_traces(g)), "{:?}", b.test_traces(g));
    assert_eq!(summary(&b, g).ended, Some(Ended::Closed));
    assert_eq!(b.purge_read(None), vec![g]);
    assert!(!listed(&b, g));
    // The admin who closed it keeps the room until a purge too.
    assert_eq!(summary(&a, g).ended, Some(Ended::Closed));
    a.mark_seen(g).unwrap();
    assert_eq!(a.purge_read(None), vec![g]);
    assert!(a.test_traces(g).is_empty(), "{:?}", a.test_traces(g));
}

#[tokio::test]
async fn own_leave_with_nothing_unread_goes_at_once() {
    let s = TestServer::start().await;
    let (g, _a, mut b) = pair(&s).await;
    b.mark_seen(g).unwrap();
    b.leave(g).await.unwrap();
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
    // The deleted pages left the write-ahead log too.
    let wal = b.dir.path().join("socketchat.db-wal");
    assert_eq!(std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0), 0);
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
    // Listed once, as ended, before and after the profile opens again.
    let rows: Vec<_> = b.groups().into_iter().filter(|x| x.id == g).collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].ended, Some(Ended::Left));
    let b = b.reopen().await;
    assert_eq!(
        b.test_traces(g),
        vec!["messages", "ended_names", "ended_rooms"]
    );
    let rows: Vec<_> = b.groups().into_iter().filter(|x| x.id == g).collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].ended, Some(Ended::Left));
    assert!(texts(&b, g).contains(&"one".to_string()));
}

#[tokio::test]
async fn ending_cut_short_inside_openmls_is_finished_on_open() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    a.send_text(g, "one").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    b.test_cut_short_ending(g, Ended::Removed);
    // OpenMLS deletes its rows one statement at a time, the tree first.
    b.test_drop_mls_tree(g);
    let b = b.reopen().await;
    assert_eq!(
        b.test_traces(g),
        vec!["messages", "ended_names", "ended_rooms"]
    );
}

#[tokio::test]
async fn ended_room_keeps_sender_names() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    b.send_text(g, "from bo").await.unwrap();
    a.send_text(g, "one").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let bk = b.my_group_key(g).unwrap();
    a.remove_member(g, &bk).await.unwrap();
    b.sync().await.unwrap();
    assert_eq!(summary(&b, g).ended, Some(Ended::Removed));
    let check = |b: &TestClient| {
        let lines = b.messages(g, 100);
        let by = |t: &str| lines.iter().find(|l| l.text == t).unwrap().sender.clone();
        assert_eq!(by("one"), "Ada");
        assert_eq!(by("from bo"), "Bo");
    };
    check(&b);
    let mut b = b.reopen().await;
    check(&b);
    b.mark_seen(g).unwrap();
    assert_eq!(b.purge_read(None), vec![g]);
    assert!(b.test_traces(g).is_empty(), "{:?}", b.test_traces(g));
}

#[tokio::test]
async fn joining_keeps_no_spare_key_packages() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    let bk = b.my_group_key(g).unwrap();
    assert_eq!(b.test_key_packages_for(bk), 0);
    let dm = a.dm(g, &bk).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    let dk = b.my_group_key(dm).expect("Bo is in the direct message");
    assert_eq!(b.test_key_packages_for(dk), 0);
}

#[tokio::test]
async fn purge_that_fails_says_so() {
    let s = TestServer::start().await;
    let (g, _a, mut b) = removed_with_unread(&s).await;
    b.mark_seen(g).unwrap();
    drain(&mut b).await;
    b.test_fail_next_purge();
    assert!(b.purge_read(None).is_empty());
    let ev = drain(&mut b).await;
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Warning(w) if w.contains("Room"))),
        "{ev:?}"
    );
    assert_eq!(b.purge_read(None), vec![g]);
}

#[tokio::test]
async fn failed_ending_is_never_undone_by_a_purge() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    a.send_text(g, "one").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    b.mark_seen(g).unwrap();
    // The ending stops after its first step, with keys and group state
    // still on disk.
    b.test_fail_next_ending();
    assert!(b.leave(g).await.is_err());
    let rows: Vec<_> = b.groups().into_iter().filter(|x| x.id == g).collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].ended, Some(Ended::Left));
    b.mark_seen(g).unwrap();
    assert_eq!(b.purge_read(None), vec![g]);
    assert!(b.test_traces(g).is_empty(), "{:?}", b.test_traces(g));
    assert!(!listed(&b, g));
    let b = b.reopen().await;
    assert!(b.test_traces(g).is_empty(), "{:?}", b.test_traces(g));
    assert!(!listed(&b, g));
}

#[tokio::test]
async fn clearing_a_failed_ending_deletes_its_keys_too() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    a.send_text(g, "one").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    b.test_fail_next_ending();
    assert!(b.leave(g).await.is_err());
    b.clear_history(g).unwrap();
    assert!(b.test_traces(g).is_empty(), "{:?}", b.test_traces(g));
    assert!(!listed(&b, g));
}

/// Warnings that say deleted rows still have old copies in the log file.
fn old_copies(ev: &[Event]) -> usize {
    ev.iter()
        .filter(|e| matches!(e, Event::Warning(w) if w.contains("old copies")))
        .count()
}

#[tokio::test]
async fn busy_log_after_leaving_warns_and_succeeds() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    a.send_text(g, "one").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    b.mark_seen(g).unwrap();
    drain(&mut b).await;
    b.test_busy_next_checkpoint();
    b.leave(g).await.unwrap();
    assert!(b.test_traces(g).is_empty(), "{:?}", b.test_traces(g));
    assert!(!listed(&b, g));
    let ev = drain(&mut b).await;
    assert_eq!(old_copies(&ev), 1, "{ev:?}");
}

#[tokio::test]
async fn busy_log_after_removal_with_unread_warns() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    a.send_text(g, "one").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    drain(&mut b).await;
    let bk = b.my_group_key(g).unwrap();
    a.remove_member(g, &bk).await.unwrap();
    b.test_busy_next_checkpoint();
    b.sync().await.unwrap();
    assert_eq!(summary(&b, g).ended, Some(Ended::Removed));
    assert_eq!(
        b.test_traces(g),
        vec!["messages", "ended_names", "ended_rooms"]
    );
    let ev = drain(&mut b).await;
    assert_eq!(old_copies(&ev), 1, "{ev:?}");
}

#[tokio::test]
async fn busy_log_after_clearing_warns_and_succeeds() {
    let s = TestServer::start().await;
    let (g, _a, mut b) = removed_with_unread(&s).await;
    drain(&mut b).await;
    b.test_busy_next_checkpoint();
    b.clear_history(g).unwrap();
    assert!(b.test_traces(g).is_empty(), "{:?}", b.test_traces(g));
    assert!(!listed(&b, g));
    assert_eq!(old_copies(&drain(&mut b).await), 1);
    // A live room too.
    let (g, mut a, mut b) = pair(&s).await;
    a.send_text(g, "one").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    drain(&mut b).await;
    b.test_busy_next_checkpoint();
    b.clear_history(g).unwrap();
    assert!(b.messages(g, 100).is_empty());
    assert_eq!(summary(&b, g).ended, None);
    assert_eq!(old_copies(&drain(&mut b).await), 1);
}

fn server_rows(s: &TestServer, g: GroupId) -> (i64, i64) {
    let db = socketchat_testkit::open_server_db(s);
    let n = |t: &str, col: &str| -> i64 {
        db.query_row(
            &format!("SELECT count(*) FROM {t} WHERE {col} = ?1"),
            [g.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap()
    };
    (n("groups", "id"), n("mailboxes", "group_id"))
}

#[tokio::test]
async fn alone_leaver_tells_the_server() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Room").await.unwrap();
    a.send_text(g, "hello").await.unwrap();
    assert_eq!(server_rows(&s, g), (1, 1));
    a.leave(g).await.unwrap();
    assert_eq!(server_rows(&s, g), (0, 0));
    assert!(a.test_traces(g).is_empty(), "{:?}", a.test_traces(g));
    assert!(!listed(&a, g));
}

#[tokio::test]
async fn alone_leaver_on_protocol_1_ends_locally() {
    let s = TestServer::start_with(|c| c.protocol_max = 1).await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Room").await.unwrap();
    a.leave(g).await.unwrap();
    assert!(a.test_traces(g).is_empty(), "{:?}", a.test_traces(g));
    assert!(!listed(&a, g));
    assert_eq!(server_rows(&s, g), (1, 1));
}

#[tokio::test]
async fn alone_leaver_ends_locally_when_the_server_is_gone() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Room").await.unwrap();
    drain(&mut a).await;
    s.handle.shutdown();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    a.leave(g).await.unwrap();
    assert!(a.test_traces(g).is_empty(), "{:?}", a.test_traces(g));
    assert!(!listed(&a, g));
    let ev = drain(&mut a).await;
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Warning(w) if w.contains("could not delete"))),
        "{ev:?}"
    );
}

#[tokio::test]
async fn alone_leaver_reconnects_after_a_dropped_connection() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Room").await.unwrap();
    drain(&mut a).await;
    a.test_drop_connections();
    a.leave(g).await.unwrap();
    assert_eq!(server_rows(&s, g), (0, 0));
    assert!(a.test_traces(g).is_empty(), "{:?}", a.test_traces(g));
    let ev = drain(&mut a).await;
    assert!(!ev.iter().any(|e| matches!(e, Event::Warning(_))), "{ev:?}");
}

#[tokio::test]
async fn refused_last_leave_still_posts_the_leave_request() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    drain(&mut b).await;
    // Bo's list of members is out of date: he believes he is alone.
    b.test_leave_as_if_alone();
    b.leave(g).await.unwrap();
    assert!(b.test_traces(g).is_empty(), "{:?}", b.test_traces(g));
    assert!(!listed(&b, g));
    // The server kept the room, and Ada sees Bo go.
    assert_eq!(server_rows(&s, g).0, 1);
    settle(&mut [&mut a]).await;
    assert_eq!(a.members(g).len(), 1);
    let ev = drain(&mut b).await;
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Warning(w) if w.contains("other people are still"))),
        "{ev:?}"
    );
}

// ---------- closing a room ----------

async fn settle_all(cs: &mut [TestClient]) {
    let mut refs: Vec<&mut TestClient> = cs.iter_mut().collect();
    settle(&mut refs).await;
}

/// Ada's room "Room" with everyone in `names` (Ada first) in it. The first
/// `admins` of them are admins. Every event so far is drained.
async fn room_of(s: &TestServer, names: &[&str], admins: usize) -> (GroupId, Vec<TestClient>) {
    let mut cs = vec![TestClient::new(s, names[0]).await];
    let g = cs[0].create_group("Room").await.unwrap();
    for n in &names[1..] {
        let mut c = TestClient::new(s, n).await;
        let link = cs[0].invite(Some(g), false).await.unwrap().0;
        c.join(&link).await.unwrap();
        cs.push(c);
        settle_all(&mut cs).await;
    }
    for i in 1..admins {
        let k = cs[i].my_group_key(g).unwrap();
        cs[0].make_admin(g, &k).await.unwrap();
    }
    settle_all(&mut cs).await;
    for c in cs.iter_mut() {
        drain(c).await;
    }
    (g, cs)
}

fn warnings(ev: &[Event]) -> Vec<&Event> {
    ev.iter()
        .filter(|e| matches!(e, Event::Warning(_)))
        .collect()
}

/// The room is no longer live for `c`, and if its history is still here
/// it shows as closed.
fn closed_for(c: &TestClient, g: GroupId) {
    assert!(
        c.my_group_key(g).is_none(),
        "{} is still in",
        c.display_name()
    );
    for x in c.groups().into_iter().filter(|x| x.id == g) {
        assert_eq!(x.ended, Some(Ended::Closed), "{}", c.display_name());
    }
}

#[tokio::test]
async fn one_admin_closes_at_once() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    drain(&mut b).await;
    drain(&mut c).await;
    assert_eq!(a.vote_close(g, true).await.unwrap(), CloseOutcome::Closed);
    // Keys go at once; the history waits for a purge.
    assert!(history_only(&a.test_traces(g)), "{:?}", a.test_traces(g));
    assert_eq!(a.purge_read(None), vec![g]);
    assert!(a.test_traces(g).is_empty(), "{:?}", a.test_traces(g));
    assert!(!listed(&a, g));
    settle(&mut [&mut b, &mut c]).await;
    for m in [&mut b, &mut c] {
        let ev = drain(m).await;
        assert!(
            ev.iter().any(
                |e| matches!(e, Event::Closed { group, name, by } if *group == g && name == "Room" && by == "Ada")
            ),
            "{ev:?}"
        );
        assert!(
            ev.iter()
                .any(|e| matches!(e, Event::Left { group, .. } if *group == g)),
            "{ev:?}"
        );
        assert!(warnings(&ev).is_empty(), "{ev:?}");
        assert_eq!(summary(m, g).ended, Some(Ended::Closed));
        assert!(
            m.messages(g, 50)
                .iter()
                .any(|l| l.notice && l.text == "Ada closed this room."),
            "{:?}",
            texts(m, g)
        );
        // Ending the room took its votes with its other state.
        assert_eq!(
            m.test_traces(g),
            vec!["messages", "ended_names", "ended_rooms"]
        );
        m.mark_seen(g).unwrap();
        assert_eq!(m.purge_read(None), vec![g]);
        assert!(m.test_traces(g).is_empty(), "{:?}", m.test_traces(g));
    }
    assert_eq!(server_rows(&s, g), (0, 0));
}

#[tokio::test]
async fn three_admins_must_all_agree() {
    let s = TestServer::start().await;
    let (g, mut cs) = room_of(&s, &["Ada", "Bo", "Cy", "Di"], 3).await;
    assert_eq!(
        cs[0].vote_close(g, true).await.unwrap(),
        CloseOutcome::Waiting { yes: 1, needed: 3 }
    );
    settle_all(&mut cs).await;
    assert!(texts(&cs[3], g).contains(&"Ada asked to close this room.".to_string()));
    let ev = drain(&mut cs[3]).await;
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::CloseVote { group, view }
            if *group == g && view.yes == 1 && view.needed == 3 && view.asked_by == "Ada")),
        "{ev:?}"
    );
    assert_eq!(
        cs[1].vote_close(g, true).await.unwrap(),
        CloseOutcome::Waiting { yes: 2, needed: 3 }
    );
    settle_all(&mut cs).await;
    assert!(texts(&cs[0], g).contains(&"Bo agreed to close this room.".to_string()));
    assert!(cs[0].test_traces(g).contains(&"close_votes"));
    assert_eq!(
        cs[2].vote_close(g, false).await.unwrap(),
        CloseOutcome::Kept
    );
    settle_all(&mut cs).await;
    let view = cs[0].close_state(g).unwrap();
    assert!(view.kept, "{view:?}");
    assert_eq!((view.yes, view.no, view.needed, view.admins), (2, 1, 3, 3));
    assert_eq!(view.my_vote, Some(true));
    assert_eq!(cs[0].details(g).await.unwrap().close, Some(view));
    let t = texts(&cs[3], g);
    assert!(
        t.iter()
            .any(|l| l.contains("Cy wants to keep this room open.")),
        "{t:?}"
    );
    assert!(
        t.iter()
            .any(|l| l.contains("This room stays open: too few admins agreed to close it.")),
        "{t:?}"
    );
    for (i, c) in cs.iter_mut().enumerate() {
        c.send_text(g, &format!("still here {i}")).await.unwrap();
    }
    settle_all(&mut cs).await;
    for c in &cs {
        assert_eq!(summary(c, g).ended, None);
        assert!(texts(c, g).contains(&"still here 3".to_string()));
    }
    assert_eq!(server_rows(&s, g).0, 1);
}

#[tokio::test]
async fn four_admins_need_three() {
    let s = TestServer::start().await;
    let (g, mut cs) = room_of(&s, &["Ada", "Bo", "Cy", "Di", "Ed"], 4).await;
    assert_eq!(
        cs[0].vote_close(g, true).await.unwrap(),
        CloseOutcome::Waiting { yes: 1, needed: 3 }
    );
    settle_all(&mut cs).await;
    assert_eq!(
        cs[1].vote_close(g, true).await.unwrap(),
        CloseOutcome::Waiting { yes: 2, needed: 3 }
    );
    settle_all(&mut cs).await;
    assert_eq!(
        cs[2].vote_close(g, true).await.unwrap(),
        CloseOutcome::Closed
    );
    settle_all(&mut cs).await;
    for c in cs.iter_mut() {
        closed_for(c, g);
        let ev = drain(c).await;
        assert!(warnings(&ev).is_empty(), "{ev:?}");
    }
    for c in [&cs[0], &cs[1], &cs[3], &cs[4]] {
        assert!(texts(c, g).contains(&"Cy closed this room.".to_string()));
    }
    assert_eq!(server_rows(&s, g), (0, 0));
}

#[tokio::test]
async fn member_cannot_close() {
    let s = TestServer::start().await;
    let (g, mut cs) = room_of(&s, &["Ada", "Bo", "Cy", "Di"], 3).await;
    let before = newest_seq(&cs[0], g);
    let err = cs[3].vote_close(g, true).await.unwrap_err();
    assert_eq!(err.to_string(), "Only admins can close this room.");
    settle_all(&mut cs).await;
    assert_eq!(newest_seq(&cs[0], g), before);
    assert_eq!(cs[0].close_state(g), None);
}

#[tokio::test]
async fn forged_close_without_votes_changes_nothing() {
    let s = TestServer::start().await;
    let (g, mut cs) = room_of(&s, &["Ada", "Bo", "Cy", "Di"], 3).await;
    cs[0]
        .test_send_app(g, &AppMsg::Closed { close_id: [7; 16] })
        .await
        .unwrap();
    // A vote from someone who is not an admin does not count either.
    cs[3]
        .test_send_app(
            g,
            &AppMsg::CloseVote {
                close_id: [8; 16],
                yes: true,
            },
        )
        .await
        .unwrap();
    settle_all(&mut cs).await;
    for c in cs.iter_mut() {
        assert_eq!(summary(c, g).ended, None, "{}", c.display_name());
        assert_eq!(c.close_state(g), None, "{}", c.display_name());
        let t = texts(c, g);
        assert!(!t.iter().any(|l| l.contains("close")), "{t:?}");
        // Not even stored.
        assert!(!c.test_traces(g).contains(&"close_votes"));
        let ev = drain(c).await;
        assert!(
            !ev.iter()
                .any(|e| matches!(e, Event::Closed { .. } | Event::Left { .. })),
            "{ev:?}"
        );
    }
    cs[1].send_text(g, "still open").await.unwrap();
    settle_all(&mut cs).await;
    assert!(texts(&cs[2], g).contains(&"still open".to_string()));
    assert_eq!(server_rows(&s, g).0, 1);
}

#[tokio::test]
async fn two_admins_finish_at_once_closes_once() {
    let s = TestServer::start().await;
    let (g, mut cs) = room_of(&s, &["Ada", "Bo", "Cy", "Di", "Ed"], 4).await;
    assert_eq!(
        cs[0].vote_close(g, true).await.unwrap(),
        CloseOutcome::Waiting { yes: 1, needed: 3 }
    );
    settle_all(&mut cs).await;
    for c in cs.iter_mut() {
        drain(c).await;
    }
    {
        let (left, right) = cs.split_at_mut(2);
        let (bo, cy) = (&mut left[1], &mut right[0]);
        let (rb, rc) = tokio::join!(bo.vote_close(g, true), cy.vote_close(g, true));
        rb.unwrap();
        rc.unwrap();
        // Each now sees three yes votes, its own among them: both finish
        // the close at the same moment.
        let (sb, sc) = tokio::join!(bo.sync(), cy.sync());
        sb.unwrap();
        sc.unwrap();
    }
    settle_all(&mut cs).await;
    let mut closers = Vec::new();
    for (i, c) in cs.iter_mut().enumerate() {
        closed_for(c, g);
        let ev = drain(c).await;
        assert!(warnings(&ev).is_empty(), "{}: {ev:?}", c.display_name());
        if i == 1 || i == 2 {
            closers.extend(ev.into_iter().filter_map(|e| match e {
                Event::Closed { by, .. } => Some(by),
                _ => None,
            }));
        }
    }
    // The admin whose commit lost the race names the one whose commit
    // landed, as that one names itself.
    assert_eq!(closers.len(), 2, "{closers:?}");
    assert_eq!(closers[0], closers[1], "{closers:?}");
    assert_eq!(server_rows(&s, g), (0, 0));
}

#[tokio::test]
async fn member_away_during_close_learns_on_return() {
    let s = TestServer::start().await;
    let (g, mut cs) = room_of(&s, &["Ada", "Bo", "Di"], 1).await;
    cs[0].send_text(g, "see you").await.unwrap();
    settle_all(&mut cs).await;
    let di = cs.pop().unwrap().reopen_later();
    assert_eq!(
        cs[0].vote_close(g, true).await.unwrap(),
        CloseOutcome::Closed
    );
    settle_all(&mut cs).await;
    let mut di = di.open().await;
    di.sync().await.unwrap();
    let ev = drain(&mut di).await;
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Left { group, .. } if *group == g)),
        "{ev:?}"
    );
    assert_eq!(summary(&di, g).ended, Some(Ended::Removed));
    assert!(texts(&di, g).contains(&"see you".to_string()));
    di.mark_seen(g).unwrap();
    assert_eq!(di.purge_read(None), vec![g]);
    assert!(di.test_traces(g).is_empty(), "{:?}", di.test_traces(g));
}

#[tokio::test]
async fn close_on_protocol_1_server_posts_nothing() {
    let s = TestServer::start_with(|c| c.protocol_max = 1).await;
    let (g, mut a, mut b) = pair(&s).await;
    let before = texts(&b, g);
    let err = a.vote_close(g, true).await.unwrap_err();
    assert!(
        matches!(err, CoreError::Net(NetError::Unsupported { .. })),
        "{err:?}"
    );
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(texts(&b, g), before);
    assert_eq!(a.close_state(g), None);
}

#[tokio::test]
async fn close_request_expires() {
    let s = TestServer::start().await;
    let (g, mut cs) = room_of(&s, &["Ada", "Bo"], 2).await;
    assert_eq!(
        cs[0].vote_close(g, true).await.unwrap(),
        CloseOutcome::Waiting { yes: 1, needed: 2 }
    );
    settle_all(&mut cs).await;
    let asked = cs[1].close_state(g).expect("Bo sees Ada's request");
    cs[1].advance_clock(CLOSE_ASK_SECS + 60);
    assert_eq!(cs[1].close_state(g), None);
    let err = cs[1].vote_close(g, false).await.unwrap_err();
    assert_eq!(err.to_string(), "Nobody has asked to close this room.");
    assert_eq!(
        cs[1].vote_close(g, true).await.unwrap(),
        CloseOutcome::Waiting { yes: 1, needed: 2 }
    );
    let fresh = cs[1].close_state(g).unwrap();
    assert_ne!(fresh.close_id, asked.close_id);
    assert_eq!(fresh.asked_by, "Bo");
    assert_eq!(fresh.my_vote, Some(true));
}

#[tokio::test]
async fn member_whose_app_was_waiting_sees_the_close() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    drain(&mut b).await;
    assert_eq!(a.vote_close(g, true).await.unwrap(), CloseOutcome::Closed);
    // The chat screen waits for the server's push, then syncs.
    assert_eq!(
        b.wait(std::time::Duration::from_secs(5)).await,
        socketchat_core::client::Wake::Push
    );
    b.sync().await.unwrap();
    assert_eq!(summary(&b, g).ended, Some(Ended::Closed));
    assert!(texts(&b, g).contains(&"Ada closed this room.".to_string()));
}

fn closed_events(ev: &[Event]) -> usize {
    ev.iter()
        .filter(|e| matches!(e, Event::Closed { .. }))
        .count()
}

#[tokio::test]
async fn forged_close_then_a_removal_ends_as_removed() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    a.test_send_app(g, &AppMsg::Closed { close_id: [7; 16] })
        .await
        .unwrap();
    a.send_text(g, "one").await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    drain(&mut b).await;
    let bk = b.my_group_key(g).unwrap();
    a.remove_member(g, &bk).await.unwrap();
    b.sync().await.unwrap();
    let ev = drain(&mut b).await;
    assert_eq!(closed_events(&ev), 0, "{ev:?}");
    assert_eq!(summary(&b, g).ended, Some(Ended::Removed));
}

#[tokio::test]
async fn remembered_close_is_forgotten_after_a_group_change() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    a.test_send_app(g, &AppMsg::Closed { close_id: [7; 16] })
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    a.update_keys(g).await.unwrap();
    a.send_text(g, "one").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    drain(&mut b).await;
    // Removing Bo leaves only Ada, as a close would, but weeks later.
    let bk = b.my_group_key(g).unwrap();
    a.remove_member(g, &bk).await.unwrap();
    b.sync().await.unwrap();
    let ev = drain(&mut b).await;
    assert_eq!(closed_events(&ev), 0, "{ev:?}");
    assert_eq!(summary(&b, g).ended, Some(Ended::Removed));
}

#[tokio::test]
async fn close_retry_posts_closed_once() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    a.test_drop_after_closed();
    assert!(a.vote_close(g, true).await.is_err());
    assert!(a.my_group_key(g).is_some());
    a.sync().await.unwrap();
    assert!(a.my_group_key(g).is_none());
    assert_eq!(a.test_closed_posts(), 1);
    settle(&mut [&mut b, &mut c]).await;
    closed_for(&b, g);
    closed_for(&c, g);
    assert_eq!(server_rows(&s, g), (0, 0));
}

#[tokio::test]
async fn half_finished_close_without_admin_rights_warns_once() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    drain(&mut c).await;
    // Cy is not an admin, yet its app holds a close it started.
    c.test_set_closing(g, [5; 16]);
    c.sync().await.unwrap();
    c.sync().await.unwrap();
    let ev = drain(&mut c).await;
    assert_eq!(warnings(&ev).len(), 1, "{ev:?}");
    assert_eq!(c.test_closed_posts(), 0);
    settle(&mut [&mut a, &mut b, &mut c]).await;
    for m in [&a, &b, &c] {
        assert_eq!(summary(m, g).ended, None, "{}", m.display_name());
    }
}

#[tokio::test]
async fn expired_request_never_closes_by_itself() {
    let s = TestServer::start().await;
    let (g, mut cs) = room_of(&s, &["Ada", "Bo", "Cy"], 2).await;
    assert_eq!(
        cs[0].vote_close(g, true).await.unwrap(),
        CloseOutcome::Waiting { yes: 1, needed: 2 }
    );
    settle_all(&mut cs).await;
    cs[0].advance_clock(CLOSE_ASK_SECS + 60);
    // With Bo gone, Ada's old yes would be enough on its own.
    cs[1].leave(g).await.unwrap();
    for _ in 0..3 {
        cs[0].sync().await.unwrap();
        cs[2].sync().await.unwrap();
    }
    assert_eq!(cs[0].members(g).len(), 2);
    assert_eq!(summary(&cs[0], g).ended, None);
    assert_eq!(summary(&cs[2], g).ended, None);
    assert_eq!(server_rows(&s, g).0, 1);
}

#[tokio::test]
async fn member_who_joined_after_the_votes_learns_who_closed() {
    let s = TestServer::start().await;
    let (g, mut cs) = room_of(&s, &["Ada", "Bo", "Cy", "Di"], 4).await;
    cs[0].vote_close(g, true).await.unwrap();
    settle_all(&mut cs).await;
    cs[1].vote_close(g, true).await.unwrap();
    settle_all(&mut cs).await;
    let mut eve = TestClient::new(&s, "Eve").await;
    let link = cs[0].invite(Some(g), false).await.unwrap().0;
    eve.join(&link).await.unwrap();
    cs.push(eve);
    settle_all(&mut cs).await;
    assert_eq!(
        cs[2].vote_close(g, true).await.unwrap(),
        CloseOutcome::Closed
    );
    settle_all(&mut cs).await;
    let eve = &mut cs[4];
    closed_for(eve, g);
    assert!(
        texts(eve, g).contains(&"Cy closed this room.".to_string()),
        "{:?}",
        texts(eve, g)
    );
    let ev = drain(eve).await;
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Closed { by, .. } if by == "Cy")),
        "{ev:?}"
    );
}

fn entry(seq: u64, len: usize) -> Entry {
    Entry {
        seq,
        mls: vec![0; len],
    }
}

#[tokio::test]
async fn pushes_from_another_server_are_not_kept() {
    let s = TestServer::start().await;
    let (g, mut a, _b) = pair(&s).await;
    let home = a.test_server_of(g);
    let push = |seq| Push::Entry {
        group: g,
        entry: entry(seq, 10),
    };
    a.test_inject_push(home + 1, push(1000));
    assert_eq!(a.test_pushed(g).0, 0);
    a.test_inject_push(home, push(1001));
    assert_eq!(a.test_pushed(g).0, 1);
}

#[tokio::test]
async fn pushed_entries_kept_up_to_a_byte_cap() {
    let s = TestServer::start().await;
    let (g, mut a, _b) = pair(&s).await;
    let home = a.test_server_of(g);
    for i in 0..20 {
        a.test_inject_push(
            home,
            Push::Entry {
                group: g,
                entry: entry(1000 + i, 1 << 20),
            },
        );
    }
    let (n, bytes) = a.test_pushed(g);
    assert!(bytes <= 8 << 20, "{n} entries, {bytes} bytes");
    // The oldest stay: a replay starts from them.
    assert!(n >= 7, "{n}");
}

#[tokio::test]
async fn failed_close_check_is_one_rooms_warning() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    drain(&mut b).await;
    b.test_fail_next_close_check();
    a.send_text(g, "one").await.unwrap();
    b.sync().await.unwrap();
    let ev = drain(&mut b).await;
    assert_eq!(warnings(&ev).len(), 1, "{ev:?}");
    assert!(texts(&b, g).contains(&"one".to_string()));
}

#[tokio::test]
async fn kept_request_stays_kept_after_an_admin_leaves() {
    let s = TestServer::start().await;
    let (g, mut cs) = room_of(&s, &["Ada", "Bo", "Cy", "Di"], 3).await;
    cs[0].vote_close(g, true).await.unwrap();
    settle_all(&mut cs).await;
    cs[1].vote_close(g, true).await.unwrap();
    settle_all(&mut cs).await;
    assert_eq!(
        cs[2].vote_close(g, false).await.unwrap(),
        CloseOutcome::Kept
    );
    settle_all(&mut cs).await;
    let kept = cs[0].close_state(g).unwrap();
    assert!(kept.kept);
    // Kept for good, in a table ending the room deletes.
    assert!(cs[0].test_traces(g).contains(&"close_kept"));
    // With Cy gone, Ada's and Bo's yes would be all two admins.
    let mut cy = cs.remove(2);
    cy.leave(g).await.unwrap();
    settle_all(&mut cs).await;
    settle_all(&mut cs).await;
    for c in &cs {
        assert_eq!(summary(c, g).ended, None, "{}", c.display_name());
        let view = c.close_state(g).unwrap();
        assert!(view.kept, "{}: {view:?}", c.display_name());
        assert_eq!(view.close_id, kept.close_id);
    }
    assert_eq!(cs[0].members(g).len(), 3);
    assert_eq!(server_rows(&s, g).0, 1);
    // Asking again starts a new request.
    assert_eq!(
        cs[0].vote_close(g, true).await.unwrap(),
        CloseOutcome::Waiting { yes: 1, needed: 2 }
    );
    let fresh = cs[0].close_state(g).unwrap();
    assert_ne!(fresh.close_id, kept.close_id);
    assert!(!fresh.kept);
}

#[tokio::test]
async fn kept_request_closed_by_an_admin_leaving_stays_kept() {
    let s = TestServer::start().await;
    // Five admins need three. Ada says yes, Bo and Cy say no: three can
    // still agree until Di leaves.
    let (g, mut cs) = room_of(&s, &["Ada", "Bo", "Cy", "Di", "Ed"], 5).await;
    cs[0].vote_close(g, true).await.unwrap();
    settle_all(&mut cs).await;
    cs[1].vote_close(g, false).await.unwrap();
    settle_all(&mut cs).await;
    cs[2].vote_close(g, false).await.unwrap();
    settle_all(&mut cs).await;
    assert!(!cs[0].close_state(g).unwrap().kept);
    let mut di = cs.remove(3);
    di.leave(g).await.unwrap();
    settle_all(&mut cs).await;
    let kept = cs[0].close_state(g).unwrap();
    assert!(kept.kept, "{kept:?}");
    assert!(texts(&cs[0], g)
        .contains(&"This room stays open: too few admins agreed to close it.".to_string()));
    // Bo and Cy change their minds, but the request was kept: it never
    // closes the room.
    cs[1]
        .test_send_app(
            g,
            &AppMsg::CloseVote {
                close_id: kept.close_id,
                yes: true,
            },
        )
        .await
        .unwrap();
    cs[2]
        .test_send_app(
            g,
            &AppMsg::CloseVote {
                close_id: kept.close_id,
                yes: true,
            },
        )
        .await
        .unwrap();
    settle_all(&mut cs).await;
    for c in &cs {
        assert_eq!(summary(c, g).ended, None, "{}", c.display_name());
    }
    assert_eq!(server_rows(&s, g).0, 1);
}

#[tokio::test]
async fn retry_after_giving_up_posts_closed_once() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    a.test_refuse_next_close_commit();
    assert!(a.vote_close(g, true).await.is_err());
    assert!(a.my_group_key(g).is_some());
    assert_eq!(a.test_closed_posts(), 1);
    assert_eq!(a.vote_close(g, true).await.unwrap(), CloseOutcome::Closed);
    assert_eq!(a.test_closed_posts(), 1);
    settle(&mut [&mut b, &mut c]).await;
    closed_for(&b, g);
    closed_for(&c, g);
    assert_eq!(server_rows(&s, g), (0, 0));
}

// ---------- open invite links ----------

const NOT_VALID: &str = "this invite link is not valid on this server";

#[tokio::test]
async fn invites_lists_room_and_server_links() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Crew").await.unwrap();
    let (room_link, room_exp) = a.invite(Some(g), false).await.unwrap();
    let (server_link, server_exp) = a.invite(None, false).await.unwrap();
    let list = a.invites().await.unwrap();
    assert_eq!(list.len(), 2, "{list:?}");
    assert!(list
        .windows(2)
        .all(|w| w[0].expires_unix <= w[1].expires_unix));
    let room = list.iter().find(|i| i.token == room_link.token).unwrap();
    assert_eq!(room.group, Some(g));
    assert_eq!(room.label, "Crew");
    assert_eq!(room.expires_unix, room_exp);
    let server = list.iter().find(|i| i.token == server_link.token).unwrap();
    assert_eq!(server.group, None);
    assert_eq!(server.label, "Server invite");
    assert_eq!(server.expires_unix, server_exp);
}

#[tokio::test]
async fn invites_sort_by_expiry_then_token_and_name_an_unnamed_room() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("").await.unwrap();
    for _ in 0..6 {
        a.invite(Some(g), false).await.unwrap();
    }
    let list = a.invites().await.unwrap();
    assert_eq!(list.len(), 6);
    assert!(list
        .windows(2)
        .all(|w| (w[0].expires_unix, w[0].token.0) < (w[1].expires_unix, w[1].token.0)));
    assert!(list.iter().all(|i| i.label == "a chat"), "{list:?}");
}

#[tokio::test]
async fn cancelled_link_no_longer_works() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Crew").await.unwrap();
    let (room_link, _) = a.invite(Some(g), false).await.unwrap();
    let (server_link, _) = a.invite(None, false).await.unwrap();
    a.cancel_invite(room_link.token).await.unwrap();
    let list = a.invites().await.unwrap();
    assert_eq!(list.len(), 1, "{list:?}");
    assert_eq!(list[0].token, server_link.token);
    let mut b = TestClient::profile_only("Bo").await;
    let err = b.join(&room_link).await.unwrap_err();
    assert!(err.to_string().contains(NOT_VALID), "{err}");
    // The link is gone for good, and so is a server link once cancelled.
    a.cancel_invite(server_link.token).await.unwrap();
    assert!(a.invites().await.unwrap().is_empty());
    let mut c = TestClient::profile_only("Cy").await;
    let err = c.join(&server_link).await.unwrap_err();
    assert!(err.to_string().contains(NOT_VALID), "{err}");
}

#[tokio::test]
async fn used_link_drops_off_the_list() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Crew").await.unwrap();
    let (link, _) = a.invite(Some(g), false).await.unwrap();
    let (spare, _) = a.invite(Some(g), false).await.unwrap();
    let mut b = TestClient::new(&s, "Bo").await;
    b.join(&link).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let list = a.invites().await.unwrap();
    assert_eq!(list.len(), 1, "{list:?}");
    assert_eq!(list[0].token, spare.token);
    // Cancelling the used link says so, and leaves the other alone.
    let err = a.cancel_invite(link.token).await.unwrap_err();
    assert!(err.to_string().contains("already used"), "{err}");
    assert_eq!(a.invites().await.unwrap().len(), 1);
}

#[tokio::test]
async fn invites_on_protocol_1_server_warn() {
    let s = TestServer::start_with(|c| c.protocol_max = 1).await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Crew").await.unwrap();
    a.invite(Some(g), false).await.unwrap();
    drain(&mut a).await;
    assert!(a.invites().await.unwrap().is_empty());
    let ev = drain(&mut a).await;
    let want = format!(
        "{} runs an older version of Socketchat, so its invite links can't be listed here.",
        s.addr()
    );
    let got: Vec<_> = warnings(&ev);
    assert_eq!(got.len(), 1, "{ev:?}");
    assert!(matches!(got[0], Event::Warning(w) if *w == want), "{ev:?}");
}

#[tokio::test]
async fn cancel_unknown_link_says_so() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let err = a
        .cancel_invite(socketchat_proto::Token([7; 16]))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, CoreError::Other(m) if m == "That invite link isn't one of yours, or it's already gone."),
        "{err:?}"
    );
}

#[tokio::test]
async fn leaving_a_room_drops_its_invite_rows_but_not_server_links() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Crew").await.unwrap();
    a.invite(Some(g), false).await.unwrap();
    let (server_link, _) = a.invite(None, false).await.unwrap();
    assert!(a.test_traces(g).contains(&"invites_made"));
    a.leave(g).await.unwrap();
    assert!(a.test_traces(g).is_empty(), "{:?}", a.test_traces(g));
    let list = a.invites().await.unwrap();
    assert_eq!(list.len(), 1, "{list:?}");
    assert_eq!(list[0].token, server_link.token);
}

#[tokio::test]
async fn unreachable_server_does_not_blank_the_list() {
    let s1 = TestServer::start().await;
    let s2 = TestServer::start().await;
    let mut a = TestClient::new(&s1, "Ada").await;
    a.join(&s2.server_invite()).await.unwrap();
    // Server links go on the newest server; the older one stops.
    let (link, _) = a.invite(None, false).await.unwrap();
    s1.handle.shutdown();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    drain(&mut a).await;
    let rows = a.test_invite_rows();
    let list = a.invites().await.unwrap();
    assert_eq!(list.len(), 1, "{list:?}");
    assert_eq!(list[0].token, link.token);
    let ev = drain(&mut a).await;
    let w = warnings(&ev);
    assert_eq!(w.len(), 1, "{ev:?}");
    assert!(
        matches!(w[0], Event::Warning(m) if m.ends_with("could not be reached, so its invite links can't be listed here.")),
        "{ev:?}"
    );
    assert_eq!(a.test_invite_rows(), rows);
}

#[tokio::test]
async fn more_than_100_server_links_are_asked_in_chunks() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let (real, _) = a.invite(None, false).await.unwrap();
    a.test_fake_server_links(150);
    assert_eq!(a.test_invite_rows(), 151);
    let list = a.invites().await.unwrap();
    assert_eq!(list.len(), 1, "{list:?}");
    assert_eq!(list[0].token, real.token);
    assert_eq!(a.test_invite_rows(), 1);
    assert!(warnings(&drain(&mut a).await).is_empty());
}

#[tokio::test]
async fn room_link_made_before_the_list_is_found_and_kept() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Crew").await.unwrap();
    let (link, exp) = a.invite(Some(g), false).await.unwrap();
    a.test_forget_invite_row(link.token);
    assert_eq!(a.test_invite_rows(), 0);
    let list = a.invites().await.unwrap();
    assert_eq!(list.len(), 1, "{list:?}");
    assert_eq!(list[0].expires_unix, exp);
    assert_eq!(a.test_invite_rows(), 1);
}

#[tokio::test]
async fn cancel_finds_a_room_link_by_its_voucher() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Crew").await.unwrap();
    let (link, _) = a.invite(Some(g), false).await.unwrap();
    a.test_forget_invite_row(link.token);
    a.cancel_invite(link.token).await.unwrap();
    assert!(a.invites().await.unwrap().is_empty());
    let mut b = TestClient::profile_only("Bo").await;
    assert!(b.join(&link).await.is_err());
}

#[tokio::test]
async fn cancelling_a_gone_link_forgets_it_here() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let (link, _) = a.invite(None, false).await.unwrap();
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    assert_eq!(a.test_invite_rows(), 1);
    let err = a.cancel_invite(link.token).await.unwrap_err();
    assert!(err.to_string().contains("already used"), "{err}");
    assert_eq!(a.test_invite_rows(), 0);
}

/// Entries the server pushed on a connection that then died are kept when
/// the app connects again.
#[tokio::test]
async fn reconnecting_keeps_pushes_from_the_old_connection() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    assert_eq!(a.test_pushed(g).0, 0);
    b.send_text(g, "pushed").await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    a.test_kill_connections();
    a.invites().await.unwrap();
    assert!(a.connected());
    assert_eq!(a.test_pushed(g).0, 1);
}

// ---------- reading a room from a script ----------

/// More unread lines than a reader asks for: the oldest unread come first,
/// and only the lines read count as seen, so an ended room keeps the rest.
#[tokio::test]
async fn reading_part_of_an_ended_room_keeps_the_rest() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    b.mark_seen(g).unwrap();
    for i in 0..60 {
        a.send_text(g, &format!("line {i}")).await.unwrap();
    }
    settle(&mut [&mut a, &mut b]).await;
    let bk = b.my_group_key(g).unwrap();
    a.remove_member(g, &bk).await.unwrap();
    b.sync().await.unwrap();
    assert!(summary(&b, g).ended.is_some());
    assert_eq!(summary(&b, g).unseen, 60);
    let read = b.lines_to_read(g, 50);
    assert_eq!(read.len(), 50);
    assert_eq!(read[0].text, "line 0");
    assert_eq!(read[49].text, "line 49");
    b.mark_seen_upto(g, read[49].seq).unwrap();
    b.purge_read(None);
    assert_eq!(summary(&b, g).unseen, 10);
    let rest = b.lines_to_read(g, 50);
    assert_eq!(rest.first().map(|l| l.text.as_str()), Some("line 10"));
    assert_eq!(rest.last().map(|l| l.text.as_str()), Some("line 59"));
}

/// With everything unread fitting in the window, the newest lines show and
/// the room ends up read.
#[tokio::test]
async fn reading_a_room_with_few_unread_shows_the_newest() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    for i in 0..5 {
        a.send_text(g, &format!("line {i}")).await.unwrap();
    }
    settle(&mut [&mut a, &mut b]).await;
    b.mark_seen(g).unwrap();
    a.send_text(g, "new").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let read = b.lines_to_read(g, 3);
    let got: Vec<_> = read.iter().map(|l| l.text.as_str()).collect();
    assert_eq!(got, ["line 3", "line 4", "new"]);
    b.mark_seen_upto(g, read[2].seq).unwrap();
    assert_eq!(summary(&b, g).unseen, 0);
}
