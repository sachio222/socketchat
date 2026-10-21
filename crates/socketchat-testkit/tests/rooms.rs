use socketchat_core::appmsg::AppMsg;
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
