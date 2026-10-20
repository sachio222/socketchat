use socketchat_core::client::{Event, Verification};
use socketchat_core::keys::Key;
use socketchat_proto::msg::GroupId;
use socketchat_testkit::{drain, settle, CutProxy, TestClient, TestServer};

/// Ada makes a group and brings in each of `others`.
async fn group(s: &TestServer, names: &[&str]) -> (GroupId, Vec<TestClient>) {
    let mut a = TestClient::new(s, names[0]).await;
    let g = a.create_group("Crew").await.unwrap();
    let mut all = vec![a];
    for n in &names[1..] {
        let link = all[0].invite(Some(g), false).await.unwrap();
        let mut c = TestClient::new(s, n).await;
        c.join(&link).await.unwrap();
        all.push(c);
        let mut refs: Vec<&mut TestClient> = all.iter_mut().collect();
        settle(&mut refs).await;
    }
    for c in all.iter_mut() {
        drain(c).await;
    }
    (g, all)
}

async fn settle_all(all: &mut [TestClient]) {
    let mut refs: Vec<&mut TestClient> = all.iter_mut().collect();
    settle(&mut refs).await;
}

fn texts(c: &TestClient, g: GroupId) -> Vec<String> {
    c.messages(g, 100)
        .into_iter()
        .filter(|l| !l.notice)
        .map(|l| format!("{}: {}", l.sender, l.text))
        .collect()
}

fn key_of(c: &TestClient, g: GroupId) -> Key {
    c.my_group_key(g).unwrap()
}

#[tokio::test]
async fn direct_message() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let link = a.invite(None, true).await.unwrap();
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let dm = b.groups()[0].id;
    assert!(b.groups()[0].is_dm);
    a.send_text(dm, "hi Bo").await.unwrap();
    b.send_text(dm, "hi Ada").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(texts(&b, dm), vec!["Ada: hi Bo", "Bo: hi Ada"]);
    assert_eq!(texts(&a, dm), vec!["Ada: hi Bo", "Bo: hi Ada"]);
}

#[tokio::test]
async fn group_of_three() {
    let s = TestServer::start().await;
    let (g, mut all) = group(&s, &["Ada", "Bo", "Cy"]).await;
    for (i, c) in all.iter_mut().enumerate() {
        c.send_text(g, &format!("hello from {i}")).await.unwrap();
        settle_all(std::slice::from_mut(c)).await;
    }
    settle_all(&mut all).await;
    for c in &all {
        let t = texts(c, g);
        assert_eq!(
            t,
            vec!["Ada: hello from 0", "Bo: hello from 1", "Cy: hello from 2"],
            "{}",
            c.display_name()
        );
    }
}

#[tokio::test]
async fn remove_member_cannot_read_later() {
    let s = TestServer::start().await;
    let (g, mut all) = group(&s, &["Ada", "Bo", "Cy"]).await;
    let ck = key_of(&all[2], g);
    all[0].remove_member(g, &ck).await.unwrap();
    settle_all(&mut all).await;
    all[0].send_text(g, "the secret plan").await.unwrap();
    settle_all(&mut all).await;
    assert!(texts(&all[1], g)
        .iter()
        .any(|t| t.contains("the secret plan")));
    assert!(!texts(&all[2], g)
        .iter()
        .any(|t| t.contains("the secret plan")));
    assert!(drain(&mut all[2])
        .await
        .iter()
        .any(|e| matches!(e, Event::Left { .. })));
    assert_eq!(all[0].members(g).len(), 2);
}

#[tokio::test]
async fn offline_member_gets_messages_on_reconnect() {
    let s = TestServer::start().await;
    let (g, mut all) = group(&s, &["Ada", "Bo"]).await;
    let b = all.pop().unwrap();
    let b_dir_client = b; // Bo goes offline by closing his client.
    let b_closed = b_dir_client.reopen_later();
    for i in 0..3 {
        all[0].send_text(g, &format!("m{i}")).await.unwrap();
    }
    let mut b = b_closed.open().await;
    b.sync().await.unwrap();
    assert_eq!(texts(&b, g), vec!["Ada: m0", "Ada: m1", "Ada: m2"]);
}

#[tokio::test]
async fn concurrent_commits_one_wins_other_retries() {
    let s = TestServer::start().await;
    let (g, mut all) = group(&s, &["Ada", "Bo"]).await;
    let (x, y) = all.split_at_mut(1);
    let (r1, r2) = tokio::join!(x[0].update_keys(g), y[0].update_keys(g));
    r1.unwrap();
    r2.unwrap();
    settle_all(&mut all).await;
    assert_eq!(all[0].epoch(g), all[1].epoch(g));
    assert_eq!(all[0].epoch(g), Some(3), "start at 1, two updates");
    all[0].send_text(g, "still here").await.unwrap();
    all[1].send_text(g, "me too").await.unwrap();
    settle_all(&mut all).await;
    assert_eq!(texts(&all[0], g), vec!["Ada: still here", "Bo: me too"]);
}

#[tokio::test]
async fn leave_then_last_admin_promotes_longest_standing() {
    let s = TestServer::start().await;
    let (g, mut all) = group(&s, &["Ada", "Bo", "Cy"]).await;
    all[0].leave(g).await.unwrap();
    settle_all(&mut all).await;
    assert!(drain(&mut all[0])
        .await
        .iter()
        .any(|e| matches!(e, Event::Left { .. })));
    let bk = key_of(&all[1], g);
    for c in &all[1..] {
        let ms = c.members(g);
        assert_eq!(ms.len(), 2);
        assert!(
            ms.iter().find(|m| m.key == bk).unwrap().admin,
            "Bo joined first and is now the admin"
        );
    }
}

#[tokio::test]
async fn name_change_posts_notice_and_keeps_trust() {
    let s = TestServer::start().await;
    let (g, mut all) = group(&s, &["Ada", "Bo"]).await;
    all[1].set_display_name("Bobby").await.unwrap();
    settle_all(&mut all).await;
    let ev = drain(&mut all[0]).await;
    assert!(
        ev.iter().any(
            |e| matches!(e, Event::NameChanged { old, new, .. } if old == "Bo" && new == "Bobby")
        ),
        "{ev:?}"
    );
    assert!(all[0]
        .messages(g, 50)
        .iter()
        .any(|l| l.notice && l.text.contains("Bo is now called Bobby")));
    assert!(all[0]
        .members(g)
        .iter()
        .any(|m| m.name == "Bobby" && m.verified));
}

#[tokio::test]
async fn new_identity_same_name_not_verified() {
    let s = TestServer::start().await;
    let (g, mut all) = group(&s, &["Ada", "Bo"]).await;
    // Bo invites a stranger who also calls themselves Bo.
    let link = all[1].invite(Some(g), false).await.unwrap();
    let mut impostor = TestClient::new(&s, "Bo").await;
    impostor.join(&link).await.unwrap();
    all.push(impostor);
    settle_all(&mut all).await;
    let bos: Vec<_> = all[0]
        .members(g)
        .into_iter()
        .filter(|m| m.name == "Bo")
        .collect();
    assert_eq!(bos.len(), 2);
    assert_eq!(bos.iter().filter(|m| m.verified).count(), 1);
}

#[tokio::test]
async fn rename_local_only_changes_my_screen() {
    let s = TestServer::start().await;
    let (g, mut all) = group(&s, &["Ada", "Bo"]).await;
    let bk = key_of(&all[1], g);
    all[0].rename_local(g, &bk, "Bo from work").unwrap();
    assert!(all[0].members(g).iter().any(|m| m.name == "Bo from work"));
    settle_all(&mut all).await;
    assert_eq!(all[1].display_name(), "Bo");
}

#[tokio::test]
async fn dm_from_shared_group() {
    let s = TestServer::start().await;
    let (g, mut all) = group(&s, &["Ada", "Bo", "Cy"]).await;
    let bk = key_of(&all[1], g);
    let dm = all[0].dm(g, &bk).await.unwrap();
    settle_all(&mut all).await;
    let ev = drain(&mut all[1]).await;
    assert!(ev.iter().any(|e| matches!(e, Event::Joined { group, verification: Verification::Verified } if *group == dm)), "{ev:?}");
    all[0].send_text(dm, "just us").await.unwrap();
    settle_all(&mut all).await;
    assert_eq!(texts(&all[1], dm), vec!["Ada: just us"]);
    assert!(
        all[2].groups().iter().all(|x| x.id != dm),
        "Cy is not in the DM"
    );
    assert_eq!(all[1].members(dm).len(), 2);
    assert!(all[1].members(dm).iter().all(|m| m.verified));
}

#[tokio::test]
async fn weekly_refresh_sends_self_update() {
    let s = TestServer::start().await;
    let (g, mut all) = group(&s, &["Ada", "Bo"]).await;
    let before = all[0].epoch(g).unwrap();
    all[0].advance_clock(8 * 24 * 3600);
    settle_all(&mut all).await;
    assert!(all[0].epoch(g).unwrap() > before);
    assert_eq!(all[0].epoch(g), all[1].epoch(g));
}

#[tokio::test]
async fn control_and_bidi_chars_stripped_and_capped() {
    let s = TestServer::start().await;
    let (g, mut all) = group(&s, &["Ada", "Bo"]).await;
    all[1].set_display_name("Bo\u{202E}nimda").await.unwrap();
    all[1].send_text(g, "\x1b[2Jcleared?\x07").await.unwrap();
    all[1].send_text(g, &"x".repeat(40_000)).await.unwrap();
    settle_all(&mut all).await;
    let lines = all[0].messages(g, 10);
    assert!(lines.iter().any(|l| l.text == "[2Jcleared?"));
    assert!(lines.iter().all(|l| l.text.len() <= 16 * 1024));
    assert!(all[0].members(g).iter().any(|m| m.name == "Bonimda"));
}

#[tokio::test]
async fn commit_in_flight_when_connection_drops_applies_once() {
    let s = TestServer::start().await;
    let proxy = CutProxy::start(s.addr()).await;
    let mut link = s.server_invite();
    link.port = proxy.port;
    let mut a = TestClient::profile_only("Ada").await;
    a.join(&link).await.unwrap();
    let g = a.create_group("G").await.unwrap();
    let mut inv = a.invite(Some(g), false).await.unwrap();
    inv.port = s.addr().port();
    let mut b = TestClient::new(&s, "Bo").await;
    b.join(&inv).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let before = a.epoch(g).unwrap();
    proxy.arm();
    assert!(a.update_keys(g).await.is_err(), "the reply never arrives");
    a.resolve_pending(g).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(a.epoch(g), Some(before + 1));
    assert_eq!(b.epoch(g), Some(before + 1));
    a.send_text(g, "after the drop").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(texts(&b, g), vec!["Ada: after the drop"]);
}
