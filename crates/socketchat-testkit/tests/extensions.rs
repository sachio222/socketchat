use socketchat_core::appmsg::{AppMsg, Extension};
use socketchat_core::client::{Event, APP_VERSION};
use socketchat_proto::msg::GroupId;
use socketchat_testkit::{drain, settle, TestClient, TestServer};

fn note(summary: Option<&str>) -> Extension {
    Extension {
        namespace: "demo".into(),
        kind: "note".into(),
        version: 1,
        body: vec![1, 2, 3],
        summary: summary.map(String::from),
    }
}

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

fn extension_events(events: Vec<Event>) -> Vec<Event> {
    events
        .into_iter()
        .filter(|e| matches!(e, Event::Extension { .. }))
        .collect()
}

#[tokio::test]
async fn extension_reaches_members_and_is_stored() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    drain(&mut b).await;
    let sent = note(Some("Ada shared a note"));
    let seq = a.send_extension(g, sent.clone()).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let got = extension_events(drain(&mut b).await);
    let ada_key = a.my_group_key(g).unwrap();
    assert_eq!(
        got,
        vec![Event::Extension {
            group: g,
            seq,
            sender_key: ada_key,
            ext: sent.clone(),
        }]
    );
    let rows = b.extensions(g, 0, 10);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].seq, seq);
    assert_eq!(rows[0].sender_key, ada_key);
    assert_eq!(rows[0].ext, sent);
    assert_eq!(a.extensions(g, 0, 10)[0].seq, seq);
    for c in [&a, &b] {
        let line = c
            .messages(g, 50)
            .into_iter()
            .find(|l| l.text == "Ada shared a note")
            .expect("summary line");
        assert_eq!(line.sender, "Ada");
        assert_eq!(line.sender_key, Some(ada_key));
        assert!(!line.notice);
        assert_eq!(line.seq, seq);
    }
}

#[tokio::test]
async fn extension_without_summary_shows_nothing() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    let before = b.messages(g, 50).len();
    drain(&mut b).await;
    a.send_extension(g, note(None)).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(extension_events(drain(&mut b).await).len(), 1);
    assert_eq!(b.extensions(g, 0, 10).len(), 1);
    assert_eq!(b.messages(g, 50).len(), before);
    assert_eq!(a.messages(g, 50).len(), before);
}

#[tokio::test]
async fn summary_is_cleaned() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    let dirty = format!("one\ntwo\u{202e}{}", "x".repeat(300));
    a.send_extension(g, note(Some(&dirty))).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let line = b
        .messages(g, 50)
        .into_iter()
        .find(|l| l.text.starts_with("one two"))
        .expect("cleaned line");
    assert_eq!(line.text.chars().count(), 200);
    assert!(!line.text.contains('\n') && !line.text.contains('\u{202e}'));
    let stored = b.extensions(g, 0, 10).remove(0).ext.summary.unwrap();
    assert_eq!(stored, line.text);
}

#[tokio::test]
async fn bad_namespace_refused_and_dropped() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    drain(&mut b).await;
    let mut bad = note(Some("hi"));
    bad.namespace = "Demo".into();
    let err = a.send_extension(g, bad.clone()).await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "an extension's namespace must be 1 to 32 characters of a-z, 0-9 and -"
    );
    settle(&mut [&mut a, &mut b]).await;
    assert!(extension_events(drain(&mut b).await).is_empty());
    // Posted raw by a hostile member: dropped on arrival.
    a.test_send_app(g, &AppMsg::Extension(bad)).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert!(extension_events(drain(&mut b).await).is_empty());
    assert!(b.extensions(g, 0, 10).is_empty());
    assert!(!b.messages(g, 50).iter().any(|l| l.text == "hi"));
}

#[tokio::test]
async fn extension_too_large_is_refused() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    drain(&mut b).await;
    let mut big = note(None);
    big.body = vec![7; 1_048_000];
    let err = a.send_extension(g, big).await.unwrap_err();
    assert_eq!(err.to_string(), "that message is too large to send");
    settle(&mut [&mut a, &mut b]).await;
    assert!(extension_events(drain(&mut b).await).is_empty());
    assert!(a.extensions(g, 0, 10).is_empty());
}

#[tokio::test]
async fn extensions_page_after_seq() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    let mut seqs = Vec::new();
    for n in 0..3u8 {
        let mut e = note(None);
        e.body = vec![n];
        seqs.push(a.send_extension(g, e).await.unwrap());
    }
    settle(&mut [&mut a, &mut b]).await;
    for c in [&a, &b] {
        let page = c.extensions(g, seqs[0], 2);
        assert_eq!(page.iter().map(|r| r.seq).collect::<Vec<_>>(), seqs[1..]);
        assert_eq!(page[0].ext.body, vec![1]);
        assert_eq!(c.extensions(g, 0, 2).len(), 2);
    }
}

#[tokio::test]
async fn members_learn_app_versions() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    for c in [&a, &b] {
        for m in c.members(g) {
            assert_eq!(m.app_version.as_deref(), Some(APP_VERSION), "{}", m.name);
        }
    }
    let mut cy = TestClient::new(&s, "Cy").await;
    cy.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b, &mut cy]).await;
    let seen = cy.members(g);
    assert_eq!(seen.len(), 3);
    for m in seen {
        assert_eq!(m.app_version.as_deref(), Some(APP_VERSION), "{}", m.name);
    }
}

#[tokio::test]
async fn version_change_is_announced_again() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    b.test_announce_version("0.5.1");
    settle(&mut [&mut b, &mut a]).await;
    let bo = a.members(g).into_iter().find(|m| m.name == "Bo").unwrap();
    assert_eq!(bo.app_version.as_deref(), Some("0.5.1"));
    let me = b.members(g).into_iter().find(|m| m.me).unwrap();
    assert_eq!(me.app_version.as_deref(), Some("0.5.1"));
}

#[tokio::test]
async fn silent_app_stays_unknown() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    a.test_announce_version("");
    let g = a.create_group("Room").await.unwrap();
    let mut b = TestClient::new(&s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let ada = b.members(g).into_iter().find(|m| m.name == "Ada").unwrap();
    assert_eq!(ada.app_version, None);
    let bo = a.members(g).into_iter().find(|m| m.name == "Bo").unwrap();
    assert_eq!(bo.app_version.as_deref(), Some(APP_VERSION));
}
