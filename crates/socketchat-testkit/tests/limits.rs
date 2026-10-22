//! What people see in the app when a server limit turns a request away.

use socketchat_testkit::{drain, settle, TestClient, TestServer};

/// A refused file or message reaches the person as the server's own words,
/// and the room works again once members have fetched.
#[tokio::test]
async fn apps_show_storage_refusals() {
    let s = TestServer::start_with(|c| {
        c.max_room_messages_mb = 1;
        c.max_member_files_mb = 1;
    })
    .await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Photos").await.unwrap();
    let mut b = TestClient::new(&s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.bin");
    std::fs::write(&path, vec![9u8; 600_000]).unwrap();
    a.send_file(g, &path, true).await.unwrap();
    let e = a.send_file(g, &path, true).await.unwrap_err();
    assert!(e.to_string().contains("1 MB"), "{e}");

    // Bo is away, so Ada's messages wait on the server for him.
    let text = "x".repeat(15_000);
    let mut refused = None;
    for _ in 0..100 {
        if let Err(e) = a.send_text(g, &text).await {
            refused = Some(e);
            break;
        }
    }
    let e = refused.expect("the room filled");
    assert!(e.to_string().contains("1 MB"), "{e}");

    // Once Bo fetches, the room takes messages again.
    settle(&mut [&mut a, &mut b]).await;
    a.send_text(g, "back again").await.unwrap();
}

/// A room link that may not make an account still brings the person into
/// the room; their app asks for a server invite only when they try to start
/// a room of their own.
#[tokio::test]
async fn a_link_past_the_account_limit_still_joins() {
    let s = TestServer::start_with(|c| c.max_accounts_from_room_links = 0).await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Book club").await.unwrap();
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    b.send_text(g, "hi").await.unwrap();
    let e = b.create_group("Mine").await.unwrap_err();
    assert!(e.to_string().contains("server invite"), "{e}");
}

/// A joiner turned away because a room has as many joins waiting as it
/// may have hears why from their own app, and the link stays usable.
#[tokio::test]
async fn a_joiner_hears_when_a_room_has_too_many_joins_waiting() {
    let s = TestServer::start_with(|c| c.max_room_welcomes = 1).await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Book club").await.unwrap();
    let first = a.invite(Some(g), false).await.unwrap().0;
    let second = a.invite(Some(g), false).await.unwrap().0;
    let mut b = TestClient::new(&s, "Bo").await;
    b.join(&first).await.unwrap();
    let mut c = TestClient::new(&s, "Cy").await;
    let e = c.join(&second).await.unwrap_err();
    assert!(e.to_string().contains("1 person invited"), "{e}");
}

/// When the server refuses to add someone who used a link, the inviter's
/// app says so once.
#[tokio::test]
async fn the_inviter_hears_when_an_add_is_refused() {
    let s = TestServer::start_with(|c| c.max_room_messages_mb = 1).await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Book club").await.unwrap();
    let mut eve = TestClient::new(&s, "Eve").await;
    eve.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    // Cy joins and then stays away, so the room's messages wait for him.
    let mut cy = TestClient::new(&s, "Cy").await;
    cy.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut eve, &mut cy]).await;
    // Bo redeems while there is room. Eve then fills the room before Ada's
    // app sees his request, so Ada's app cannot add him.
    let mut b = TestClient::new(&s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    // Large texts, then smaller ones, until not even a short one fits.
    for size in [15_000, 1_000, 50] {
        let text = "x".repeat(size);
        let mut full = false;
        for _ in 0..200 {
            if eve.send_text(g, &text).await.is_err() {
                full = true;
                break;
            }
        }
        assert!(full, "the room never filled");
    }
    let mut evs = drain(&mut a).await;
    for _ in 0..3 {
        a.sync().await.unwrap();
        evs.extend(drain(&mut a).await);
    }
    let warnings: Vec<String> = evs
        .into_iter()
        .filter_map(|ev| match ev {
            socketchat_core::client::Event::Warning(w) => Some(w),
            _ => None,
        })
        .filter(|w| w.contains("could not add"))
        .collect();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("1 MB"), "{warnings:?}");
}
