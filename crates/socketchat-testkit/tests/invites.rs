use socketchat_core::client::{Event, JoinStatus, Verification};
use socketchat_core::keys::{fingerprint, KeyPair};
use socketchat_core::net::NetError;
use socketchat_core::CoreError;
use socketchat_testkit::{drain, settle, TestClient, TestServer};

fn joined(events: &[Event]) -> Option<&Verification> {
    events.iter().find_map(|e| match e {
        Event::Joined { verification, .. } => Some(verification),
        _ => None,
    })
}

#[tokio::test]
async fn server_invite_registers_account() {
    let s = TestServer::start().await;
    let mut a = TestClient::profile_only("Ada").await;
    let st = a.join(&s.server_invite()).await.unwrap();
    assert_eq!(st, JoinStatus::Registered);
    a.create_group("Book club").await.unwrap();
}

#[tokio::test]
async fn group_invite_join_verified_by_inviter() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Book club").await.unwrap();
    let link = a.invite(Some(g), false).await.unwrap().0;
    assert!(link.inviter_fpr.is_some() && link.secret.is_some());
    let mut b = TestClient::profile_only("Bo").await;
    assert!(matches!(
        b.join(&link).await.unwrap(),
        JoinStatus::Waiting { .. }
    ));
    settle(&mut [&mut a, &mut b]).await;
    let ev = drain(&mut b).await;
    assert_eq!(joined(&ev), Some(&Verification::Verified), "{ev:?}");
    settle(&mut [&mut a, &mut b]).await;
    let bm = b.members(g);
    assert_eq!(bm.len(), 2);
    let ada = bm
        .iter()
        .find(|m| m.name == "Ada")
        .expect("Bo sees Ada by name");
    assert!(ada.verified);
    assert!(a.members(g).iter().any(|m| m.name == "Bo" && m.verified));
    assert_eq!(b.groups()[0].name, "Book club");
}

#[tokio::test]
async fn join_completed_by_other_admin_when_inviter_offline_is_verified() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut c = TestClient::profile_only("Cy").await;
    c.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut c]).await;
    let ck = c.my_group_key(g).unwrap();
    a.make_admin(g, &ck).await.unwrap();
    settle(&mut [&mut a, &mut c]).await;
    let link = a.invite(Some(g), false).await.unwrap().0;
    settle(&mut [&mut a, &mut c]).await;
    // Ada goes offline; Cy, an admin, completes the join.
    drop(a);
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    settle(&mut [&mut c, &mut b]).await;
    let ev = drain(&mut b).await;
    assert_eq!(joined(&ev), Some(&Verification::Verified), "{ev:?}");
}

#[tokio::test]
async fn invite_single_use() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let link = a.invite(Some(g), false).await.unwrap().0;
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    let mut c = TestClient::profile_only("Cy").await;
    let err = c.join(&link).await.unwrap_err();
    assert!(
        matches!(err, CoreError::Net(NetError::Refused(ref s)) if s.contains("already used")),
        "{err:?}"
    );
}

#[tokio::test]
async fn invite_expiry() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let link = a.invite(Some(g), false).await.unwrap().0;
    s.handle.advance_clock(25 * 3600);
    let mut b = TestClient::profile_only("Bo").await;
    let err = b.join(&link).await.unwrap_err();
    assert!(
        matches!(err, CoreError::Net(NetError::Refused(ref s)) if s.contains("expired")),
        "{err:?}"
    );
}

#[tokio::test]
async fn invite_reports_the_server_expiry() {
    let s = TestServer::start_with(|c| c.invite_ttl_hours = 2).await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    for (group, dm) in [(Some(g), false), (None, true)] {
        let (_, expires_unix) = a.invite(group, dm).await.unwrap();
        assert_eq!(a.hours_until(expires_unix), 2, "{group:?} {dm}");
    }
}

#[tokio::test]
async fn mismatched_inviter_fingerprint_warns() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut link = a.invite(Some(g), false).await.unwrap().0;
    link.inviter_fpr = Some(fingerprint(&KeyPair::generate().public()));
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let ev = drain(&mut b).await;
    assert!(
        matches!(joined(&ev), Some(Verification::Unverified { .. })),
        "{ev:?}"
    );
    assert!(b
        .members(g)
        .iter()
        .all(|m| !m.verified || m.key == b.my_group_key(g).unwrap()));
}

#[tokio::test]
async fn server_cannot_forge_join() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let link = a.invite(Some(g), false).await.unwrap().0;
    // Ada is offline while Bo redeems, so the only copy of the request she
    // will see is the one the server hands her later.
    let mut a = a.reopen().await;
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    // A hostile server swaps in a KeyPackage of its own choosing.
    let forged = socketchat_testkit::forged_key_package_blob();
    let db = rusqlite_conn(&s);
    db.execute("UPDATE joins SET key_package = ?1", [forged])
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert!(joined(&drain(&mut b).await).is_none());
    assert_eq!(a.members(g).len(), 1);
    let warned = drain(&mut a).await;
    assert!(
        warned.iter().any(|e| matches!(e, Event::Warning(_))),
        "{warned:?}"
    );
}

fn rusqlite_conn(s: &TestServer) -> socketchat_testkit::Db {
    socketchat_testkit::open_server_db(s)
}

#[tokio::test]
async fn members_cannot_invite_when_disabled() {
    let s = TestServer::start_with(|c| c.members_can_invite = false).await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut b = TestClient::new(&s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(b.members(g).len(), 2);
    let err = b.invite(Some(g), false).await.unwrap_err();
    assert!(
        matches!(err, CoreError::Net(NetError::Refused(_))),
        "{err:?}"
    );
}

#[tokio::test]
async fn two_admins_race_on_one_join() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut c = TestClient::profile_only("Cy").await;
    c.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut c]).await;
    let ck = c.my_group_key(g).unwrap();
    a.make_admin(g, &ck).await.unwrap();
    let link = a.invite(Some(g), false).await.unwrap().0;
    settle(&mut [&mut a, &mut c]).await;
    drain(&mut a).await;
    drain(&mut c).await;
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    let (ra, rc) = tokio::join!(a.sync(), c.sync());
    ra.unwrap();
    rc.unwrap();
    settle(&mut [&mut a, &mut c, &mut b]).await;
    assert_eq!(a.members(g).len(), 3);
    assert_eq!(c.members(g).len(), 3);
    assert_eq!(b.members(g).len(), 3);
    for x in [&mut a, &mut c] {
        let ev = drain(x).await;
        assert!(!ev.iter().any(|e| matches!(e, Event::Warning(_))), "{ev:?}");
    }
}

fn bo_verified_in(a: &TestClient, g: socketchat_proto::msg::GroupId) -> bool {
    a.members(g).iter().any(|m| m.name == "Bo" && m.verified)
}

/// The server stops listing a link once it is used, but the inviter still
/// needs what it kept for the link to let the joiner in.
#[tokio::test]
async fn listing_links_before_the_join_request_is_handled_keeps_the_join() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Crew").await.unwrap();
    let (link, _) = a.invite(Some(g), false).await.unwrap();
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    assert!(a.invites().await.unwrap().is_empty());
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(b.groups().len(), 1, "Bo never got in");
    assert!(bo_verified_in(&a, g), "{:?}", a.members(g));
}

/// The joiner's proof that they hold the link comes after the add; listing
/// links in between still lets the inviter mark them verified.
#[tokio::test]
async fn listing_links_before_the_joiners_proof_keeps_the_verified_mark() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Crew").await.unwrap();
    let (link, _) = a.invite(Some(g), false).await.unwrap();
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    a.sync().await.unwrap();
    assert_eq!(a.members(g).len(), 2, "Ada let Bo in");
    assert!(!bo_verified_in(&a, g));
    assert!(a.invites().await.unwrap().is_empty());
    settle(&mut [&mut a, &mut b]).await;
    assert!(bo_verified_in(&a, g), "{:?}", a.members(g));
}

/// Cancelling a link that was just used says so, and the join still
/// completes.
#[tokio::test]
async fn cancelling_a_used_link_keeps_the_join() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Crew").await.unwrap();
    let (link, _) = a.invite(Some(g), false).await.unwrap();
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    let err = a.cancel_invite(link.token).await.unwrap_err();
    assert!(err.to_string().contains("already used"), "{err}");
    assert!(a.invites().await.unwrap().is_empty());
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(b.groups().len(), 1, "Bo never got in");
    assert!(bo_verified_in(&a, g), "{:?}", a.members(g));
}
