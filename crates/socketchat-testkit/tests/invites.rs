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
/// An admin lets the joiner in while the inviter is offline. The join waits
/// for the inviter, and is verified on both sides once she is back.
async fn join_completed_by_other_admin_waits_for_inviter() {
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
    let away = a.reopen_later();
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    settle(&mut [&mut c, &mut b]).await;
    let ev = drain(&mut b).await;
    assert_eq!(
        joined(&ev),
        Some(&Verification::Waiting {
            inviter: "the person who invited you".into()
        }),
        "{ev:?}"
    );
    let ak = c.members(g).iter().find(|m| m.name == "Ada").unwrap().key;
    assert!(!b.members(g).iter().any(|m| m.key == ak && m.verified));

    // Ada comes back, sees Bo added, shares her name, and Bo's proof counts.
    let mut b = b.reopen().await;
    let mut a = away.open().await;
    settle(&mut [&mut a, &mut c, &mut b]).await;
    let ev = drain(&mut b).await;
    assert!(
        ev.iter().any(|e| matches!(e,
            Event::InviteConfirmed { group, inviter } if *group == g && inviter == "Ada")),
        "{ev:?}"
    );
    assert!(b.members(g).iter().any(|m| m.key == ak && m.verified));
    let bk = b.my_group_key(g).unwrap();
    assert!(a.members(g).iter().any(|m| m.key == bk && m.verified));
}

/// A join that waits for an inviter who leaves the room before confirming
/// it ends as unverified, with a warning, instead of waiting forever.
#[tokio::test]
async fn join_waiting_for_inviter_who_left_is_unverified() {
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
    let ak = a.my_group_key(g).unwrap();
    let link = a.invite(Some(g), false).await.unwrap().0;
    settle(&mut [&mut a, &mut c]).await;
    drop(a);
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    settle(&mut [&mut c, &mut b]).await;
    let ev = drain(&mut b).await;
    assert!(
        matches!(joined(&ev), Some(Verification::Waiting { .. })),
        "{ev:?}"
    );
    c.remove_member(g, &ak).await.unwrap();
    settle(&mut [&mut c, &mut b]).await;
    let ev = drain(&mut b).await;
    assert!(
        ev.iter().any(|e| matches!(e,
            Event::Warning(w) if w.contains("could not be confirmed"))),
        "{ev:?}"
    );
    assert!(b.members(g).iter().all(|m| m.me || !m.verified));
}

/// The inviter's app still owes its profile after it closes between the
/// add and posting the profile. On its next start it posts it, and the
/// join ends verified with nothing else done.
#[tokio::test]
async fn owed_profile_survives_inviter_restart() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let link = a.invite(Some(g), false).await.unwrap().0;
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    // Ada's add goes through, then her app closes before her profile does.
    a.test_fail_next_after_add(g);
    a.sync().await.unwrap();
    let away = a.reopen_later();
    b.sync().await.unwrap();
    b.sync().await.unwrap();
    let ev = drain(&mut b).await;
    assert!(
        matches!(joined(&ev), Some(Verification::Waiting { .. })),
        "{ev:?}"
    );
    let mut a = away.open().await;
    settle(&mut [&mut a, &mut b]).await;
    let ev = drain(&mut b).await;
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::InviteConfirmed { inviter, .. } if inviter == "Ada")),
        "{ev:?}"
    );
    assert!(b.members(g).iter().any(|m| m.name == "Ada" && m.verified));
}

/// The joiner's app shows the waiting state, then the confirmation, when
/// the inviter's name arrives after the joiner first reads the room.
#[tokio::test]
async fn late_confirmation_from_inviter_marks_join_verified() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let link = a.invite(Some(g), false).await.unwrap().0;
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    // Ada's add goes through, but sharing her name fails this once.
    a.test_fail_next_after_add(g);
    a.sync().await.unwrap();
    b.sync().await.unwrap();
    let ev = drain(&mut b).await;
    assert!(
        matches!(joined(&ev), Some(Verification::Waiting { .. })),
        "{ev:?}"
    );
    settle(&mut [&mut a, &mut b]).await;
    let ev = drain(&mut b).await;
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::InviteConfirmed { inviter, .. } if inviter == "Ada")),
        "{ev:?}"
    );
    assert!(b.members(g).iter().any(|m| m.name == "Ada" && m.verified));
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
async fn members_cannot_invite_in_an_admins_only_room() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut b = TestClient::new(&s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(b.members(g).len(), 2);
    a.set_who_can_invite(g, socketchat_core::settings::WhoCanInvite::Admins)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let err = b.invite(Some(g), false).await.unwrap_err();
    assert!(matches!(err, CoreError::Other(_)), "{err:?}");
}

/// The server setting for accounts no longer stops members inviting into
/// a room: a member's link still brings someone in, who gets no account.
#[tokio::test]
async fn members_still_invite_into_rooms_when_they_make_no_accounts() {
    let s = TestServer::start_with(|c| c.members_make_accounts = false).await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut b = TestClient::new(&s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let mut c = TestClient::profile_only("Cy").await;
    c.join(&b.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert_eq!(a.members(g).len(), 3);
    let err = b.invite(None, false).await.unwrap_err();
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

/// Ada's room with Cy in it, each app knowing the other's name.
async fn room_with_cy(s: &TestServer) -> (TestClient, TestClient, socketchat_proto::msg::GroupId) {
    let mut a = TestClient::new(s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut c = TestClient::profile_only("Cy").await;
    c.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut c]).await;
    (a, c, g)
}

/// Once Cy is removed, the links Cy made let nobody in.
#[tokio::test]
async fn removed_members_link_lets_nobody_in() {
    let s = TestServer::start().await;
    let (mut a, mut c, g) = room_with_cy(&s).await;
    let link = c.invite(Some(g), false).await.unwrap().0;
    settle(&mut [&mut a, &mut c]).await;
    let ck = c.my_group_key(g).unwrap();
    a.remove_member(g, &ck).await.unwrap();
    settle(&mut [&mut a, &mut c]).await;
    let mut b = TestClient::profile_only("Bo").await;
    let r = b.join(&link).await;
    assert!(
        matches!(r, Err(CoreError::Net(NetError::Refused(_)))),
        "{r:?}"
    );
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(a.members(g).len(), 1, "{:?}", a.members(g));
    assert!(b.groups().is_empty());
}

/// Bo asks to join through Cy's link, then Cy is removed before anyone
/// lets Bo in. The admin's app does not complete the join.
#[tokio::test]
async fn join_through_link_of_member_removed_meanwhile_waits() {
    let s = TestServer::start().await;
    let (mut a, mut c, g) = room_with_cy(&s).await;
    let link = c.invite(Some(g), false).await.unwrap().0;
    settle(&mut [&mut a, &mut c]).await;
    let mut b = TestClient::profile_only("Bo").await;
    assert!(matches!(
        b.join(&link).await.unwrap(),
        JoinStatus::Waiting { .. }
    ));
    let ck = c.my_group_key(g).unwrap();
    a.remove_member(g, &ck).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert_eq!(a.members(g).len(), 1, "{:?}", a.members(g));
    assert!(b.groups().is_empty());
}

/// An app never adds back the key of an admin who was removed, even when
/// the server lets that key register again.
#[tokio::test]
async fn removed_admins_key_is_not_added_back() {
    let s = TestServer::start().await;
    let (mut a, mut c, g) = room_with_cy(&s).await;
    let ck = c.my_group_key(g).unwrap();
    a.make_admin(g, &ck).await.unwrap();
    settle(&mut [&mut a, &mut c]).await;
    let old_key = c.test_group_key_pair(g).unwrap();
    a.remove_member(g, &ck).await.unwrap();
    settle(&mut [&mut a, &mut c]).await;
    // The server's record of who left is gone.
    let _ = rusqlite_conn(&s).execute("DELETE FROM retired_keys", []);
    let link = a.invite(Some(g), false).await.unwrap().0;
    let mut back = TestClient::profile_only("Cy").await;
    back.test_join_with_mailbox_key(&link, old_key)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut back]).await;
    assert!(
        a.members(g).iter().all(|m| m.key != ck),
        "{:?}",
        a.members(g)
    );
    assert!(back.groups().is_empty());
}

const LINK_MAKER_LEFT: &str = "This invite link stopped working, because the person who made it left the room or the room now lets only admins invite. Ask someone in the room for a new link.";

/// Bo asked to join through Cy's link, then Cy was removed. Bo's app says
/// why the link stopped working and stops waiting.
#[tokio::test]
async fn joiner_hears_when_the_links_maker_left() {
    let s = TestServer::start().await;
    let (mut a, mut c, g) = room_with_cy(&s).await;
    let link = c.invite(Some(g), false).await.unwrap().0;
    settle(&mut [&mut a, &mut c]).await;
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    assert_eq!(b.test_pending_joins(), 1);
    let ck = c.my_group_key(g).unwrap();
    a.remove_member(g, &ck).await.unwrap();
    b.sync().await.unwrap();
    let ev = drain(&mut b).await;
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Warning(w) if w == LINK_MAKER_LEFT)),
        "{ev:?}"
    );
    assert_eq!(b.test_pending_joins(), 0);
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert_eq!(a.members(g).len(), 1, "{:?}", a.members(g));
    assert!(b.groups().is_empty());
    assert!(!drain(&mut b)
        .await
        .iter()
        .any(|e| matches!(e, Event::Warning(_))));
}

/// A rename an admin sent before being removed, replayed later by the
/// server, changes nothing.
#[tokio::test]
async fn replayed_rename_from_a_removed_admin_is_ignored() {
    let s = TestServer::start().await;
    let (mut a, mut c, g) = room_with_cy(&s).await;
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    let ck = c.my_group_key(g).unwrap();
    a.make_admin(g, &ck).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    c.rename_room(g, "Cy's room").await.unwrap();
    let old: Vec<u8> = rusqlite_conn(&s)
        .query_row(
            "SELECT mls FROM log WHERE group_id = ?1 ORDER BY seq DESC LIMIT 1",
            [g.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    a.remove_member(g, &ck).await.unwrap();
    a.rename_room(g, "Ada's room").await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    socketchat_testkit::append_to_log(&s, g, &old);
    settle(&mut [&mut a, &mut b]).await;
    let name = |x: &TestClient| x.groups().iter().find(|r| r.id == g).unwrap().name.clone();
    assert_eq!(name(&b), "Ada's room");
    assert_eq!(name(&a), "Ada's room");
}

/// A joiner whose invite could not be confirmed keeps its name and
/// identity key out of the room, and makes no links there, until it marks
/// someone in the room verified.
#[tokio::test]
async fn unconfirmed_joiner_shares_name_once_they_verify_someone() {
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
    let ak = a.my_group_key(g).unwrap();
    let link = a.invite(Some(g), false).await.unwrap().0;
    settle(&mut [&mut a, &mut c]).await;
    drop(a);
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    settle(&mut [&mut c, &mut b]).await;
    c.remove_member(g, &ak).await.unwrap();
    settle(&mut [&mut c, &mut b]).await;
    let bk = b.my_group_key(g).unwrap();
    let named = |c: &TestClient| c.members(g).iter().any(|m| m.key == bk && m.name == "Bo");
    assert!(!named(&c), "{:?}", c.members(g));
    assert!(b.invite(Some(g), false).await.is_err());
    assert!(b.mark_verified(g, &ck).unwrap());
    settle(&mut [&mut c, &mut b]).await;
    assert!(named(&c), "{:?}", c.members(g));
    assert!(b.invite(Some(g), false).await.is_ok());
}

/// The inviter's app lets someone in a day after they asked, when the
/// invite's own 24 hours are over. The join waits for the inviter, and her
/// profile confirms it, so the new member is verified and named on both
/// sides.
#[tokio::test]
async fn late_join_after_the_invite_expired_is_confirmed_by_the_inviter() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let link = a.invite(Some(g), false).await.unwrap().0;
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    b.advance_clock(25 * 3600);
    settle(&mut [&mut a, &mut b]).await;
    let ev = drain(&mut b).await;
    assert_eq!(joined(&ev), Some(&Verification::Verified), "{ev:?}");
    settle(&mut [&mut a, &mut b]).await;
    let bk = b.my_group_key(g).unwrap();
    assert!(
        a.members(g)
            .iter()
            .any(|m| m.key == bk && m.name == "Bo" && m.verified),
        "{:?}",
        a.members(g)
    );
}

/// A joiner whose own invite is not confirmed is told what to do before
/// making a link there: wait for the inviter while one is expected, and
/// compare safety numbers once the inviter can no longer confirm it.
#[tokio::test]
async fn held_joiner_is_told_what_to_wait_for() {
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
    let ak = a.my_group_key(g).unwrap();
    let link = a.invite(Some(g), false).await.unwrap().0;
    settle(&mut [&mut a, &mut c]).await;
    drop(a);
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    settle(&mut [&mut c, &mut b]).await;
    let waiting = b.invite(Some(g), false).await.unwrap_err().to_string();
    assert!(
        waiting.contains("Wait for the person who invited you to confirm it."),
        "{waiting}"
    );
    c.remove_member(g, &ak).await.unwrap();
    settle(&mut [&mut c, &mut b]).await;
    let unconfirmed = b.invite(Some(g), false).await.unwrap_err().to_string();
    assert!(
        unconfirmed.contains("Compare safety numbers with someone there"),
        "{unconfirmed}"
    );
}

/// A voucher signed by someone other than the person in the link stays a
/// failed check when it has also expired: only an expired voucher that is
/// otherwise genuine waits for the inviter.
#[tokio::test]
async fn forged_voucher_that_also_expired_stays_unverified() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let (link, exp) = a.invite(Some(g), false).await.unwrap();
    let secret = link.secret.unwrap();
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    a.sync().await.unwrap();
    let forged = socketchat_core::keys::Voucher::new(
        &KeyPair::generate(),
        link.token,
        &secret,
        g,
        a.my_group_key(g).unwrap(),
        exp,
    );
    let sealed = socketchat_core::keys::seal_voucher(
        &socketchat_core::keys::voucher_seal_key(&secret),
        &forged,
    );
    let changed = socketchat_testkit::open_server_db(&s)
        .execute("UPDATE welcomes SET voucher = ?1", [sealed])
        .unwrap();
    assert_eq!(changed, 1);
    b.advance_clock(25 * 3600);
    settle(&mut [&mut a, &mut b]).await;
    let ev = drain(&mut b).await;
    assert!(
        matches!(joined(&ev), Some(Verification::Unverified { reason })
            if reason.contains("someone other than the person in the link")),
        "{ev:?}"
    );
}

/// A link handed to the app in code, past the text parser, with a host
/// that is not a name or an address: the app refuses it before storing a
/// server, so no later warning can carry that host to a terminal.
#[tokio::test]
async fn join_refuses_a_link_whose_host_is_not_a_name_or_address() {
    let s = TestServer::start().await;
    let mut a = TestClient::profile_only("Ada").await;
    let mut link = s.server_invite();
    link.host = "evil\u{1b}]0;owned\u{7}\u{1b}[2J.example.com".into();
    let r = a.join(&link).await;
    assert!(r.is_err(), "{r:?}");
    a.take_events();
    a.invites().await.unwrap();
    let said: Vec<String> = a
        .take_events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Warning(w) => Some(w),
            _ => None,
        })
        .collect();
    assert!(said.is_empty(), "no server was stored: {said:?}");
}

/// A long host name in a warning keeps every character: names are cut at
/// 64 characters, hosts are not.
#[tokio::test]
async fn warnings_show_a_long_host_in_full() {
    let s = TestServer::start().await;
    let mut a = TestClient::profile_only("Ada").await;
    let mut link = s.server_invite();
    link.host = format!("{}.{}.invalid", "a".repeat(60), "b".repeat(30));
    assert!(a.join(&link).await.is_err());
    a.take_events();
    a.invites().await.unwrap();
    let said: Vec<String> = a
        .take_events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Warning(w) => Some(w),
            _ => None,
        })
        .collect();
    assert!(said.iter().any(|w| w.contains(&link.host)), "{said:?}");
}

#[tokio::test]
async fn a_web_link_registers_like_the_raw_link() {
    let s = TestServer::start().await;
    let raw = s.server_invite();
    let web = socketchat_proto::to_web_link(&raw.to_string()).unwrap();
    assert!(web.starts_with("https://socketchat.org/join#socketchat://"));
    let parsed: socketchat_proto::InviteLink = web.parse().unwrap();
    assert_eq!(parsed, raw);
    let mut a = TestClient::profile_only("Ada").await;
    assert_eq!(a.join(&parsed).await.unwrap(), JoinStatus::Registered);
    a.create_group("Book club").await.unwrap();
}

#[tokio::test]
async fn a_web_group_link_lets_the_joiner_in_like_the_raw_link() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Book club").await.unwrap();
    let raw = a.invite(Some(g), false).await.unwrap().0;
    let web = socketchat_proto::to_web_link(&raw.to_string()).unwrap();
    let parsed: socketchat_proto::InviteLink = web.parse().unwrap();
    assert_eq!(parsed, raw);
    let mut b = TestClient::profile_only("Bo").await;
    assert!(matches!(
        b.join(&parsed).await.unwrap(),
        JoinStatus::Waiting { .. }
    ));
    settle(&mut [&mut a, &mut b]).await;
    let ev = drain(&mut b).await;
    assert_eq!(joined(&ev), Some(&Verification::Verified), "{ev:?}");
}
