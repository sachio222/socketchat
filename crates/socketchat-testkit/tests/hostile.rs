//! How the app holds up when members, servers or timing work against it:
//! vouchers that do not check out, lost replies, broken groups and stale
//! pins.

use socketchat_core::appmsg::AppMsg;
use socketchat_core::client::{Client, Event, Verification};
use socketchat_core::keys::{invite_signing_key, voucher_seal_key, KeyPair, Voucher};
use socketchat_core::CoreError;
use socketchat_proto::msg::GroupId;
use socketchat_testkit::{drain, passphrase, settle, CutProxy, TestClient, TestServer};

fn texts(c: &TestClient, g: GroupId) -> Vec<String> {
    c.messages(g, 100)
        .into_iter()
        .filter(|l| !l.notice)
        .map(|l| format!("{}: {}", l.sender, l.text))
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

/// Ada reaches the server through a proxy that can drop one reply; Bo
/// connects directly.
async fn proxied_pair() -> (TestServer, CutProxy, TestClient, TestClient, GroupId) {
    let s = TestServer::start().await;
    let proxy = CutProxy::start(s.addr()).await;
    let mut link = s.server_invite();
    link.port = proxy.port;
    let mut a = TestClient::profile_only("Ada").await;
    a.join(&link).await.unwrap();
    let g = a.create_group("G").await.unwrap();
    let mut inv = a.invite(Some(g), false).await.unwrap().0;
    inv.port = s.addr().port();
    let mut b = TestClient::new(&s, "Bo").await;
    b.join(&inv).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    (s, proxy, a, b, g)
}

// ---------- invites and verified marks ----------

/// A member rewrites a voucher to name the admin as the inviter.
#[tokio::test]
async fn forged_voucher_makes_admin_verify_stranger() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut m = TestClient::profile_only("Mal").await;
    m.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut m]).await;
    let (link, exp) = m.invite(Some(g), false).await.unwrap();
    let secret = link.secret.unwrap();
    let mut forged = Voucher::new(
        &KeyPair::generate(),
        link.token,
        &secret,
        g,
        a.my_group_key(g).unwrap(),
        exp,
    );
    forged.inviter_identity = a.identity();
    m.test_send_app(
        g,
        &AppMsg::Voucher {
            voucher: forged,
            request_key: invite_signing_key(&secret).public(),
            seal_key: voucher_seal_key(&secret),
        },
    )
    .await
    .unwrap();
    settle(&mut [&mut a, &mut m]).await;
    let mut p = TestClient::profile_only("Bo").await;
    p.join(&link).await.unwrap();
    settle(&mut [&mut a, &mut m, &mut p]).await;
    let am = a.members(g);
    assert!(am.iter().any(|x| x.name == "Bo"), "Bo was added: {am:?}");
    assert!(
        !am.iter().any(|x| x.name == "Bo" && x.verified),
        "Ada marks a stranger verified: {am:?}"
    );
}

/// A member races the real invitee with a puppet, using what every member
/// learns about Ada's link. The puppet's request cannot pass Ada's check,
/// so the puppet is never added, let alone verified.
#[tokio::test]
async fn member_racing_the_invitee_earns_no_verified_mark() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut m = TestClient::profile_only("Mal").await;
    m.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut m]).await;
    let (link, _) = a.invite(Some(g), false).await.unwrap();
    settle(&mut [&mut a, &mut m]).await;
    let request_key = m
        .test_invite_request_key(g, link.token)
        .expect("members can check join requests for Ada's link");
    // The puppet holds the token but not the link's secret, and signs with
    // what members hold.
    let mut puppet_link = link.clone();
    puppet_link.secret = Some([9; 32]);
    let mut p = TestClient::profile_only("Pup").await;
    p.test_join_signing_with(&puppet_link, request_key.0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut m, &mut p]).await;
    let am = a.members(g);
    assert!(
        !am.iter()
            .any(|x| x.name == "Pup" || x.name.starts_with("someone")),
        "Ada added the puppet: {am:?}"
    );
    assert_eq!(a.epoch(g), m.epoch(g));
    assert_eq!(am.len(), 2, "{am:?}");
}

/// A member who saw Bo's answer to Ada's direct-message request adds Bo to
/// a chat of their own, and a hostile server hands Bo that Welcome.
#[tokio::test]
async fn direct_message_from_the_wrong_adder_is_unverified() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    let mut m = TestClient::profile_only("Mal").await;
    m.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b, &mut m]).await;
    assert!(
        b.members(g).iter().any(|x| x.name == "Ada" && x.verified),
        "Bo trusts Ada through her invite"
    );
    let bk = b.my_group_key(g).unwrap();
    let dm = a.dm(g, &bk).await.unwrap();
    b.sync().await.unwrap();
    m.sync().await.unwrap();
    let seen = m.test_dm_accepts_seen();
    let kp = seen.first().expect("Mal saw Bo's answer");
    let trap = m.create_group("Trap").await.unwrap();
    // The hostile server moves Bo's waiting mailbox into Mal's chat, so it
    // takes Mal's commit, then hands Bo the Welcome.
    let db = socketchat_testkit::open_server_db(&s);
    let mailbox: Vec<u8> = db
        .query_row(
            "SELECT mailbox FROM joins WHERE group_id = ?1",
            [dm.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    db.execute(
        "UPDATE mailboxes SET group_id = ?1 WHERE key = ?2",
        rusqlite::params![trap.0.as_slice(), mailbox],
    )
    .unwrap();
    let welcome = m.test_add_and_keep_welcome(trap, kp).await.unwrap();
    db.execute(
        "INSERT INTO welcomes (mailbox, welcome, voucher, created_unix) VALUES (?1, ?2, x'', 0)",
        rusqlite::params![mailbox, welcome],
    )
    .unwrap();
    drain(&mut b).await;
    b.sync().await.unwrap();
    let ev = drain(&mut b).await;
    let v = ev.iter().find_map(|e| match e {
        Event::Joined {
            group,
            verification,
        } if *group == trap => Some(verification.clone()),
        _ => None,
    });
    assert!(
        matches!(v, Some(Verification::Unverified { .. })),
        "Bo's app calls Mal's chat a verified direct message with Ada: {v:?} {ev:?}"
    );
}

/// A Welcome from a member who is not the inviter is not marked verified
/// until the inviter confirms the join from inside the room. While no
/// confirmation comes, nobody shows as verified.
#[tokio::test]
async fn forged_welcome_from_member_is_not_verified() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut m = TestClient::new(&s, "Mal").await;
    m.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut m]).await;
    let link = a.invite(Some(g), false).await.unwrap().0;
    m.sync().await.unwrap();
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    let blob = m
        .test_join_request_blob(g, link.token)
        .await
        .expect("Bo's request is waiting");
    let welcome = socketchat_testkit::welcome_into_copy(g, &blob);
    m.test_add_with_welcome(g, link.token, welcome)
        .await
        .unwrap();
    b.sync().await.unwrap();
    let ev = drain(&mut b).await;
    let v = ev.iter().find_map(|e| match e {
        Event::Joined {
            group,
            verification,
        } if *group == g => Some(verification.clone()),
        _ => None,
    });
    assert!(
        matches!(&v, Some(Verification::Unverified { reason }) if reason.contains("not in this chat")),
        "{ev:?}"
    );
    // Ada shares her name in the real room as usual. Bo is not in it.
    settle(&mut [&mut a, &mut m, &mut b]).await;
    let bm = b.members(g);
    assert!(bm.iter().all(|x| x.me || !x.verified), "{bm:?}");
}

/// Only the inviter's own key in the room can confirm a join. The inviter's
/// profile reposted by another member leaves the join waiting, and the
/// inviter's own profile still confirms it afterwards.
#[tokio::test]
async fn inviter_profile_from_other_member_does_not_confirm_join() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut c = TestClient::new(&s, "Cy").await;
    c.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    let mut m = TestClient::new(&s, "Mal").await;
    m.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut c, &mut m]).await;
    let ck = c.my_group_key(g).unwrap();
    a.make_admin(g, &ck).await.unwrap();
    let ak = a.my_group_key(g).unwrap();
    let ada_binding = a.test_binding(g).unwrap();
    let link = a.invite(Some(g), false).await.unwrap().0;
    settle(&mut [&mut a, &mut c, &mut m]).await;
    // Ada goes offline; Cy, an admin, lets Bo in.
    let away = a.reopen_later();
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    settle(&mut [&mut c, &mut m, &mut b]).await;
    let ev = drain(&mut b).await;
    let waiting = Verification::Waiting {
        inviter: "the person who invited you".into(),
    };
    assert!(
        ev.contains(&Event::Joined {
            group: g,
            verification: waiting
        }),
        "{ev:?}"
    );

    // Mal reposts Ada's profile, binding and all, from his own key.
    m.test_send_app(
        g,
        &AppMsg::Profile {
            display_name: "Ada".into(),
            binding: ada_binding,
        },
    )
    .await
    .unwrap();
    settle(&mut [&mut c, &mut m, &mut b]).await;
    let ev = drain(&mut b).await;
    assert!(
        !ev.iter()
            .any(|e| matches!(e, Event::InviteConfirmed { .. })),
        "{ev:?}"
    );
    let bm = b.members(g);
    assert!(bm.iter().all(|x| x.me || !x.verified), "{bm:?}");

    // Ada's own profile confirms the join once she is back.
    let mut a = away.open().await;
    settle(&mut [&mut a, &mut c, &mut m, &mut b]).await;
    let ev = drain(&mut b).await;
    assert!(
        ev.iter().any(|e| matches!(e,
            Event::InviteConfirmed { group, inviter } if *group == g && inviter == "Ada")),
        "{ev:?}"
    );
    assert!(b.members(g).iter().any(|x| x.key == ak && x.verified));
}

/// The inviter marks someone verified from an invite proof only when that
/// person joined with the invite, and only once per invite. A member who
/// knows the link but did not join with it stays unverified.
#[tokio::test]
async fn invite_proof_from_other_member_is_ignored() {
    use socketchat_core::keys::invite_proof;

    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut c = TestClient::new(&s, "Cy").await;
    c.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut c]).await;
    // Mal joins with Cy's link, so Ada has no reason to verify him.
    let mut m = TestClient::new(&s, "Mal").await;
    m.join(&c.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut c, &mut m]).await;
    let mk = m.my_group_key(g).unwrap();
    let mal_verified = |a: &TestClient| a.members(g).iter().any(|x| x.key == mk && x.verified);
    assert!(!mal_verified(&a));

    // Mal learns the secret in Ada's next link and proves it, first before
    // anyone joins with it, then again after Bo did.
    let link = a.invite(Some(g), false).await.unwrap().0;
    let secret = link.secret.unwrap();
    let proof = AppMsg::InviteProof {
        token: link.token,
        proof: invite_proof(&secret, &g, &mk),
    };
    m.test_send_app(g, &proof).await.unwrap();
    settle(&mut [&mut a, &mut c, &mut m]).await;
    assert!(!mal_verified(&a), "{:?}", a.members(g));

    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    settle(&mut [&mut a, &mut c, &mut m, &mut b]).await;
    let bk = b.my_group_key(g).unwrap();
    assert!(
        a.members(g).iter().any(|x| x.key == bk && x.verified),
        "{:?}",
        a.members(g)
    );
    m.test_send_app(g, &proof).await.unwrap();
    settle(&mut [&mut a, &mut c, &mut m, &mut b]).await;
    assert!(!mal_verified(&a), "{:?}", a.members(g));
}

// ---------- lost replies to commits ----------

/// Someone else posts between Ada's last fetch and her commit, and the
/// reply to the commit never arrives.
#[tokio::test]
async fn lost_reply_with_message_before_commit() {
    let (_s, proxy, mut a, mut b, g) = proxied_pair().await;
    b.send_text(g, "between").await.unwrap();
    let before = a.epoch(g).unwrap();
    proxy.arm();
    assert!(a.update_keys(g).await.is_err(), "the reply never arrives");
    a.resolve_pending(g).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(b.epoch(g), Some(before + 1));
    assert_eq!(a.epoch(g), b.epoch(g), "Ada and Bo disagree on the epoch");
    a.send_text(g, "after the drop").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert!(
        texts(&b, g).contains(&"Ada: after the drop".to_string()),
        "{:?}",
        texts(&b, g)
    );
}

/// The app closes before the commit is settled.
#[tokio::test]
async fn lost_reply_then_restart() {
    let (_s, proxy, mut a, mut b, g) = proxied_pair().await;
    let before = a.epoch(g).unwrap();
    proxy.arm();
    assert!(a.update_keys(g).await.is_err(), "the reply never arrives");
    let mut a = a.reopen().await;
    a.sync().await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(b.epoch(g), Some(before + 1));
    assert_eq!(a.epoch(g), b.epoch(g), "Ada and Bo disagree on the epoch");
    a.send_text(g, "after restart").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert!(
        texts(&b, g).contains(&"Ada: after restart".to_string()),
        "{:?}",
        texts(&b, g)
    );
}

/// The weekly key refresh loses its reply, then the app opens again a week
/// later.
#[tokio::test]
async fn lost_refresh_then_restart_breaks_sync() {
    let (_s, proxy, mut a, mut b, g) = proxied_pair().await;
    proxy.arm();
    assert!(a.update_keys(g).await.is_err());
    let mut a = a.reopen().await;
    a.advance_clock(8 * 24 * 3600);
    let r = a.sync().await;
    assert!(r.is_ok(), "{r:?}");
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(a.epoch(g), b.epoch(g), "Ada and Bo disagree on the epoch");
}

/// A commit that never reached the server is dropped once the log shows it
/// is not there, so the next change goes through.
#[tokio::test]
async fn commit_the_server_never_took_is_dropped() {
    let (_s, proxy, mut a, mut b, g) = proxied_pair().await;
    let before = a.epoch(g).unwrap();
    // Bo moves the group on first, so Ada's staged commit can never land.
    b.update_keys(g).await.unwrap();
    proxy.arm();
    assert!(a.update_keys(g).await.is_err());
    let mut a = a.reopen().await;
    a.update_keys(g).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(a.epoch(g), Some(before + 2));
    assert_eq!(a.epoch(g), b.epoch(g));
}

/// An app that lost track of its own commit says so instead of going quiet.
#[tokio::test]
async fn out_of_step_chat_warns_once() {
    let (_s, proxy, mut a, mut b, g) = proxied_pair().await;
    proxy.arm();
    assert!(a.update_keys(g).await.is_err());
    a.test_drop_pending_commit(g);
    drain(&mut a).await;
    a.sync().await.unwrap();
    b.send_text(g, "one").await.unwrap();
    b.send_text(g, "two").await.unwrap();
    a.sync().await.unwrap();
    let w = warnings(&drain(&mut a).await);
    let out: Vec<_> = w
        .iter()
        .filter(|w| w.contains("fell out of step"))
        .collect();
    assert_eq!(out.len(), 1, "{w:?}");
}

/// A chat that fell out of step is not told this app's version: the
/// message could not reach the others anyway.
#[tokio::test]
async fn out_of_step_chat_is_not_told_the_app_version() {
    let (_s, proxy, mut a, mut b, g) = proxied_pair().await;
    proxy.arm();
    assert!(a.update_keys(g).await.is_err());
    a.test_drop_pending_commit(g);
    b.send_text(g, "one").await.unwrap();
    a.sync().await.unwrap();
    assert!(warnings(&drain(&mut a).await)
        .iter()
        .any(|w| w.contains("fell out of step")));
    a.test_announce_version("9.9.9");
    for _ in 0..3 {
        a.sync().await.unwrap();
    }
    let me = a.members(g).into_iter().find(|m| m.me).unwrap();
    assert_ne!(me.app_version.as_deref(), Some("9.9.9"));
    let w = warnings(&drain(&mut a).await);
    assert!(!w.iter().any(|w| w.contains("app version")), "{w:?}");
}

/// A room the server will not take the version message in says so once
/// per session, not on every sync.
#[tokio::test]
async fn refused_version_message_warns_once() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Crew").await.unwrap();
    a.sync().await.unwrap();
    drain(&mut a).await;
    a.test_announce_version("9.9.9");
    a.test_refuse_posts(g);
    for _ in 0..4 {
        a.sync().await.unwrap();
    }
    let w = warnings(&drain(&mut a).await);
    let shared: Vec<_> = w
        .iter()
        .filter(|w| w.starts_with("Could not share your app version in Crew"))
        .collect();
    assert_eq!(shared.len(), 1, "{w:?}");
}

// ---------- sync keeps going ----------

/// One broken group does not stop the others on the same server.
#[tokio::test]
async fn broken_group_does_not_stop_the_others() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let broken = a.create_group("Broken").await.unwrap();
    let g = a.create_group("Fine").await.unwrap();
    a.test_break_group(broken);
    drain(&mut a).await;
    let r = a.sync().await;
    assert!(r.is_ok(), "{r:?}");
    assert!(!warnings(&drain(&mut a).await).is_empty());
    let mut c = TestClient::profile_only("Cy").await;
    c.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    for _ in 0..4 {
        let _ = a.sync().await;
        c.sync().await.unwrap();
    }
    assert!(
        c.groups().iter().any(|x| x.id == g),
        "Cy never got into Ada's other group"
    );
}

/// Only the server's "not a member" answer means this person is out.
#[tokio::test]
async fn refused_fetch_keeps_the_group_unless_not_a_member() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    drain(&mut a).await;
    a.test_refuse_next_fetch(g, "the server is busy; try again soon");
    a.sync().await.unwrap();
    let ev = drain(&mut a).await;
    assert!(
        !ev.iter().any(|e| matches!(e, Event::Left { .. })),
        "{ev:?}"
    );
    assert!(!warnings(&ev).is_empty(), "{ev:?}");
    assert!(a.groups().iter().any(|x| x.id == g && !x.left));
    a.send_text(g, "still here").await.unwrap();
    a.test_refuse_next_fetch(g, "you are not a member of this group");
    a.sync().await.unwrap();
    let ev = drain(&mut a).await;
    assert!(ev.iter().any(|e| matches!(e, Event::Left { .. })), "{ev:?}");
}

/// Two big messages in a row; the others can still fetch what follows.
#[tokio::test]
async fn two_big_messages_do_not_block_fetch() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    for _ in 0..2 {
        b.test_send_app(
            g,
            &AppMsg::Text {
                body: "x".repeat(700_000),
            },
        )
        .await
        .unwrap();
    }
    b.send_text(g, "after").await.unwrap();
    for _ in 0..3 {
        let _ = a.sync().await;
    }
    assert!(
        texts(&a, g).contains(&"Bo: after".to_string()),
        "Ada never gets the later message"
    );
}

/// A message over the server's size limit is turned down before it goes
/// out, and the group keeps working.
#[tokio::test]
async fn oversized_message_is_refused_before_sending() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let err = a
        .test_send_app(
            g,
            &AppMsg::Text {
                body: "x".repeat(1_100_000),
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, socketchat_core::CoreError::Other(ref w) if w.contains("too large")),
        "the app sent it anyway: {err:?}"
    );
    a.send_text(g, "small").await.unwrap();
}

// ---------- profiles and servers ----------

/// The chat screen is open while a script opens the same profile.
#[tokio::test]
async fn second_open_of_one_profile_is_refused() {
    let s = TestServer::start().await;
    let a = TestClient::new(&s, "Ada").await;
    let second = Client::open(a.dir.path(), passphrase()).await;
    let err = second.err().expect("a second open must fail");
    assert_eq!(
        err.to_string(),
        "Socketchat is already open on this profile."
    );
    let mut a = a.reopen().await;
    a.create_group("After").await.unwrap();
}

/// The operator set the server up again: same address, new certificate. A
/// plain join with a new link is refused and shows both fingerprints; once
/// Ada accepts the new certificate the link works, and the app says it now
/// trusts the new one.
#[tokio::test]
async fn new_certificate_in_a_link_replaces_the_old_pin_once_accepted() {
    use socketchat_core::keys::fingerprint_text;
    let s = TestServer::start().await;
    let old = s.fpr();
    let mut a = TestClient::new(&s, "Ada").await;
    let s = s.replace_with_fresh().await;
    drain(&mut a).await;
    let link = s.server_invite();
    let err = a.join(&link).await.unwrap_err();
    assert!(
        matches!(err, CoreError::NewCertificate { pinned, offered, .. } if pinned == old && offered == s.fpr()),
        "{err:?}"
    );
    let said = err.to_string();
    assert!(said.contains(&fingerprint_text(&old)), "{said}");
    assert!(said.contains(&fingerprint_text(&s.fpr())), "{said}");
    assert!(said.contains("socketchat join --new-certificate"), "{said}");
    a.join_new_certificate(&link).await.unwrap();
    a.create_group("Again").await.unwrap();
    let w = warnings(&drain(&mut a).await);
    assert!(w.iter().any(|w| w.contains("new certificate")), "{w:?}");
}

/// Accepting the certificate in a bogus link changes nothing when the
/// server does not have that certificate: Ada keeps her chat.
#[tokio::test]
async fn accepting_a_bogus_certificate_keeps_the_old_pin() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut bogus = s.server_invite();
    bogus.cert_fpr = [7; 32];
    let err = a.join_new_certificate(&bogus).await.unwrap_err();
    assert!(
        matches!(
            err,
            CoreError::Net(socketchat_core::net::NetError::CertMismatch { .. })
        ),
        "{err:?}"
    );
    a.send_text(g, "still here").await.unwrap();
    a.sync().await.unwrap();
    assert!(
        !warnings(&drain(&mut a).await)
            .iter()
            .any(|w| w.contains("new certificate")),
        "the pin changed"
    );
}

/// A change that adds someone to the room and comes from no member of it
/// is refused: the creator's app says so once, and the room stays as it
/// was.
#[tokio::test]
async fn a_change_from_outside_the_room_leaves_it_as_it_was() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Room").await.unwrap();
    let (gi, tree) = a.test_uploaded_group_info(g).expect("uploaded");
    socketchat_testkit::append_to_log(&s, g, &socketchat_testkit::outside_commit(&gi, &tree));
    drain(&mut a).await;
    a.sync().await.unwrap();
    a.sync().await.unwrap();
    assert_eq!(a.epoch(g), Some(0), "the outside commit was merged");
    assert_eq!(a.members(g).len(), 1, "{:?}", a.members(g));
    assert_eq!(a.details(g).await.unwrap().size, 1);
    let warned = warnings(&drain(&mut a).await);
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(warned[0].contains("not a member"), "{warned:?}");

    // The room still works, and someone who joins later finds two people.
    let mut b = TestClient::new(&s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(b.members(g).len(), 2, "{:?}", b.members(g));
    assert_eq!(a.members(g).len(), 2, "{:?}", a.members(g));
    a.send_text(g, "hello").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert!(
        texts(&b, g).contains(&"Ada: hello".to_string()),
        "{:?}",
        texts(&b, g)
    );
}

/// A member of the MLS group this app has no record of still shows in the
/// member list, as someone unknown.
#[tokio::test]
async fn member_with_no_record_shows_as_unknown() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Room").await.unwrap();
    let mut b = TestClient::new(&s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let bk = b.my_group_key(g).unwrap();
    a.test_forget_member_row(g, bk);
    let ms = a.members(g);
    assert_eq!(ms.len(), 2, "{ms:?}");
    let bo = ms.iter().find(|m| m.key == bk).expect("Bo listed");
    assert!(bo.name.starts_with("someone ("), "{}", bo.name);
    assert!(!bo.verified && !bo.me && !bo.admin);
    let ada = ms.iter().find(|m| m.me).expect("Ada listed");
    assert_eq!(ada.name, "Ada");
    assert!(ada.admin);
}

// ---------- who may change a room ----------

/// Ada's room with Bo and Cy in it, Ada its only admin. Every event so far
/// is drained.
async fn room_of_three(s: &TestServer) -> (GroupId, TestClient, TestClient, TestClient) {
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

fn admins(c: &TestClient, g: GroupId) -> Vec<String> {
    c.members(g)
        .into_iter()
        .filter(|m| m.admin)
        .map(|m| m.name)
        .collect()
}

/// A member who is not an admin makes themselves the only admin, and the
/// change reaches the room's log. The other apps keep the room as it was
/// and say so once.
#[tokio::test]
async fn non_admin_admin_change_is_refused_by_clients() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = room_of_three(&s).await;
    let bk = b.my_group_key(g).unwrap();
    let epoch = a.epoch(g);
    let commit = b.test_unchecked_commit(g, &[], Some(&[bk])).unwrap();
    socketchat_testkit::append_to_log(&s, g, &commit);
    for x in [&mut a, &mut c] {
        x.sync().await.unwrap();
        x.sync().await.unwrap();
        assert_eq!(x.epoch(g), epoch);
        assert_eq!(admins(x, g), vec!["Ada".to_string()]);
        let warned = warnings(&drain(x).await);
        assert_eq!(warned.len(), 1, "{warned:?}");
        assert!(warned[0].contains("no right"), "{warned:?}");
    }
}

/// A member who is not an admin removes everyone else. The apps of those
/// removed, and of anyone else, keep them in the room.
#[tokio::test]
async fn non_admin_removal_is_refused_by_clients() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = room_of_three(&s).await;
    let ak = a.my_group_key(g).unwrap();
    let ck = c.my_group_key(g).unwrap();
    let commit = b.test_unchecked_commit(g, &[ak, ck], None).unwrap();
    socketchat_testkit::append_to_log(&s, g, &commit);
    for x in [&mut a, &mut c] {
        x.sync().await.unwrap();
        x.sync().await.unwrap();
        assert_eq!(x.members(g).len(), 3, "{:?}", x.members(g));
        let warned = warnings(&drain(x).await);
        assert_eq!(warned.len(), 1, "{warned:?}");
    }
    // The room carries on for the two who were not fooled.
    a.send_text(g, "still here").await.unwrap();
    c.sync().await.unwrap();
    assert!(texts(&c, g).contains(&"Ada: still here".to_string()));
}

/// An admin's own changes still apply everywhere: making an admin, then
/// removing a member.
#[tokio::test]
async fn admin_changes_still_apply() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = room_of_three(&s).await;
    let bk = b.my_group_key(g).unwrap();
    let ck = c.my_group_key(g).unwrap();
    a.make_admin(g, &bk).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    b.remove_member(g, &ck).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    for x in [&a, &b] {
        assert_eq!(x.members(g).len(), 2, "{:?}", x.members(g));
        assert_eq!(admins(x, g).len(), 2);
    }
    for x in [&mut a, &mut b] {
        assert!(warnings(&drain(x).await).is_empty());
    }
}

/// A member's request to add someone, once it reaches the room's log,
/// never rides along when another member commits a leave.
#[tokio::test]
async fn commit_leaves_ignores_foreign_proposals() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = room_of_three(&s).await;
    let ck = c.my_group_key(g).unwrap();
    let add = b
        .test_propose_add(g, &socketchat_testkit::forged_key_package_blob())
        .unwrap();
    socketchat_testkit::append_to_log(&s, g, &add);
    a.sync().await.unwrap();
    c.leave(g).await.unwrap();
    for _ in 0..3 {
        a.sync().await.unwrap();
    }
    let ms = a.members(g);
    assert_eq!(ms.len(), 2, "{ms:?}");
    assert!(ms.iter().all(|m| m.key != ck), "{ms:?}");
}

// ---------- who takes over from the last admin ----------

/// Ada, the only admin, leaves, and the server's records put Cy's join
/// before Bo's. Bo's app knows it was in the room before Cy, so it picks
/// the next admin from its own record.
#[tokio::test]
async fn successor_comes_from_the_apps_own_join_record() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, c) = room_of_three(&s).await;
    let ck = c.my_group_key(g).unwrap();
    drop(c);
    open_db_set_joined(&s, ck, 0);
    a.leave(g).await.unwrap();
    for _ in 0..3 {
        b.sync().await.unwrap();
    }
    let ms = b.members(g);
    assert!(
        ms.iter().all(|m| m.key != ck || !m.admin),
        "Cy made admin on the server's word: {ms:?}"
    );
}

/// The same records, and Cy's app commits the leave and makes Cy the
/// admin. Bo, who joined first, refuses that change and says so.
#[tokio::test]
async fn first_joiner_refuses_a_promotion_out_of_order() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = room_of_three(&s).await;
    let ck = c.my_group_key(g).unwrap();
    let epoch = b.epoch(g);
    open_db_set_joined(&s, ck, 0);
    a.leave(g).await.unwrap();
    for _ in 0..3 {
        c.sync().await.unwrap();
    }
    assert!(c.members(g).iter().any(|m| m.key == ck && m.admin));
    b.sync().await.unwrap();
    b.sync().await.unwrap();
    assert_eq!(b.epoch(g), epoch);
    assert!(b.members(g).iter().all(|m| m.key != ck || !m.admin));
    let warned = warnings(&drain(&mut b).await);
    assert_eq!(warned.len(), 1, "{warned:?}");
}

/// Rewrites the join order the server keeps for `key`, as an operator
/// with the database could.
fn open_db_set_joined(s: &TestServer, key: socketchat_core::keys::Key, seq: i64) {
    let db = socketchat_testkit::open_server_db(s);
    db.execute(
        "UPDATE mailboxes SET joined_seq = ?1 WHERE key = ?2",
        rusqlite::params![seq, key.0.as_slice()],
    )
    .unwrap();
}

// ---------- what an unconfirmed joiner shares ----------

/// A join whose Welcome comes with no voucher. The joiner's app says the
/// invite could not be checked and shares neither its name nor its
/// identity key nor its app version there.
#[tokio::test]
async fn unverified_join_sends_no_profile() {
    let s = TestServer::start().await;
    let (mut b, g) = joined_into_servers_copy(&s).await;
    let ev = drain(&mut b).await;
    assert!(
        ev.iter().any(|e| matches!(
            e,
            Event::Joined {
                verification: Verification::Unverified { .. },
                ..
            }
        )),
        "{ev:?}"
    );
    let sent = b.test_sent_kinds(g);
    assert!(
        !sent.iter().any(|k| k == "Profile" || k == "AppInfo"),
        "{sent:?}"
    );
}

/// The same join tells the person their name stays hidden there.
#[tokio::test]
async fn held_unverified_join_says_the_name_is_hidden() {
    let s = TestServer::start().await;
    let (mut b, _) = joined_into_servers_copy(&s).await;
    let warned = warnings(&drain(&mut b).await);
    assert!(
        warned
            .iter()
            .any(|w| w.contains("Your name stays hidden there until you mark someone verified.")),
        "{warned:?}"
    );
}

/// Bo's join with a link whose Welcome comes with no voucher and names a
/// different room from the link's. Bo has synced twice; his events are
/// not drained.
async fn joined_into_servers_copy(s: &TestServer) -> (TestClient, GroupId) {
    let mut a = TestClient::new(s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    a.update_keys(g).await.unwrap();
    let link = a.invite(Some(g), false).await.unwrap().0;
    drop(a);
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    let db = socketchat_testkit::open_server_db(s);
    let (mailbox, blob): (Vec<u8>, Vec<u8>) = db
        .query_row("SELECT mailbox, key_package FROM joins", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    db.execute("DELETE FROM joins", []).unwrap();
    // Bo's mailbox counts as joined, so his app can post there.
    db.execute(
        "UPDATE mailboxes SET joined_seq = 0, cursor = 0 WHERE key = ?1",
        [&mailbox],
    )
    .unwrap();
    let welcome = socketchat_testkit::welcome_into_copy(g, &blob);
    db.execute(
        "INSERT INTO welcomes (mailbox, welcome, voucher, created_unix) VALUES (?1, ?2, x'', 0)",
        rusqlite::params![mailbox, welcome],
    )
    .unwrap();
    b.sync().await.unwrap();
    b.sync().await.unwrap();
    (b, g)
}

/// A request in the store that is not a member's own request to leave
/// stays out of the commit this app makes when someone leaves, even if it
/// got into the store.
#[tokio::test]
async fn commit_leaves_takes_only_requests_to_leave() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = room_of_three(&s).await;
    let ak = a.my_group_key(g).unwrap();
    let bk = b.my_group_key(g).unwrap();
    let ck = c.my_group_key(g).unwrap();
    let grab = b.test_propose_admins(g, &[ak, bk]).unwrap();
    socketchat_testkit::append_to_log(&s, g, &grab);
    a.sync().await.unwrap();
    let warned = warnings(&drain(&mut a).await);
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(warned[0].contains("no right"), "{warned:?}");
    a.test_store_proposal(g, &grab).unwrap();
    c.leave(g).await.unwrap();
    for _ in 0..3 {
        a.sync().await.unwrap();
    }
    assert!(a.members(g).iter().all(|m| m.key != ck));
    b.sync().await.unwrap();
    assert_eq!(
        b.test_merged_commits(g).last(),
        Some(&vec!["Remove".to_string()]),
        "{:?}",
        b.test_merged_commits(g)
    );
    assert_eq!(admins(&b, g), vec!["Ada".to_string()]);
}

/// After a refused change, a room that moved on without this app gives
/// no second warning on top.
#[tokio::test]
async fn refused_change_warns_once_when_the_room_moves_on() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, _c) = room_of_three(&s).await;
    let bk = b.my_group_key(g).unwrap();
    let commit = b.test_unchecked_commit(g, &[], Some(&[bk])).unwrap();
    socketchat_testkit::append_to_log(&s, g, &commit);
    // The server moves its own epoch along with the change it let through.
    socketchat_testkit::open_server_db(&s)
        .execute("UPDATE groups SET epoch = epoch + 1", [])
        .unwrap();
    b.send_text(g, "mine now").await.unwrap();
    a.sync().await.unwrap();
    a.sync().await.unwrap();
    let warned = warnings(&drain(&mut a).await);
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(warned[0].contains("no right"), "{warned:?}");
}

/// Once a later change merges in the room, a refusal from before no
/// longer keeps this app quiet: falling out of step after that is
/// reported.
#[tokio::test]
async fn drift_after_a_later_change_is_reported_despite_an_old_refusal() {
    let (s, proxy, mut a, mut b, g) = proxied_pair().await;
    let bk = b.my_group_key(g).unwrap();
    let commit = b.test_unchecked_commit(g, &[], Some(&[bk])).unwrap();
    b.test_drop_pending_commit(g);
    socketchat_testkit::append_to_log(&s, g, &commit);
    drain(&mut a).await;
    a.sync().await.unwrap();
    let w = warnings(&drain(&mut a).await);
    assert_eq!(w.len(), 1, "{w:?}");
    assert!(w[0].contains("no right"), "{w:?}");
    // An honest change merges everywhere.
    a.update_keys(g).await.unwrap();
    b.sync().await.unwrap();
    // Then this app loses its own next change, as in a real fault.
    proxy.arm();
    assert!(a.update_keys(g).await.is_err());
    a.test_drop_pending_commit(g);
    a.sync().await.unwrap();
    b.send_text(g, "one").await.unwrap();
    a.sync().await.unwrap();
    let w = warnings(&drain(&mut a).await);
    let out: Vec<_> = w
        .iter()
        .filter(|w| w.contains("fell out of step"))
        .collect();
    assert_eq!(out.len(), 1, "{w:?}");
}
