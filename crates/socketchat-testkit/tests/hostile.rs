//! Members, servers and timing that work against the app: forged vouchers,
//! lost replies, broken groups and stale pins.

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
        "socketchat is already open on this profile."
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
