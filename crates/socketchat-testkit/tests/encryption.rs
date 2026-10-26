//! What the app can say about a room's encryption: the room's own suite,
//! the line each room shows once, and who is verified, including someone
//! new under the name of a person verified earlier.

use socketchat_core::client::{changed_key_notice, ChatLine, JoinCheck};
use socketchat_core::keys::{fingerprint, Key, KeyPair};
use socketchat_core::suite::{FALLBACK_SUITE, SUITE};
use socketchat_proto::msg::GroupId;
use socketchat_testkit::{settle, TestClient, TestServer};

/// Ada makes the room "Room"; Bo joins from her link, so Ada's app marks
/// him verified and his marks her verified.
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

/// Ada's room with Bo and Cy, each in through Ada's own link.
async fn trio(s: &TestServer) -> (GroupId, TestClient, TestClient, TestClient) {
    let (g, mut a, mut b) = pair(s).await;
    let mut c = TestClient::new(s, "Cy").await;
    c.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    (g, a, b, c)
}

/// Someone new who calls themselves `name` joins `g` through `inviter`'s
/// link, so nobody else's app has verified them.
async fn newcomer(inviter: &mut TestClient, g: GroupId, name: &str) -> TestClient {
    let link = inviter.invite(Some(g), false).await.unwrap().0;
    let mut m = TestClient::profile_only(name).await;
    m.join(&link).await.unwrap();
    m
}

fn member(c: &TestClient, g: GroupId, key: Key) -> socketchat_core::client::MemberView {
    c.members(g)
        .into_iter()
        .find(|m| m.key == key)
        .expect("in the member list")
}

fn notices(c: &TestClient, g: GroupId) -> Vec<String> {
    c.messages(g, 500)
        .into_iter()
        .filter(|l: &ChatLine| l.notice)
        .map(|l| l.text)
        .collect()
}

#[tokio::test]
async fn each_room_reports_its_own_suite() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    assert_eq!(a.room_suite(g), Some(SUITE));
    assert_eq!(b.room_suite(g), Some(SUITE));
    assert!(a.details(g).await.unwrap().post_quantum);

    a.test_standard_suite(true);
    let plain = a.create_group("Plain").await.unwrap();
    assert_eq!(a.room_suite(plain), Some(FALLBACK_SUITE));
    assert!(!a.details(plain).await.unwrap().post_quantum);
    assert_eq!(
        a.room_suite(g),
        Some(SUITE),
        "the first room keeps its suite"
    );

    b.join(&a.invite(Some(plain), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(b.room_suite(plain), Some(FALLBACK_SUITE));
    assert!(!b.details(plain).await.unwrap().post_quantum);
}

#[tokio::test]
async fn a_new_room_starts_with_the_encryption_line() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Room").await.unwrap();
    let line = a.encryption_line(g).expect("a line in a new room");
    assert_eq!(line.after_seq, 0, "it sits above everything");
    assert_eq!(line.state, JoinCheck::Checked);

    let mut b = TestClient::new(&s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let line = b.encryption_line(g).expect("a line in a joined room");
    assert_eq!(line.after_seq, 0);
    assert_eq!(line.state, JoinCheck::Checked);
    // Placing it again changes nothing.
    b.place_encryption_line(g).unwrap();
    assert_eq!(b.encryption_line(g).unwrap().after_seq, 0);
}

/// A join waiting for its inviter says so until the inviter confirms it.
#[tokio::test]
async fn a_waiting_join_says_who_it_waits_for_until_confirmed() {
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
    let away = a.reopen_later();
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    settle(&mut [&mut c, &mut b]).await;
    assert_eq!(
        b.encryption_line(g).unwrap().state,
        JoinCheck::Waiting {
            inviter: "the person who invited you".into()
        }
    );

    let mut a = away.open().await;
    settle(&mut [&mut a, &mut c, &mut b]).await;
    assert_eq!(b.encryption_line(g).unwrap().state, JoinCheck::Checked);
}

#[tokio::test]
async fn a_join_that_failed_its_check_stays_unchecked() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut link = a.invite(Some(g), false).await.unwrap().0;
    link.inviter_fpr = Some(fingerprint(&KeyPair::generate().public()));
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&link).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert_eq!(b.encryption_line(g).unwrap().state, JoinCheck::Unchecked);
    let b = b.reopen().await;
    assert_eq!(b.encryption_line(g).unwrap().state, JoinCheck::Unchecked);
}

/// A room made before this release has no line until it is first opened;
/// then the line goes after its newest line, once.
#[tokio::test]
async fn an_older_room_gets_the_line_once_where_its_history_ends() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    a.send_text(g, "one").await.unwrap();
    a.send_text(g, "two").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    b.test_forget_encryption_line(g);
    assert_eq!(b.encryption_line(g), None);
    let newest = b.messages(g, 500).last().unwrap().seq;

    b.place_encryption_line(g).unwrap();
    let line = b.encryption_line(g).expect("placed on opening");
    assert_eq!(line.after_seq, newest);
    assert_eq!(line.state, JoinCheck::Checked);

    a.send_text(g, "three").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    b.place_encryption_line(g).unwrap();
    assert_eq!(b.encryption_line(g).unwrap().after_seq, newest, "only once");
    let b = b.reopen().await;
    assert_eq!(b.encryption_line(g).unwrap().after_seq, newest);
}

#[tokio::test]
async fn someone_new_under_a_verified_name_is_flagged_once() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    let bk = b.my_group_key(g).unwrap();
    assert!(member(&a, g, bk).verified);

    let mut m = newcomer(&mut c, g, "Bo").await;
    settle(&mut [&mut a, &mut b, &mut c, &mut m]).await;
    let mk = m.my_group_key(g).unwrap();
    let flagged = member(&a, g, mk);
    assert!(flagged.changed_key && !flagged.verified, "{flagged:?}");
    assert!(
        !member(&a, g, bk).changed_key,
        "the verified Bo is not flagged"
    );
    let warn = changed_key_notice("Bo", "Bo");
    assert_eq!(
        warn,
        "Bo joined with a different key from the Bo you verified. Treat them as someone new until you compare safety numbers: /verify Bo"
    );
    let count = |c: &TestClient| notices(c, g).iter().filter(|n| **n == warn).count();
    assert_eq!(count(&a), 1, "{:?}", notices(&a, g));
    // Cy never verified Bo, so nothing changed for Cy.
    assert!(!member(&c, g, mk).changed_key);
    assert_eq!(count(&c), 0);

    // Someone else joins, and everyone shares their name again: the
    // notice stays one.
    let mut d = newcomer(&mut c, g, "Di").await;
    settle(&mut [&mut a, &mut b, &mut c, &mut m, &mut d]).await;
    assert_eq!(count(&a), 1, "{:?}", notices(&a, g));

    // Verifying the new key clears the flag.
    assert!(a.mark_verified(g, &mk).unwrap());
    assert!(!member(&a, g, mk).changed_key);
}

#[tokio::test]
async fn the_flag_clears_when_the_newcomer_leaves() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    let mut m = newcomer(&mut c, g, "Bo").await;
    settle(&mut [&mut a, &mut b, &mut c, &mut m]).await;
    assert!(a.members(g).iter().any(|x| x.changed_key));
    m.leave(g).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert!(a.members(g).iter().all(|x| !x.changed_key));
}

/// The names of verified people outlive the rooms they were seen in, and a
/// profile from before this release learns them from its member lists.
#[tokio::test]
async fn a_verified_name_is_remembered_after_its_member_leaves() {
    let s = TestServer::start().await;
    let (g, a, mut b) = pair(&s).await;
    a.test_forget_verified_names();
    let mut a = a.reopen().await;
    b.leave(g).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let mut a = a.reopen().await;

    let g2 = a.create_group("Second").await.unwrap();
    let mut c = TestClient::new(&s, "Cy").await;
    c.join(&a.invite(Some(g2), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut c]).await;
    // The real Bo comes back through Cy's link: still verified, not flagged.
    b.join(&c.invite(Some(g2), false).await.unwrap().0)
        .await
        .unwrap();
    let mut m = newcomer(&mut c, g2, "Bo").await;
    settle(&mut [&mut a, &mut b, &mut c, &mut m]).await;
    let bo = member(&a, g2, b.my_group_key(g2).unwrap());
    assert!(bo.verified && !bo.changed_key, "{bo:?}");
    let other = member(&a, g2, m.my_group_key(g2).unwrap());
    assert!(other.changed_key && !other.verified, "{other:?}");
}

#[tokio::test]
async fn names_match_as_the_name_rules_fold_them() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    let mut m = newcomer(&mut c, g, " bO\u{200B} ").await;
    settle(&mut [&mut a, &mut b, &mut c, &mut m]).await;
    let other = member(&a, g, m.my_group_key(g).unwrap());
    assert!(other.changed_key, "{other:?}");
    assert!(notices(&a, g).contains(&changed_key_notice("bO", "Bo")));
}

#[tokio::test]
async fn a_routine_key_refresh_stays_silent() {
    let s = TestServer::start().await;
    let (g, mut a, mut b, mut c) = trio(&s).await;
    let before = notices(&a, g);
    b.update_keys(g).await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    assert_eq!(notices(&a, g), before);
    let bo = member(&a, g, b.my_group_key(g).unwrap());
    assert!(bo.verified && !bo.changed_key, "{bo:?}");
    assert!(a.members(g).iter().all(|x| !x.changed_key));
}
