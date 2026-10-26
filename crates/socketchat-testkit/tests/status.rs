//! What `/status` and `socketchat status` read from a client: the server
//! and the connection to it, this profile, the open room and its
//! encryption.

use std::time::Duration;

use socketchat_core::client::{Link, StatusView};
use socketchat_core::keys::safety_digits;
use socketchat_core::settings::{WhoCanInvite, WhoCanSetTopic};
use socketchat_core::suite::{FALLBACK_SUITE, SUITE};
use socketchat_proto::msg::GroupId;
use socketchat_testkit::{settle, TestClient, TestServer};

/// Ada makes "Book club"; Bo joins from her link.
async fn pair(s: &TestServer) -> (GroupId, TestClient, TestClient) {
    let mut a = TestClient::new(s, "Ada").await;
    let g = a.create_group("Book club").await.unwrap();
    let mut b = TestClient::new(s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    (g, a, b)
}

/// Stops a server and waits for its port to close.
async fn stop(s: &TestServer) {
    s.handle.shutdown();
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn status_reads_the_server_this_profile_and_the_open_room() {
    let s = TestServer::start().await;
    let (g, mut a, b) = pair(&s).await;
    let before = socketchat_core::now_unix();
    let st: StatusView = a.status(Some(g)).await;
    assert_eq!(st.name, "Ada");
    // Ada's digits are one half of the safety number she shares with Bo.
    let bo = b.identity();
    let ada_bo = a
        .members(g)
        .into_iter()
        .find(|m| !m.me)
        .map(|m| a.safety_number(g, &m.key).unwrap())
        .unwrap();
    assert_eq!(st.safety_digits, safety_digits(&a.identity()));
    assert_eq!(st.safety_digits.len(), 35, "{}", st.safety_digits);
    assert!(
        ada_bo.starts_with(&st.safety_digits) || ada_bo.ends_with(&st.safety_digits),
        "{ada_bo} vs {}",
        st.safety_digits
    );
    assert!(ada_bo.contains(&safety_digits(&bo)), "{ada_bo}");

    let server = st.server.expect("the room's server");
    assert_eq!(server.host, "127.0.0.1");
    assert_eq!(server.port, s.addr().port());
    assert_eq!(server.cert_fpr, s.fpr());
    assert_eq!(server.rooms, 1);
    assert_eq!(server.members_invite, Some(true));
    match server.link {
        Link::Connected {
            since_unix,
            protocol,
        } => {
            assert_eq!(protocol, socketchat_proto::PROTOCOL_VERSION);
            assert!(since_unix <= before + 1, "{since_unix} {before}");
            assert!(since_unix + 120 > before, "{since_unix} {before}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(st.other_servers, 0);

    let room = st.room.expect("the open room");
    assert!(!room.is_dm);
    assert_eq!(room.members, 2);
    assert_eq!(
        room.verified,
        a.members(g).iter().filter(|m| m.verified).count(),
        "the People title's rule"
    );
    assert_eq!(room.admins, 1);
    assert!(room.admin);
    assert_eq!(room.invite, WhoCanInvite::Anyone);
    assert_eq!(room.slow_secs, 0);
    assert_eq!(room.topic_who, WhoCanSetTopic::Admins);
    assert!(!room.topic);
    assert!(room.post_quantum);
    assert_eq!(
        room.suite,
        "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519 (0x004F)"
    );

    // Bo is not an admin, and sees the room's settings as they change.
    a.set_slow_mode(g, 30).await.unwrap();
    a.set_topic(g, "Piranesi").await.unwrap();
    let mut b = b;
    settle(&mut [&mut a, &mut b]).await;
    let room = b.status(Some(g)).await.room.unwrap();
    assert!(!room.admin);
    assert_eq!(room.admins, 1);
    assert_eq!(room.slow_secs, 30);
    assert!(room.topic);
}

#[tokio::test]
async fn a_standard_suite_room_says_so() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    a.test_standard_suite(true);
    let g = a.create_group("Plain").await.unwrap();
    let room = a.status(Some(g)).await.room.unwrap();
    assert!(!room.post_quantum);
    assert_eq!(
        room.suite,
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001)"
    );
    assert_eq!(a.room_suite(g), Some(FALLBACK_SUITE));
    assert_ne!(SUITE, FALLBACK_SUITE);
}

#[tokio::test]
async fn a_direct_chat_is_marked_as_one() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s).await;
    let bk = a.members(g).into_iter().find(|m| !m.me).unwrap().key;
    let dm = a.dm(g, &bk).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let st = a.status(Some(dm)).await;
    let room = st.room.unwrap();
    assert!(room.is_dm);
    assert_eq!(room.members, 2);
    assert_eq!(st.server.unwrap().rooms, 2);
}

#[tokio::test]
async fn with_no_room_open_status_names_the_server_new_rooms_go_on() {
    let (s1, s2) = (TestServer::start().await, TestServer::start().await);
    let mut a = TestClient::new(&s1, "Ada").await;
    a.join(&s2.server_invite()).await.unwrap();
    a.sync().await.unwrap();
    let st = a.status(None).await;
    assert!(st.room.is_none());
    let server = st.server.unwrap();
    assert_eq!(server.port, s2.addr().port(), "the newest server");
    assert_eq!(server.rooms, 0);
    assert_eq!(st.other_servers, 1);
}

#[tokio::test]
async fn a_profile_with_no_server_has_no_connection_to_show() {
    let mut a = TestClient::profile_only("Ada").await;
    let st = a.status(None).await;
    assert!(st.server.is_none());
    assert!(st.room.is_none());
    assert_eq!(st.other_servers, 0);
    assert_eq!(st.name, "Ada");
}

#[tokio::test]
async fn the_server_rule_on_inviting_shows_when_connected() {
    let s = TestServer::start_with(|c| c.members_can_invite_to_rooms = false).await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Book club").await.unwrap();
    let server = a.status(Some(g)).await.server.unwrap();
    assert_eq!(server.members_invite, Some(false));
}

#[tokio::test]
async fn status_says_how_the_connection_stands_without_reconnecting() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Book club").await.unwrap();

    // A connection that died and has not been tried again.
    a.test_kill_connections();
    let server = a.status(Some(g)).await.server.unwrap();
    assert_eq!(server.link, Link::Lost);
    assert_eq!(
        server.members_invite, None,
        "nothing asked while it is down"
    );
    assert_eq!(server.link, a.status(Some(g)).await.server.unwrap().link);

    // A server that could not be reached says why.
    stop(&s).await;
    a.sync().await.unwrap();
    let server = a.status(Some(g)).await.server.unwrap();
    assert_eq!(
        server.link,
        Link::Unreachable("connection refused".into()),
        "{server:?}"
    );
    assert_eq!(server.members_invite, None);
    assert_eq!(
        server.cert_fpr,
        s.fpr(),
        "the pinned certificate still shows"
    );

    // A profile just opened has not tried yet.
    let mut a = a.reopen().await;
    let server = a.status(Some(g)).await.server.unwrap();
    assert_eq!(server.link, Link::NotYet);
}
