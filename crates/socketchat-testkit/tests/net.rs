use std::sync::Arc;

use socketchat_core::keys::KeyPair;
use socketchat_core::net::{Conn, NetError};
use socketchat_proto::msg::{Request, Response};
use socketchat_testkit::{SlowProxy, TestServer};

#[tokio::test]
async fn connects_with_matching_fingerprint() {
    let s = TestServer::start().await;
    let c = Conn::connect("127.0.0.1", s.addr().port(), s.fpr())
        .await
        .unwrap();
    assert!(matches!(
        c.request(Request::Challenge).await.unwrap(),
        Response::Challenge(_)
    ));
}

#[tokio::test]
async fn mismatched_server_certificate_refused() {
    let s = TestServer::start().await;
    let wrong = [7u8; 32];
    match Conn::connect("127.0.0.1", s.addr().port(), wrong).await {
        Err(NetError::CertMismatch { expected, got }) => {
            assert_eq!(expected, wrong);
            assert_eq!(got, s.fpr());
        }
        Err(e) => panic!("wrong error: {e:?}"),
        Ok(_) => panic!("connected to a server with the wrong certificate"),
    }
}

#[tokio::test]
async fn request_ids_match_concurrent_replies() {
    let s = TestServer::start().await;
    let c = Arc::new(
        Conn::connect("127.0.0.1", s.addr().port(), s.fpr())
            .await
            .unwrap(),
    );
    let mut tasks = vec![];
    for _ in 0..20 {
        let c = c.clone();
        tasks.push(tokio::spawn(async move {
            c.request(Request::Challenge).await.unwrap()
        }));
    }
    let mut seen = std::collections::HashSet::new();
    for t in tasks {
        let Response::Challenge(ch) = t.await.unwrap() else {
            panic!()
        };
        assert!(seen.insert(ch), "each request gets its own reply");
    }
}

#[tokio::test]
async fn register_then_prove_on_new_connection() {
    let s = TestServer::start().await;
    let link = s.server_invite();
    let k = KeyPair::generate();
    let c = Conn::connect("127.0.0.1", s.addr().port(), s.fpr())
        .await
        .unwrap();
    c.register_account(link.token, &k).await.unwrap();
    let c2 = Conn::connect("127.0.0.1", s.addr().port(), s.fpr())
        .await
        .unwrap();
    c2.prove(&k).await.unwrap();
    let err = c2
        .register_account(link.token, &KeyPair::generate())
        .await
        .unwrap_err();
    assert!(matches!(err, NetError::Refused(_)), "{err:?}");
}

#[tokio::test]
async fn reconnect_after_server_restart_reproves_keys() {
    let mut s = TestServer::start().await;
    let link = s.server_invite();
    let k = KeyPair::generate();
    let mut c = Conn::connect("127.0.0.1", s.addr().port(), s.fpr())
        .await
        .unwrap();
    c.register_account(link.token, &k).await.unwrap();
    s.restart().await;
    assert!(
        c.next_push().await.is_none(),
        "push stream ends when the server goes away"
    );
    assert!(matches!(
        c.request(Request::Challenge).await,
        Err(NetError::Disconnected)
    ));
    c.reconnect().await.unwrap();
    // The account key was proven again, so it can make a server invite.
    let r = c
        .request(Request::CreateInvite { group: None })
        .await
        .unwrap();
    assert!(matches!(r, Response::Invite { .. }), "{r:?}");
}

/// Large requests reach a server that reads slowly. The client handed each
/// request to TLS without flushing; when the socket was full, the last TLS
/// records of a request stayed in the TLS buffer until the next write, so a
/// large request with nothing after it never arrived whole and timed out.
/// Windows CI saw this with two 700 KB messages; the slow link here shows it
/// on every platform.
#[tokio::test]
async fn large_requests_reach_a_slow_server_whole() {
    use socketchat_proto::msg::GroupId;
    let s = TestServer::start().await;
    let proxy = SlowProxy::start(
        s.addr(),
        4096,
        16 * 1024,
        std::time::Duration::from_millis(1),
    )
    .await;
    let c = Conn::connect("127.0.0.1", proxy.port, s.fpr())
        .await
        .unwrap();
    // Only a signed-in connection may send large frames.
    c.register_account(s.server_invite().token, &KeyPair::generate())
        .await
        .unwrap();
    let big = || Request::Post {
        group: GroupId([0; 16]),
        mls: vec![7; 700_000],
        welcome: None,
    };
    let replies = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        tokio::join!(
            c.request(big()),
            c.request(big()),
            c.request(big()),
            c.request(big())
        )
    })
    .await
    .expect("a large request never reached the server whole");
    // In no room, the app is turned down each time, but each one is answered.
    for r in [replies.0, replies.1, replies.2, replies.3] {
        assert!(
            matches!(r, Ok(Response::Refused(_)) | Err(NetError::Server(_))),
            "{r:?}"
        );
    }
}

/// One address over its share of connections, behind a router that a whole
/// office or school shares, gets a reply it can show instead of a reset.
#[tokio::test]
async fn crowded_network_is_told_why() {
    let s = TestServer::start_with(|c| c.max_per_ip = 1).await;
    let first = Conn::connect("127.0.0.1", s.addr().port(), s.fpr())
        .await
        .unwrap();
    let err = Conn::connect("127.0.0.1", s.addr().port(), s.fpr())
        .await
        .err()
        .expect("a second connection from one address got in");
    assert_eq!(
        err.to_string(),
        "this server has too many connections from your network right now; try again in a few minutes"
    );
    // The first connection still works, and its slot comes back when it
    // closes.
    assert!(matches!(
        first.request(Request::Challenge).await.unwrap(),
        Response::Challenge(_)
    ));
    drop(first);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    Conn::connect("127.0.0.1", s.addr().port(), s.fpr())
        .await
        .unwrap();
}

/// A server at its connection limit says it is full.
#[tokio::test]
async fn full_server_is_told_why() {
    let s = TestServer::start_with(|c| c.max_connections = 1).await;
    let _first = Conn::connect("127.0.0.1", s.addr().port(), s.fpr())
        .await
        .unwrap();
    let err = Conn::connect("127.0.0.1", s.addr().port(), s.fpr())
        .await
        .err()
        .expect("a connection over the limit got in");
    assert_eq!(
        err.to_string(),
        "this server is full right now; try again in a few minutes"
    );
}
