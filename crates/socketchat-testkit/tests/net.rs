use std::sync::Arc;

use socketchat_core::keys::KeyPair;
use socketchat_core::net::{Conn, NetError};
use socketchat_proto::msg::{Request, Response};
use socketchat_testkit::TestServer;

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
