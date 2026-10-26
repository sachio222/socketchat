mod common;

use common::{auth_sig, Raw};
use socketchat_core::keys::KeyPair;
use socketchat_proto::msg::{ClientFrame, Request, Response, ServerFrame};
use socketchat_server::{init, make_server_invite, Config, Server, ServerHandle, ACCEPTABLE_USE};

async fn start(max_connections: usize) -> (tempfile::TempDir, ServerHandle) {
    let d = tempfile::tempdir().unwrap();
    init(d.path(), "localhost").unwrap();
    let mut cfg = Config::load(d.path()).unwrap();
    cfg.listen = "127.0.0.1:0".parse().unwrap();
    cfg.max_connections = max_connections;
    let h = Server::start(cfg).await.unwrap();
    (d, h)
}

#[test]
fn init_writes_config_and_cert_and_prints_aup() {
    let d = tempfile::tempdir().unwrap();
    let r = init(d.path(), "chat.example.com").unwrap();
    assert!(d.path().join("socketchat-server.toml").exists());
    assert!(d.path().join("cert.der").exists());
    assert!(d.path().join("key.der").exists());
    assert_ne!(r.cert_fpr, [0; 32]);
    assert!(ACCEPTABLE_USE.contains("Acceptable use"));
    let cfg = Config::load(d.path()).unwrap();
    assert_eq!(cfg.public_host, "chat.example.com");
    assert_eq!(cfg.retention_days, 30);
    assert_eq!(cfg.max_file_mb, 100);
    assert_eq!(cfg.invite_ttl_hours, 24);
    assert!(cfg.members_make_accounts);
    assert!(!cfg.require_standard_suite);
    assert_eq!(cfg.max_connections, 1000);
    assert_eq!(cfg.listen.port(), 7444);
}

#[test]
fn init_refuses_to_overwrite() {
    let d = tempfile::tempdir().unwrap();
    let first = init(d.path(), "h").unwrap();
    assert!(init(d.path(), "h").is_err());
    let cert = std::fs::read(d.path().join("cert.der")).unwrap();
    assert_eq!(
        <[u8; 32]>::from(<sha2::Sha256 as sha2::Digest>::digest(&cert)),
        first.cert_fpr
    );
}

#[tokio::test]
async fn hello_version_mismatch_closes() {
    let (_d, h) = start(10).await;
    let mut c = Raw::connect(h.addr, h.cert_fpr).await;
    c.send(&ClientFrame::Hello { version: 99 }).await;
    assert_eq!(
        c.recv().await,
        Some(ServerFrame::VersionMismatch {
            server: socketchat_proto::PROTOCOL_VERSION
        })
    );
    assert_eq!(c.recv().await, None);
}

#[tokio::test]
async fn request_before_hello_closes() {
    let (_d, h) = start(10).await;
    let mut c = Raw::connect(h.addr, h.cert_fpr).await;
    c.send(&ClientFrame::Req {
        id: 1,
        body: Request::Challenge,
    })
    .await;
    assert_eq!(c.recv().await, None);
}

#[tokio::test]
async fn register_account_with_server_invite() {
    let (d, h) = start(10).await;
    let link = make_server_invite(d.path()).unwrap();
    assert_eq!(link.cert_fpr, h.cert_fpr);
    assert!(link.inviter_fpr.is_none());
    let k = KeyPair::generate();
    let mut c = Raw::connect(h.addr, h.cert_fpr).await;
    c.hello().await;
    let ch = c.challenge().await;
    assert_eq!(
        c.req(Request::RegisterAccount {
            token: link.token,
            key: k.public(),
            sig: auth_sig(&k, &ch)
        })
        .await,
        Response::Ok
    );
    // A later connection signs in with the same key.
    let mut c2 = Raw::connect(h.addr, h.cert_fpr).await;
    c2.hello().await;
    let ch2 = c2.challenge().await;
    assert_ne!(ch, ch2);
    assert_eq!(
        c2.req(Request::Prove {
            key: k.public(),
            sig: auth_sig(&k, &ch2)
        })
        .await,
        Response::Ok
    );
}

#[tokio::test]
async fn register_with_used_token_refused() {
    let (d, h) = start(10).await;
    let link = make_server_invite(d.path()).unwrap();
    let mut c = Raw::connect(h.addr, h.cert_fpr).await;
    c.hello().await;
    let ch = c.challenge().await;
    let (a, b) = (KeyPair::generate(), KeyPair::generate());
    assert_eq!(
        c.req(Request::RegisterAccount {
            token: link.token,
            key: a.public(),
            sig: auth_sig(&a, &ch)
        })
        .await,
        Response::Ok
    );
    let r = c
        .req(Request::RegisterAccount {
            token: link.token,
            key: b.public(),
            sig: auth_sig(&b, &ch),
        })
        .await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
}

#[tokio::test]
async fn register_with_expired_token_refused() {
    let (d, h) = start(10).await;
    let link = make_server_invite(d.path()).unwrap();
    h.advance_clock(25 * 3600);
    let mut c = Raw::connect(h.addr, h.cert_fpr).await;
    c.hello().await;
    let ch = c.challenge().await;
    let k = KeyPair::generate();
    let r = c
        .req(Request::RegisterAccount {
            token: link.token,
            key: k.public(),
            sig: auth_sig(&k, &ch),
        })
        .await;
    assert!(
        matches!(r, Response::Refused(ref s) if s.contains("expired")),
        "{r:?}"
    );
}

#[tokio::test]
async fn prove_with_bad_signature_refused() {
    let (d, h) = start(10).await;
    let link = make_server_invite(d.path()).unwrap();
    let k = KeyPair::generate();
    let mut c = Raw::connect(h.addr, h.cert_fpr).await;
    c.hello().await;
    let ch = c.challenge().await;
    assert_eq!(
        c.req(Request::RegisterAccount {
            token: link.token,
            key: k.public(),
            sig: auth_sig(&k, &ch)
        })
        .await,
        Response::Ok
    );
    let mut c2 = Raw::connect(h.addr, h.cert_fpr).await;
    c2.hello().await;
    let _ch2 = c2.challenge().await;
    // Replaying the first connection's signature fails on the second.
    let r = c2
        .req(Request::Prove {
            key: k.public(),
            sig: auth_sig(&k, &ch),
        })
        .await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    // An unknown key fails even with a good signature.
    let stranger = KeyPair::generate();
    let ch3 = c2.challenge().await;
    let r = c2
        .req(Request::Prove {
            key: stranger.public(),
            sig: auth_sig(&stranger, &ch3),
        })
        .await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
}

#[tokio::test]
async fn connection_limit_enforced() {
    let (_d, h) = start(2).await;
    let mut a = Raw::connect(h.addr, h.cert_fpr).await;
    a.hello().await;
    let mut b = Raw::connect(h.addr, h.cert_fpr).await;
    b.hello().await;
    let mut c = Raw::connect(h.addr, h.cert_fpr).await;
    c.send(&ClientFrame::Hello {
        version: socketchat_proto::PROTOCOL_VERSION,
    })
    .await;
    // The third hears that the server is full, then the connection closes.
    assert_eq!(
        c.recv().await,
        Some(ServerFrame::Busy(socketchat_proto::msg::Busy::Full))
    );
    assert_eq!(c.recv().await, None);
    drop(a);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let mut d2 = Raw::connect(h.addr, h.cert_fpr).await;
    d2.hello().await;
}
