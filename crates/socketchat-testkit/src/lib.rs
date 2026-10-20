//! Test helpers: a real server in a temporary directory on a free port, and
//! headless clients with their own temporary profiles.

use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};

use socketchat_core::client::{Client, Event};
use socketchat_core::keys::KeyPair;
use socketchat_proto::InviteLink;
use socketchat_server::{init, make_server_invite, Config, Server, ServerHandle};

pub type Db = rusqlite::Connection;

pub const PASSPHRASE: &str = "correct horse battery staple";

pub struct TestServer {
    pub dir: tempfile::TempDir,
    pub handle: ServerHandle,
    cfg: Config,
}

impl TestServer {
    pub async fn start() -> TestServer {
        Self::start_with(|_| {}).await
    }

    pub async fn start_with(f: impl FnOnce(&mut Config)) -> TestServer {
        let dir = tempfile::tempdir().expect("temp dir");
        init(dir.path(), "127.0.0.1").expect("init");
        let mut cfg = Config::load(dir.path()).expect("config");
        cfg.listen = "127.0.0.1:0".parse().unwrap();
        f(&mut cfg);
        let handle = Server::start(cfg.clone()).await.expect("start");
        cfg.listen = handle.addr;
        cfg.save().expect("save config");
        TestServer { dir, handle, cfg }
    }

    pub fn addr(&self) -> SocketAddr {
        self.handle.addr
    }

    pub fn fpr(&self) -> [u8; 32] {
        self.handle.cert_fpr
    }

    pub fn server_invite(&self) -> InviteLink {
        make_server_invite(self.dir.path()).expect("invite")
    }

    /// Stops the server and starts it again on the same port and data.
    pub async fn restart(&mut self) {
        self.handle.shutdown();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        for _ in 0..50 {
            match Server::start(self.cfg.clone()).await {
                Ok(h) => {
                    self.handle = h;
                    return;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
            }
        }
        panic!("server did not restart");
    }
}

/// Opens the server's database file directly, as an attacker who took the
/// server over could.
pub fn open_server_db(s: &TestServer) -> Db {
    rusqlite::Connection::open(s.dir.path().join(socketchat_server::db::DB_FILE)).expect("db")
}

/// KeyPackages a hostile server might swap in for a real joiner's.
pub fn forged_key_package_blob() -> Vec<u8> {
    let prov = openmls_rust_crypto::OpenMlsRustCrypto::default();
    socketchat_core::invite::key_package_blob(&prov, &KeyPair::generate()).expect("blob")
}

/// A headless client with its own temporary profile directory.
pub struct TestClient {
    client: Client,
    pub dir: tempfile::TempDir,
}

impl TestClient {
    /// A profile with no server yet.
    pub async fn profile_only(name: &str) -> TestClient {
        let dir = tempfile::tempdir().expect("temp dir");
        let client = Client::create_profile(dir.path(), PASSPHRASE, name)
            .await
            .expect("profile");
        TestClient { client, dir }
    }

    /// A profile with an account on `s`.
    pub async fn new(s: &TestServer, name: &str) -> TestClient {
        let mut c = Self::profile_only(name).await;
        c.join(&s.server_invite()).await.expect("server invite");
        c
    }

    /// Closes this client; `open` on the result brings it back from disk.
    pub fn reopen_later(self) -> ClosedClient {
        let TestClient { client, dir } = self;
        drop(client);
        ClosedClient { dir }
    }

    /// Closes this client and opens its profile again from disk.
    pub async fn reopen(self) -> TestClient {
        let TestClient { client, dir } = self;
        drop(client);
        let client = Client::open(dir.path(), PASSPHRASE).await.expect("reopen");
        TestClient { client, dir }
    }
}

/// A profile on disk whose client is closed.
pub struct ClosedClient {
    dir: tempfile::TempDir,
}

impl ClosedClient {
    pub async fn open(self) -> TestClient {
        let client = Client::open(self.dir.path(), PASSPHRASE)
            .await
            .expect("open");
        TestClient {
            client,
            dir: self.dir,
        }
    }
}

impl Deref for TestClient {
    type Target = Client;
    fn deref(&self) -> &Client {
        &self.client
    }
}

impl DerefMut for TestClient {
    fn deref_mut(&mut self) -> &mut Client {
        &mut self.client
    }
}

/// Lets every client fetch and act a few times, so joins, profiles and
/// messages finish moving.
pub async fn settle(clients: &mut [&mut TestClient]) {
    for _ in 0..4 {
        for c in clients.iter_mut() {
            c.sync().await.expect("sync");
        }
    }
}

/// Events a client has queued so far.
pub async fn drain(c: &mut TestClient) -> Vec<Event> {
    c.take_events()
}

/// A TCP relay between a client and the server that can drop one reply:
/// once armed, it forwards the client's next bytes, discards whatever the
/// server sends back, and closes both sides.
pub struct CutProxy {
    pub port: u16,
    armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl CutProxy {
    pub async fn start(target: SocketAddr) -> CutProxy {
        use std::sync::atomic::Ordering;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let armed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let armed2 = armed.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let Ok(server) = tokio::net::TcpStream::connect(target).await else {
                    continue;
                };
                let (mut cr, mut cw) = client.into_split();
                let (mut sr, mut sw) = server.into_split();
                let armed = armed2.clone();
                let cut = std::sync::Arc::new(tokio::sync::Notify::new());
                let cut2 = cut.clone();
                let armed_up = armed.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        let n = match cr.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if sw.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        if armed_up.load(Ordering::SeqCst) {
                            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                            armed_up.store(false, Ordering::SeqCst);
                            cut2.notify_waiters();
                            break;
                        }
                    }
                });
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        tokio::select! {
                            _ = cut.notified() => break,
                            r = sr.read(&mut buf) => {
                                let n = match r { Ok(0) | Err(_) => break, Ok(n) => n };
                                if armed.load(Ordering::SeqCst) {
                                    continue;
                                }
                                if cw.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    let _ = cw.shutdown().await;
                });
            }
        });
        CutProxy { port, armed }
    }

    /// Drops the server's reply to the client's next request.
    pub fn arm(&self) {
        self.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}
