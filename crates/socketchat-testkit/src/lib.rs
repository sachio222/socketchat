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

    /// Closes this client and opens its profile again from disk.
    pub async fn reopen(self) -> TestClient {
        let TestClient { client, dir } = self;
        drop(client);
        let client = Client::open(dir.path(), PASSPHRASE).await.expect("reopen");
        TestClient { client, dir }
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
