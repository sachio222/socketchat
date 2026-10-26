//! Test helpers: a real server in a temporary directory on a free port, and
//! headless clients with their own temporary profiles.

use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};

use socketchat_core::client::{Client, Event};
use socketchat_core::keys::KeyPair;
use socketchat_proto::InviteLink;
use socketchat_server::{init, make_server_invite, Config, Server, ServerHandle};

pub type Db = rusqlite::Connection;

/// The passphrase for every temporary test profile: 16 random bytes in hex,
/// made once per test run so a reopened profile gets the same one.
pub fn passphrase() -> &'static str {
    static PASS: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PASS.get_or_init(|| {
        let mut bytes = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    })
}

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

    /// Stops the server and starts a new one on the same port with fresh
    /// data and a new certificate, as an operator who set it up again would.
    pub async fn replace_with_fresh(self) -> TestServer {
        let addr = self.addr();
        self.handle.shutdown();
        drop(self);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        for _ in 0..50 {
            let dir = tempfile::tempdir().expect("temp dir");
            init(dir.path(), "127.0.0.1").expect("init");
            let mut cfg = Config::load(dir.path()).expect("config");
            cfg.listen = addr;
            match Server::start(cfg.clone()).await {
                Ok(handle) => {
                    cfg.save().expect("save config");
                    return TestServer { dir, handle, cfg };
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
            }
        }
        panic!("no new server on the old port");
    }

    /// Stops the server and starts it again on the same port and data,
    /// with its config changed by `f`, as an operator who edits the file
    /// and restarts would.
    pub async fn restart_with(&mut self, f: impl FnOnce(&mut Config)) {
        f(&mut self.cfg);
        self.cfg.save().expect("save config");
        self.restart().await;
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

/// Appends `mls` to a room's log on the server, as an operator who
/// writes to the database directly could. Returns its sequence number.
pub fn append_to_log(s: &TestServer, group: socketchat_proto::msg::GroupId, mls: &[u8]) -> u64 {
    let db = open_server_db(s);
    let seq: i64 = db
        .query_row(
            "SELECT next_seq FROM groups WHERE id = ?1",
            [group.0.as_slice()],
            |r| r.get(0),
        )
        .expect("room on the server");
    db.execute(
        "INSERT INTO log (group_id, seq, mls, created_unix) VALUES (?1, ?2, ?3, 0)",
        rusqlite::params![group.0.as_slice(), seq, mls],
    )
    .expect("log row");
    db.execute(
        "UPDATE groups SET next_seq = next_seq + 1 WHERE id = ?1",
        [group.0.as_slice()],
    )
    .expect("next seq");
    seq as u64
}

/// An MLS external commit that adds a new leaf to the room described by
/// `group_info` and `ratchet_tree`, for tests of changes from outside a
/// room.
pub fn outside_commit(group_info: &[u8], ratchet_tree: &[u8]) -> Vec<u8> {
    use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
    use openmls::prelude::{
        LeafNodeParameters, MlsGroup, MlsMessageBodyIn, MlsMessageIn, RatchetTreeIn,
    };
    use openmls_traits::OpenMlsProvider as _;
    use socketchat_core::suite::{capabilities, group_join_config};

    let MlsMessageBodyIn::GroupInfo(gi) = MlsMessageIn::tls_deserialize_exact(group_info)
        .expect("group info")
        .extract()
    else {
        panic!("not a GroupInfo")
    };
    let tree = RatchetTreeIn::tls_deserialize_exact(ratchet_tree).expect("ratchet tree");
    let prov = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let key = KeyPair::generate();
    let (_, bundle) = MlsGroup::external_commit_builder()
        .with_ratchet_tree(tree)
        .with_config(group_join_config())
        .build_group(&prov, gi, key.credential())
        .expect("external commit group")
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(capabilities())
                .build(),
        )
        .load_psks(prov.storage())
        .expect("psks")
        .build(prov.rand(), prov.crypto(), &key, |_| true)
        .expect("external commit")
        .finalize(&prov)
        .expect("finalize");
    bundle.commit().tls_serialize_detached().expect("encode")
}

/// A Welcome for the owner of the KeyPackages in `blob` that does not lead
/// into the room `group`.
pub fn welcome_into_copy(group: socketchat_proto::msg::GroupId, blob: &[u8]) -> Vec<u8> {
    use openmls::prelude::tls_codec::Serialize as _;
    use openmls::prelude::MlsGroup;
    use socketchat_core::suite::{group_create_config, SUITE};

    let prov = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let key = KeyPair::generate();
    let mut copy = MlsGroup::new_with_group_id(
        &prov,
        &key,
        &group_create_config(SUITE, &[key.public()]),
        openmls::group::GroupId::from_slice(&group.0),
        key.credential(),
    )
    .expect("group");
    let kp = socketchat_core::invite::pick_key_package(&prov, blob, SUITE).expect("KeyPackage");
    let (_, welcome, _) = copy.add_members(&prov, &key, &[kp]).expect("add");
    welcome.tls_serialize_detached().expect("encode")
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
        let client = Client::create_profile(dir.path(), passphrase(), name)
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
        let client = Client::open(dir.path(), passphrase())
            .await
            .expect("reopen");
        TestClient { client, dir }
    }
}

/// A profile on disk whose client is closed.
pub struct ClosedClient {
    dir: tempfile::TempDir,
}

impl ClosedClient {
    pub async fn open(self) -> TestClient {
        let client = Client::open(self.dir.path(), passphrase())
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

/// A TCP relay that reads the client's bytes slowly into a small socket
/// buffer, as a busy link to a server would: `chunk` bytes at a time, with
/// `pause` between reads. The client's socket fills while it writes a large
/// request. Replies pass through at full speed.
pub struct SlowProxy {
    pub port: u16,
}

impl SlowProxy {
    pub async fn start(
        target: SocketAddr,
        rcvbuf: u32,
        chunk: usize,
        pause: std::time::Duration,
    ) -> SlowProxy {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let sock = tokio::net::TcpSocket::new_v4().unwrap();
        // Accepted sockets take their receive buffer from the listener.
        sock.set_recv_buffer_size(rcvbuf).unwrap();
        sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = sock.listen(16).unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let Ok(server) = tokio::net::TcpStream::connect(target).await else {
                    continue;
                };
                let (mut cr, mut cw) = client.into_split();
                let (mut sr, mut sw) = server.into_split();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; chunk];
                    loop {
                        tokio::time::sleep(pause).await;
                        let n = match cr.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if sw.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    let _ = sw.shutdown().await;
                });
                tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut sr, &mut cw).await;
                    let _ = cw.shutdown().await;
                });
            }
        });
        SlowProxy { port }
    }
}

#[cfg(test)]
mod tests {
    use super::passphrase;

    #[test]
    fn passphrase_is_random_hex_made_once_per_run() {
        let p = passphrase();
        assert_eq!(p.len(), 32, "{p}");
        assert!(p.chars().all(|c| c.is_ascii_hexdigit()), "{p}");
        assert_eq!(p, passphrase(), "a reopened profile needs the same one");
    }
}
