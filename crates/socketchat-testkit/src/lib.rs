//! Test helpers: a real server in a temporary directory on a free port.

use std::net::SocketAddr;

use socketchat_proto::InviteLink;
use socketchat_server::{init, make_server_invite, Config, Server, ServerHandle};

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
        init(dir.path(), "localhost").expect("init");
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
