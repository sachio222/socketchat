//! The socketchat relay server.
//!
//! It stores and forwards encrypted MLS messages and file chunks. It checks
//! signed group changes against each group's admin list, and it never holds
//! a key that can read a message.

mod auth;
pub mod config;
mod conn;
pub mod db;
mod files;
mod groups;
mod invites;
pub mod tls;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection};
use socketchat_proto::{InviteLink, Token};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

pub use config::Config;

/// The acceptable-use statement, printed when a server is first set up.
pub const ACCEPTABLE_USE: &str = include_str!("../../../ACCEPTABLE_USE.md");

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("config: {0}")]
    Config(String),
    #[error("TLS: {0}")]
    Tls(String),
    #[error("database: {0}")]
    Db(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

impl From<rusqlite::Error> for ServerError {
    fn from(e: rusqlite::Error) -> Self {
        ServerError::Db(e.to_string())
    }
}

/// What `init` made.
#[derive(Debug)]
pub struct InitReport {
    pub config_path: PathBuf,
    pub cert_fpr: [u8; 32],
}

/// Sets up a new server in `data_dir`: config file, certificate and an empty
/// database. Refuses to touch a directory that already has a certificate.
pub fn init(data_dir: &Path, public_host: &str) -> Result<InitReport, ServerError> {
    std::fs::create_dir_all(data_dir)?;
    let data_dir = data_dir.canonicalize()?;
    let cert_fpr = tls::create(&data_dir, public_host)?;
    let cfg = Config {
        public_host: public_host.to_string(),
        data_dir: data_dir.clone(),
        ..Config::default()
    };
    cfg.save()?;
    db::open(&data_dir)?;
    Ok(InitReport {
        config_path: data_dir.join(config::CONFIG_FILE),
        cert_fpr,
    })
}

pub(crate) fn random_token() -> Token {
    let mut t = [0u8; 16];
    OsRng.fill_bytes(&mut t);
    Token(t)
}

pub(crate) fn system_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Makes a one-time link that registers a new person on this server. Works
/// while the server is running, since SQLite in WAL mode allows it.
pub fn make_server_invite(data_dir: &Path) -> Result<InviteLink, ServerError> {
    let cfg = Config::load(data_dir)?;
    let conn = db::open(&cfg.data_dir)?;
    let token = random_token();
    conn.execute(
        "INSERT INTO invites (token, group_id, expires_unix, uses_left) VALUES (?1, NULL, ?2, 1)",
        params![
            token.0.as_slice(),
            (system_now() + cfg.invite_ttl_hours as u64 * 3600) as i64
        ],
    )?;
    Ok(InviteLink {
        host: cfg.public_host.clone(),
        port: cfg.listen.port(),
        token,
        cert_fpr: tls::fingerprint(&cfg.data_dir)?,
        inviter_fpr: None,
        secret: None,
    })
}

pub(crate) struct State {
    pub cfg: Config,
    pub db: Mutex<Connection>,
    clock_offset: AtomicU64,
    pub conns: AtomicUsize,
    pub online: conn::Online,
}

impl State {
    pub fn now(&self) -> u64 {
        system_now() + self.clock_offset.load(Ordering::Relaxed)
    }
}

pub struct Server;

/// A running server.
pub struct ServerHandle {
    pub addr: SocketAddr,
    pub cert_fpr: [u8; 32],
    state: Arc<State>,
    stop: watch::Sender<bool>,
}

impl Server {
    /// Binds the listener and starts serving in the background.
    pub async fn start(cfg: Config) -> Result<ServerHandle, ServerError> {
        let acceptor: TlsAcceptor = tls::acceptor(&cfg.data_dir)?;
        let cert_fpr = tls::fingerprint(&cfg.data_dir)?;
        let conn = db::open(&cfg.data_dir)?;
        let listener = TcpListener::bind(cfg.listen).await?;
        let addr = listener.local_addr()?;
        let state = Arc::new(State {
            cfg,
            db: Mutex::new(conn),
            clock_offset: AtomicU64::new(0),
            conns: AtomicUsize::new(0),
            online: Default::default(),
        });
        let (stop, stop_rx) = watch::channel(false);
        let st = state.clone();
        tokio::spawn(async move {
            let mut stop_rx2 = stop_rx.clone();
            loop {
                tokio::select! {
                    _ = stop_rx2.changed() => break,
                    acc = listener.accept() => {
                        let Ok((tcp, _)) = acc else { continue };
                        let _ = tcp.set_nodelay(true);
                        tokio::spawn(conn::serve(st.clone(), acceptor.clone(), tcp, stop_rx.clone()));
                    }
                }
            }
        });
        Ok(ServerHandle {
            addr,
            cert_fpr,
            state,
            stop,
        })
    }
}

impl ServerHandle {
    /// Moves the server's clock forward, for tests of expiry and retention.
    pub fn advance_clock(&self, secs: u64) {
        self.state.clock_offset.fetch_add(secs, Ordering::Relaxed);
    }

    /// Stops accepting and closes every connection.
    pub fn shutdown(&self) {
        let _ = self.stop.send(true);
    }

    pub fn config(&self) -> &Config {
        &self.state.cfg
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}
