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
mod retention;
pub mod tls;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection};
use socketchat_proto::msg::Busy;
use socketchat_proto::{InviteLink, Token};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

pub use config::Config;
pub use conn::QUEUE_BYTES;

/// The acceptable-use statement, printed when a server is first set up.
pub const ACCEPTABLE_USE: &str = include_str!("../../../ACCEPTABLE_USE.md");

/// The acceptable-use statement as plain terminal text, without Markdown
/// heading marks or backticks.
pub fn acceptable_use_text() -> String {
    let mut out = String::new();
    for line in ACCEPTABLE_USE.lines() {
        let heading = line.trim_start_matches('#');
        let line = if heading.len() < line.len() {
            heading.trim_start()
        } else {
            line
        };
        out.push_str(&line.replace('`', ""));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod acceptable_use_tests {
    use super::*;

    #[test]
    fn acceptable_use_text_has_no_markdown_marks() {
        let text = acceptable_use_text();
        assert!(text.contains("Acceptable use"), "{text}");
        assert!(!text.contains('`'), "{text}");
        for line in text.lines() {
            assert!(!line.starts_with('#'), "heading mark left in: {line}");
        }
        assert!(text.contains("CODE_OF_CONDUCT.md"), "{text}");
    }

    #[test]
    fn acceptable_use_text_keeps_every_bullet() {
        let text = acceptable_use_text();
        let bullets: Vec<&str> = ACCEPTABLE_USE
            .lines()
            .filter(|l| l.starts_with("- "))
            .collect();
        assert!(!bullets.is_empty());
        for b in bullets {
            assert!(text.lines().any(|l| l == b), "bullet missing: {b}");
        }
    }
}

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
    // An absolute path as given, not resolved through links: canonicalize
    // would give \\?\C:\... on Windows, which then shows up in the config.
    let data_dir = std::path::absolute(data_dir)?;
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
    pub per_ip: conn::PerIp,
    /// Replies and pushes waiting to be written, over every connection.
    pub queued: Arc<conn::Queued>,
    /// Room for connections being turned away with a reply.
    pub refusals: Arc<tokio::sync::Semaphore>,
}

/// Locks `m` even when a thread panicked while holding it. Requests that
/// change several rows run in a transaction, which a panic rolls back, so
/// what the lock guards stays whole.
pub(crate) fn relock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl State {
    /// The database, locked.
    pub fn db(&self) -> MutexGuard<'_, Connection> {
        relock(&self.db)
    }

    pub fn now(&self) -> u64 {
        system_now() + self.clock_offset.load(Ordering::Relaxed)
    }

    /// Today, as the Unix time of its first second. Account and mailbox
    /// records store this instead of the exact second, so an account and a
    /// mailbox made by one group invite cannot be paired by their times.
    pub fn today(&self) -> u64 {
        start_of_day(self.now())
    }
}

/// `t` rounded down to a whole day.
pub fn start_of_day(t: u64) -> u64 {
    t - t % DAY_SECS
}

pub const DAY_SECS: u64 = 24 * 3600;

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
            per_ip: Default::default(),
            queued: Default::default(),
            refusals: Arc::new(tokio::sync::Semaphore::new(conn::MAX_REFUSALS)),
        });
        let (stop, stop_rx) = watch::channel(false);
        let sweeper = state.clone();
        let mut sweep_stop = stop_rx.clone();
        tokio::spawn(async move {
            let hour = std::time::Duration::from_secs(3600);
            let mut every = tokio::time::interval_at(tokio::time::Instant::now() + hour, hour);
            loop {
                tokio::select! {
                    _ = sweep_stop.changed() => break,
                    _ = every.tick() => retention::sweep(&sweeper),
                }
            }
        });
        let st = state.clone();
        tokio::spawn(async move {
            let mut stop_rx2 = stop_rx.clone();
            loop {
                tokio::select! {
                    _ = stop_rx2.changed() => break,
                    acc = listener.accept() => {
                        let Ok((tcp, peer)) = acc else { continue };
                        let _ = tcp.set_nodelay(true);
                        // An address over its share hears why and is closed,
                        // or is dropped before TLS when too many are being
                        // turned away at once.
                        let Some(slot) = conn::PerIp::take(&st, peer.ip(), st.cfg.max_per_ip) else {
                            if let Ok(permit) = st.refusals.clone().try_acquire_owned() {
                                tokio::spawn(conn::refuse(acceptor.clone(), tcp, Busy::Network, permit));
                            }
                            continue;
                        };
                        tokio::spawn(conn::serve(st.clone(), acceptor.clone(), tcp, stop_rx.clone(), slot));
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

    /// Runs the hourly cleanup now: expired messages, files, invites and
    /// join requests go.
    pub fn sweep_now(&self) {
        retention::sweep(&self.state);
    }

    /// Stops accepting and closes every connection.
    pub fn shutdown(&self) {
        let _ = self.stop.send(true);
    }

    pub fn config(&self) -> &Config {
        &self.state.cfg
    }

    /// Frames waiting to be written, over every connection. For tests.
    #[doc(hidden)]
    pub fn queued_frames(&self) -> usize {
        self.state.queued.frames.load(Ordering::Relaxed)
    }

    /// Bytes waiting to be written, over every connection. For tests.
    #[doc(hidden)]
    pub fn queued_bytes(&self) -> usize {
        self.state.queued.bytes.load(Ordering::Relaxed)
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod lock_tests {
    use super::*;

    #[test]
    fn relock_recovers_from_a_panic() {
        let m = Arc::new(Mutex::new(1));
        let m2 = m.clone();
        let _ = std::thread::spawn(move || {
            let _g = m2.lock().unwrap();
            panic!("boom");
        })
        .join();
        assert!(m.is_poisoned());
        *relock(&m) += 1;
        assert_eq!(*relock(&m), 2);
    }
}

#[cfg(test)]
mod init_tests {
    use super::*;

    #[test]
    fn init_stores_a_plain_absolute_path() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("srv");
        init(&dir, "127.0.0.1").unwrap();
        let cfg = Config::load(&dir).unwrap();
        assert!(cfg.data_dir.is_absolute(), "{}", cfg.data_dir.display());
        // canonicalize gives \\?\C:\... on Windows, which leaks into the
        // config and into what `init` prints.
        let shown = cfg.data_dir.display().to_string();
        assert!(!shown.starts_with(r"\\?\"), "{shown}");
        assert_eq!(cfg.data_dir, std::path::absolute(&dir).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn init_keeps_a_linked_folder_as_given() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("real")).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(tmp.path().join("real"), &link).unwrap();
        let report = init(&link.join("srv"), "127.0.0.1").unwrap();
        assert_eq!(
            report.config_path,
            link.join("srv").join(config::CONFIG_FILE)
        );
        let cfg = Config::load(&link.join("srv")).unwrap();
        assert_eq!(cfg.data_dir, link.join("srv"));
    }
}
