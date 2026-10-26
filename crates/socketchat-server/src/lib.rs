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
mod perms;
mod quota;
mod retention;
mod rules;
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

/// A one-line warning when `public_host` is not a name or an IP address,
/// which a server set up by an earlier release can hold: apps from 0.5.1
/// refuse the invite links it makes. The host is quoted with escapes, so
/// the line prints safely.
pub fn public_host_warning(cfg: &Config) -> Option<String> {
    (!socketchat_proto::valid_host(&cfg.public_host)).then(|| {
        format!(
            "Warning: public_host {:?} is not a name or an IP address, so Socketchat 0.5.1 apps refuse the invite links this server makes. Write a name in another script in its xn-- form.",
            cfg.public_host
        )
    })
}

/// Sets up a new server in `data_dir`: config file, certificate and an empty
/// database. Refuses to touch a directory that already has a certificate.
pub fn init(data_dir: &Path, public_host: &str) -> Result<InitReport, ServerError> {
    if !socketchat_proto::valid_host(public_host) {
        return Err(ServerError::Config(format!(
            "--host {public_host:?} is not a name or an IP address, so invite links cannot carry it. Use a name such as chat.example.com, an IP address, or a name in another script in its xn-- form."
        )));
    }
    perms::create_private_dir(data_dir)?;
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
    /// What connections not yet signed in may hold in partly received
    /// frames, over every connection.
    pub pre_sign_in: Arc<conn::Budget>,
    /// The server's stored bytes as last counted.
    pub stored: Mutex<quota::Stored>,
    /// Each room's admins and settings, as last read or merged.
    pub rules: rules::Rules,
    /// How fast each member has posted in each room.
    pub limiter: rules::Limiter,
    /// When the server started, for the pace limit's clock.
    started: std::time::Instant,
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

    /// Milliseconds since the server started, for the pace limit, plus
    /// any time a test moved the clock on. It never runs backwards when
    /// the system clock is set.
    pub fn now_ms(&self) -> u64 {
        let ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        ms + self.clock_offset.load(Ordering::Relaxed) * 1000
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
        // Folders and files from earlier releases, or made by hand, may be
        // open to other accounts on this machine.
        let tightened = perms::tighten(&cfg.data_dir);
        if !tightened.is_empty() {
            eprintln!(
                "socketchat-server: limited {} file(s) and folder(s) in {} to this account",
                tightened.len(),
                cfg.data_dir.display()
            );
        }
        let acceptor: TlsAcceptor = tls::acceptor(&cfg.data_dir)?;
        let cert_fpr = tls::fingerprint(&cfg.data_dir)?;
        let conn = db::open(&cfg.data_dir)?;
        let listener = TcpListener::bind(cfg.listen).await?;
        let addr = listener.local_addr()?;
        // 0 would refuse every connection's first large frame; it counts as 1.
        let cfg_budget = cfg
            .max_buffered_before_sign_in_mb
            .max(1)
            .saturating_mul(1_000_000);
        let state = Arc::new(State {
            cfg,
            db: Mutex::new(conn),
            clock_offset: AtomicU64::new(0),
            conns: AtomicUsize::new(0),
            online: Default::default(),
            per_ip: Default::default(),
            queued: Default::default(),
            refusals: Arc::new(tokio::sync::Semaphore::new(conn::MAX_REFUSALS)),
            pre_sign_in: Arc::new(conn::Budget::new(cfg_budget)),
            stored: Default::default(),
            rules: Default::default(),
            limiter: Default::default(),
            started: std::time::Instant::now(),
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
        // Buckets that hold no one back go every minute, off the post path.
        let pruner = state.clone();
        let mut prune_stop = stop_rx.clone();
        tokio::spawn(async move {
            let every_minute = rules::PRUNE_EVERY;
            let mut every =
                tokio::time::interval_at(tokio::time::Instant::now() + every_minute, every_minute);
            loop {
                tokio::select! {
                    _ = prune_stop.changed() => break,
                    _ = every.tick() => pruner.limiter.prune(pruner.now_ms()),
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

    /// Connections that hold a slot: from when the server accepts one until
    /// it has given back every slot the connection took. For tests.
    #[doc(hidden)]
    pub fn connections(&self) -> usize {
        self.state.per_ip.total()
    }

    /// Bytes waiting to be written, over every connection. For tests.
    #[doc(hidden)]
    pub fn queued_bytes(&self) -> usize {
        self.state.queued.bytes.load(Ordering::Relaxed)
    }

    /// Bytes that connections not yet signed in hold in partly received
    /// frames. For tests.
    #[doc(hidden)]
    pub fn held_before_sign_in(&self) -> usize {
        self.state.pre_sign_in.used()
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

    /// A server set up by an earlier release can hold a host that 0.5.1
    /// apps refuse in links; `server run` says so when it starts.
    #[test]
    fn a_host_links_cannot_carry_gets_a_warning() {
        let mut cfg = Config::default();
        assert_eq!(public_host_warning(&cfg), None);
        cfg.public_host = "pаypal.com".into();
        let w = public_host_warning(&cfg).unwrap();
        assert!(w.contains("xn--"), "{w}");
        assert!(!w.contains('\n'), "one line: {w}");
        cfg.public_host = "evil\u{1b}[2J".into();
        assert!(!public_host_warning(&cfg).unwrap().contains('\u{1b}'));
    }

    /// Apps refuse a link whose host is not a name or an address, so
    /// `init` refuses one before it writes anything.
    #[test]
    fn init_refuses_a_host_links_cannot_carry() {
        let tmp = tempfile::tempdir().unwrap();
        for bad in ["two words", "chat.example.com/x", "pаypal.com", ""] {
            let dir = tmp.path().join("srv");
            let e = init(&dir, bad).unwrap_err().to_string();
            assert!(e.contains("not a name or an IP address"), "{bad:?}: {e}");
            assert!(!dir.join(config::CONFIG_FILE).exists(), "{bad:?}");
        }
        init(&tmp.path().join("v6"), "::1").unwrap();
    }

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
