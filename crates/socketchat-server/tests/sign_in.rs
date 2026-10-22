//! Connections that do not sign in: they get a fixed time to do so, whatever
//! they send, while honest apps sign in well inside it, on a slow link and
//! many at once from one address.

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use common::*;
use socketchat_core::keys::KeyPair;
use socketchat_core::net::Conn;
use socketchat_proto::msg::{to_frame, ClientFrame, Request, Response, ServerFrame};
use socketchat_server::config::SIGN_IN_LIMIT;
use socketchat_server::{init, make_server_invite, Config, Server, ServerHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Env {
    d: tempfile::TempDir,
    h: ServerHandle,
}

async fn env_with(f: impl FnOnce(&mut Config)) -> Env {
    let d = tempfile::tempdir().unwrap();
    init(d.path(), "localhost").unwrap();
    let mut cfg = Config::load(d.path()).unwrap();
    cfg.listen = "127.0.0.1:0".parse().unwrap();
    f(&mut cfg);
    let h = Server::start(cfg).await.unwrap();
    Env { d, h }
}

impl Env {
    async fn raw(&self) -> Raw {
        let mut c = Raw::connect(self.h.addr, self.h.cert_fpr).await;
        c.hello().await;
        c
    }

    /// A new account's key, registered on its own connection.
    async fn account(&self) -> KeyPair {
        let key = KeyPair::generate();
        let token = make_server_invite(self.d.path()).unwrap().token;
        let mut c = self.raw().await;
        let ch = c.challenge().await;
        let r = c
            .req(Request::RegisterAccount {
                token,
                key: key.public(),
                sig: auth_sig(&key, &ch),
            })
            .await;
        assert_eq!(r, Response::Ok);
        key
    }
}

/// Sends a Challenge without waiting for its answer. False once the
/// server has closed the connection.
async fn ask_challenge(c: &mut Raw, id: u32) -> bool {
    let f = to_frame(&ClientFrame::Req {
        id,
        body: Request::Challenge,
    })
    .unwrap();
    c.send_raw(&f).await.is_ok()
}

/// Keeps asking for challenges without signing in, until the server
/// closes the connection. Returns how long that took, or None if it
/// was still open after `give_up`.
async fn squat(c: &mut Raw, every: Duration, give_up: Duration) -> Option<Duration> {
    let started = Instant::now();
    let mut id = 1;
    while started.elapsed() < give_up {
        if !ask_challenge(c, id).await {
            return Some(started.elapsed());
        }
        id += 1;
        match c.recv().await {
            Some(ServerFrame::Resp { .. }) => {}
            None => return Some(started.elapsed()),
            other => panic!("unexpected {other:?}"),
        }
        tokio::time::sleep(every).await;
    }
    None
}

// ---------- the window ----------

/// Requests before sign-in do not keep a connection open: a Challenge
/// every 200 ms, well inside the idle limit, still ends at the sign-in
/// window.
#[tokio::test]
async fn connection_that_never_signs_in_is_closed() {
    let e = env_with(|c| {
        c.timing.sign_in = Duration::from_secs(1);
        c.timing.idle = Duration::from_secs(10);
    })
    .await;
    let connected = Instant::now();
    let mut c = e.raw().await;
    let closed = squat(&mut c, Duration::from_millis(200), Duration::from_secs(6)).await;
    let after = connected.elapsed();
    assert!(
        closed.is_some(),
        "a connection that never signed in was still open after {after:?}"
    );
    assert!(
        after >= Duration::from_millis(900),
        "closed after {after:?}, before its 1 s window"
    );
}

/// Connections that never sign in cannot keep every slot: once their
/// window ends, a real app gets in.
#[tokio::test]
async fn unsigned_connections_do_not_hold_every_slot() {
    let e = env_with(|c| {
        c.max_connections = 3;
        c.timing.idle = Duration::from_secs(2);
        c.timing.sign_in = Duration::from_millis(1500);
    })
    .await;
    let mut squatters = Vec::new();
    for _ in 0..3 {
        squatters.push(e.raw().await);
    }
    for round in 0..3u32 {
        tokio::time::sleep(Duration::from_millis(1000)).await;
        for s in &mut squatters {
            if ask_challenge(s, round + 1).await {
                let _ = s.recv().await;
            }
        }
    }
    let mut c = Raw::connect(e.h.addr, e.h.cert_fpr).await;
    let r = c.hello_as(socketchat_proto::PROTOCOL_VERSION).await;
    assert!(
        matches!(r, Some(ServerFrame::HelloOk { .. })),
        "a real app is locked out by connections that never signed in: {r:?}"
    );
}

/// Signing in, by proving a key or registering one, lifts the window: the
/// connection then lives by the idle limit alone.
#[tokio::test]
async fn signed_in_connections_outlive_the_window() {
    let e = env_with(|c| {
        c.timing.sign_in = Duration::from_millis(500);
        c.timing.idle = Duration::from_secs(10);
    })
    .await;
    // Proving a key the server knows.
    let key = e.account().await;
    let mut proved = e.raw().await;
    let ch = proved.challenge().await;
    let r = proved
        .req(Request::Prove {
            key: key.public(),
            sig: auth_sig(&key, &ch),
        })
        .await;
    assert_eq!(r, Response::Ok);
    // Registering a new account.
    let token = make_server_invite(e.d.path()).unwrap().token;
    let fresh = KeyPair::generate();
    let mut registered = e.raw().await;
    let ch = registered.challenge().await;
    let r = registered
        .req(Request::RegisterAccount {
            token,
            key: fresh.public(),
            sig: auth_sig(&fresh, &ch),
        })
        .await;
    assert_eq!(r, Response::Ok);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    proved.challenge().await;
    registered.challenge().await;
}

/// A frame larger than any request an app sends before signing in closes
/// the connection; the requests apps do send before signing in pass.
#[tokio::test]
async fn large_frame_before_sign_in_closes_the_connection() {
    let e = env_with(|_| {}).await;
    let mut c = e.raw().await;
    // The largest request an app sends before it signs in: asking about
    // 100 server links.
    let tokens = vec![socketchat_proto::Token([7; 16]); 100];
    let r = c
        .req(Request::ListInvites {
            server_tokens: tokens,
        })
        .await;
    assert!(matches!(r, Response::Invites(_)), "{r:?}");
    let big = to_frame(&ClientFrame::Req {
        id: 99,
        body: Request::ListInvites {
            server_tokens: vec![socketchat_proto::Token([7; 16]); 1000],
        },
    })
    .unwrap();
    let _ = c.send_raw(&big).await;
    assert_eq!(c.recv().await, None);
}

// ---------- honest apps ----------

/// Passes bytes both ways between an app and the server, holding each
/// piece for `one_way` first, as a slow mobile link would.
async fn slow_link(server: SocketAddr, one_way: Duration) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((app, _)) = l.accept().await {
            let up = TcpStream::connect(server).await.unwrap();
            let (ar, aw) = app.into_split();
            let (ur, uw) = up.into_split();
            tokio::spawn(delay_pipe(ar, uw, one_way));
            tokio::spawn(delay_pipe(ur, aw, one_way));
        }
    });
    addr
}

async fn delay_pipe(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    one_way: Duration,
) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
    tokio::spawn(async move {
        while let Some((due, bytes)) = rx.recv().await {
            tokio::time::sleep_until(due.into()).await;
            if to.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = to.shutdown().await;
    });
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match from.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if tx
                    .send((Instant::now() + one_way, buf[..n].to_vec()))
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

/// Connects with the app's own code and signs in with `key`, registering
/// it under `token` when one is given. Returns how long that took.
async fn app_sign_in(
    addr: SocketAddr,
    fpr: [u8; 32],
    protocol: u16,
    key: &KeyPair,
    token: Option<socketchat_proto::Token>,
) -> Duration {
    let started = Instant::now();
    let c = Conn::connect_upto("127.0.0.1", addr.port(), fpr, protocol)
        .await
        .unwrap();
    match token {
        Some(t) => c.register_account(t, key).await.unwrap(),
        None => c.prove(key).await.unwrap(),
    }
    started.elapsed()
}

/// An app on a slow mobile link, 300 ms each way, signs in far inside the
/// window: TCP, TLS, Hello, a challenge and its proof.
#[tokio::test]
async fn honest_sign_in_on_a_slow_link_fits_the_window() {
    let e = env_with(|_| {}).await;
    let fast = app_sign_in(
        e.h.addr,
        e.h.cert_fpr,
        socketchat_proto::PROTOCOL_VERSION,
        &KeyPair::generate(),
        Some(make_server_invite(e.d.path()).unwrap().token),
    )
    .await;
    let slow_addr = slow_link(e.h.addr, Duration::from_millis(300)).await;
    let key = KeyPair::generate();
    let register = app_sign_in(
        slow_addr,
        e.h.cert_fpr,
        socketchat_proto::PROTOCOL_VERSION,
        &key,
        Some(make_server_invite(e.d.path()).unwrap().token),
    )
    .await;
    let prove = app_sign_in(
        slow_addr,
        e.h.cert_fpr,
        socketchat_proto::PROTOCOL_VERSION,
        &key,
        None,
    )
    .await;
    // Protocol 1, as a 0.4.0 app speaks it.
    let old = app_sign_in(slow_addr, e.h.cert_fpr, 1, &key, None).await;
    eprintln!(
        "sign-in: {fast:?} direct; over 600 ms round trips: register {register:?}, prove {prove:?}, protocol 1 {old:?}"
    );
    for t in [register, prove, old] {
        assert!(
            t * 10 <= SIGN_IN_LIMIT,
            "a slow-link sign-in took {t:?}, more than a tenth of the {SIGN_IN_LIMIT:?} window"
        );
    }
}

/// A family or an office behind one address: many apps connect and sign in
/// at the same moment, as after the server restarts, and every one gets in
/// under the default settings.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_apps_from_one_address_sign_in_at_once() {
    const APPS: usize = 100;
    let e = env_with(|_| {}).await;
    let mut keys = Vec::new();
    for _ in 0..APPS {
        keys.push(e.account().await);
    }
    let started = Instant::now();
    let mut tasks = Vec::new();
    for (i, key) in keys.into_iter().enumerate() {
        let (addr, fpr) = (e.h.addr, e.h.cert_fpr);
        // Every other app speaks protocol 1, as 0.4.0 does.
        let protocol = if i % 2 == 0 {
            socketchat_proto::PROTOCOL_VERSION
        } else {
            1
        };
        tasks.push(tokio::spawn(async move {
            app_sign_in(addr, fpr, protocol, &key, None).await
        }));
    }
    let mut slowest = Duration::ZERO;
    for t in tasks {
        slowest = slowest.max(t.await.unwrap());
    }
    eprintln!(
        "{APPS} apps from one address signed in together in {:?}; the slowest took {slowest:?}",
        started.elapsed()
    );
    assert!(slowest * 10 <= SIGN_IN_LIMIT, "slowest sign-in {slowest:?}");
}

// ---------- limits that must not lock honest apps out ----------

/// Announces a frame of `len` bytes and sends all of it but the last byte.
/// Stops quietly once the server closes the connection.
async fn half_send(c: &mut Raw, len: usize) {
    if c.send_raw(&(len as u32).to_be_bytes()).await.is_err() {
        return;
    }
    let piece = vec![0u8; 16 * 1024];
    let mut left = len - 1;
    while left > 0 {
        let n = left.min(piece.len());
        if c.send_raw(&piece[..n]).await.is_err() {
            return;
        }
        left -= n;
    }
}

/// Signs in a new account with the app's own code, directly.
async fn honest_app(e: &Env) -> Result<(), socketchat_core::net::NetError> {
    let c = Conn::connect("127.0.0.1", e.h.addr.port(), e.h.cert_fpr).await?;
    let token = make_server_invite(e.d.path()).unwrap().token;
    c.register_account(token, &KeyPair::generate()).await?;
    let r = c.request(Request::CreateInvite { group: None }).await?;
    assert!(matches!(r, Response::Invite { .. }), "{r:?}");
    Ok(())
}

/// Waits until the server counts at least `n` bytes before sign-in.
async fn counted_at_least(e: &Env, n: usize) -> usize {
    let started = Instant::now();
    loop {
        let c = e.h.held_before_sign_in();
        if c >= n || started.elapsed() > Duration::from_secs(5) {
            return c;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// While large half-sent frames fill the shared budget, an app still says
/// Hello and signs in: the small frames that sign in always fit.
#[tokio::test]
async fn honest_app_signs_in_while_the_budget_is_full() {
    let e = env_with(|c| {
        c.max_frame_before_sign_in = socketchat_proto::MAX_FRAME;
        c.max_buffered_before_sign_in_mb = 1;
    })
    .await;
    let mut fillers = Vec::new();
    for size in [600_000 - 4, 400_000 - 4] {
        let mut c = e.raw().await;
        half_send(&mut c, size).await;
        fillers.push(c);
    }
    let counted = counted_at_least(&e, 990_000).await;
    assert!(counted >= 990_000, "budget not filled: {counted} bytes");
    honest_app(&e)
        .await
        .expect("an app could not sign in while the budget was full");
}

/// A budget of 0 in the config counts as 1 MB, so it never blocks every
/// sign-in.
#[tokio::test]
async fn zero_budget_counts_as_one_megabyte() {
    let e = env_with(|c| {
        c.max_frame_before_sign_in = socketchat_proto::MAX_FRAME;
        c.max_buffered_before_sign_in_mb = 0;
    })
    .await;
    honest_app(&e).await.expect("sign-in with a budget of 0");
    let mut c = e.raw().await;
    half_send(&mut c, 500_000).await;
    let counted = counted_at_least(&e, 400_000).await;
    assert!(counted >= 400_000, "{counted} bytes counted");
}

/// `max_frame_before_sign_in` under 1,024 counts as 1,024, so sign-in
/// requests always fit; over 1 MiB it counts as 1 MiB.
#[tokio::test]
async fn frame_limit_setting_is_clamped() {
    let low = env_with(|c| c.max_frame_before_sign_in = 0).await;
    honest_app(&low)
        .await
        .expect("sign-in with a frame limit of 0");
    // A request of about 1,000 bytes before sign-in is still answered.
    let mut c = low.raw().await;
    let r = c
        .req(Request::ListInvites {
            server_tokens: vec![socketchat_proto::Token([7; 16]); 60],
        })
        .await;
    assert!(matches!(r, Response::Invites(_)), "{r:?}");

    let high = env_with(|c| c.max_frame_before_sign_in = 4 * socketchat_proto::MAX_FRAME).await;
    // A frame of 1 MiB may be sent before sign-in...
    let mut c = high.raw().await;
    half_send(&mut c, socketchat_proto::MAX_FRAME).await;
    let counted = counted_at_least(&high, socketchat_proto::MAX_FRAME / 2).await;
    assert!(counted >= socketchat_proto::MAX_FRAME / 2, "{counted}");
    // ...and a larger one closes the connection.
    let mut c = high.raw().await;
    let _ = c
        .send_raw(&((socketchat_proto::MAX_FRAME as u32) + 1).to_be_bytes())
        .await;
    let _ = c.send_raw(&[0u8; 1024]).await;
    assert_eq!(c.recv().await, None);
}

/// Requests sent as fast as the server answers them do not stretch the
/// window: the connection closes when it ends. The last reply may arrive
/// up to a second after the 500 ms window, which leaves room for a slow
/// test machine; a server that let the stream keep it open would answer
/// for the whole 10 seconds.
#[tokio::test]
async fn window_is_exact_under_a_stream_of_requests() {
    let e = env_with(|c| {
        c.timing.sign_in = Duration::from_millis(500);
        c.timing.idle = Duration::from_secs(10);
    })
    .await;
    let connected = Instant::now();
    let mut c = e.raw().await;
    let batch: Vec<u8> = (0..20u32)
        .flat_map(|id| {
            to_frame(&ClientFrame::Req {
                id,
                body: Request::Challenge,
            })
            .unwrap()
        })
        .collect();
    let mut last_reply = None;
    'flood: while connected.elapsed() < Duration::from_secs(10) {
        if c.send_raw(&batch).await.is_err() {
            break;
        }
        for _ in 0..20 {
            match c.recv().await {
                Some(_) => last_reply = Some(connected.elapsed()),
                None => break 'flood,
            }
        }
    }
    let closed = connected.elapsed();
    assert!(
        closed < Duration::from_secs(10),
        "still open after {closed:?}"
    );
    let last = last_reply.unwrap_or_default();
    assert!(
        last <= Duration::from_millis(1500),
        "a reply came {last:?} after connecting, past the 500 ms window"
    );
}
