//! Memory held for connections that have not signed in, measured with a
//! counting allocator. The count covers this whole test process, the test
//! clients included, so the tests here run one at a time.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Duration;

use common::*;
use socketchat_proto::MAX_FRAME;
use socketchat_server::{init, Config, Server, ServerHandle};

struct Counting;
static LIVE: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size() as isize, Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        LIVE.fetch_add(n as isize - l.size() as isize, Ordering::Relaxed);
        System.realloc(p, l, n)
    }
}

#[global_allocator]
static A: Counting = Counting;

/// One test at a time, so one test's connections do not show in another's
/// count.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Connections each test opens.
const N: usize = 40;

const KIB: usize = 1024;

async fn start(f: impl FnOnce(&mut Config)) -> (tempfile::TempDir, ServerHandle) {
    let d = tempfile::tempdir().unwrap();
    init(d.path(), "localhost").unwrap();
    let mut cfg = Config::load(d.path()).unwrap();
    cfg.listen = "127.0.0.1:0".parse().unwrap();
    // The global cap is tiny; it must not matter for what a connection
    // may hold before it signs in.
    cfg.max_connections = 4;
    f(&mut cfg);
    let h = Server::start(cfg).await.unwrap();
    (d, h)
}

/// Announces a frame of `len` bytes and sends all of it but the last byte.
/// Stops quietly once the server closes the connection.
async fn half_send(c: &mut Raw, len: usize) {
    if c.send_raw(&(len as u32).to_be_bytes()).await.is_err() {
        return;
    }
    let piece = vec![0u8; 16 * KIB];
    let mut left = len - 1;
    while left > 0 {
        let n = left.min(piece.len());
        if c.send_raw(&piece[..n]).await.is_err() {
            return;
        }
        left -= n;
    }
}

/// Bytes allocated now, after giving tasks a moment to settle.
async fn live_after(wait: Duration) -> isize {
    tokio::time::sleep(wait).await;
    LIVE.load(Ordering::Relaxed)
}

fn mib(b: isize) -> f64 {
    b as f64 / (1024.0 * 1024.0)
}

/// A connection that has not said Hello may send only a Hello, so it
/// holds next to nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn half_sent_frames_before_hello_hold_little() {
    let _one = SERIAL.lock().await;
    let (_d, h) = start(|_| {}).await;
    let mut conns = Vec::new();
    for _ in 0..N {
        conns.push(Raw::connect(h.addr, h.cert_fpr).await);
    }
    let before = live_after(Duration::from_millis(300)).await;
    for c in &mut conns {
        half_send(c, MAX_FRAME).await;
    }
    let held = live_after(Duration::from_millis(1500)).await - before;
    eprintln!(
        "{N} connections before Hello, each half-sending a 1 MiB frame: {:.2} MiB held",
        mib(held)
    );
    assert!(
        held < (N * 64 * KIB) as isize,
        "{N} connections that never said Hello hold {:.1} MiB",
        mib(held)
    );
}

/// After Hello and until it signs in, a connection may send only small
/// frames.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn half_sent_frames_before_sign_in_hold_little() {
    let _one = SERIAL.lock().await;
    let (_d, h) = start(|c| c.max_connections = 1000).await;
    let mut conns = Vec::new();
    for _ in 0..N {
        let mut c = Raw::connect(h.addr, h.cert_fpr).await;
        c.hello().await;
        conns.push(c);
    }
    let before = live_after(Duration::from_millis(300)).await;
    for c in &mut conns {
        half_send(c, MAX_FRAME).await;
    }
    let held = live_after(Duration::from_millis(1500)).await - before;
    eprintln!(
        "{N} connections after Hello, not signed in, each half-sending a 1 MiB frame: {:.2} MiB held",
        mib(held)
    );
    assert!(
        held < (N * 64 * KIB) as isize,
        "{N} connections that said Hello but never signed in hold {:.1} MiB",
        mib(held)
    );
}

/// Connections that have not signed in share one budget for what they
/// hold, so many addresses together cannot use more than the operator set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connections_not_signed_in_share_one_budget() {
    let _one = SERIAL.lock().await;
    let (_d, h) = start(|c| {
        c.max_connections = 1000;
        // Each connection alone may send a large frame; only the shared
        // budget stops them.
        c.max_frame_before_sign_in = MAX_FRAME;
        c.max_buffered_before_sign_in_mb = 1;
    })
    .await;
    let mut conns = Vec::new();
    for _ in 0..N {
        let mut c = Raw::connect(h.addr, h.cert_fpr).await;
        c.hello().await;
        conns.push(c);
    }
    let before = live_after(Duration::from_millis(300)).await;
    for c in &mut conns {
        half_send(c, 256 * KIB).await;
    }
    let held = live_after(Duration::from_millis(1500)).await - before;
    let counted = h.held_before_sign_in();
    eprintln!(
        "{N} connections half-sending 256 KiB each against a 1 MB budget: {:.2} MiB held, {counted} bytes counted",
        mib(held)
    );
    // The budget is in use, and no further.
    assert!(
        counted > 500_000 && counted <= 1_000_000,
        "{counted} bytes counted"
    );
    assert!(
        held < (2 * 1024 * KIB) as isize,
        "connections not signed in hold {:.1} MiB past a 1 MB budget",
        mib(held)
    );
}

/// What a connection that has not signed in costs at most under the
/// default settings: its share of the largest frame it may half-send, on
/// top of the connection itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn largest_frame_before_sign_in_costs_its_size() {
    let _one = SERIAL.lock().await;
    let (_d, h) = start(|c| c.max_connections = 1000).await;
    let empty = live_after(Duration::from_millis(300)).await;
    let mut conns = Vec::new();
    for _ in 0..N {
        let mut c = Raw::connect(h.addr, h.cert_fpr).await;
        c.hello().await;
        conns.push(c);
    }
    let before = live_after(Duration::from_millis(300)).await;
    let frame = socketchat_server::config::MAX_FRAME_BEFORE_SIGN_IN;
    for c in &mut conns {
        half_send(c, frame).await;
    }
    let held = live_after(Duration::from_millis(1500)).await - before;
    let counted = h.held_before_sign_in();
    eprintln!(
        "{N} connections after Hello: {:.1} KiB each, both ends of the test included; half-sending {frame}-byte frames adds {:.1} KiB each ({counted} bytes counted)",
        (before - empty) as f64 / (N * KIB) as f64,
        held as f64 / (N * KIB) as f64,
    );
    // Each connection's first bytes are its own, outside the budget.
    let own = socketchat_server::config::SIGN_IN_FRAME_FLOOR;
    assert_eq!(counted, N * (4 + frame - own));
    assert!(
        held < (N * 2 * frame) as isize,
        "{:.1} KiB each",
        held as f64 / (N * KIB) as f64
    );
}

/// A signed-in connection that sends a length prefix announcing the
/// largest frame and 1 KiB of it holds little: room grows with the bytes
/// that arrive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn barely_started_frame_after_sign_in_holds_little() {
    let _one = SERIAL.lock().await;
    let (d, h) = start(|c| c.max_connections = 1000).await;
    let mut conns = Vec::new();
    for _ in 0..N {
        let mut c = Raw::connect(h.addr, h.cert_fpr).await;
        c.hello().await;
        let key = socketchat_core::keys::KeyPair::generate();
        let token = socketchat_server::make_server_invite(d.path())
            .unwrap()
            .token;
        let ch = c.challenge().await;
        let r = c
            .req(socketchat_proto::msg::Request::RegisterAccount {
                token,
                key: key.public(),
                sig: auth_sig(&key, &ch),
            })
            .await;
        assert_eq!(r, socketchat_proto::msg::Response::Ok);
        conns.push(c);
    }
    let before = live_after(Duration::from_millis(300)).await;
    for c in &mut conns {
        let mut start = (MAX_FRAME as u32).to_be_bytes().to_vec();
        start.extend([0u8; KIB]);
        c.send_raw(&start).await.unwrap();
    }
    let held = live_after(Duration::from_millis(1000)).await - before;
    eprintln!(
        "{N} signed-in connections, each sending 1 KiB of a frame announced at 1 MiB: {:.1} KiB held each",
        held as f64 / (N * KIB) as f64
    );
    assert!(
        held < (N * 32 * KIB) as isize,
        "{:.1} MiB held for {N} barely started frames",
        mib(held)
    );
}
