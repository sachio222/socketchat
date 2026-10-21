//! One task per connection: TLS, the Hello exchange, then requests in and
//! responses and pushes out.
//!
//! Each connection has a short queue of encoded frames waiting to be
//! written, bounded in frames and in bytes. The reader waits for room for
//! the largest reply before it handles the next request, so a client that
//! never reads stalls only itself. A push that does not fit closes that
//! connection; the client fetches what it missed when it reconnects.
//!
//! A write that makes no progress for `WRITE_LIMIT` ends the connection,
//! and once the reader stops, the writer gets `WRITER_GRACE` to finish
//! before it is stopped, so a peer that stopped reading frees its slot.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use socketchat_proto::msg::{
    from_body, to_frame, Busy, ClientFrame, Key, Request, Response, ServerFrame,
};
use socketchat_proto::{FrameDecoder, MAX_FRAME, MIN_PROTOCOL_VERSION};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Notify, OwnedSemaphorePermit};
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;

use crate::{auth, files, groups, invites, relock, State};

/// Frames one connection may have waiting to be written.
pub const QUEUE_FRAMES: usize = 64;

/// Bytes one connection may have waiting to be written, a reply being
/// worked on included. Room for about two of the largest frames.
pub const QUEUE_BYTES: usize = 2 * 1024 * 1024;

/// The largest frame on the wire: a full body and its length.
const MAX_WIRE: usize = MAX_FRAME + 4;

/// Longest one frame's write may take before the connection is dropped.
const WRITE_LIMIT: Duration = Duration::from_secs(30);

/// How long the writer may go on after the reader stops.
const WRITER_GRACE: Duration = Duration::from_secs(10);

/// Most connections turned away with a reply at once. Past this, a
/// connection over its address's share is dropped before TLS.
pub const MAX_REFUSALS: usize = 64;

/// Longest a connection being turned away may take: TLS, its Hello and
/// the reply.
const REFUSE_LIMIT: Duration = Duration::from_secs(5);

/// The most a connection being turned away may send before its Hello is
/// whole. A Hello is a few bytes.
const REFUSE_READ_MAX: usize = 64;

static NEXT_CONN: AtomicU64 = AtomicU64::new(1);

/// What waits to be written over every connection, for tests and limits.
#[derive(Default)]
pub struct Queued {
    pub frames: AtomicUsize,
    pub bytes: AtomicUsize,
}

/// One connection's count of bytes waiting to be written.
struct Account {
    bytes: AtomicUsize,
    /// Wakes the reader when bytes leave the queue.
    drained: Notify,
    all: Arc<Queued>,
    /// The most `bytes` has ever counted, for tests of the accounting.
    #[cfg(test)]
    peak: AtomicUsize,
}

impl Account {
    fn new(all: Arc<Queued>) -> Account {
        Account {
            bytes: AtomicUsize::new(0),
            drained: Notify::new(),
            all,
            #[cfg(test)]
            peak: AtomicUsize::new(0),
        }
    }

    /// Counts `n` more bytes if they fit under `limit`.
    fn take(&self, n: usize, limit: usize) -> bool {
        let mut b = self.bytes.load(Ordering::Acquire);
        loop {
            let Some(next) = b.checked_add(n).filter(|&t| t <= limit) else {
                return false;
            };
            match self
                .bytes
                .compare_exchange_weak(b, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    #[cfg(test)]
                    self.peak.fetch_max(next, Ordering::Relaxed);
                    return true;
                }
                Err(now) => b = now,
            }
        }
    }

    fn give(&self, n: usize) {
        self.bytes.fetch_sub(n, Ordering::AcqRel);
        self.drained.notify_one();
    }
}

/// One encoded frame in a connection's queue. Its bytes count until it is
/// written or thrown away; it counts as a queued frame until the writer
/// takes it.
struct Frame {
    bytes: Arc<Vec<u8>>,
    acct: Arc<Account>,
    queued: bool,
}

impl Frame {
    /// Wraps `bytes`, already counted on `acct`.
    fn new(bytes: Arc<Vec<u8>>, acct: &Arc<Account>) -> Frame {
        acct.all.frames.fetch_add(1, Ordering::Relaxed);
        acct.all.bytes.fetch_add(bytes.len(), Ordering::Relaxed);
        Frame {
            bytes,
            acct: acct.clone(),
            queued: true,
        }
    }

    /// The writer has it now.
    fn taken(&mut self) {
        if std::mem::take(&mut self.queued) {
            self.acct.all.frames.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl Drop for Frame {
    fn drop(&mut self) {
        self.taken();
        let n = self.bytes.len();
        self.acct.all.bytes.fetch_sub(n, Ordering::Relaxed);
        self.acct.give(n);
    }
}

/// The sending side of one connection's queue.
#[derive(Clone)]
pub struct Tx {
    inner: mpsc::Sender<Frame>,
    /// Wakes the connection's reader to close it.
    close: Arc<Notify>,
    acct: Arc<Account>,
}

impl Tx {
    /// Queues `bytes` if there is room in frames and in bytes. A push that
    /// does not fit closes the connection.
    fn push(&self, bytes: &Arc<Vec<u8>>) -> bool {
        if !self.acct.take(bytes.len(), QUEUE_BYTES) {
            self.close.notify_one();
            return false;
        }
        match self.inner.try_send(Frame::new(bytes.clone(), &self.acct)) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.close.notify_one();
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Queues the encoded `frame`, for frames the server makes itself.
    fn push_frame(&self, frame: &ServerFrame) -> bool {
        encode(frame).is_some_and(|b| self.push(&Arc::new(b)))
    }
}

/// Room held for a reply while the request is handled.
struct Reserved {
    acct: Arc<Account>,
    held: usize,
}

impl Reserved {
    /// Waits until the largest reply fits in the queue's bytes, then holds
    /// that room.
    async fn wait(acct: &Arc<Account>) -> Reserved {
        while !acct.take(MAX_WIRE, QUEUE_BYTES) {
            acct.drained.notified().await;
        }
        Reserved {
            acct: acct.clone(),
            held: MAX_WIRE,
        }
    }

    /// Queues the encoded reply `bytes` in the room held for it, and gives
    /// back the room it does not use. The reply's bytes are counted from
    /// the room already held, never on top of it, so the count never goes
    /// over the limit and a push that fits beside the reply is not refused.
    fn send(mut self, permit: mpsc::Permit<'_, Frame>, bytes: Vec<u8>) {
        let n = bytes.len();
        if n <= self.held {
            self.acct.give(self.held - n);
        } else {
            // No reply is larger than a frame, which the room covers.
            self.acct.take(n - self.held, usize::MAX);
        }
        self.held = 0;
        permit.send(Frame::new(Arc::new(bytes), &self.acct));
    }
}

impl Drop for Reserved {
    fn drop(&mut self) {
        if self.held > 0 {
            self.acct.give(self.held);
        }
    }
}

/// Connections that have proven a key, so pushes can reach them.
#[derive(Default)]
pub struct Online {
    inner: Mutex<HashMap<Key, Vec<(u64, Tx)>>>,
}

impl Online {
    pub fn add(&self, key: Key, conn: u64, tx: Tx) {
        let mut m = relock(&self.inner);
        let v = m.entry(key).or_default();
        if !v.iter().any(|(c, _)| *c == conn) {
            v.push((conn, tx));
        }
    }

    fn remove_conn(&self, conn: u64) {
        let mut m = relock(&self.inner);
        m.retain(|_, v| {
            v.retain(|(c, _)| *c != conn);
            !v.is_empty()
        });
    }

    /// Sends `frame` to every connection signed in as one of `keys`, except
    /// `skip`. A connection holding several of the keys gets it once. A
    /// connection whose queue is full is dropped from the list and closed.
    pub fn push_many(&self, keys: &[Key], frame: &ServerFrame, skip: Option<u64>) {
        // Encoded once, shared by every queue it goes to.
        let Some(bytes) = encode(frame).map(Arc::new) else {
            return;
        };
        let mut m = relock(&self.inner);
        let mut sent: HashSet<u64> = skip.into_iter().collect();
        let mut full = Vec::new();
        for k in keys {
            for (c, tx) in m.get(k).into_iter().flatten() {
                if sent.insert(*c) && !tx.push(&bytes) {
                    full.push(*c);
                }
            }
        }
        if !full.is_empty() {
            m.retain(|_, v| {
                v.retain(|(c, _)| !full.contains(c));
                !v.is_empty()
            });
        }
    }
}

/// What the server knows about one connection.
#[derive(Clone)]
pub struct ConnState {
    pub id: u64,
    pub challenge: Option<[u8; 32]>,
    pub proven: HashSet<Key>,
    pub tx: Tx,
    /// The protocol the connection said Hello with; 0 until it does.
    pub version: u16,
}

struct CountGuard(Arc<State>);

impl Drop for CountGuard {
    fn drop(&mut self) {
        self.0.conns.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Takes the connection off the push list however its task ends, a panic
/// included, so the writer stops and the socket closes.
struct OnlineGuard(Arc<State>, u64);

impl Drop for OnlineGuard {
    fn drop(&mut self) {
        self.0.online.remove_conn(self.1);
    }
}

/// Open connections per address.
#[derive(Default)]
pub struct PerIp {
    inner: Mutex<HashMap<IpAddr, usize>>,
}

/// The address a connection counts against: IPv4 as is, IPv6 by its /64.
fn source(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    }
}

/// One connection's place in its address's count, given back on drop.
pub struct IpSlot(Arc<State>, IpAddr);

impl PerIp {
    /// A slot for a connection from `ip`, or None when that address holds
    /// `max` already.
    pub fn take(state: &Arc<State>, ip: IpAddr, max: usize) -> Option<IpSlot> {
        let ip = source(ip);
        let mut m = relock(&state.per_ip.inner);
        let n = m.entry(ip).or_default();
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(IpSlot(state.clone(), ip))
    }
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let mut m = relock(&self.0.per_ip.inner);
        if let Some(n) = m.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.1);
            }
        }
    }
}

/// The bytes for `f`. A reply too large for one frame becomes an error reply
/// to the same request; a push that large is skipped.
fn encode(f: &ServerFrame) -> Option<Vec<u8>> {
    match to_frame(f) {
        Ok(b) => Some(b),
        Err(_) => match f {
            ServerFrame::Resp { id, .. } => to_frame(&ServerFrame::Resp {
                id: *id,
                body: Response::Error("that reply is too large to send".into()),
            })
            .ok(),
            _ => None,
        },
    }
}

/// Writes queued frames until the queue closes, a write fails, or a frame
/// takes longer than `limit`.
async fn write_frames<W: AsyncWrite + Unpin>(
    mut rx: mpsc::Receiver<Frame>,
    mut wr: W,
    close: Arc<Notify>,
    limit: Duration,
) {
    while let Some(mut f) = rx.recv().await {
        f.taken();
        // Flush every frame. When the socket is full, a TLS stream keeps the
        // last records of a write in its own buffer and sends them only on
        // the next write or a flush; a reply with nothing after it would
        // never arrive whole.
        let sent = tokio::time::timeout(limit, async {
            wr.write_all(&f.bytes).await?;
            wr.flush().await
        })
        .await;
        drop(f);
        if !matches!(sent, Ok(Ok(()))) {
            close.notify_one();
            return;
        }
    }
    let _ = tokio::time::timeout(limit, wr.shutdown()).await;
}

/// Turns a connection away with a reply the app can show: TLS, the app's
/// Hello, then `Busy` and close. It reads the Hello first, because closing
/// with it unread resets the connection and the reply can be lost. It holds
/// no slot and gives up after `REFUSE_LIMIT`.
pub async fn refuse(
    acceptor: TlsAcceptor,
    tcp: TcpStream,
    why: Busy,
    _permit: OwnedSemaphorePermit,
) {
    let _ = tokio::time::timeout(REFUSE_LIMIT, async {
        let mut tls = acceptor.accept(tcp).await.ok()?;
        let mut dec = FrameDecoder::default();
        let mut buf = [0u8; REFUSE_READ_MAX];
        let mut read = 0;
        while dec.next_frame().ok()?.is_none() {
            let n = tls.read(&mut buf).await.ok()?;
            read += n;
            if n == 0 || read > REFUSE_READ_MAX {
                return None;
            }
            dec.push(&buf[..n]);
        }
        let bytes = to_frame(&ServerFrame::Busy(why)).ok()?;
        tls.write_all(&bytes).await.ok()?;
        tls.flush().await.ok()?;
        tls.shutdown().await.ok()
    })
    .await;
}

pub async fn serve(
    state: Arc<State>,
    acceptor: TlsAcceptor,
    tcp: TcpStream,
    mut stop: watch::Receiver<bool>,
    _slot: IpSlot,
) {
    let count = state.conns.fetch_add(1, Ordering::Relaxed) + 1;
    let _guard = CountGuard(state.clone());
    let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
        Ok(Ok(s)) => s,
        _ => return,
    };
    let timing = state.cfg.timing;
    let (mut rd, wr) = tokio::io::split(tls);
    let (stx, rx) = mpsc::channel::<Frame>(QUEUE_FRAMES);
    let close = Arc::new(Notify::new());
    let acct = Arc::new(Account::new(state.queued.clone()));
    let tx = Tx {
        inner: stx,
        close: close.clone(),
        acct: acct.clone(),
    };
    let mut writer = tokio::spawn(write_frames(rx, wr, close.clone(), WRITE_LIMIT));

    let mut cs = ConnState {
        id: NEXT_CONN.fetch_add(1, Ordering::Relaxed),
        challenge: None,
        proven: HashSet::new(),
        tx: tx.clone(),
        version: 0,
    };
    let _online = OnlineGuard(state.clone(), cs.id);
    let mut dec = FrameDecoder::default();
    let mut buf = vec![0u8; 16 * 1024];
    let mut greeted = false;
    // Hello must come soon after TLS; after that, a request must come
    // within the idle limit of the last one.
    let mut deadline = Instant::now() + timing.hello;

    'conn: loop {
        loop {
            let body = match dec.next_frame() {
                Ok(Some(b)) => b,
                Ok(None) => break,
                Err(_) => break 'conn,
            };
            let Ok(frame) = from_body::<ClientFrame>(&body) else {
                break 'conn;
            };
            match frame {
                ClientFrame::Hello { version } if !greeted => {
                    if count > state.cfg.max_connections {
                        tx.push_frame(&ServerFrame::Busy(Busy::Full));
                        break 'conn;
                    }
                    if !(MIN_PROTOCOL_VERSION..=state.cfg.protocol_max).contains(&version) {
                        tx.push_frame(&ServerFrame::VersionMismatch {
                            server: state.cfg.protocol_max,
                        });
                        break 'conn;
                    }
                    greeted = true;
                    cs.version = version;
                    tx.push_frame(&ServerFrame::HelloOk { version });
                    deadline = Instant::now() + timing.idle;
                }
                ClientFrame::Req { id, body } if greeted => {
                    // Wait for room for the reply, in bytes and in frames,
                    // before doing the work.
                    let reserved = tokio::select! {
                        r = Reserved::wait(&acct) => r,
                        _ = stop.changed() => break 'conn,
                        _ = close.notified() => break 'conn,
                        _ = tokio::time::sleep_until(deadline) => break 'conn,
                    };
                    let permit = tokio::select! {
                        p = tx.inner.reserve() => match p {
                            Ok(p) => p,
                            Err(_) => break 'conn,
                        },
                        _ = stop.changed() => break 'conn,
                        _ = close.notified() => break 'conn,
                        _ = tokio::time::sleep_until(deadline) => break 'conn,
                    };
                    let resp = if body.min_version() > cs.version {
                        Response::Refused("this server needs a newer app for that".into())
                    } else {
                        handle(&state, &mut cs, body).await
                    };
                    if let Some(b) = encode(&ServerFrame::Resp { id, body: resp }) {
                        reserved.send(permit, b);
                    }
                    deadline = Instant::now() + timing.idle;
                }
                _ => break 'conn,
            }
        }
        tokio::select! {
            _ = stop.changed() => break,
            _ = close.notified() => break,
            _ = tokio::time::sleep_until(deadline) => break,
            r = rd.read(&mut buf) => match r {
                Ok(0) | Err(_) => break,
                Ok(n) => dec.push(&buf[..n]),
            },
        }
    }

    state.online.remove_conn(cs.id);
    drop(cs);
    drop(tx);
    // The writer sends what is queued, but a peer that stopped reading must
    // not hold the connection's slot.
    if tokio::time::timeout(WRITER_GRACE, &mut writer)
        .await
        .is_err()
    {
        writer.abort();
    }
}

/// Runs slow OpenMLS work off the async workers.
async fn blocking(f: impl FnOnce() -> Response + Send + 'static) -> Response {
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or_else(|_| Response::Error("the server failed on that request".into()))
}

async fn handle(state: &Arc<State>, cs: &mut ConnState, req: Request) -> Response {
    match req {
        Request::Challenge => auth::challenge(cs),
        Request::Prove { key, sig } => auth::prove(state, cs, key, sig),
        Request::RegisterAccount { token, key, sig } => {
            auth::register_account(state, cs, token, key, sig)
        }
        Request::RegisterMailbox { token, key, sig } => {
            groups::register_mailbox(state, cs, token, key, sig)
        }
        Request::CreateGroup {
            group_info,
            ratchet_tree,
        } => {
            let (state, cs) = (state.clone(), cs.clone());
            blocking(move || groups::create_group(&state, &cs, &group_info, &ratchet_tree)).await
        }
        Request::Post {
            group,
            mls,
            welcome,
        } => {
            let (state, cs) = (state.clone(), cs.clone());
            blocking(move || groups::post(&state, &cs, group, &mls, welcome)).await
        }
        // Reads that can be large go off the async workers too, with the
        // database lock they hold.
        Request::Fetch {
            group,
            after,
            limit,
        } => {
            let (state, cs) = (state.clone(), cs.clone());
            blocking(move || groups::fetch(&state, &cs, group, after, limit)).await
        }
        Request::Ack { group, seq } => groups::ack(state, cs, group, seq),
        Request::Members { group } => groups::members(state, cs, group),
        Request::CreateInvite { group } => groups::create_invite(state, cs, group),
        Request::FetchWelcomes => groups::fetch_welcomes(state, cs),
        Request::RedeemInvite {
            token,
            key_package,
            mac,
        } => invites::redeem(state, cs, token, key_package, mac),
        Request::PendingJoins { group, after } => {
            let (state, cs) = (state.clone(), cs.clone());
            blocking(move || invites::pending(&state, &cs, group, after)).await
        }
        Request::FileBegin { group, size } => files::begin(state, cs, group, size),
        Request::FileChunk { file, index, data } => files::chunk(state, cs, file, index, &data),
        Request::FileEnd { file } => files::end(state, cs, file),
        Request::FileGet { file, index } => files::get(state, cs, file, index),
        Request::FileDone { file } => files::done(state, cs, file),
        Request::ListInvites { server_tokens } => groups::list_invites(state, cs, &server_tokens),
        Request::CancelInvite { token } => groups::cancel_invite(state, cs, token),
        Request::GroupCreated { group } => groups::group_created(state, cs, group),
        Request::LastLeave { group } => groups::last_leave(state, cs, group),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socketchat_proto::msg::Entry;
    use socketchat_proto::MAX_FRAME;

    #[test]
    fn oversized_reply_becomes_an_error_reply() {
        let big = |seq| Entry {
            seq,
            mls: vec![0; MAX_FRAME / 2 + 10],
        };
        let f = ServerFrame::Resp {
            id: 7,
            body: Response::Entries(vec![big(1), big(2)]),
        };
        assert!(to_frame(&f).is_err());
        let bytes = encode(&f).expect("an error reply");
        let back: ServerFrame = from_body(&bytes[4..]).unwrap();
        assert!(
            matches!(
                back,
                ServerFrame::Resp {
                    id: 7,
                    body: Response::Error(_)
                }
            ),
            "{back:?}"
        );
    }

    fn account() -> Arc<Account> {
        Arc::new(Account::new(Default::default()))
    }

    /// Queuing a reply turns the room held for it into the reply's own
    /// count. Adding the reply first and giving the held room back after
    /// counted both for a moment, so a push that fit beside the reply was
    /// refused and closed a healthy connection.
    #[tokio::test]
    async fn reply_takes_over_its_held_room() {
        let acct = account();
        let reserved = Reserved::wait(&acct).await;
        // Pushes fill the rest of the queue's bytes.
        assert!(acct.take(QUEUE_BYTES - MAX_WIRE, QUEUE_BYTES));
        let (tx, mut rx) = mpsc::channel(4);
        let permit = tx.reserve().await.unwrap();
        reserved.send(permit, vec![0; 100]);
        let peak = acct.peak.load(Ordering::Relaxed);
        assert!(
            peak <= QUEUE_BYTES,
            "counted {} bytes over the limit",
            peak - QUEUE_BYTES
        );
        assert_eq!(
            acct.bytes.load(Ordering::Relaxed),
            QUEUE_BYTES - MAX_WIRE + 100
        );
        // Room the reply did not use is free again.
        assert!(acct.take(MAX_WIRE - 100, QUEUE_BYTES));
        acct.give(QUEUE_BYTES - 100);
        drop(rx.recv().await);
        assert_eq!(acct.bytes.load(Ordering::Relaxed), 0);
        assert_eq!(acct.all.bytes.load(Ordering::Relaxed), 0);
    }

    /// Room held for a reply that never comes is given back whole.
    #[tokio::test]
    async fn unused_reservation_is_given_back() {
        let acct = account();
        drop(Reserved::wait(&acct).await);
        assert_eq!(acct.bytes.load(Ordering::Relaxed), 0);
    }

    /// A writer that keeps bytes until flushed, as TLS does when the socket
    /// is full, still delivers a lone frame: the writer flushes each one.
    #[tokio::test]
    async fn each_frame_is_flushed() {
        let (near, mut far) = tokio::io::duplex(64 * 1024);
        let buffered = tokio::io::BufWriter::new(near);
        let (tx, rx) = mpsc::channel(4);
        let acct = account();
        let bytes = encode(&ServerFrame::HelloOk { version: 1 }).unwrap();
        assert!(acct.take(bytes.len(), QUEUE_BYTES));
        tx.send(Frame::new(Arc::new(bytes.clone()), &acct))
            .await
            .ok()
            .unwrap();
        let w = tokio::spawn(write_frames(
            rx,
            buffered,
            Arc::new(Notify::new()),
            WRITE_LIMIT,
        ));
        let mut got = vec![0u8; bytes.len()];
        tokio::time::timeout(Duration::from_secs(2), far.read_exact(&mut got))
            .await
            .expect("the frame stayed in the writer's buffer")
            .unwrap();
        assert_eq!(got, bytes);
        assert_eq!(acct.bytes.load(Ordering::Relaxed), 0);
        assert_eq!(acct.all.bytes.load(Ordering::Relaxed), 0);
        drop(tx);
        w.await.unwrap();
    }

    /// A write that makes no progress ends the writer and closes the
    /// connection, and what was queued is no longer counted.
    #[tokio::test]
    async fn stuck_write_gives_up() {
        let (near, _far) = tokio::io::duplex(16);
        let (tx, rx) = mpsc::channel(4);
        let acct = account();
        for _ in 0..2 {
            assert!(acct.take(1000, QUEUE_BYTES));
            tx.send(Frame::new(Arc::new(vec![0; 1000]), &acct))
                .await
                .ok()
                .unwrap();
        }
        let close = Arc::new(Notify::new());
        let w = tokio::spawn(write_frames(
            rx,
            near,
            close.clone(),
            Duration::from_millis(200),
        ));
        tokio::time::timeout(Duration::from_secs(2), close.notified())
            .await
            .expect("a stuck write did not close the connection");
        w.await.unwrap();
        assert_eq!(acct.bytes.load(Ordering::Relaxed), 0);
        assert_eq!(acct.all.frames.load(Ordering::Relaxed), 0);
    }

    /// A push of the largest message the log takes fits beside the room
    /// held for a reply.
    #[test]
    fn largest_push_fits_beside_a_reply() {
        let f = ServerFrame::Push(socketchat_proto::msg::Push::Entry {
            group: socketchat_proto::msg::GroupId([0; 16]),
            entry: Entry {
                seq: u64::MAX,
                mls: vec![0; crate::groups::MAX_MLS],
            },
        });
        let len = encode(&f).unwrap().len();
        assert!(MAX_WIRE + len <= QUEUE_BYTES, "{len}");
    }

    #[test]
    fn ipv6_counts_by_its_network() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::9".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(source(a), source(b));
        assert_ne!(source(a), source(c));
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(source(mapped), "192.0.2.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn oversized_push_is_skipped() {
        let f = ServerFrame::Push(socketchat_proto::msg::Push::Entry {
            group: socketchat_proto::msg::GroupId([0; 16]),
            entry: Entry {
                seq: 1,
                mls: vec![0; MAX_FRAME + 1],
            },
        });
        assert!(encode(&f).is_none());
    }
}
