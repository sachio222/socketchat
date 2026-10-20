//! One task per connection: TLS, the Hello exchange, then requests in and
//! responses and pushes out.
//!
//! Each connection has a short queue of frames waiting to be written. The
//! reader waits for room in it before it handles the next request, so a
//! client that never reads stalls only itself. A push that finds the queue
//! full closes that connection; the client fetches what it missed when it
//! reconnects.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use socketchat_proto::msg::{
    from_body, to_frame, ClientFrame, Key, Request, Response, ServerFrame,
};
use socketchat_proto::{FrameDecoder, PROTOCOL_VERSION};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Notify};
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;

use crate::{auth, files, groups, invites, relock, State};

/// Frames one connection may have waiting to be written.
pub const QUEUE_FRAMES: usize = 64;

static NEXT_CONN: AtomicU64 = AtomicU64::new(1);

/// The sending side of one connection's queue.
#[derive(Clone)]
pub struct Tx {
    inner: mpsc::Sender<ServerFrame>,
    /// Wakes the connection's reader to close it.
    close: Arc<Notify>,
    queued: Arc<AtomicUsize>,
}

impl Tx {
    /// Queues `frame` if there is room. A full queue closes the connection.
    fn push(&self, frame: ServerFrame) -> bool {
        match self.inner.try_send(frame) {
            Ok(()) => {
                self.queued.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.close.notify_one();
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    fn send(&self, permit: mpsc::Permit<'_, ServerFrame>, frame: ServerFrame) {
        self.queued.fetch_add(1, Ordering::Relaxed);
        permit.send(frame);
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
        let mut m = relock(&self.inner);
        let mut sent: HashSet<u64> = skip.into_iter().collect();
        let mut full = Vec::new();
        for k in keys {
            for (c, tx) in m.get(k).into_iter().flatten() {
                if sent.insert(*c) && !tx.push(frame.clone()) {
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

pub async fn serve(
    state: Arc<State>,
    acceptor: TlsAcceptor,
    tcp: TcpStream,
    mut stop: watch::Receiver<bool>,
) {
    let count = state.conns.fetch_add(1, Ordering::Relaxed) + 1;
    let _guard = CountGuard(state.clone());
    let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
        Ok(Ok(s)) => s,
        _ => return,
    };
    let timing = state.cfg.timing;
    let (mut rd, mut wr) = tokio::io::split(tls);
    let (stx, mut rx) = mpsc::channel::<ServerFrame>(QUEUE_FRAMES);
    let close = Arc::new(Notify::new());
    let tx = Tx {
        inner: stx,
        close: close.clone(),
        queued: state.queued.clone(),
    };
    let queued = state.queued.clone();
    let writer_close = close.clone();
    let writer = tokio::spawn(async move {
        while let Some(f) = rx.recv().await {
            queued.fetch_sub(1, Ordering::Relaxed);
            let Some(bytes) = encode(&f) else { continue };
            if wr.write_all(&bytes).await.is_err() {
                writer_close.notify_one();
                return;
            }
        }
        let _ = wr.shutdown().await;
    });

    let mut cs = ConnState {
        id: NEXT_CONN.fetch_add(1, Ordering::Relaxed),
        challenge: None,
        proven: HashSet::new(),
        tx: tx.clone(),
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
                        break 'conn;
                    }
                    if version != PROTOCOL_VERSION {
                        tx.push(ServerFrame::VersionMismatch {
                            server: PROTOCOL_VERSION,
                        });
                        break 'conn;
                    }
                    greeted = true;
                    tx.push(ServerFrame::HelloOk {
                        version: PROTOCOL_VERSION,
                    });
                    deadline = Instant::now() + timing.idle;
                }
                ClientFrame::Req { id, body } if greeted => {
                    // Wait for room for the reply before doing the work.
                    let permit = tokio::select! {
                        p = tx.inner.reserve() => match p {
                            Ok(p) => p,
                            Err(_) => break 'conn,
                        },
                        _ = stop.changed() => break 'conn,
                        _ = close.notified() => break 'conn,
                        _ = tokio::time::sleep_until(deadline) => break 'conn,
                    };
                    let resp = handle(&state, &mut cs, body).await;
                    tx.send(permit, ServerFrame::Resp { id, body: resp });
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
    let _ = writer.await;
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
        Request::Fetch {
            group,
            after,
            limit,
        } => groups::fetch(state, cs, group, after, limit),
        Request::Ack { group, seq } => groups::ack(state, cs, group, seq),
        Request::Members { group } => groups::members(state, cs, group),
        Request::CreateInvite { group } => groups::create_invite(state, cs, group),
        Request::FetchWelcomes => groups::fetch_welcomes(state, cs),
        Request::RedeemInvite {
            token,
            key_package,
            mac,
        } => invites::redeem(state, cs, token, key_package, mac),
        Request::PendingJoins { group } => invites::pending(state, cs, group),
        Request::FileBegin { group, size } => files::begin(state, cs, group, size),
        Request::FileChunk { file, index, data } => files::chunk(state, cs, file, index, &data),
        Request::FileEnd { file } => files::end(state, cs, file),
        Request::FileGet { file, index } => files::get(state, cs, file, index),
        Request::FileDone { file } => files::done(state, cs, file),
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
