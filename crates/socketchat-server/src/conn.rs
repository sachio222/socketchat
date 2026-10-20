//! One task per connection: TLS, the Hello exchange, then requests in and
//! responses and pushes out.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use socketchat_proto::msg::{
    from_body, to_frame, ClientFrame, Key, Request, Response, ServerFrame,
};
use socketchat_proto::{FrameDecoder, PROTOCOL_VERSION};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsAcceptor;

use crate::{auth, State};

pub type Tx = mpsc::UnboundedSender<ServerFrame>;

static NEXT_CONN: AtomicU64 = AtomicU64::new(1);

/// Connections that have proven a key, so pushes can reach them.
#[derive(Default)]
pub struct Online {
    inner: Mutex<HashMap<Key, Vec<(u64, Tx)>>>,
}

impl Online {
    pub fn add(&self, key: Key, conn: u64, tx: Tx) {
        let mut m = self.inner.lock().unwrap();
        let v = m.entry(key).or_default();
        if !v.iter().any(|(c, _)| *c == conn) {
            v.push((conn, tx));
        }
    }

    fn remove_conn(&self, conn: u64) {
        let mut m = self.inner.lock().unwrap();
        m.retain(|_, v| {
            v.retain(|(c, _)| *c != conn);
            !v.is_empty()
        });
    }

    /// Sends `frame` to every connection signed in as `key`. Connections that
    /// share several keys get it once.
    pub fn push_many(&self, keys: &[Key], frame: &ServerFrame) {
        let m = self.inner.lock().unwrap();
        let mut sent = HashSet::new();
        for k in keys {
            for (c, tx) in m.get(k).into_iter().flatten() {
                if sent.insert(*c) {
                    let _ = tx.send(frame.clone());
                }
            }
        }
    }
}

/// What the server knows about one connection.
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
    let (mut rd, mut wr) = tokio::io::split(tls);
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerFrame>();
    let writer = tokio::spawn(async move {
        while let Some(f) = rx.recv().await {
            let Ok(bytes) = to_frame(&f) else { break };
            if wr.write_all(&bytes).await.is_err() {
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
    let mut dec = FrameDecoder::default();
    let mut buf = vec![0u8; 16 * 1024];
    let mut greeted = false;

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
                        let _ = tx.send(ServerFrame::VersionMismatch {
                            server: PROTOCOL_VERSION,
                        });
                        break 'conn;
                    }
                    greeted = true;
                    let _ = tx.send(ServerFrame::HelloOk {
                        version: PROTOCOL_VERSION,
                    });
                }
                ClientFrame::Req { id, body } if greeted => {
                    let resp = handle(&state, &mut cs, body).await;
                    let _ = tx.send(ServerFrame::Resp { id, body: resp });
                }
                _ => break 'conn,
            }
        }
        tokio::select! {
            _ = stop.changed() => break,
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

async fn handle(state: &State, cs: &mut ConnState, req: Request) -> Response {
    match req {
        Request::Challenge => auth::challenge(cs),
        Request::Prove { key, sig } => auth::prove(state, cs, key, sig),
        Request::RegisterAccount { token, key, sig } => {
            auth::register_account(state, cs, token, key, sig)
        }
        _ => Response::Error("this server does not handle that request yet".into()),
    }
}
