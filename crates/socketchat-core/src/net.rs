//! The client's connection to a server: TLS 1.3 pinned to the certificate
//! fingerprint from the invite link, then requests and pushes.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use socketchat_proto::msg::{
    from_body, to_frame, Busy, ClientFrame, Key, Push, Request, Response, ServerFrame,
};
use socketchat_proto::{FrameDecoder, Token, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::TlsConnector;

use crate::keys::{KeyPair, CTX_AUTH};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum NetError {
    #[error(
        "the server's certificate does not match the invite link; someone may be in the middle"
    )]
    CertMismatch { expected: [u8; 32], got: [u8; 32] },
    #[error("secure connection failed: {0}")]
    Tls(String),
    #[error("could not reach the server: {0}")]
    Io(String),
    #[error("the server speaks protocol {0}; update socketchat")]
    Version(u16),
    #[error(
        "this server runs an older version of socketchat that can't do that yet; ask the person who runs it to update it"
    )]
    Unsupported { needs: u16, server: u16 },
    #[error("the connection to the server dropped")]
    Disconnected,
    #[error("the server took too long to answer")]
    Timeout,
    #[error("{}", busy_text(.0))]
    Busy(Busy),
    #[error("{0}")]
    Refused(String),
    #[error("server error: {0}")]
    Server(String),
    #[error("unexpected reply from the server: {0}")]
    Unexpected(String),
}

/// What to tell people when a server turns them away.
fn busy_text(why: &Busy) -> &'static str {
    match why {
        Busy::Full => "this server is full right now; try again in a few minutes",
        Busy::Network => {
            "this server has too many connections from your network right now; try again in a few minutes"
        }
    }
}

/// Accepts only the certificate whose SHA-256 matches the pin, and records
/// what it saw so a mismatch can say which certificate showed up.
#[derive(Debug)]
struct Pinned {
    pin: [u8; 32],
    seen: Arc<Mutex<Option<[u8; 32]>>>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        *self.seen.lock().unwrap() = Some(got);
        if got == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("certificate pin mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not allowed".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

type Pending = Arc<Mutex<HashMap<u32, oneshot::Sender<Response>>>>;

struct Link {
    out: mpsc::UnboundedSender<ClientFrame>,
    pending: Pending,
    alive: Arc<AtomicBool>,
}

/// One connection to one server.
pub struct Conn {
    host: String,
    port: u16,
    fpr: [u8; 32],
    link: Link,
    /// The newest version this app offers when it connects.
    max: u16,
    /// The version agreed with the server.
    protocol: u16,
    pushes: mpsc::UnboundedReceiver<Push>,
    next_id: AtomicU32,
    keys: Mutex<Vec<KeyPair>>,
}

async fn open(
    host: &str,
    port: u16,
    fpr: [u8; 32],
    version: u16,
) -> Result<(Link, mpsc::UnboundedReceiver<Push>, u16), NetError> {
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .map_err(|_| NetError::Timeout)?
        .map_err(|e| NetError::Io(e.to_string()))?;
    let _ = tcp.set_nodelay(true);
    let seen = Arc::new(Mutex::new(None));
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| NetError::Tls(e.to_string()))?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(Pinned {
        pin: fpr,
        seen: seen.clone(),
    }))
    .with_no_client_auth();
    let name = ServerName::try_from("socketchat").expect("static name");
    let tls = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        TlsConnector::from(Arc::new(cfg)).connect(name, tcp),
    )
    .await
    {
        Err(_) => return Err(NetError::Timeout),
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(match *seen.lock().unwrap() {
                Some(got) if got != fpr => NetError::CertMismatch { expected: fpr, got },
                _ => NetError::Tls(e.to_string()),
            })
        }
    };
    let (mut rd, mut wr) = tokio::io::split(tls);

    let hello = to_frame(&ClientFrame::Hello { version })
        .map_err(|e| NetError::Unexpected(e.to_string()))?;
    write_frame(&mut wr, &hello)
        .await
        .map_err(|e| NetError::Io(e.to_string()))?;
    let mut dec = FrameDecoder::default();
    let mut buf = vec![0u8; 16 * 1024];
    let first = loop {
        if let Some(b) = dec
            .next_frame()
            .map_err(|e| NetError::Unexpected(e.to_string()))?
        {
            break from_body::<ServerFrame>(&b).map_err(|e| NetError::Unexpected(e.to_string()))?;
        }
        let n = tokio::time::timeout(CONNECT_TIMEOUT, rd.read(&mut buf))
            .await
            .map_err(|_| NetError::Timeout)?
            .map_err(|e| NetError::Io(e.to_string()))?;
        if n == 0 {
            return Err(NetError::Disconnected);
        }
        dec.push(&buf[..n]);
    };
    let agreed = match first {
        ServerFrame::HelloOk { version: v } if v == version => v,
        ServerFrame::HelloOk { version: v } => {
            return Err(NetError::Unexpected(format!(
                "the server answered with protocol {v} after Hello {version}"
            )))
        }
        ServerFrame::VersionMismatch { server } => return Err(NetError::Version(server)),
        ServerFrame::Busy(why) => return Err(NetError::Busy(why)),
        other => return Err(NetError::Unexpected(format!("{other:?}"))),
    };

    let (out, out_rx) = mpsc::unbounded_channel::<ClientFrame>();
    tokio::spawn(write_frames(out_rx, wr));

    let pending: Pending = Default::default();
    let alive = Arc::new(AtomicBool::new(true));
    let (push_tx, push_rx) = mpsc::unbounded_channel();
    let (p2, a2) = (pending.clone(), alive.clone());
    tokio::spawn(async move {
        'read: loop {
            loop {
                match dec.next_frame() {
                    Ok(Some(b)) => match from_body::<ServerFrame>(&b) {
                        Ok(ServerFrame::Resp { id, body }) => {
                            if let Some(tx) = p2.lock().unwrap().remove(&id) {
                                let _ = tx.send(body);
                            }
                        }
                        Ok(ServerFrame::Push(p)) => {
                            let _ = push_tx.send(p);
                        }
                        _ => break 'read,
                    },
                    Ok(None) => break,
                    Err(_) => break 'read,
                }
            }
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => dec.push(&buf[..n]),
            }
        }
        a2.store(false, Ordering::SeqCst);
        p2.lock().unwrap().clear();
        drop(push_tx);
    });

    Ok((
        Link {
            out,
            pending,
            alive,
        },
        push_rx,
        agreed,
    ))
}

/// Opens a connection at `max`; when the server only speaks an older
/// version this app also knows, opens once more at that version.
async fn open_upto(
    host: &str,
    port: u16,
    fpr: [u8; 32],
    max: u16,
) -> Result<(Link, mpsc::UnboundedReceiver<Push>, u16), NetError> {
    match open(host, port, fpr, max).await {
        Err(NetError::Version(server)) if (MIN_PROTOCOL_VERSION..max).contains(&server) => {
            open(host, port, fpr, server).await
        }
        other => other,
    }
}

/// Writes one encoded frame and flushes it. When the socket is full, a TLS
/// stream keeps the last records of a write in its own buffer and sends
/// them only on the next write or a flush; a request with nothing after it
/// would never arrive whole.
async fn write_frame<W: AsyncWrite + Unpin>(wr: &mut W, bytes: &[u8]) -> std::io::Result<()> {
    wr.write_all(bytes).await?;
    wr.flush().await
}

/// Writes frames from the queue until it closes or a write fails.
async fn write_frames<W: AsyncWrite + Unpin>(
    mut rx: mpsc::UnboundedReceiver<ClientFrame>,
    mut wr: W,
) {
    while let Some(f) = rx.recv().await {
        let Ok(bytes) = to_frame(&f) else { break };
        if write_frame(&mut wr, &bytes).await.is_err() {
            break;
        }
    }
    let _ = wr.shutdown().await;
}

impl Conn {
    pub async fn connect(host: &str, port: u16, fpr: [u8; 32]) -> Result<Conn, NetError> {
        Self::connect_upto(host, port, fpr, PROTOCOL_VERSION).await
    }

    /// Connects offering protocol versions up to `max`.
    pub async fn connect_upto(
        host: &str,
        port: u16,
        fpr: [u8; 32],
        max: u16,
    ) -> Result<Conn, NetError> {
        let (link, pushes, protocol) = open_upto(host, port, fpr, max).await?;
        Ok(Conn {
            host: host.to_string(),
            port,
            fpr,
            link,
            max,
            protocol,
            pushes,
            next_id: AtomicU32::new(1),
            keys: Mutex::new(vec![]),
        })
    }

    /// The protocol version agreed with the server.
    pub fn protocol(&self) -> u16 {
        self.protocol
    }

    pub fn is_alive(&self) -> bool {
        self.link.alive.load(Ordering::SeqCst)
    }

    /// Sends a request and waits for its reply.
    pub async fn request(&self, body: Request) -> Result<Response, NetError> {
        if !self.is_alive() {
            return Err(NetError::Disconnected);
        }
        if body.min_version() > self.protocol {
            return Err(NetError::Unsupported {
                needs: body.min_version(),
                server: self.protocol,
            });
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.link.pending.lock().unwrap().insert(id, tx);
        if self.link.out.send(ClientFrame::Req { id, body }).is_err() {
            self.link.pending.lock().unwrap().remove(&id);
            return Err(NetError::Disconnected);
        }
        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Err(_) => {
                self.link.pending.lock().unwrap().remove(&id);
                Err(NetError::Timeout)
            }
            Ok(Err(_)) => Err(NetError::Disconnected),
            // The server's own words reach people's screens: no escape codes.
            Ok(Ok(Response::Error(e))) => Err(NetError::Server(crate::sanitize::clean_text(&e))),
            Ok(Ok(Response::Refused(why))) => {
                Ok(Response::Refused(crate::sanitize::clean_text(&why)))
            }
            Ok(Ok(r)) => Ok(r),
        }
    }

    /// Sends a request whose only good reply is `Ok`.
    pub async fn request_ok(&self, body: Request) -> Result<(), NetError> {
        match self.request(body).await? {
            Response::Ok => Ok(()),
            Response::Refused(why) => Err(NetError::Refused(why)),
            other => Err(NetError::Unexpected(format!("{other:?}"))),
        }
    }

    async fn signed_challenge(
        &self,
        key: &KeyPair,
    ) -> Result<socketchat_proto::msg::Sig, NetError> {
        let Response::Challenge(c) = self.request(Request::Challenge).await? else {
            return Err(NetError::Unexpected("no challenge".into()));
        };
        Ok(key.sign(CTX_AUTH, &[c.as_slice(), &key.public().0].concat()))
    }

    fn remember(&self, key: &KeyPair) {
        let mut keys = self.keys.lock().unwrap();
        if !keys.iter().any(|k| k.public() == key.public()) {
            keys.push(key.clone());
        }
    }

    /// Signs in with a key the server already knows.
    pub async fn prove(&self, key: &KeyPair) -> Result<(), NetError> {
        let sig = self.signed_challenge(key).await?;
        self.request_ok(Request::Prove {
            key: key.public(),
            sig,
        })
        .await?;
        self.remember(key);
        Ok(())
    }

    /// Registers a server account key with an invite token.
    pub async fn register_account(&self, token: Token, key: &KeyPair) -> Result<(), NetError> {
        let sig = self.signed_challenge(key).await?;
        self.request_ok(Request::RegisterAccount {
            token,
            key: key.public(),
            sig,
        })
        .await?;
        self.remember(key);
        Ok(())
    }

    /// Registers a group key's mailbox: under a group invite, or (with
    /// `None`) for a group this connection's account is about to create.
    pub async fn register_mailbox(
        &self,
        token: Option<Token>,
        key: &KeyPair,
    ) -> Result<(), NetError> {
        let sig = self.signed_challenge(key).await?;
        self.request_ok(Request::RegisterMailbox {
            token,
            key: key.public(),
            sig,
        })
        .await?;
        self.remember(key);
        Ok(())
    }

    /// Keys this connection has signed in with.
    pub fn proven(&self) -> Vec<Key> {
        self.keys
            .lock()
            .unwrap()
            .iter()
            .map(|k| k.public())
            .collect()
    }

    /// Forgets a key, for example after leaving its group.
    pub fn forget(&self, key: &Key) {
        self.keys.lock().unwrap().retain(|k| &k.public() != key);
    }

    /// Marks the connection dropped without closing it.
    #[cfg(feature = "test-hooks")]
    pub fn test_mark_dead(&self) {
        self.link.alive.store(false, Ordering::SeqCst);
    }

    /// A push that already arrived, without waiting.
    pub fn try_push(&mut self) -> Option<Push> {
        self.pushes.try_recv().ok()
    }

    /// Polls for the next push; `Ready(None)` means the connection dropped.
    pub fn poll_push(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Push>> {
        self.pushes.poll_recv(cx)
    }

    /// The next push from the server. `None` means the connection dropped.
    pub async fn next_push(&mut self) -> Option<Push> {
        self.pushes.recv().await
    }

    /// Opens a fresh connection to the same server and signs in again with
    /// every key used before.
    pub async fn reconnect(&mut self) -> Result<(), NetError> {
        let (link, pushes, protocol) = open_upto(&self.host, self.port, self.fpr, self.max).await?;
        self.protocol = protocol;
        self.link = link;
        self.pushes = pushes;
        let keys: Vec<KeyPair> = self.keys.lock().unwrap().clone();
        for k in &keys {
            self.prove(k).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer that keeps bytes until flushed, as TLS does when the socket
    /// is full, still delivers a lone request: the writer flushes each one.
    #[tokio::test]
    async fn each_frame_is_flushed() {
        let (near, mut far) = tokio::io::duplex(64 * 1024);
        let (tx, rx) = mpsc::unbounded_channel();
        let w = tokio::spawn(write_frames(rx, tokio::io::BufWriter::new(near)));
        let f = ClientFrame::Req {
            id: 1,
            body: Request::Challenge,
        };
        let bytes = to_frame(&f).unwrap();
        tx.send(f).unwrap();
        let mut got = vec![0u8; bytes.len()];
        tokio::time::timeout(Duration::from_secs(2), far.read_exact(&mut got))
            .await
            .expect("the request stayed in the writer's buffer")
            .unwrap();
        assert_eq!(got, bytes);
        drop(tx);
        w.await.unwrap();
    }

    /// The Hello goes out whole on its own, with nothing written after it.
    #[tokio::test]
    async fn hello_is_flushed() {
        let (near, mut far) = tokio::io::duplex(64 * 1024);
        let mut wr = tokio::io::BufWriter::new(near);
        let hello = to_frame(&ClientFrame::Hello {
            version: PROTOCOL_VERSION,
        })
        .unwrap();
        write_frame(&mut wr, &hello).await.unwrap();
        let mut got = vec![0u8; hello.len()];
        tokio::time::timeout(Duration::from_secs(2), far.read_exact(&mut got))
            .await
            .expect("the Hello stayed in the writer's buffer")
            .unwrap();
        assert_eq!(got, hello);
    }
}
