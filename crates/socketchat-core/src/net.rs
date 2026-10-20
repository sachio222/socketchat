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
    from_body, to_frame, ClientFrame, Key, Push, Request, Response, ServerFrame,
};
use socketchat_proto::{FrameDecoder, Token, PROTOCOL_VERSION};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    #[error("the connection to the server dropped")]
    Disconnected,
    #[error("the server took too long to answer")]
    Timeout,
    #[error("{0}")]
    Refused(String),
    #[error("server error: {0}")]
    Server(String),
    #[error("unexpected reply from the server: {0}")]
    Unexpected(String),
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
    pushes: mpsc::UnboundedReceiver<Push>,
    next_id: AtomicU32,
    keys: Mutex<Vec<KeyPair>>,
}

async fn open(
    host: &str,
    port: u16,
    fpr: [u8; 32],
) -> Result<(Link, mpsc::UnboundedReceiver<Push>), NetError> {
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

    let hello = to_frame(&ClientFrame::Hello {
        version: PROTOCOL_VERSION,
    })
    .map_err(|e| NetError::Unexpected(e.to_string()))?;
    wr.write_all(&hello)
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
    match first {
        ServerFrame::HelloOk { .. } => {}
        ServerFrame::VersionMismatch { server } => return Err(NetError::Version(server)),
        other => return Err(NetError::Unexpected(format!("{other:?}"))),
    }

    let (out, mut out_rx) = mpsc::unbounded_channel::<ClientFrame>();
    tokio::spawn(async move {
        while let Some(f) = out_rx.recv().await {
            let Ok(bytes) = to_frame(&f) else { break };
            if wr.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

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
    ))
}

impl Conn {
    pub async fn connect(host: &str, port: u16, fpr: [u8; 32]) -> Result<Conn, NetError> {
        let (link, pushes) = open(host, port, fpr).await?;
        Ok(Conn {
            host: host.to_string(),
            port,
            fpr,
            link,
            pushes,
            next_id: AtomicU32::new(1),
            keys: Mutex::new(vec![]),
        })
    }

    pub fn is_alive(&self) -> bool {
        self.link.alive.load(Ordering::SeqCst)
    }

    /// Sends a request and waits for its reply.
    pub async fn request(&self, body: Request) -> Result<Response, NetError> {
        if !self.is_alive() {
            return Err(NetError::Disconnected);
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
            Ok(Ok(Response::Error(e))) => Err(NetError::Server(e)),
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
        let (link, pushes) = open(&self.host, self.port, self.fpr).await?;
        self.link = link;
        self.pushes = pushes;
        let keys: Vec<KeyPair> = self.keys.lock().unwrap().clone();
        for k in &keys {
            self.prove(k).await?;
        }
        Ok(())
    }
}
