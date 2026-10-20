//! A bare test client: pinned TLS plus frames, nothing else.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use socketchat_core::keys::{KeyPair, CTX_AUTH};
use socketchat_proto::msg::{from_body, to_frame, ClientFrame, Request, Response, ServerFrame};
use socketchat_proto::FrameDecoder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

#[derive(Debug)]
struct Pinned([u8; 32]);

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if <[u8; 32]>::from(Sha256::digest(end.as_ref())) == self.0 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("pin mismatch".into()))
        }
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("tls1.2".into()))
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            c,
            d,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub struct Raw {
    s: TlsStream<TcpStream>,
    d: FrameDecoder,
    next_id: u32,
}

impl Raw {
    pub async fn connect(addr: SocketAddr, fpr: [u8; 32]) -> Raw {
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned(fpr)))
        .with_no_client_auth();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let s = TlsConnector::from(Arc::new(cfg))
            .connect(ServerName::try_from("socketchat").unwrap(), tcp)
            .await
            .unwrap();
        Raw {
            s,
            d: FrameDecoder::default(),
            next_id: 1,
        }
    }

    pub async fn send(&mut self, f: &ClientFrame) {
        self.s.write_all(&to_frame(f).unwrap()).await.unwrap();
        self.s.flush().await.unwrap();
    }

    /// Next frame, or None when the server closed the connection.
    pub async fn recv(&mut self) -> Option<ServerFrame> {
        loop {
            if let Some(b) = self.d.next_frame().unwrap() {
                return Some(from_body(&b).unwrap());
            }
            let mut buf = [0u8; 8192];
            let n = match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.s.read(&mut buf),
            )
            .await
            .expect("server stalled")
            {
                Ok(n) => n,
                Err(_) => return None,
            };
            if n == 0 {
                return None;
            }
            self.d.push(&buf[..n]);
        }
    }

    pub async fn hello(&mut self) {
        self.send(&ClientFrame::Hello {
            version: socketchat_proto::PROTOCOL_VERSION,
        })
        .await;
        assert!(matches!(
            self.recv().await,
            Some(ServerFrame::HelloOk { .. })
        ));
    }

    pub async fn req(&mut self, body: Request) -> Response {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&ClientFrame::Req { id, body }).await;
        loop {
            match self.recv().await.expect("connection closed") {
                ServerFrame::Resp { id: rid, body } if rid == id => return body,
                ServerFrame::Push(_) => continue,
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    pub async fn challenge(&mut self) -> [u8; 32] {
        match self.req(Request::Challenge).await {
            Response::Challenge(c) => c,
            r => panic!("{r:?}"),
        }
    }
}

pub fn auth_sig(k: &KeyPair, challenge: &[u8; 32]) -> socketchat_proto::msg::Sig {
    k.sign(CTX_AUTH, &[challenge.as_slice(), &k.public().0].concat())
}
