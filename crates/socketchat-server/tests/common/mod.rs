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

    /// Writes bytes as they are, for tests that pipeline many frames.
    pub async fn send_raw(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.s.write_all(bytes).await?;
        self.s.flush().await
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

// ---------- MLS helpers for group tests ----------

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use socketchat_core::suite::{capabilities, group_create_config, group_join_config};
use socketchat_proto::msg::{GroupId as Gid, WelcomeOut};
use socketchat_proto::Token;

/// One person in a test: a connection, a group key and their MLS state.
pub struct Person {
    pub conn: Raw,
    pub key: KeyPair,
    pub prov: OpenMlsRustCrypto,
    pub group: Option<MlsGroup>,
    pub gid: Option<Gid>,
    pub last_seq: u64,
}

pub fn ser(m: &MlsMessageOut) -> Vec<u8> {
    m.tls_serialize_detached().unwrap()
}

impl Person {
    pub async fn new(addr: SocketAddr, fpr: [u8; 32]) -> Person {
        let mut conn = Raw::connect(addr, fpr).await;
        conn.hello().await;
        Person {
            conn,
            key: KeyPair::generate(),
            prov: OpenMlsRustCrypto::default(),
            group: None,
            gid: None,
            last_seq: 0,
        }
    }

    /// Registers an account with a server invite, then a mailbox for a new
    /// group, then creates that group with `self` as the only admin.
    pub async fn create_group(&mut self, server_invite: Token, suite: Ciphersuite) -> Response {
        let acct = KeyPair::generate();
        let ch = self.conn.challenge().await;
        assert_eq!(
            self.conn
                .req(Request::RegisterAccount {
                    token: server_invite,
                    key: acct.public(),
                    sig: auth_sig(&acct, &ch)
                })
                .await,
            Response::Ok
        );
        let r = self
            .conn
            .req(Request::RegisterMailbox {
                token: None,
                key: self.key.public(),
                sig: auth_sig(&self.key, &ch),
            })
            .await;
        assert_eq!(r, Response::Ok);
        self.create_only(suite).await
    }

    pub async fn create_only(&mut self, suite: Ciphersuite) -> Response {
        let mut id = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
        let g = MlsGroup::new_with_group_id(
            &self.prov,
            &self.key,
            &group_create_config(suite, &[self.key.public()]),
            GroupId::from_slice(&id),
            self.key.credential(),
        )
        .unwrap();
        let gi = ser(&g
            .export_group_info(self.prov.crypto(), &self.key, false)
            .unwrap());
        let tree = g.export_ratchet_tree().tls_serialize_detached().unwrap();
        self.group = Some(g);
        self.gid = Some(Gid(id));
        self.conn
            .req(Request::CreateGroup {
                group_info: gi,
                ratchet_tree: tree,
            })
            .await
    }

    pub fn g(&mut self) -> &mut MlsGroup {
        self.group.as_mut().unwrap()
    }

    pub async fn invite(&mut self) -> Token {
        match self
            .conn
            .req(Request::CreateInvite { group: self.gid })
            .await
        {
            Response::Invite { token, .. } => token,
            r => panic!("{r:?}"),
        }
    }

    /// Registers this person's mailbox under a group invite token.
    pub async fn redeem_mailbox(&mut self, token: Token) -> Response {
        let ch = self.conn.challenge().await;
        self.conn
            .req(Request::RegisterMailbox {
                token: Some(token),
                key: self.key.public(),
                sig: auth_sig(&self.key, &ch),
            })
            .await
    }

    pub fn key_package(&self) -> KeyPackage {
        KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .build(
                socketchat_core::suite::SUITE,
                &self.prov,
                &self.key,
                self.key.credential(),
            )
            .unwrap()
            .key_package()
            .clone()
    }

    pub async fn post(&mut self, mls: Vec<u8>, welcome: Option<WelcomeOut>) -> Response {
        let gid = self.gid.unwrap();
        self.conn
            .req(Request::Post {
                group: gid,
                mls,
                welcome,
            })
            .await
    }

    /// Adds `kp` (registered under `token`) and posts the commit + welcome.
    pub async fn add(&mut self, kp: KeyPackage, token: Token) -> Response {
        let g = self.group.as_mut().unwrap();
        let (c, w, _) = g.add_members(&self.prov, &self.key, &[kp]).unwrap();
        let r = self
            .post(
                ser(&c),
                Some(WelcomeOut {
                    token,
                    welcome: ser(&w),
                    voucher: b"v".to_vec(),
                }),
            )
            .await;
        self.settle(&r);
        r
    }

    /// Merges the pending commit if the server took it, drops it otherwise.
    pub fn settle(&mut self, r: &Response) {
        let g = self.group.as_mut().unwrap();
        if matches!(r, Response::Posted { .. }) {
            g.merge_pending_commit(&self.prov).unwrap();
        } else {
            g.clear_pending_commit(self.prov.storage()).unwrap();
        }
    }

    /// Joins from the welcome the server pushed or stored.
    pub async fn join_from_welcome(&mut self, gid: Gid) {
        let ws = match self.conn.req(Request::FetchWelcomes).await {
            Response::Welcomes(ws) => ws,
            r => panic!("{r:?}"),
        };
        let w = ws
            .into_iter()
            .find(|w| w.mailbox == self.key.public())
            .expect("a welcome");
        let MlsMessageBodyIn::Welcome(w) = MlsMessageIn::tls_deserialize_exact(&w.welcome)
            .unwrap()
            .extract()
        else {
            panic!()
        };
        let g = StagedWelcome::new_from_welcome(&self.prov, &group_join_config(), w, None)
            .unwrap()
            .into_group(&self.prov)
            .unwrap();
        self.group = Some(g);
        self.gid = Some(gid);
        let ch = self.conn.challenge().await;
        assert_eq!(
            self.conn
                .req(Request::Prove {
                    key: self.key.public(),
                    sig: auth_sig(&self.key, &ch)
                })
                .await,
            Response::Ok
        );
        self.last_seq = match self.conn.req(Request::Members { group: gid }).await {
            Response::Members(ms) => {
                ms.iter()
                    .find(|m| m.key == self.key.public())
                    .unwrap()
                    .joined_seq
            }
            r => panic!("{r:?}"),
        };
    }

    /// Fetches and applies everything new in the group log.
    pub async fn catch_up(&mut self) {
        let gid = self.gid.unwrap();
        let es = match self
            .conn
            .req(Request::Fetch {
                group: gid,
                after: self.last_seq,
                limit: 500,
            })
            .await
        {
            Response::Entries(es) => es,
            r => panic!("{r:?}"),
        };
        for e in es {
            self.last_seq = e.seq;
            let pm = MlsMessageIn::tls_deserialize_exact(&e.mls)
                .unwrap()
                .try_into_protocol_message()
                .unwrap();
            let p = &self.prov;
            let g = self.group.as_mut().unwrap();
            if pm.epoch() < g.epoch() {
                continue;
            }
            // Our own messages do not open; skip them.
            if let Ok(m) = g.process_message(p, pm) {
                match m.into_content() {
                    ProcessedMessageContent::StagedCommitMessage(sc) => {
                        g.merge_staged_commit(p, *sc).unwrap()
                    }
                    ProcessedMessageContent::ProposalMessage(qp) => {
                        g.store_pending_proposal(p.storage(), *qp).unwrap()
                    }
                    _ => {}
                }
            }
        }
    }
}
