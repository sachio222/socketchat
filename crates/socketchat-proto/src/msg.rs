//! Messages that travel inside frames.
//!
//! The client sends [`ClientFrame`]s, the server sends [`ServerFrame`]s. Each
//! is encoded with postcard. MLS messages ride inside as opaque bytes.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{encode_frame, FrameError, Token};

/// Random ID of a group on a server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GroupId(pub [u8; 16]);

/// An Ed25519 public key: a group key, an account key, or an identity key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Key(pub [u8; 32]);

/// An Ed25519 signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sig(#[serde(with = "serde_bytes")] pub [u8; 64]);

/// Random ID of an uploaded file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileId(pub [u8; 16]);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ClientFrame {
    Hello { version: u16 },
    Req { id: u32, body: Request },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ServerFrame {
    HelloOk {
        version: u16,
    },
    VersionMismatch {
        server: u16,
    },
    Resp {
        id: u32,
        body: Response,
    },
    Push(Push),
    /// Sent instead of `HelloOk` when the server will not serve this
    /// connection now. The server closes the connection after it.
    Busy(Busy),
}

/// Why a server turned a connection away at Hello.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Busy {
    /// The server already serves `max_connections` connections.
    Full,
    /// The connection's address (an IPv6 address by its /64 network)
    /// already holds `max_per_ip` connections.
    Network,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Request {
    /// Ask for a random challenge to sign for this connection.
    Challenge,
    /// Prove this connection holds `key`.
    Prove {
        key: Key,
        sig: Sig,
    },
    /// Register a server account key with an invite token.
    RegisterAccount {
        token: Token,
        key: Key,
        sig: Sig,
    },
    /// Register a group key's mailbox. `token` is the group invite; `None`
    /// means a new group the proven account is about to create.
    RegisterMailbox {
        token: Option<Token>,
        key: Key,
        sig: Sig,
    },
    CreateGroup {
        #[serde(with = "serde_bytes")]
        group_info: Vec<u8>,
        #[serde(with = "serde_bytes")]
        ratchet_tree: Vec<u8>,
    },
    Post {
        group: GroupId,
        #[serde(with = "serde_bytes")]
        mls: Vec<u8>,
        welcome: Option<WelcomeOut>,
    },
    Fetch {
        group: GroupId,
        after: u64,
        limit: u16,
    },
    Ack {
        group: GroupId,
        seq: u64,
    },
    Members {
        group: GroupId,
    },
    CreateInvite {
        group: Option<GroupId>,
    },
    RedeemInvite {
        token: Token,
        #[serde(with = "serde_bytes")]
        key_package: Vec<u8>,
        mac: [u8; 32],
    },
    /// Join requests waiting in `group`, oldest first, as many as fit one
    /// reply. `after` is the (lodged time, token) of the last request the
    /// client already has; the reply starts strictly after it.
    PendingJoins {
        group: GroupId,
        after: Option<(u64, Token)>,
    },
    FetchWelcomes,
    FileBegin {
        group: GroupId,
        size: u64,
    },
    FileChunk {
        file: FileId,
        index: u32,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    FileEnd {
        file: FileId,
    },
    FileGet {
        file: FileId,
        index: u32,
    },
    FileDone {
        file: FileId,
    },
    /// Protocol 2. Open invite links this connection's keys made in groups,
    /// plus the server invites named by `server_tokens` (at most 100; the
    /// server keeps no record of who made a server invite).
    ListInvites {
        server_tokens: Vec<Token>,
    },
    /// Protocol 2. Cancels an open invite link the connection made.
    CancelInvite {
        token: Token,
    },
    /// Protocol 2. When `group` was created on this server.
    GroupCreated {
        group: GroupId,
    },
    /// Protocol 2. The only member leaves: the server deletes the group
    /// and everything it holds for it. Refused while anyone else is in it.
    LastLeave {
        group: GroupId,
    },
}

impl Request {
    /// The lowest protocol a connection must have said Hello with for the
    /// server to run this request. No catch-all arm: a new variant must be
    /// given its version here.
    pub fn min_version(&self) -> u16 {
        match self {
            Request::Challenge
            | Request::Prove { .. }
            | Request::RegisterAccount { .. }
            | Request::RegisterMailbox { .. }
            | Request::CreateGroup { .. }
            | Request::Post { .. }
            | Request::Fetch { .. }
            | Request::Ack { .. }
            | Request::Members { .. }
            | Request::CreateInvite { .. }
            | Request::RedeemInvite { .. }
            | Request::PendingJoins { .. }
            | Request::FetchWelcomes
            | Request::FileBegin { .. }
            | Request::FileChunk { .. }
            | Request::FileEnd { .. }
            | Request::FileGet { .. }
            | Request::FileDone { .. } => 1,
            Request::ListInvites { .. }
            | Request::CancelInvite { .. }
            | Request::GroupCreated { .. }
            | Request::LastLeave { .. } => 2,
        }
    }
}

/// An open invite link, as `Response::Invites` lists it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InviteInfo {
    pub token: Token,
    /// The group the link leads into; `None` for a server invite.
    pub group: Option<GroupId>,
    pub expires_unix: u64,
}

/// A Welcome for the person who redeemed `token`, with the inviter's voucher.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WelcomeOut {
    pub token: Token,
    #[serde(with = "serde_bytes")]
    pub welcome: Vec<u8>,
    /// The voucher sealed under a key from the invite secret, which the
    /// server never holds. Empty for a direct message.
    #[serde(with = "serde_bytes")]
    pub voucher: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Response {
    Ok,
    Challenge([u8; 32]),
    Posted {
        seq: u64,
    },
    /// A Commit lost the race; the group is at `epoch`.
    Conflict {
        epoch: u64,
    },
    /// The server checked the request and said no, with a reason for people.
    Refused(String),
    Entries(Vec<Entry>),
    Members(Vec<MemberInfo>),
    Invite {
        token: Token,
        expires_unix: u64,
    },
    JoinLodged,
    Joins(Vec<JoinRequest>),
    Welcomes(Vec<WelcomeIn>),
    File(FileId),
    Chunk(#[serde(with = "serde_bytes")] Vec<u8>),
    /// Something went wrong on the server or the request made no sense.
    Error(String),
    /// Protocol 2. Answers `ListInvites`, oldest expiry first.
    Invites(Vec<InviteInfo>),
    /// Protocol 2. Answers `GroupCreated`.
    GroupCreated {
        created_unix: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    #[serde(with = "serde_bytes")]
    pub mls: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemberInfo {
    pub key: Key,
    pub joined_seq: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JoinRequest {
    pub token: Token,
    #[serde(with = "serde_bytes")]
    pub key_package: Vec<u8>,
    pub mac: [u8; 32],
    pub lodged_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WelcomeIn {
    pub mailbox: Key,
    #[serde(with = "serde_bytes")]
    pub welcome: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub voucher: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Push {
    Entry {
        group: GroupId,
        entry: Entry,
    },
    Welcome(WelcomeIn),
    JoinRequest {
        group: GroupId,
        request: JoinRequest,
    },
}

/// Encodes `v` and wraps it in a frame.
pub fn to_frame<T: Serialize>(v: &T) -> Result<Vec<u8>, FrameError> {
    let body = postcard::to_stdvec(v).map_err(|e| FrameError::Postcard(e.to_string()))?;
    encode_frame(&body)
}

/// Decodes a frame body.
pub fn from_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, FrameError> {
    postcard::from_bytes(body).map_err(|e| FrameError::Postcard(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FrameDecoder, Token};

    fn rt<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(v: T) {
        let mut d = FrameDecoder::default();
        d.push(&to_frame(&v).unwrap());
        let body = d.next_frame().unwrap().unwrap();
        assert_eq!(from_body::<T>(&body).unwrap(), v);
    }

    #[test]
    fn every_request_roundtrips() {
        let g = GroupId([9; 16]);
        let k = Key([1; 32]);
        let s = Sig([2; 64]);
        let t = Token([3; 16]);
        let f = FileId([4; 16]);
        let w = WelcomeOut {
            token: t,
            welcome: vec![5; 10],
            voucher: vec![6; 4],
        };
        for body in [
            Request::Challenge,
            Request::Prove { key: k, sig: s },
            Request::RegisterAccount {
                token: t,
                key: k,
                sig: s,
            },
            Request::RegisterMailbox {
                token: Some(t),
                key: k,
                sig: s,
            },
            Request::RegisterMailbox {
                token: None,
                key: k,
                sig: s,
            },
            Request::CreateGroup {
                group_info: vec![1, 2],
                ratchet_tree: vec![3],
            },
            Request::Post {
                group: g,
                mls: vec![7; 100],
                welcome: Some(w.clone()),
            },
            Request::Post {
                group: g,
                mls: vec![],
                welcome: None,
            },
            Request::Fetch {
                group: g,
                after: 5,
                limit: 100,
            },
            Request::Ack { group: g, seq: 6 },
            Request::Members { group: g },
            Request::CreateInvite { group: Some(g) },
            Request::CreateInvite { group: None },
            Request::RedeemInvite {
                token: t,
                key_package: vec![8; 50],
                mac: [9; 32],
            },
            Request::PendingJoins {
                group: g,
                after: None,
            },
            Request::PendingJoins {
                group: g,
                after: Some((99, Token([2; 16]))),
            },
            Request::FetchWelcomes,
            Request::FileBegin {
                group: g,
                size: 1 << 33,
            },
            Request::FileChunk {
                file: f,
                index: 3,
                data: vec![0; 65536],
            },
            Request::FileEnd { file: f },
            Request::FileGet { file: f, index: 0 },
            Request::FileDone { file: f },
            Request::ListInvites {
                server_tokens: vec![t, Token([4; 16])],
            },
            Request::ListInvites {
                server_tokens: vec![],
            },
            Request::CancelInvite { token: t },
            Request::GroupCreated { group: g },
        ] {
            rt(ClientFrame::Req { id: 42, body });
        }
        rt(ClientFrame::Hello {
            version: crate::PROTOCOL_VERSION,
        });
    }

    #[test]
    fn every_response_and_push_roundtrips() {
        let g = GroupId([1; 16]);
        let entry = Entry {
            seq: 3,
            mls: vec![1, 2, 3],
        };
        let jr = JoinRequest {
            token: Token([2; 16]),
            key_package: vec![3],
            mac: [4; 32],
            lodged_unix: 99,
        };
        let wi = WelcomeIn {
            mailbox: Key([5; 32]),
            welcome: vec![6],
            voucher: vec![7],
        };
        for body in [
            Response::Ok,
            Response::Challenge([1; 32]),
            Response::Posted { seq: 1 },
            Response::Conflict { epoch: 4 },
            Response::Refused("no".into()),
            Response::Entries(vec![entry.clone()]),
            Response::Members(vec![MemberInfo {
                key: Key([8; 32]),
                joined_seq: 2,
            }]),
            Response::Invite {
                token: Token([1; 16]),
                expires_unix: 5,
            },
            Response::JoinLodged,
            Response::Joins(vec![jr.clone()]),
            Response::Welcomes(vec![wi.clone()]),
            Response::File(FileId([3; 16])),
            Response::Chunk(vec![1; 10]),
            Response::Error("bad".into()),
            Response::Invites(vec![
                InviteInfo {
                    token: Token([1; 16]),
                    group: Some(g),
                    expires_unix: 7,
                },
                InviteInfo {
                    token: Token([2; 16]),
                    group: None,
                    expires_unix: 8,
                },
            ]),
            Response::Invites(vec![]),
            Response::GroupCreated { created_unix: 99 },
        ] {
            rt(ServerFrame::Resp { id: 7, body });
        }
        rt(ServerFrame::HelloOk { version: 1 });
        rt(ServerFrame::VersionMismatch { server: 2 });
        rt(ServerFrame::Busy(Busy::Full));
        rt(ServerFrame::Busy(Busy::Network));
        rt(ServerFrame::Push(Push::Entry { group: g, entry }));
        rt(ServerFrame::Push(Push::Welcome(wi)));
        rt(ServerFrame::Push(Push::JoinRequest {
            group: g,
            request: jr,
        }));
    }

    #[test]
    fn min_version_marks_protocol_2_requests() {
        let g = GroupId([9; 16]);
        let k = Key([1; 32]);
        let s = Sig([2; 64]);
        let t = Token([3; 16]);
        let f = FileId([4; 16]);
        let v1 = [
            Request::Challenge,
            Request::Prove { key: k, sig: s },
            Request::RegisterAccount {
                token: t,
                key: k,
                sig: s,
            },
            Request::RegisterMailbox {
                token: None,
                key: k,
                sig: s,
            },
            Request::CreateGroup {
                group_info: vec![],
                ratchet_tree: vec![],
            },
            Request::Post {
                group: g,
                mls: vec![],
                welcome: None,
            },
            Request::Fetch {
                group: g,
                after: 0,
                limit: 1,
            },
            Request::Ack { group: g, seq: 1 },
            Request::Members { group: g },
            Request::CreateInvite { group: None },
            Request::RedeemInvite {
                token: t,
                key_package: vec![],
                mac: [0; 32],
            },
            Request::PendingJoins {
                group: g,
                after: None,
            },
            Request::FetchWelcomes,
            Request::FileBegin { group: g, size: 1 },
            Request::FileChunk {
                file: f,
                index: 0,
                data: vec![],
            },
            Request::FileEnd { file: f },
            Request::FileGet { file: f, index: 0 },
            Request::FileDone { file: f },
        ];
        for r in v1 {
            assert_eq!(r.min_version(), 1, "{r:?}");
        }
        for r in [
            Request::ListInvites {
                server_tokens: vec![],
            },
            Request::CancelInvite { token: t },
            Request::GroupCreated { group: g },
            Request::LastLeave { group: g },
        ] {
            assert_eq!(r.min_version(), 2, "{r:?}");
        }
    }

    #[test]
    fn protocol_numbers() {
        assert_eq!(crate::PROTOCOL_VERSION, 2);
        assert_eq!(crate::MIN_PROTOCOL_VERSION, 1);
    }

    #[test]
    fn hello_is_first_and_tiny() {
        let f = to_frame(&ClientFrame::Hello {
            version: crate::PROTOCOL_VERSION,
        })
        .unwrap();
        assert!(f.len() < 16, "{} bytes", f.len());
    }

    #[test]
    fn bytes_are_compact() {
        // 64 KiB of data costs only a few bytes of overhead.
        let f = to_frame(&ClientFrame::Req {
            id: 1,
            body: Request::FileChunk {
                file: FileId([0; 16]),
                index: 0,
                data: vec![0; 65536],
            },
        })
        .unwrap();
        assert!(f.len() < 65536 + 40, "{} bytes", f.len());
    }

    #[test]
    fn garbage_is_an_error() {
        assert!(from_body::<ClientFrame>(&[0xff, 0xff, 0xff]).is_err());
    }

    proptest::proptest! {
        #[test]
        fn decoder_never_panics(chunks in proptest::collection::vec(proptest::collection::vec(proptest::num::u8::ANY, 0..64), 0..16)) {
            let mut d = FrameDecoder::default();
            for c in chunks {
                d.push(&c);
                while let Ok(Some(body)) = d.next_frame() {
                    let _ = from_body::<ClientFrame>(&body);
                    let _ = from_body::<ServerFrame>(&body);
                }
            }
        }
    }
}
