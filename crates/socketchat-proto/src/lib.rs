//! Wire messages, framing and invite links for socketchat.
//!
//! This crate holds no cryptography and does no I/O, so the client and the
//! server agree on bytes without sharing anything else.

pub mod frame;
pub mod link;
pub mod msg;

pub use frame::{encode_frame, FrameDecoder, FrameError, MAX_FRAME};
pub use link::{
    from_web_link, invite_message, to_web_link, valid_host, InviteLink, LinkError, Token, SITE_URL,
    WEB_JOIN_URL,
};

/// Newest protocol number: sent in the first frame of every connection.
pub const PROTOCOL_VERSION: u16 = 2;

/// Oldest protocol number a server still serves.
pub const MIN_PROTOCOL_VERSION: u16 = 1;

/// Port the server listens on unless its config says otherwise.
pub const DEFAULT_PORT: u16 = 7444;
