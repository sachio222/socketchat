//! Invite links.
//!
//! `socketchat://host:port/j/<token>#<cert-fpr>[.<inviter-fpr>.<invite-secret>]`
//!
//! Every value is base64url without padding. The part after `#` is the link
//! fragment: clients never send it to the server.

use std::fmt;
use std::str::FromStr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const SCHEME: &str = "socketchat://";

/// Random invite token the server stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Token(pub [u8; 16]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteLink {
    pub host: String,
    pub port: u16,
    pub token: Token,
    /// SHA-256 of the server's TLS certificate.
    pub cert_fpr: [u8; 32],
    /// Fingerprint of the inviter's identity key. Absent on server invites.
    pub inviter_fpr: Option<[u8; 32]>,
    /// Secret only clients see. Absent on server invites.
    pub secret: Option<[u8; 32]>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LinkError {
    #[error("an invite link starts with socketchat://")]
    Scheme,
    #[error("the link has no server address")]
    Host,
    #[error("the port in the link is not a number")]
    Port,
    #[error("the link is missing its invite token")]
    Token,
    #[error("the part after # is cut short or changed; ask for a fresh link")]
    Fragment,
}

fn b64<const N: usize>(s: &str) -> Option<[u8; N]> {
    B64.decode(s).ok()?.try_into().ok()
}

impl fmt::Display for InviteLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{SCHEME}{}:{}/j/{}#{}",
            self.host,
            self.port,
            B64.encode(self.token.0),
            B64.encode(self.cert_fpr)
        )?;
        if let (Some(i), Some(s)) = (self.inviter_fpr, self.secret) {
            write!(f, ".{}.{}", B64.encode(i), B64.encode(s))?;
        }
        Ok(())
    }
}

impl FromStr for InviteLink {
    type Err = LinkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s.trim().strip_prefix(SCHEME).ok_or(LinkError::Scheme)?;
        let (addr, rest) = rest.split_once("/j/").ok_or(LinkError::Token)?;
        let (token, fragment) = rest.split_once('#').ok_or(LinkError::Fragment)?;
        let (host, port) = match addr.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().map_err(|_| LinkError::Port)?),
            None => (addr, crate::DEFAULT_PORT),
        };
        if host.is_empty() {
            return Err(LinkError::Host);
        }
        let token = Token(b64(token).ok_or(LinkError::Token)?);
        let parts: Vec<&str> = fragment.split('.').collect();
        let cert_fpr = b64(parts[0]).ok_or(LinkError::Fragment)?;
        let (inviter_fpr, secret) = match parts.len() {
            1 => (None, None),
            3 => (
                Some(b64(parts[1]).ok_or(LinkError::Fragment)?),
                Some(b64(parts[2]).ok_or(LinkError::Fragment)?),
            ),
            _ => return Err(LinkError::Fragment),
        };
        Ok(InviteLink {
            host: host.to_string(),
            port,
            token,
            cert_fpr,
            inviter_fpr,
            secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group_link() -> InviteLink {
        InviteLink {
            host: "chat.example.com".into(),
            port: 7444,
            token: Token([1; 16]),
            cert_fpr: [2; 32],
            inviter_fpr: Some([3; 32]),
            secret: Some([4; 32]),
        }
    }

    #[test]
    fn link_roundtrip_group_invite() {
        let l = group_link();
        let s = l.to_string();
        assert!(s.starts_with("socketchat://chat.example.com:7444/j/"));
        assert_eq!(s.parse::<InviteLink>().unwrap(), l);
    }

    #[test]
    fn link_roundtrip_server_invite() {
        let l = InviteLink {
            inviter_fpr: None,
            secret: None,
            ..group_link()
        };
        let s = l.to_string();
        assert_eq!(s.matches('.').count(), 2, "only the host dots: {s}");
        assert_eq!(s.parse::<InviteLink>().unwrap(), l);
    }

    #[test]
    fn link_rejects_wrong_scheme() {
        let s = group_link()
            .to_string()
            .replace("socketchat://", "https://");
        assert_eq!(s.parse::<InviteLink>(), Err(LinkError::Scheme));
    }

    #[test]
    fn link_rejects_bad_fragment_len() {
        let s = group_link().to_string();
        let cut = &s[..s.len() - 3];
        assert!(cut.parse::<InviteLink>().is_err());
        let two_parts = format!("{}", s.rsplit_once('.').unwrap().0);
        assert!(two_parts.parse::<InviteLink>().is_err());
    }

    #[test]
    fn link_default_port_when_missing() {
        let s = group_link().to_string().replace(":7444", "");
        assert_eq!(s.parse::<InviteLink>().unwrap().port, crate::DEFAULT_PORT);
    }

    #[test]
    fn link_accepts_ipv4_host() {
        let l = InviteLink {
            host: "192.168.1.20".into(),
            port: 9000,
            ..group_link()
        };
        assert_eq!(l.to_string().parse::<InviteLink>().unwrap(), l);
    }
}
