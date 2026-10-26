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

/// Join page that shows a friend how to install socketchat. The invite
/// goes after `#`, which browsers never send to the web server. The QR
/// code in the invite box holds this form, since a phone camera opens web
/// addresses and has no app for `socketchat://`.
pub const WEB_JOIN_URL: &str = "https://socketchat.org/join";

/// The web form of a `socketchat://` link, or `None` for anything else.
pub fn to_web_link(link: &str) -> Option<String> {
    let link = link.trim();
    link.starts_with(SCHEME)
        .then(|| format!("{WEB_JOIN_URL}#{link}"))
}

/// Where people learn to install Socketchat.
pub const SITE_URL: &str = "https://socketchat.org";

/// What the invite box copies: a line about Socketchat, where to install
/// it and the command that uses `link`, ready to paste into a terminal.
/// The quotes keep the link whole in every shell. It names the computer
/// because the message is often read on a phone, where Socketchat does
/// not run.
pub fn invite_message(link: &str) -> String {
    format!(
        "Join me on Socketchat, an encrypted chat.\n1. Install it on your computer from {SITE_URL}\n2. Then run: socketchat join \"{}\"",
        link.trim()
    )
}

/// The `socketchat://` link inside a web link, or `None` when the text is
/// not a web link made by [`to_web_link`]. The address a browser shows
/// after the page's redirect to `/join/` counts too.
pub fn from_web_link(web: &str) -> Option<&str> {
    join_page_fragment(web).filter(|bare| bare.starts_with(SCHEME))
}

/// The part after `#` of an address of the join page, empty when it has
/// none, or `None` for any other text. Only the exact address counts:
/// `https`, `socketchat.org` in lower case, path `/join` or `/join/`, and
/// nothing between the path and `#`.
fn join_page_fragment(web: &str) -> Option<&str> {
    let rest = web.trim().strip_prefix(WEB_JOIN_URL)?;
    let rest = rest.strip_prefix('/').unwrap_or(rest);
    if rest.is_empty() {
        return Some(rest);
    }
    rest.strip_prefix('#')
}

/// Whether `text` is a web address, in any mix of upper and lower case.
fn is_web_address(text: &str) -> bool {
    let t = text.trim().as_bytes();
    [b"http://".as_slice(), b"https://"]
        .iter()
        .any(|p| t.len() >= p.len() && t[..p.len()].eq_ignore_ascii_case(p))
}

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
    #[error("the server address in the link is not a name or an IP address")]
    Host,
    #[error("the port in the link is not a number")]
    Port,
    #[error("the link is missing its invite token")]
    Token,
    #[error("the part after # is cut short or changed; ask for a fresh link")]
    Fragment,
    /// A web address other than the join page.
    #[error("the only web address that carries an invite is https://socketchat.org/join")]
    Web,
}

/// Longest host name DNS allows, in characters.
const MAX_HOST: usize = 253;

/// Whether `host` is a server address a link may carry: an IPv4 or IPv6
/// address, or a host name made of ASCII letters, digits, hyphens and
/// underscores in dot-separated labels of 1 to 63 characters, none
/// starting or ending with a hyphen. That leaves out spaces, control
/// characters and every character outside ASCII, so a host prints safely
/// and cannot pass for another name written in look-alike letters. A name
/// in another script travels in its ASCII form (`xn--...`), which is what
/// DNS looks up anyway.
pub fn valid_host(host: &str) -> bool {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    let name = host.strip_suffix('.').unwrap_or(host);
    !name.is_empty()
        && name.len() <= MAX_HOST
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Splits `addr`, the part before `/j/`, into host and port. An IPv6
/// address comes in brackets (`[::1]:7444`), or bare with the port after
/// its last colon, as older servers wrote it.
fn host_and_port(addr: &str) -> Result<(&str, u16), LinkError> {
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or(LinkError::Host)?;
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(LinkError::Host);
        }
        let port = match after {
            "" => crate::DEFAULT_PORT,
            p => p
                .strip_prefix(':')
                .ok_or(LinkError::Host)?
                .parse()
                .map_err(|_| LinkError::Port)?,
        };
        return Ok((host, port));
    }
    match addr.rsplit_once(':') {
        Some((h, p)) => Ok((h, p.parse().map_err(|_| LinkError::Port)?)),
        None => Ok((addr, crate::DEFAULT_PORT)),
    }
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
        // A link is only ever read here, never opened: nothing in it,
        // the part after `#` least of all, goes to a web server.
        let s = s.trim();
        let s = match join_page_fragment(s) {
            Some(bare) if bare.starts_with(SCHEME) => bare,
            Some(_) => return Err(LinkError::Fragment),
            None if is_web_address(s) => return Err(LinkError::Web),
            None => s,
        };
        let rest = s.strip_prefix(SCHEME).ok_or(LinkError::Scheme)?;
        let (addr, rest) = rest.split_once("/j/").ok_or(LinkError::Token)?;
        let (token, fragment) = rest.split_once('#').ok_or(LinkError::Fragment)?;
        let (host, port) = host_and_port(addr)?;
        if !valid_host(host) {
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
        let s = group_link().to_string().replace("socketchat://", "chat://");
        assert_eq!(s.parse::<InviteLink>(), Err(LinkError::Scheme));
    }

    #[test]
    fn link_rejects_bad_fragment_len() {
        let s = group_link().to_string();
        let cut = &s[..s.len() - 3];
        assert!(cut.parse::<InviteLink>().is_err());
        let two_parts = s.rsplit_once('.').unwrap().0;
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

    fn with_host(addr: &str) -> String {
        group_link()
            .to_string()
            .replace("chat.example.com:7444", addr)
    }

    #[test]
    fn link_refuses_a_host_that_is_not_a_name_or_address() {
        for addr in [
            "evil\u{1b}[31m.example.com:7444",
            "evil\u{7}.example.com:7444",
            "two words:7444",
            "user@chat.example.com:7444",
            "chat.example.com?x=1:7444",
            "chat.example.com/x:7444",
            "-chat.example.com:7444",
            "chat-.example.com:7444",
            "chat..example.com:7444",
            ".:7444",
            "pаypal.com:7444",
            "chat.example.com\u{202e}moc:7444",
            "xn--pypal-4ve.com\u{200b}:7444",
            "[::1:7444",
            "[not an address]:7444",
            "[::1]x:7444",
        ] {
            assert_eq!(
                with_host(addr).parse::<InviteLink>(),
                Err(LinkError::Host),
                "{addr:?}"
            );
        }
        let long = format!("{}.com:7444", "a".repeat(64));
        assert_eq!(with_host(&long).parse::<InviteLink>(), Err(LinkError::Host));
        let too_long = format!("{}com:7444", "abcdefghi.".repeat(26));
        assert_eq!(
            with_host(&too_long).parse::<InviteLink>(),
            Err(LinkError::Host)
        );
    }

    #[test]
    fn link_takes_names_and_addresses() {
        for (addr, host, port) in [
            ("localhost:7444", "localhost", 7444),
            ("Chat.Example.com:7444", "Chat.Example.com", 7444),
            ("chat.example.com.:7444", "chat.example.com.", 7444),
            ("xn--pypal-4ve.com:7444", "xn--pypal-4ve.com", 7444),
            ("home_box.lan:7444", "home_box.lan", 7444),
            ("10.0.0.7:9000", "10.0.0.7", 9000),
            ("[::1]:7444", "::1", 7444),
            ("[2001:db8::7]", "2001:db8::7", crate::DEFAULT_PORT),
            ("2001:db8::7:7444", "2001:db8::7", 7444),
        ] {
            let l = with_host(addr).parse::<InviteLink>().unwrap();
            assert_eq!((l.host.as_str(), l.port), (host, port), "{addr}");
        }
    }

    #[test]
    fn link_checks_a_host_given_in_code() {
        assert!(valid_host("chat.example.com"));
        assert!(valid_host("::1"));
        assert!(!valid_host("evil\u{1b}[2J"));
        assert!(!valid_host(""));
    }

    #[test]
    fn web_link_roundtrip() {
        let bare = group_link().to_string();
        let web = to_web_link(&bare).unwrap();
        assert_eq!(web, format!("https://socketchat.org/join#{bare}"));
        assert_eq!(from_web_link(&web), Some(bare.as_str()));
        assert_eq!(web.parse::<InviteLink>().unwrap(), group_link());
    }

    #[test]
    fn invite_message_holds_a_command_to_paste() {
        let bare = group_link().to_string();
        assert_eq!(
            invite_message(&format!(" {bare}\n")),
            format!(
                "Join me on Socketchat, an encrypted chat.\n1. Install it on your computer from https://socketchat.org\n2. Then run: socketchat join \"{bare}\""
            )
        );
    }

    #[test]
    fn web_link_needs_a_socketchat_link() {
        assert_eq!(to_web_link("https://example.com/x"), None);
        assert_eq!(to_web_link(""), None);
    }

    #[test]
    fn web_link_without_fragment_is_not_one() {
        assert_eq!(from_web_link("https://socketchat.org/join"), None);
        assert_eq!(from_web_link("socketchat://chat.example.com/j/x#y"), None);
    }

    #[test]
    fn web_link_wrong_host_is_not_one() {
        let bare = group_link().to_string();
        let web = format!("https://example.com/join#{bare}");
        assert_eq!(from_web_link(&web), None);
        assert_eq!(web.parse::<InviteLink>(), Err(LinkError::Web));
    }

    #[test]
    fn web_link_empty_fragment_is_a_bad_link() {
        for web in [
            WEB_JOIN_URL.to_string(),
            format!("{WEB_JOIN_URL}/"),
            format!("{WEB_JOIN_URL}#"),
            format!("{WEB_JOIN_URL}/#"),
            format!("{WEB_JOIN_URL}#nonsense"),
            format!("{WEB_JOIN_URL}#https://example.com"),
        ] {
            assert_eq!(web.parse::<InviteLink>(), Err(LinkError::Fragment), "{web}");
        }
    }

    #[test]
    fn web_link_roundtrip_server_invite() {
        let l = InviteLink {
            inviter_fpr: None,
            secret: None,
            ..group_link()
        };
        let bare = l.to_string();
        let web = to_web_link(&bare).unwrap();
        assert_eq!(from_web_link(&web), Some(bare.as_str()));
        assert_eq!(web.parse::<InviteLink>().unwrap(), l);
    }

    #[test]
    fn web_link_with_a_slash_before_the_hash_is_one() {
        // The join page lives at /join/, and a browser that followed the
        // redirect shows that address.
        let bare = group_link().to_string();
        let web = format!("https://socketchat.org/join/#{bare}");
        assert_eq!(from_web_link(&web), Some(bare.as_str()));
        assert_eq!(web.parse::<InviteLink>().unwrap(), group_link());
    }

    #[test]
    fn other_web_addresses_are_refused_plainly() {
        let bare = group_link().to_string();
        for web in [
            "https://example.com/nope".to_string(),
            format!("https://example.com/join#{bare}"),
            format!("http://socketchat.org/join#{bare}"),
            format!("https://www.socketchat.org/join#{bare}"),
            format!("https://socketchat.org/joinme#{bare}"),
            format!("https://socketchat.org/join?x=1#{bare}"),
            format!("https://socketchat.org.example.com/join#{bare}"),
            format!("https://socketchat.org@example.com/join#{bare}"),
            format!("HTTPS://SOCKETCHAT.ORG/JOIN#{bare}"),
            format!("https://socketchat.org/join#https://socketchat.org/join#{bare}"),
        ] {
            assert_eq!(from_web_link(&web), None, "{web}");
            let e = web.parse::<InviteLink>().unwrap_err();
            assert!(
                matches!(e, LinkError::Web | LinkError::Fragment),
                "{web}: {e:?}"
            );
        }
        assert_eq!(
            LinkError::Web.to_string(),
            "the only web address that carries an invite is https://socketchat.org/join"
        );
    }

    #[test]
    fn a_web_link_is_checked_as_strictly_as_the_raw_link() {
        // The link inside goes through the same host check.
        let bad = group_link()
            .to_string()
            .replace("chat.example.com", "evil\u{1b}[2J.example.com");
        let web = format!("{WEB_JOIN_URL}#{bad}");
        assert_eq!(web.parse::<InviteLink>(), Err(LinkError::Host));
    }
}
