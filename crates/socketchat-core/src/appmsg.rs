//! What travels inside a group's encrypted application messages. The server
//! never sees any of it.

use serde::{Deserialize, Serialize};

use socketchat_proto::Token;

use crate::keys::{verify, Binding, GroupId, Key, KeyPair, Sig, Voucher, CTX_TOPIC};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum AppMsg {
    Text {
        body: String,
    },
    /// A member's display name, and their identity key vouching for their
    /// key in this group.
    Profile {
        display_name: String,
        binding: Binding,
    },
    GroupName {
        name: String,
    },
    /// An invite link's signed voucher, the public key that checks the
    /// joiner's signed request, and a key derived from the link's secret
    /// that seals the voucher for them. Any admin can complete the join with
    /// these, and no member can make a request of their own. The secret
    /// itself stays with the link's maker and the joiner.
    Voucher {
        voucher: Voucher,
        request_key: Key,
        seal_key: [u8; 32],
    },
    /// A file uploaded in sealed chunks, with what it takes to open it.
    File(crate::files::FileOffer),
    /// Marks a group as a two-person direct message.
    IsDm,
    /// Asks the member with group key `to` to open a direct message: the new
    /// chat is `group`, `token` lets them register a mailbox in it, and
    /// `dm_key` is the asker's key in the new chat, the one that will add them.
    DmRequest {
        to: Key,
        group: GroupId,
        token: Token,
        dm_key: Key,
    },
    /// Answers a DmRequest with KeyPackages for the new chat.
    DmAccept {
        to: Key,
        group: GroupId,
        token: Token,
        #[serde(with = "serde_bytes")]
        key_packages: Vec<u8>,
    },
    /// A joiner's proof, made from the invite secret, that they hold the
    /// link `token` belongs to. Only the link's maker can check it.
    InviteProof {
        token: Token,
        proof: [u8; 32],
    },
    /// A message for an add-on: `namespace` names the add-on, `kind` the sort
    /// of message, `version` the layout of `body`. An app with no add-on for
    /// the namespace shows `summary`, or nothing.
    Extension(Extension),
    /// The app version a member runs, so others know what it can read.
    AppInfo {
        app_version: String,
    },
    /// A member's vote on closing the room that close request `close_id`
    /// asks to end.
    CloseVote {
        close_id: [u8; 16],
        yes: bool,
    },
    /// Close request `close_id` passed: the room has ended.
    Closed {
        close_id: [u8; 16],
    },
    /// The room's topic, or its removal.
    Topic(Topic),
}

/// A room's topic: one line, set by an admin, or by anyone when the room
/// allows it. Empty text removes the topic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Topic {
    pub text: String,
    /// The group key of the member who set it.
    pub set_by: Key,
    /// When they set it, on their clock.
    pub set_unix: u64,
    /// `set_by` over the room, the time and the text, so whoever passes
    /// the topic on cannot change who set it, or what it says.
    pub sig: Sig,
    /// Passed on for someone who joined: an app takes it only while it
    /// has no topic for the room.
    pub repost: bool,
}

impl Topic {
    /// A topic `signer`, a member's key in `group`, sets now.
    pub fn new(signer: &KeyPair, group: GroupId, text: &str, set_unix: u64) -> Topic {
        Topic {
            text: text.to_string(),
            set_by: signer.public(),
            set_unix,
            sig: signer.sign(CTX_TOPIC, &topic_msg(&group, set_unix, text)),
            repost: false,
        }
    }

    /// Whether `set_by` signed this topic for `group`.
    pub fn verify(&self, group: &GroupId) -> bool {
        verify(
            &self.set_by,
            CTX_TOPIC,
            &topic_msg(group, self.set_unix, &self.text),
            &self.sig,
        )
    }
}

/// What a topic's signature covers: group ID (16) || set time as
/// big-endian u64 (8) || the text.
fn topic_msg(group: &GroupId, set_unix: u64, text: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(24 + text.len());
    m.extend_from_slice(&group.0);
    m.extend_from_slice(&set_unix.to_be_bytes());
    m.extend_from_slice(text.as_bytes());
    m
}

/// Longest summary of an extension message, in characters.
pub const MAX_SUMMARY_CHARS: usize = 200;
/// Longest app version, in characters.
pub const MAX_APP_VERSION_CHARS: usize = 32;

/// One message for an add-on, carried inside the group's encrypted messages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extension {
    pub namespace: String,
    pub kind: String,
    pub version: u16,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    pub summary: Option<String>,
}

impl Extension {
    /// Whether `namespace` and `kind` are written the way every app expects.
    pub fn check(&self) -> Result<(), &'static str> {
        let word = |s: &str, extra: &[u8]| {
            (1..=32).contains(&s.len())
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || extra.contains(&b))
        };
        if !word(&self.namespace, b"-") {
            return Err("an extension's namespace must be 1 to 32 characters of a-z, 0-9 and -");
        }
        if !word(&self.kind, b"._-") {
            return Err("an extension's kind must be 1 to 32 characters of a-z, 0-9, ., _ and -");
        }
        Ok(())
    }
}

impl AppMsg {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("app messages always encode")
    }

    pub fn decode(b: &[u8]) -> Option<AppMsg> {
        postcard::from_bytes(b).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(namespace: &str, kind: &str) -> Extension {
        Extension {
            namespace: namespace.into(),
            kind: kind.into(),
            version: 1,
            body: Vec::new(),
            summary: None,
        }
    }

    use crate::keys::KeyPair;

    /// The topic is variant 13, after every variant an app up to 0.5.1
    /// knows, so the numbers of the others stay as they were.
    #[test]
    fn a_topic_is_variant_13() {
        let k = KeyPair::generate();
        let t = Topic::new(&k, GroupId([1; 16]), "Saturday at noon", 1_700_000_000);
        let b = AppMsg::Topic(t.clone()).encode();
        assert_eq!(b[0], 13);
        assert_eq!(AppMsg::decode(&b), Some(AppMsg::Topic(t)));
        assert_eq!(AppMsg::IsDm.encode(), [5]);
        assert_eq!(AppMsg::Closed { close_id: [0; 16] }.encode()[0], 12);
    }

    /// An app up to 0.5.1 knows variants 0 to 12. Postcard refuses a
    /// variant number past the last one, so such an app reads a topic as
    /// no message at all and goes on.
    #[test]
    fn an_app_up_to_0_5_1_reads_a_topic_as_nothing() {
        #[allow(dead_code)]
        #[derive(Debug, Deserialize)]
        enum Old {
            V0,
            V1,
            V2,
            V3,
            V4,
            V5,
            V6,
            V7,
            V8,
            V9,
            V10,
            V11,
            V12,
        }
        let k = KeyPair::generate();
        let b = AppMsg::Topic(Topic::new(&k, GroupId([1; 16]), "hi", 1)).encode();
        assert!(postcard::from_bytes::<Old>(&b).is_err());
        assert!(postcard::from_bytes::<Old>(&AppMsg::IsDm.encode()).is_ok());
    }

    #[test]
    fn a_topic_signature_covers_room_time_and_text() {
        let k = KeyPair::generate();
        let g = GroupId([7; 16]);
        let t = Topic::new(&k, g, "Book club: Piranesi", 100);
        assert_eq!(t.set_by, k.public());
        assert!(t.verify(&g));
        assert!(!t.verify(&GroupId([8; 16])), "another room");
        let mut x = t.clone();
        x.text.push('!');
        assert!(!x.verify(&g), "other text");
        let mut x = t.clone();
        x.set_unix = 101;
        assert!(!x.verify(&g), "another time");
        let mut x = t.clone();
        x.set_by = KeyPair::generate().public();
        assert!(!x.verify(&g), "another setter");
        let mut x = t.clone();
        x.repost = true;
        assert!(x.verify(&g), "passing it on keeps the signature");
        let cleared = Topic::new(&k, g, "", 200);
        assert!(cleared.verify(&g));
    }

    #[test]
    fn extension_check_rules() {
        assert!(ext("demo", "note.reply").check().is_ok());
        assert!(ext("demo-2", "a_b-c.d").check().is_ok());
        assert!(ext(&"a".repeat(32), &"k".repeat(32)).check().is_ok());
        for bad in ["", &"a".repeat(33), "Demo", "my demo", "a.b", "a_b"] {
            assert_eq!(
                ext(bad, "note").check(),
                Err("an extension's namespace must be 1 to 32 characters of a-z, 0-9 and -"),
                "namespace {bad:?}"
            );
        }
        for bad in ["", &"k".repeat(33), "Note", "note reply", "a/b"] {
            assert_eq!(
                ext("demo", bad).check(),
                Err("an extension's kind must be 1 to 32 characters of a-z, 0-9, ., _ and -"),
                "kind {bad:?}"
            );
        }
    }
}
