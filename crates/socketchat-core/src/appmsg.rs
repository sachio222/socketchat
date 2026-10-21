//! What travels inside a group's encrypted application messages. The server
//! never sees any of it.

use serde::{Deserialize, Serialize};

use socketchat_proto::Token;

use crate::keys::{Binding, GroupId, Key, Voucher};

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
