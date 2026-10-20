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
}

impl AppMsg {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("app messages always encode")
    }

    pub fn decode(b: &[u8]) -> Option<AppMsg> {
        postcard::from_bytes(b).ok()
    }
}
