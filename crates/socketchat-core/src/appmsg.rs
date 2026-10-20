//! What travels inside a group's encrypted application messages. The server
//! never sees any of it.

use serde::{Deserialize, Serialize};

use crate::keys::{Binding, Voucher};

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
    /// An invite link's voucher and secret, so any member can check the
    /// joiner's request and an admin can complete it.
    Voucher {
        voucher: Voucher,
        secret: [u8; 32],
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
