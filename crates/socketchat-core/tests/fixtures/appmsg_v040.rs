//! The `AppMsg` enum exactly as socketchat 0.4.0 shipped it (commit e4db1d0).
//! A 0.4.0 app decodes with this; it must refuse every variant added later.

use serde::{Deserialize, Serialize};

use socketchat_core::files::FileOffer;
use socketchat_core::keys::{Binding, GroupId, Key, Voucher};
use socketchat_proto::Token;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum AppMsg {
    Text {
        body: String,
    },
    Profile {
        display_name: String,
        binding: Binding,
    },
    GroupName {
        name: String,
    },
    Voucher {
        voucher: Voucher,
        request_key: Key,
        seal_key: [u8; 32],
    },
    File(FileOffer),
    IsDm,
    DmRequest {
        to: Key,
        group: GroupId,
        token: Token,
        dm_key: Key,
    },
    DmAccept {
        to: Key,
        group: GroupId,
        token: Token,
        #[serde(with = "serde_bytes")]
        key_packages: Vec<u8>,
    },
    InviteProof {
        token: Token,
        proof: [u8; 32],
    },
}

impl AppMsg {
    pub fn decode(b: &[u8]) -> Option<AppMsg> {
        postcard::from_bytes(b).ok()
    }
}
