//! A 0.4.0 app must skip every app message added since, and 0.5.0 must
//! encode the old ones byte for byte as 0.4.0 did.

#[path = "fixtures/appmsg_v040.rs"]
mod v040;

use socketchat_core::appmsg::{AppMsg, Extension};
use socketchat_core::files::FileOffer;
use socketchat_core::keys::{Binding, GroupId, Key, Sig, Voucher};
use socketchat_proto::msg::FileId;
use socketchat_proto::Token;

fn key(n: u8) -> Key {
    Key([n; 32])
}

fn group(n: u8) -> GroupId {
    GroupId([n; 16])
}

fn token(n: u8) -> Token {
    Token([n; 16])
}

fn binding() -> Binding {
    Binding {
        group: group(1),
        group_key: key(2),
        identity: key(3),
        sig: Sig([4; 64]),
    }
}

fn voucher() -> Voucher {
    Voucher {
        token: token(5),
        secret_hash: [6; 32],
        group: group(1),
        inviter_group_key: key(2),
        expires_unix: 1_700_000_000,
        inviter_identity: key(3),
        sig: Sig([7; 64]),
    }
}

fn offer() -> FileOffer {
    FileOffer {
        id: FileId([8; 16]),
        name: "photo.png".into(),
        size: 1234,
        mime: "image/png".into(),
        sha256: [9; 32],
        key: [10; 32],
        nonce_prefix: [11; 19],
    }
}

#[test]
fn new_variants_are_skipped_by_0_4_0() {
    let new = [
        AppMsg::Extension(Extension {
            namespace: "demo".into(),
            kind: "note".into(),
            version: 1,
            body: vec![1, 2, 3],
            summary: Some("a note".into()),
        }),
        AppMsg::AppInfo {
            app_version: "0.5.0".into(),
        },
        AppMsg::CloseVote {
            close_id: [1; 16],
            yes: true,
        },
        AppMsg::Closed { close_id: [2; 16] },
    ];
    for msg in new {
        let bytes = msg.encode();
        let old = std::panic::catch_unwind(|| v040::AppMsg::decode(&bytes))
            .expect("a 0.4.0 app must not panic on a new message");
        assert_eq!(old, None, "0.4.0 must skip {msg:?}");
        assert_eq!(AppMsg::decode(&bytes), Some(msg));
    }
}

#[test]
fn old_variants_encode_as_0_4_0_did() {
    let pairs: Vec<(AppMsg, v040::AppMsg)> = vec![
        (
            AppMsg::Text { body: "hi".into() },
            v040::AppMsg::Text { body: "hi".into() },
        ),
        (
            AppMsg::Profile {
                display_name: "Ada".into(),
                binding: binding(),
            },
            v040::AppMsg::Profile {
                display_name: "Ada".into(),
                binding: binding(),
            },
        ),
        (
            AppMsg::GroupName { name: "g".into() },
            v040::AppMsg::GroupName { name: "g".into() },
        ),
        (
            AppMsg::Voucher {
                voucher: voucher(),
                request_key: key(12),
                seal_key: [13; 32],
            },
            v040::AppMsg::Voucher {
                voucher: voucher(),
                request_key: key(12),
                seal_key: [13; 32],
            },
        ),
        (AppMsg::File(offer()), v040::AppMsg::File(offer())),
        (AppMsg::IsDm, v040::AppMsg::IsDm),
        (
            AppMsg::DmRequest {
                to: key(14),
                group: group(15),
                token: token(16),
                dm_key: key(17),
            },
            v040::AppMsg::DmRequest {
                to: key(14),
                group: group(15),
                token: token(16),
                dm_key: key(17),
            },
        ),
        (
            AppMsg::DmAccept {
                to: key(14),
                group: group(15),
                token: token(16),
                key_packages: vec![1, 2, 3],
            },
            v040::AppMsg::DmAccept {
                to: key(14),
                group: group(15),
                token: token(16),
                key_packages: vec![1, 2, 3],
            },
        ),
        (
            AppMsg::InviteProof {
                token: token(18),
                proof: [19; 32],
            },
            v040::AppMsg::InviteProof {
                token: token(18),
                proof: [19; 32],
            },
        ),
    ];
    for (new, old) in pairs {
        let bytes = postcard::to_stdvec(&old).unwrap();
        assert_eq!(new.encode(), bytes, "{new:?}");
        assert_eq!(v040::AppMsg::decode(&bytes), Some(old));
        assert_eq!(AppMsg::decode(&bytes), Some(new));
    }
}

#[test]
fn later_variants_are_skipped_by_0_5_0() {
    assert_eq!(AppMsg::decode(&[40, 1, 2, 3]), None);
}
