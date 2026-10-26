//! Inviting someone you already share a room with to another room.
//!
//! The two apps talk through the shared room's encrypted messages. Every
//! member of that room can read those messages, so what only the two of
//! them should see travels sealed with HPKE (RFC 9180) under keys made
//! fresh for each invite: the room to join, its server and the invite
//! token one way, and the joiner's KeyPackages the other.
//! The sealing binds the shared room, the request and both members' keys
//! there, so a sealed part cannot be moved to another request or sender.

use openmls::prelude::tls_codec::VLBytes;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use socketchat_proto::msg::GroupId;
use socketchat_proto::Token;

use crate::keys::Key;

/// How long an invite by name stays open, as invite links do.
pub const ADD_TTL_SECS: u64 = 24 * 3600;

/// Names one request: 16 random bytes the asker picks.
pub type AskId = [u8; 16];

/// Length of an HPKE public key for X25519.
pub const ADD_KEY_LEN: usize = 32;

/// The largest sealed part an app opens, in bytes.
pub const MAX_SEALED: usize = 16 * 1024;

/// The block a sealed offer's plaintext is padded to.
const OFFER_BLOCK: usize = 1024;

/// The block a sealed answer's plaintext is padded to, so the size of the
/// KeyPackages inside does not show.
const ANSWER_BLOCK: usize = 4096;

const INFO_OFFER: &[u8] = b"socketchat/v1/add-offer";
const INFO_ANSWER: &[u8] = b"socketchat/v1/add-answer";

fn config() -> HpkeConfig {
    HpkeConfig(
        HpkeKemType::DhKem25519,
        HpkeKdfType::HkdfSha256,
        HpkeAeadType::ChaCha20Poly1305,
    )
}

/// An HPKE key pair made for one request.
pub struct AddKeyPair {
    pub public: Vec<u8>,
    pub private: Zeroizing<Vec<u8>>,
}

/// A fresh key pair from 32 random bytes.
pub fn new_key_pair(crypto: &impl OpenMlsCrypto) -> Option<AddKeyPair> {
    let mut ikm = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(ikm.as_mut());
    let kp = crypto.derive_hpke_keypair(config(), ikm.as_ref()).ok()?;
    Some(AddKeyPair {
        public: kp.public,
        private: Zeroizing::new(kp.private.to_vec()),
    })
}

/// A sealed part: the HPKE encapsulated key and the ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    #[serde(with = "serde_bytes")]
    pub enc: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ct: Vec<u8>,
}

/// What the asker tells only the person asked: where the room is and how
/// to get in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    /// The room's name, as the asker's app knows it.
    pub room_name: String,
    pub group: GroupId,
    pub host: String,
    pub port: u16,
    /// SHA-256 of the room's server certificate.
    pub cert_fpr: [u8; 32],
    /// The invite token that registers the joiner's mailbox in the room.
    pub token: Token,
    /// The asker's key in the room: the one that adds the joiner.
    pub adder_key: Key,
    pub expires_unix: u64,
}

/// What the person invited sends only the inviter when they join: the
/// KeyPackages for the room, one per suite, as a join lodges them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer {
    #[serde(with = "serde_bytes")]
    pub key_packages: Vec<u8>,
}

/// What the sealing binds: shared room (16) || request (16) || sender's
/// key in the shared room (32) || recipient's key there (32).
fn bound(via: &GroupId, ask: &AskId, from: &Key, to: &Key) -> Vec<u8> {
    let mut m = Vec::with_capacity(96);
    m.extend_from_slice(&via.0);
    m.extend_from_slice(ask);
    m.extend_from_slice(&from.0);
    m.extend_from_slice(&to.0);
    m
}

/// Postcard bytes of `v`, padded with zeros to a whole number of `block`s.
fn padded<T: Serialize>(v: &T, block: usize) -> Option<Zeroizing<Vec<u8>>> {
    let mut b = Zeroizing::new(postcard::to_stdvec(v).ok()?);
    let len = b.len().div_ceil(block).max(1) * block;
    b.resize(len, 0);
    Some(b)
}

/// The sealing context for one request.
pub struct Context<'a> {
    pub via: &'a GroupId,
    pub ask: &'a AskId,
    pub from: &'a Key,
    pub to: &'a Key,
}

fn seal(
    crypto: &impl OpenMlsCrypto,
    pk: &[u8],
    info: &[u8],
    cx: &Context,
    plain: &[u8],
) -> Option<Sealed> {
    if pk.len() != ADD_KEY_LEN {
        return None;
    }
    let aad = bound(cx.via, cx.ask, cx.from, cx.to);
    let c = crypto.hpke_seal(config(), pk, info, &aad, plain).ok()?;
    Some(Sealed {
        enc: c.kem_output.as_slice().to_vec(),
        ct: c.ciphertext.as_slice().to_vec(),
    })
}

fn open(
    crypto: &impl OpenMlsCrypto,
    sk: &[u8],
    info: &[u8],
    cx: &Context,
    s: &Sealed,
) -> Option<Zeroizing<Vec<u8>>> {
    if s.enc.len() != ADD_KEY_LEN || s.ct.len() > MAX_SEALED {
        return None;
    }
    let aad = bound(cx.via, cx.ask, cx.from, cx.to);
    let c = HpkeCiphertext {
        kem_output: VLBytes::new(s.enc.clone()),
        ciphertext: VLBytes::new(s.ct.clone()),
    };
    crypto
        .hpke_open(config(), &c, sk, info, &aad)
        .ok()
        .map(Zeroizing::new)
}

/// Seals `offer` for the person whose request key is `pk`. `cx.from` is the
/// asker's key in the shared room and `cx.to` the person's.
pub fn seal_offer(
    crypto: &impl OpenMlsCrypto,
    pk: &[u8],
    cx: &Context,
    offer: &Offer,
) -> Option<Sealed> {
    seal(crypto, pk, INFO_OFFER, cx, &padded(offer, OFFER_BLOCK)?)
}

/// Opens an offer sealed for `sk`, or `None` if it does not open in this
/// context.
pub fn open_offer(
    crypto: &impl OpenMlsCrypto,
    sk: &[u8],
    cx: &Context,
    s: &Sealed,
) -> Option<Offer> {
    let b = open(crypto, sk, INFO_OFFER, cx, s)?;
    postcard::take_from_bytes(&b).ok().map(|(o, _)| o)
}

/// Seals `answer` for the asker whose reply key is `pk`. `cx.from` is the
/// person's key in the shared room and `cx.to` the asker's.
pub fn seal_answer(
    crypto: &impl OpenMlsCrypto,
    pk: &[u8],
    cx: &Context,
    answer: &Answer,
) -> Option<Sealed> {
    seal(crypto, pk, INFO_ANSWER, cx, &padded(answer, ANSWER_BLOCK)?)
}

/// Opens an answer sealed for `sk`.
pub fn open_answer(
    crypto: &impl OpenMlsCrypto,
    sk: &[u8],
    cx: &Context,
    s: &Sealed,
) -> Option<Answer> {
    let b = open(crypto, sk, INFO_ANSWER, cx, s)?;
    postcard::take_from_bytes(&b).ok().map(|(a, _)| a)
}

/// Whether an app that says it runs `version` knows this kind of invite:
/// one after 0.5.2. No version, or one that does not read, means an app
/// from before 0.5.0, which says none.
pub fn knows_add(version: Option<&str>) -> bool {
    use crate::update::Version;
    let Some(v) = version.and_then(Version::parse) else {
        return false;
    };
    v > Version::parse("0.5.2").expect("a version")
}

/// A random request ID.
pub fn new_ask() -> AskId {
    let mut a = [0u8; 16];
    OsRng.fill_bytes(&mut a);
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_rust_crypto::RustCrypto;

    fn offer() -> Offer {
        Offer {
            room_name: "Climbing Saturdays".into(),
            group: GroupId([9; 16]),
            host: "chat.example.com".into(),
            port: 7444,
            cert_fpr: [3; 32],
            token: Token([4; 16]),
            adder_key: Key([5; 32]),
            expires_unix: 1_000,
        }
    }

    #[test]
    fn an_offer_opens_only_in_its_own_context() {
        let c = RustCrypto::default();
        let kp = new_key_pair(&c).unwrap();
        let (via, ask, a, b) = (GroupId([1; 16]), [2u8; 16], Key([6; 32]), Key([7; 32]));
        let cx = Context {
            via: &via,
            ask: &ask,
            from: &a,
            to: &b,
        };
        let s = seal_offer(&c, &kp.public, &cx, &offer()).unwrap();
        assert_eq!(open_offer(&c, &kp.private, &cx, &s), Some(offer()));
        let other_ask = [8u8; 16];
        let other_room = GroupId([8; 16]);
        let other = Key([8; 32]);
        for bad in [
            Context {
                ask: &other_ask,
                ..cx
            },
            Context {
                via: &other_room,
                ..cx
            },
            Context { from: &other, ..cx },
            Context { to: &other, ..cx },
        ] {
            assert_eq!(open_offer(&c, &kp.private, &bad, &s), None);
        }
        // Another key, an answer's context string, a changed byte.
        let kp2 = new_key_pair(&c).unwrap();
        assert_eq!(open_offer(&c, &kp2.private, &cx, &s), None);
        assert_eq!(open_answer(&c, &kp.private, &cx, &s), None);
        let mut x = s.clone();
        x.ct[0] ^= 1;
        assert_eq!(open_offer(&c, &kp.private, &cx, &x), None);
    }

    #[test]
    fn answers_of_any_size_up_to_a_block_seal_to_one_size() {
        let c = RustCrypto::default();
        let kp = new_key_pair(&c).unwrap();
        let (via, ask, a, b) = (GroupId([1; 16]), [2u8; 16], Key([6; 32]), Key([7; 32]));
        let cx = Context {
            via: &via,
            ask: &ask,
            from: &a,
            to: &b,
        };
        let small = Answer {
            key_packages: vec![1; 10],
        };
        let big = Answer {
            key_packages: vec![1; 4000],
        };
        let s1 = seal_answer(&c, &kp.public, &cx, &small).unwrap();
        let s2 = seal_answer(&c, &kp.public, &cx, &big).unwrap();
        assert_eq!(s1.ct.len(), s2.ct.len());
        assert_eq!(open_answer(&c, &kp.private, &cx, &s2), Some(big));
    }

    #[test]
    fn offers_for_short_and_long_room_names_seal_to_the_same_size() {
        let c = RustCrypto::default();
        let kp = new_key_pair(&c).unwrap();
        let (via, ask, a, b) = (GroupId([1; 16]), [2u8; 16], Key([6; 32]), Key([7; 32]));
        let cx = Context {
            via: &via,
            ask: &ask,
            from: &a,
            to: &b,
        };
        let short = seal_offer(&c, &kp.public, &cx, &offer()).unwrap();
        let mut long = offer();
        long.room_name = "x".repeat(64);
        long.host = "h".repeat(253);
        let long = seal_offer(&c, &kp.public, &cx, &long).unwrap();
        assert_eq!(short.ct.len(), long.ct.len());
    }

    #[test]
    fn a_wrong_size_key_seals_nothing() {
        let c = RustCrypto::default();
        let (via, ask, a, b) = (GroupId([1; 16]), [2u8; 16], Key([6; 32]), Key([7; 32]));
        let cx = Context {
            via: &via,
            ask: &ask,
            from: &a,
            to: &b,
        };
        assert!(seal_offer(&c, &[1; 31], &cx, &offer()).is_none());
    }

    #[test]
    fn apps_after_0_5_2_know_this_kind_of_invite() {
        assert!(!knows_add(None));
        assert!(!knows_add(Some("0.4.0")));
        assert!(!knows_add(Some("0.5.1")));
        assert!(!knows_add(Some("0.5.2")));
        assert!(!knows_add(Some("not a version")));
        assert!(knows_add(Some("0.5.3")));
        assert!(knows_add(Some("0.5.3-rc.1")));
        assert!(knows_add(Some("0.6.0")));
    }
}
