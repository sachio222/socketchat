//! Keys and the signatures socketchat makes with them.
//!
//! Every key is Ed25519. Each signature covers a context string, a zero
//! byte, then the message, so a signature made for one purpose never
//! verifies for another.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use openmls::prelude::{BasicCredential, CredentialWithKey};
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::types::SignatureScheme;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use socketchat_proto::Token;
use zeroize::Zeroizing;

pub use socketchat_proto::msg::{GroupId, Key, Sig};

/// Signing in to a server: the message is `challenge || key`.
pub const CTX_AUTH: &[u8] = b"socketchat/v1/auth";
/// An identity key vouching for its owner's key in one group.
pub const CTX_BINDING: &[u8] = b"socketchat/v1/group-key-binding";
/// An inviter vouching for an invite link they made.
pub const CTX_VOUCHER: &[u8] = b"socketchat/v1/voucher";
/// A joiner's request to join through an invite link: the message is
/// `token || mailbox key`.
pub const CTX_JOIN_REQUEST: &[u8] = b"socketchat/v1/join-request";
/// A member's group key signing the topic they set for a room: the message
/// is `group ID || set time || text`.
pub const CTX_TOPIC: &[u8] = b"socketchat/v1/topic";

/// An Ed25519 key pair. The private half is wiped from memory on drop.
#[derive(Clone)]
pub struct KeyPair {
    sk: SigningKey,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &self.public())
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
struct RawSeed([u8; 32]);

impl Serialize for KeyPair {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        RawSeed(self.sk.to_bytes()).serialize(s)
    }
}

impl<'de> Deserialize<'de> for KeyPair {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let RawSeed(seed) = RawSeed::deserialize(d)?;
        Ok(KeyPair {
            sk: SigningKey::from_bytes(&seed),
        })
    }
}

fn signed_bytes(ctx: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(ctx.len() + 1 + msg.len());
    v.extend_from_slice(ctx);
    v.push(0);
    v.extend_from_slice(msg);
    v
}

impl KeyPair {
    pub fn generate() -> Self {
        KeyPair {
            sk: SigningKey::generate(&mut OsRng),
        }
    }

    /// The key pair whose Ed25519 seed is `seed`.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        KeyPair {
            sk: SigningKey::from_bytes(seed),
        }
    }

    pub fn public(&self) -> Key {
        Key(self.sk.verifying_key().to_bytes())
    }

    pub fn sign(&self, ctx: &[u8], msg: &[u8]) -> Sig {
        Sig(self.sk.sign(&signed_bytes(ctx, msg)).to_bytes())
    }

    /// The MLS credential for this key. The credential's identity is the
    /// public key itself, so it carries no name.
    pub fn credential(&self) -> CredentialWithKey {
        let public = self.public().0.to_vec();
        CredentialWithKey {
            credential: BasicCredential::new(public.clone()).into(),
            signature_key: public.into(),
        }
    }
}

/// Lets OpenMLS sign with a socketchat key.
impl Signer for KeyPair {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.sk.sign(payload).to_bytes().to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// Checks a signature made with [`KeyPair::sign`] under the same context.
pub fn verify(key: &Key, ctx: &[u8], msg: &[u8], sig: &Sig) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(&key.0) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig.0);
    vk.verify_strict(&signed_bytes(ctx, msg), &sig).is_ok()
}

/// SHA-256 of the public key. Invite links carry this.
pub fn fingerprint(key: &Key) -> [u8; 32] {
    Sha256::digest(key.0).into()
}

/// A certificate or key fingerprint for people to compare: hex in groups of
/// four, such as `9f2c 41d0 ...`.
pub fn fingerprint_text(f: &[u8; 32]) -> String {
    f.chunks(2)
        .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Thirty digits for one key, built the way Signal's numeric fingerprint
/// (version 1) builds them: SHA-512 iterated 5,200 times, then six 5-digit
/// groups.
fn safety_half(key: &Key) -> String {
    let mut hash = Vec::with_capacity(66);
    hash.extend_from_slice(&0u16.to_be_bytes());
    hash.extend_from_slice(&key.0);
    hash.extend_from_slice(&key.0);
    for _ in 0..5200 {
        let mut d = Sha512::new();
        d.update(&hash);
        d.update(key.0);
        hash = d.finalize().to_vec();
    }
    hash[..30]
        .chunks(5)
        .map(|c| {
            let n = c.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64);
            format!("{:05}", n % 100_000)
        })
        .collect()
}

/// The 60-digit number two people compare to check that nobody sits between
/// them. Both sides compute the same number.
pub fn safety_number(a: &Key, b: &Key) -> String {
    let (x, y) = (safety_half(a), safety_half(b));
    if x <= y {
        x + &y
    } else {
        y + &x
    }
}

/// Splits a safety number into 12 groups of 5 digits for reading aloud.
pub fn display_safety_number(n: &str) -> String {
    n.as_bytes()
        .chunks(5)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

/// An identity key's statement that `group_key` belongs to it in `group`.
/// Sent only inside the group's encrypted messages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub group: GroupId,
    pub group_key: Key,
    pub identity: Key,
    pub sig: Sig,
}

fn binding_msg(group: &GroupId, group_key: &Key) -> Vec<u8> {
    [group.0.as_slice(), group_key.0.as_slice()].concat()
}

impl Binding {
    pub fn new(identity: &KeyPair, group: GroupId, group_key: Key) -> Binding {
        let sig = identity.sign(CTX_BINDING, &binding_msg(&group, &group_key));
        Binding {
            group,
            group_key,
            identity: identity.public(),
            sig,
        }
    }

    pub fn verify(&self) -> bool {
        verify(
            &self.identity,
            CTX_BINDING,
            &binding_msg(&self.group, &self.group_key),
            &self.sig,
        )
    }
}

/// The inviter's signed promise about one invite link. Every member holds
/// it; the server never sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Voucher {
    pub token: Token,
    pub secret_hash: [u8; 32],
    pub group: GroupId,
    pub inviter_group_key: Key,
    pub expires_unix: u64,
    pub inviter_identity: Key,
    pub sig: Sig,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum VoucherError {
    #[error("the invite was signed by someone other than the person in the link")]
    WrongInviter,
    #[error("the invite's signature does not match its contents")]
    BadSignature,
    #[error("the invite has expired")]
    Expired,
}

impl Voucher {
    fn msg(&self) -> Vec<u8> {
        [
            self.token.0.as_slice(),
            &self.secret_hash,
            &self.group.0,
            &self.inviter_group_key.0,
            &self.expires_unix.to_be_bytes(),
        ]
        .concat()
    }

    pub fn new(
        identity: &KeyPair,
        token: Token,
        secret: &[u8; 32],
        group: GroupId,
        inviter_group_key: Key,
        expires_unix: u64,
    ) -> Voucher {
        let mut v = Voucher {
            token,
            secret_hash: Sha256::digest(secret).into(),
            group,
            inviter_group_key,
            expires_unix,
            inviter_identity: identity.public(),
            sig: Sig([0; 64]),
        };
        v.sig = identity.sign(CTX_VOUCHER, &v.msg());
        v
    }

    /// Checks the voucher against the inviter fingerprint from the link.
    pub fn verify(
        &self,
        expected_identity_fpr: &[u8; 32],
        now_unix: u64,
    ) -> Result<(), VoucherError> {
        if &fingerprint(&self.inviter_identity) != expected_identity_fpr {
            return Err(VoucherError::WrongInviter);
        }
        if !verify(&self.inviter_identity, CTX_VOUCHER, &self.msg(), &self.sig) {
            return Err(VoucherError::BadSignature);
        }
        if now_unix > self.expires_unix {
            return Err(VoucherError::Expired);
        }
        Ok(())
    }

    pub fn secret_matches(&self, secret: &[u8; 32]) -> bool {
        <[u8; 32]>::from(Sha256::digest(secret)) == self.secret_hash
    }
}

/// Labels the key and the associated data for a voucher sealed to a joiner.
const VOUCHER_SEAL: &[u8] = b"socketchat/v1/voucher-seal";
const SEAL_NONCE_LEN: usize = 24;

/// Labels the seed of the key a joiner signs their join request with.
const INVITE_SIGN: &[u8] = b"socketchat/v1/invite-sign";
/// Labels the key a joiner proves they hold the link with.
const INVITE_PROOF: &[u8] = b"socketchat/v1/invite-proof";

fn derive(secret: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, secret)
        .expand(label, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

/// The key that seals a voucher for the joiner: HKDF-SHA256 of the invite
/// secret, no salt, info `socketchat/v1/voucher-seal`. Members get this
/// key, never the secret, so any admin can complete a join.
pub fn voucher_seal_key(secret: &[u8; 32]) -> [u8; 32] {
    derive(secret, VOUCHER_SEAL)
}

/// The key a joiner signs their join request with: an Ed25519 key whose
/// seed is HKDF-SHA256 of the invite secret, no salt, info
/// `socketchat/v1/invite-sign`. Members get only its public half, so they
/// can check a request but cannot make one, and cannot make the
/// [`invite_proof`] that only the link's holder can make either.
pub fn invite_signing_key(secret: &[u8; 32]) -> KeyPair {
    let seed = Zeroizing::new(derive(secret, INVITE_SIGN));
    KeyPair::from_seed(&seed)
}

fn join_request_msg(token: &Token, mailbox: &Key) -> Vec<u8> {
    [token.0.as_slice(), &mailbox.0].concat()
}

/// A joiner's signature on their request: the token they redeemed and
/// their new mailbox, which is the key their KeyPackage is made for. The
/// KeyPackage's own signature, by that mailbox key, ties it to this.
pub fn sign_join_request(signing: &KeyPair, token: &Token, mailbox: &Key) -> Sig {
    signing.sign(CTX_JOIN_REQUEST, &join_request_msg(token, mailbox))
}

/// Checks a [`sign_join_request`] signature against the public key members
/// received with the voucher.
pub fn join_request_ok(request_key: &Key, token: &Token, mailbox: &Key, sig: &Sig) -> bool {
    verify(
        request_key,
        CTX_JOIN_REQUEST,
        &join_request_msg(token, mailbox),
        sig,
    )
}

fn voucher_seal_cipher(seal_key: &[u8; 32]) -> XChaCha20Poly1305 {
    <XChaCha20Poly1305 as chacha20poly1305::KeyInit>::new(seal_key.into())
}

/// Seals a voucher for the joiner, who holds the invite secret from the link.
/// The server stores and forwards the result but cannot read it, so it never
/// learns the inviter's identity key.
///
/// Key: [`voucher_seal_key`]. Cipher: XChaCha20-Poly1305 with a fresh
/// random nonce. Output: nonce, then ciphertext.
pub fn seal_voucher(seal_key: &[u8; 32], voucher: &Voucher) -> Vec<u8> {
    let plain = Zeroizing::new(postcard::to_stdvec(voucher).expect("a voucher always encodes"));
    let mut nonce = [0u8; SEAL_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let sealed = voucher_seal_cipher(seal_key)
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: VOUCHER_SEAL,
            },
        )
        .expect("XChaCha20-Poly1305 encrypts any voucher-sized message");
    [nonce.as_slice(), &sealed].concat()
}

/// Opens a voucher sealed by [`seal_voucher`]. `None` when the key is
/// wrong or any byte was changed.
pub fn open_voucher(seal_key: &[u8; 32], sealed: &[u8]) -> Option<Voucher> {
    if sealed.len() < SEAL_NONCE_LEN {
        return None;
    }
    let (nonce, body) = sealed.split_at(SEAL_NONCE_LEN);
    let plain = Zeroizing::new(
        voucher_seal_cipher(seal_key)
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: body,
                    aad: VOUCHER_SEAL,
                },
            )
            .ok()?,
    );
    postcard::from_bytes(&plain).ok()
}

type HmacSha256 = Hmac<Sha256>;

fn proof_mac(secret: &[u8; 32], group: &GroupId, group_key: &Key) -> HmacSha256 {
    let mut m =
        HmacSha256::new_from_slice(&derive(secret, INVITE_PROOF)).expect("any key length works");
    m.update(&group.0);
    m.update(&group_key.0);
    m
}

/// A joiner's proof that they hold the invite secret itself, bound to their
/// key in the group. Only the link's maker can check it, and no other
/// member can make it, so only the real invitee earns the maker's verified
/// mark.
pub fn invite_proof(secret: &[u8; 32], group: &GroupId, group_key: &Key) -> [u8; 32] {
    proof_mac(secret, group, group_key)
        .finalize()
        .into_bytes()
        .into()
}

/// Constant-time check of [`invite_proof`].
pub fn proof_matches(
    secret: &[u8; 32],
    group: &GroupId,
    group_key: &Key,
    proof: &[u8; 32],
) -> bool {
    proof_mac(secret, group, group_key)
        .verify_slice(proof)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use socketchat_proto::Token;

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn sign_verify_roundtrip() {
        let k = KeyPair::generate();
        let sig = k.sign(CTX_AUTH, b"challenge");
        assert!(verify(&k.public(), CTX_AUTH, b"challenge", &sig));
        assert!(!verify(&k.public(), CTX_AUTH, b"challengf", &sig));
        assert!(!verify(
            &KeyPair::generate().public(),
            CTX_AUTH,
            b"challenge",
            &sig
        ));
    }

    #[test]
    fn verify_rejects_other_context() {
        let k = KeyPair::generate();
        let sig = k.sign(CTX_AUTH, b"m");
        assert!(!verify(&k.public(), CTX_VOUCHER, b"m", &sig));
    }

    #[test]
    fn keypair_survives_serde() {
        let k = KeyPair::generate();
        let bytes = postcard::to_stdvec(&k).unwrap();
        let back: KeyPair = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back.public(), k.public());
        assert!(verify(
            &k.public(),
            CTX_AUTH,
            b"x",
            &back.sign(CTX_AUTH, b"x")
        ));
    }

    #[test]
    fn safety_number_symmetric_and_60_digits() {
        let (a, b) = (KeyPair::generate().public(), KeyPair::generate().public());
        let n = safety_number(&a, &b);
        assert_eq!(n, safety_number(&b, &a));
        assert_eq!(n.len(), 60);
        assert!(n.bytes().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn safety_number_changes_with_key() {
        let (a, b, c) = (
            KeyPair::generate().public(),
            KeyPair::generate().public(),
            KeyPair::generate().public(),
        );
        assert_ne!(safety_number(&a, &b), safety_number(&a, &c));
    }

    #[test]
    fn safety_number_groups_display() {
        let (a, b) = (KeyPair::generate().public(), KeyPair::generate().public());
        let shown = display_safety_number(&safety_number(&a, &b));
        assert_eq!(shown.split(' ').count(), 12);
    }

    #[test]
    fn binding_detects_swapped_group_key() {
        let id = KeyPair::generate();
        let g = GroupId([1; 16]);
        let gk = KeyPair::generate().public();
        let b = Binding::new(&id, g, gk);
        assert!(b.verify());
        let swapped = Binding {
            group_key: KeyPair::generate().public(),
            ..b.clone()
        };
        assert!(!swapped.verify());
        let other_group = Binding {
            group: GroupId([2; 16]),
            ..b
        };
        assert!(!other_group.verify());
    }

    fn voucher(id: &KeyPair) -> Voucher {
        Voucher::new(
            id,
            Token([1; 16]),
            &[7; 32],
            GroupId([2; 16]),
            KeyPair::generate().public(),
            NOW + 3600,
        )
    }

    #[test]
    fn voucher_verifies_for_link_fingerprint() {
        let id = KeyPair::generate();
        let v = voucher(&id);
        assert_eq!(v.verify(&fingerprint(&id.public()), NOW), Ok(()));
        assert!(v.secret_matches(&[7; 32]));
        assert!(!v.secret_matches(&[8; 32]));
    }

    #[test]
    fn voucher_rejects_wrong_identity_fpr() {
        let v = voucher(&KeyPair::generate());
        let other = fingerprint(&KeyPair::generate().public());
        assert_eq!(v.verify(&other, NOW), Err(VoucherError::WrongInviter));
    }

    #[test]
    fn voucher_rejects_forged_fields() {
        let id = KeyPair::generate();
        let mut v = voucher(&id);
        v.group = GroupId([9; 16]);
        assert_eq!(
            v.verify(&fingerprint(&id.public()), NOW),
            Err(VoucherError::BadSignature)
        );
    }

    #[test]
    fn voucher_rejects_expired() {
        let id = KeyPair::generate();
        let v = voucher(&id);
        assert_eq!(
            v.verify(&fingerprint(&id.public()), NOW + 3601),
            Err(VoucherError::Expired)
        );
    }

    #[test]
    fn sealed_voucher_roundtrip() {
        let v = voucher(&KeyPair::generate());
        let sealed = seal_voucher(&[7; 32], &v);
        assert_eq!(open_voucher(&[7; 32], &sealed), Some(v));
    }

    #[test]
    fn sealed_voucher_needs_the_invite_secret() {
        let v = voucher(&KeyPair::generate());
        let sealed = seal_voucher(&[7; 32], &v);
        assert_eq!(open_voucher(&[8; 32], &sealed), None);
    }

    #[test]
    fn sealed_voucher_rejects_any_changed_byte() {
        let v = voucher(&KeyPair::generate());
        let sealed = seal_voucher(&[7; 32], &v);
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert_eq!(open_voucher(&[7; 32], &bad), None, "byte {i}");
        }
        assert_eq!(open_voucher(&[7; 32], &sealed[..sealed.len() - 1]), None);
        assert_eq!(open_voucher(&[7; 32], &[]), None);
    }

    #[test]
    fn sealed_voucher_hides_inviter_identity() {
        let id = KeyPair::generate();
        let v = voucher(&id);
        let sealed = seal_voucher(&[7; 32], &v);
        let identity = id.public().0;
        assert!(!sealed.windows(identity.len()).any(|w| w == identity));
        assert_ne!(
            seal_voucher(&[7; 32], &v),
            sealed,
            "a fresh nonce every time"
        );
    }

    #[test]
    fn join_request_signature_needs_the_secret() {
        let secret = [3u8; 32];
        let (t, mailbox) = (Token([1; 16]), KeyPair::generate().public());
        let signing = invite_signing_key(&secret);
        let public = signing.public();
        assert_eq!(
            invite_signing_key(&secret).public(),
            public,
            "same secret, same key"
        );
        assert_ne!(invite_signing_key(&[4; 32]).public(), public);
        let sig = sign_join_request(&signing, &t, &mailbox);
        assert!(join_request_ok(&public, &t, &mailbox, &sig));
        assert!(!join_request_ok(&public, &Token([2; 16]), &mailbox, &sig));
        assert!(!join_request_ok(
            &public,
            &t,
            &KeyPair::generate().public(),
            &sig
        ));
        // What a member holds: the public key and the seal key. Neither
        // signs a request that checks.
        for seed in [public.0, voucher_seal_key(&secret)] {
            let forged = sign_join_request(&KeyPair::from_seed(&seed), &t, &mailbox);
            assert!(!join_request_ok(&public, &t, &mailbox, &forged));
        }
        // A signature for another purpose does not pass as a request.
        let other = signing.sign(CTX_VOUCHER, &[t.0.as_slice(), &mailbox.0].concat());
        assert!(!join_request_ok(&public, &t, &mailbox, &other));
    }

    #[test]
    fn members_keys_cannot_make_the_joiners_proof() {
        let secret = [3u8; 32];
        let (g, k) = (GroupId([1; 16]), KeyPair::generate().public());
        let proof = invite_proof(&secret, &g, &k);
        assert!(proof_matches(&secret, &g, &k, &proof));
        assert!(!proof_matches(&secret, &GroupId([2; 16]), &k, &proof));
        assert!(!proof_matches(
            &secret,
            &g,
            &KeyPair::generate().public(),
            &proof
        ));
        let request_key = invite_signing_key(&secret).public().0;
        for member_key in [request_key, voucher_seal_key(&secret)] {
            assert!(!proof_matches(
                &secret,
                &g,
                &k,
                &invite_proof(&member_key, &g, &k)
            ));
            assert_ne!(member_key, secret);
        }
        assert_ne!(request_key, voucher_seal_key(&secret));
    }
}
