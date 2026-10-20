//! The MLS settings every socketchat group uses, kept in one place so groups
//! can move to the final post-quantum suite when it is published.

use openmls::prelude::*;

use crate::keys::Key;

/// ML-KEM-768 + X25519 hybrid, from the IETF MLS post-quantum draft.
pub const SUITE: Ciphersuite = Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519;

/// The standard RFC 9420 suite. An operator can require it.
pub const FALLBACK_SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// GroupContext extension that lists the group's admin keys (private-use
/// range of RFC 9420).
pub const ADMINS_EXT: u16 = 0xff00;

/// How many old epochs a member keeps keys for, so a message sent just
/// before a group change still opens.
pub const MAX_PAST_EPOCHS: usize = 2;

/// Leaf capabilities every socketchat client advertises.
pub fn capabilities() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[SUITE, FALLBACK_SUITE]),
        Some(&[ExtensionType::Unknown(ADMINS_EXT)]),
        None,
        Some(&[CredentialType::Basic]),
    )
}

/// The admin list as a GroupContext extension: each key prefixed by its
/// 2-byte length.
pub fn admins_extension(admins: &[Key]) -> Extension {
    let mut b = Vec::with_capacity(admins.len() * 34);
    for k in admins {
        b.extend_from_slice(&32u16.to_be_bytes());
        b.extend_from_slice(&k.0);
    }
    Extension::Unknown(ADMINS_EXT, UnknownExtension(b))
}

/// Reads the admin list from an extension. Anything malformed reads as no
/// admins, which the server and clients treat as "refuse".
pub fn decode_admins(ext: &Extension) -> Vec<Key> {
    let Extension::Unknown(t, UnknownExtension(b)) = ext else {
        return vec![];
    };
    if *t != ADMINS_EXT {
        return vec![];
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if i + 2 > b.len() {
            return vec![];
        }
        let n = u16::from_be_bytes([b[i], b[i + 1]]) as usize;
        if n != 32 || i + 2 + n > b.len() {
            return vec![];
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&b[i + 2..i + 2 + n]);
        out.push(Key(k));
        i += 2 + n;
    }
    out
}

/// The admin list in a group's current context.
pub fn parse_admins(ctx: &GroupContext) -> Vec<Key> {
    admins_from(ctx.extensions())
}

/// The admin list in a set of GroupContext extensions, for example
/// `MlsGroup::extensions()`.
pub fn admins_from(exts: &Extensions<GroupContext>) -> Vec<Key> {
    exts.iter()
        .find(|e| matches!(e, Extension::Unknown(t, _) if *t == ADMINS_EXT))
        .map(decode_admins)
        .unwrap_or_default()
}

/// GroupContext extensions for a group with these admins.
pub fn group_context_extensions(admins: &[Key]) -> Extensions<GroupContext> {
    Extensions::from_vec(vec![
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(ADMINS_EXT)],
            &[],
            &[CredentialType::Basic],
        )),
        admins_extension(admins),
    ])
    .expect("two distinct extension types")
}

/// Config for creating a group: group changes travel signed but not
/// encrypted (PublicMessage), application messages encrypted.
pub fn group_create_config(suite: Ciphersuite, admins: &[Key]) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(suite)
        .capabilities(capabilities())
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .with_group_context_extensions(group_context_extensions(admins))
        .use_ratchet_tree_extension(true)
        .build()
}

/// Config for joining a group from a Welcome.
pub fn group_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .use_ratchet_tree_extension(true)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;
    use openmls_rust_crypto::OpenMlsRustCrypto;

    #[test]
    fn admins_extension_roundtrip() {
        let p = OpenMlsRustCrypto::default();
        let me = KeyPair::generate();
        let other = KeyPair::generate().public();
        let cfg = group_create_config(SUITE, &[me.public(), other]);
        let g = MlsGroup::new(&p, &me, &cfg, me.credential()).unwrap();
        assert_eq!(admins_from(g.extensions()), vec![me.public(), other]);
    }

    #[test]
    fn suite_group_creates_on_0x004f() {
        assert_eq!(SUITE as u16, 0x004F);
        assert_eq!(FALLBACK_SUITE as u16, 0x0001);
        let p = OpenMlsRustCrypto::default();
        let me = KeyPair::generate();
        let g = MlsGroup::new(
            &p,
            &me,
            &group_create_config(SUITE, &[me.public()]),
            me.credential(),
        )
        .unwrap();
        assert_eq!(g.ciphersuite(), SUITE);
    }

    #[test]
    fn parse_admins_ignores_garbage() {
        let ext = Extension::Unknown(ADMINS_EXT, UnknownExtension(vec![0, 40, 1, 2]));
        assert!(decode_admins(&ext).is_empty());
    }
}
