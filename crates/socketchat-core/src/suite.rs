//! The MLS settings every socketchat group uses, kept in one place so groups
//! can move to the final post-quantum suite when it is published.

use openmls::prelude::*;

use crate::keys::Key;
use crate::settings::RoomSettings;

/// ML-KEM-768 + X25519 hybrid, from the IETF MLS post-quantum draft.
pub const SUITE: Ciphersuite = Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519;

/// The standard RFC 9420 suite. An operator can require it.
pub const FALLBACK_SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// GroupContext extension that lists the group's admin keys (private-use
/// range of RFC 9420).
pub const ADMINS_EXT: u16 = 0xff00;

/// KeyPackage extension that carries a joiner's signature on their join
/// request (private-use range of RFC 9420). See `invite::key_package_blob`.
pub const JOIN_SIG_EXT: u16 = 0xff01;

/// GroupContext extension that holds the room's settings (private-use
/// range of RFC 9420). See [`crate::settings`]. A room carries it only
/// once an admin changes a setting from its default; while it does, every
/// member's app must list it in its capabilities.
pub const ROOM_SETTINGS_EXT: u16 = 0xff02;

/// How many old epochs a member keeps keys for, so a message sent just
/// before a group change still opens.
pub const MAX_PAST_EPOCHS: usize = 2;

/// Every encrypted application message is padded with zeros to a whole
/// number of blocks this size, so the server sees a size rounded up instead
/// of the length of what was written. With 256, every text of up to 169
/// ASCII characters, and every vote and app version, is one block in
/// either suite.
pub const PADDING_BLOCK: usize = 256;

/// Leaf capabilities every socketchat client advertises.
pub fn capabilities() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[SUITE, FALLBACK_SUITE]),
        Some(&[
            ExtensionType::Unknown(ADMINS_EXT),
            ExtensionType::Unknown(JOIN_SIG_EXT),
            ExtensionType::Unknown(ROOM_SETTINGS_EXT),
        ]),
        None,
        Some(&[CredentialType::Basic]),
    )
}

/// The capabilities apps up to 0.5.1 advertise: no room settings. Tests
/// use them to stand in for an older app.
#[doc(hidden)]
pub fn capabilities_0_5_1() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[SUITE, FALLBACK_SUITE]),
        Some(&[
            ExtensionType::Unknown(ADMINS_EXT),
            ExtensionType::Unknown(JOIN_SIG_EXT),
        ]),
        None,
        Some(&[CredentialType::Basic]),
    )
}

/// Whether a leaf's or KeyPackage's capabilities let it be in a room with
/// settings.
pub fn takes_settings(caps: &Capabilities) -> bool {
    caps.extensions()
        .contains(&ExtensionType::Unknown(ROOM_SETTINGS_EXT))
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

/// GroupContext extensions for a group with these admins and settings. A
/// room on the default settings gets exactly what rooms got before
/// settings existed, so apps up to 0.5.1 can still join it; any other
/// settings add the settings extension and require every member to take
/// it.
pub fn group_context_extensions(
    admins: &[Key],
    settings: &RoomSettings,
) -> Extensions<GroupContext> {
    if settings.is_default() {
        return Extensions::from_vec(vec![
            Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                &[ExtensionType::Unknown(ADMINS_EXT)],
                &[],
                &[CredentialType::Basic],
            )),
            admins_extension(admins),
        ])
        .expect("two distinct extension types");
    }
    Extensions::from_vec(vec![
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[
                ExtensionType::Unknown(ADMINS_EXT),
                ExtensionType::Unknown(ROOM_SETTINGS_EXT),
            ],
            &[],
            &[CredentialType::Basic],
        )),
        admins_extension(admins),
        settings.extension(),
    ])
    .expect("three distinct extension types")
}

/// Config for creating a group: group changes travel signed but not
/// encrypted (PublicMessage), application messages encrypted.
pub fn group_create_config(suite: Ciphersuite, admins: &[Key]) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(suite)
        .capabilities(capabilities())
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .with_group_context_extensions(group_context_extensions(admins, &RoomSettings::default()))
        .use_ratchet_tree_extension(true)
        .padding_size(PADDING_BLOCK)
        .build()
}

/// Config for joining a group from a Welcome.
pub fn group_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .use_ratchet_tree_extension(true)
        .padding_size(PADDING_BLOCK)
        .build()
}

/// Loads a stored group. OpenMLS stores each group's settings with it, so a
/// group made or joined before padding came in still has none: it moves to
/// [`group_join_config`] here, and the change is stored. Those groups'
/// settings match it in every other way, so only the padding changes.
pub fn load_group<S: openmls::storage::StorageProvider>(
    storage: &S,
    gid: &openmls::group::GroupId,
) -> Result<Option<MlsGroup>, S::Error> {
    let Some(mut g) = MlsGroup::load(storage, gid)? else {
        return Ok(None);
    };
    if g.configuration().padding_size() != PADDING_BLOCK {
        g.set_configuration(storage, &group_join_config())?;
    }
    Ok(Some(g))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::appmsg::AppMsg;
    use crate::keys::KeyPair;
    use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
    use openmls_rust_crypto::OpenMlsRustCrypto;

    /// The create config every app up to 0.5.1 used: no padding.
    pub(crate) fn create_config_0_5_1(suite: Ciphersuite, admins: &[Key]) -> MlsGroupCreateConfig {
        MlsGroupCreateConfig::builder()
            .ciphersuite(suite)
            .capabilities(capabilities())
            .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(MAX_PAST_EPOCHS)
            .with_group_context_extensions(group_context_extensions(
                admins,
                &RoomSettings::default(),
            ))
            .use_ratchet_tree_extension(true)
            .build()
    }

    /// The join config every app up to 0.5.1 used: no padding.
    pub(crate) fn join_config_0_5_1() -> MlsGroupJoinConfig {
        MlsGroupJoinConfig::builder()
            .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(MAX_PAST_EPOCHS)
            .use_ratchet_tree_extension(true)
            .build()
    }

    /// Bytes on the wire for a text message of `chars` characters.
    pub(crate) fn wire_len(
        p: &impl openmls_traits::OpenMlsProvider,
        me: &KeyPair,
        g: &mut MlsGroup,
        chars: usize,
    ) -> usize {
        let m = AppMsg::Text {
            body: "a".repeat(chars),
        };
        g.create_message(p, me, &m.encode())
            .unwrap()
            .tls_serialize_detached()
            .unwrap()
            .len()
    }

    fn new_group(p: &OpenMlsRustCrypto, me: &KeyPair, suite: Ciphersuite) -> MlsGroup {
        MlsGroup::new(
            p,
            me,
            &group_create_config(suite, &[me.public()]),
            me.credential(),
        )
        .unwrap()
    }

    /// Alice makes a room with `create`, adds Bo, and Bo joins with `join`.
    fn pair(
        p_a: &OpenMlsRustCrypto,
        a: &KeyPair,
        create: &MlsGroupCreateConfig,
        p_b: &OpenMlsRustCrypto,
        b: &KeyPair,
        join: &MlsGroupJoinConfig,
    ) -> (MlsGroup, MlsGroup) {
        let mut ga = MlsGroup::new(p_a, a, create, a.credential()).unwrap();
        let blob = crate::invite::key_package_blob(p_b, b).unwrap();
        let kp = crate::invite::pick_key_package(p_a, &blob, create.ciphersuite()).unwrap();
        let (_, welcome, _) = ga.add_members(p_a, a, &[kp]).unwrap();
        ga.merge_pending_commit(p_a).unwrap();
        let welcome = welcome.tls_serialize_detached().unwrap();
        let MlsMessageBodyIn::Welcome(w) = MlsMessageIn::tls_deserialize_exact(&welcome)
            .unwrap()
            .extract()
        else {
            panic!("not a Welcome")
        };
        let gb = StagedWelcome::new_from_welcome(p_b, join, w, None)
            .unwrap()
            .into_group(p_b)
            .unwrap();
        (ga, gb)
    }

    /// What `to` reads from the message `sent`.
    fn open(p: &OpenMlsRustCrypto, to: &mut MlsGroup, sent: &MlsMessageOut) -> Option<AppMsg> {
        let bytes = sent.tls_serialize_detached().unwrap();
        let msg = MlsMessageIn::tls_deserialize_exact(&bytes)
            .unwrap()
            .try_into_protocol_message()
            .unwrap();
        match to.process_message(p, msg).unwrap().into_content() {
            ProcessedMessageContent::ApplicationMessage(m) => AppMsg::decode(&m.into_bytes()),
            _ => None,
        }
    }

    #[test]
    fn new_groups_pad_from_the_start() {
        assert_eq!(
            group_create_config(SUITE, &[]).padding_size(),
            PADDING_BLOCK
        );
        assert_eq!(group_join_config().padding_size(), PADDING_BLOCK);
        // A new room keeps exactly the join settings, so moving an older
        // room onto them changes nothing but the padding.
        let p = OpenMlsRustCrypto::default();
        let me = KeyPair::generate();
        assert_eq!(
            new_group(&p, &me, SUITE).configuration(),
            &group_join_config()
        );
    }

    #[test]
    fn short_texts_have_one_wire_size() {
        for suite in [SUITE, FALLBACK_SUITE] {
            let p = OpenMlsRustCrypto::default();
            let me = KeyPair::generate();
            let mut g = new_group(&p, &me, suite);
            let one = wire_len(&p, &me, &mut g, 1);
            for chars in [0, 50, 100, 160, 169] {
                assert_eq!(wire_len(&p, &me, &mut g, chars), one, "{chars} characters");
            }
        }
    }

    #[test]
    fn one_byte_over_takes_the_next_block() {
        let p = OpenMlsRustCrypto::default();
        let me = KeyPair::generate();
        let mut g = new_group(&p, &me, SUITE);
        let one = wire_len(&p, &me, &mut g, 1);
        let fits = (1..2000)
            .take_while(|&n| wire_len(&p, &me, &mut g, n) == one)
            .last()
            .unwrap();
        assert_eq!(fits, 169, "the longest text that fits one block");
        assert_eq!(wire_len(&p, &me, &mut g, fits + 1), one + PADDING_BLOCK);
        // Every length lands on a whole block.
        for n in 1..=2000 {
            let extra = wire_len(&p, &me, &mut g, n) - one;
            assert_eq!(extra % PADDING_BLOCK, 0, "{n} characters");
        }
    }

    #[test]
    fn padded_messages_open_in_a_0_5_1_app() {
        let (p_a, p_b) = (OpenMlsRustCrypto::default(), OpenMlsRustCrypto::default());
        let (a, b) = (KeyPair::generate(), KeyPair::generate());
        let (mut ga, mut gb) = pair(
            &p_a,
            &a,
            &group_create_config(SUITE, &[a.public()]),
            &p_b,
            &b,
            &join_config_0_5_1(),
        );
        assert_eq!(
            wire_len(&p_a, &a, &mut ga, 1),
            wire_len(&p_a, &a, &mut ga, 160)
        );
        for body in ["", "hi", &"x".repeat(170), &"y".repeat(5000)] {
            let m = AppMsg::Text { body: body.into() };
            let sent = ga.create_message(&p_a, &a, &m.encode()).unwrap();
            assert_eq!(open(&p_b, &mut gb, &sent), Some(m));
        }
    }

    #[test]
    fn messages_from_a_0_5_1_app_still_open() {
        let (p_a, p_b) = (OpenMlsRustCrypto::default(), OpenMlsRustCrypto::default());
        let (a, b) = (KeyPair::generate(), KeyPair::generate());
        let (mut ga, mut gb) = pair(
            &p_a,
            &a,
            &create_config_0_5_1(SUITE, &[a.public()]),
            &p_b,
            &b,
            &group_join_config(),
        );
        assert_eq!(gb.configuration().padding_size(), PADDING_BLOCK);
        // The 0.5.1 sender pads nothing.
        assert_ne!(
            wire_len(&p_a, &a, &mut ga, 1),
            wire_len(&p_a, &a, &mut ga, 2)
        );
        for body in ["", "hi", &"z".repeat(5000)] {
            let m = AppMsg::Text { body: body.into() };
            let sent = ga.create_message(&p_a, &a, &m.encode()).unwrap();
            assert_eq!(open(&p_b, &mut gb, &sent), Some(m));
        }
    }

    #[test]
    fn a_room_from_before_padding_pads_once_loaded() {
        let p = OpenMlsRustCrypto::default();
        let me = KeyPair::generate();
        let gid = MlsGroup::new(
            &p,
            &me,
            &create_config_0_5_1(SUITE, &[me.public()]),
            me.credential(),
        )
        .unwrap()
        .group_id()
        .clone();
        let raw = MlsGroup::load(p.storage(), &gid).unwrap().unwrap();
        assert_eq!(raw.configuration().padding_size(), 0, "stored before 0.5.2");

        let mut g = load_group(p.storage(), &gid).unwrap().unwrap();
        assert_eq!(g.configuration(), &group_join_config());
        assert_eq!(wire_len(&p, &me, &mut g, 1), wire_len(&p, &me, &mut g, 160));
        // The new setting is stored, so the next load needs no change.
        let again = MlsGroup::load(p.storage(), &gid).unwrap().unwrap();
        assert_eq!(again.configuration().padding_size(), PADDING_BLOCK);
    }

    #[test]
    fn loading_a_missing_room_finds_nothing() {
        let p = OpenMlsRustCrypto::default();
        let gid = openmls::group::GroupId::from_slice(&[9; 16]);
        assert!(load_group(p.storage(), &gid).unwrap().is_none());
    }

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

    /// Bo's KeyPackages with the capabilities an app up to 0.5.1 has.
    fn old_key_package(p: &OpenMlsRustCrypto, b: &KeyPair) -> KeyPackage {
        KeyPackage::builder()
            .leaf_node_capabilities(capabilities_0_5_1())
            .build(SUITE, p, b, b.credential())
            .unwrap()
            .key_package()
            .clone()
    }

    /// Alice's commit that sets the room's settings, staged in `ga`.
    fn commit_settings(
        p: &OpenMlsRustCrypto,
        a: &KeyPair,
        ga: &mut MlsGroup,
        settings: &RoomSettings,
    ) -> Result<MlsMessageOut, String> {
        let admins = admins_from(ga.extensions());
        let bundle = ga
            .commit_builder()
            .propose_group_context_extensions(group_context_extensions(&admins, settings))
            .map_err(|e| e.to_string())?
            .load_psks(p.storage())
            .map_err(|e| e.to_string())?
            .build(p.rand(), p.crypto(), a, |_| true)
            .map_err(|e| e.to_string())?
            .stage_commit(p)
            .map_err(|e| e.to_string())?;
        Ok(bundle.into_messages().0)
    }

    fn admins_only() -> RoomSettings {
        RoomSettings::new(crate::settings::WhoCanInvite::Admins, 20)
    }

    #[test]
    fn settings_reach_every_member() {
        let (p_a, p_b) = (OpenMlsRustCrypto::default(), OpenMlsRustCrypto::default());
        let (a, b) = (KeyPair::generate(), KeyPair::generate());
        let (mut ga, mut gb) = pair(
            &p_a,
            &a,
            &group_create_config(SUITE, &[a.public()]),
            &p_b,
            &b,
            &group_join_config(),
        );
        let commit = commit_settings(&p_a, &a, &mut ga, &admins_only()).unwrap();
        ga.merge_pending_commit(&p_a).unwrap();
        let bytes = commit.tls_serialize_detached().unwrap();
        let msg = MlsMessageIn::tls_deserialize_exact(&bytes)
            .unwrap()
            .try_into_protocol_message()
            .unwrap();
        let ProcessedMessageContent::StagedCommitMessage(sc) =
            gb.process_message(&p_b, msg).unwrap().into_content()
        else {
            panic!("not a commit")
        };
        assert_eq!(
            crate::settings::settings_in(sc.group_context().extensions()),
            Some(admins_only())
        );
        gb.merge_staged_commit(&p_b, *sc).unwrap();
        for g in [&ga, &gb] {
            assert_eq!(
                crate::settings::room_settings(g.extensions()),
                admins_only()
            );
            assert_eq!(admins_from(g.extensions()), vec![a.public()]);
        }
    }

    /// While a member's app predates settings, MLS itself refuses to set
    /// them; going back to the defaults works with anyone.
    #[test]
    fn settings_need_every_member_to_take_them() {
        let (p_a, p_b) = (OpenMlsRustCrypto::default(), OpenMlsRustCrypto::default());
        let (a, b) = (KeyPair::generate(), KeyPair::generate());
        let mut ga = MlsGroup::new(
            &p_a,
            &a,
            &group_create_config(SUITE, &[a.public()]),
            a.credential(),
        )
        .unwrap();
        let kp = old_key_package(&p_b, &b);
        ga.add_members(&p_a, &a, &[kp]).unwrap();
        ga.merge_pending_commit(&p_a).unwrap();
        assert!(commit_settings(&p_a, &a, &mut ga, &admins_only()).is_err());
        ga.clear_pending_commit(p_a.storage()).unwrap();
        commit_settings(&p_a, &a, &mut ga, &RoomSettings::default()).unwrap();
    }

    /// A room with settings takes no one whose app predates them.
    #[test]
    fn a_room_with_settings_refuses_an_old_joiner() {
        let (p_a, p_b) = (OpenMlsRustCrypto::default(), OpenMlsRustCrypto::default());
        let (a, b) = (KeyPair::generate(), KeyPair::generate());
        let mut ga = MlsGroup::new(
            &p_a,
            &a,
            &group_create_config(SUITE, &[a.public()]),
            a.credential(),
        )
        .unwrap();
        commit_settings(&p_a, &a, &mut ga, &admins_only()).unwrap();
        ga.merge_pending_commit(&p_a).unwrap();
        let old = old_key_package(&p_b, &b);
        assert!(!takes_settings(old.leaf_node().capabilities()));
        assert!(ga.add_members(&p_a, &a, &[old]).is_err());
        let blob = crate::invite::key_package_blob(&p_b, &b).unwrap();
        let new = crate::invite::pick_key_package(&p_a, &blob, SUITE).unwrap();
        assert!(takes_settings(new.leaf_node().capabilities()));
        ga.add_members(&p_a, &a, &[new]).unwrap();
    }

    #[test]
    fn default_settings_keep_the_old_context() {
        let me = KeyPair::generate().public();
        let exts = group_context_extensions(&[me], &RoomSettings::default());
        assert_eq!(exts.iter().count(), 2);
        assert!(exts
            .iter()
            .all(|e| !matches!(e, Extension::Unknown(t, _) if *t == ROOM_SETTINGS_EXT)));
        let exts = group_context_extensions(&[me], &admins_only());
        assert_eq!(exts.iter().count(), 3);
        assert!(exts
            .required_capabilities()
            .unwrap()
            .extension_types()
            .contains(&ExtensionType::Unknown(ROOM_SETTINGS_EXT)));
    }

    #[test]
    fn parse_admins_ignores_garbage() {
        let ext = Extension::Unknown(ADMINS_EXT, UnknownExtension(vec![0, 40, 1, 2]));
        assert!(decode_admins(&ext).is_empty());
    }
}
