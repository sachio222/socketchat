//! KeyPackages for joining. A joiner does not know which suite the group
//! uses, so it lodges one KeyPackage per suite socketchat allows, and the
//! person adding them picks the one that matches.

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;

use crate::keys::KeyPair;
use crate::suite::{capabilities, FALLBACK_SUITE, SUITE};
use crate::CoreError;

/// KeyPackages for `key`, one per allowed suite, encoded as one blob. The
/// private parts land in the provider's storage.
pub fn key_package_blob(prov: &impl OpenMlsProvider, key: &KeyPair) -> Result<Vec<u8>, CoreError> {
    let mut kps = Vec::new();
    for suite in [SUITE, FALLBACK_SUITE] {
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .build(suite, prov, key, key.credential())
            .map_err(|e| CoreError::Mls(e.to_string()))?;
        kps.push(
            bundle
                .key_package()
                .tls_serialize_detached()
                .map_err(|e| CoreError::Mls(e.to_string()))?,
        );
    }
    Ok(postcard::to_stdvec(&kps)?)
}

/// The KeyPackage in `blob` for `suite`, checked.
pub fn pick_key_package(
    prov: &impl OpenMlsProvider,
    blob: &[u8],
    suite: Ciphersuite,
) -> Option<KeyPackage> {
    let kps: Vec<Vec<u8>> = postcard::from_bytes(blob).ok()?;
    kps.iter().find_map(|b| {
        let kp = KeyPackageIn::tls_deserialize_exact(b)
            .ok()?
            .validate(prov.crypto(), ProtocolVersion::Mls10)
            .ok()?;
        (kp.ciphersuite() == suite).then_some(kp)
    })
}

/// Whole hours from `now_unix` until `expires_unix`, rounded to the nearest
/// hour so a few seconds of travel time or clock drift do not show.
pub fn hours_left(expires_unix: u64, now_unix: u64) -> u64 {
    (expires_unix.saturating_sub(now_unix) + 1800) / 3600
}

/// "1 hour" or "N hours", for sentences about when a link expires.
pub fn hours_text(hours: u64) -> String {
    if hours == 1 {
        "1 hour".into()
    } else {
        format!("{hours} hours")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hours_left_rounds_to_the_nearest_hour() {
        let now = 1_800_000_000;
        assert_eq!(hours_left(now + 2 * 3600, now), 2);
        assert_eq!(hours_left(now + 2 * 3600 - 5, now), 2);
        assert_eq!(hours_left(now + 2 * 3600 + 5, now), 2);
        assert_eq!(hours_left(now + 48 * 3600, now), 48);
        assert_eq!(hours_left(now, now + 10), 0, "already expired");
    }

    #[test]
    fn hours_text_counts_one_hour_as_singular() {
        assert_eq!(hours_text(1), "1 hour");
        assert_eq!(hours_text(2), "2 hours");
        assert_eq!(hours_text(24), "24 hours");
    }
}
