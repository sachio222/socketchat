//! The socketchat client engine, with no screen.
//!
//! Tests drive several of these at once against a real server; the terminal
//! app is one front end on top.

pub mod appmsg;
pub mod client;
pub mod close;
pub mod error;
pub mod files;
pub mod invite;
pub mod keys;
pub mod net;
mod perms;
pub mod provider;
pub mod sanitize;
pub mod settings;
pub mod store;
pub mod suite;
pub mod topic;
pub mod update;

pub use error::CoreError;
pub use socketchat_proto as proto;

/// Text that a built program holds only when the `test-hooks` feature is on.
/// `scripts/release-binary-check.sh` fails a release build that holds it.
#[cfg(feature = "test-hooks")]
pub const TEST_HOOKS_MARKER: &str = "socketchat-core test-hooks compiled in";

/// Keeps [`TEST_HOOKS_MARKER`] in every program that can open a profile, so
/// the release check finds it even after the linker drops unused data.
#[cfg(feature = "test-hooks")]
#[inline(never)]
pub(crate) fn keep_test_hooks_marker() {
    std::hint::black_box(TEST_HOOKS_MARKER);
}

/// Seconds since 1970, from the system clock.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
