//! The socketchat client engine, with no screen.
//!
//! Tests drive several of these at once against a real server; the terminal
//! app is one front end on top.

pub mod error;
pub mod keys;
pub mod net;
pub mod provider;
pub mod store;
pub mod suite;

pub use error::CoreError;
pub use socketchat_proto as proto;

/// Seconds since 1970, from the system clock.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
