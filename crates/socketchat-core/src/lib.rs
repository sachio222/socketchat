//! The socketchat client engine, with no screen.
//!
//! Tests drive several of these at once against a real server; the terminal
//! app is one front end on top.

pub mod error;
pub mod keys;
pub mod suite;

pub use error::CoreError;
pub use socketchat_proto as proto;
