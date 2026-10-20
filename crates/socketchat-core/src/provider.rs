//! The OpenMLS provider: RustCrypto for the cryptography, and OpenMLS's
//! SQLite storage on an encrypted SQLCipher connection.

use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;

/// Serializes OpenMLS's stored values as JSON, as OpenMLS's own examples do.
#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

pub type Storage = SqliteStorageProvider<JsonCodec, rusqlite::Connection>;

pub struct Provider {
    crypto: RustCrypto,
    storage: Storage,
}

impl Provider {
    pub(crate) fn new(storage: Storage) -> Self {
        Provider {
            crypto: RustCrypto::default(),
            storage,
        }
    }
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = Storage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
