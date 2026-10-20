//! The server's self-signed certificate. Clients pin its SHA-256, which
//! travels in every invite link, so no certificate authority is involved.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio_rustls::TlsAcceptor;

use crate::ServerError;

pub const CERT_FILE: &str = "cert.der";
pub const KEY_FILE: &str = "key.der";

/// Makes a certificate for `host` and writes it to `dir`. Refuses to replace
/// an existing one, since that would break every invite link already sent.
pub fn create(dir: &Path, host: &str) -> Result<[u8; 32], ServerError> {
    let (cert_path, key_path) = (dir.join(CERT_FILE), dir.join(KEY_FILE));
    if cert_path.exists() || key_path.exists() {
        return Err(ServerError::Config(format!(
            "{} already has a certificate; delete cert.der and key.der to make a new one",
            dir.display()
        )));
    }
    let ck = rcgen::generate_simple_self_signed(vec![host.to_string()])
        .map_err(|e| ServerError::Tls(e.to_string()))?;
    std::fs::write(&cert_path, ck.cert.der())?;
    write_private(&key_path, &ck.signing_key.serialize_der())?;
    Ok(Sha256::digest(ck.cert.der()).into())
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

/// SHA-256 of the stored certificate.
pub fn fingerprint(dir: &Path) -> Result<[u8; 32], ServerError> {
    let der = std::fs::read(dir.join(CERT_FILE))?;
    Ok(Sha256::digest(der).into())
}

/// A TLS 1.3 acceptor for the stored certificate.
pub fn acceptor(dir: &Path) -> Result<TlsAcceptor, ServerError> {
    let cert = CertificateDer::from(std::fs::read(dir.join(CERT_FILE))?);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::fs::read(dir.join(KEY_FILE))?));
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| ServerError::Tls(e.to_string()))?
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .map_err(|e| ServerError::Tls(e.to_string()))?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}
