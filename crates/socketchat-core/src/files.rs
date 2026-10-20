//! Files, photos and videos.
//!
//! Each file gets a fresh random key and travels in 64 KiB chunks, each
//! sealed with XChaCha20-Poly1305 in the STREAM construction, which catches
//! chunks that were changed, dropped or reordered. The key, name and hash
//! travel inside the group's encrypted messages; the server stores only the
//! sealed chunks.

use std::io::Read;

use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use img_parts::jpeg::Jpeg;
use img_parts::png::Png;
use img_parts::webp::WebP;
use img_parts::{Bytes, ImageEXIF};
use serde::{Deserialize, Serialize};
use socketchat_proto::msg::FileId;

use crate::CoreError;

/// Plaintext bytes per chunk.
pub const CHUNK: usize = 64 * 1024;
/// Bytes the cipher adds to each chunk.
pub const TAG: usize = 16;

/// What a group member needs to fetch, open and check a file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOffer {
    pub id: FileId,
    pub name: String,
    pub size: u64,
    pub mime: String,
    pub sha256: [u8; 32],
    pub key: [u8; 32],
    pub nonce_prefix: [u8; 19],
}

impl FileOffer {
    /// Whether this is a photo the sender's app cleaned of location and
    /// device data before sending. Other files and videos go as they are.
    pub fn metadata_removed(&self) -> bool {
        [Kind::Jpeg, Kind::Png, Kind::WebP]
            .iter()
            .any(|k| self.mime == mime(*k))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Jpeg,
    Png,
    WebP,
    Video,
    Other,
}

/// Recognizes a file by its first bytes, not its name.
pub fn sniff(head: &[u8]) -> Kind {
    let at = |o: usize, m: &[u8]| head.len() >= o + m.len() && &head[o..o + m.len()] == m;
    if at(0, b"\xff\xd8\xff") {
        Kind::Jpeg
    } else if at(0, b"\x89PNG\r\n\x1a\n") {
        Kind::Png
    } else if at(0, b"RIFF") && at(8, b"WEBP") {
        Kind::WebP
    } else if at(4, b"ftyp") || at(0, b"\x1a\x45\xdf\xa3") || (at(0, b"RIFF") && at(8, b"AVI ")) {
        Kind::Video
    } else {
        Kind::Other
    }
}

pub fn mime(kind: Kind) -> &'static str {
    match kind {
        Kind::Jpeg => "image/jpeg",
        Kind::Png => "image/png",
        Kind::WebP => "image/webp",
        Kind::Video => "video",
        Kind::Other => "application/octet-stream",
    }
}

/// Removes location, device and other hidden text from a photo without
/// touching its pixels.
pub fn strip_image(kind: Kind, bytes: Vec<u8>) -> Result<Vec<u8>, CoreError> {
    let bad = |e: img_parts::Error| CoreError::Other(format!("could not read the image: {e}"));
    let out = match kind {
        Kind::Jpeg => {
            let mut j = Jpeg::from_bytes(Bytes::from(bytes)).map_err(bad)?;
            // APP1-APP13 and APP15 hold EXIF, XMP, IPTC and maker notes;
            // APP14 (Adobe colour) and APP0 (JFIF) are kept. COM is comments.
            j.segments_mut().retain(|s| {
                let m = s.marker();
                !((0xE1..=0xED).contains(&m) || m == 0xEF || m == 0xFE)
            });
            j.encoder().bytes()
        }
        Kind::Png => {
            let mut p = Png::from_bytes(Bytes::from(bytes)).map_err(bad)?;
            p.chunks_mut()
                .retain(|c| !matches!(&c.kind(), b"eXIf" | b"tEXt" | b"iTXt" | b"zTXt" | b"tIME"));
            p.encoder().bytes()
        }
        Kind::WebP => {
            let mut w = WebP::from_bytes(Bytes::from(bytes)).map_err(bad)?;
            w.set_exif(None);
            w.remove_chunks_by_id(*b"XMP ");
            w.encoder().bytes()
        }
        _ => return Ok(bytes),
    };
    Ok(out.to_vec())
}

/// How many chunks a file of `size` bytes takes. An empty file takes one.
pub fn chunk_count(size: u64) -> u32 {
    size.div_ceil(CHUNK as u64).max(1) as u32
}

/// Reads until `buf` is full or the reader ends. Returns bytes read.
pub fn fill(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

pub fn encryptor(key: &[u8; 32], prefix: &[u8; 19]) -> EncryptorBE32<XChaCha20Poly1305> {
    EncryptorBE32::from_aead(XChaCha20Poly1305::new(key.into()), prefix.into())
}

pub fn decryptor(key: &[u8; 32], prefix: &[u8; 19]) -> DecryptorBE32<XChaCha20Poly1305> {
    DecryptorBE32::from_aead(XChaCha20Poly1305::new(key.into()), prefix.into())
}

/// A safe file name to save as: the last path part only, with unsafe
/// characters removed.
pub fn safe_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = crate::sanitize::clean_name(base)
        .chars()
        .filter(|c| !matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        .collect();
    let cleaned = cleaned.trim_start_matches('.').trim().to_string();
    if cleaned.is_empty() {
        "file".into()
    } else {
        cleaned
    }
}

/// `name`, or `name (1)`, `name (2)` and so on, before the extension.
pub fn numbered(name: &str, k: u32) -> String {
    if k == 0 {
        return name.to_string();
    }
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem} ({k}).{ext}"),
        _ => format!("{name} ({k})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_by_content() {
        assert_eq!(sniff(b"\xff\xd8\xff\xe0...."), Kind::Jpeg);
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\n...."), Kind::Png);
        assert_eq!(sniff(b"RIFF\0\0\0\0WEBPVP8 "), Kind::WebP);
        assert_eq!(sniff(b"\0\0\0\x18ftypmp42"), Kind::Video);
        assert_eq!(sniff(b"\x1a\x45\xdf\xa3...."), Kind::Video);
        assert_eq!(sniff(b"hello"), Kind::Other);
    }

    #[test]
    fn chunk_counts() {
        assert_eq!(chunk_count(0), 1);
        assert_eq!(chunk_count(1), 1);
        assert_eq!(chunk_count(CHUNK as u64), 1);
        assert_eq!(chunk_count(CHUNK as u64 + 1), 2);
    }

    #[test]
    fn names_stay_inside_the_folder() {
        assert_eq!(safe_name("../../etc/passwd"), "passwd");
        assert_eq!(safe_name("C:\\Users\\x\\evil.exe"), "evil.exe");
        assert_eq!(safe_name(".bashrc"), "bashrc");
        assert_eq!(safe_name(""), "file");
        assert_eq!(numbered("a.txt", 2), "a (2).txt");
        assert_eq!(numbered("README", 1), "README (1)");
    }

    #[test]
    fn stream_roundtrip_and_tamper() {
        let (key, prefix) = ([7u8; 32], [9u8; 19]);
        let mut e = encryptor(&key, &prefix);
        let a = e.encrypt_next(b"first".as_slice()).unwrap();
        let b = e.encrypt_last(b"second".as_slice()).unwrap();
        let mut d = decryptor(&key, &prefix);
        assert_eq!(d.decrypt_next(a.as_slice()).unwrap(), b"first");
        assert_eq!(d.decrypt_last(b.as_slice()).unwrap(), b"second");
        // Swapping order fails.
        let mut d = decryptor(&key, &prefix);
        assert!(d.decrypt_next(b.as_slice()).is_err());
    }
}
