//! Files, photos and videos.
//!
//! Each file gets a fresh random key and travels in 64 KiB chunks, each
//! sealed with XChaCha20-Poly1305 in the STREAM construction, which catches
//! chunks that were changed, dropped or reordered. The key, name and hash
//! travel inside the group's encrypted messages; the server stores only the
//! sealed chunks.

use std::io::Read;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
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
        CLEANED.iter().any(|k| self.mime == mime(*k))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Jpeg,
    Png,
    WebP,
    Gif,
    Video,
    /// A photo Socketchat cannot clean, such as HEIC, TIFF or camera raw.
    /// Like a video, it goes as it is once the person says yes.
    OtherPhoto,
    Other,
}

/// Photo kinds Socketchat cleans before sending. The send path and the
/// "cleaned" claim both read this list, so they cannot disagree.
pub const CLEANED: [Kind; 4] = [Kind::Jpeg, Kind::Png, Kind::WebP, Kind::Gif];

/// Largest photo Socketchat cleans. A bigger one goes as it is, once the
/// person says yes.
pub const MAX_PHOTO_BYTES: u64 = 100 * 1024 * 1024;

/// Major brands of ISO media files (`ftyp`) that hold still pictures:
/// HEIF and HEIC, AVIF, and Canon CR3 raw.
const PHOTO_BRANDS: &[&[u8; 4]] = &[
    b"heic", b"heix", b"heim", b"heis", b"hevc", b"hevx", b"hevm", b"hevs", b"mif1", b"msf1",
    b"avif", b"avis", b"crx ",
];

/// Recognizes a file by its first bytes, not its name. Reads at most 16.
pub fn sniff(head: &[u8]) -> Kind {
    let at = |o: usize, m: &[u8]| head.len() >= o + m.len() && &head[o..o + m.len()] == m;
    let photo_brand = PHOTO_BRANDS.iter().any(|b| at(8, &b[..]));
    if at(0, b"\xff\xd8\xff") {
        Kind::Jpeg
    } else if at(0, b"\x89PNG\r\n\x1a\n") {
        Kind::Png
    } else if at(0, b"RIFF") && at(8, b"WEBP") {
        Kind::WebP
    } else if at(0, b"GIF87a") || at(0, b"GIF89a") {
        Kind::Gif
    } else if at(4, b"ftyp") && photo_brand
        // TIFF and the camera raw formats built on it (DNG, NEF, CR2,
        // ARW, ORF, RW2), and BigTIFF.
        || at(0, b"II*\0")
        || at(0, b"MM\0*")
        || at(0, b"II+\0")
        || at(0, b"MM\0+")
        || at(0, b"IIRO")
        || at(0, b"IIRS")
        || at(0, b"IIU\0")
        || at(0, b"FUJIFILMCCD-RAW")
        // JPEG XL, bare and boxed, and JPEG 2000.
        || at(0, b"\xff\x0a")
        || at(0, b"\0\0\0\x0cJXL \r\n\x87\n")
        || at(0, b"\0\0\0\x0cjP  \r\n\x87\n")
        // Photoshop.
        || at(0, b"8BPS")
    {
        Kind::OtherPhoto
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
        Kind::Gif => "image/gif",
        Kind::Video => "video",
        Kind::OtherPhoto => "image",
        Kind::Other => "application/octet-stream",
    }
}

/// Removes location, device and other hidden data from a photo without
/// touching its pixels. It writes a new file holding only what a viewer
/// needs to draw the picture, so data it does not know about goes too:
/// thumbnails, second images (depth maps, HDR gain maps, motion-photo
/// video), and anything after the end of the picture. A JPEG keeps one
/// EXIF value, its orientation, so a photo taken sideways shows upright.
/// A photo larger than
/// [`MAX_PHOTO_BYTES`], or one it cannot read, is refused.
pub fn strip_image(kind: Kind, bytes: Vec<u8>) -> Result<Vec<u8>, CoreError> {
    if bytes.len() as u64 > MAX_PHOTO_BYTES {
        return Err(CoreError::Other("the photo is too big to clean".into()));
    }
    let out = match kind {
        Kind::Jpeg => clean_jpeg(&bytes),
        Kind::Png => clean_png(&bytes),
        Kind::WebP => clean_webp(&bytes),
        Kind::Gif => clean_gif(&bytes),
        _ => return Ok(bytes),
    };
    out.map_err(|why| CoreError::Other(format!("could not read the image: {why}")))
}

/// JPEG segments a decoder needs: frame headers (SOF0 to SOF15, without
/// the reserved JPG marker), Huffman and arithmetic tables, quantization
/// tables, line count and restart interval. JPEG-LS and other extensions
/// are refused.
fn jpeg_needs(marker: u8) -> bool {
    matches!(marker, 0xC0..=0xC7 | 0xC9..=0xCF | 0xDB..=0xDD)
}

/// The Orientation value (1 to 8) in the first IFD of an EXIF APP1 body,
/// if it holds one as a single SHORT.
fn exif_orientation(body: &[u8]) -> Option<u16> {
    let t = body.strip_prefix(b"Exif\0\0")?;
    let be = match t.get(..4)? {
        b"MM\0*" => true,
        b"II*\0" => false,
        _ => return None,
    };
    let u16_of = |b: &[u8]| match be {
        true => u16::from_be_bytes([b[0], b[1]]),
        false => u16::from_le_bytes([b[0], b[1]]),
    };
    let u32_of = |b: &[u8]| match be {
        true => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        false => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
    };
    let ifd = u32_of(t.get(4..8)?) as usize;
    let count = u16_of(t.get(ifd..ifd.checked_add(2)?)?) as usize;
    for i in 0..count {
        let at = ifd.checked_add(2 + 12 * i)?;
        let entry = t.get(at..at.checked_add(12)?)?;
        if u16_of(&entry[..2]) == 0x0112 {
            let value = u16_of(&entry[8..10]);
            let single_short = u16_of(&entry[2..4]) == 3 && u32_of(&entry[4..8]) == 1;
            return (single_short && (1..=8).contains(&value)).then_some(value);
        }
    }
    None
}

/// An EXIF APP1 body holding Orientation `o` and nothing else.
fn orientation_exif(o: u16) -> Vec<u8> {
    let mut v = b"Exif\0\0MM\0*\0\0\0\x08\0\x01\x01\x12\0\x03\0\0\0\x01".to_vec();
    v.extend_from_slice(&o.to_be_bytes());
    v.extend_from_slice(&[0; 6]);
    v
}

fn put_segment(out: &mut Vec<u8>, marker: u8, body: &[u8]) {
    out.extend_from_slice(&[0xFF, marker]);
    out.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
    out.extend_from_slice(body);
}

/// Where a scan's coded data ends: at the first marker that is not a
/// stuffed zero or a restart.
fn scan_end(b: &[u8], from: usize) -> usize {
    let mut i = from;
    while let Some(off) = b[i..].iter().position(|&x| x == 0xFF) {
        let j = i + off;
        match b.get(j + 1) {
            Some(0x00 | 0xD0..=0xD7) => i = j + 2,
            _ => return j,
        }
    }
    b.len()
}

/// Rewrites a JPEG from the start of image to its first end of image,
/// keeping the tables, frame and scans, a bare JFIF header with no
/// thumbnail, the Adobe colour-transform flag, and a new EXIF block with
/// only the first EXIF block's orientation. Every other APPn and
/// comment goes, wherever it sits, and so does everything after the end.
/// A file cut short inside a scan is closed.
fn clean_jpeg(b: &[u8]) -> Result<Vec<u8>, &'static str> {
    if !b.starts_with(&[0xFF, 0xD8]) {
        return Err("it is not a JPEG");
    }
    let mut out = Vec::with_capacity(b.len());
    out.extend_from_slice(&[0xFF, 0xD8]);
    let (mut pos, mut scans) = (2, 0usize);
    let (mut jfif, mut adobe, mut exif) = (false, false, false);
    loop {
        if pos >= b.len() {
            break;
        }
        if b[pos] != 0xFF {
            return Err("its structure is broken");
        }
        // Any number of fill bytes may come before a marker.
        while b.get(pos + 1) == Some(&0xFF) {
            pos += 1;
        }
        let Some(&marker) = b.get(pos + 1) else {
            break;
        };
        pos += 2;
        match marker {
            0xD9 if scans > 0 => {
                out.extend_from_slice(&[0xFF, 0xD9]);
                return Ok(out);
            }
            // Markers with no length and nothing a decoder needs.
            0x01 | 0xD0..=0xD7 => continue,
            0x00 | 0xD8 | 0xD9 => return Err("its structure is broken"),
            _ => {}
        }
        let Some(len) = b.get(pos..pos + 2) else {
            break;
        };
        let len = u16::from_be_bytes([len[0], len[1]]) as usize;
        if len < 2 {
            return Err("its structure is broken");
        }
        let Some(body) = b.get(pos + 2..pos + len) else {
            break;
        };
        pos += len;
        match marker {
            0xDA => {
                put_segment(&mut out, marker, body);
                let end = scan_end(b, pos);
                out.extend_from_slice(&b[pos..end]);
                scans += 1;
                pos = end;
            }
            // JFIF: identifier, version, units and density; no thumbnail.
            0xE0 if !jfif && body.len() >= 14 && body.starts_with(b"JFIF\0") => {
                jfif = true;
                let mut header = body[..12].to_vec();
                header.extend_from_slice(&[0, 0]);
                put_segment(&mut out, marker, &header);
            }
            // EXIF: only the orientation, from the first block.
            0xE1 if !exif && body.starts_with(b"Exif\0\0") => {
                exif = true;
                if let Some(o) = exif_orientation(body) {
                    put_segment(&mut out, marker, &orientation_exif(o));
                }
            }
            // Adobe: identifier, version, flags and colour transform.
            0xEE if !adobe && body.len() >= 12 && body.starts_with(b"Adobe") => {
                adobe = true;
                put_segment(&mut out, marker, &body[..12]);
            }
            0xE0..=0xEF | 0xFE => {}
            m if jpeg_needs(m) => put_segment(&mut out, m, body),
            _ => return Err("it uses a JPEG feature Socketchat cannot clean"),
        }
    }
    if scans == 0 {
        return Err("it ends before the picture");
    }
    out.extend_from_slice(&[0xFF, 0xD9]);
    Ok(out)
}

/// PNG chunks that draw the picture: the critical chunks, transparency,
/// colour space and gamma, background, pixel size and animation.
const PNG_DRAWS: &[&[u8; 4]] = &[
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"cHRM", b"gAMA", b"sBIT", b"sRGB", b"cICP",
    b"mDCV", b"cLLI", b"bKGD", b"pHYs", b"acTL", b"fcTL", b"fdAT",
];

/// Rewrites a PNG with only the chunks in [`PNG_DRAWS`], up to its end
/// chunk.
fn clean_png(b: &[u8]) -> Result<Vec<u8>, &'static str> {
    const SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";
    if !b.starts_with(SIGNATURE) {
        return Err("it is not a PNG");
    }
    let mut out = SIGNATURE.to_vec();
    let mut pos = SIGNATURE.len();
    loop {
        let head = b.get(pos..pos + 8).ok_or("it is cut short")?;
        let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
        let end = (pos + 12).checked_add(len).ok_or("it is cut short")?;
        let chunk = b.get(pos..end).ok_or("it is cut short")?;
        let kind = &chunk[4..8];
        if PNG_DRAWS.iter().any(|k| &k[..] == kind) {
            out.extend_from_slice(chunk);
        }
        if kind == b"IEND" {
            return Ok(out);
        }
        pos = end;
    }
}

/// One RIFF chunk inside `b[..end]` at `pos`: its id, its data and where
/// the next one starts.
fn riff_chunk(b: &[u8], pos: usize, end: usize) -> Result<(&[u8], &[u8], usize), &'static str> {
    let head = b.get(pos..pos + 8).filter(|_| pos + 8 <= end);
    let head = head.ok_or("it is cut short")?;
    let len = u32::from_le_bytes([head[4], head[5], head[6], head[7]]) as usize;
    let data_end = (pos + 8).checked_add(len).filter(|e| *e <= end);
    let data_end = data_end.ok_or("it is cut short")?;
    // Chunks are padded to an even length.
    Ok((
        &head[..4],
        &b[pos + 8..data_end],
        (data_end + (len & 1)).min(end),
    ))
}

fn put_riff_chunk(out: &mut Vec<u8>, id: &[u8], data: &[u8]) {
    out.extend_from_slice(id);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    if data.len() % 2 == 1 {
        out.push(0);
    }
}

/// Rewrites a WebP with only the chunks that draw the picture: the
/// header, the image and alpha data, and the animation and its frames,
/// each frame cleaned the same way. The header's flags then say there is
/// no colour profile, EXIF or XMP.
fn clean_webp(b: &[u8]) -> Result<Vec<u8>, &'static str> {
    if b.len() < 12 || &b[..4] != b"RIFF" || &b[8..12] != b"WEBP" {
        return Err("it is not a WebP");
    }
    let riff_len = u32::from_le_bytes([b[4], b[5], b[6], b[7]]) as usize;
    let end = b.len().min(riff_len.saturating_add(8));
    let mut body = b"WEBP".to_vec();
    let mut flags_at = None;
    let mut pos = 12;
    while pos < end {
        let (id, data, next) = riff_chunk(b, pos, end)?;
        match id {
            b"VP8X" if data.len() >= 10 && flags_at.is_none() => {
                flags_at = Some(body.len() + 8);
                put_riff_chunk(&mut body, id, &data[..10]);
            }
            b"VP8 " | b"VP8L" | b"ALPH" | b"ANIM" => put_riff_chunk(&mut body, id, data),
            b"ANMF" if data.len() >= 16 => {
                let mut frame = data[..16].to_vec();
                let mut at = 16;
                while at < data.len() {
                    let (id, d, next) = riff_chunk(data, at, data.len())?;
                    if matches!(id, b"VP8 " | b"VP8L" | b"ALPH") {
                        put_riff_chunk(&mut frame, id, d);
                    }
                    at = next;
                }
                put_riff_chunk(&mut body, id, &frame);
            }
            b"VP8X" | b"ANMF" => return Err("its structure is broken"),
            _ => {}
        }
        pos = next;
    }
    if let Some(at) = flags_at {
        // ICC profile, EXIF and XMP.
        body[at] &= !(0x20 | 0x08 | 0x04);
    }
    let mut out = b"RIFF".to_vec();
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend(body);
    Ok(out)
}

/// Bytes in a GIF colour table, from the packed field that announces it.
fn gif_colour_table(packed: u8) -> usize {
    match packed & 0x80 {
        0 => 0,
        _ => 3 << ((packed & 7) + 1),
    }
}

/// Where the run of GIF sub-blocks starting at `pos` ends, after its
/// zero-length terminator.
fn gif_sub_blocks_end(b: &[u8], mut pos: usize) -> Result<usize, &'static str> {
    loop {
        let len = *b.get(pos).ok_or("it is cut short")? as usize;
        pos += 1 + len;
        if len == 0 {
            return Ok(pos);
        }
        if pos > b.len() {
            return Err("it is cut short");
        }
    }
}

/// Rewrites a GIF with only what draws it: the header, screen descriptor
/// and colour tables, each image with its data, frame timing (graphic
/// control), and the loop count (`NETSCAPE2.0` or `ANIMEXTS1.0`), each
/// rebuilt in its standard form. Comments, plain text and every other
/// application block, XMP included, go, and so does anything after the
/// end. A GIF cut short between blocks is closed.
fn clean_gif(b: &[u8]) -> Result<Vec<u8>, &'static str> {
    if !(b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a")) {
        return Err("it is not a GIF");
    }
    let screen = b.get(6..13).ok_or("it is cut short")?;
    let mut pos = 13 + gif_colour_table(screen[4]);
    let mut out = b.get(..pos).ok_or("it is cut short")?.to_vec();
    let mut images = 0usize;
    while let Some(&block) = b.get(pos) {
        match block {
            0x3B => {
                out.push(0x3B);
                return Ok(out);
            }
            0x2C => {
                let desc = b.get(pos..pos + 10).ok_or("it is cut short")?;
                // Descriptor, local colour table, LZW code size, data.
                let data = pos + 10 + gif_colour_table(desc[9]) + 1;
                let end = gif_sub_blocks_end(b, data)?;
                out.extend_from_slice(&b[pos..end]);
                images += 1;
                pos = end;
            }
            0x21 => {
                let label = *b.get(pos + 1).ok_or("it is cut short")?;
                let end = gif_sub_blocks_end(b, pos + 2)?;
                let first = b.get(pos + 2..end).unwrap_or_default();
                match (label, first) {
                    (0xF9, [4, timing @ .., 0]) if timing.len() == 4 => {
                        out.extend_from_slice(&[0x21, 0xF9, 4]);
                        out.extend_from_slice(timing);
                        out.push(0);
                    }
                    (0xFF, [11, id @ .., 3, 1, lo, hi, 0])
                        if id == b"NETSCAPE2.0" || id == b"ANIMEXTS1.0" =>
                    {
                        out.extend_from_slice(&[0x21, 0xFF, 11]);
                        out.extend_from_slice(id);
                        out.extend_from_slice(&[3, 1, *lo, *hi, 0]);
                    }
                    _ => {}
                }
                pos = end;
            }
            _ => return Err("its structure is broken"),
        }
    }
    if images == 0 {
        return Err("it ends before the picture");
    }
    out.push(0x3B);
    Ok(out)
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
/// characters removed. It never starts with a dot (a hidden file on Unix),
/// never ends with a dot or space (which Windows drops on saving), and
/// never names a Windows device such as `CON` or `nul.txt`, which gets a
/// leading `_`.
pub fn safe_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = crate::sanitize::clean_name(base)
        .chars()
        .filter(|c| !matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        .collect();
    let cleaned = cleaned.trim_matches(|c: char| c == '.' || c.is_whitespace());
    if cleaned.is_empty() {
        "file".into()
    } else if windows_device(cleaned) {
        format!("_{cleaned}")
    } else {
        cleaned.to_string()
    }
}

/// Whether Windows reads `name` as a device: CON, PRN, AUX, NUL, CONIN$,
/// CONOUT$, COM0 to COM9 and LPT0 to LPT9 (with ¹, ² and ³ too), in any
/// case, with any extension and with spaces before it.
fn windows_device(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").trim_end();
    let stem = stem.to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    let port = stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"));
    let mut rest = port.unwrap_or("x").chars();
    matches!(
        (rest.next(), rest.next()),
        (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
    )
}

/// Makes a new file in `dir` for a download in progress, under a name no
/// one can know ahead of time.
pub fn create_part(dir: &Path, id: &FileId) -> std::io::Result<(std::fs::File, PathBuf)> {
    use rand_core::{OsRng, RngCore};
    for _ in 0..8 {
        let mut nonce = [0u8; 8];
        OsRng.fill_bytes(&mut nonce);
        let part = dir.join(format!(".socketchat-{}-{}.part", hex(&id.0), hex(&nonce)));
        match open_part(&part) {
            Ok(f) => return Ok((f, part)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not make a new file to download into",
    ))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// How long a part file stays untouched before it counts as left over.
pub const STALE_PART: std::time::Duration = std::time::Duration::from_secs(3600);

/// Deletes part files that earlier downloads of `id` left in `dir`, other
/// than `keep`: only regular files owned by the same account as `keep` and
/// untouched for [`STALE_PART`]. A link is never followed or removed. On
/// systems other than Unix it leaves them.
pub fn remove_stale_parts(dir: &Path, id: &FileId, keep: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(mine) = std::fs::symlink_metadata(keep).map(|m| m.uid()) else {
            return;
        };
        let prefix = format!(".socketchat-{}", hex(&id.0));
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let name = e.file_name();
            let Some(rest) = name
                .to_str()
                .and_then(|n| n.strip_prefix(prefix.as_str()))
                .and_then(|r| r.strip_suffix(".part"))
            else {
                continue;
            };
            let nonce = rest.strip_prefix('-');
            let named_ours = rest.is_empty()
                || nonce.is_some_and(|n| n.len() == 16 && n.bytes().all(|c| c.is_ascii_hexdigit()));
            let path = e.path();
            if !named_ours || path == keep {
                continue;
            }
            let Ok(m) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            let age = m.modified().ok().and_then(|t| t.elapsed().ok());
            if m.file_type().is_file() && m.uid() == mine && age.is_some_and(|a| a > STALE_PART) {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (dir, id, keep);
}

/// Opens `path` as a new file that only this account can read. It refuses
/// a file or a link already at `path`, so it never writes through a link
/// or empties someone's file.
pub fn open_part(path: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o.open(path)
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

/// Moves the finished download at `part` into `dir` as `name`, or the first
/// free numbered name, and never replaces an existing file. It hard-links
/// the file where the folder allows that, and copies it into a new file where
/// it does not, as on FAT32 and exFAT drives.
pub fn publish(part: &Path, dir: &Path, name: &str) -> std::io::Result<PathBuf> {
    publish_with(part, dir, name, |from, to| std::fs::hard_link(from, to))
}

/// `publish` with the hard-link step passed in, so tests can make it fail.
pub(crate) fn publish_with(
    part: &Path,
    dir: &Path,
    name: &str,
    link: impl Fn(&Path, &Path) -> std::io::Result<()>,
) -> std::io::Result<PathBuf> {
    use std::io::ErrorKind::AlreadyExists;
    let mut copy = false;
    let mut k = 0;
    let saved = loop {
        let candidate = dir.join(numbered(name, k));
        let placed = if copy {
            copy_new(part, &candidate)
        } else {
            match link(part, &candidate) {
                Err(e) if e.kind() != AlreadyExists => {
                    copy = true;
                    copy_new(part, &candidate)
                }
                r => r,
            }
        };
        match placed {
            Ok(()) => break candidate,
            Err(e) if e.kind() == AlreadyExists && k < 10_000 => k += 1,
            Err(e) => return Err(e),
        }
    };
    std::fs::remove_file(part)?;
    Ok(saved)
}

/// Copies `part` into `target`, which must not exist yet.
fn copy_new(part: &Path, target: &Path) -> std::io::Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut out = o.open(target)?;
    let copied = std::fs::File::open(part)
        .and_then(|mut src| std::io::copy(&mut src, &mut out))
        .and_then(|_| out.sync_all());
    if let Err(e) = copied {
        drop(out);
        let _ = std::fs::remove_file(target);
        return Err(e);
    }
    Ok(())
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

    fn part_with(dir: &std::path::Path, bytes: &[u8]) -> std::path::PathBuf {
        let part = dir.join(".socketchat-test.part");
        std::fs::write(&part, bytes).unwrap();
        part
    }

    #[test]
    fn publish_links_under_a_free_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"keep me").unwrap();
        let part = part_with(dir.path(), b"new");
        let saved = publish(&part, dir.path(), "a.txt").unwrap();
        assert_eq!(saved, dir.path().join("a (1).txt"));
        assert_eq!(std::fs::read(&saved).unwrap(), b"new");
        assert_eq!(std::fs::read(dir.path().join("a.txt")).unwrap(), b"keep me");
        assert!(!part.exists());
    }

    #[test]
    fn publish_copies_where_hard_links_fail() {
        // FAT32 and exFAT drives have no hard links.
        let dir = tempfile::tempdir().unwrap();
        let part = part_with(dir.path(), b"photo bytes");
        let no_links = |_: &std::path::Path, _: &std::path::Path| {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "no hard links here",
            ))
        };
        let saved = publish_with(&part, dir.path(), "p.jpg", no_links).unwrap();
        assert_eq!(saved, dir.path().join("p.jpg"));
        assert_eq!(std::fs::read(&saved).unwrap(), b"photo bytes");
        assert!(!part.exists());
    }

    #[test]
    fn publish_copy_never_replaces_a_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("p.jpg"), b"old").unwrap();
        std::fs::write(dir.path().join("p (1).jpg"), b"older").unwrap();
        let part = part_with(dir.path(), b"new");
        let no_links = |_: &std::path::Path, _: &std::path::Path| {
            Err(std::io::Error::other("no hard links here"))
        };
        let saved = publish_with(&part, dir.path(), "p.jpg", no_links).unwrap();
        assert_eq!(saved, dir.path().join("p (2).jpg"));
        assert_eq!(std::fs::read(&saved).unwrap(), b"new");
        assert_eq!(std::fs::read(dir.path().join("p.jpg")).unwrap(), b"old");
        assert_eq!(
            std::fs::read(dir.path().join("p (1).jpg")).unwrap(),
            b"older"
        );
        assert!(!part.exists());
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

    // ---------- photo cleaning ----------

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    fn seg(marker: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![0xFF, marker];
        v.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    fn app1(body: &[u8]) -> Vec<u8> {
        seg(0xE1, body)
    }

    /// A small JPEG: SOI, the `head` segments, tables, one scan, EOI, then
    /// `tail`.
    fn jpeg(head: &[Vec<u8>], tail: &[u8]) -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8];
        for h in head {
            v.extend_from_slice(h);
        }
        v.extend(seg(0xDB, &[0u8; 65]));
        v.extend(seg(0xC0, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0]));
        v.extend(seg(0xC4, &[0u8; 17]));
        v.extend(seg(0xDA, &[1, 1, 0, 0, 63, 0]));
        v.extend_from_slice(&[0x12, 0x34, 0xFF, 0x00, 0x56, 0xFF, 0xD0, 0x78]);
        v.extend_from_slice(&[0xFF, 0xD9]);
        v.extend_from_slice(tail);
        v
    }

    /// A progressive JPEG whose second scan follows an XMP segment holding
    /// `xmp`.
    fn progressive_jpeg_with_app1_between_scans(xmp: &[u8]) -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8];
        v.extend(seg(0xDB, &[0u8; 65]));
        v.extend(seg(0xC2, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0]));
        v.extend(seg(0xC4, &[0u8; 17]));
        v.extend(seg(0xDA, &[1, 1, 0, 0, 63, 0]));
        v.extend_from_slice(&[0x12, 0x34, 0x56]);
        let mut x = b"http://ns.adobe.com/xap/1.0/\0".to_vec();
        x.extend_from_slice(xmp);
        v.extend(app1(&x));
        v.extend(seg(0xFE, b"comment between scans"));
        v.extend(seg(0xDA, &[1, 1, 0, 0, 63, 0]));
        v.extend_from_slice(&[0x9a, 0xbc]);
        v.extend_from_slice(&[0xFF, 0xD9]);
        v
    }

    #[test]
    fn strip_removes_exif_in_trailing_images_and_between_scans() {
        let second = jpeg(&[app1(b"Exif\0\0GPS-SECOND")], &[]);
        let first = jpeg(&[app1(b"Exif\0\0GPS-FIRST")], &second);
        let out = strip_image(Kind::Jpeg, first).unwrap();
        assert!(!contains(&out, b"GPS-"), "{out:02x?}");
        let prog = progressive_jpeg_with_app1_between_scans(b"<exif:GPSLatitude>");
        let out = strip_image(Kind::Jpeg, prog).unwrap();
        assert!(!contains(&out, b"GPSLatitude"));
        assert!(!contains(&out, b"comment between scans"));
        // Both scans are still there.
        assert!(contains(&out, &[0x12, 0x34, 0x56]));
        assert!(contains(&out, &[0x9a, 0xbc, 0xFF, 0xD9]));
    }

    #[test]
    fn jpeg_cleaning_keeps_only_what_decodes() {
        // JFIF with a 1x1 thumbnail, an MPF index, an ICC profile, a
        // comment and an Adobe colour segment with trailing extras.
        let mut jfif = b"JFIF\0\x01\x02\x01\x00\x48\x00\x48\x01\x01".to_vec();
        jfif.extend_from_slice(b"THM");
        let mut adobe = b"Adobe\0\x64\x00\x00\x00\x00\x01".to_vec();
        adobe.extend_from_slice(b"ADOBE-EXTRA");
        let input = jpeg(
            &[
                seg(0xE0, &jfif),
                seg(0xE0, b"JFXX\0\x10THUMBNAIL"),
                seg(0xE2, b"MPF\0MM\0*SECOND-IMAGE-INDEX"),
                seg(0xE2, b"ICC_PROFILE\0\x01\x01DEVICE-PROFILE"),
                seg(0xEE, &adobe),
                seg(0xFE, b"COMMENT-TEXT"),
            ],
            b"TRAILER",
        );
        let out = strip_image(Kind::Jpeg, input).unwrap();
        let mut want = vec![0xFF, 0xD8];
        want.extend(seg(0xE0, b"JFIF\0\x01\x02\x01\x00\x48\x00\x48\x00\x00"));
        want.extend(seg(0xEE, b"Adobe\0\x64\x00\x00\x00\x00\x01"));
        want.extend(seg(0xDB, &[0u8; 65]));
        want.extend(seg(0xC0, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0]));
        want.extend(seg(0xC4, &[0u8; 17]));
        want.extend(seg(0xDA, &[1, 1, 0, 0, 63, 0]));
        want.extend_from_slice(&[0x12, 0x34, 0xFF, 0x00, 0x56, 0xFF, 0xD0, 0x78]);
        want.extend_from_slice(&[0xFF, 0xD9]);
        assert_eq!(out, want);
    }

    #[test]
    fn a_jpeg_cut_short_in_its_scan_is_closed() {
        let mut v = jpeg(&[app1(b"Exif\0\0GPS")], &[]);
        v.truncate(v.len() - 3);
        let out = strip_image(Kind::Jpeg, v).unwrap();
        assert!(!contains(&out, b"GPS"));
        assert!(out.ends_with(&[0xFF, 0xD9]));
    }

    #[test]
    fn photos_too_big_to_clean_are_refused() {
        let mut big = jpeg(&[], &[]);
        big.resize(MAX_PHOTO_BYTES as usize + 1, 0);
        assert!(strip_image(Kind::Jpeg, big).is_err());
    }

    fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        fn crc32(d: &[u8]) -> u32 {
            let mut c = 0xFFFF_FFFFu32;
            for &b in d {
                c ^= b as u32;
                for _ in 0..8 {
                    c = if c & 1 != 0 {
                        0xEDB8_8320 ^ (c >> 1)
                    } else {
                        c >> 1
                    };
                }
            }
            !c
        }
        let mut v = (data.len() as u32).to_be_bytes().to_vec();
        let mut body = kind.to_vec();
        body.extend_from_slice(data);
        v.extend_from_slice(&body);
        v.extend_from_slice(&crc32(&body).to_be_bytes());
        v
    }

    #[test]
    fn png_keeps_only_what_draws_the_picture() {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        let keep = [
            png_chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]),
            png_chunk(b"sRGB", &[0]),
            png_chunk(b"IDAT", b"\x78\x9c"),
        ];
        v.extend_from_slice(&keep[0]);
        v.extend(png_chunk(b"eXIf", b"MM\0*PNG-GPS"));
        v.extend(png_chunk(b"caBX", b"c2pa-PNG-LOCATION"));
        v.extend_from_slice(&keep[1]);
        v.extend(png_chunk(b"tEXt", b"Author\0Someone"));
        v.extend(png_chunk(b"prVt", b"PRIVATE-CHUNK"));
        v.extend_from_slice(&keep[2]);
        v.extend(png_chunk(b"IEND", b""));
        v.extend_from_slice(b"AFTER-THE-END");
        let out = strip_image(Kind::Png, v).unwrap();
        let mut want = b"\x89PNG\r\n\x1a\n".to_vec();
        for k in &keep {
            want.extend_from_slice(k);
        }
        want.extend(png_chunk(b"IEND", b""));
        assert_eq!(out, want);
    }

    fn riff_chunk(id: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut v = id.to_vec();
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(data);
        if data.len() % 2 == 1 {
            v.push(0);
        }
        v
    }

    fn webp(chunks: &[Vec<u8>]) -> Vec<u8> {
        let mut body = b"WEBP".to_vec();
        for c in chunks {
            body.extend_from_slice(c);
        }
        let mut v = b"RIFF".to_vec();
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend(body);
        v
    }

    #[test]
    fn webp_keeps_only_what_draws_the_picture() {
        // Flags: ICC, EXIF and XMP present.
        let vp8x = |flags: u8| riff_chunk(b"VP8X", &[flags, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let vp8 = riff_chunk(b"VP8 ", &[0x30, 0x01, 0x00, 0x9d, 0x01, 0x2a, 1, 0, 1]);
        let frame = |inner: &[Vec<u8>]| {
            let mut d = vec![0u8; 16];
            for c in inner {
                d.extend_from_slice(c);
            }
            riff_chunk(b"ANMF", &d)
        };
        let input = webp(&[
            vp8x(0x20 | 0x08 | 0x04 | 0x02),
            riff_chunk(b"ICCP", b"DEVICE-PROFILE"),
            riff_chunk(b"ANIM", &[0; 6]),
            frame(&[riff_chunk(b"C2PA", b"FRAME-LOCATION"), vp8.clone()]),
            riff_chunk(b"EXIF", b"MM\0*GPS"),
            riff_chunk(b"XMP ", b"<x/>"),
            riff_chunk(b"C2PA", b"WEBP-LOCATION"),
        ]);
        let out = strip_image(Kind::WebP, input).unwrap();
        let want = webp(&[
            vp8x(0x02),
            riff_chunk(b"ANIM", &[0; 6]),
            frame(std::slice::from_ref(&vp8)),
        ]);
        assert_eq!(out, want);
    }

    /// Small random changes to good photos. Cleaning may refuse them, but
    /// must never panic, and never makes a file more than a few bytes
    /// bigger.
    #[test]
    fn hostile_photos_never_panic() {
        let seeds = [
            (
                Kind::Jpeg,
                jpeg(&[app1(&exif_with_orientation(b"II", 6))], b""),
            ),
            (
                Kind::Gif,
                gif(
                    &[
                        gif_ext(0xFF, &[b"NETSCAPE2.0", &[1, 0, 0]]),
                        gif_ext(0xFE, &[b"c"]),
                        gif_image(),
                    ],
                    b"",
                ),
            ),
            (Kind::Jpeg, progressive_jpeg_with_app1_between_scans(b"x")),
            (
                Kind::Jpeg,
                jpeg(
                    &[seg(0xE0, b"JFIF\0\x01\x02\x01\x00\x48\x00\x48\x00\x00")],
                    b"",
                ),
            ),
            (Kind::Png, {
                let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
                v.extend(png_chunk(b"IHDR", &[0; 13]));
                v.extend(png_chunk(b"IDAT", b"\x78\x9c"));
                v.extend(png_chunk(b"IEND", b""));
                v
            }),
            (
                Kind::WebP,
                webp(&[
                    riff_chunk(b"VP8X", &[0x0c, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    riff_chunk(b"ANMF", &[0; 20]),
                    riff_chunk(b"EXIF", b"MM\0*"),
                ]),
            ),
        ];
        let mut rng: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        for i in 0..40_000u32 {
            let (kind, seed) = &seeds[i as usize % seeds.len()];
            let mut v = seed.clone();
            for _ in 0..1 + next() % 6 {
                let p = next() as usize % v.len();
                match next() % 4 {
                    0 => v[p] = next() as u8,
                    1 => v.truncate(p.max(3)),
                    2 => v.insert(p, next() as u8),
                    _ => {
                        if p + 4 <= v.len() {
                            v[p..p + 4].copy_from_slice(&(next() as u32).to_be_bytes());
                        }
                    }
                }
            }
            let len = v.len();
            // A closing marker and a rebuilt orientation block may add a
            // few bytes; nothing more.
            if let Ok(out) = strip_image(*kind, v) {
                assert!(
                    out.len() <= len + 8,
                    "{kind:?} grew from {len} to {}",
                    out.len()
                );
            }
        }
    }

    #[test]
    fn photo_formats_that_cannot_be_cleaned_are_known() {
        for head in [
            &b"II*\0\x08\0\0\0...."[..],
            b"MM\0*\0\0\0\x08....",
            b"II+\0\x08\0\0\0....",
            b"IIRO\x08\0\0\0....",
            b"IIU\0\x08\0\0\0....",
            b"FUJIFILMCCD-RAW ",
            b"\xff\x0a\xfa\x7f....",
            b"\0\0\0\x0cJXL \r\n\x87\n",
            b"\0\0\0\x0cjP  \r\n\x87\n",
            b"\0\0\0\x18ftypheic",
            b"\0\0\0\x18ftypmif1",
            b"\0\0\0\x1cftypavif",
            b"\0\0\0\x18ftypcrx ",
            b"8BPS\0\x01\0\0",
        ] {
            assert_eq!(sniff(head), Kind::OtherPhoto, "{head:?}");
        }
        assert_eq!(sniff(b"\0\0\0\x18ftypmp42"), Kind::Video);
        assert_eq!(sniff(b"\0\0\0\x14ftypqt  "), Kind::Video);
    }

    /// An EXIF block in `order` ("MM" or "II") whose first IFD holds Make,
    /// Orientation `o` and a pointer to a GPS IFD, followed by a
    /// thumbnail IFD.
    fn exif_with_orientation(order: &[u8; 2], o: u16) -> Vec<u8> {
        let be = order == b"MM";
        let u16b = |v: u16| if be { v.to_be_bytes() } else { v.to_le_bytes() };
        let u32b = |v: u32| if be { v.to_be_bytes() } else { v.to_le_bytes() };
        let mut t = order.to_vec();
        t.extend(u16b(42));
        t.extend(u32b(8));
        // IFD0 at 8: 3 entries, then next-IFD offset.
        let ifd0_end = 8 + 2 + 3 * 12 + 4;
        let make_at = ifd0_end as u32;
        let gps_at = make_at + 12;
        t.extend(u16b(3));
        for (tag, typ, count, value) in [
            (0x010Fu16, 2u16, 11u32, u32b(make_at)),
            (0x0112, 3, 1, {
                let mut v = [0u8; 4];
                v[..2].copy_from_slice(&u16b(o));
                v
            }),
            (0x8825, 4, 1, u32b(gps_at)),
        ] {
            t.extend(u16b(tag));
            t.extend(u16b(typ));
            t.extend(u32b(count));
            t.extend(value);
        }
        t.extend(u32b(0));
        t.extend_from_slice(b"SecretMake\0\0");
        // GPS IFD: one entry holding "N".
        t.extend(u16b(1));
        t.extend(u16b(1));
        t.extend(u16b(2));
        t.extend(u32b(2));
        t.extend_from_slice(b"N\0\0\0");
        t.extend(u32b(0));
        let mut body = b"Exif\0\0".to_vec();
        body.extend(t);
        body
    }

    #[test]
    fn jpeg_keeps_only_the_orientation_tag() {
        let want = |o: u8| {
            let mut v = vec![0xFF, 0xD8];
            v.extend(app1(&[
                b'E', b'x', b'i', b'f', 0, 0, b'M', b'M', 0, 42, 0, 0, 0, 8, 0, 1, 0x01, 0x12, 0,
                3, 0, 0, 0, 1, 0, o, 0, 0, 0, 0, 0, 0,
            ]));
            v
        };
        for order in [b"MM", b"II"] {
            let input = jpeg(&[app1(&exif_with_orientation(order, 6))], &[]);
            let out = strip_image(Kind::Jpeg, input).unwrap();
            assert!(out.starts_with(&want(6)), "{order:?}: {out:02x?}");
            assert!(!contains(&out, b"SecretMake"));
            assert!(!contains(&out, b"N\0\0\0"));
        }
        // No orientation, or one outside 1 to 8: no EXIF at all.
        for o in [0, 9, 0xFFFF] {
            let input = jpeg(&[app1(&exif_with_orientation(b"MM", o))], &[]);
            let out = strip_image(Kind::Jpeg, input).unwrap();
            assert!(!contains(&out, b"Exif\0\0"), "{o}");
        }
        // Only the first EXIF block counts, and only one block comes out.
        let input = jpeg(
            &[
                app1(&exif_with_orientation(b"II", 3)),
                app1(&exif_with_orientation(b"MM", 8)),
            ],
            &[],
        );
        let out = strip_image(Kind::Jpeg, input).unwrap();
        assert!(out.starts_with(&want(3)));
        assert_eq!(out.windows(6).filter(|w| w == b"Exif\0\0").count(), 1);
    }

    #[test]
    fn jpeg_ls_is_refused() {
        let input = jpeg(&[seg(0xF7, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0])], &[]);
        assert!(strip_image(Kind::Jpeg, input).is_err());
        let input = jpeg(&[seg(0xF8, &[1, 0, 0])], &[]);
        assert!(strip_image(Kind::Jpeg, input).is_err());
    }

    #[test]
    fn webp_header_keeps_its_spec_size() {
        let input = webp(&[
            riff_chunk(
                b"VP8X",
                &[0x0c, 0, 0, 0, 0, 0, 0, 0, 0, 0, b'E', b'X', b'T', b'R'],
            ),
            riff_chunk(b"VP8L", &[0x2f, 0, 0, 0, 0]),
        ]);
        let out = strip_image(Kind::WebP, input).unwrap();
        let want = webp(&[
            riff_chunk(b"VP8X", &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            riff_chunk(b"VP8L", &[0x2f, 0, 0, 0, 0]),
        ]);
        assert_eq!(out, want);
    }

    /// A GIF: header, screen with a 2-colour table, then `blocks`, the
    /// trailer and `tail`.
    fn gif(blocks: &[Vec<u8>], tail: &[u8]) -> Vec<u8> {
        let mut v = b"GIF89a".to_vec();
        v.extend_from_slice(&[4, 0, 4, 0, 0x80, 0, 0]);
        v.extend_from_slice(&[0, 0, 0, 255, 255, 255]);
        for b in blocks {
            v.extend_from_slice(b);
        }
        v.push(0x3B);
        v.extend_from_slice(tail);
        v
    }

    /// An extension block: introducer, label, then `data` as sub-blocks.
    fn gif_ext(label: u8, subs: &[&[u8]]) -> Vec<u8> {
        let mut v = vec![0x21, label];
        for s in subs {
            v.push(s.len() as u8);
            v.extend_from_slice(s);
        }
        v.push(0);
        v
    }

    /// One 4x4 image with a local 2-colour table.
    fn gif_image() -> Vec<u8> {
        let mut v = vec![0x2C, 0, 0, 0, 0, 4, 0, 4, 0, 0x80];
        v.extend_from_slice(&[9, 9, 9, 7, 7, 7]);
        v.extend_from_slice(&[2, 3, 0x84, 0x8f, 0x05, 0]);
        v
    }

    #[test]
    fn gif_keeps_only_what_draws_the_picture() {
        assert_eq!(sniff(b"GIF89a\x04\0\x04\0"), Kind::Gif);
        assert_eq!(sniff(b"GIF87a\x04\0\x04\0"), Kind::Gif);
        let looping = gif_ext(0xFF, &[b"NETSCAPE2.0", &[1, 0, 0]]);
        let looping_old = gif_ext(0xFF, &[b"ANIMEXTS1.0", &[1, 0, 0]]);
        let control = gif_ext(0xF9, &[&[4, 0, 10, 0]]);
        let input = gif(
            &[
                gif_ext(0xFE, &[b"SecretComment"]),
                looping.clone(),
                gif_ext(0xFF, &[b"XMP DataXMP", b"<exif:GPSLatitude>", &[1, 0]]),
                looping_old.clone(),
                control.clone(),
                gif_ext(0x01, &[&[0; 12], b"SecretText"]),
                gif_image(),
                gif_ext(0xFF, &[b"ICCRGBG1012", b"DEVICE-PROFILE"]),
                gif_ext(0x7A, &[b"unknown"]),
                control.clone(),
                gif_image(),
            ],
            b"AFTER-THE-END",
        );
        let out = strip_image(Kind::Gif, input).unwrap();
        let want = gif(
            &[
                looping,
                looping_old,
                control.clone(),
                gif_image(),
                control,
                gif_image(),
            ],
            b"",
        );
        assert_eq!(out, want);
        // A GIF cut short after a whole image is closed; one cut short
        // inside a block is refused.
        let mut cut = gif(&[gif_image()], b"");
        cut.pop();
        assert_eq!(
            strip_image(Kind::Gif, cut.clone()).unwrap(),
            gif(&[gif_image()], b"")
        );
        cut.truncate(cut.len() - 3);
        assert!(strip_image(Kind::Gif, cut).is_err());
    }

    // ---------- saving ----------

    #[test]
    fn saved_names_are_never_dotfiles_or_devices() {
        assert_eq!(safe_name(". .bashrc"), "bashrc");
        assert_eq!(safe_name("..  .envrc"), "envrc");
        assert_eq!(safe_name(" .profile"), "profile");
        assert_eq!(safe_name("..."), "file");
        assert!(!safe_name("a.pdf.").ends_with('.'));
        assert_eq!(safe_name("invoice.pdf. . "), "invoice.pdf");
        // A control character goes; a line break, like any space, becomes one.
        assert_eq!(safe_name("a\u{7}b\nc.txt"), "ab c.txt");
        assert_eq!(safe_name("dir/..\\x"), "x");
        // Windows device names, in any case and with any extension.
        for dev in [
            "CON",
            "con",
            "PRN",
            "AUX",
            "NUL",
            "nul.txt",
            "NUL.tar.gz",
            "COM1",
            "com9.jpg",
            "COM0",
            "LPT1",
            "lpt9.doc",
            "COM\u{b9}",
            "LPT\u{b2}.txt",
            "CONIN$",
            "conout$.x",
            "nul .txt",
            "AUX  ",
        ] {
            let got = safe_name(dev);
            assert!(got.starts_with('_'), "{dev:?} became {got:?}");
        }
        for fine in ["CONSOLE.txt", "nullable.rs", "COM10", "LPT", "auxiliary"] {
            assert_eq!(safe_name(fine), fine);
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_download_never_writes_through_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let canary = dir.path().join("canary");
        std::fs::write(&canary, b"keep me").unwrap();
        let id = FileId([7; 16]);
        let (mut f, part) = create_part(dir.path(), &id).unwrap();
        std::io::Write::write_all(&mut f, b"x").unwrap();
        drop(f);
        // Whatever name a part file gets, a link planted there is refused.
        std::fs::remove_file(&part).unwrap();
        std::os::unix::fs::symlink(&canary, &part).unwrap();
        assert!(open_part(&part).is_err());
        // An existing file is never truncated.
        std::fs::remove_file(&part).unwrap();
        std::fs::write(&part, b"someone's file").unwrap();
        assert!(open_part(&part).is_err());
        assert_eq!(std::fs::read(&part).unwrap(), b"someone's file");
        assert_eq!(std::fs::read(&canary).unwrap(), b"keep me");
    }

    #[cfg(unix)]
    #[test]
    fn copied_saves_are_private_too() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let part = part_with(dir.path(), b"photo bytes");
        let no_links = |_: &std::path::Path, _: &std::path::Path| {
            Err(std::io::Error::other("no hard links here"))
        };
        let saved = publish_with(&part, dir.path(), "p.jpg", no_links).unwrap();
        let mode = std::fs::metadata(&saved).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn stale_part_files_go_but_links_and_fresh_ones_stay() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let id = FileId([7; 16]);
        let hex = "07".repeat(16);
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3 * 3600);
        let make = |name: &str, age: Option<std::time::SystemTime>| {
            let p = d.join(name);
            let f = std::fs::File::create(&p).unwrap();
            if let Some(t) = age {
                f.set_modified(t).unwrap();
            }
            p
        };
        let stale = make(
            &format!(".socketchat-{hex}-0123456789abcdef.part"),
            Some(old),
        );
        let stale_old_name = make(&format!(".socketchat-{hex}.part"), Some(old));
        let fresh = make(&format!(".socketchat-{hex}-1111111111111111.part"), None);
        let other_file = make(
            &format!(".socketchat-{}-0123456789abcdef.part", "08".repeat(16)),
            Some(old),
        );
        let not_a_part = make(
            &format!(".socketchat-{hex}-0123456789abcdef.txt"),
            Some(old),
        );
        let canary = make("canary", Some(old));
        std::fs::write(&canary, b"keep me").unwrap();
        let link = d.join(format!(".socketchat-{hex}-fedcba9876543210.part"));
        std::os::unix::fs::symlink(&canary, &link).unwrap();
        let (_f, keep) = create_part(d, &id).unwrap();
        remove_stale_parts(d, &id, &keep);
        assert!(!stale.exists());
        assert!(!stale_old_name.exists());
        for p in [&fresh, &other_file, &not_a_part, &keep] {
            assert!(p.exists(), "{p:?}");
        }
        assert!(link.symlink_metadata().is_ok(), "the link itself stays");
        assert_eq!(std::fs::read(&canary).unwrap(), b"keep me");
    }

    #[cfg(unix)]
    #[test]
    fn part_files_are_private_and_unpredictable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let id = FileId([7; 16]);
        let (_a, pa) = create_part(dir.path(), &id).unwrap();
        let (_b, pb) = create_part(dir.path(), &id).unwrap();
        assert_ne!(pa, pb);
        let mode = std::fs::metadata(&pa).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
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
