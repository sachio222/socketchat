//! Frames: a 4-byte big-endian length, then that many bytes of body.

use thiserror::Error;

/// Largest frame body either side accepts: 1 MiB.
pub const MAX_FRAME: usize = 1 << 20;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame of {0} bytes is over the 1 MiB limit")]
    TooLarge(usize),
    #[error("could not decode message: {0}")]
    Postcard(String),
}

/// Prefixes `body` with its length.
pub fn encode_frame(body: &[u8]) -> Result<Vec<u8>, FrameError> {
    if body.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(body.len()));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// A decoder that held a frame larger than this gives its memory back once
/// that frame is out, so one large message does not stay allocated for the
/// life of a connection.
const KEEP_AFTER_FRAME: usize = 64 * 1024;

/// A frame's buffer starts at this size, or at the frame's own size when
/// that is smaller, and grows with the bytes that actually arrive.
const GROW_FROM: usize = 16 * 1024;

/// Collects bytes as they arrive and hands back whole frame bodies.
#[derive(Debug)]
pub struct FrameDecoder {
    buf: Vec<u8>,
    /// Largest body accepted, at most `MAX_FRAME`.
    limit: usize,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        FrameDecoder {
            buf: Vec::new(),
            limit: MAX_FRAME,
        }
    }
}

impl FrameDecoder {
    /// Accepts bodies of at most `limit` bytes from the next frame on, and
    /// never more than `MAX_FRAME`.
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit.min(MAX_FRAME);
    }

    pub fn push(&mut self, bytes: &[u8]) {
        let total = self.buf.len() + bytes.len();
        let mut head = [0u8; 4];
        let have = self.buf.len().min(4);
        head[..have].copy_from_slice(&self.buf[..have]);
        let more = (4 - have).min(bytes.len());
        head[have..have + more].copy_from_slice(&bytes[..more]);
        let len = (have + more == 4).then(|| u32::from_be_bytes(head) as usize);
        if len.is_some_and(|l| l > self.limit) {
            // Keep only the length, which `next_frame` refuses, and take
            // no room for the body.
            self.buf.extend_from_slice(&bytes[..more]);
            return;
        }
        if total > self.buf.capacity() {
            // Room grows with what has arrived, to the frame's exact size
            // once it is near.
            let target = len
                .map(|l| 4 + l)
                .filter(|&w| w >= total)
                .map(|w| w.min((2 * total).max(GROW_FROM)));
            match target {
                Some(t) => self.buf.reserve_exact(t - self.buf.len()),
                None => self.buf.reserve(bytes.len()),
            }
        }
        self.buf.extend_from_slice(bytes);
    }

    /// The body length the next frame announces, once its 4-byte prefix
    /// has arrived.
    pub fn announced(&self) -> Option<usize> {
        let head: [u8; 4] = self.buf.get(..4)?.try_into().ok()?;
        Some(u32::from_be_bytes(head) as usize)
    }

    /// Bytes received and not yet handed back as a frame.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Bytes of memory the decoder holds.
    pub fn held(&self) -> usize {
        self.buf.capacity()
    }

    /// Returns the next complete body, `None` if more bytes are needed, or an
    /// error as soon as a length prefix announces an oversized frame.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        let Some(len) = self.announced() else {
            return Ok(None);
        };
        if len > self.limit {
            return Err(FrameError::TooLarge(len));
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let body = self.buf[4..4 + len].to_vec();
        self.buf.drain(..4 + len);
        if self.buf.is_empty() && self.buf.capacity() > KEEP_AFTER_FRAME {
            self.buf = Vec::new();
        }
        Ok(Some(body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let body = b"hello frames".to_vec();
        let mut d = FrameDecoder::default();
        d.push(&encode_frame(&body).unwrap());
        assert_eq!(d.next_frame().unwrap(), Some(body));
        assert_eq!(d.next_frame().unwrap(), None);
    }

    #[test]
    fn frame_split_across_pushes() {
        let body = vec![7u8; 300];
        let wire = encode_frame(&body).unwrap();
        let mut d = FrameDecoder::default();
        for b in &wire[..wire.len() - 1] {
            d.push(std::slice::from_ref(b));
            assert_eq!(d.next_frame().unwrap(), None);
        }
        d.push(&wire[wire.len() - 1..]);
        assert_eq!(d.next_frame().unwrap(), Some(body));
    }

    #[test]
    fn frame_too_large_rejected() {
        let mut d = FrameDecoder::default();
        d.push(&((MAX_FRAME as u32) + 1).to_be_bytes());
        assert_eq!(d.next_frame(), Err(FrameError::TooLarge(MAX_FRAME + 1)));
        assert_eq!(
            encode_frame(&vec![0u8; MAX_FRAME + 1]),
            Err(FrameError::TooLarge(MAX_FRAME + 1))
        );
    }

    /// A frame's room grows with the bytes that arrive and ends at its
    /// exact size, not doubled past it.
    #[test]
    fn room_grows_to_exactly_the_announced_frame() {
        let body = vec![1u8; 300_000];
        let wire = encode_frame(&body).unwrap();
        let mut d = FrameDecoder::default();
        let mut sent = 0;
        for piece in wire[..wire.len() - 1].chunks(16 * 1024) {
            d.push(piece);
            sent += piece.len();
            assert!(
                d.held() <= (2 * sent).max(GROW_FROM),
                "{} for {sent}",
                d.held()
            );
            assert_eq!(d.next_frame().unwrap(), None);
        }
        assert_eq!(d.announced(), Some(body.len()));
        assert_eq!(d.held(), wire.len());
        d.push(&wire[wire.len() - 1..]);
        assert_eq!(d.next_frame().unwrap(), Some(body));
        // A large frame's memory goes once it is out.
        assert_eq!(d.held(), 0);
        assert_eq!(d.announced(), None);
    }

    /// A bare length prefix announcing the largest frame takes little room.
    #[test]
    fn prefix_alone_takes_little_room() {
        let mut d = FrameDecoder::default();
        d.push(&(MAX_FRAME as u32).to_be_bytes());
        assert_eq!(d.next_frame().unwrap(), None);
        assert!(d.held() <= GROW_FROM, "{}", d.held());
    }

    /// A length over the decoder's limit is refused, and none of the body
    /// that came with it is kept.
    #[test]
    fn over_limit_frame_refused_before_room_is_taken() {
        let mut d = FrameDecoder::default();
        d.set_limit(100);
        let mut wire = 1000u32.to_be_bytes().to_vec();
        wire.extend([5u8; 500]);
        d.push(&wire);
        assert!(d.held() <= 8, "{}", d.held());
        assert_eq!(d.next_frame(), Err(FrameError::TooLarge(1000)));
        // The same split a byte at a time.
        let mut d = FrameDecoder::default();
        d.set_limit(100);
        for b in &wire[..20] {
            d.push(std::slice::from_ref(b));
        }
        assert!(d.held() <= 8, "{}", d.held());
        assert_eq!(d.next_frame(), Err(FrameError::TooLarge(1000)));
        // A frame within the limit passes, and the limit never exceeds
        // MAX_FRAME.
        let mut d = FrameDecoder::default();
        d.set_limit(100);
        d.push(&encode_frame(&[3u8; 100]).unwrap());
        assert_eq!(d.next_frame().unwrap(), Some(vec![3u8; 100]));
        d.set_limit(usize::MAX);
        d.push(&((MAX_FRAME as u32) + 1).to_be_bytes());
        assert_eq!(d.next_frame(), Err(FrameError::TooLarge(MAX_FRAME + 1)));
    }

    /// The prefix may arrive a byte at a time, and a push may carry the end
    /// of one frame and the start of the next.
    #[test]
    fn announced_length_across_pushes() {
        let mut wire = encode_frame(b"abc").unwrap();
        wire.extend(encode_frame(&[9u8; 70_000]).unwrap());
        let mut d = FrameDecoder::default();
        for b in &wire[..2] {
            d.push(std::slice::from_ref(b));
            assert_eq!(d.announced(), None);
        }
        d.push(&wire[2..11]);
        assert_eq!(d.announced(), Some(3));
        assert_eq!(d.next_frame().unwrap(), Some(b"abc".to_vec()));
        assert_eq!(d.announced(), Some(70_000));
        d.push(&wire[11..]);
        assert_eq!(d.next_frame().unwrap().map(|b| b.len()), Some(70_000));
    }

    #[test]
    fn two_frames_in_one_push() {
        let mut wire = encode_frame(b"a").unwrap();
        wire.extend(encode_frame(b"bc").unwrap());
        let mut d = FrameDecoder::default();
        d.push(&wire);
        assert_eq!(d.next_frame().unwrap(), Some(b"a".to_vec()));
        assert_eq!(d.next_frame().unwrap(), Some(b"bc".to_vec()));
    }
}
