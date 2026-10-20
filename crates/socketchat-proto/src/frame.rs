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

/// Collects bytes as they arrive and hands back whole frame bodies.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Returns the next complete body, `None` if more bytes are needed, or an
    /// error as soon as a length prefix announces an oversized frame.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len > MAX_FRAME {
            return Err(FrameError::TooLarge(len));
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let body = self.buf[4..4 + len].to_vec();
        self.buf.drain(..4 + len);
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
