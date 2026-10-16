//! Framing — 2-byte big-endian length prefix + payload (mirrors the reference
//! core's `frame` / `FrameReader`).

/// Hard cap: a u16 length prefix caps any single frame at 65535 bytes.
pub const MAX_FRAME_PAYLOAD: usize = u16::MAX as usize;

/// Encode one frame: `u16::to_be_bytes(len) || payload`.
pub fn frame(payload: &[u8]) -> Vec<u8> {
    debug_assert!(payload.len() <= MAX_FRAME_PAYLOAD, "frame too large");
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Incremental frame decoder. Feed arbitrary chunks, drain whole frames.
/// Partial frames are buffered; frames larger than the cap never occur (u16).
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Bytes currently buffered (incomplete frame remainder).
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Append a chunk of bytes.
    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Pop the next complete frame payload, if one is buffered.
    pub fn pop_frame(&mut self) -> Option<Vec<u8>> {
        if self.buf.len() < 2 {
            return None;
        }
        let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
        if self.buf.len() < 2 + len {
            return None;
        }
        let payload = self.buf[2..2 + len].to_vec();
        self.buf.drain(..2 + len);
        Some(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_coalescing() {
        let a = frame(b"hello");
        let b = frame(b"world");
        let mut d = FrameDecoder::new();
        // drip-feed one byte at a time
        let mut got = Vec::new();
        for byte in a.iter().chain(b.iter()) {
            d.push(&[*byte]);
            while let Some(p) = d.pop_frame() {
                got.push(p);
            }
        }
        assert_eq!(got, vec![b"hello".to_vec(), b"world".to_vec()]);
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn partial_frame_waits() {
        let mut d = FrameDecoder::new();
        d.push(&[0x00, 0x05, b'a']);
        assert_eq!(d.pop_frame(), None);
        assert_eq!(d.buffered(), 3);
        d.push(b"bcde");
        assert_eq!(d.pop_frame(), Some(b"abcde".to_vec()));
    }
}
