//! Codec for encoding/decoding Tallow protocol messages
//!
//! Framing: 4-byte big-endian length prefix + postcard-serialized payload.
//! Maximum message size: 16 MiB (prevents OOM from malicious peers).

use super::Message;
use crate::{ProtocolError, Result};
use bytes::{Buf, BufMut, BytesMut};

/// Maximum allowed message size (16 MiB)
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Length prefix size (4 bytes, big-endian u32)
const LENGTH_PREFIX_SIZE: usize = 4;

/// Tallow protocol codec
///
/// Encodes/decodes `Message` values using postcard serialization
/// with a 4-byte big-endian length prefix for framing.
#[derive(Debug, Default)]
pub struct TallowCodec;

impl TallowCodec {
    /// Create a new codec
    pub fn new() -> Self {
        Self
    }

    /// Encode a message into a buffer
    ///
    /// Format: `[4-byte BE length][postcard payload]`
    pub fn encode_msg(&mut self, msg: &Message, buf: &mut BytesMut) -> Result<()> {
        let payload = postcard::to_stdvec(msg)
            .map_err(|e| ProtocolError::EncodingError(format!("postcard encode failed: {}", e)))?;

        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::EncodingError(format!(
                "message too large: {} bytes (max {})",
                payload.len(),
                MAX_MESSAGE_SIZE
            )));
        }

        buf.reserve(LENGTH_PREFIX_SIZE + payload.len());
        buf.put_u32(payload.len() as u32);
        buf.extend_from_slice(&payload);

        Ok(())
    }

    /// Decode a message from a buffer
    ///
    /// Returns `Ok(Some(msg))` if a complete message was decoded,
    /// `Ok(None)` if more data is needed, or `Err` on invalid data.
    pub fn decode_msg(&mut self, buf: &mut BytesMut) -> Result<Option<Message>> {
        // Need at least the length prefix
        if buf.len() < LENGTH_PREFIX_SIZE {
            return Ok(None);
        }

        // Peek at the length (don't consume yet)
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

        // L-20: Reject zero-length messages — a valid postcard message is always >= 1 byte
        // (at minimum a variant discriminant). Zero-length payloads indicate a malformed
        // or malicious frame and should not be passed to the deserializer.
        if len == 0 {
            return Err(ProtocolError::DecodingError(
                "zero-length message payload".to_string(),
            ));
        }

        if len > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::DecodingError(format!(
                "message too large: {} bytes (max {})",
                len, MAX_MESSAGE_SIZE
            )));
        }

        // Check if we have the full payload
        if buf.len() < LENGTH_PREFIX_SIZE + len {
            return Ok(None);
        }

        // Consume the length prefix
        buf.advance(LENGTH_PREFIX_SIZE);

        // Extract and consume the payload
        let payload = buf.split_to(len);

        let msg = postcard::from_bytes(&payload)
            .map_err(|e| ProtocolError::DecodingError(format!("postcard decode failed: {}", e)))?;

        Ok(Some(msg))
    }
}

/// Implement tokio_util Encoder for async stream usage
impl tokio_util::codec::Encoder<Message> for TallowCodec {
    type Error = ProtocolError;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<()> {
        self.encode_msg(&item, dst)
    }
}

/// Implement tokio_util Decoder for async stream usage
impl tokio_util::codec::Decoder for TallowCodec {
    type Item = Message;
    type Error = ProtocolError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Message>> {
        self.decode_msg(src)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codec_roundtrip() {
        let mut codec = TallowCodec::new();
        let mut buf = BytesMut::new();

        let msg = Message::RoomJoin {
            room_id: vec![42u8; 32],
            password_hash: None,
            forward_to_relay: None,
        };

        codec.encode_msg(&msg, &mut buf).unwrap();

        let decoded = codec.decode_msg(&mut buf).unwrap();
        assert_eq!(decoded, Some(msg));
        assert!(buf.is_empty(), "buffer should be fully consumed");
    }

    #[test]
    fn test_codec_partial_data() {
        let mut codec = TallowCodec::new();
        let mut buf = BytesMut::new();

        let msg = Message::Ping;
        codec.encode_msg(&msg, &mut buf).unwrap();

        // Save full encoded data
        let full = buf.clone();

        // Feed partial data (just the length prefix)
        buf.clear();
        buf.extend_from_slice(&full[..LENGTH_PREFIX_SIZE]);

        assert_eq!(codec.decode_msg(&mut buf).unwrap(), None);

        // Now feed the rest
        buf.extend_from_slice(&full[LENGTH_PREFIX_SIZE..]);
        let decoded = codec.decode_msg(&mut buf).unwrap();
        assert_eq!(decoded, Some(Message::Ping));
    }

    #[test]
    fn test_codec_multiple_messages() {
        let mut codec = TallowCodec::new();
        let mut buf = BytesMut::new();

        let messages = vec![Message::Ping, Message::Pong, Message::RoomLeave];

        // Encode all messages into the same buffer
        for msg in &messages {
            codec.encode_msg(msg, &mut buf).unwrap();
        }

        // Decode all messages back
        for expected in &messages {
            let decoded = codec.decode_msg(&mut buf).unwrap();
            assert_eq!(decoded.as_ref(), Some(expected));
        }

        assert!(buf.is_empty());
    }

    #[test]
    fn test_codec_oversized_message() {
        let mut codec = TallowCodec::new();
        let mut buf = BytesMut::new();

        // Simulate a message claiming to be too large
        buf.put_u32((MAX_MESSAGE_SIZE + 1) as u32);

        let result = codec.decode_msg(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_codec_empty_buffer() {
        let mut codec = TallowCodec::new();
        let mut buf = BytesMut::new();

        assert_eq!(codec.decode_msg(&mut buf).unwrap(), None);
    }

    #[test]
    fn test_codec_chunk_message() {
        let mut codec = TallowCodec::new();
        let mut buf = BytesMut::new();

        let msg = Message::Chunk {
            transfer_id: [7u8; 16],
            index: 99,
            total: Some(1000),
            data: vec![0xAB; 65536], // 64KB chunk
        };

        codec.encode_msg(&msg, &mut buf).unwrap();

        let decoded = codec.decode_msg(&mut buf).unwrap();
        assert_eq!(decoded, Some(msg));
    }
}
