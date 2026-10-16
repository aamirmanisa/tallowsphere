//! Zstandard compression (default algorithm)

use crate::{ProtocolError, Result};

/// Default Zstandard compression level
const DEFAULT_LEVEL: i32 = 3;

/// Compress data with Zstandard
///
/// # Arguments
///
/// * `data` - Data to compress
/// * `level` - Compression level (1-22, default 3)
pub fn compress(data: &[u8], level: i32) -> Result<Vec<u8>> {
    zstd::encode_all(data, level)
        .map_err(|e| ProtocolError::CompressionError(format!("zstd compress failed: {}", e)))
}

/// Maximum decompressed output size (256 MiB) to prevent decompression bombs
const MAX_DECOMPRESS_SIZE: usize = 256 * 1024 * 1024;

/// Decompress Zstandard data with streaming size limit.
///
/// Reads incrementally and aborts as soon as output exceeds [`MAX_DECOMPRESS_SIZE`],
/// preventing decompression bombs from exhausting memory.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut decoder = zstd::Decoder::new(data)
        .map_err(|e| ProtocolError::CompressionError(format!("zstd init failed: {}", e)))?;
    let mut output = Vec::new();
    let mut buf = [0u8; 64 * 1024]; // 64 KiB read chunks
    loop {
        let n = decoder.read(&mut buf).map_err(|e| {
            ProtocolError::CompressionError(format!("zstd decompress failed: {}", e))
        })?;
        if n == 0 {
            break;
        }
        output.extend_from_slice(&buf[..n]);
        if output.len() > MAX_DECOMPRESS_SIZE {
            return Err(ProtocolError::CompressionError(format!(
                "decompressed size exceeds limit of {} bytes",
                MAX_DECOMPRESS_SIZE
            )));
        }
    }
    Ok(output)
}

/// Compress with default level (3)
pub fn compress_default(data: &[u8]) -> Result<Vec<u8>> {
    compress(data, DEFAULT_LEVEL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zstd_roundtrip() {
        let data = b"hello world! This is some compressible text data.";
        let compressed = compress(data, 3).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(&decompressed, data);
    }

    #[test]
    fn test_zstd_empty() {
        let compressed = compress(b"", 3).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn test_zstd_compresses() {
        let data = vec![0u8; 10000]; // Highly compressible
        let compressed = compress(&data, 3).unwrap();
        assert!(compressed.len() < data.len());
    }
}
