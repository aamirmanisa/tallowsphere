//! Brotli compression

use crate::{ProtocolError, Result};
use std::io::{Read, Write};

/// Default Brotli quality level
const DEFAULT_QUALITY: u32 = 4;

/// Brotli buffer size
const BUFFER_SIZE: usize = 4096;

/// Compress data with Brotli
///
/// # Arguments
///
/// * `data` - Data to compress
/// * `quality` - Compression quality (0-11, default 4)
pub fn compress(data: &[u8], quality: u32) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut encoder = brotli::CompressorWriter::new(&mut output, BUFFER_SIZE, quality, 22);
    encoder
        .write_all(data)
        .map_err(|e| ProtocolError::CompressionError(format!("brotli compress failed: {}", e)))?;
    drop(encoder);
    Ok(output)
}

/// Maximum decompressed output size (256 MiB) to prevent decompression bombs
const MAX_DECOMPRESS_SIZE: usize = 256 * 1024 * 1024;

/// Decompress Brotli data
///
/// Limits output to [`MAX_DECOMPRESS_SIZE`] to prevent decompression bombs.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut decoder = brotli::Decompressor::new(data, BUFFER_SIZE);
    // Read in chunks to enforce size limit without reading everything first
    let mut buf = [0u8; 65536];
    loop {
        let n = decoder.read(&mut buf).map_err(|e| {
            ProtocolError::CompressionError(format!("brotli decompress failed: {}", e))
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

/// Compress with default quality (4)
pub fn compress_default(data: &[u8]) -> Result<Vec<u8>> {
    compress(data, DEFAULT_QUALITY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_brotli_roundtrip() {
        let data = b"hello world! This is some compressible text data.";
        let compressed = compress(data, 4).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(&decompressed, data);
    }
}
