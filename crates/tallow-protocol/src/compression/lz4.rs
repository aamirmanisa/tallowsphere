//! LZ4 compression (fastest algorithm)

use crate::{ProtocolError, Result};

/// Compress data with LZ4
pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    Ok(lz4_flex::compress_prepend_size(data))
}

/// Maximum decompressed output size (256 MiB) to prevent decompression bombs
const MAX_DECOMPRESS_SIZE: usize = 256 * 1024 * 1024;

/// Decompress LZ4 data with pre-validated size limit.
///
/// lz4_flex prepends a 4-byte LE original size. We validate this BEFORE
/// decompression to prevent allocation of attacker-controlled buffer sizes.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    // lz4_flex prepends 4-byte LE uncompressed size
    if data.len() >= 4 {
        let claimed = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if claimed > MAX_DECOMPRESS_SIZE {
            return Err(ProtocolError::CompressionError(format!(
                "LZ4 header claims {} bytes, exceeds limit of {} bytes",
                claimed, MAX_DECOMPRESS_SIZE
            )));
        }
    }
    let result = lz4_flex::decompress_size_prepended(data)
        .map_err(|e| ProtocolError::CompressionError(format!("lz4 decompress failed: {}", e)))?;
    // Belt-and-suspenders: also check actual output
    if result.len() > MAX_DECOMPRESS_SIZE {
        return Err(ProtocolError::CompressionError(format!(
            "decompressed size {} exceeds limit of {} bytes",
            result.len(),
            MAX_DECOMPRESS_SIZE
        )));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lz4_roundtrip() {
        let data = b"hello world! This is some compressible text data.";
        let compressed = compress(data).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(&decompressed, data);
    }
}
