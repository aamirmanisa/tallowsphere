//! LZMA/XZ compression (highest ratio)

use crate::{ProtocolError, Result};

/// Compress data with LZMA
///
/// # Arguments
///
/// * `data` - Data to compress
/// * `preset` - Compression preset (0-9, default 6)
pub fn compress(data: &[u8], _preset: u32) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    lzma_rs::lzma_compress_with_options(
        &mut &data[..],
        &mut output,
        &lzma_rs::compress::Options {
            unpacked_size: lzma_rs::compress::UnpackedSize::WriteToHeader(Some(data.len() as u64)),
        },
    )
    .map_err(|e| ProtocolError::CompressionError(format!("lzma compress failed: {}", e)))?;
    Ok(output)
}

/// Maximum decompressed output size (256 MiB) to prevent decompression bombs
const MAX_DECOMPRESS_SIZE: usize = 256 * 1024 * 1024;

/// Decompress LZMA data with pre-validated size limit.
///
/// LZMA headers encode the uncompressed size. We parse it first and reject
/// payloads that claim to exceed [`MAX_DECOMPRESS_SIZE`] before allocating.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    // LZMA header: 5 bytes properties + 8 bytes LE uncompressed size
    if data.len() >= 13 {
        let claimed_size = u64::from_le_bytes(data[5..13].try_into().unwrap_or([0xFF; 8]));
        // 0xFFFFFFFFFFFFFFFF means "unknown size" — allow streaming but cap output
        if claimed_size != u64::MAX && claimed_size as usize > MAX_DECOMPRESS_SIZE {
            return Err(ProtocolError::CompressionError(format!(
                "LZMA header claims {} bytes, exceeds limit of {} bytes",
                claimed_size, MAX_DECOMPRESS_SIZE
            )));
        }
    }
    let mut output = Vec::new();
    lzma_rs::lzma_decompress(&mut &data[..], &mut output)
        .map_err(|e| ProtocolError::CompressionError(format!("lzma decompress failed: {}", e)))?;
    if output.len() > MAX_DECOMPRESS_SIZE {
        return Err(ProtocolError::CompressionError(format!(
            "decompressed size {} exceeds limit of {} bytes",
            output.len(),
            MAX_DECOMPRESS_SIZE
        )));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lzma_roundtrip() {
        let data = b"hello world! This is some compressible text data.";
        let compressed = compress(data, 6).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(&decompressed, data);
    }
}
