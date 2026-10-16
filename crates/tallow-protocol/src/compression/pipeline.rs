//! Compression pipeline with automatic algorithm selection
//!
//! Analyzes the first 64KB of data to determine compressibility,
//! then selects the best algorithm based on content type and size.

use super::{analysis, CompressionAlgorithm};
use crate::Result;

/// Compression pipeline
#[derive(Debug)]
pub struct CompressionPipeline {
    algorithm: CompressionAlgorithm,
}

impl CompressionPipeline {
    /// Create a new compression pipeline with a specific algorithm
    pub fn new(algorithm: CompressionAlgorithm) -> Self {
        Self { algorithm }
    }

    /// Auto-select algorithm based on data analysis
    pub fn auto(data: &[u8]) -> Self {
        let algorithm = select_algorithm(data);
        Self { algorithm }
    }

    /// Get the selected algorithm
    pub fn algorithm(&self) -> CompressionAlgorithm {
        self.algorithm
    }

    /// Compress data using the selected algorithm
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        compress(data, self.algorithm)
    }

    /// Decompress data using the specified algorithm
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        decompress(data, self.algorithm)
    }
}

/// Select the best compression algorithm based on data analysis
///
/// Examines the first 64KB to determine:
/// - If data is already compressed (high entropy) → None
/// - File type from magic bytes → algorithm choice
/// - Otherwise → Zstd (best general-purpose default)
pub fn select_algorithm(data: &[u8]) -> CompressionAlgorithm {
    let sample = if data.len() > 65536 {
        &data[..65536]
    } else {
        data
    };

    // Skip compression for already-compressed data
    if !analysis::is_compressible(sample) {
        return CompressionAlgorithm::None;
    }

    // Skip compression for known-compressed file types
    if let Some("zip" | "gzip" | "png" | "jpeg") = analysis::detect_file_type(sample) {
        return CompressionAlgorithm::None;
    }

    // Default: Zstd (best speed/ratio tradeoff)
    CompressionAlgorithm::Zstd
}

/// Compress data with the specified algorithm
pub fn compress(data: &[u8], algorithm: CompressionAlgorithm) -> Result<Vec<u8>> {
    match algorithm {
        CompressionAlgorithm::Zstd => super::zstd::compress_default(data),
        CompressionAlgorithm::Brotli => super::brotli::compress_default(data),
        CompressionAlgorithm::Lz4 => super::lz4::compress(data),
        CompressionAlgorithm::Lzma => super::lzma::compress(data, 6),
        CompressionAlgorithm::None => Ok(data.to_vec()),
    }
}

/// Decompress data with the specified algorithm
pub fn decompress(data: &[u8], algorithm: CompressionAlgorithm) -> Result<Vec<u8>> {
    match algorithm {
        CompressionAlgorithm::Zstd => super::zstd::decompress(data),
        CompressionAlgorithm::Brotli => super::brotli::decompress(data),
        CompressionAlgorithm::Lz4 => super::lz4::decompress(data),
        CompressionAlgorithm::Lzma => super::lzma::decompress(data),
        CompressionAlgorithm::None => Ok(data.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_selection_text() {
        let data = b"hello world this is some text data that should be compressible";
        let pipeline = CompressionPipeline::auto(data);
        assert_eq!(pipeline.algorithm(), CompressionAlgorithm::Zstd);
    }

    #[test]
    fn test_auto_selection_high_entropy() {
        // Random-looking data (high entropy) should not be compressed
        let data: Vec<u8> = (0..=255).cycle().take(65536).collect();
        let pipeline = CompressionPipeline::auto(&data);
        assert_eq!(pipeline.algorithm(), CompressionAlgorithm::None);
    }

    #[test]
    fn test_pipeline_roundtrip() {
        let data = b"compressible data repeated compressible data repeated";
        for algo in &[
            CompressionAlgorithm::Zstd,
            CompressionAlgorithm::Lz4,
            CompressionAlgorithm::Brotli,
            CompressionAlgorithm::Lzma,
            CompressionAlgorithm::None,
        ] {
            let compressed = compress(data, *algo).unwrap();
            let decompressed = decompress(&compressed, *algo).unwrap();
            assert_eq!(&decompressed, data, "roundtrip failed for {:?}", algo);
        }
    }
}
