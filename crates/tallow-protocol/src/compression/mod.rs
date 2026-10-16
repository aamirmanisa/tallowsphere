//! Compression algorithms and pipeline

pub mod analysis;
pub mod brotli;
pub mod lz4;
pub mod lzma;
pub mod pipeline;
pub mod zstd;

use crate::Result;

/// Compression algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    /// Zstandard
    Zstd,
    /// Brotli
    Brotli,
    /// LZ4
    Lz4,
    /// LZMA/XZ
    Lzma,
    /// No compression
    None,
}

/// Compression trait
pub trait Compressor {
    /// Compress data
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Decompress data
    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>>;
}
