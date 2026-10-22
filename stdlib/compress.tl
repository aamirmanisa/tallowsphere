// tallow.compress — gzip/zstd/brotli compression

enum Algorithm {
    Gzip,
    Zstd,
    Brotli,
    Deflate,
}

/// Compress bytes with default algorithm (zstd)
fn compress(data: Bytes) -> Bytes {
    compress_with(data, algo: .Zstd, level: 3)
}

/// Compress with specific algorithm and level
// native: compresses data
native fn compress_with(data: Bytes, algo: Algorithm, level: i32) -> Bytes

/// Decompress bytes (auto-detects algorithm)
// native: decompresses data
native fn decompress(data: Bytes) -> Result<Bytes>

/// Decompress with explicit algorithm
// native: decompresses with specific algorithm
native fn decompress_with(data: Bytes, algo: Algorithm) -> Result<Bytes>

/// Gzip helpers
fn gzip(data: Bytes) -> Bytes { compress_with(data, algo: .Gzip, level: 6) }
fn gunzip(data: Bytes) -> Result<Bytes> { decompress_with(data, algo: .Gzip) }

/// Zstd helpers
fn zstd(data: Bytes) -> Bytes { compress_with(data, algo: .Zstd, level: 3) }
fn unzstd(data: Bytes) -> Result<Bytes> { decompress_with(data, algo: .Zstd) }

/// Brotli helpers
fn brotli(data: Bytes) -> Bytes { compress_with(data, algo: .Brotli, level: 6) }
fn unbrotli(data: Bytes) -> Result<Bytes> { decompress_with(data, algo: .Brotli) }
