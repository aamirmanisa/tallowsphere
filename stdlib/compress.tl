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
native fn gzip(data: Bytes) -> Bytes
native fn gunzip(data: Bytes) -> Result<Bytes>

/// Zstd helpers
native fn zstd(data: Bytes) -> Bytes
native fn unzstd(data: Bytes) -> Result<Bytes>

/// Brotli helpers
native fn brotli(data: Bytes) -> Bytes
native fn unbrotli(data: Bytes) -> Result<Bytes>
