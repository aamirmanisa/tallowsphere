//! SHA3 hash function implementations

use sha3::{Digest, Sha3_256};

/// Hash data using SHA3-256
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// 32-byte SHA3-256 hash
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Streaming SHA3-256 hasher
pub struct StreamHasher {
    hasher: Sha3_256,
}

impl StreamHasher {
    /// Create a new streaming SHA3-256 hasher
    pub fn new() -> Self {
        Self {
            hasher: Sha3_256::new(),
        }
    }

    /// Update with more data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize and return the hash
    pub fn finalize(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

impl Default for StreamHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256() {
        let data = b"hello world";
        let h1 = sha3_256(data);
        let h2 = sha3_256(data);
        assert_eq!(h1, h2);
        assert_ne!(sha3_256(b"hello world"), sha3_256(b"hello!"));
    }

    #[test]
    fn test_stream_hasher() {
        let mut hasher = StreamHasher::new();
        hasher.update(b"hello ");
        hasher.update(b"world");
        let h1 = hasher.finalize();
        let h2 = sha3_256(b"hello world");
        assert_eq!(h1, h2);
    }
}
