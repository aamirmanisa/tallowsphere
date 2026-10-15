//! BLAKE3 hash function implementations

use blake3::{derive_key as blake3_derive_key, Hash, Hasher};

/// Hash data using BLAKE3
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// 32-byte BLAKE3 hash
pub fn hash(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

/// Keyed hash using BLAKE3 in MAC mode
///
/// # Arguments
///
/// * `key` - 32-byte key for the MAC
/// * `data` - The data to authenticate
///
/// # Returns
///
/// 32-byte MAC tag
pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(data);
    hasher.finalize().into()
}

/// Derive a key using BLAKE3 KDF mode
///
/// # Arguments
///
/// * `context` - Context string for domain separation
/// * `key_material` - Input key material to derive from
///
/// # Returns
///
/// 32-byte derived key
pub fn derive_key(context: &str, key_material: &[u8]) -> [u8; 32] {
    blake3_derive_key(context, key_material)
}

/// Streaming BLAKE3 hasher for large data
pub struct StreamHasher {
    hasher: Hasher,
}

impl StreamHasher {
    /// Create a new streaming hasher
    pub fn new() -> Self {
        Self {
            hasher: Hasher::new(),
        }
    }

    /// Create a new keyed streaming hasher
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        Self {
            hasher: Hasher::new_keyed(key),
        }
    }

    /// Update with more data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize and return the hash
    pub fn finalize(&self) -> [u8; 32] {
        self.hasher.finalize().into()
    }

    /// Finalize and return the hash as a Hash object
    pub fn finalize_hash(&self) -> Hash {
        self.hasher.finalize()
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
    fn test_hash() {
        let data = b"hello world";
        let h1 = hash(data);
        let h2 = hash(data);
        assert_eq!(h1, h2);
        assert_ne!(hash(b"hello world"), hash(b"hello world!"));
    }

    #[test]
    fn test_keyed_hash() {
        let key = [0u8; 32];
        let data = b"message";
        let mac1 = keyed_hash(&key, data);
        let mac2 = keyed_hash(&key, data);
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_derive_key() {
        let material = b"source material";
        let key1 = derive_key("context1", material);
        let key2 = derive_key("context2", material);
        assert_ne!(key1, key2); // Different contexts produce different keys
    }

    #[test]
    fn test_stream_hasher() {
        let mut hasher = StreamHasher::new();
        hasher.update(b"hello ");
        hasher.update(b"world");
        let h1 = hasher.finalize();
        let h2 = hash(b"hello world");
        assert_eq!(h1, h2);
    }
}
