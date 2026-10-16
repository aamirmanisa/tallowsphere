//! Chunking strategy with AES-256-GCM encryption per chunk
//!
//! Each chunk is encrypted with a counter-based nonce and AAD
//! binding the chunk index to prevent reordering attacks.

use serde::{Deserialize, Serialize};

/// Default chunk size (256 KB)
///
/// Larger chunks reduce per-chunk overhead (AAD, nonce, AES-GCM tag) and
/// improve throughput on high-latency links by sending more data per round trip.
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// Minimum chunk size (16 KB)
pub const MIN_CHUNK_SIZE: usize = 16 * 1024;

/// Maximum chunk size (4 MB)
pub const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Chunk configuration
#[derive(Debug, Clone)]
pub struct ChunkConfig {
    /// Chunk size in bytes
    pub size: usize,
    /// Minimum chunk size
    pub min_size: usize,
    /// Maximum chunk size
    pub max_size: usize,
}

impl ChunkConfig {
    /// Create default chunk config (256 KB)
    pub fn new() -> Self {
        Self {
            size: DEFAULT_CHUNK_SIZE,
            min_size: MIN_CHUNK_SIZE,
            max_size: MAX_CHUNK_SIZE,
        }
    }

    /// Create config with custom chunk size
    pub fn with_size(size: usize) -> Self {
        Self {
            size: size.clamp(MIN_CHUNK_SIZE, MAX_CHUNK_SIZE),
            min_size: MIN_CHUNK_SIZE,
            max_size: MAX_CHUNK_SIZE,
        }
    }
}

impl Default for ChunkConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate adaptive chunk size based on network conditions
///
/// Adjusts chunk size based on throughput and RTT:
/// - Higher throughput → larger chunks (less overhead)
/// - Higher RTT → larger chunks (fewer round-trips)
pub fn adaptive_chunk_size(throughput_bps: u64, rtt_ms: u64) -> usize {
    // Target: fill ~2 RTT windows of data per chunk
    // This balances latency (not too large) with throughput (not too small)
    let bytes_per_ms = throughput_bps / 8 / 1000;
    let target = (bytes_per_ms * rtt_ms * 2) as usize;

    target.clamp(MIN_CHUNK_SIZE, MAX_CHUNK_SIZE)
}

/// A single chunk of file data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    /// Chunk index (0-based)
    pub index: u64,
    /// Raw (unencrypted) data
    pub data: Vec<u8>,
}

/// Build AAD (Additional Authenticated Data) for a chunk
///
/// Binds the transfer ID and chunk index to the ciphertext,
/// preventing chunk reordering attacks.
pub fn build_chunk_aad(transfer_id: &[u8; 16], chunk_index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(24);
    aad.extend_from_slice(transfer_id);
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad
}

/// Build a counter-based nonce for AES-256-GCM
///
/// Format: [4 zero bytes][8-byte BE chunk counter]
/// Guarantees uniqueness: each chunk gets a different nonce.
pub fn build_chunk_nonce(chunk_index: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&chunk_index.to_be_bytes());
    nonce
}

/// Build a domain-separated counter nonce for scoped (v3) chunk crypto.
///
/// Format: `[0x01 domain byte][3 zero bytes][8-byte BE chunk counter]`.
/// The domain byte keeps chunk nonces disjoint from chat nonces (which use
/// `0x02`), so a key that is (incorrectly) shared across paths cannot yield
/// an identical `(key, nonce)` pair.
pub fn build_chunk_nonce_scoped(chunk_index: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0] = 0x01;
    nonce[4..12].copy_from_slice(&chunk_index.to_be_bytes());
    nonce
}

/// Split data into chunks
pub fn split_into_chunks(data: &[u8], chunk_size: usize) -> Vec<Chunk> {
    data.chunks(chunk_size)
        .enumerate()
        .map(|(i, chunk_data)| Chunk {
            index: i as u64,
            data: chunk_data.to_vec(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_config_default() {
        let config = ChunkConfig::new();
        assert_eq!(config.size, DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn test_adaptive_chunk_size() {
        // 100 Mbps, 50ms RTT
        let size = adaptive_chunk_size(100_000_000, 50);
        assert!(size >= MIN_CHUNK_SIZE);
        assert!(size <= MAX_CHUNK_SIZE);
    }

    #[test]
    fn test_scoped_chunk_nonce_domain_separation() {
        let legacy = build_chunk_nonce(7);
        let scoped = build_chunk_nonce_scoped(7);
        assert_eq!(&legacy[..4], &[0u8; 4]);
        assert_eq!(scoped[0], 0x01);
        assert_eq!(&scoped[1..4], &[0u8; 3]);
        // Counter still disambiguates chunks within a scope.
        assert_ne!(scoped, build_chunk_nonce_scoped(8));
        // And the counter bytes match the legacy layout for auditing.
        assert_eq!(&scoped[4..12], &legacy[4..12]);
    }

    #[test]
    fn test_nonce_domains_pairwise_disjoint_across_paths() {
        // One-key-one-scheme invariant (crypto report item #9): with the SAME
        // session key and the same counter value, the three nonce domains must
        // be pairwise distinct — a (wrongly) shared key can then never collide
        // a (key, nonce) pair across paths:
        //   legacy chunk [0x00;4] || counter, scoped chunk 0x01 || [0;3] || counter,
        //   chat 0x02 || [0;3] || counter.
        use crate::chat::encrypt::encrypt_chat_text;
        let key = [7u8; 32];
        for ctr in [0u64, 1, 7, 42, u32::MAX as u64] {
            let legacy = build_chunk_nonce(ctr);
            let scoped = build_chunk_nonce_scoped(ctr);
            let mut chat_counter = ctr;
            let (_, chat) = encrypt_chat_text("x", &key, &mut chat_counter).unwrap();

            assert_ne!(legacy, scoped, "legacy vs scoped chunk domain, ctr {ctr}");
            assert_ne!(legacy, chat, "legacy chunk vs chat domain, ctr {ctr}");
            assert_ne!(scoped, chat, "scoped chunk vs chat domain, ctr {ctr}");

            assert_eq!(&legacy[..4], &[0u8; 4]);
            assert_eq!(&scoped[..4], &[0x01, 0u8, 0, 0]);
            assert_eq!(&chat[..4], &[0x02, 0u8, 0, 0]);
            // Counters stay byte-aligned across domains for audits.
            assert_eq!(&legacy[4..], &chat[4..]);
            assert_eq!(&scoped[4..], &chat[4..]);
        }
    }

    #[test]
    fn test_chunk_aad_uniqueness() {
        let id = [1u8; 16];
        let aad1 = build_chunk_aad(&id, 0);
        let aad2 = build_chunk_aad(&id, 1);
        assert_ne!(aad1, aad2);
    }

    #[test]
    fn test_chunk_nonce_uniqueness() {
        let n1 = build_chunk_nonce(0);
        let n2 = build_chunk_nonce(1);
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_split_into_chunks() {
        let data = vec![0u8; 150];
        let chunks = split_into_chunks(&data, 64);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].data.len(), 64);
        assert_eq!(chunks[1].data.len(), 64);
        assert_eq!(chunks[2].data.len(), 22);
    }
}
