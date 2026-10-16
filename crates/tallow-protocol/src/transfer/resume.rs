//! Transfer resume state
//!
//! Saves and restores transfer progress for resuming interrupted transfers.

use crate::{ProtocolError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

/// Magic for the versioned receive-state envelope (design §3.2).
pub const RECEIVE_STATE_MAGIC: [u8; 4] = *b"TRSV";
/// Envelope version for the receive-state file.
pub const RECEIVE_STATE_VERSION: u8 = 1;
/// `kind` discriminator for receive-state envelopes.
pub const RECEIVE_STATE_KIND: &str = "receive";

/// Resume state for interrupted transfers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeState {
    /// Transfer ID
    pub transfer_id: [u8; 16],
    /// Set of chunk indices that have been verified
    pub verified_chunks: HashSet<u64>,
    /// Total expected chunks
    pub total_chunks: u64,
    /// Bytes successfully transferred
    pub bytes_transferred: u64,
    /// BLAKE3 hash of the manifest (to verify same transfer)
    pub manifest_hash: [u8; 32],
}

impl ResumeState {
    /// Create a new resume state for a transfer
    pub fn new(transfer_id: [u8; 16], total_chunks: u64, manifest_hash: [u8; 32]) -> Self {
        Self {
            transfer_id,
            verified_chunks: HashSet::new(),
            total_chunks,
            bytes_transferred: 0,
            manifest_hash,
        }
    }

    /// Mark a chunk as verified
    pub fn mark_verified(&mut self, chunk_index: u64, chunk_size: u64) {
        self.verified_chunks.insert(chunk_index);
        self.bytes_transferred += chunk_size;
    }

    /// Check if a chunk has been verified
    pub fn is_verified(&self, chunk_index: u64) -> bool {
        self.verified_chunks.contains(&chunk_index)
    }

    /// Get the next chunk index that needs to be transferred
    pub fn next_needed_chunk(&self) -> Option<u64> {
        (0..self.total_chunks).find(|i| !self.verified_chunks.contains(i))
    }

    /// Get completion percentage
    pub fn completion_percentage(&self) -> f64 {
        if self.total_chunks == 0 {
            return 0.0;
        }
        (self.verified_chunks.len() as f64 / self.total_chunks as f64) * 100.0
    }

    /// Serialize to bytes for checkpoint
    pub fn checkpoint(&self) -> Result<Vec<u8>> {
        postcard::to_stdvec(self)
            .map_err(|e| ProtocolError::EncodingError(format!("checkpoint encode failed: {}", e)))
    }

    /// Restore from checkpoint bytes
    pub fn restore(data: &[u8]) -> Result<Self> {
        postcard::from_bytes(data)
            .map_err(|e| ProtocolError::DecodingError(format!("checkpoint decode failed: {}", e)))
    }

    /// Check if transfer is complete
    pub fn is_complete(&self) -> bool {
        self.verified_chunks.len() as u64 >= self.total_chunks
    }
}

/// Versioned receive-state envelope (design §3.2).
///
/// ```text
/// { magic:"TRSV", ver:1, kind:"receive", file_blake3:[u8;32], file_size:u64,
///   chunk_size:u32, transfer_id:[u8;16], created_unix:u64, updated_unix:u64,
///   resume: <ResumeState postcard bytes> }
/// ```
///
/// The envelope is advisory: the completion gate stays the full-file BLAKE3 and
/// atomic rename in the receive path. It is written atomically (tmp + rename +
/// dir fsync) and validated on load against the transfer identity
/// (`file_blake3` + `file_size` + `chunk_size`); any mismatch must make the
/// caller discard the state and restart, never resume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiveStateFile {
    /// Envelope magic `TRSV`.
    pub magic: [u8; 4],
    /// Envelope version.
    pub version: u8,
    /// Envelope kind discriminator (`"receive"`).
    pub kind: String,
    /// BLAKE3 of the whole file (identity + `ResumeState::manifest_hash`).
    pub file_blake3: [u8; 32],
    /// Total file size in bytes (identity check).
    pub file_size: u64,
    /// Plaintext chunk size used by the transfer (identity check).
    pub chunk_size: u32,
    /// Per-transfer id (chunk-crypto scope).
    pub transfer_id: [u8; 16],
    /// Creation time (unix seconds).
    pub created_unix: u64,
    /// Last update time (unix seconds).
    pub updated_unix: u64,
    /// Shipped resume state (source of truth for verified chunks).
    pub resume: ResumeState,
}

impl ReceiveStateFile {
    /// New envelope for a fresh receive of `file_blake3`.
    pub fn new(
        file_blake3: [u8; 32],
        file_size: u64,
        chunk_size: u32,
        transfer_id: [u8; 16],
    ) -> Self {
        let now = unix_now();
        let total_chunks = if chunk_size == 0 {
            0
        } else {
            file_size.div_ceil(chunk_size as u64)
        };
        Self {
            magic: RECEIVE_STATE_MAGIC,
            version: RECEIVE_STATE_VERSION,
            kind: RECEIVE_STATE_KIND.to_string(),
            file_blake3,
            file_size,
            chunk_size,
            transfer_id,
            created_unix: now,
            updated_unix: now,
            resume: ResumeState::new(transfer_id, total_chunks, file_blake3),
        }
    }

    /// Mark the envelope as updated (called on each checkpoint).
    pub fn touch(&mut self) {
        self.updated_unix = unix_now();
    }

    /// Encode the envelope with postcard.
    pub fn encode(&self) -> Result<Vec<u8>> {
        postcard::to_stdvec(self)
            .map_err(|e| ProtocolError::EncodingError(format!("receive state encode: {e}")))
    }

    /// Decode + validate the envelope (magic/version/kind).
    pub fn decode(data: &[u8]) -> Result<Self> {
        let state: Self = postcard::from_bytes(data)
            .map_err(|e| ProtocolError::DecodingError(format!("receive state decode: {e}")))?;
        if state.magic != RECEIVE_STATE_MAGIC {
            return Err(ProtocolError::InvalidMessage(
                "receive state: bad magic".to_string(),
            ));
        }
        if state.version != RECEIVE_STATE_VERSION {
            return Err(ProtocolError::VersionMismatch {
                local: RECEIVE_STATE_VERSION as u32,
                remote: state.version as u32,
            });
        }
        if state.kind != RECEIVE_STATE_KIND {
            return Err(ProtocolError::InvalidMessage(format!(
                "receive state: unexpected kind '{}'",
                state.kind
            )));
        }
        Ok(state)
    }

    /// Atomically persist to `path` (tmp + fsync + rename + dir fsync where possible).
    pub fn save_atomic(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ProtocolError::Io(std::io::Error::new(
                    e.kind(),
                    format!("create state dir '{}': {e}", parent.display()),
                ))
            })?;
        }
        let bytes = self.encode()?;
        let tmp = path.with_extension("state.tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        if let Some(parent) = path.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    /// Load + validate an envelope from `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        Self::decode(&bytes)
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resume_state_basic() {
        let mut state = ResumeState::new([1u8; 16], 10, [0u8; 32]);
        assert_eq!(state.completion_percentage(), 0.0);
        assert_eq!(state.next_needed_chunk(), Some(0));

        state.mark_verified(0, 1024);
        assert!(state.is_verified(0));
        assert!(!state.is_verified(1));
        assert_eq!(state.next_needed_chunk(), Some(1));
    }

    #[test]
    fn test_resume_state_complete() {
        let mut state = ResumeState::new([1u8; 16], 3, [0u8; 32]);
        state.mark_verified(0, 100);
        state.mark_verified(1, 100);
        state.mark_verified(2, 100);
        assert!(state.is_complete());
        assert_eq!(state.next_needed_chunk(), None);
    }

    #[test]
    fn test_resume_checkpoint_roundtrip() {
        let mut state = ResumeState::new([1u8; 16], 10, [42u8; 32]);
        state.mark_verified(0, 1024);
        state.mark_verified(3, 1024);

        let bytes = state.checkpoint().unwrap();
        let restored = ResumeState::restore(&bytes).unwrap();

        assert_eq!(restored.transfer_id, state.transfer_id);
        assert!(restored.is_verified(0));
        assert!(restored.is_verified(3));
        assert!(!restored.is_verified(1));
    }

    fn tmp_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let nonce: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        p.push(format!("tallow-resume-test-{}-{}", tag, nonce));
        std::fs::create_dir_all(&p).unwrap();
        p.join("file.state")
    }

    #[test]
    fn receive_state_envelope_roundtrip_and_identity() {
        let path = tmp_path("roundtrip");
        let mut env = ReceiveStateFile::new([5u8; 32], 700_000, 262_144, [9u8; 16]);
        env.resume.mark_verified(0, 262_144);
        env.resume.mark_verified(1, 262_144);
        env.touch();
        env.save_atomic(&path).unwrap();

        let loaded = ReceiveStateFile::load(&path).unwrap();
        assert_eq!(loaded.magic, RECEIVE_STATE_MAGIC);
        assert_eq!(loaded.version, RECEIVE_STATE_VERSION);
        assert_eq!(loaded.kind, RECEIVE_STATE_KIND);
        assert_eq!(loaded.file_blake3, [5u8; 32]);
        assert_eq!(loaded.file_size, 700_000);
        assert_eq!(loaded.chunk_size, 262_144);
        assert_eq!(loaded.resume.total_chunks, 3);
        assert!(loaded.resume.is_verified(0) && loaded.resume.is_verified(1));
        assert!(!loaded.resume.is_verified(2));
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn receive_state_truncated_prefixes_error_cleanly() {
        let env = ReceiveStateFile::new([1u8; 32], 1000, 256, [2u8; 16]);
        let bytes = env.encode().unwrap();
        for n in 0..bytes.len() {
            // every prefix must fail cleanly (no panic/hang)
            let res = ReceiveStateFile::decode(&bytes[..n]);
            assert!(res.is_err(), "prefix {n} unexpectedly decoded");
        }
        let pos = bytes.len() / 2;
        let mut flipped = bytes.clone();
        flipped[pos] ^= 0xff;
        // either a clean decode error or a decode that fails validation later
        let _ = ReceiveStateFile::decode(&flipped);
    }

    #[test]
    fn receive_state_rejects_bad_version_and_magic() {
        let mut env = ReceiveStateFile::new([1u8; 32], 1000, 256, [2u8; 16]);
        env.version = RECEIVE_STATE_VERSION + 1;
        let bytes = env.encode().unwrap();
        assert!(matches!(
            ReceiveStateFile::decode(&bytes),
            Err(ProtocolError::VersionMismatch { .. })
        ));

        let mut env = ReceiveStateFile::new([1u8; 32], 1000, 256, [2u8; 16]);
        env.magic = *b"XXXX";
        let bytes = env.encode().unwrap();
        assert!(ReceiveStateFile::decode(&bytes).is_err());

        let mut env = ReceiveStateFile::new([1u8; 32], 1000, 256, [2u8; 16]);
        env.kind = "delta-sync".to_string();
        let bytes = env.encode().unwrap();
        assert!(ReceiveStateFile::decode(&bytes).is_err());
    }
}
