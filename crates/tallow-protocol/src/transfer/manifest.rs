//! File manifest for transfer metadata
//!
//! Contains the list of files, their sizes and hashes.
//! Signed by the sender before transfer begins.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Transfer content type
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub enum TransferType {
    /// Regular file transfer
    #[default]
    Files,
    /// Text-only transfer (no files written to disk on receive)
    Text,
    /// Clipboard text content
    Clipboard,
    /// Clipboard image data
    ClipboardImage,
    /// URL/link sharing
    Url,
}

/// File entry in manifest
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileEntry {
    /// Relative file path (sanitized, no parent traversal)
    pub path: PathBuf,
    /// File size in bytes
    pub size: u64,
    /// BLAKE3 hash of file contents
    pub hash: [u8; 32],
    /// Number of chunks for this file
    pub chunk_count: u64,
}

/// File manifest containing transfer metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    /// List of files
    pub files: Vec<FileEntry>,
    /// Total size of all files in bytes
    pub total_size: u64,
    /// Total number of chunks across all files
    pub total_chunks: u64,
    /// Chunk size used for splitting
    pub chunk_size: usize,
    /// Compression algorithm used (as string identifier)
    pub compression: Option<String>,
    /// BLAKE3 hash of the serialized manifest (before signing)
    pub manifest_hash: Option<[u8; 32]>,
    /// Type of transfer (files or text)
    #[serde(default)]
    pub transfer_type: TransferType,
    /// Whether compression is applied per-chunk (true) or whole-file (false).
    /// Per-chunk compression enables streaming I/O for large files.
    #[serde(default)]
    pub per_chunk_compression: bool,
}

impl FileManifest {
    /// Create a new empty manifest
    pub fn new(chunk_size: usize) -> Self {
        Self {
            files: Vec::new(),
            total_size: 0,
            total_chunks: 0,
            chunk_size,
            compression: None,
            manifest_hash: None,
            transfer_type: TransferType::default(),
            per_chunk_compression: true,
        }
    }

    /// Add a file to the manifest
    pub fn add_file(&mut self, path: PathBuf, size: u64, hash: [u8; 32]) {
        let chunk_count = size.div_ceil(self.chunk_size as u64);
        self.total_size += size;
        self.total_chunks += chunk_count;
        self.files.push(FileEntry {
            path,
            size,
            hash,
            chunk_count,
        });
    }

    /// Compute and store the manifest hash
    pub fn finalize(&mut self) -> crate::Result<()> {
        let bytes = postcard::to_stdvec(&self.files).map_err(|e| {
            crate::ProtocolError::EncodingError(format!("manifest finalize failed: {}", e))
        })?;
        self.manifest_hash = Some(blake3::hash(&bytes).into());
        Ok(())
    }

    /// Serialize the manifest to bytes
    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        postcard::to_stdvec(self).map_err(|e| {
            crate::ProtocolError::EncodingError(format!("manifest serialize failed: {}", e))
        })
    }

    /// Maximum total chunks allowed per transfer (DoS protection).
    /// At 256 KB per chunk, 1M chunks = 256 GB max transfer.
    const MAX_TOTAL_CHUNKS: u64 = 1_000_000;

    /// Maximum total transfer size in bytes (DoS protection): 10 TB
    const MAX_TOTAL_SIZE: u64 = 10_000_000_000_000;

    /// Maximum number of files in a single manifest
    const MAX_FILE_COUNT: usize = 1_000_000;

    /// Maximum individual file size in bytes: 1 TB
    const MAX_FILE_SIZE: u64 = 1_000_000_000_000;

    /// Deserialize a manifest from bytes, with validation against DoS limits
    pub fn from_bytes(data: &[u8]) -> crate::Result<Self> {
        let manifest: Self = postcard::from_bytes(data).map_err(|e| {
            crate::ProtocolError::DecodingError(format!("manifest decode failed: {}", e))
        })?;

        manifest.validate()?;
        Ok(manifest)
    }

    /// Validate manifest fields against DoS limits
    fn validate(&self) -> crate::Result<()> {
        if self.total_chunks > Self::MAX_TOTAL_CHUNKS {
            return Err(crate::ProtocolError::TransferFailed(format!(
                "manifest total_chunks {} exceeds limit {}",
                self.total_chunks,
                Self::MAX_TOTAL_CHUNKS
            )));
        }

        if self.total_size > Self::MAX_TOTAL_SIZE {
            return Err(crate::ProtocolError::TransferFailed(format!(
                "manifest total_size {} exceeds limit {}",
                self.total_size,
                Self::MAX_TOTAL_SIZE
            )));
        }

        if self.files.len() > Self::MAX_FILE_COUNT {
            return Err(crate::ProtocolError::TransferFailed(format!(
                "manifest file count {} exceeds limit {}",
                self.files.len(),
                Self::MAX_FILE_COUNT
            )));
        }

        // Validate individual files
        let mut computed_size: u64 = 0;
        let mut computed_chunks: u64 = 0;
        for entry in &self.files {
            if entry.size > Self::MAX_FILE_SIZE {
                return Err(crate::ProtocolError::TransferFailed(format!(
                    "file size {} exceeds limit {}",
                    entry.size,
                    Self::MAX_FILE_SIZE
                )));
            }
            computed_size = computed_size.checked_add(entry.size).ok_or_else(|| {
                crate::ProtocolError::TransferFailed("manifest total_size overflow".to_string())
            })?;
            computed_chunks = computed_chunks
                .checked_add(entry.chunk_count)
                .ok_or_else(|| {
                    crate::ProtocolError::TransferFailed(
                        "manifest total_chunks overflow".to_string(),
                    )
                })?;
        }

        // Cross-validate header totals against computed values from file entries
        if computed_size != self.total_size {
            return Err(crate::ProtocolError::TransferFailed(format!(
                "manifest total_size {} does not match sum of file sizes {}",
                self.total_size, computed_size
            )));
        }
        if computed_chunks != self.total_chunks {
            return Err(crate::ProtocolError::TransferFailed(format!(
                "manifest total_chunks {} does not match sum of file chunks {}",
                self.total_chunks, computed_chunks
            )));
        }

        Ok(())
    }

    /// Get total number of files
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Sanitize file paths to prevent directory traversal
    ///
    /// Removes parent directory components (`..`), root prefixes (`/`, `C:\`),
    /// and prefix components to ensure paths are strictly relative.
    pub fn sanitize_paths(&mut self) {
        for entry in &mut self.files {
            let sanitized: PathBuf = entry
                .path
                .components()
                .filter(|c| {
                    matches!(
                        c,
                        std::path::Component::Normal(_) | std::path::Component::CurDir
                    )
                })
                .collect();
            // If sanitization results in an empty path, use a safe fallback
            entry.path = if sanitized.as_os_str().is_empty() {
                PathBuf::from("unnamed")
            } else {
                sanitized
            };
        }
    }
}

impl Default for FileManifest {
    fn default() -> Self {
        Self::new(crate::transfer::chunking::DEFAULT_CHUNK_SIZE)
    }
}

// ---------------------------------------------------------------------------
// Manifest encryption (v5+ offer manifests) — relay-blinding for metadata
// ---------------------------------------------------------------------------

/// AAD for file-manifest encryption — domain-separated from chunk encryption.
///
/// Byte-for-byte parity contract with the browser wasm bridge
/// (`MANIFEST_AAD` in `crates/tallow-web/src/transfer.rs`, annotated
/// "MUST match CLI exactly"). Change only together with a protocol version.
pub const MANIFEST_AAD: &[u8] = b"tallow-manifest-v1";

/// Fixed, domain-separated nonce for manifest encryption.
///
/// `[0xFF; 4] || [0u8; 8]` — cannot collide with chunk nonces
/// (`[0u8; 4] || index.to_be_bytes()`). Safety invariant: exactly one
/// manifest encryption per session key; every transfer negotiates a fresh
/// KEM session, so this (key, nonce) pair is never reused across transfers.
pub fn manifest_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].fill(0xFF);
    nonce
}

/// Encrypt a manifest for the `FileOffer` (v5+ sessions).
///
/// Mirrors the browser `prepareFileOffer` path so the relay sees ciphertext
/// only — filenames and sizes stay hidden from it.
pub fn encrypt_manifest(session_key: &[u8; 32], manifest_bytes: &[u8]) -> crate::Result<Vec<u8>> {
    tallow_crypto::symmetric::aes_encrypt(
        session_key,
        &manifest_nonce(),
        manifest_bytes,
        MANIFEST_AAD,
    )
    .map_err(|e| crate::ProtocolError::TransferFailed(format!("manifest encryption failed: {}", e)))
}

/// Decrypt a manifest from a received `FileOffer`.
pub fn decrypt_manifest(session_key: &[u8; 32], encrypted: &[u8]) -> crate::Result<Vec<u8>> {
    tallow_crypto::symmetric::aes_decrypt(session_key, &manifest_nonce(), encrypted, MANIFEST_AAD)
        .map_err(|e| {
            crate::ProtocolError::TransferFailed(format!("manifest decryption failed: {}", e))
        })
}

// ---------------------------------------------------------------------------
// Sync ManifestExchange encryption (H12) — relay-blinding for sync metadata
// ---------------------------------------------------------------------------

/// AAD for `sync` ManifestExchange payloads — domain-separated from offer
/// manifests because sync uses fresh random nonces per payload (no web-parity
/// constraint on this lane).
pub const SYNC_MANIFEST_AAD: &[u8] = b"tallow-sync-manifest-v1";

/// Encrypt a sync manifest as `nonce || ciphertext` (fresh random 96-bit
/// nonce per call — safe for multiple messages under one session key).
pub fn encrypt_sync_manifest(
    session_key: &[u8; 32],
    manifest_bytes: &[u8],
) -> crate::Result<Vec<u8>> {
    let nonce: [u8; 12] = rand::random();
    let ciphertext = tallow_crypto::symmetric::aes_encrypt(
        session_key,
        &nonce,
        manifest_bytes,
        SYNC_MANIFEST_AAD,
    )
    .map_err(|e| {
        crate::ProtocolError::TransferFailed(format!("sync manifest encryption failed: {}", e))
    })?;
    let mut framed = Vec::with_capacity(12 + ciphertext.len());
    framed.extend_from_slice(&nonce);
    framed.extend_from_slice(&ciphertext);
    Ok(framed)
}

/// Decrypt a `nonce || ciphertext` sync manifest (v5+ peers).
pub fn decrypt_sync_manifest(session_key: &[u8; 32], framed: &[u8]) -> crate::Result<Vec<u8>> {
    if framed.len() < 12 + 16 {
        return Err(crate::ProtocolError::TransferFailed(
            "sync manifest too short".to_string(),
        ));
    }
    let (nonce, ciphertext) = framed.split_at(12);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce);
    tallow_crypto::symmetric::aes_decrypt(session_key, &nonce_arr, ciphertext, SYNC_MANIFEST_AAD)
        .map_err(|e| {
            crate::ProtocolError::TransferFailed(format!("sync manifest decryption failed: {}", e))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_add_file() {
        let mut manifest = FileManifest::new(64 * 1024);
        manifest.add_file(PathBuf::from("test.txt"), 1024, [0u8; 32]);
        assert_eq!(manifest.file_count(), 1);
        assert_eq!(manifest.total_size, 1024);
        assert_eq!(manifest.total_chunks, 1);
    }

    #[test]
    fn test_manifest_chunk_count() {
        let mut manifest = FileManifest::new(64 * 1024);
        // File larger than one chunk
        manifest.add_file(
            PathBuf::from("big.bin"),
            200_000, // ~3 chunks at 64KB
            [0u8; 32],
        );
        assert_eq!(manifest.files[0].chunk_count, 4); // ceil(200000/65536)
    }

    #[test]
    fn test_manifest_roundtrip() {
        let mut manifest = FileManifest::new(64 * 1024);
        manifest.add_file(PathBuf::from("a.txt"), 100, [1u8; 32]);
        manifest.add_file(PathBuf::from("b.txt"), 200, [2u8; 32]);
        manifest.finalize().unwrap();

        let bytes = manifest.to_bytes().unwrap();
        let decoded = FileManifest::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.file_count(), 2);
        assert_eq!(decoded.total_size, 300);
    }

    #[test]
    fn test_sanitize_paths() {
        let mut manifest = FileManifest::new(64 * 1024);
        manifest.add_file(PathBuf::from("../../../etc/passwd"), 100, [0u8; 32]);
        manifest.sanitize_paths();
        assert!(!manifest.files[0].path.to_string_lossy().contains(".."));
        // Should keep only the filename component
        assert_eq!(manifest.files[0].path, PathBuf::from("etc/passwd"));
    }

    #[test]
    fn test_sanitize_absolute_paths() {
        let mut manifest = FileManifest::new(64 * 1024);
        manifest.add_file(PathBuf::from("/etc/passwd"), 100, [0u8; 32]);
        manifest.sanitize_paths();
        // Root component should be stripped
        assert!(!manifest.files[0].path.is_absolute());
        assert_eq!(manifest.files[0].path, PathBuf::from("etc/passwd"));
    }

    #[test]
    fn test_sanitize_empty_path() {
        let mut manifest = FileManifest::new(64 * 1024);
        manifest.add_file(PathBuf::from(".."), 100, [0u8; 32]);
        manifest.sanitize_paths();
        // Should fall back to "unnamed"
        assert_eq!(manifest.files[0].path, PathBuf::from("unnamed"));
    }
}

#[cfg(test)]
mod manifest_crypto_tests {
    use super::*;

    #[test]
    fn nonce_and_aad_match_browser_contract() {
        // Byte-for-byte parity with crates/tallow-web/src/transfer.rs
        // (MANIFEST_AAD / manifest_nonce): the relay-blinding contract.
        assert_eq!(MANIFEST_AAD, b"tallow-manifest-v1");
        assert_eq!(
            manifest_nonce(),
            [0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn manifest_encrypt_decrypt_roundtrip_and_key_binding() {
        let key = [0x5au8; 32];
        let plaintext = b"postcard manifest bytes";
        let encrypted = encrypt_manifest(&key, plaintext).unwrap();
        assert_ne!(encrypted.as_slice(), plaintext.as_slice());
        assert_eq!(decrypt_manifest(&key, &encrypted).unwrap(), plaintext);
        // Wrong key must fail authentication.
        assert!(decrypt_manifest(&[0x99u8; 32], &encrypted).is_err());
        // Tampered ciphertext must fail authentication.
        let mut tampered = encrypted.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(decrypt_manifest(&key, &tampered).is_err());
    }

    #[test]
    fn sync_manifest_roundtrip_fresh_nonces_and_fail_closed() {
        let key = [0x33u8; 32];
        let plaintext = b"sync exchange manifest bytes";
        let e1 = encrypt_sync_manifest(&key, plaintext).unwrap();
        let e2 = encrypt_sync_manifest(&key, plaintext).unwrap();
        // Fresh random nonce per call: distinct ciphertexts, no GCM reuse.
        assert_ne!(e1, e2);
        assert_eq!(e1.len(), 12 + plaintext.len() + 16);
        assert_eq!(decrypt_sync_manifest(&key, &e1).unwrap(), plaintext);
        assert_eq!(decrypt_sync_manifest(&key, &e2).unwrap(), plaintext);
        // Wrong key, tamper, truncation, and non-ciphertext input all fail closed.
        assert!(decrypt_sync_manifest(&[0u8; 32], &e1).is_err());
        let mut t = e1.clone();
        let l = t.len() - 1;
        t[l] ^= 1;
        assert!(decrypt_sync_manifest(&key, &t).is_err());
        assert!(decrypt_sync_manifest(&key, &e1[..20]).is_err());
        assert!(decrypt_sync_manifest(
            &key,
            b"not ciphertext at all, but long enough to pass the length gate"
        )
        .is_err());
    }

    #[tokio::test]
    async fn sync_exchange_frame_roundtrips_codec_with_encrypted_manifest() {
        use crate::wire::codec::TallowCodec;
        use bytes::BytesMut;

        let transfer_id = [0x44u8; 16];
        let key = [0x66u8; 32];
        let mut pipeline = crate::transfer::send::SendPipeline::new(transfer_id, key);
        let _ = pipeline.prepare_text(b"sync frame payload").await.unwrap();
        let manifest_bytes = pipeline.manifest().to_bytes().unwrap();
        let encrypted = encrypt_sync_manifest(&key, &manifest_bytes).unwrap();

        // The frame that sync.rs actually puts on the wire.
        let msg = crate::wire::Message::ManifestExchange {
            transfer_id,
            manifest: encrypted,
        };
        let mut codec = TallowCodec::new();
        let mut buf = BytesMut::new();
        codec.encode_msg(&msg, &mut buf).unwrap();
        let mut read = buf.clone();
        let decoded = codec.decode_msg(&mut read).unwrap().unwrap();
        let crate::wire::Message::ManifestExchange { manifest, .. } = decoded else {
            panic!("expected ManifestExchange");
        };
        // Receiver path: decrypt then parse.
        let plain = decrypt_sync_manifest(&key, &manifest).unwrap();
        let parsed = FileManifest::from_bytes(&plain).unwrap();
        assert_eq!(parsed.files.len(), 1);
    }
}
