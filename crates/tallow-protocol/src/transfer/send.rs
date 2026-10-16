//! File sending pipeline
//!
//! Reads files, builds manifest, chunks, compresses, encrypts,
//! and sends via the wire protocol.
//!
//! Supports streaming I/O for large files — files are read, compressed,
//! and encrypted one chunk at a time to avoid loading entire files into memory.

use crate::compression::{self, CompressionAlgorithm};
use crate::transfer::chunking::{self, ChunkConfig};
use crate::transfer::exclusion::ExclusionConfig;
use crate::transfer::manifest::{FileManifest, TransferType};
use crate::transfer::progress::TransferProgress;
use crate::wire::Message;
use crate::{ProtocolError, Result};
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;

/// Send pipeline for file transfers
pub struct SendPipeline {
    /// Unique transfer ID
    transfer_id: [u8; 16],
    /// Chunk configuration
    chunk_config: ChunkConfig,
    /// Compression algorithm
    compression: CompressionAlgorithm,
    /// File manifest
    manifest: FileManifest,
    /// Progress tracker
    progress: Option<TransferProgress>,
    /// Session encryption key (32 bytes, AES-256-GCM)
    session_key: [u8; 32],
    /// Scoped transfer keys (v3): per-transfer subkeys + domain-separated nonces
    scoped_keys: bool,
    /// v5+ encrypted manifests: the FileOffer manifest is AES-256-GCM
    /// encrypted under the session key (browser `prepareFileOffer` parity).
    manifest_encryption: bool,
    /// Simple (transport-only) mode: raw chunks (`Message::SimpleChunk`), no
    /// compression, no AEAD; the manifest stays plaintext. Set only after the
    /// peer confirmed capability via `Message::ModeAccept`.
    simple_mode: bool,
    /// File exclusion configuration for directory scanning
    exclusion: ExclusionConfig,
}

impl Drop for SendPipeline {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.session_key.zeroize();
    }
}

impl std::fmt::Debug for SendPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendPipeline")
            .field("transfer_id", &hex::encode(self.transfer_id))
            .field("chunk_config", &self.chunk_config)
            .field("compression", &self.compression)
            .finish()
    }
}

// Minimal hex encoding for debug display
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

/// Reader for streaming file chunks without loading the entire file into memory.
///
/// Each call to `next_chunk` reads up to `chunk_size` bytes from the file.
pub struct FileChunkReader {
    file: tokio::io::BufReader<tokio::fs::File>,
    chunk_size: usize,
    buffer: Vec<u8>,
    done: bool,
}

impl FileChunkReader {
    /// Open a file for streaming chunk reads
    async fn open(path: &Path, chunk_size: usize) -> Result<Self> {
        let file = tokio::fs::File::open(path).await.map_err(|e| {
            ProtocolError::TransferFailed(format!("open {}: {}", path.display(), e))
        })?;
        Ok(Self {
            file: tokio::io::BufReader::with_capacity(chunk_size, file),
            chunk_size,
            buffer: vec![0u8; chunk_size],
            done: false,
        })
    }

    /// Read the next chunk of raw data from the file.
    ///
    /// Returns `None` when the file is fully read.
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        if self.done {
            return Ok(None);
        }

        let mut total_read = 0;
        // Read exactly chunk_size bytes (or less at EOF)
        while total_read < self.chunk_size {
            let n = self
                .file
                .read(&mut self.buffer[total_read..])
                .await
                .map_err(|e| ProtocolError::TransferFailed(format!("read chunk: {}", e)))?;
            if n == 0 {
                self.done = true;
                break;
            }
            total_read += n;
        }

        if total_read == 0 {
            return Ok(None);
        }

        Ok(Some(self.buffer[..total_read].to_vec()))
    }
}

impl SendPipeline {
    /// Create a new send pipeline
    pub fn new(transfer_id: [u8; 16], session_key: [u8; 32]) -> Self {
        Self {
            transfer_id,
            chunk_config: ChunkConfig::new(),
            compression: CompressionAlgorithm::Zstd,
            manifest: FileManifest::new(chunking::DEFAULT_CHUNK_SIZE),
            progress: None,
            session_key,
            scoped_keys: false,
            manifest_encryption: false,
            simple_mode: false,
            exclusion: ExclusionConfig::default(),
        }
    }

    /// Set chunk configuration
    pub fn with_chunk_config(mut self, config: ChunkConfig) -> Self {
        self.chunk_config = config;
        self
    }

    /// Set compression algorithm
    pub fn with_compression(mut self, algo: CompressionAlgorithm) -> Self {
        self.compression = algo;
        self
    }

    /// Set file exclusion configuration for directory scanning
    pub fn with_exclusion(mut self, config: ExclusionConfig) -> Self {
        self.exclusion = config;
        self
    }

    /// Replace the session key after construction.
    ///
    /// This is used by the KEM handshake flow: the pipeline is created
    /// with a placeholder key for file scanning, then the real key is
    /// set after the handshake completes (before any encryption occurs).
    pub fn set_session_key(&mut self, key: [u8; 32]) {
        use zeroize::Zeroize;
        self.session_key.zeroize();
        self.session_key = key;
    }

    /// Enable scoped (per-transfer subkey) chunk crypto for this pipeline.
    ///
    /// Set from the KEM handshake result
    /// (`SenderHandshake::scoped_transfer_keys()`) once the peer is known to
    /// support v3. When enabled, the raw session key is never used for chunk
    /// AEAD: each chunk encrypts under a per-transfer subkey
    /// (`tallow_crypto::file::derive_transfer_subkey`) and its nonce carries
    /// the chunk domain byte (ATK-4-3 migration). Legacy (`false`, the
    /// default) preserves byte-identical v2 behavior.
    pub fn set_scoped_transfer_keys(&mut self, scoped: bool) {
        self.scoped_keys = scoped;
    }

    /// Enable v5+ encrypted manifests for this pipeline.
    ///
    /// Set from the KEM handshake result (`pq_auth()`; v5+) once the peer is
    /// known to support it. When enabled, `FileOffer` manifests are
    /// AES-256-GCM encrypted under the session key
    /// ([`crate::transfer::manifest::encrypt_manifest`]) so the relay never
    /// sees filenames or sizes (browser parity). Pre-v5 peers keep the
    /// plaintext manifest (the loud pre-v5 alarm already applies).
    pub fn set_manifest_encryption(&mut self, enabled: bool) {
        self.manifest_encryption = enabled;
    }

    /// Enable Simple (transport-only) mode for this pipeline.
    ///
    /// Chunks are sent raw (no compression, no AEAD) as `Message::SimpleChunk`
    /// and the manifest is built in plaintext form. Enable only after the peer
    /// confirmed Simple capability (`Message::ModeAccept`); never on E2E.
    pub fn set_simple_mode(&mut self, enabled: bool) {
        self.simple_mode = enabled;
        if enabled {
            // Simple file sends may call `prepare` before this flag is known
            // (it is only set after the ModeAccept exchange) — correct the
            // manifest here so the rebuilt offer declares raw chunks instead
            // of a leftover `zstd` that browser receivers now reject.
            self.manifest.per_chunk_compression = false;
            self.manifest.compression = None;
        }
    }

    /// Force plain (uncompressed) chunk frames for the rest of this transfer.
    ///
    /// Used when the receiver signalled `NO_ZSTD_CHUNK_FLAG` (browser peers
    /// cannot decode zstd): chunks go out raw and the manifest declares
    /// `compression = "none"` so any receiver — CLI or browser — stores them
    /// as-is. Call before [`build_offer_message`](Self::build_offer_message)
    /// so the rebuilt offer reflects the change.
    pub fn force_plain_chunks(&mut self) {
        self.compression = CompressionAlgorithm::None;
        self.manifest.compression = Some("none".to_string());
    }

    /// Build the `FileOffer` message for the prepared manifest.
    ///
    /// Call after the session key is set — on v5+ sessions the manifest is
    /// encrypted (browser `prepareFileOffer` parity); pre-v5 sessions keep
    /// the plaintext form. Pipelines that prepare before the handshake must
    /// rebuild the offer with this after `set_session_key` +
    /// `set_manifest_encryption`.
    pub fn build_offer_message(&self) -> Result<Message> {
        let manifest_bytes = self.manifest.to_bytes()?;
        let manifest_bytes = if self.manifest_encryption {
            tracing::debug!("FileOffer manifest encrypted (v5 session)");
            crate::transfer::manifest::encrypt_manifest(&self.session_key, &manifest_bytes)?
        } else {
            manifest_bytes
        };
        Ok(Message::FileOffer {
            transfer_id: self.transfer_id,
            manifest: manifest_bytes,
        })
    }

    /// Prepare files for transfer — scan, hash, build manifest
    ///
    /// Uses streaming BLAKE3 hashing so large files are not loaded into memory.
    ///
    /// # Arguments
    ///
    /// * `paths` - Files or directories to send
    ///
    /// # Returns
    ///
    /// The file manifest and a list of FileOffer messages
    pub async fn prepare(&mut self, paths: &[PathBuf]) -> Result<Vec<Message>> {
        let mut messages = Vec::new();

        for path in paths {
            self.scan_path(path).await?;
        }

        self.manifest.finalize()?;
        if self.simple_mode {
            // Simple mode: raw chunks on the wire — no compression metadata.
            self.manifest.per_chunk_compression = false;
            self.manifest.compression = None;
        } else {
            self.manifest.per_chunk_compression = true;
            self.manifest.compression = Some(match self.compression {
                CompressionAlgorithm::Zstd => "zstd".to_string(),
                CompressionAlgorithm::Lz4 => "lz4".to_string(),
                CompressionAlgorithm::Brotli => "brotli".to_string(),
                CompressionAlgorithm::Lzma => "lzma".to_string(),
                CompressionAlgorithm::None => "none".to_string(),
            });
        }
        self.progress = Some(TransferProgress::new(self.manifest.total_size));

        // Create FileOffer message (encrypted on v5+ sessions)
        messages.push(self.build_offer_message()?);

        Ok(messages)
    }

    /// Compute BLAKE3 hash of a file using streaming reads (O(chunk_size) memory)
    async fn hash_file_streaming(path: &Path, chunk_size: usize) -> Result<[u8; 32]> {
        let file = tokio::fs::File::open(path).await.map_err(|e| {
            ProtocolError::TransferFailed(format!("open for hash {}: {}", path.display(), e))
        })?;
        let mut reader = tokio::io::BufReader::with_capacity(chunk_size, file);
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; chunk_size];

        loop {
            let n = reader.read(&mut buf).await.map_err(|e| {
                ProtocolError::TransferFailed(format!("read for hash {}: {}", path.display(), e))
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }

        Ok(hasher.finalize().into())
    }

    /// Scan a path and add it to the manifest (streaming hash — no full file load)
    async fn scan_path(&mut self, path: &Path) -> Result<()> {
        let metadata = tokio::fs::metadata(path).await.map_err(|e| {
            ProtocolError::TransferFailed(format!("cannot read {}: {}", path.display(), e))
        })?;

        if metadata.is_file() {
            let hash = Self::hash_file_streaming(path, self.chunk_config.size).await?;
            let relative_path = path
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("unnamed"));

            self.manifest.add_file(relative_path, metadata.len(), hash);
        } else if metadata.is_dir() {
            self.scan_directory(path, path).await?;
        }

        Ok(())
    }

    /// Recursively scan a directory, respecting exclusion rules if configured
    async fn scan_directory(&mut self, base: &Path, dir: &Path) -> Result<()> {
        // Use exclusion-aware walker for the root directory scan
        if self.exclusion.is_active() && dir == base {
            let files = self.exclusion.walk_directory(base)?;
            for file_path in files {
                let metadata = tokio::fs::metadata(&file_path).await.map_err(|e| {
                    ProtocolError::TransferFailed(format!("stat {}: {}", file_path.display(), e))
                })?;
                let hash = Self::hash_file_streaming(&file_path, self.chunk_config.size).await?;
                let relative = file_path
                    .strip_prefix(base)
                    .unwrap_or(&file_path)
                    .to_path_buf();
                self.manifest.add_file(relative, metadata.len(), hash);
            }
            return Ok(());
        }

        // Fallback: standard recursive directory walk (no exclusion)
        let mut entries = tokio::fs::read_dir(dir).await.map_err(|e| {
            ProtocolError::TransferFailed(format!("readdir {}: {}", dir.display(), e))
        })?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| ProtocolError::TransferFailed(format!("readdir entry: {}", e)))?
        {
            let path = entry.path();
            let file_type = entry
                .file_type()
                .await
                .map_err(|e| ProtocolError::TransferFailed(format!("file_type: {}", e)))?;

            if file_type.is_file() {
                let metadata = entry
                    .metadata()
                    .await
                    .map_err(|e| ProtocolError::TransferFailed(format!("stat: {}", e)))?;
                let hash = Self::hash_file_streaming(&path, self.chunk_config.size).await?;
                let relative = path.strip_prefix(base).unwrap_or(&path).to_path_buf();

                self.manifest.add_file(relative, metadata.len(), hash);
            } else if file_type.is_dir() {
                Box::pin(self.scan_directory(base, &path)).await?;
            }
        }

        Ok(())
    }

    /// Open a file for streaming chunk reads.
    ///
    /// Use with `encrypt_chunk()` to process files without loading them
    /// entirely into memory.
    pub async fn open_file_reader(&self, file_path: &Path) -> Result<FileChunkReader> {
        FileChunkReader::open(file_path, self.chunk_config.size).await
    }

    /// Compress and encrypt a single raw chunk of file data.
    ///
    /// Used with `open_file_reader()` for streaming chunk generation.
    /// Each chunk is independently compressed then encrypted with AES-256-GCM.
    ///
    /// # Arguments
    ///
    /// * `raw_data` - Uncompressed chunk data (up to chunk_size bytes)
    /// * `global_index` - Global chunk index across all files
    /// * `total_chunks` - Total chunks across all files (set on final chunk only)
    /// * `is_last` - Whether this is the last chunk of the transfer
    pub fn encrypt_chunk(
        &self,
        raw_data: &[u8],
        global_index: u64,
        total_chunks: u64,
        is_last: bool,
    ) -> Result<Message> {
        // Simple (transport-only) mode: raw bytes on the wire — no compression,
        // no AEAD. Mirrors `Chunk`'s fields so ack/merkle handling is shared.
        if self.simple_mode {
            return Ok(Message::SimpleChunk {
                transfer_id: self.transfer_id,
                index: global_index,
                total: if is_last { Some(total_chunks) } else { None },
                data: raw_data.to_vec(),
            });
        }

        // Compress this chunk independently
        let compressed = compression::pipeline::compress(raw_data, self.compression)?;

        // Build AAD and nonce (domain-separated in scoped/v3 mode)
        let aad = chunking::build_chunk_aad(&self.transfer_id, global_index);
        let nonce = if self.scoped_keys {
            chunking::build_chunk_nonce_scoped(global_index)
        } else {
            chunking::build_chunk_nonce(global_index)
        };

        // Encrypt with AES-256-GCM. Scoped mode never uses the raw session
        // key: chunk crypto runs under a per-transfer subkey (ATK-4-3).
        let mut subkey_guard: Option<[u8; 32]> = if self.scoped_keys {
            Some(tallow_crypto::file::derive_transfer_subkey(
                &self.session_key,
                &self.transfer_id,
            ))
        } else {
            None
        };
        let chunk_key: &[u8; 32] = subkey_guard.as_ref().unwrap_or(&self.session_key);

        let encrypt_result =
            tallow_crypto::symmetric::aes_encrypt(chunk_key, &nonce, &compressed, &aad);

        if let Some(ref mut subkey) = subkey_guard {
            use zeroize::Zeroize;
            subkey.zeroize();
        }

        let encrypted = encrypt_result.map_err(|e| {
            ProtocolError::TransferFailed(format!("chunk encryption failed: {}", e))
        })?;

        Ok(Message::Chunk {
            transfer_id: self.transfer_id,
            index: global_index,
            total: if is_last { Some(total_chunks) } else { None },
            data: encrypted,
        })
    }

    /// Generate chunk messages for a specific file (legacy — loads entire file)
    ///
    /// For large files, prefer `open_file_reader()` + `encrypt_chunk()` instead.
    pub async fn chunk_file(
        &self,
        file_path: &Path,
        start_chunk_index: u64,
    ) -> Result<Vec<Message>> {
        let data = tokio::fs::read(file_path).await.map_err(|e| {
            ProtocolError::TransferFailed(format!("read {}: {}", file_path.display(), e))
        })?;

        self.chunk_data(&data, start_chunk_index).await
    }

    /// Get the manifest
    pub fn manifest(&self) -> &FileManifest {
        &self.manifest
    }

    /// Get the transfer ID
    pub fn transfer_id(&self) -> &[u8; 16] {
        &self.transfer_id
    }

    /// Get chunk size
    pub fn chunk_size(&self) -> usize {
        self.chunk_config.size
    }

    /// Prepare a text payload for transfer as a virtual file.
    ///
    /// The text is treated as a single file named `_tallow_text_` in the manifest.
    /// The receiver detects this special name and prints to stdout instead of disk.
    pub async fn prepare_text(&mut self, text: &[u8]) -> Result<Vec<Message>> {
        let hash: [u8; 32] = blake3::hash(text).into();

        self.manifest.transfer_type = TransferType::Text;
        self.manifest
            .add_file(PathBuf::from("_tallow_text_"), text.len() as u64, hash);

        self.manifest.finalize()?;
        if self.simple_mode {
            // Simple mode: raw chunks on the wire — no compression metadata.
            self.manifest.per_chunk_compression = false;
            self.manifest.compression = None;
        } else {
            self.manifest.per_chunk_compression = true;
            self.manifest.compression = Some(match self.compression {
                CompressionAlgorithm::Zstd => "zstd".to_string(),
                CompressionAlgorithm::Lz4 => "lz4".to_string(),
                CompressionAlgorithm::Brotli => "brotli".to_string(),
                CompressionAlgorithm::Lzma => "lzma".to_string(),
                CompressionAlgorithm::None => "none".to_string(),
            });
        }
        self.progress = Some(TransferProgress::new(self.manifest.total_size));

        Ok(vec![self.build_offer_message()?])
    }

    /// Generate chunk messages for in-memory data (text or stdin).
    ///
    /// Uses per-chunk compression: each chunk is independently compressed
    /// and encrypted.
    pub async fn chunk_data(&self, data: &[u8], start_chunk_index: u64) -> Result<Vec<Message>> {
        let chunk_size = self.chunk_config.size;
        let raw_chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();
        let num_chunks = raw_chunks.len() as u64;
        let total = start_chunk_index + num_chunks;

        let mut messages = Vec::with_capacity(raw_chunks.len());

        for (i, raw_chunk) in raw_chunks.iter().enumerate() {
            let global_index = start_chunk_index + i as u64;
            let is_last = i as u64 + 1 == num_chunks;

            let msg = self.encrypt_chunk(raw_chunk, global_index, total, is_last)?;
            messages.push(msg);
        }

        Ok(messages)
    }

    /// Update progress and return current state
    pub fn update_progress(&mut self, bytes: u64) -> Option<&TransferProgress> {
        if let Some(ref mut progress) = self.progress {
            progress.update(bytes);
        }
        self.progress.as_ref()
    }
}
