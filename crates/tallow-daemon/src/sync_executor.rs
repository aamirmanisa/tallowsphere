//! Sync execution loop — reacts to filesystem change events, determines
//! sync strategy (WholeFile vs BlockDelta), invokes the delta engine for
//! Merkle tree comparison and block-level transfer, and applies delta
//! payloads to destination files with BLAKE3 verification.
//!
//! The sync executor spawns as a background tokio task that listens on the
//! SSE broadcast channel for `FileChange` events, matches them against
//! active sync pairs, applies debounce, filter rules, and triggers the
//! appropriate sync path.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::sync::Mutex;
use tracing;

use crate::db::SyncPair;
use crate::delta::{self, DeltaPayload, BLOCK_SIZE};
use crate::sse::ProgressEvent;

// ── Sync strategy ────────────────────────────────────────────────────────

/// Which approach to use for syncing a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStrategy {
    /// Copy the entire file (for small files, large change ratio, or oversized files).
    WholeFile,
    /// Only transfer changed 4KB blocks identified by Merkle tree comparison.
    BlockDelta,
}

/// Thresholds for the tiered sync strategy.
const SMALL_FILE_THRESHOLD: u64 = 1_048_576; // 1MB
const DELTA_MAX_SIZE: u64 = 100_000_000; // 100MB
const DELTA_MAX_CHANGE_RATIO: f64 = 0.5; // 50%

/// Determine the sync strategy based on file size and change ratio.
///
/// Tiered decision table:
/// | File Size    | Change % | Strategy    | Rationale                              |
/// |-------------|----------|-------------|----------------------------------------|
/// | <1MB        | any      | WholeFile   | Delta overhead > transfer savings      |
/// | 1MB–100MB   | <50%     | BlockDelta  | Only changed blocks transfer           |
/// | 1MB–100MB   | >=50%    | WholeFile   | Delta overhead exceeds savings         |
/// | >100MB      | <50%     | WholeFile   | v1: CDC deferred; whole-file fallback  |
/// | >100MB      | >=50%    | WholeFile   | Whole file                             |
pub fn compute_sync_strategy(file_size: u64, change_ratio: f64) -> SyncStrategy {
    if file_size < SMALL_FILE_THRESHOLD {
        return SyncStrategy::WholeFile;
    }
    if file_size <= DELTA_MAX_SIZE && change_ratio < DELTA_MAX_CHANGE_RATIO {
        return SyncStrategy::BlockDelta;
    }
    SyncStrategy::WholeFile
}

// ── Whole-file copy fallback ─────────────────────────────────────────────

/// Simple whole-file copy with BLAKE3 verification and .merkle file generation.
///
/// Used as the fallback when delta sync is not beneficial. Copies the source
/// file to the destination, computes BLAKE3 hashes, and writes a .merkle
/// companion file in the tallow-merkle-v1 format.
pub fn copy_with_merkle(
    source_path: &Path,
    dest_path: &Path,
    chunk_size: usize,
) -> Result<(String, Vec<Vec<String>>)> {
    use std::io::{BufReader, Read, Write};

    // Ensure parent directory exists
    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create parent dir: {}", parent.display()))?;
    }

    let src_file = std::fs::File::open(source_path)
        .with_context(|| format!("cannot open source: {}", source_path.display()))?;
    let mut dst_file = std::fs::File::create(dest_path)
        .with_context(|| format!("cannot create dest: {}", dest_path.display()))?;

    let mut reader = BufReader::with_capacity(chunk_size, src_file);
    let mut hasher = blake3::Hasher::new();
    let mut chunk_hashes: Vec<String> = Vec::new();

    let mut buf = vec![0u8; chunk_size];

    loop {
        let n = reader
            .read(&mut buf)
            .with_context(|| format!("read error on: {}", source_path.display()))?;
        if n == 0 {
            break;
        }
        let slice = &buf[..n];

        hasher.update(slice);
        dst_file
            .write_all(slice)
            .with_context(|| format!("write error on: {}", dest_path.display()))?;

        let chunk_hash = blake3::hash(slice).to_hex().to_string();
        chunk_hashes.push(chunk_hash);
    }

    drop(dst_file);

    let file_hash = hasher.finalize().to_hex().to_string();

    // Build Merkle tree
    let tree = build_merkle_tree(&chunk_hashes);

    // Write .merkle companion file
    write_merkle_file(dest_path, &tree, &file_hash, chunk_size)?;

    Ok((file_hash, tree))
}

/// Build a full binary Merkle tree from leaf hashes.
fn build_merkle_tree(chunk_hashes: &[String]) -> Vec<Vec<String>> {
    if chunk_hashes.is_empty() {
        return vec![vec![blake3::hash(b"").to_hex().to_string()]];
    }
    let mut layers: Vec<Vec<String>> = vec![chunk_hashes.to_vec()];
    let mut current = chunk_hashes.to_vec();
    while current.len() > 1 {
        let mut next = Vec::new();
        for pair in current.chunks(2) {
            if pair.len() == 2 {
                let combined = format!("{}{}", pair[0], pair[1]);
                let parent = blake3::hash(combined.as_bytes());
                next.push(parent.to_hex().to_string());
            } else {
                next.push(pair[0].clone());
            }
        }
        layers.push(next.clone());
        current = next;
    }
    layers
}

/// Write a .merkle companion file alongside the destination file.
fn write_merkle_file(
    file_path: &Path,
    tree: &[Vec<String>],
    source_hash: &str,
    chunk_size: usize,
) -> Result<()> {
    let merkle_path = PathBuf::from(format!("{}.merkle", file_path.display()));
    let root_hash = tree
        .last()
        .and_then(|l| l.last())
        .cloned()
        .unwrap_or_default();
    let chunk_hashes: Vec<&String> = tree
        .first()
        .map_or(&[] as &[String], |l| l.as_slice())
        .iter()
        .collect();

    let created_at = chrono::Utc::now().to_rfc3339();
    let file_size = std::fs::metadata(file_path)
        .map(|m| m.len())
        .unwrap_or(0);

    let merkle_json = serde_json::json!({
        "format": "tallow-merkle-v1",
        "file_path": file_path.to_string_lossy(),
        "file_size": file_size,
        "chunk_size": chunk_size,
        "chunk_count": chunk_hashes.len(),
        "root_hash": root_hash,
        "chunk_hashes": chunk_hashes,
        "tree_layers": tree,
        "source_hash": source_hash,
        "algorithm": "blake3",
        "created_at": created_at,
        "verified": true
    });

    let json_str = serde_json::to_string_pretty(&merkle_json).unwrap_or_default();
    std::fs::write(&merkle_path, json_str)
        .with_context(|| format!("cannot write merkle file: {}", merkle_path.display()))?;

    Ok(())
}

// ── Block delta application ──────────────────────────────────────────────

/// Apply a delta payload to a destination file.
///
/// Patches only the changed blocks into the destination file, leaving
/// unchanged blocks untouched. Verifies each written block against its
/// BLAKE3 hash, and verifies the full file hash against the expected
/// merkle_root after application.
pub fn apply_block_delta(dest_path: &Path, delta: &DeltaPayload) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};

    let block_size = delta.block_size;

    // Determine the total file size needed
    let total_size = delta.total_blocks as u64 * block_size as u64;

    // Open destination file for read+write (create if needed)
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dest_path)
        .with_context(|| format!("cannot open dest for delta: {}", dest_path.display()))?;

    // Extend file if needed
    let current_size = file
        .metadata()
        .map(|m| m.len())
        .unwrap_or(0);
    if total_size > current_size {
        file.set_len(total_size)
            .with_context(|| "cannot extend destination file")?;
    }

    // Apply each changed block
    for delta_block in &delta.changed_blocks {
        let offset = delta_block.block_index as u64 * block_size as u64;
        file.seek(SeekFrom::Start(offset))
            .with_context(|| format!("seek failed at block {}", delta_block.block_index))?;

        // Verify the block data before writing
        let actual_hash = blake3::hash(&delta_block.data).to_hex().to_string();
        if actual_hash != delta_block.hash {
            return Err(anyhow::anyhow!(
                "delta block {} hash mismatch: expected {}, got {}",
                delta_block.block_index,
                delta_block.hash,
                actual_hash
            ));
        }

        file.write_all(&delta_block.data)
            .with_context(|| format!("write failed at block {}", delta_block.block_index))?;
    }

    // Verify full file hash
    file.seek(SeekFrom::Start(0))?;
    let mut full_hasher = blake3::Hasher::new();
    let mut verify_buf = vec![0u8; 65536];
    loop {
        let n = file.read(&mut verify_buf)?;
        if n == 0 {
            break;
        }
        full_hasher.update(&verify_buf[..n]);
    }
    let full_hash = full_hasher.finalize().to_hex().to_string();

    // The merkle_root in the delta is the expected BLAKE3 hash of the new file
    if full_hash != delta.new_merkle_root {
        return Err(anyhow::anyhow!(
            "full file hash mismatch after delta: expected {}, got {}",
            delta.new_merkle_root,
            full_hash
        ));
    }

    Ok(())
}

// ── Sync file logic ──────────────────────────────────────────────────────

/// Result of a single file sync operation.
#[derive(Debug, Clone)]
pub struct SyncResult {
    pub strategy: SyncStrategy,
    pub bytes_transferred: u64,
    pub blocks_changed: Option<usize>,
    pub duration_ms: u64,
}

/// AppState reference for the sync executor.
/// Mirrors the actual AppState from main.rs for testability.
pub struct SyncState {
    pub db: Arc<tokio::sync::Mutex<rusqlite::Connection>>,
    pub progress_tx: tokio::sync::broadcast::Sender<ProgressEvent>,
    pub device_id: String,
}

/// Sync a single file for a given sync pair.
///
/// Steps:
/// 1. Compute relative path from sync_pair.source_dir
/// 2. Determine if it's a remove event (delete file_versions row)
/// 3. Read local file metadata and .merkle file
/// 4. Read remote .merkle file from dest_dir
/// 5. Compare Merkle trees, determine strategy
/// 6. Execute WholeFile copy or BlockDelta transfer
/// 7. Update database (file_versions, device state, sync history)
/// 8. Emit SSE progress events
pub async fn sync_file(
    state: &SyncState,
    sync_pair: &SyncPair,
    relative_path: &str,
    event_kind: &str,
) -> Result<SyncResult> {
    let start = Instant::now();

    let source_path = PathBuf::from(&sync_pair.source_dir).join(relative_path);
    let dest_path = PathBuf::from(&sync_pair.dest_dir).join(relative_path);

    // Emit start event
    let _ = state.progress_tx.send(ProgressEvent::SyncFileStarted {
        pair_id: sync_pair.id.clone(),
        relative_path: relative_path.to_string(),
        strategy: "unknown".to_string(),
        file_size: 0,
    });

    // Handle remove events
    if event_kind == "remove" {
        let db = state.db.lock().await;
        let _ = crate::db::insert_sync_history(
            &db,
            &sync_pair.id,
            "file_removed",
            relative_path,
            None,
        );
        // Delete file version entries for this path
        let _ = db.execute(
            "DELETE FROM file_versions WHERE sync_pair_id = ?1 AND relative_path = ?2",
            rusqlite::params![sync_pair.id, relative_path],
        );
        let duration = start.elapsed().as_millis() as u64;
        let _ = state.progress_tx.send(ProgressEvent::SyncFileCompleted {
            pair_id: sync_pair.id.clone(),
            relative_path: relative_path.to_string(),
            strategy: "removed".to_string(),
            bytes_transferred: 0,
            blocks_changed: None,
            duration_ms: duration,
        });
        return Ok(SyncResult {
            strategy: SyncStrategy::WholeFile,
            bytes_transferred: 0,
            blocks_changed: None,
            duration_ms: duration,
        });
    }

    // Read local file metadata
    let metadata = std::fs::metadata(&source_path)
        .with_context(|| format!("cannot stat source: {}", source_path.display()))?;
    let file_size = metadata.len();
    let modified_at = metadata
        .modified()
        .ok()
        .and_then(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| {
                    chrono::DateTime::from_timestamp(d.as_secs() as i64, d.subsec_nanos())
                        .map(|dt| dt.to_rfc3339())
                })
                .flatten()
        })
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

    // Read local .merkle file
    let local_merkle_path = PathBuf::from(format!("{}.merkle", source_path.display()));
    let local_merkle = delta::parse_merkle_file(&local_merkle_path).ok();

    // Read remote .merkle file
    let remote_merkle_path = PathBuf::from(format!("{}.merkle", dest_path.display()));
    let remote_merkle = delta::parse_merkle_file(&remote_merkle_path).ok();

    // Determine strategy
    let (strategy, bytes_transferred, blocks_changed) = if let (Some(local_m), Some(remote_m))
        = (&local_merkle, &remote_merkle)
    {
        // Both have Merkle trees — compare and decide
        let diff = delta::compare_merkle_trees(local_m, remote_m);
        let strategy =
            compute_sync_strategy(file_size, diff.change_ratio);

        match strategy {
            SyncStrategy::BlockDelta => {
                // Read only changed blocks
                let delta_blocks =
                    delta::compute_delta_blocks(&source_path, local_m, &diff.changed_blocks)?;
                let changed_count = delta_blocks.len();
                let new_merkle_root = local_m.merkle_root.clone();
                let payload = delta::assemble_delta_payload(
                    &delta_blocks,
                    relative_path,
                    local_m.total_blocks,
                    local_m.block_size,
                    &new_merkle_root,
                );

                // Apply to destination
                apply_block_delta(&dest_path, &payload)?;

                // Re-write .merkle for destination (matches source after sync)
                copy_with_merkle(&source_path, &dest_path, local_m.block_size)?;

                let total_bytes = delta_blocks.iter().map(|b| b.data.len() as u64).sum();
                (SyncStrategy::BlockDelta, total_bytes, Some(changed_count))
            }
            SyncStrategy::WholeFile => {
                // Whole-file copy
                copy_with_merkle(&source_path, &dest_path, 262144)?;
                (SyncStrategy::WholeFile, file_size, None)
            }
        }
    } else {
        // No Merkle tree available — treat as new file, whole-file copy
        copy_with_merkle(&source_path, &dest_path, 262144)?;
        (SyncStrategy::WholeFile, file_size, None)
    };

    // Update database
    {
        let db = state.db.lock().await;
        let new_version = crate::db::increment_device_version(
            &db,
            &state.device_id,
            &sync_pair.id,
        )?;

        // Compute new Merkle root after sync
        let new_merkle_path = PathBuf::from(format!("{}.merkle", source_path.display()));
        let new_merkle_root = delta::parse_merkle_file(&new_merkle_path)
            .ok()
            .map(|m| m.merkle_root);

        crate::db::upsert_file_version(
            &db,
            &sync_pair.id,
            relative_path,
            &state.device_id,
            new_version as i64,
            new_merkle_root.as_deref(),
            file_size as i64,
            &modified_at,
        )?;

        let detail = format!(
            "strategy={:?} bytes={}",
            strategy, bytes_transferred
        );
        crate::db::insert_sync_history(
            &db,
            &sync_pair.id,
            "file_synced",
            relative_path,
            Some(&detail),
        )?;
    }

    let duration_ms = start.elapsed().as_millis() as u64;

    // Emit completion event
    let _ = state.progress_tx.send(ProgressEvent::SyncFileCompleted {
        pair_id: sync_pair.id.clone(),
        relative_path: relative_path.to_string(),
        strategy: format!("{:?}", strategy).to_lowercase(),
        bytes_transferred,
        blocks_changed,
        duration_ms,
    });

    Ok(SyncResult {
        strategy,
        bytes_transferred,
        blocks_changed,
        duration_ms,
    })
}

// ── File change handler ──────────────────────────────────────────────────

/// In-memory debounce state: tracks the last sync time per file path.
static DEBOUNCE_MAP: std::sync::LazyLock<Mutex<HashMap<String, Instant>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Minimum interval between syncs for the same file (debounce).
const DEBOUNCE_INTERVAL_MS: u64 = 2000;

/// Handle a FileChange event: match against active sync pairs, apply
/// debounce, filter rules, and trigger sync.
pub async fn handle_file_change(
    state: &SyncState,
    path: &str,
    kind: &str,
) -> Result<()> {
    let db = state.db.lock().await;
    let active_pairs = crate::db::list_sync_pairs(&db, Some("active"))?;
    drop(db);

    if active_pairs.is_empty() {
        return Ok(());
    }

    for pair in &active_pairs {
        let source_dir = PathBuf::from(&pair.source_dir);
        let event_path = std::path::absolute(PathBuf::from(path)).unwrap_or_else(|_| PathBuf::from(path));
        let source_abs = std::path::absolute(&source_dir).unwrap_or_else(|_| source_dir.clone());

        // Check if the event path is within the source directory
        if !event_path.starts_with(&source_abs) {
            continue;
        }

        // Compute relative path
        let relative_path = event_path
            .strip_prefix(&source_abs)
            .unwrap_or(Path::new(path))
            .to_string_lossy()
            .to_string();

        if relative_path.is_empty() {
            continue;
        }

        // Apply filter rules from config_json (if present)
        if let Some(config_json) = &pair.config_json {
            if !matches_filter(&relative_path, config_json) {
                tracing::debug!("Filter skipped: {}", relative_path);
                continue;
            }
        }

        // Apply debounce
        {
            let mut map = DEBOUNCE_MAP.lock().await;
            let key = format!("{}:{}", pair.id, relative_path);
            if let Some(last) = map.get(&key) {
                if last.elapsed() < Duration::from_millis(DEBOUNCE_INTERVAL_MS) {
                    tracing::debug!("Debounce skipped: {}", relative_path);
                    continue;
                }
            }
            map.insert(key, Instant::now());
        }

        // Execute sync
        if let Err(e) = sync_file(state, pair, &relative_path, kind).await {
            tracing::error!(
                "Sync failed for {} in pair {}: {:#}",
                relative_path,
                pair.id,
                e
            );
            let _ = state.progress_tx.send(ProgressEvent::SyncFileError {
                pair_id: pair.id.clone(),
                relative_path: relative_path.clone(),
                error: format!("{:#}", e),
            });
        }
    }

    Ok(())
}

/// Simple filter check: parses config_json for include/exclude glob patterns.
/// Returns true if the path passes the filter (should be synced).
fn matches_filter(relative_path: &str, config_json: &str) -> bool {
    // Parse JSON filter config
    let filter: serde_json::Value = match serde_json::from_str(config_json) {
        Ok(v) => v,
        Err(_) => return true, // invalid config → don't filter
    };

    // Check exclude patterns first
    if let Some(excludes) = filter.get("exclude").and_then(|v| v.as_array()) {
        for pattern in excludes {
            if let Some(pat) = pattern.as_str() {
                if simple_glob_match(pat, relative_path) {
                    return false;
                }
            }
        }
    }

    // Check include patterns
    if let Some(includes) = filter.get("include").and_then(|v| v.as_array()) {
        if includes.is_empty() {
            return true;
        }
        for pattern in includes {
            if let Some(pat) = pattern.as_str() {
                if simple_glob_match(pat, relative_path) {
                    return true;
                }
            }
        }
        return false; // didn't match any include pattern
    }

    true // no include patterns → accept all
}

/// Minimal glob-like matching supporting * and ** wildcards.
fn simple_glob_match(pattern: &str, path: &str) -> bool {
    // Convert glob patterns to simple substring/suffix checks
    if pattern == "**" || pattern == "**/**" {
        return true;
    }

    // Handle **/middle/** patterns (globstar in middle)
    // e.g., "**/node_modules/**" matches "src/node_modules/pkg/file.js"
    if let Some(rest) = pattern.strip_prefix("**/") {
        if let Some(middle) = rest.strip_suffix("/**") {
            // Match middle anywhere in the path
            let prefix = format!("/{}", middle);
            let mid = format!("/{}/", middle);
            let suffix = format!("{}/", middle);
            return path == middle
                || path.starts_with(&suffix)
                || path.contains(&mid)
                || path.ends_with(&prefix);
        }
        // Handle **/suffix patterns
        return path == rest || path.ends_with(&format!("/{}", rest));
    }

    // Handle prefix/** patterns
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return path == prefix || path.starts_with(&format!("{}/", prefix));
    }

    // Handle *.ext patterns
    if pattern.starts_with("*.") {
        let ext = &pattern[1..]; // keep the dot
        return path.ends_with(ext);
    }

    // Exact match
    pattern == path
}

// ── Sync executor spawn ──────────────────────────────────────────────────

/// Spawn the sync executor as a background tokio task.
///
/// Listens on the SSE broadcast channel for `FileChange` events, matches
/// them against active sync pairs, and triggers the appropriate sync
/// strategy. Runs until the shutdown signal is received.
pub fn spawn_sync_executor(
    state: SyncState,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut progress_rx = state.progress_tx.subscribe();
        tracing::info!("Sync executor started, listening for FileChange events");

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    tracing::info!("Sync executor shutting down");
                    break;
                }
                event = progress_rx.recv() => {
                    match event {
                        Ok(ProgressEvent::FileChange { path, kind, .. }) => {
                            if let Err(e) = handle_file_change(&state, &path, &kind).await {
                                tracing::error!("handle_file_change error: {:#}", e);
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!("Sync executor lagged by {} messages", n);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            tracing::info!("Progress channel closed, sync executor exiting");
                            break;
                        }
                        _ => {} // ignore non-FileChange events
                    }
                }
            }
        }
    });
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── Test 1: compute_sync_strategy ────────────────────────────────────

    #[test]
    fn test_small_file_always_whole_file() {
        assert_eq!(
            compute_sync_strategy(500 * 1024, 0.9), // 500KB, 90% changed
            SyncStrategy::WholeFile,
            "files under 1MB should always use WholeFile"
        );
        assert_eq!(
            compute_sync_strategy(1024 * 1024 - 1, 0.01), // just under 1MB
            SyncStrategy::WholeFile,
            "files under 1MB should always use WholeFile regardless of change ratio"
        );
    }

    #[test]
    fn test_delta_range_file_with_low_change_ratio() {
        assert_eq!(
            compute_sync_strategy(50_000_000, 0.3), // 50MB, 30% changed
            SyncStrategy::BlockDelta,
            "1MB-100MB with <50% change should use BlockDelta"
        );
        assert_eq!(
            compute_sync_strategy(100_000_000, 0.49), // 100MB, 49% changed
            SyncStrategy::BlockDelta,
            "100MB exactly with <50% change should use BlockDelta"
        );
    }

    #[test]
    fn test_medium_file_with_high_change_ratio_falls_back() {
        assert_eq!(
            compute_sync_strategy(50_000_000, 0.6), // 50MB, 60% changed
            SyncStrategy::WholeFile,
            ">=50% change should use WholeFile even for delta-range size"
        );
        assert_eq!(
            compute_sync_strategy(50_000_000, 0.5), // 50MB, 50% changed
            SyncStrategy::WholeFile,
            "exactly 50% change should use WholeFile"
        );
    }

    #[test]
    fn test_oversized_file_always_whole_file() {
        assert_eq!(
            compute_sync_strategy(200_000_000, 0.2), // 200MB, 20% changed
            SyncStrategy::WholeFile,
            "files > 100MB should use WholeFile (CDC deferred to v2)"
        );
        assert_eq!(
            compute_sync_strategy(150_000_000, 0.01),
            SyncStrategy::WholeFile,
            "files > 100MB even with tiny change should use WholeFile"
        );
    }

    // ── Test 2: apply_block_delta ─────────────────────────────────────────

    #[test]
    fn test_apply_block_delta_patches_changed_blocks() {
        let dir = TempDir::new().unwrap();
        let dest_path = dir.path().join("dest.dat");

        // Create initial destination with known content
        let initial = vec![0u8; BLOCK_SIZE * 4]; // 4 blocks of zeros
        std::fs::write(&dest_path, &initial).unwrap();

        // Create delta payload changing blocks 1 and 3
        let changed_data_1: Vec<u8> = (0..BLOCK_SIZE).map(|i| (i % 256) as u8).collect();
        let changed_data_3: Vec<u8> = (0..BLOCK_SIZE).map(|i| ((i + 100) % 256) as u8).collect();
        let hash_1 = blake3::hash(&changed_data_1).to_hex().to_string();
        let hash_3 = blake3::hash(&changed_data_3).to_hex().to_string();

        // Compute expected full file hash
        let mut expected_data = initial.clone();
        expected_data[BLOCK_SIZE..BLOCK_SIZE * 2].copy_from_slice(&changed_data_1);
        expected_data[BLOCK_SIZE * 3..BLOCK_SIZE * 4].copy_from_slice(&changed_data_3);
        let expected_root = blake3::hash(&expected_data).to_hex().to_string();

        let payload = DeltaPayload {
            file_path: "dest.dat".to_string(),
            total_blocks: 4,
            block_size: BLOCK_SIZE,
            changed_blocks: vec![
                delta::DeltaBlock {
                    block_index: 1,
                    hash: hash_1,
                    data: changed_data_1,
                },
                delta::DeltaBlock {
                    block_index: 3,
                    hash: hash_3,
                    data: changed_data_3,
                },
            ],
            new_merkle_root: expected_root,
        };

        apply_block_delta(&dest_path, &payload).unwrap();

        // Verify: blocks 0 and 2 should be unchanged (zeros)
        let result = std::fs::read(&dest_path).unwrap();
        assert_eq!(result.len(), BLOCK_SIZE * 4);
        assert!(result[..BLOCK_SIZE].iter().all(|&b| b == 0), "block 0 unchanged");
        assert_ne!(result[BLOCK_SIZE..BLOCK_SIZE * 2], vec![0u8; BLOCK_SIZE], "block 1 changed");
        assert!(result[BLOCK_SIZE * 2..BLOCK_SIZE * 3].iter().all(|&b| b == 0), "block 2 unchanged");
        assert_ne!(result[BLOCK_SIZE * 3..], vec![0u8; BLOCK_SIZE], "block 3 changed");
    }

    #[test]
    fn test_apply_block_delta_verifies_hash() {
        let dir = TempDir::new().unwrap();
        let dest_path = dir.path().join("verify.dat");

        // Create initial destination
        let initial = vec![0u8; BLOCK_SIZE * 2];
        std::fs::write(&dest_path, &initial).unwrap();

        // Create payload with wrong hash → should fail
        let bad_data: Vec<u8> = (0..BLOCK_SIZE).map(|i| i as u8).collect();
        let wrong_hash = "badhash".to_string();

        let payload = DeltaPayload {
            file_path: "verify.dat".to_string(),
            total_blocks: 2,
            block_size: BLOCK_SIZE,
            changed_blocks: vec![delta::DeltaBlock {
                block_index: 0,
                hash: wrong_hash,
                data: bad_data,
            }],
            new_merkle_root: "does_not_matter".to_string(),
        };

        let result = apply_block_delta(&dest_path, &payload);
        assert!(result.is_err(), "should fail on hash mismatch");
    }

    // ── Test 3: copy_with_merkle ──────────────────────────────────────────

    #[test]
    fn test_copy_with_merkle_creates_destination_and_merkle_file() {
        let dir = TempDir::new().unwrap();
        let src_path = dir.path().join("src.txt");
        let dst_path = dir.path().join("dst.txt");

        let content = b"Hello, Tallow Copy! This is a test file for merkle verification.".repeat(50);
        std::fs::write(&src_path, &content).unwrap();

        let (_hash, _tree) = copy_with_merkle(&src_path, &dst_path, BLOCK_SIZE / 2).unwrap();

        // Verify destination exists and matches source
        assert!(dst_path.exists());
        let src_bytes = std::fs::read(&src_path).unwrap();
        let dst_bytes = std::fs::read(&dst_path).unwrap();
        assert_eq!(src_bytes, dst_bytes, "destination should match source exactly");

        // Verify .merkle file was created
        let merkle_path = PathBuf::from(format!("{}.merkle", dst_path.display()));
        assert!(merkle_path.exists());

        // Verify .merkle file is valid JSON and parseable
        let merkle = delta::parse_merkle_file(&merkle_path).unwrap();
        assert!(!merkle.merkle_root.is_empty());
        assert!(merkle.total_blocks > 0);
    }

    // ── Test 4: filter matching ───────────────────────────────────────────

    #[test]
    fn test_filter_exclude_pattern() {
        let config = r#"{"exclude": ["*.tmp", "*.log"]}"#;
        assert!(!matches_filter("data.tmp", config), "should exclude .tmp");
        assert!(!matches_filter("debug.log", config), "should exclude .log");
        assert!(matches_filter("data.txt", config), "should include .txt");
        assert!(matches_filter("notes.md", config), "should include .md");
    }

    #[test]
    fn test_filter_include_pattern() {
        let config = r#"{"include": ["*.txt", "*.md"]}"#;
        assert!(matches_filter("readme.txt", config), "should include .txt");
        assert!(matches_filter("notes.md", config), "should include .md");
        assert!(!matches_filter("script.py", config), "should exclude .py");
    }

    #[test]
    fn test_filter_both_include_and_exclude() {
        let config = r#"{"include": ["*.txt", "*.md"], "exclude": ["backup.txt"]}"#;
        assert!(matches_filter("notes.txt", config));
        assert!(!matches_filter("backup.txt", config), "exclude overrides");
        assert!(!matches_filter("script.py", config));
    }

    #[test]
    fn test_filter_deep_path_pattern() {
        let config = r#"{"exclude": ["**/node_modules/**", "**/.git/**"]}"#;
        assert!(!matches_filter("src/node_modules/pkg/file.js", config));
        assert!(!matches_filter(".git/objects/abc", config));
        assert!(matches_filter("src/main.rs", config));
    }

    // ── Test 5: rolling checksum match via delta module ──────────────────

    #[test]
    fn test_rolling_checksum_integration() {
        // Verify the rolling checksum from delta.rs works correctly
        use crate::delta::rolling_checksum_match;

        let window = vec![0xAAu8; delta::BLOCK_SIZE];
        let mut source = vec![0x00u8; 100];
        source.extend_from_slice(&window);
        source.extend_from_slice(&[0x00u8; 100]);

        let offset = rolling_checksum_match(&source, &window);
        assert_eq!(offset, Some(100), "should find the window at offset 100");
    }

    // ── Test 6: write_merkle_file format compatibility ───────────────────

    #[test]
    fn test_merkle_file_round_trip() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("roundtrip.dat");

        let content = b"test content for round trip verification".repeat(20);
        std::fs::write(&file_path, &content).unwrap();

        let (_hash, _tree) = copy_with_merkle(&file_path, &file_path, 4096).unwrap();

        // Parse it back
        let merkle_path = PathBuf::from(format!("{}.merkle", file_path.display()));
        let parsed = delta::parse_merkle_file(&merkle_path).unwrap();

        assert_eq!(parsed.block_size, 4096);
        assert!(parsed.total_blocks > 0);
        assert!(!parsed.merkle_root.is_empty());
        assert_eq!(parsed.chunk_hashes.len(), parsed.total_blocks);
    }

    // ── Test 7: apply_block_delta with file growth ───────────────────────

    #[test]
    fn test_apply_block_delta_file_growth() {
        let dir = TempDir::new().unwrap();
        let dest_path = dir.path().join("grow.dat");

        // Start with a small file (1 block)
        let initial = vec![0u8; BLOCK_SIZE];
        std::fs::write(&dest_path, &initial).unwrap();

        // Create delta that makes it 3 blocks
        let new_block_data: Vec<u8> = (0..BLOCK_SIZE).map(|i| (i % 256) as u8).collect();
        let new_block_hash = blake3::hash(&new_block_data).to_hex().to_string();

        let expected_data: Vec<u8> = {
            let mut d = vec![0u8; BLOCK_SIZE * 3];
            d[..BLOCK_SIZE].copy_from_slice(&initial);
            d[BLOCK_SIZE..BLOCK_SIZE * 2].copy_from_slice(&new_block_data);
            d[BLOCK_SIZE * 2..BLOCK_SIZE * 3].copy_from_slice(&new_block_data);
            d
        };
        let expected_root = blake3::hash(&expected_data).to_hex().to_string();

        let payload = DeltaPayload {
            file_path: "grow.dat".to_string(),
            total_blocks: 3,
            block_size: BLOCK_SIZE,
            changed_blocks: vec![
                delta::DeltaBlock {
                    block_index: 1,
                    hash: new_block_hash.clone(),
                    data: new_block_data.clone(),
                },
                delta::DeltaBlock {
                    block_index: 2,
                    hash: new_block_hash,
                    data: new_block_data,
                },
            ],
            new_merkle_root: expected_root,
        };

        apply_block_delta(&dest_path, &payload).unwrap();

        let result = std::fs::read(&dest_path).unwrap();
        assert_eq!(result.len(), BLOCK_SIZE * 3, "file should have grown to 3 blocks");
    }
}
