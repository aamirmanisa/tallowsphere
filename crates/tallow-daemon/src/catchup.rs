//! Offline change detection on daemon restart.
//!
//! When the daemon restarts, it scans watched directories for files modified
//! since the last recorded checkpoint timestamp (mtime-based). Detected
//! changes are emitted as `ProgressEvent::FileChange` with `kind: "catchup"`.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc, TimeZone};
use serde::{Deserialize, Serialize};
use tracing;

use crate::config::Config;
use crate::sse::ProgressEvent;

/// Represents the persistent checkpoint of the last file scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WatchCheckpoint {
    /// ISO 8601 timestamp of the last full scan.
    last_scan: String,
    /// Per-directory timestamps (ISO 8601) for future per-dir optimization.
    dirs: HashMap<String, String>,
}

impl WatchCheckpoint {
    fn new(timestamp: &str) -> Self {
        Self {
            last_scan: timestamp.to_string(),
            dirs: HashMap::new(),
        }
    }
}

/// Scan watched directories for files modified since the last checkpoint.
///
/// Emits `ProgressEvent::FileChange` with `kind: "catchup"` for each
/// detected change. Returns the total number of changes detected.
///
/// If no prior checkpoint exists, all files are treated as changed
/// (epoch timestamp used as baseline).
pub async fn catch_up_changes(
    cfg: &Config,
    progress_tx: &tokio::sync::broadcast::Sender<ProgressEvent>,
) -> usize {
    if cfg.watch_dirs.is_empty() {
        return 0;
    }

    let checkpoint_path = cfg.data_dir.join("watch_checkpoint.json");

    // Load previous checkpoint, or default to epoch if none exists.
    let since = load_since(&checkpoint_path);

    tracing::info!(
        "Starting offline catch-up scan (since: {})",
        since.to_rfc3339()
    );

    let mut total_changed = 0usize;

    for dir in &cfg.watch_dirs {
        if !dir.is_dir() {
            tracing::warn!("Catch-up: skipping non-directory: {}", dir.display());
            continue;
        }

        let changed = scan_dir(dir, since);
        tracing::debug!(
            "Catch-up: {} changed file(s) in {}",
            changed.len(),
            dir.display()
        );

        for path in &changed {
            let event = ProgressEvent::FileChange {
                path: path.to_string_lossy().to_string(),
                kind: "catchup".to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            };

            // Best-effort send — no subscribers is not an error.
            let _ = progress_tx.send(event);
        }

        total_changed += changed.len();
    }

    // Persist updated checkpoint.
    let now = chrono::Utc::now();
    let checkpoint = WatchCheckpoint::new(&now.to_rfc3339());
    if let Err(e) = save_checkpoint(&checkpoint_path, &checkpoint) {
        tracing::warn!("Failed to save watch checkpoint: {}", e);
    }

    if total_changed > 0 {
        tracing::info!("Offline catch-up complete: {} change(s) detected", total_changed);
    } else {
        tracing::debug!("Offline catch-up complete: no changes detected");
    }

    total_changed
}

/// Load the last-scan timestamp from the checkpoint file.
/// Returns epoch (1970-01-01T00:00:00Z) if no checkpoint exists.
fn load_since(checkpoint_path: &Path) -> DateTime<Utc> {
    match fs::read_to_string(checkpoint_path) {
        Ok(contents) => match serde_json::from_str::<WatchCheckpoint>(&contents) {
            Ok(cp) => match DateTime::parse_from_rfc3339(&cp.last_scan) {
                Ok(dt) => dt.with_timezone(&Utc),
                Err(_) => {
                    tracing::warn!("Invalid timestamp in checkpoint, scanning from epoch");
                    Utc.timestamp_millis_opt(0).unwrap()
                }
            },
            Err(e) => {
                tracing::warn!("Corrupted checkpoint file, scanning from epoch: {}", e);
                Utc.timestamp_millis_opt(0).unwrap()
            }
        },
        Err(_) => {
            // No prior checkpoint — first run.
            tracing::debug!("No prior watch checkpoint, scanning from epoch");
            Utc.timestamp_millis_opt(0).unwrap()
        }
    }
}

/// Recursively scan a directory tree for files modified after `since`.
fn scan_dir(dir: &Path, since: DateTime<Utc>) -> Vec<std::path::PathBuf> {
    let mut changed = Vec::new();

    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::debug!("Cannot read directory {}: {}", dir.display(), e);
            return changed;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();

        if path.is_dir() {
            changed.extend(scan_dir(&path, since));
        } else {
            if let Ok(meta) = entry.metadata() {
                if let Ok(modified) = meta.modified() {
                    // Convert SystemTime to chrono::DateTime<Utc>.
                    let duration_since_epoch = modified
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default();
                    let mtime_secs = duration_since_epoch.as_secs() as i64;
                    let mtime_nanos = duration_since_epoch.subsec_nanos();

                    // Use Utc.timestamp_opt (deprecated but available) or Utc.timestamp_nanos.
                    let mtime: DateTime<Utc> = Utc
                        .timestamp_opt(mtime_secs, mtime_nanos)
                        .single()
                        .unwrap_or_else(|| Utc.timestamp_millis_opt(0).unwrap());

                    if mtime > since {
                        changed.push(path);
                    }
                }
            }
        }
    }

    changed
}

/// Write the checkpoint to disk as JSON.
fn save_checkpoint(
    checkpoint_path: &Path,
    checkpoint: &WatchCheckpoint,
) -> Result<(), anyhow::Error> {
    let json = serde_json::to_string_pretty(checkpoint)?;
    fs::write(checkpoint_path, json)?;
    Ok(())
}
