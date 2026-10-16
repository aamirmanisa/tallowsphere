//! Real-time filesystem watcher using notify-debouncer-full.
//!
//! Watches configured directories for create/modify/delete events,
//! coalesces rapid changes with configurable per-file debounce, and
//! emits `ProgressEvent::FileChange` events via the SSE broadcast channel.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use notify::RecursiveMode;
use notify_debouncer_full::{new_debouncer, DebouncedEvent};
use tracing;

use crate::config::Config;
use crate::sse::ProgressEvent;

/// Spawn the filesystem watcher as a background tokio task.
///
/// The watcher monitors `cfg.watch_dirs` for filesystem events using
/// `notify-debouncer-full` with configurable debounce timeouts. Detected
/// changes are emitted as `ProgressEvent::FileChange` via the provided
/// broadcast channel. The watcher runs until the shutdown signal is received.
///
/// If `watch_dirs` is empty, this function is a no-op (logs and returns).
pub fn spawn_watcher(
    cfg: &Config,
    progress_tx: tokio::sync::broadcast::Sender<ProgressEvent>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    if cfg.watch_dirs.is_empty() {
        tracing::info!("No watch directories configured; watcher disabled");
        return;
    }

    // Debouncer timeout: use the smaller default debounce for instant
    // notifications, but track large-file emits separately for extended debounce.
    let debounce_timeout = Duration::from_millis(cfg.debounce_delay_ms);

    // Create the debouncer with a blocking mpsc channel for event delivery.
    let (tx, rx) = mpsc::channel();

    let mut debouncer = match new_debouncer(
        debounce_timeout,
        None,
        tx,
    ) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("Failed to create filesystem debouncer: {}", e);
            return;
        }
    };

    // Watch all configured directories recursively.
    for dir in &cfg.watch_dirs {
        if dir.is_dir() {
            match debouncer.watch(dir, RecursiveMode::Recursive) {
                Ok(()) => tracing::info!("Watching directory: {}", dir.display()),
                Err(e) => tracing::warn!("Failed to watch {}: {}", dir.display(), e),
            }
        } else {
            tracing::warn!("Watch dir is not a directory: {}", dir.display());
        }
    }

    let large_threshold = cfg.large_file_threshold_bytes;
    let large_debounce = Duration::from_millis(cfg.debounce_large_file_ms);
    let small_debounce = debounce_timeout;

    // Wrap receiver in Arc<Mutex<>> so it can be shared across spawn_blocking calls.
    let rx = Arc::new(Mutex::new(rx));

    // Spawn a tokio task that polls the mpsc receiver for debounced events.
    tokio::spawn(async move {
        // Track last-emit time per path for large-file extended debounce.
        let mut last_emit_times: HashMap<PathBuf, Instant> = HashMap::new();

        loop {
            // Check shutdown signal first (non-blocking).
            if shutdown_rx.has_changed().unwrap_or(false) {
                tracing::info!("Watcher shutting down");
                break;
            }

            // Poll the blocking receiver with a short timeout using spawn_blocking.
            let rx_clone = rx.clone();
            let recv_result = tokio::task::spawn_blocking(move || {
                rx_clone.lock().unwrap().recv_timeout(Duration::from_millis(250))
            })
            .await;

            // Unwrap spawn_blocking result, then handle recv result.
            // Channel type is Result<Vec<DebouncedEvent>, Vec<notify::Error>>
            // so we need three levels of unwrap: spawn_blocking → recv_timeout → debounce result.
            let events: Vec<DebouncedEvent> = match recv_result {
                Ok(Ok(Ok(events))) => events,
                Ok(Ok(Err(errs))) => {
                    tracing::warn!("Debounce errors ({} events dropped): {:?}", errs.len(), errs.first());
                    continue;
                }
                Ok(Err(mpsc::RecvTimeoutError::Timeout)) => continue,
                Ok(Err(mpsc::RecvTimeoutError::Disconnected)) => {
                    tracing::debug!("Watcher event channel closed");
                    break;
                }
                Err(_) => {
                    tracing::debug!("Watcher event channel closed (join error)");
                    break;
                }
            };

            // Process each debounced event.
            for event in &events {
                handle_event(
                    event,
                    &progress_tx,
                    &mut last_emit_times,
                    small_debounce,
                    large_debounce,
                    large_threshold,
                );
            }
        }

        // debouncer dropped here, stopping the underlying OS watcher.
        tracing::info!("Watcher stopped");
    });
}

/// Map a debounced filesystem event to a human-readable kind string.
fn kind_to_str(kind: &notify::EventKind) -> &'static str {
    use notify::event::*;

    match kind {
        EventKind::Create(_) => "create",
        EventKind::Modify(_) => "modify",
        EventKind::Remove(_) => "remove",
        EventKind::Access(_) => "access",
        EventKind::Other => "other",
        EventKind::Any => "any",
    }
}

/// Extract the main path from a debounced event.
fn event_path(event: &DebouncedEvent) -> Option<&std::path::Path> {
    event.paths.first().map(|p| p.as_path())
}

/// Process a single debounced event: apply large-file extra debounce,
/// map to a ProgressEvent::FileChange, and broadcast via SSE.
fn handle_event(
    event: &DebouncedEvent,
    progress_tx: &tokio::sync::broadcast::Sender<ProgressEvent>,
    last_emit_times: &mut HashMap<PathBuf, Instant>,
    _small_debounce: Duration,
    large_debounce: Duration,
    large_threshold: u64,
) {
    let Some(path) = event_path(event) else {
        return;
    };

    let now = Instant::now();
    let kind_str = kind_to_str(&event.kind);

    // For Modify events on large files, apply extended debounce window.
    if matches!(event.kind, notify::EventKind::Modify(_)) {
        // Check if the file is large (best-effort — metadata failure = not large).
        let is_large = std::fs::metadata(path)
            .ok()
            .map(|m| m.len() > large_threshold)
            .unwrap_or(false);

        if is_large {
            if let Some(last_emit) = last_emit_times.get(path) {
                if now.duration_since(*last_emit) < large_debounce {
                    // Still within the large-file debounce window — suppress.
                    tracing::debug!(
                        "Suppressed large-file event for {} (within {}ms debounce)",
                        path.display(),
                        large_debounce.as_millis()
                    );
                    return;
                }
            }
        }
    }

    // Update last-emit time for this path.
    last_emit_times.insert(path.to_path_buf(), now);

    // Prune stale entries from the last_emit_times map periodically
    // to prevent unbounded memory growth. Prune entries older than
    // 2x the large debounce window.
    if last_emit_times.len() > 1000 {
        let prune_before = now.checked_sub(large_debounce * 2).unwrap_or(now);
        last_emit_times.retain(|_, t| *t >= prune_before);
    }

    // Build and send the FileChange event.
    let event = ProgressEvent::FileChange {
        path: path.to_string_lossy().to_string(),
        kind: kind_str.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    if let Err(e) = progress_tx.send(event) {
        // No active SSE subscribers — this is normal.
        tracing::debug!("No SSE subscribers for file change event: {}", e);
    }
}
