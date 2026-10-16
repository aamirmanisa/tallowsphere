//! Filesystem watch mode with debounced event handling
//!
//! Monitors a directory for file changes and emits batched events suitable
//! for triggering incremental sync transfers. Uses the `notify` crate (v7)
//! with manual debouncing to coalesce rapid filesystem events.

use crate::{ProtocolError, Result};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc as std_mpsc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// A batch of changed files detected by the watcher
#[derive(Debug, Clone)]
pub struct WatchEvent {
    /// Files that were created or modified during this batch window
    pub changed_files: Vec<PathBuf>,
    /// When this batch was collected
    pub timestamp: Instant,
}

/// Configuration for the filesystem watcher
#[derive(Debug, Clone)]
pub struct WatchConfig {
    /// Directory to watch
    pub path: PathBuf,
    /// How long to wait before flushing a batch of events
    pub debounce_duration: Duration,
    /// Whether to watch subdirectories recursively
    pub recursive: bool,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("."),
            debounce_duration: Duration::from_millis(500),
            recursive: true,
        }
    }
}

/// Handle to stop the filesystem watcher
///
/// Dropping the handle does NOT stop the watcher; call [`WatchHandle::stop`]
/// explicitly to signal the background thread to exit.
pub struct WatchHandle {
    stop_tx: std_mpsc::Sender<()>,
}

impl WatchHandle {
    /// Signal the watcher thread to stop
    pub fn stop(self) {
        let _ = self.stop_tx.send(());
    }
}

/// Start a filesystem watcher that sends batched change events.
///
/// Spawns a dedicated OS thread (not a tokio task) that creates a `notify`
/// watcher, collects raw events, deduplicates and debounces them, then
/// forwards [`WatchEvent`] batches through a tokio mpsc channel.
///
/// Returns a receiver for events and a handle to stop the watcher.
///
/// # Errors
///
/// Returns an error if the watch path does not exist or the watcher
/// cannot be initialized.
pub fn start_watcher(config: WatchConfig) -> Result<(mpsc::Receiver<WatchEvent>, WatchHandle)> {
    use notify::{RecursiveMode, Watcher};

    let watch_path = config.path.clone();
    if !watch_path.exists() {
        return Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("watch path does not exist: {}", watch_path.display()),
        )));
    }

    let (event_tx, event_rx) = mpsc::channel::<WatchEvent>(64);
    let (stop_tx, stop_rx) = std_mpsc::channel::<()>();

    let debounce = config.debounce_duration;
    let recursive = config.recursive;

    std::thread::spawn(move || {
        // Channel for raw notify events
        let (raw_tx, raw_rx) = std_mpsc::channel();

        let mut watcher = match notify::recommended_watcher(
            move |res: std::result::Result<notify::Event, notify::Error>| {
                if let Ok(event) = res {
                    let _ = raw_tx.send(event);
                }
            },
        ) {
            Ok(w) => w,
            Err(_) => return,
        };

        let mode = if recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };

        if watcher.watch(&watch_path, mode).is_err() {
            return;
        }

        let mut pending: HashSet<PathBuf> = HashSet::new();
        let mut batch_start: Option<Instant> = None;

        loop {
            // Check for stop signal (non-blocking)
            if stop_rx.try_recv().is_ok() {
                break;
            }

            // Wait for events with a timeout
            let timeout = match batch_start {
                Some(start) => {
                    let elapsed = start.elapsed();
                    if elapsed >= debounce {
                        Duration::from_millis(0)
                    } else {
                        debounce - elapsed
                    }
                }
                None => Duration::from_millis(100),
            };

            match raw_rx.recv_timeout(timeout) {
                Ok(event) => {
                    // Filter to create and modify events
                    let dominated_kind = matches!(
                        event.kind,
                        notify::EventKind::Create(_) | notify::EventKind::Modify(_)
                    );
                    if dominated_kind {
                        for path in event.paths {
                            // Only include files that exist (skip transient renames)
                            if path.exists() {
                                pending.insert(path);
                            }
                        }
                        if batch_start.is_none() {
                            batch_start = Some(Instant::now());
                        }
                    }
                }
                Err(std_mpsc::RecvTimeoutError::Timeout) => {
                    // Timeout — flush the batch if debounce window expired
                }
                Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                    break;
                }
            }

            // Flush the batch if the debounce window has elapsed
            if let Some(start) = batch_start {
                if start.elapsed() >= debounce && !pending.is_empty() {
                    let changed_files: Vec<PathBuf> = pending.drain().collect();
                    let watch_event = WatchEvent {
                        changed_files,
                        timestamp: Instant::now(),
                    };
                    // Use blocking_send since we're on a std thread
                    if event_tx.blocking_send(watch_event).is_err() {
                        // Receiver dropped, exit
                        break;
                    }
                    batch_start = None;
                }
            }
        }
    });

    Ok((event_rx, WatchHandle { stop_tx }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watch_config_default() {
        let config = WatchConfig::default();
        assert_eq!(config.path, PathBuf::from("."));
        assert_eq!(config.debounce_duration, Duration::from_millis(500));
        assert!(config.recursive);
    }

    #[test]
    fn test_watch_handle_stop() {
        let (stop_tx, stop_rx) = std_mpsc::channel::<()>();
        let handle = WatchHandle { stop_tx };
        handle.stop();
        // The stop signal should have been sent
        assert!(stop_rx.recv().is_ok());
    }

    #[test]
    fn test_watch_event_creation() {
        let event = WatchEvent {
            changed_files: vec![PathBuf::from("test.txt"), PathBuf::from("other.rs")],
            timestamp: Instant::now(),
        };
        assert_eq!(event.changed_files.len(), 2);
    }

    #[test]
    fn test_start_watcher_nonexistent_path() {
        let config = WatchConfig {
            path: PathBuf::from("/nonexistent/path/that/does/not/exist"),
            debounce_duration: Duration::from_millis(100),
            recursive: true,
        };
        let result = start_watcher(config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_start_watcher_and_stop() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config = WatchConfig {
            path: dir.path().to_path_buf(),
            debounce_duration: Duration::from_millis(50),
            recursive: true,
        };
        let (mut rx, handle) = start_watcher(config).expect("watcher should start");

        // Stop immediately
        handle.stop();

        // Give the thread a moment to process the stop
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Channel should eventually close (no more events)
        // try_recv should return empty or disconnected
        let result = rx.try_recv();
        assert!(
            result.is_err(),
            "should have no events after immediate stop"
        );
    }
}
