//! Test-only helpers shared by the config module's unit tests.
//!
//! Mirrors the repo's temp-dir pattern (`std::env::temp_dir()` + pid-unique
//! names, e.g. `src/logging.rs`), with best-effort cleanup on drop. No test in
//! this module ever touches the real `~/.config/tallow` or
//! `~/.local/state/tallow` paths.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// A uniquely named temp directory, removed on drop (best-effort).
pub(crate) struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create a fresh temp directory tagged for debugging.
    pub(crate) fn new(tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "tallow-config-{}-{tag}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create test temp dir");
        TempDir { path }
    }

    /// The directory path.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// A path inside the directory.
    pub(crate) fn join(&self, rel: &str) -> PathBuf {
        self.path.join(rel)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
