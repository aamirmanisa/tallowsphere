//! Local state: per-recipe scheduling state (`state.json`, atomic writes)
//! and append-only JSONL sinks (`dead-letter.jsonl`, `runs.jsonl`).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Scheduling state of one recipe.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RecipeState {
    /// Last completed run (success or dead-letter) — ms since epoch.
    pub last_run_ms: u64,
    /// Consecutive failures (reset on success).
    pub failures: u32,
    /// Total runs (attempts excluded; one per schedule slot).
    pub runs: u64,
}

/// Whole scheduler state file.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct State {
    pub recipes: BTreeMap<String, RecipeState>,
}

impl State {
    /// Load; a missing file is empty state; corrupt content is an error
    /// (fail-closed — do not silently reschedule everything).
    pub fn load(path: &Path) -> std::io::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("state.json corrupt: {e}"),
                )
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e),
        }
    }

    /// Atomic save (tmp + rename).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

/// Append one JSON value as a JSONL line.
pub fn append_jsonl(path: &Path, value: &serde_json::Value) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{value}")?;
    f.flush()
}
