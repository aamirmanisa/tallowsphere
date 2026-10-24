//! Append-only run journal and deterministic replay.
//!
//! One JSON object per line. The checkpoint hash of a wave is computed over the
//! wave's committed results **sorted by task id**, so two workers that finish in
//! a different order still produce the same hash — that is the property replay
//! depends on.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde_json::json;

/// One journal line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    RunStarted { run_id: String, mesh_seed: u64, tasks: usize },
    WaveStarted { wave: usize, seed: u64 },
    TaskCommitted { wave: usize, task: String, result_hash: String },
    /// What a model was asked and what it answered. `response` is `None` for a
    /// private data class: the hashes are still recorded, the text is not, and
    /// replay refuses the run rather than pretending it can reproduce it.
    LlmRecorded {
        wave: usize,
        task: String,
        model: String,
        prompt_hash: String,
        response_hash: String,
        response: Option<String>,
        data_class: String,
    },
    TaskRetried { wave: usize, task: String, attempt: u32, reason: String },
    TaskFailed { wave: usize, task: String, reason: String },
    InjectApplied { wave: usize, key: String, value: String },
    WaveEnded { wave: usize, checkpoint: String },
    RunStopped { drained: bool },
}

impl Event {
    fn to_json(&self) -> serde_json::Value {
        match self {
            Event::RunStarted { run_id, mesh_seed, tasks } => json!({
                "kind": "run_started", "run_id": run_id, "mesh_seed": mesh_seed, "tasks": tasks
            }),
            Event::WaveStarted { wave, seed } => json!({
                "kind": "wave_started", "wave": wave, "seed": seed
            }),
            Event::TaskCommitted { wave, task, result_hash } => json!({
                "kind": "task_committed", "wave": wave, "task": task, "hash": result_hash
            }),
            Event::LlmRecorded { wave, task, model, prompt_hash, response_hash, response, data_class } => json!({
                "kind": "llm_recorded", "wave": wave, "task": task, "model": model,
                "prompt_hash": prompt_hash, "response_hash": response_hash,
                "response": response, "data_class": data_class
            }),
            Event::TaskRetried { wave, task, attempt, reason } => json!({
                "kind": "task_retried", "wave": wave, "task": task, "attempt": attempt, "reason": reason
            }),
            Event::TaskFailed { wave, task, reason } => json!({
                "kind": "task_failed", "wave": wave, "task": task, "reason": reason
            }),
            Event::InjectApplied { wave, key, value } => json!({
                "kind": "inject_applied", "wave": wave, "key": key, "value": value
            }),
            Event::WaveEnded { wave, checkpoint } => json!({
                "kind": "wave_ended", "wave": wave, "checkpoint": checkpoint
            }),
            Event::RunStopped { drained } => json!({
                "kind": "run_stopped", "drained": drained
            }),
        }
    }
}

/// Append-only writer. `append` flushes, because a checkpoint that is still in
/// a buffer when the process dies is not a checkpoint.
pub struct Journal {
    path: PathBuf,
    file: File,
}

impl Journal {
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Journal { path, file })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&mut self, event: &Event) -> std::io::Result<()> {
        let line = event.to_json().to_string();
        writeln!(self.file, "{line}")?;
        self.file.flush()
    }
}

/// Hash of a wave's results. Order-independent by construction.
pub fn checkpoint_hash(results: &[(String, String)]) -> String {
    let mut sorted: BTreeMap<&str, &str> = BTreeMap::new();
    for (task, hash) in results {
        sorted.insert(task.as_str(), hash.as_str());
    }
    let mut hasher = blake3::Hasher::new();
    for (task, hash) in sorted {
        hasher.update(task.as_bytes());
        hasher.update(&[0u8]);
        hasher.update(hash.as_bytes());
        hasher.update(b"\n");
    }
    hasher.finalize().to_hex().to_string()
}

/// Replay outcome for one wave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayedWave {
    pub wave: usize,
    pub checkpoint: String,
    pub tasks: usize,
}

/// Recompute every checkpoint from the journal's own committed results and
/// compare it with what was recorded. Returns the first mismatch as an error,
/// naming the wave — a replay that "mostly" matches is a failed replay.
pub fn replay(path: impl AsRef<Path>) -> Result<Vec<ReplayedWave>, String> {
    let file = File::open(path.as_ref())
        .map_err(|e| format!("replay: cannot open {}: {e}", path.as_ref().display()))?;
    let reader = BufReader::new(file);

    let mut current: Option<usize> = None;
    let mut results: Vec<(String, String)> = Vec::new();
    let mut out: Vec<ReplayedWave> = Vec::new();

    for (lineno, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("replay: line {}: {e}", lineno + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(&line)
            .map_err(|e| format!("replay: line {} is not JSON: {e}", lineno + 1))?;
        let kind = v["kind"].as_str().unwrap_or("");
        match kind {
            "wave_started" => {
                current = Some(v["wave"].as_u64().unwrap_or(0) as usize);
                results.clear();
            }
            "llm_recorded" => {
                // A private-class run has hashes but no text. Replay cannot
                // reproduce a model answer without the text it was given, and
                // pretending otherwise would be the simulation this plane
                // exists to rule out.
                if v["data_class"].as_str().unwrap_or("public") == "private" {
                    return Err(format!(
                        "replay: non-replayable: private data class at line {}",
                        lineno + 1
                    ));
                }
            }
            "task_committed" => {
                results.push((
                    v["task"].as_str().unwrap_or("").to_string(),
                    v["hash"].as_str().unwrap_or("").to_string(),
                ));
            }
            "wave_ended" => {
                let wave = v["wave"].as_u64().unwrap_or(0) as usize;
                let recorded = v["checkpoint"].as_str().unwrap_or("");
                let recomputed = checkpoint_hash(&results);
                if recorded != recomputed {
                    return Err(format!(
                        "replay: wave {wave} mismatch — journal says {recorded}, results hash to {recomputed}"
                    ));
                }
                out.push(ReplayedWave {
                    wave,
                    checkpoint: recorded.to_string(),
                    tasks: results.len(),
                });
                current = None;
                results.clear();
            }
            _ => {}
        }
    }

    if current.is_some() {
        return Err(format!(
            "replay: journal ends inside wave {} — no checkpoint to compare",
            current.unwrap_or(0)
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "tallow-mesh-{}-{}-{name}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        p
    }

    #[test]
    fn checkpoint_hash_is_order_independent() {
        let a = vec![
            ("t1".to_string(), "h1".to_string()),
            ("t2".to_string(), "h2".to_string()),
        ];
        let b = vec![
            ("t2".to_string(), "h2".to_string()),
            ("t1".to_string(), "h1".to_string()),
        ];
        assert_eq!(checkpoint_hash(&a), checkpoint_hash(&b));
        let c = vec![
            ("t1".to_string(), "h1".to_string()),
            ("t2".to_string(), "CHANGED".to_string()),
        ];
        assert_ne!(checkpoint_hash(&a), checkpoint_hash(&c));
    }

    #[test]
    fn journal_round_trips_and_replays() {
        let path = temp_path("roundtrip");
        let mut j = Journal::open(&path).expect("open");
        j.append(&Event::RunStarted {
            run_id: "r1".into(),
            mesh_seed: 42,
            tasks: 2,
        })
        .unwrap();
        j.append(&Event::WaveStarted { wave: 0, seed: 9 }).unwrap();
        j.append(&Event::TaskCommitted {
            wave: 0,
            task: "a".into(),
            result_hash: "ha".into(),
        })
        .unwrap();
        j.append(&Event::TaskCommitted {
            wave: 0,
            task: "b".into(),
            result_hash: "hb".into(),
        })
        .unwrap();
        let cp = checkpoint_hash(&[("a".into(), "ha".into()), ("b".into(), "hb".into())]);
        j.append(&Event::WaveEnded {
            wave: 0,
            checkpoint: cp.clone(),
        })
        .unwrap();
        drop(j);

        let waves = replay(&path).expect("replay");
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0].checkpoint, cp);
        assert_eq!(waves[0].tasks, 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn replay_names_the_mismatching_wave() {
        let path = temp_path("mismatch");
        let mut j = Journal::open(&path).expect("open");
        j.append(&Event::WaveStarted { wave: 3, seed: 1 }).unwrap();
        j.append(&Event::TaskCommitted {
            wave: 3,
            task: "a".into(),
            result_hash: "real".into(),
        })
        .unwrap();
        j.append(&Event::WaveEnded {
            wave: 3,
            checkpoint: "believed".into(),
        })
        .unwrap();
        drop(j);

        let err = replay(&path).expect_err("mismatch must be refused");
        assert!(err.contains("wave 3"), "{err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn truncated_journal_is_refused() {
        let path = temp_path("truncated");
        let mut j = Journal::open(&path).expect("open");
        j.append(&Event::WaveStarted { wave: 0, seed: 1 }).unwrap();
        j.append(&Event::TaskCommitted {
            wave: 0,
            task: "a".into(),
            result_hash: "h".into(),
        })
        .unwrap();
        drop(j);
        let err = replay(&path).expect_err("unterminated wave must be refused");
        assert!(err.contains("ends inside wave"), "{err}");
        let _ = std::fs::remove_file(&path);
    }
}
