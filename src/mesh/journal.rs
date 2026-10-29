//! Append-only run journal and deterministic replay.
//!
//! A record is one line, `<blake3-hex-16> <json>\n`, where the digest covers the
//! JSON text exactly as written (before the newline). `append` calls
//! `sync_data()` before it returns, so a returned append is a durable append.
//!
//! `open` classifies what it finds, per `docs/spec/JOURNAL-CRASH-SAFETY.md`:
//!
//! - a complete line whose digest matches is a good record and is kept;
//! - a complete line whose digest differs is corruption of committed data and
//!   **refuses** the open, naming the line;
//! - trailing bytes without a newline are a torn tail from a crash and are
//!   **truncated** back to the last good record, reporting the discarded bytes.
//!
//! Truncation happens only at the tail. A torn record in the middle of a file is
//! corruption (a later append was glued onto a partial line), not a crash
//! artifact, and is refused rather than silently discarding history.
//!
//! Journals written before framing carry no digest prefix; those lines are read
//! as *legacy* records without a self-check, counted once, and new appends are
//! framed. The checksum is only claimed for records that carry one.
//!
//! The checkpoint hash of a wave is computed over the wave's committed results
//! **sorted by task id**, so two workers that finish in a different order still
//! produce the same hash — that is the property replay depends on.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::json;

/// Hex characters of BLAKE3 digest kept in the frame prefix (64 bits).
const DIGEST_HEX_LEN: usize = 16;

/// Digest over the JSON text as written, truncated to the frame prefix length.
fn record_digest(json: &str) -> String {
    let hex = blake3::hash(json.as_bytes()).to_hex();
    hex[..DIGEST_HEX_LEN].to_string()
}

/// Split a stored line into `(claimed digest, JSON text)` when it is framed.
/// `None` means the line has no digest prefix — a legacy record.
fn split_frame(line: &str) -> Option<(&str, &str)> {
    if line.len() <= DIGEST_HEX_LEN {
        return None;
    }
    let (prefix, rest) = line.split_at(DIGEST_HEX_LEN);
    if !rest.starts_with(' ') || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some((prefix, &rest[1..]))
}

fn corrupt(lineno: usize, why: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("journal: line {lineno} is corrupt: {why}"),
    )
}

/// Verify one newline-terminated line. A line that neither carries a matching
/// digest nor parses as legacy JSON is corruption, not a torn tail.
fn check_complete_line(line: &str, lineno: usize) -> std::io::Result<bool> {
    match split_frame(line) {
        Some((claimed, json_text)) => {
            let actual = record_digest(json_text);
            if !claimed.eq_ignore_ascii_case(&actual) {
                return Err(corrupt(lineno, "digest mismatch on a committed record"));
            }
            serde_json::from_str::<serde_json::Value>(json_text)
                .map_err(|e| corrupt(lineno, format!("framed record is not JSON: {e}")))?;
            Ok(false)
        }
        None => {
            serde_json::from_str::<serde_json::Value>(line).map_err(|e| {
                corrupt(
                    lineno,
                    format!("neither a framed record nor legacy JSON: {e}"),
                )
            })?;
            Ok(true)
        }
    }
}

/// What recovery found and did.
#[derive(Clone, Copy, Debug, Default)]
struct Recovery {
    legacy: usize,
    discarded: u64,
}

/// Walk the complete lines, verifying each. Returns `(good_len, legacy_count)`.
///
/// Every byte after the last newline is a torn tail by definition: the writer
/// emits the newline last, so a durable record always ends with one.
fn classify(bytes: &[u8]) -> std::io::Result<(usize, usize)> {
    let mut offset = 0usize;
    let mut legacy = 0usize;
    let mut lineno = 0usize;
    while let Some(rel) = bytes[offset..].iter().position(|&b| b == b'\n') {
        let end = offset + rel;
        lineno += 1;
        let line = std::str::from_utf8(&bytes[offset..end])
            .map_err(|e| corrupt(lineno, format!("not UTF-8: {e}")))?;
        if !line.is_empty() && check_complete_line(line, lineno)? {
            legacy += 1;
        }
        offset = end + 1;
    }
    Ok((offset, legacy))
}

/// Classify the existing journal and truncate a torn tail, if any.
fn recover(path: &Path) -> std::io::Result<Recovery> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Recovery::default()),
        Err(e) => return Err(e),
    };
    let (good_len, legacy) = classify(&bytes)?;
    let discarded = (bytes.len() - good_len) as u64;
    if discarded > 0 {
        let file = OpenOptions::new().write(true).open(path)?;
        file.set_len(good_len as u64)?;
        // The size change is file metadata; sync_all covers it where sync_data
        // is only required to cover the data.
        file.sync_all()?;
    }
    Ok(Recovery { legacy, discarded })
}

static SNAPSHOT_SEQ: AtomicU64 = AtomicU64::new(0);

/// Write a snapshot that is rewritten rather than appended (the rotation
/// report) as **temp file → `sync_data` → `rename` → `sync_dir`**, so a reader
/// sees either the old file or the new one and never a half-written one.
///
/// The temp file lives in the destination directory so the rename stays within
/// one filesystem, which is what makes it atomic.
pub fn write_snapshot_atomic(path: impl AsRef<Path>, contents: &[u8]) -> std::io::Result<()> {
    let path = path.as_ref();
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let leaf = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("snapshot path {} has no file name", path.display()),
        )
    })?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(
        ".{}.tmp.{}.{}.{}",
        leaf.to_string_lossy(),
        std::process::id(),
        nanos,
        SNAPSHOT_SEQ.fetch_add(1, Ordering::Relaxed)
    ));

    let write = || -> std::io::Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        file.write_all(contents)?;
        file.sync_data()?;
        drop(file);
        std::fs::rename(&tmp, path)?;
        sync_dir(dir)
    };
    let result = write();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Make the rename durable. Directories cannot be opened as files on Windows,
/// where `rename` over an existing file is already the documented atomic swap.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

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

/// Append-only writer. `append` syncs, because a checkpoint that is still in a
/// buffer, or only in the page cache, when the process dies is not a checkpoint.
pub struct Journal {
    path: PathBuf,
    file: File,
    /// Records read from a pre-framing journal; reported once, unchecked.
    legacy_records: usize,
    /// Torn tail bytes discarded by `open`.
    discarded_bytes: u64,
}

impl Journal {
    /// Open (or create) a journal, recovering a torn tail first.
    ///
    /// A digest mismatch on a complete line is corruption of committed data and
    /// refuses the open, naming the line. A missing final newline — or an
    /// incomplete digest/JSON at the tail — is a crash artifact and is
    /// truncated back to the last good record.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let recovery = recover(&path)?;
        if recovery.discarded > 0 {
            eprintln!(
                "journal {}: discarded {} byte(s) of a torn tail from an interrupted write",
                path.display(),
                recovery.discarded
            );
        }
        if recovery.legacy > 0 {
            eprintln!(
                "journal {}: {} legacy record(s) without a digest prefix (read unchecked)",
                path.display(),
                recovery.legacy
            );
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Journal {
            path,
            file,
            legacy_records: recovery.legacy,
            discarded_bytes: recovery.discarded,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of pre-framing records found at `open`; they carry no self-check.
    pub fn legacy_records(&self) -> usize {
        self.legacy_records
    }

    /// Bytes of a torn tail discarded at `open`. Zero for a clean journal.
    pub fn discarded_bytes(&self) -> u64 {
        self.discarded_bytes
    }

    /// Append one framed record. When this returns `Ok`, the record is on disk.
    pub fn append(&mut self, event: &Event) -> std::io::Result<()> {
        let json_text = event.to_json().to_string();
        let digest = record_digest(&json_text);
        let mut line = String::with_capacity(digest.len() + 1 + json_text.len() + 1);
        line.push_str(&digest);
        line.push(' ');
        line.push_str(&json_text);
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.file.sync_data()
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
        // A framed record carries `<digest> <json>`; verify the digest before
        // trusting the text, then parse the JSON that follows it. A legacy line
        // has no prefix and is parsed as-is.
        let json_text = match split_frame(&line) {
            Some((claimed, json_text)) => {
                if !claimed.eq_ignore_ascii_case(&record_digest(json_text)) {
                    return Err(format!(
                        "replay: line {} is corrupt: digest mismatch on a committed record",
                        lineno + 1
                    ));
                }
                json_text
            }
            None => line.as_str(),
        };
        let v: serde_json::Value = serde_json::from_str(json_text)
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
