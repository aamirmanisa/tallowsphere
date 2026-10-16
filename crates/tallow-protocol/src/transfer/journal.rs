//! Delta-sync journal (design `cycle-02/09-transfer-design.md` §3.2)
//!
//! Per-file checkpoint for `tallow delta-sync`: crash resume + a skip signal
//! that survives copy-side mtime drift (local copies do not preserve mtime, so
//! the target-cache mtime check alone re-copies everything on every run).
//!
//! Journal file (one per source/target pair):
//!   `<journal-dir>/run-<blake3(canonical source‖target)[..12]>.postcard`
//! Default journal dir: `<target>/.tallow-journal/`. Postcard payload:
//!
//! ```text
//! { magic:"TRSJ", ver:1, source, target,
//!   entries: [ { rel_path, size, mtime, src_blake3:Option<[u8;32]>,
//!                status: Pending|Committed|Failed, ts } ] }
//! ```
//!
//! The journal is advisory: it is written atomically (tmp + fsync + rename +
//! dir fsync), a corrupt journal is ignored with a warning (full sync, never a
//! failed run), and `--no-resume` disables it. The completion gate for any
//! individual file stays the copy itself (plus `--verify`'s BLAKE3 check).

use crate::{ProtocolError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Magic for the delta-sync journal file.
pub const JOURNAL_MAGIC: [u8; 4] = *b"TRSJ";
/// Journal format version.
pub const JOURNAL_VERSION: u8 = 1;
/// Default batch flush cadence: every N updated entries…
pub const DEFAULT_FLUSH_ENTRIES: usize = 256;
/// …or every N seconds, whichever comes first (design §3.2).
pub const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(10);

/// Per-file status in the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JournalEntryStatus {
    /// Copy started but not confirmed (a crash candidate: re-copy on load).
    Pending,
    /// Copy finished (and `--verify` passed, when enabled): skip when the
    /// recorded source revision still matches.
    Committed,
    /// Copy failed after the retry budget: re-copy on the next run.
    Failed,
}

/// One file entry in the journal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Path relative to the sync source root.
    pub rel_path: String,
    /// Source size at the recorded revision.
    pub size: u64,
    /// Source mtime (unix seconds) at the recorded revision.
    pub mtime: u64,
    /// Source BLAKE3 when known (`--verify` runs record it).
    pub src_blake3: Option<[u8; 32]>,
    /// Last known status.
    pub status: JournalEntryStatus,
    /// Unix seconds of the last update to this entry.
    pub ts: u64,
}

/// Serialized journal (design §3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaSyncJournal {
    /// Magic `TRSJ`.
    pub magic: [u8; 4],
    /// Format version.
    pub ver: u8,
    /// Source root as passed on the command line.
    pub source: String,
    /// Target root as passed on the command line.
    pub target: String,
    /// Per-file entries.
    pub entries: Vec<JournalEntry>,
}

/// Journal consult result for one file (design §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalDecision {
    /// A `Committed` entry attests the target already holds this exact source
    /// revision — skip even when the target-cache mtime check misses.
    Skip,
    /// The previous run was interrupted while copying this file — re-copy
    /// regardless of what the target looks like.
    Recopy,
}

/// Pure consult for one file (design §3.2).
///
/// - `Committed` + size/mtime match ⇒ [`JournalDecision::Skip`], but only when
///   the target file is present and size-identical (a missing or size-diverged
///   target falls back to the caller's own check);
/// - `Pending` from a previous run ⇒ [`JournalDecision::Recopy`];
/// - `Failed`, a stale source revision, or no entry ⇒ `None` (no opinion).
pub fn consult(
    entry: Option<&JournalEntry>,
    src_size: u64,
    src_mtime: u64,
    target: Option<(u64, u64)>,
) -> Option<JournalDecision> {
    let e = entry?;
    match e.status {
        JournalEntryStatus::Pending => Some(JournalDecision::Recopy),
        JournalEntryStatus::Committed => {
            if e.size == src_size && e.mtime == src_mtime {
                match target {
                    // Target present with the expected size ⇒ nothing to do.
                    Some((dst_size, _)) if dst_size == src_size => Some(JournalDecision::Skip),
                    _ => None,
                }
            } else {
                None
            }
        }
        JournalEntryStatus::Failed => None,
    }
}

/// Journal file name for a source/target pair:
/// `run-<blake3(source‖target)[..12]>.postcard` (design §3.2).
///
/// Paths are canonicalized when they exist (falling back to an absolute-ized
/// form) so the same pair always maps to the same journal.
pub fn journal_file_name(source: &Path, target: &Path) -> String {
    let src = canon_or_abs(source);
    let dst = canon_or_abs(target);
    let mut hasher = blake3::Hasher::new();
    hasher.update(src.to_string_lossy().as_bytes());
    // Separator: ("…/ab", "…/c") must not collide with ("…/a", "…/bc").
    hasher.update(&[0u8]);
    hasher.update(dst.to_string_lossy().as_bytes());
    let hex = hasher.finalize().to_hex();
    format!("run-{}.postcard", &hex[..12])
}

fn canon_or_abs(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| {
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|c| c.join(p))
                .unwrap_or_else(|_| p.to_path_buf())
        }
    })
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl DeltaSyncJournal {
    /// Fresh empty journal for a source/target pair.
    pub fn new(source: &str, target: &str) -> Self {
        Self {
            magic: JOURNAL_MAGIC,
            ver: JOURNAL_VERSION,
            source: source.to_string(),
            target: target.to_string(),
            entries: Vec::new(),
        }
    }

    /// Encode with postcard.
    pub fn encode(&self) -> Result<Vec<u8>> {
        postcard::to_stdvec(self)
            .map_err(|e| ProtocolError::EncodingError(format!("delta-sync journal encode: {e}")))
    }

    /// Decode + validate magic/version.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let journal: Self = postcard::from_bytes(data)
            .map_err(|e| ProtocolError::DecodingError(format!("delta-sync journal decode: {e}")))?;
        if journal.magic != JOURNAL_MAGIC {
            return Err(ProtocolError::InvalidMessage(
                "delta-sync journal: bad magic".to_string(),
            ));
        }
        if journal.ver != JOURNAL_VERSION {
            return Err(ProtocolError::VersionMismatch {
                local: JOURNAL_VERSION as u32,
                remote: journal.ver as u32,
            });
        }
        Ok(journal)
    }

    /// Atomically persist to `path` (tmp + fsync + rename + dir fsync).
    pub fn save_atomic(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ProtocolError::Io(std::io::Error::new(
                    e.kind(),
                    format!("create journal dir '{}': {e}", parent.display()),
                ))
            })?;
        }
        let bytes = self.encode()?;
        let tmp = path.with_extension("postcard.tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        if let Some(parent) = path.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    /// Load + validate a journal from `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        Self::decode(&bytes)
    }

    /// Linear lookup by relative path (the writer keeps an index for hot use).
    pub fn entry(&self, rel_path: &str) -> Option<&JournalEntry> {
        self.entries.iter().find(|e| e.rel_path == rel_path)
    }
}

/// In-memory journal with batched persistence, used by the `delta-sync` arm.
///
/// Updates are advisory: callers warn on errors and continue (a broken journal
/// must never fail a sync). Flushes happen every `flush_entries` updates or
/// every `flush_interval`, plus one explicit final flush by the caller.
pub struct JournalWriter {
    journal: DeltaSyncJournal,
    path: PathBuf,
    index: HashMap<String, usize>,
    dirty: usize,
    last_flush: Instant,
    flush_entries: usize,
    flush_interval: Duration,
}

impl JournalWriter {
    /// Open the journal at `path`, loading the previous run's state when
    /// present. A missing journal starts fresh silently; a corrupt journal (or
    /// one recorded for a different source/target pair) is discarded with a
    /// warning so the caller can do a full sync — never an error.
    pub fn open(path: &Path, source: &str, target: &str) -> (Self, Option<String>) {
        let mut warning: Option<String> = None;
        let journal = match std::fs::read(path) {
            Ok(bytes) => match DeltaSyncJournal::decode(&bytes) {
                Ok(j) if j.source == source && j.target == target => j,
                Ok(j) => {
                    warning = Some(format!(
                        "delta-sync journal {} is for a different source/target ({} -> {}); starting a full sync",
                        path.display(),
                        j.source,
                        j.target
                    ));
                    DeltaSyncJournal::new(source, target)
                }
                Err(e) => {
                    warning = Some(format!(
                        "corrupt delta-sync journal {} ({e}); starting a full sync",
                        path.display()
                    ));
                    DeltaSyncJournal::new(source, target)
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                DeltaSyncJournal::new(source, target)
            }
            Err(e) => {
                warning = Some(format!(
                    "cannot read delta-sync journal {} ({e}); starting a full sync",
                    path.display()
                ));
                DeltaSyncJournal::new(source, target)
            }
        };
        let index = journal
            .entries
            .iter()
            .enumerate()
            .map(|(i, e)| (e.rel_path.clone(), i))
            .collect();
        (
            Self {
                journal,
                path: path.to_path_buf(),
                index,
                dirty: 0,
                last_flush: Instant::now(),
                flush_entries: DEFAULT_FLUSH_ENTRIES,
                flush_interval: DEFAULT_FLUSH_INTERVAL,
            },
            warning,
        )
    }

    /// Test hook: override the batch flush cadence.
    pub fn set_flush_policy(&mut self, entries: usize, interval: Duration) {
        self.flush_entries = entries.max(1);
        self.flush_interval = interval;
    }

    /// Consult the journal for one file (see [`consult`]).
    pub fn consult(
        &self,
        rel_path: &str,
        src_size: u64,
        src_mtime: u64,
        target: Option<(u64, u64)>,
    ) -> Option<JournalDecision> {
        let entry = self.index.get(rel_path).map(|&i| &self.journal.entries[i]);
        consult(entry, src_size, src_mtime, target)
    }

    /// Record that a copy is about to start (crash candidate).
    pub fn mark_pending(&mut self, rel_path: &str, size: u64, mtime: u64) -> Result<()> {
        self.upsert(rel_path, size, mtime, None, JournalEntryStatus::Pending);
        self.maybe_flush()
    }

    /// Record a successful copy (and `--verify` pass, when enabled).
    pub fn mark_committed(
        &mut self,
        rel_path: &str,
        size: u64,
        mtime: u64,
        src_blake3: Option<[u8; 32]>,
    ) -> Result<()> {
        self.upsert(
            rel_path,
            size,
            mtime,
            src_blake3,
            JournalEntryStatus::Committed,
        );
        self.maybe_flush()
    }

    /// Record a copy that failed after its retry budget.
    pub fn mark_failed(&mut self, rel_path: &str, size: u64, mtime: u64) -> Result<()> {
        self.upsert(rel_path, size, mtime, None, JournalEntryStatus::Failed);
        self.maybe_flush()
    }

    fn upsert(
        &mut self,
        rel_path: &str,
        size: u64,
        mtime: u64,
        src_blake3: Option<[u8; 32]>,
        status: JournalEntryStatus,
    ) {
        let ts = unix_now();
        match self.index.get(rel_path) {
            Some(&i) => {
                let e = &mut self.journal.entries[i];
                e.size = size;
                e.mtime = mtime;
                if src_blake3.is_some() {
                    e.src_blake3 = src_blake3;
                }
                e.status = status;
                e.ts = ts;
            }
            None => {
                self.journal.entries.push(JournalEntry {
                    rel_path: rel_path.to_string(),
                    size,
                    mtime,
                    src_blake3,
                    status,
                    ts,
                });
                self.index
                    .insert(rel_path.to_string(), self.journal.entries.len() - 1);
            }
        }
        self.dirty += 1;
    }

    /// Flush when the batch cadence (entries / interval) is reached.
    pub fn maybe_flush(&mut self) -> Result<()> {
        if self.dirty >= self.flush_entries || self.last_flush.elapsed() >= self.flush_interval {
            return self.flush();
        }
        Ok(())
    }

    /// Persist remaining changes (no-op when nothing is dirty).
    pub fn flush(&mut self) -> Result<()> {
        if self.dirty == 0 {
            self.last_flush = Instant::now();
            return Ok(());
        }
        self.journal.save_atomic(&self.path)?;
        self.dirty = 0;
        self.last_flush = Instant::now();
        Ok(())
    }

    /// Entry count.
    pub fn len(&self) -> usize {
        self.journal.entries.len()
    }

    /// Whether the journal holds no entries.
    pub fn is_empty(&self) -> bool {
        self.journal.entries.is_empty()
    }

    /// `(committed, pending, failed)` counts.
    pub fn counts(&self) -> (usize, usize, usize) {
        let mut c = (0usize, 0usize, 0usize);
        for e in &self.journal.entries {
            match e.status {
                JournalEntryStatus::Committed => c.0 += 1,
                JournalEntryStatus::Pending => c.1 += 1,
                JournalEntryStatus::Failed => c.2 += 1,
            }
        }
        c
    }

    /// Path the journal is (or will be) persisted to.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let nonce: u128 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("tallow-journal-test-{tag}-{nonce}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn entry(rel: &str, size: u64, mtime: u64, status: JournalEntryStatus) -> JournalEntry {
        JournalEntry {
            rel_path: rel.to_string(),
            size,
            mtime,
            src_blake3: None,
            status,
            ts: 0,
        }
    }

    #[test]
    fn journal_file_name_is_stable_and_separator_scoped() {
        let a = journal_file_name(
            Path::new("/tmp/tallow-journal-src-aa"),
            Path::new("/tmp/tallow-journal-dst-aa"),
        );
        assert!(a.starts_with("run-") && a.ends_with(".postcard"), "{a}");
        let mid = &a[4..a.len() - ".postcard".len()];
        assert_eq!(mid.len(), 12);
        assert!(mid.chars().all(|c| c.is_ascii_hexdigit()), "{mid}");
        // stable across calls
        assert_eq!(
            a,
            journal_file_name(
                Path::new("/tmp/tallow-journal-src-aa"),
                Path::new("/tmp/tallow-journal-dst-aa")
            )
        );
        // source change ⇒ name change
        assert_ne!(
            a,
            journal_file_name(
                Path::new("/tmp/tallow-journal-src-bb"),
                Path::new("/tmp/tallow-journal-dst-aa")
            )
        );
        // separator prevents concatenation collisions
        assert_ne!(
            journal_file_name(Path::new("/tmp/ab"), Path::new("/tmp/c")),
            journal_file_name(Path::new("/tmp/a"), Path::new("/tmp/bc"))
        );
    }

    #[test]
    fn journal_roundtrip_and_generation_validation() {
        let dir = tmp_dir("roundtrip");
        let path = dir.join("run-test.postcard");
        let mut j = DeltaSyncJournal::new("/src", "/dst");
        j.entries.push(JournalEntry {
            rel_path: "a/b.bin".to_string(),
            size: 42,
            mtime: 7,
            src_blake3: Some([9u8; 32]),
            status: JournalEntryStatus::Committed,
            ts: 1,
        });
        j.entries
            .push(entry("c.txt", 1, 2, JournalEntryStatus::Pending));
        j.save_atomic(&path).unwrap();

        let loaded = DeltaSyncJournal::load(&path).unwrap();
        assert_eq!(loaded.magic, JOURNAL_MAGIC);
        assert_eq!(loaded.ver, JOURNAL_VERSION);
        assert_eq!(loaded.source, "/src");
        assert_eq!(loaded.target, "/dst");
        assert_eq!(loaded.entries.len(), 2);
        let b = loaded.entry("a/b.bin").unwrap();
        assert_eq!(b.status, JournalEntryStatus::Committed);
        assert_eq!(b.src_blake3, Some([9u8; 32]));
        assert_eq!(b.size, 42);
        assert_eq!(
            loaded.entry("c.txt").unwrap().status,
            JournalEntryStatus::Pending
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn journal_rejects_bad_version_magic_and_truncation() {
        let mut j = DeltaSyncJournal::new("/s", "/d");
        j.entries
            .push(entry("f", 10, 100, JournalEntryStatus::Committed));
        let bytes = j.encode().unwrap();
        for n in 0..bytes.len() {
            // every prefix must fail cleanly (no panic/hang)
            assert!(
                DeltaSyncJournal::decode(&bytes[..n]).is_err(),
                "prefix {n} unexpectedly decoded"
            );
        }
        let mut bad = j.clone();
        bad.ver = JOURNAL_VERSION + 1;
        assert!(matches!(
            DeltaSyncJournal::decode(&bad.encode().unwrap()),
            Err(ProtocolError::VersionMismatch { .. })
        ));
        bad.ver = JOURNAL_VERSION;
        bad.magic = *b"XXXX";
        assert!(DeltaSyncJournal::decode(&bad.encode().unwrap()).is_err());
    }

    #[test]
    fn journal_consult_semantics() {
        let committed =
            |size: u64, mtime: u64| entry("f", size, mtime, JournalEntryStatus::Committed);
        // Committed + exact revision + target present with matching size ⇒ Skip.
        assert_eq!(
            consult(Some(&committed(10, 100)), 10, 100, Some((10, 999))),
            Some(JournalDecision::Skip)
        );
        // Committed but the source revision moved on ⇒ no opinion.
        assert_eq!(
            consult(Some(&committed(10, 100)), 11, 100, Some((11, 5))),
            None
        );
        assert_eq!(
            consult(Some(&committed(10, 100)), 10, 101, Some((10, 5))),
            None
        );
        // Committed but the target is missing / size-diverged ⇒ caller's check.
        assert_eq!(consult(Some(&committed(10, 100)), 10, 100, None), None);
        assert_eq!(
            consult(Some(&committed(10, 100)), 10, 100, Some((9, 100))),
            None
        );
        // Pending ⇒ always re-copy, whatever the target looks like.
        let p = entry("f", 10, 100, JournalEntryStatus::Pending);
        assert_eq!(
            consult(Some(&p), 10, 100, Some((10, 100))),
            Some(JournalDecision::Recopy)
        );
        assert_eq!(consult(Some(&p), 1, 1, None), Some(JournalDecision::Recopy));
        // Failed / absent ⇒ no opinion.
        let f = entry("f", 10, 100, JournalEntryStatus::Failed);
        assert_eq!(consult(Some(&f), 10, 100, Some((10, 100))), None);
        assert_eq!(consult(None, 10, 100, Some((10, 100))), None);
    }

    #[test]
    fn journal_writer_batches_and_marks() {
        let dir = tmp_dir("writer");
        let path = dir.join("run-w.postcard");
        let (mut w, warn) = JournalWriter::open(&path, "/s", "/d");
        assert!(warn.is_none());
        w.set_flush_policy(2, Duration::from_secs(3600));

        w.mark_pending("a", 1, 10).unwrap();
        assert!(!path.exists(), "must not flush below the batch threshold");
        w.mark_committed("b", 2, 20, Some([3u8; 32])).unwrap();
        assert!(path.exists(), "second mark hits the 2-entry threshold");

        let loaded = DeltaSyncJournal::load(&path).unwrap();
        assert_eq!(
            loaded.entry("a").unwrap().status,
            JournalEntryStatus::Pending
        );
        assert_eq!(
            loaded.entry("b").unwrap().status,
            JournalEntryStatus::Committed
        );
        assert_eq!(loaded.entry("b").unwrap().src_blake3, Some([3u8; 32]));

        // In-memory view agrees, and the index path is used.
        assert_eq!(
            w.consult("a", 1, 10, Some((1, 10))),
            Some(JournalDecision::Recopy)
        );
        assert_eq!(
            w.consult("b", 2, 20, Some((2, 99))),
            Some(JournalDecision::Skip)
        );

        w.mark_failed("a", 1, 10).unwrap();
        w.flush().unwrap();
        let loaded = DeltaSyncJournal::load(&path).unwrap();
        assert_eq!(
            loaded.entry("a").unwrap().status,
            JournalEntryStatus::Failed
        );
        assert_eq!(w.counts(), (1, 0, 1));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn journal_writer_corrupt_or_foreign_starts_fresh() {
        let dir = tmp_dir("corrupt");
        let path = dir.join("run-c.postcard");
        std::fs::write(&path, b"not a postcard journal").unwrap();
        let (mut w, warn) = JournalWriter::open(&path, "/s", "/d");
        assert!(
            warn.as_deref().unwrap_or("").contains("corrupt"),
            "unexpected warning: {warn:?}"
        );
        assert!(w.is_empty());
        w.mark_pending("x", 1, 1).unwrap();
        w.flush().unwrap();
        assert!(
            DeltaSyncJournal::load(&path).is_ok(),
            "must recover cleanly"
        );

        // A valid journal recorded for a different pair is discarded too.
        let mut other = DeltaSyncJournal::new("/other-src", "/other-dst");
        other
            .entries
            .push(entry("y", 1, 1, JournalEntryStatus::Committed));
        other.save_atomic(&path).unwrap();
        let (w2, warn2) = JournalWriter::open(&path, "/s", "/d");
        assert!(
            warn2.as_deref().unwrap_or("").contains("different"),
            "unexpected warning: {warn2:?}"
        );
        assert!(w2.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }
}
