//! Replication primitives — copy-and-verify plus auto-repair for
//! content-addressed stores (task A1.3.2, frozen interface B02 §5; design:
//! `impl/A1.3.1_replication_design.md` §3 and D1/D3).
//!
//! This module is deliberately **file-level**: it copies one object from one
//! path to another and never overwrites. Store walking, manifests-per-store
//! and T0/T1 diffing are composed on top of these primitives by the caller
//! (the A1.3.2 replication job), because §5 freezes exactly this surface.
//!
//! Contract (verbatim intent of §5):
//!
//! - [`copy_and_verify`] — copy bytes with `create_new` semantics. If the
//!   destination already exists: equal bytes → [`CopyStatus::AlreadyPresent`]
//!   (the destination is *not* rewritten, mtime stays put); differing bytes →
//!   the destination is moved aside to `"<dst>.quarantine-<ms>"` and
//!   [`CopyStatus::Quarantined`] is returned. Evidence is never destroyed.
//! - [`restore_missing`] — first candidate whose sha256 equals the expected
//!   hash wins; the target is written with `create_new`. No candidate matches
//!   → `io::Error` of kind `NotFound` with an explicit message listing what
//!   was tried.
//! - [`manifest_for`] — constructor for the serde-round-trippable per-artifact
//!   [`ReplicationManifest`].
//!
//! **Auto-repair loop (documented, bounded):** a collision (`Quarantined`)
//! moves the bad destination aside without touching it; calling the same
//! primitive *once more* then sees an absent destination and completes the
//! repair with `Copied`. At most two calls per file — never an unbounded
//! retry loop (design D1/D3: retries bounded at 3 across attempts).
//!
//! Only hash equality counts as verification — mode/mtime/seals are never
//! trusted (design D5).

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── hashing helpers ──────────────────────────────────────────────────────────

/// sha256 of `bytes`, lowercase hex (64 chars).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    to_hex(h.finalize().as_slice())
}

/// sha256 of the file at `path`, lowercase hex (64 chars).
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    Ok(sha256_hex(&std::fs::read(path)?))
}

/// Lowercase hex encoding — local helper, no extra dependency (`hex` crate
/// is absent in this workspace).
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Unix ms since epoch. Never panics (0 only if the clock predates 1970).
fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Best-effort freeze of a freshly written object: strip write bits on Unix
/// (mirrors `raw_store`; T0/T1 objects are mode 0444, design D4). Freeze
/// failure is not an error — `create_new` already guarantees write-once.
fn freeze(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

// ── types (frozen §5) ────────────────────────────────────────────────────────

/// Per-artifact replication record (§5). Serde round-trippable; field names
/// are the frozen wire names `hash`, `size`, `locations`, `last_verified_ms`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationManifest {
    /// sha256 hex id of the artifact bytes.
    pub hash: String,
    /// Byte length of the artifact.
    pub size: u64,
    /// Every store location currently holding (or supposed to hold) a copy.
    pub locations: Vec<String>,
    /// Local clock, unix ms, of the last successful byte verification.
    pub last_verified_ms: i64,
}

/// Result classification of one copy/restore attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyStatus {
    /// Bytes were written to the destination (fresh `create_new` write).
    Copied,
    /// Destination already held byte-identical content; nothing was written.
    AlreadyPresent,
    /// Destination held *different* bytes; they were moved to
    /// `"<dst>.quarantine-<ms>"` and left there as evidence. The destination
    /// path is now free — call once more to complete the repair.
    Quarantined,
}

/// Outcome of a copy/restore attempt (§5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyOutcome {
    /// What happened.
    pub status: CopyStatus,
    /// sha256 hex of the source/expected bytes (the verified identity).
    pub hash: String,
    /// Byte length of those bytes.
    pub bytes: u64,
    /// Human-readable detail (includes the quarantine path on collisions).
    pub detail: String,
}

// ── primitives (frozen §5) ───────────────────────────────────────────────────

/// Copy `src_file` to `dst_file` with `create_new` semantics, verifying by
/// hash.
///
/// - Destination absent → bytes copied, `fsync`ed, best-effort frozen 0444,
///   [`CopyStatus::Copied`].
/// - Destination exists and equals the source bytes → [`CopyStatus::AlreadyPresent`];
///   the destination is never rewritten (mtime stable).
/// - Destination exists but differs → moved to `"<dst>.quarantine-<ms>"`,
///   [`CopyStatus::Quarantined`]. Nothing is deleted and the source is
///   untouched; call again to complete the repair.
///
/// Parent directories of `dst_file` are created as needed. Errors are
/// propagated with `io::ErrorKind` preserved where possible.
pub fn copy_and_verify(src_file: &Path, dst_file: &Path) -> std::io::Result<CopyOutcome> {
    let bytes = std::fs::read(src_file).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "replication: cannot read source {}: {e}",
                src_file.display()
            ),
        )
    })?;
    let hash = sha256_hex(&bytes);
    write_verified(dst_file, &bytes, &hash)
}

/// Restore `target_file` from the first candidate in `candidates` whose
/// sha256 equals `expected_hash`.
///
/// Candidates that are missing or unreadable are skipped (recorded in the
/// error message if nothing matches). A matching candidate is written to
/// `target_file` with `create_new` semantics — the collision rules of
/// [`copy_and_verify`] apply (identical target → `AlreadyPresent`; differing
/// target → quarantined, then call again to finish).
///
/// If no candidate matches, returns `io::ErrorKind::NotFound` whose message
/// states the expected hash and every candidate tried with its reason.
pub fn restore_missing(
    expected_hash: &str,
    candidates: &[PathBuf],
    target_file: &Path,
) -> std::io::Result<CopyOutcome> {
    let mut tried: Vec<String> = Vec::with_capacity(candidates.len());
    for cand in candidates {
        match std::fs::read(cand) {
            Ok(bytes) => {
                let actual = sha256_hex(&bytes);
                if actual == expected_hash {
                    let mut outcome = write_verified(target_file, &bytes, expected_hash)?;
                    outcome.detail = format!(
                        "from candidate {} — {}",
                        cand.display(),
                        outcome.detail
                    );
                    return Ok(outcome);
                }
                tried.push(format!("{}: hash {}", cand.display(), actual));
            }
            Err(e) => {
                tried.push(format!("{}: unreadable ({e})", cand.display()));
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!(
            "replication: no candidate matched sha256 {expected_hash}; tried {} candidate(s): {}",
            candidates.len(),
            if tried.is_empty() {
                "(none provided)".to_string()
            } else {
                tried.join("; ")
            }
        ),
    ))
}

/// Construct a [`ReplicationManifest`] (§5). Pure value assembly — callers
/// own when/how the fields are computed.
pub fn manifest_for(
    hash: &str,
    size: u64,
    locations: &[String],
    ts_ms: i64,
) -> ReplicationManifest {
    ReplicationManifest {
        hash: hash.to_string(),
        size,
        locations: locations.to_vec(),
        last_verified_ms: ts_ms,
    }
}

// ── internals ────────────────────────────────────────────────────────────────

/// Shared write path: `create_new` write of `bytes` to `dst` with the
/// collision rules of the frozen contract. `hash` must already be
/// `sha256_hex(bytes)` (callers compute it once; restore passes the expected
/// hash it verified against).
fn write_verified(dst: &Path, bytes: &[u8], hash: &str) -> std::io::Result<CopyOutcome> {
    ensure_parent(dst)?;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)
    {
        Ok(mut f) => {
            let written = f.write_all(bytes).and_then(|()| f.sync_all());
            drop(f);
            if let Err(e) = written {
                // Never leave a torn object wedged at a destination: remove
                // the partial file so a retry can succeed cleanly.
                let _ = std::fs::remove_file(dst);
                return Err(e);
            }
            freeze(dst);
            Ok(CopyOutcome {
                status: CopyStatus::Copied,
                hash: hash.to_string(),
                bytes: bytes.len() as u64,
                detail: format!(
                    "copied {} bytes to {} (sha256 {hash})",
                    bytes.len(),
                    dst.display()
                ),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = std::fs::read(dst)?;
            if existing == bytes {
                Ok(CopyOutcome {
                    status: CopyStatus::AlreadyPresent,
                    hash: hash.to_string(),
                    bytes: bytes.len() as u64,
                    detail: format!(
                        "{} already holds identical bytes (sha256 {hash}); not rewritten",
                        dst.display()
                    ),
                })
            } else {
                let q = unique_quarantine_path(dst, now_ms());
                std::fs::rename(dst, &q).map_err(|e| {
                    std::io::Error::new(
                        e.kind(),
                        format!(
                            "replication: {} conflicts with incoming bytes (sha256 {hash}) \
                             and could not be quarantined to {}: {e}; destination left untouched",
                            dst.display(),
                            q.display()
                        ),
                    )
                })?;
                Ok(CopyOutcome {
                    status: CopyStatus::Quarantined,
                    hash: hash.to_string(),
                    bytes: bytes.len() as u64,
                    detail: format!(
                        "{} held different bytes ({} vs incoming {}); moved to {} as evidence; \
                         run once more to complete the repair",
                        dst.display(),
                        sha256_hex(&existing),
                        hash,
                        q.display()
                    ),
                })
            }
        }
        Err(e) => Err(e),
    }
}

/// `"<dst>.quarantine-<ms>"`, bumping `ms` on the (rare) chance the name is
/// taken so evidence is never overwritten.
fn unique_quarantine_path(dst: &Path, mut ms: i64) -> PathBuf {
    loop {
        let mut os = dst.as_os_str().to_os_string();
        os.push(format!(".quarantine-{ms}"));
        let p = PathBuf::from(os);
        if !p.exists() {
            return p;
        }
        ms += 1;
    }
}

/// Create `dst`'s parent directories when needed (mirrors `RawStore::put_bytes`).
fn ensure_parent(dst: &Path) -> std::io::Result<()> {
    match dst.parent() {
        Some(p) if !p.as_os_str().is_empty() => std::fs::create_dir_all(p),
        _ => Ok(()),
    }
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sha(data: &[u8]) -> String {
        sha256_hex(data)
    }

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn copy_roundtrip_lands_and_hashes() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src.bin");
        let dst = d.path().join("out/deep/dst.bin");
        let payload = b"tallow replication payload \x00\x01\x02";
        write(&src, payload);

        let out = copy_and_verify(&src, &dst).unwrap();
        assert_eq!(out.status, CopyStatus::Copied);
        assert_eq!(out.hash, sha(payload));
        assert_eq!(out.bytes, payload.len() as u64);
        assert_eq!(std::fs::read(&dst).unwrap(), payload);
        // Post-copy re-hash of the stored bytes (design D1: a copy only
        // counts after re-hash).
        assert_eq!(sha256_file(&dst).unwrap(), out.hash);
    }

    #[test]
    fn recopy_identical_is_already_present_and_not_rewritten() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src.bin");
        let dst = d.path().join("dst.bin");
        write(&src, b"identical bytes");
        copy_and_verify(&src, &dst).unwrap();
        let m1 = std::fs::metadata(&dst).unwrap().modified().unwrap();
        std::thread::sleep(Duration::from_millis(20));

        let out = copy_and_verify(&src, &dst).unwrap();
        assert_eq!(out.status, CopyStatus::AlreadyPresent);
        assert_eq!(out.hash, sha(b"identical bytes"));
        let m2 = std::fs::metadata(&dst).unwrap().modified().unwrap();
        assert_eq!(m1, m2, "identical destination must not be rewritten");
        assert_eq!(std::fs::read(&dst).unwrap(), b"identical bytes");
    }

    #[test]
    fn conflicting_dst_is_quarantined_and_byte_preserved() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src.bin");
        let dst = d.path().join("dst.bin");
        let good = b"genuine incoming bytes";
        let bad = b"corrupted pre-existing bytes";
        write(&src, good);
        write(&dst, bad);

        let out = copy_and_verify(&src, &dst).unwrap();
        assert_eq!(out.status, CopyStatus::Quarantined);
        assert_eq!(out.hash, sha(good));
        // Destination moved aside — no overwrite, no delete.
        assert!(!dst.exists(), "conflicting destination must be moved aside");
        let q: Vec<PathBuf> = std::fs::read_dir(d.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.contains(".quarantine-"))
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(q.len(), 1, "exactly one quarantine file expected");
        assert_eq!(
            std::fs::read(&q[0]).unwrap(),
            bad,
            "quarantine byte-preserved"
        );
        assert!(
            out.detail.contains(q[0].to_str().unwrap()),
            "outcome detail names the quarantine path: {}",
            out.detail
        );
        // Source untouched.
        assert_eq!(std::fs::read(&src).unwrap(), good);

        // Bounded auto-repair: second call sees a free destination and lands.
        let out2 = copy_and_verify(&src, &dst).unwrap();
        assert_eq!(out2.status, CopyStatus::Copied);
        assert_eq!(std::fs::read(&dst).unwrap(), good);
    }

    #[test]
    fn restore_from_second_candidate_when_first_is_bad() {
        let d = tempfile::tempdir().unwrap();
        let good = b"the one true payload";
        let expected = sha(good);
        let bad_peer = d.path().join("peer1.bin");
        let good_peer = d.path().join("peer2.bin");
        write(&bad_peer, b"wrong bytes at peer 1");
        write(&good_peer, good);
        let target = d.path().join("restore/target.bin");

        let out = restore_missing(
            &expected,
            &[bad_peer.clone(), good_peer.clone(), d.path().join("absent.bin")],
            &target,
        )
        .unwrap();
        assert_eq!(out.status, CopyStatus::Copied);
        assert_eq!(out.hash, expected);
        assert_eq!(out.bytes, good.len() as u64);
        assert_eq!(std::fs::read(&target).unwrap(), good);
        assert!(out.detail.contains("peer2.bin"), "detail names winner");
        assert_eq!(sha256_file(&target).unwrap(), expected);
    }

    #[test]
    fn restore_no_match_is_not_found_and_target_untouched() {
        let d = tempfile::tempdir().unwrap();
        let expected = sha(b"never stored anywhere");
        let c1 = d.path().join("c1.bin");
        let c2 = d.path().join("c2.bin");
        write(&c1, b"something else");
        // c2 intentionally absent — both must be reported.
        let target = d.path().join("target.bin");

        let err = restore_missing(&expected, &[c1, c2], &target).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        let msg = err.to_string();
        assert!(msg.contains(&expected), "message states expected hash: {msg}");
        assert!(msg.contains("peer") || msg.contains("c1.bin"), "{msg}");
        assert!(msg.contains("absent") || msg.contains("unreadable"), "{msg}");
        assert!(!target.exists(), "no match must not create the target");
    }

    #[test]
    fn restore_quarantines_conflicting_target_then_completes() {
        let d = tempfile::tempdir().unwrap();
        let good = b"good peer bytes";
        let expected = sha(good);
        let peer = d.path().join("peer.bin");
        write(&peer, good);
        let target = d.path().join("target.bin");
        write(&target, b"rotten local copy");

        let out = restore_missing(&expected, &[peer.clone()], &target).unwrap();
        assert_eq!(out.status, CopyStatus::Quarantined);
        assert!(!target.exists());

        let out2 = restore_missing(&expected, &[peer], &target).unwrap();
        assert_eq!(out2.status, CopyStatus::Copied);
        assert_eq!(std::fs::read(&target).unwrap(), good);
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let m = manifest_for(
            &sha(b"x"),
            1234,
            &[
                "~/Nixe/data/stores/raw/aa/bb/…".to_string(),
                "/var/lib/tallow/replica/raw/aa/bb/…".to_string(),
            ],
            1_789_096_579_388,
        );
        let json = serde_json::to_string(&m).unwrap();
        // Frozen wire field names.
        assert!(json.contains("\"hash\""));
        assert!(json.contains("\"size\""));
        assert!(json.contains("\"locations\""));
        assert!(json.contains("\"last_verified_ms\""));
        let back: ReplicationManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn empty_payload_is_a_valid_object() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("empty.bin");
        let dst = d.path().join("empty-copy.bin");
        write(&src, b"");
        let out = copy_and_verify(&src, &dst).unwrap();
        assert_eq!(out.status, CopyStatus::Copied);
        assert_eq!(
            out.hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(out.bytes, 0);
        assert_eq!(std::fs::read(&dst).unwrap(), b"");
    }

    #[test]
    fn missing_source_propagates_not_found() {
        let d = tempfile::tempdir().unwrap();
        let err = copy_and_verify(
            &d.path().join("nope.bin"),
            &d.path().join("dst.bin"),
        )
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(!d.path().join("dst.bin").exists());
    }

    #[test]
    fn quarantine_names_never_collide() {
        let d = tempfile::tempdir().unwrap();
        let dst = d.path().join("obj.bin");
        let p1 = unique_quarantine_path(&dst, 42);
        std::fs::write(&p1, b"first").unwrap();
        let p2 = unique_quarantine_path(&dst, 42);
        assert_ne!(p1, p2);
        assert!(p2.to_str().unwrap().contains(".quarantine-43"));
    }
}
