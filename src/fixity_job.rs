//! Fixity sweep job — the job layer of the fixity flow (task A1.3.3,
//! frozen interface §3; design contract A1.3.1 §D3).
//!
//! [`crate::fixity`] is the verdict layer (pure, read-only audit: hash bytes,
//! classify [`Severity`], render JSONL lines and an exit code). This module is
//! the **job layer** on top of it: it scans the primary and mirror stores,
//! applies the cross-store severity policy, auto-repairs a damaged or absent
//! copy when its peer holds verified-good bytes (via [`crate::replication`]),
//! and writes the report set the scrub job/cron consumes:
//!
//! - `reports/fixity-<ts>.json` — JSONL findings + the plain summary line
//!   `ok=N warn=N critical=N` (exact [`report_lines`] format; `<ts>` is the
//!   caller-supplied `now_ms`);
//! - `reports/latest.json` — byte-identical copy of the newest report;
//! - `reports/ALERT` — plain text, written **only** when at least one
//!   `critical` finding remains after auto-repair;
//! - `reports/cursor.json` — best-effort cursor checkpoint (documented as the
//!   optional part of §3; a failure here never affects the sweep outcome).
//!
//! ## Severity policy (job level; the audit itself stays conservative)
//!
//! One finding per `(hash, store)` pair, in deterministic order (hashes
//! ascending, primary then mirror). Raw per-store verdicts come from
//! [`scan_store_sharded`] (mismatch/absent → `critical`; unreadable/malformed
//! → `warn`). The job layer then applies the design-D3 cross-store rule —
//! *"no good copy anywhere → critical"*:
//!
//! - a non-`ok` verdict on one side is **auto-repaired** when the other side
//!   verifies `ok`; after a successful repair the finding is recorded as
//!   `warn` with the full detection story (hash mismatch / absence) and the
//!   repair evidence in `detail` — recorded, never silent;
//! - if repair is impossible (no verified-good peer) or fails, the finding
//!   stays `critical` and the sweep writes `ALERT`;
//! - both sides `ok` → `ok`.
//!
//! ## Scope note
//!
//! The sweep covers the **sharded** content-addressed layout
//! (`root/<ab>/<cd>/<hash>`, `RawStore`-compatible) on both stores — the
//! objects design D3 audits. Non-sharded derived objects (`derived/<key>`) are
//! walked by `replication_plan` (A1.3.2) and are an explicit follow-up for
//! this job, not a silent omission.
//!
//! [`run_sweep`] is infallible by frozen contract (it returns
//! [`SweepOutcome`], not a `Result`): unreadable store roots simply yield no
//! enumerated objects (their peers' objects then surface as absent and are
//! repairable from the peer side), and a failure to write the report set
//! forces the returned `exit_code` to `2` (a sweep that cannot file its
//! evidence is a critical-class failure) instead of panicking.

use std::path::{Path, PathBuf};

use crate::fixity::{
    audit_file, exit_code, report_lines, scan_store_sharded, FixityFinding, Severity,
};
use crate::replication::{restore_missing, CopyStatus};

// ── report-set names (frozen §3 + design D3) ────────────────────────────────

/// Newest report file: `reports/fixity-<now_ms>.json`.
pub const REPORT_PREFIX: &str = "fixity-";
/// Byte-identical copy of the newest report.
pub const LATEST_REPORT_FILE: &str = "latest.json";
/// Plain-text alert, written only when a critical finding remains.
pub const ALERT_FILE: &str = "ALERT";
/// Best-effort cursor checkpoint.
pub const CURSOR_FILE: &str = "cursor.json";

/// Frozen outcome of one sweep (§3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepOutcome {
    /// [`exit_code`] over the final findings; also forced to `2` when the
    /// report set could not be written (see module docs).
    pub exit_code: i32,
    /// Findings written to the report (one per `(hash, store)` pair).
    pub findings_count: usize,
    /// Findings that remain `critical` after auto-repair (→ `ALERT` file).
    pub critical_count: usize,
    /// Path of the `fixity-<now_ms>.json` report (whether or not writing it
    /// succeeded — on failure the returned exit code is forced to `2`).
    pub report_path: PathBuf,
}

// ── layout helpers ──────────────────────────────────────────────────────────

/// Canonical id shape: exactly 64 lowercase hex chars (same rule as
/// `fixity`/`RawStore`; a hash becomes a path component and must not escape
/// `root/`).
fn is_valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// One shard component: exactly 2 lowercase hex chars.
fn is_shard_component(s: &str) -> bool {
    s.len() == 2 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Sharded content-address layout, mirroring `RawStore`/`fixity`:
/// `root/<ab>/<cd>/<hash>`.
fn object_path(root: &Path, hash: &str) -> PathBuf {
    debug_assert!(is_valid_hash(hash), "object_path called with invalid hash");
    root.join(&hash[0..2]).join(&hash[2..4]).join(hash)
}

/// Enumerate the content addresses **present** in a sharded store by path
/// (independent of content, so a corrupted-content object is still listed).
/// Junk at any level — wrong depth, non-hex shard names, non-64-hex leaf names —
/// is ignored. Sorted + deduped for determinism.
fn walk_sharded_hashes(root: &Path) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let Ok(l1) = std::fs::read_dir(root) else {
        return out;
    };
    for e1 in l1.flatten() {
        let s1 = e1.file_name().to_string_lossy().into_owned();
        if !is_shard_component(&s1) || !e1.path().is_dir() {
            continue;
        }
        let Ok(l2) = std::fs::read_dir(e1.path()) else {
            continue;
        };
        for e2 in l2.flatten() {
            let s2 = e2.file_name().to_string_lossy().into_owned();
            if !is_shard_component(&s2) || !e2.path().is_dir() {
                continue;
            }
            let Ok(l3) = std::fs::read_dir(e2.path()) else {
                continue;
            };
            for e3 in l3.flatten() {
                let s3 = e3.file_name().to_string_lossy().into_owned();
                if is_valid_hash(&s3) && &s3[0..2] == s1.as_str() && &s3[2..4] == s2.as_str() {
                    out.push(s3);
                }
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

// ── auto-repair (bounded; via crate::replication) ───────────────────────────

enum RepairOutcome {
    /// Target now holds bytes that re-verify as `hash`.
    Repaired { detail: String },
    /// No verified-good peer, or the repair itself failed.
    NotRepairable { reason: String },
}

/// Restore `hash` at `target_root` from the peer copy at `peer_root`, via
/// [`restore_missing`] (the §3 reuse requirement).
///
/// Bounded two-call pattern (mirrors `replication.rs` docs): the first call
/// may collide with corrupted bytes at the target, which are *quarantined as
/// evidence* and the destination freed; the second call lands the verified
/// bytes. At most two calls — never an unbounded retry loop. Success is
/// declared only after a re-audit ([`audit_file`]) verifies hash equality
/// (design D5: mode/mtime/seals are never trusted).
fn attempt_repair(hash: &str, peer_root: &Path, target_root: &Path) -> RepairOutcome {
    let peer = object_path(peer_root, hash);
    let target = object_path(target_root, hash);

    let mut quarantine_note = String::new();
    let mut calls = 0u8;
    for _ in 0..2 {
        calls += 1;
        match restore_missing(hash, std::slice::from_ref(&peer), &target) {
            Ok(outcome) => match outcome.status {
                CopyStatus::Copied | CopyStatus::AlreadyPresent => break,
                CopyStatus::Quarantined => {
                    quarantine_note = format!(
                        "conflicting bytes at the target were kept as evidence ({})",
                        outcome.detail
                    );
                }
            },
            Err(e) => {
                return RepairOutcome::NotRepairable {
                    reason: e.to_string(),
                };
            }
        }
    }

    // Only hash equality counts as verification (design D5).
    let check = audit_file(&target, hash);
    if check.severity == Severity::Ok {
        RepairOutcome::Repaired {
            detail: format!(
                "restored from peer {} in {calls} call(s), sha256 re-verified after copy{}",
                peer.display(),
                if quarantine_note.is_empty() {
                    String::new()
                } else {
                    format!("; {quarantine_note}")
                }
            ),
        }
    } else {
        RepairOutcome::NotRepairable {
            reason: format!(
                "post-repair re-audit is still '{}' ({})",
                check.severity.as_str(),
                check.detail
            ),
        }
    }
}

/// A finding whose damage was detected and then repaired from the peer:
/// recorded as `warn` (a verified good copy exists, so the D3 condition
/// "no good copy anywhere → critical" does not hold), with the detection
/// story kept verbatim — never silent.
fn repaired_finding(raw: &FixityFinding, hash: &str, repair_detail: String) -> FixityFinding {
    FixityFinding {
        path: raw.path.clone(),
        expected: raw.expected.clone(),
        actual: Some(hash.to_string()),
        severity: Severity::Warn,
        detail: format!(
            "detected then auto-repaired: {}. repair: {repair_detail}; severity recorded \
             warn because a verified-good copy exists ('no good copy anywhere → critical' \
             does not hold)",
            raw.detail
        ),
    }
}

/// A finding that stays critical because no verified-good copy exists / the
/// repair failed: the original verdict plus the repair failure reason.
fn unrepaired_finding(raw: &FixityFinding, reason: String) -> FixityFinding {
    FixityFinding {
        severity: Severity::Critical,
        detail: format!("{}; auto-repair did not complete: {reason}", raw.detail),
        ..raw.clone()
    }
}

// ── the sweep (frozen §3) ───────────────────────────────────────────────────

/// Run one fixity sweep over `primary` + `mirror`, writing the report set
/// into `reports_dir`. `now_ms` is the caller's clock (unix ms) and names the
/// report file — no internal clock reads, so runs are deterministic in tests.
///
/// See the module docs for the severity/repair policy and the write-failure
/// behavior (never panics; unfileable reports force `exit_code = 2`).
pub fn run_sweep(
    primary: &Path,
    mirror: &Path,
    reports_dir: &Path,
    now_ms: i64,
) -> SweepOutcome {
    // 1) Union of recorded hashes across both stores.
    let mut hashes = walk_sharded_hashes(primary);
    hashes.extend(walk_sharded_hashes(mirror));
    hashes.sort_unstable();
    hashes.dedup();

    // 2) Raw per-store audits, in the same hash order.
    let primary_raw = scan_store_sharded(primary, &hashes);
    let mirror_raw = scan_store_sharded(mirror, &hashes);

    // 3) Cross-store policy + bounded auto-repair, one hash at a time so a
    //    repair completes before the pair is classified.
    let mut findings: Vec<FixityFinding> = Vec::with_capacity(hashes.len() * 2);
    let mut repaired_count: usize = 0;
    for (i, hash) in hashes.iter().enumerate() {
        let p = &primary_raw[i];
        let m = &mirror_raw[i];
        let p_ok = p.severity == Severity::Ok;
        let m_ok = m.severity == Severity::Ok;

        let p_final = if p_ok {
            p.clone()
        } else if m_ok {
            match attempt_repair(hash, mirror, primary) {
                RepairOutcome::Repaired { detail } => {
                    repaired_count += 1;
                    repaired_finding(p, hash, detail)
                }
                RepairOutcome::NotRepairable { reason } => unrepaired_finding(p, reason),
            }
        } else {
            // No good copy anywhere → critical, as detected (nothing deleted).
            p.clone()
        };

        let m_final = if m_ok {
            m.clone()
        } else if p_ok {
            match attempt_repair(hash, primary, mirror) {
                RepairOutcome::Repaired { detail } => {
                    repaired_count += 1;
                    repaired_finding(m, hash, detail)
                }
                RepairOutcome::NotRepairable { reason } => unrepaired_finding(m, reason),
            }
        } else {
            m.clone()
        };

        findings.push(p_final);
        findings.push(m_final);
    }

    // 4) Report set.
    let code = exit_code(&findings);
    let critical_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();

    let mut body = report_lines(&findings).join("\n");
    body.push('\n');
    let report_path = reports_dir.join(format!("{}{now_ms}.json", REPORT_PREFIX));

    let mut report_written = std::fs::create_dir_all(reports_dir).is_ok();
    if report_written {
        report_written = std::fs::write(&report_path, &body).is_ok()
            && std::fs::write(reports_dir.join(LATEST_REPORT_FILE), &body).is_ok();
    }

    if critical_count > 0 {
        let alert = render_alert(&findings, now_ms, &report_path, repaired_count);
        // Best effort; the report itself already records every critical.
        let _ = std::fs::write(reports_dir.join(ALERT_FILE), alert);
    }

    // Optional (documented) cursor checkpoint — best effort by contract.
    let cursor = serde_json::json!({
        "last_sweep_ms": now_ms,
        "objects_scanned": hashes.len(),
        "findings_count": findings.len(),
        "critical_count": critical_count,
        "repaired_count": repaired_count,
    });
    let _ = std::fs::write(
        reports_dir.join(CURSOR_FILE),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&cursor).unwrap_or_else(|_| "{}".to_string())
        ),
    );

    // A sweep that cannot file its report set is a critical-class failure; the
    // frozen exit-code contract tops out at 2, so clamp rather than invent 3.
    let final_code = if report_written { code } else { code.max(2) };

    SweepOutcome {
        exit_code: final_code,
        findings_count: findings.len(),
        critical_count,
        report_path,
    }
}

/// Plain-text `ALERT` body: the critical findings, the report pointer, and an
/// explicit no-deletion statement.
fn render_alert(
    findings: &[FixityFinding],
    now_ms: i64,
    report_path: &Path,
    repaired_count: usize,
) -> String {
    let critical: Vec<&FixityFinding> = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .collect();
    let mut s = String::new();
    s.push_str(&format!(
        "FIXITY ALERT — critical finding(s) at unix-ms {now_ms}\n"
    ));
    s.push_str(&format!("report: {}\n", report_path.display()));
    s.push_str(&format!(
        "critical findings: {} of {} (auto-repaired from peers this sweep: {repaired_count})\n",
        critical.len(),
        findings.len()
    ));
    s.push_str(
        "No good copy of the objects below exists; nothing was deleted by this sweep, the \
         affected objects are preserved as-is (A1.3.1 D3: no good copy anywhere → critical).\n\n",
    );
    for f in critical {
        s.push_str(&format!("[critical] {}\n  {}\n", f.path, f.detail));
    }
    s
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn sha(data: &[u8]) -> String {
        crate::replication::sha256_hex(data)
    }

    /// Store `bytes` at their sharded content address under `root`; returns the
    /// hash (mirrors what `RawStore::put_bytes` leaves on disk).
    fn put_sharded(root: &Path, bytes: &[u8]) -> String {
        let h = sha(bytes);
        let p = object_path(root, &h);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, bytes).unwrap();
        h
    }

    /// Parse the JSON finding lines of a report (skips the plain summary line).
    fn read_jsonl(path: &Path) -> Vec<serde_json::Value> {
        let text = fs::read_to_string(path).unwrap();
        text.lines()
            .filter(|l| l.trim_start().starts_with('{'))
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// Quarantine evidence files (`*.quarantine-*`) in `dir`.
    fn quarantine_files(dir: &Path) -> Vec<PathBuf> {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.contains(".quarantine-"))
                    .unwrap_or(false)
            })
            .collect()
    }

    #[test]
    fn clean_stores_yield_ok_report_latest_and_no_alert() {
        let d = tempfile::tempdir().unwrap();
        let primary = d.path().join("primary");
        let mirror = d.path().join("mirror");
        let reports = d.path().join("reports");

        let h1 = put_sharded(&primary, b"object-one");
        let h2 = put_sharded(&primary, b"object-two");
        put_sharded(&mirror, b"object-one");
        put_sharded(&mirror, b"object-two");

        let out = run_sweep(&primary, &mirror, &reports, 1_760_000_000_000);
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.critical_count, 0);
        assert_eq!(out.findings_count, 4);
        assert_eq!(out.report_path, reports.join("fixity-1760000000000.json"));
        assert!(out.report_path.exists());

        // latest.json is byte-identical; summary line is the frozen format.
        let ts_body = fs::read_to_string(&out.report_path).unwrap();
        let latest = fs::read_to_string(reports.join(LATEST_REPORT_FILE)).unwrap();
        assert_eq!(ts_body, latest);
        assert!(ts_body.ends_with("ok=4 warn=0 critical=0\n"));

        assert!(!reports.join(ALERT_FILE).exists());

        // Every hash appears once per store, all ok.
        let rows = read_jsonl(&out.report_path);
        assert_eq!(rows.len(), 4);
        for h in [&h1, &h2] {
            let n = rows
                .iter()
                .filter(|r| r.get("expected").and_then(|v| v.as_str()) == Some(h.as_str()))
                .count();
            assert_eq!(n, 2, "hash {h} must have one finding per store");
        }
        for r in &rows {
            assert_eq!(r.get("severity").and_then(|v| v.as_str()), Some("ok"));
        }

        // Cursor checkpoint names this sweep.
        let cur: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(reports.join(CURSOR_FILE)).unwrap()).unwrap();
        assert_eq!(cur["last_sweep_ms"], 1_760_000_000_000i64);
        assert_eq!(cur["objects_scanned"], 2);
        assert_eq!(cur["repaired_count"], 0);
    }

    #[test]
    fn mirror_corruption_is_detected_quarantined_and_repaired() {
        let d = tempfile::tempdir().unwrap();
        let primary = d.path().join("primary");
        let mirror = d.path().join("mirror");
        let reports = d.path().join("reports");

        let good = b"atomic object".as_slice();
        let h = put_sharded(&primary, good);
        put_sharded(&mirror, good);
        let mpath = object_path(&mirror, &h);
        fs::write(&mpath, b"corrupted object").unwrap();

        let out = run_sweep(&primary, &mirror, &reports, 1_760_000_000_001);
        // Policy: a good peer copy exists and repair succeeded → warn (recorded
        // detection), not a residual critical; no ALERT.
        assert_eq!(out.exit_code, 1);
        assert_eq!(out.critical_count, 0);
        assert!(!reports.join(ALERT_FILE).exists());

        // Repaired bytes are back at the content address, re-verified.
        assert_eq!(fs::read(&mpath).unwrap(), good);
        assert_eq!(crate::replication::sha256_file(&mpath).unwrap(), h);

        // Corrupted bytes were NOT deleted — quarantine evidence next to target.
        let q = quarantine_files(mpath.parent().unwrap());
        assert_eq!(q.len(), 1, "exactly one quarantine file expected");
        assert_eq!(fs::read(&q[0]).unwrap(), b"corrupted object");

        // Detection story present in the report, not silent.
        let rows = read_jsonl(&out.report_path);
        let row = rows
            .iter()
            .find(|r| {
                r.get("path").and_then(|v| v.as_str()) == Some(mpath.display().to_string().as_str())
            })
            .expect("mirror finding present");
        assert_eq!(row.get("severity").and_then(|v| v.as_str()), Some("warn"));
        let det = row.get("detail").and_then(|v| v.as_str()).unwrap();
        assert!(det.contains("hash mismatch"), "detail: {det}");
        assert!(det.contains("auto-repaired"), "detail: {det}");
    }

    #[test]
    fn both_copies_corrupt_is_critical_alert_and_nothing_deleted() {
        let d = tempfile::tempdir().unwrap();
        let primary = d.path().join("primary");
        let mirror = d.path().join("mirror");
        let reports = d.path().join("reports");

        let h = put_sharded(&primary, b"both-bad");
        put_sharded(&mirror, b"both-bad");
        let ppath = object_path(&primary, &h);
        let mpath = object_path(&mirror, &h);
        fs::write(&ppath, b"primary rotted").unwrap();
        fs::write(&mpath, b"mirror rotted").unwrap();

        let out = run_sweep(&primary, &mirror, &reports, 1_760_000_000_002);
        assert_eq!(out.exit_code, 2);
        assert_eq!(out.critical_count, 2);

        // ALERT written, naming both critical objects.
        let alert = fs::read_to_string(reports.join(ALERT_FILE)).unwrap();
        assert!(alert.contains("FIXITY ALERT"));
        assert!(alert.contains(ppath.display().to_string().as_str()));
        assert!(alert.contains(mpath.display().to_string().as_str()));

        // Nothing deleted: both corrupted objects remain, byte-for-byte; no
        // repair was attempted (no good peer), so no quarantine either.
        assert_eq!(fs::read(&ppath).unwrap(), b"primary rotted");
        assert_eq!(fs::read(&mpath).unwrap(), b"mirror rotted");
        assert!(quarantine_files(ppath.parent().unwrap()).is_empty());
        assert!(quarantine_files(mpath.parent().unwrap()).is_empty());
    }

    #[test]
    fn absent_primary_object_is_restored_from_mirror() {
        let d = tempfile::tempdir().unwrap();
        let primary = d.path().join("primary");
        let mirror = d.path().join("mirror");
        let reports = d.path().join("reports");

        let h = put_sharded(&primary, b"restore-me");
        put_sharded(&mirror, b"restore-me");
        let ppath = object_path(&primary, &h);
        fs::remove_file(&ppath).unwrap();

        let out = run_sweep(&primary, &mirror, &reports, 1_760_000_000_003);
        assert_eq!(out.exit_code, 1);
        assert_eq!(out.critical_count, 0);
        assert!(!reports.join(ALERT_FILE).exists());

        // Missing object restored from the mirror (via restore_missing).
        assert_eq!(fs::read(&ppath).unwrap(), b"restore-me");
        assert_eq!(crate::replication::sha256_file(&ppath).unwrap(), h);

        let rows = read_jsonl(&out.report_path);
        let row = rows
            .iter()
            .find(|r| {
                r.get("path").and_then(|v| v.as_str()) == Some(ppath.display().to_string().as_str())
            })
            .expect("primary finding present");
        assert_eq!(row.get("severity").and_then(|v| v.as_str()), Some("warn"));
        let det = row.get("detail").and_then(|v| v.as_str()).unwrap();
        assert!(det.contains("absent"), "detail: {det}");
        assert!(det.contains("restored from peer"), "detail: {det}");
    }

    #[test]
    fn empty_stores_write_zeroed_report() {
        let d = tempfile::tempdir().unwrap();
        let primary = d.path().join("primary");
        let mirror = d.path().join("mirror");
        fs::create_dir_all(&primary).unwrap();
        fs::create_dir_all(&mirror).unwrap();
        let reports = d.path().join("reports");

        let out = run_sweep(&primary, &mirror, &reports, 42);
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.findings_count, 0);
        assert_eq!(out.critical_count, 0);
        let body = fs::read_to_string(&out.report_path).unwrap();
        assert_eq!(body, "ok=0 warn=0 critical=0\n");
        assert!(!reports.join(ALERT_FILE).exists());
    }

    #[test]
    fn walk_ignores_non_sharded_junk() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("store");
        let real = put_sharded(&root, b"real-object");

        // Junk that must be ignored: stray root file, wrong-depth leaf,
        // uppercase (non-canonical) shard tree, leaf not matching its shards.
        fs::write(root.join("README"), b"x").unwrap();
        fs::create_dir_all(root.join("aa").join("bb")).unwrap();
        fs::write(root.join("aa").join("bb").join("short"), b"y").unwrap();
        fs::create_dir_all(root.join("AB").join("CD")).unwrap();
        fs::write(root.join("AB").join("CD").join("f".repeat(64)), b"z").unwrap();
        fs::write(root.join("aa").join("bb").join("e".repeat(64)), b"w").unwrap();

        let hs = walk_sharded_hashes(&root);
        assert_eq!(hs, vec![real]);
    }
}
