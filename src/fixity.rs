//! Fixity audit — hash-based integrity checking for the raw/derived stores
//! (task A1.3.3, frozen interface §6; design contract A1.3.1 §D3/§4).
//!
//! This module is the **verdict layer** of the fixity flow: it hashes stored
//! bytes, compares them against the expected content address, classifies the
//! result into [`Severity`], and renders machine-consumable report lines plus
//! a process exit code for the scrub jobs.
//!
//! It deliberately does **not** quarantine, repair, or write report files —
//! those are the job layer's responsibilities (design D3: quarantine format,
//! repair order, `reports/latest.json`, `ALERT`). Keeping the audit pure makes
//! it trivially testable and safe to run read-only.
//!
//! ## Severity model (per A1.3.1 §D3 partial-failure matrix)
//!
//! | Severity   | Condition                                   | Meaning |
//! |------------|---------------------------------------------|---------|
//! | `Ok`       | bytes read, hash == expected                | intact |
//! | `Warn`     | bytes unreadable (I/O error)                | store trouble; retry/alert (`warn→critical`) |
//! | `Critical` | bytes read, hash != expected                | corruption or replacement of immutable bytes |
//! | `Critical` | recorded object absent from a sharded store | evidence loss (see decision below) |
//!
//! ## Documented decisions (asymmetries are intentional, not accidents)
//!
//! 1. **Absence is context-dependent.** [`audit_file`] is a single-file probe
//!    with no manifest context: a missing file is `Warn` (the path may simply
//!    not be expected to exist). [`scan_store_sharded`] receives explicit
//!    `hashes` — *recorded* content addresses that must exist in the store —
//!    so an absent object there is `Critical` (design D3: "no good copy
//!    anywhere → critical"; the scrub exists precisely to catch silent
//!    deletion). Per-store absence may still be repairable from a peer — that
//!    policy lives in the replication job (A1.3.2), not here; this audit
//!    reports the raw verdict conservatively.
//! 2. **Malformed expected ids** (not 64 lowercase hex chars) in a scan are
//!    `Warn`: no object path is derivable, so neither integrity nor corruption
//!    can be honestly asserted. The finding says so in `detail`.
//! 3. **Hash comparison is ASCII-case-insensitive** (`expected` is kept as
//!    given, `actual` is always lowercase) — canonical form is lowercase
//!    (matches `RawStore`'s strictness), but a case difference in a caller's
//!    expected string must not masquerade as corruption.
//! 4. **`actual` is `Some(hash)` whenever the bytes could be read** (both
//!    `Ok` and mismatch); `None` when unreadable/absent/malformed.
//! 5. The full design contract (cursor, cadence, auto-repair, `ALERT` file)
//!    is implemented by the job layer on top of these primitives; this file
//!    stays dependency-light (`sha2`, `serde`, `serde_json`) and side-effect
//!    free except for reading the filesystem.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Fixity verdict for one object. Exit-code mapping lives in [`exit_code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Bytes read and hashed to the expected address.
    Ok,
    /// Could not read the bytes (I/O error, malformed id, single-probe absence).
    Warn,
    /// Hash mismatch, or a recorded object absent from a sharded store.
    Critical,
}

impl Severity {
    /// Stable lowercase string as used in reports and the JSONL output.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Ok => "ok",
            Severity::Warn => "warn",
            Severity::Critical => "critical",
        }
    }
}

/// One fixity observation. `Serialize`/`Deserialize` — this is the JSONL unit
/// of the fixity report (design D3: `reports/fixity-<utc-ts>.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixityFinding {
    /// Path that was examined (or the derived expected location for scans).
    pub path: String,
    /// Expected sha256 content address, as provided by the caller.
    pub expected: String,
    /// Actual sha256 of the stored bytes, when they could be read.
    pub actual: Option<String>,
    /// Verdict; see module docs for the exact rules.
    pub severity: Severity,
    /// Human-readable explanation (stable prefix before `:` where practical).
    pub detail: String,
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Lowercase hex encoding — local helper, no extra dependency.
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// sha256 of `bytes`, lowercase hex (64 chars).
fn hash_of(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    to_hex(h.finalize().as_slice())
}

/// Canonical id shape: exactly 64 lowercase hex chars (same rule as
/// `RawStore`; a hash becomes a path component and must not escape `root/`).
fn is_valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Sharded content-address layout, mirroring `RawStore`:
/// `root/<ab>/<cd>/<hash>` (first two / next two hex chars).
fn object_path(root: &Path, hash: &str) -> PathBuf {
    root.join(&hash[0..2]).join(&hash[2..4]).join(hash)
}

/// Shared audit core. `absent_is_critical` selects the absence policy:
/// `false` for the single-file probe, `true` for manifest-driven scans.
fn audit_impl(path: &Path, expected: &str, absent_is_critical: bool) -> FixityFinding {
    let path_s = path.display().to_string();
    match std::fs::read(path) {
        Ok(bytes) => {
            let actual = hash_of(&bytes);
            if actual.eq_ignore_ascii_case(expected) {
                FixityFinding {
                    path: path_s,
                    expected: expected.to_string(),
                    actual: Some(actual),
                    severity: Severity::Ok,
                    detail: "intact: stored bytes hash to the expected sha256".to_string(),
                }
            } else {
                FixityFinding {
                    path: path_s,
                    expected: expected.to_string(),
                    actual: Some(actual.clone()),
                    severity: Severity::Critical,
                    detail: format!(
                        "hash mismatch: stored bytes hash to {actual}, expected {expected} \
                         (corruption or replacement of immutable bytes; never silently \
                         repaired — see A1.3.1 D3)"
                    ),
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let (severity, detail) = if absent_is_critical {
                (
                    Severity::Critical,
                    "absent: recorded object missing from store (Critical per A1.3.1 D3 — \
                     a recorded content address with no object is evidence loss)"
                        .to_string(),
                )
            } else {
                (
                    Severity::Warn,
                    "absent: no file at path (single-file audit does not escalate; \
                     scan_store_sharded treats absent recorded objects as Critical)"
                        .to_string(),
                )
            };
            FixityFinding {
                path: path_s,
                expected: expected.to_string(),
                actual: None,
                severity,
                detail,
            }
        }
        Err(e) => FixityFinding {
            path: path_s,
            expected: expected.to_string(),
            actual: None,
            severity: Severity::Warn,
            detail: format!("unreadable: {e}"),
        },
    }
}

// ── public API (frozen interface §6) ────────────────────────────────────────

/// Audit one file's bytes against `expected_hash`.
///
/// - `Ok` — bytes read and hash matches;
/// - `Critical` — bytes read but hash differs (actual hash reported);
/// - `Warn` — unreadable (I/O error) or absent (single-file probe policy; see
///   module docs decision 1).
///
/// `expected_hash` should be a 64-char lowercase hex id (the `RawStore`
/// canonical form; comparison itself is case-insensitive). A malformed
/// `expected_hash` is **not** re-validated here and will surface as a
/// `Critical` mismatch against a genuine actual hash — callers feeding ids
/// from untrusted/manifest sources should validate first
/// ([`scan_store_sharded`] does).
pub fn audit_file(path: &std::path::Path, expected_hash: &str) -> FixityFinding {
    audit_impl(path, expected_hash, false)
}

/// Audit a set of recorded content addresses against a sharded store rooted at
/// `root` (object layout `root/<ab>/<cd>/<hash>` — `RawStore`-compatible).
///
/// Findings are returned in input order (deterministic; callers own any
/// sorting/grouping). Per design D3, **absent recorded objects are
/// `Critical`** here; malformed ids are `Warn` (no path derivable).
pub fn scan_store_sharded(root: &std::path::Path, hashes: &[String]) -> Vec<FixityFinding> {
    let mut out = Vec::with_capacity(hashes.len());
    for hash in hashes {
        if !is_valid_hash(hash) {
            out.push(FixityFinding {
                path: root.join(hash).display().to_string(),
                expected: hash.clone(),
                actual: None,
                severity: Severity::Warn,
                detail: "invalid sha256 hex id (not 64 lowercase hex chars): no object \
                         path derivable; not scanned"
                    .to_string(),
            });
            continue;
        }
        out.push(audit_impl(&object_path(root, hash), hash, true));
    }
    out
}

/// Render findings as JSONL: one JSON object per finding, then a final plain
/// summary line `ok=N warn=N critical=N` (always present, even when empty).
/// The summary line is *not* JSON by contract.
pub fn report_lines(findings: &[FixityFinding]) -> Vec<String> {
    let mut lines = Vec::with_capacity(findings.len() + 1);
    for f in findings {
        match serde_json::to_string(f) {
            Ok(s) => lines.push(s),
            // Unreachable for this struct (no non-string map keys, no floats);
            // kept so report rendering can never panic a scrub job.
            Err(e) => lines.push(format!("{{\"error\":\"serialize failed: {e}\"}}")),
        }
    }
    let mut ok = 0usize;
    let mut warn = 0usize;
    let mut critical = 0usize;
    for f in findings {
        match f.severity {
            Severity::Ok => ok += 1,
            Severity::Warn => warn += 1,
            Severity::Critical => critical += 1,
        }
    }
    lines.push(format!("ok={ok} warn={warn} critical={critical}"));
    lines
}

/// Process exit code for a set of findings (design D3 alerting contract):
/// `0` all ok / empty; `1` any warn (no critical); `2` any critical.
pub fn exit_code(findings: &[FixityFinding]) -> i32 {
    let mut code = 0;
    for f in findings {
        match f.severity {
            Severity::Ok => {}
            Severity::Warn => code = code.max(1),
            Severity::Critical => return 2,
        }
    }
    code
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    fn sha256_hex(bytes: &[u8]) -> String {
        hash_of(bytes)
    }

    /// Store `bytes` at their sharded content address under `root`; returns the
    /// hash. Mirrors what `RawStore::put_bytes` leaves on disk.
    fn put_sharded(root: &Path, bytes: &[u8]) -> String {
        let h = sha256_hex(bytes);
        let p = root.join(&h[0..2]).join(&h[2..4]).join(&h);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, bytes).unwrap();
        h
    }

    #[test]
    fn intact_file_is_ok_with_actual_hash() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("object.bin");
        fs::write(&p, b"fixity-test-bytes").unwrap();
        let expected = sha256_hex(b"fixity-test-bytes");

        let f = audit_file(&p, &expected);
        assert_eq!(f.severity, Severity::Ok);
        assert_eq!(f.expected, expected);
        assert_eq!(f.actual.as_deref(), Some(expected.as_str()));
        assert!(f.detail.contains("intact"), "detail: {}", f.detail);
        // Uppercase expectation must not masquerade as corruption (decision 3).
        let f2 = audit_file(&p, &expected.to_ascii_uppercase());
        assert_eq!(f2.severity, Severity::Ok);
    }

    #[test]
    fn corrupted_bytes_are_critical_and_report_actual_hash() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("object.bin");
        let good = b"the-original-bytes";
        let expected = sha256_hex(good);
        fs::write(&p, b"the-CORRUPTED-bytes").unwrap();

        let f = audit_file(&p, &expected);
        assert_eq!(f.severity, Severity::Critical);
        let actual = f.actual.expect("actual hash must be reported");
        assert_ne!(actual, expected);
        assert_eq!(actual, sha256_hex(b"the-CORRUPTED-bytes"));
        assert!(f.detail.contains("hash mismatch"), "detail: {}", f.detail);
    }

    #[test]
    fn absent_file_is_warn_in_single_audit() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("never-written.bin");
        let f = audit_file(&p, &sha256_hex(b"whatever"));
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.actual.is_none());
        assert!(f.detail.contains("absent"), "detail: {}", f.detail);
    }

    #[test]
    fn unreadable_is_warn() {
        let dir = tempfile::tempdir().unwrap();

        // Preference: simulate an unreadable file via permissions...
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let locked = dir.path().join("locked.bin");
            fs::write(&locked, b"data").unwrap();
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
            if fs::read(&locked).is_err() {
                let f = audit_file(&locked, &sha256_hex(b"data"));
                assert_eq!(f.severity, Severity::Warn);
                assert!(f.actual.is_none());
                assert!(f.detail.contains("unreadable"), "detail: {}", f.detail);
                // restore so tempdir cleanup can remove it
                fs::set_permissions(&locked, fs::Permissions::from_mode(0o644)).unwrap();
            } else {
                // ...but a privileged process reads mode-000 files anyway; fall
                // through to the deterministic I/O-error case below.
                eprintln!(
                    "note: permission-based unreadable simulation skipped \
                     (process can read mode 000 — privileged user)"
                );
            }
        }

        // Deterministic I/O error that holds even for root: a directory where a
        // file is expected (`read(2)` on a directory fails with EISDIR).
        let as_dir = dir.path().join("is-a-directory");
        fs::create_dir(&as_dir).unwrap();
        let f = audit_file(&as_dir, &sha256_hex(b""));
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.actual.is_none());
        assert!(f.detail.contains("unreadable"), "detail: {}", f.detail);
    }

    #[test]
    fn scan_store_sharded_mixed_set() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // 1) intact object
        let good_hash = put_sharded(root, b"intact-object");
        // 2) corrupted object: bytes at their content address replaced
        let corrupted_addr = put_sharded(root, b"original-content");
        let corrupted_path = object_path(root, &corrupted_addr);
        fs::write(&corrupted_path, b"replaced-content").unwrap();
        // 3) absent object: recorded but never written
        let absent_hash = sha256_hex(b"never-stored");
        // 4) malformed id
        let bogus = "not-a-sha256-id".to_string();

        let hashes = vec![
            good_hash.clone(),
            corrupted_addr.clone(),
            absent_hash.clone(),
            bogus.clone(),
        ];
        let findings = scan_store_sharded(root, &hashes);

        assert_eq!(findings.len(), 4);
        // order preserved (input order)
        assert_eq!(findings[0].expected, good_hash);
        assert_eq!(findings[1].expected, corrupted_addr);
        assert_eq!(findings[2].expected, absent_hash);
        assert_eq!(findings[3].expected, bogus);

        assert_eq!(findings[0].severity, Severity::Ok);
        assert_eq!(findings[1].severity, Severity::Critical);
        assert_eq!(findings[1].actual.as_deref(), Some(sha256_hex(b"replaced-content").as_str()));
        assert_eq!(findings[2].severity, Severity::Critical);
        assert!(findings[2].detail.contains("absent"), "detail: {}", findings[2].detail);
        assert!(findings[2].actual.is_none());
        assert_eq!(findings[3].severity, Severity::Warn);
        assert!(findings[3].detail.contains("invalid"), "detail: {}", findings[3].detail);
        // the malformed finding must not claim a real object path was checked
        assert!(findings[3].path.contains("not-a-sha256-id"));

        // sharded path shape is what RawStore would have written
        assert_eq!(
            findings[0].path,
            object_path(root, &good_hash).display().to_string()
        );

        // mixed set with a critical → 2
        assert_eq!(exit_code(&findings), 2);

        // missing object in scan is Critical even without any mismatch
        let only_missing = scan_store_sharded(root, &[sha256_hex(b"gone")]);
        assert_eq!(only_missing[0].severity, Severity::Critical);
        assert_eq!(exit_code(&only_missing), 2);
    }

    #[test]
    fn exit_codes_map_ok_warn_critical() {
        let mk = |severity: Severity| FixityFinding {
            path: "/x".to_string(),
            expected: "aa".to_string(),
            actual: None,
            severity,
            detail: "d".to_string(),
        };

        assert_eq!(exit_code(&[]), 0);
        assert_eq!(exit_code(&[mk(Severity::Ok), mk(Severity::Ok)]), 0);
        assert_eq!(exit_code(&[mk(Severity::Warn)]), 1);
        assert_eq!(exit_code(&[mk(Severity::Ok), mk(Severity::Warn)]), 1);
        // critical dominates warn
        assert_eq!(exit_code(&[mk(Severity::Warn), mk(Severity::Critical)]), 2);
        assert_eq!(exit_code(&[mk(Severity::Critical)]), 2);
        assert_eq!(
            exit_code(&[mk(Severity::Ok), mk(Severity::Warn), mk(Severity::Critical)]),
            2
        );
    }

    #[test]
    fn report_lines_are_jsonl_plus_summary() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let good = put_sharded(root, b"report-intact");
        let absent = sha256_hex(b"report-absent");
        let findings = scan_store_sharded(root, &[good.clone(), absent.clone()]);

        let lines = report_lines(&findings);
        assert_eq!(lines.len(), findings.len() + 1);

        // every finding line parses as a JSON object with the contract fields
        for (i, line) in lines[..findings.len()].iter().enumerate() {
            let v: serde_json::Value =
                serde_json::from_str(line).unwrap_or_else(|e| panic!("line {i} not JSON: {e}: {line}"));
            assert!(v.get("path").is_some(), "line {i} missing path");
            assert!(v.get("expected").is_some(), "line {i} missing expected");
            assert!(v.get("actual").is_some(), "line {i} missing actual key");
            assert!(v.get("severity").is_some(), "line {i} missing severity");
            assert!(v.get("detail").is_some(), "line {i} missing detail");
            let sev = v["severity"].as_str().unwrap();
            assert!(
                matches!(sev, "ok" | "warn" | "critical"),
                "line {i} severity {sev:?} not a stable string"
            );
            assert_eq!(sev, findings[i].severity.as_str());
        }
        assert_eq!(lines[0].contains("\"severity\":\"ok\""), true);

        // summary line is the exact contract shape, not JSON
        assert_eq!(lines.last().unwrap(), "ok=1 warn=0 critical=1");
        assert!(serde_json::from_str::<serde_json::Value>(lines.last().unwrap()).is_err());

        // empty findings → just the (zeroed) summary
        assert_eq!(report_lines(&[]), vec!["ok=0 warn=0 critical=0".to_string()]);
    }

    #[test]
    fn finding_and_severity_serde_roundtrip() {
        let f = FixityFinding {
            path: "/store/ab/cd/deadbeef".to_string(),
            expected: "deadbeef".to_string(),
            actual: None,
            severity: Severity::Critical,
            detail: "hash mismatch".to_string(),
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"severity\":\"critical\""));
        assert!(json.contains("\"actual\":null"));
        let back: FixityFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);

        let all = [
            (Severity::Ok, "\"ok\""),
            (Severity::Warn, "\"warn\""),
            (Severity::Critical, "\"critical\""),
        ];
        for (sev, lit) in all {
            assert_eq!(serde_json::to_string(&sev).unwrap(), lit);
        }
    }
}
