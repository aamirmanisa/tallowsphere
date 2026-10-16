//! Fixity drill — end-to-end exercises of the fixity sweep job (A1.3.3b,
//! frozen interface §3) against real on-disk stores in tempdirs.
//!
//! Three scenarios, one per corruption/loss class:
//!
//! 1. **Mirror byte-flip** — a single flipped byte in the mirror copy is
//!    detected (hash mismatch), auto-repaired from the primary (verified
//!    good peer), the conflicting bytes kept as quarantine evidence, and the
//!    event recorded as `warn` per the job's severity policy (design D3:
//!    critical only when no good copy exists anywhere).
//! 2. **Both copies corrupt** — nothing repairable: every copy stays
//!    `critical`, `ALERT` is written naming both objects, and **nothing is
//!    deleted** (objects preserved byte-for-byte; no repair attempted).
//! 3. **Primary object deleted** — absence detected in the primary store,
//!    restored from the mirror via `replication::restore_missing`, recorded
//!    as `warn` with the detection story.
//!
//! Every scenario asserts against both the returned [`SweepOutcome`] and the
//! written report set (`fixity-<ts>.json`, `latest.json`, `ALERT`).

use std::fs;
use std::path::{Path, PathBuf};

use tallow::fixity_job::{run_sweep, ALERT_FILE, CURSOR_FILE, LATEST_REPORT_FILE};
use tallow::replication::{sha256_file, sha256_hex};

// ── helpers ─────────────────────────────────────────────────────────────────

/// Sharded content-address path: `root/<ab>/<cd>/<hash>`.
fn shard_path(root: &Path, hash: &str) -> PathBuf {
    root.join(&hash[0..2]).join(&hash[2..4]).join(hash)
}

/// Store `bytes` at their sharded content address under `root`; returns hash.
fn put_sharded(root: &Path, bytes: &[u8]) -> String {
    let h = sha256_hex(bytes);
    let p = shard_path(root, &h);
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

/// The single finding for `path`, or panic.
fn finding_for<'a>(rows: &'a [serde_json::Value], path: &Path) -> &'a serde_json::Value {
    let want = path.display().to_string();
    rows.iter()
        .find(|r| r.get("path").and_then(|v| v.as_str()) == Some(want.as_str()))
        .unwrap_or_else(|| panic!("no finding for {}", want))
}

/// `*.quarantine-*` evidence files in `dir`.
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

/// A tempdir holding the two stores + the reports dir for one scenario.
struct Fixture {
    _dir: tempfile::TempDir,
    primary: PathBuf,
    mirror: PathBuf,
    reports: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("stores/primary");
        let mirror = dir.path().join("stores/mirror");
        let reports = dir.path().join("stores/reports");
        fs::create_dir_all(&primary).unwrap();
        fs::create_dir_all(&mirror).unwrap();
        Self {
            _dir: dir,
            primary,
            mirror,
            reports,
        }
    }
}

// ── scenario 1 ──────────────────────────────────────────────────────────────

#[test]
fn scenario1_mirror_byte_flip_detected_and_repaired() {
    let fx = Fixture::new();
    let good = b"drill-object-payload".as_slice();
    let h = put_sharded(&fx.primary, good);
    put_sharded(&fx.mirror, good);

    // Flip the mirror copy: same object path, different bytes.
    let mpath = shard_path(&fx.mirror, &h);
    fs::write(&mpath, b"drill-object-payloAd").unwrap(); // one byte flipped

    let out = run_sweep(&fx.primary, &fx.mirror, &fx.reports, 1_760_000_000_100);

    // Severity policy: detected → repaired from a verified-good peer → warn.
    assert_eq!(out.exit_code, 1, "warn-class outcome");
    assert_eq!(out.critical_count, 0);
    assert!(out.report_path.exists());
    assert_eq!(
        fs::read_to_string(&out.report_path).unwrap(),
        fs::read_to_string(fx.reports.join(LATEST_REPORT_FILE)).unwrap(),
        "latest.json mirrors the timestamped report"
    );
    assert!(
        !fx.reports.join(ALERT_FILE).exists(),
        "no ALERT when every critical was repaired"
    );

    // Detection is recorded, not silent.
    let rows = read_jsonl(&out.report_path);
    let row = finding_for(&rows, &mpath);
    assert_eq!(
        row.get("severity").and_then(|v| v.as_str()),
        Some("warn"),
        "repaired finding is warn per policy: {row}"
    );
    let det = row.get("detail").and_then(|v| v.as_str()).unwrap();
    assert!(det.contains("hash mismatch"), "detail records detection: {det}");
    assert!(det.contains("auto-repaired"), "detail records repair: {det}");

    // The mirror copy is byte-restored and re-verifies at its address.
    assert_eq!(fs::read(&mpath).unwrap(), good);
    assert_eq!(sha256_file(&mpath).unwrap(), h);

    // Corrupted bytes are preserved as quarantine evidence (never deleted).
    let q = quarantine_files(mpath.parent().unwrap());
    assert_eq!(q.len(), 1, "one quarantine file expected");
    assert_eq!(fs::read(&q[0]).unwrap(), b"drill-object-payloAd");

    // Cursor checkpoint written (optional §3 item).
    assert!(fx.reports.join(CURSOR_FILE).exists());
}

// ── scenario 2 ──────────────────────────────────────────────────────────────

#[test]
fn scenario2_both_copies_bad_critical_alert_nothing_deleted() {
    let fx = Fixture::new();
    let h = put_sharded(&fx.primary, b"both-copies-bad");
    put_sharded(&fx.mirror, b"both-copies-bad");
    let ppath = shard_path(&fx.primary, &h);
    let mpath = shard_path(&fx.mirror, &h);
    fs::write(&ppath, b"primary rotted").unwrap();
    fs::write(&mpath, b"mirror rotted").unwrap();

    let out = run_sweep(&fx.primary, &fx.mirror, &fx.reports, 1_760_000_000_200);

    assert_eq!(out.exit_code, 2, "critical-class outcome");
    assert_eq!(out.critical_count, 2, "both stores critical");
    assert!(out.report_path.exists());

    // ALERT names both affected objects.
    let alert = fs::read_to_string(fx.reports.join(ALERT_FILE)).unwrap();
    assert!(alert.contains("FIXITY ALERT"), "alert: {alert}");
    assert!(alert.contains(ppath.display().to_string().as_str()));
    assert!(alert.contains(mpath.display().to_string().as_str()));

    // Report rows carry critical for both paths.
    let rows = read_jsonl(&out.report_path);
    for p in [&ppath, &mpath] {
        assert_eq!(
            finding_for(&rows, p).get("severity").and_then(|v| v.as_str()),
            Some("critical"),
            "no good copy anywhere → critical"
        );
    }

    // Nothing deleted: corrupted objects preserved byte-for-byte, and no
    // repair was attempted (no verified-good peer) → no quarantine files.
    assert_eq!(fs::read(&ppath).unwrap(), b"primary rotted");
    assert_eq!(fs::read(&mpath).unwrap(), b"mirror rotted");
    assert!(quarantine_files(ppath.parent().unwrap()).is_empty());
    assert!(quarantine_files(mpath.parent().unwrap()).is_empty());

    // latest.json also reflects the critical summary.
    let latest = fs::read_to_string(fx.reports.join(LATEST_REPORT_FILE)).unwrap();
    assert!(latest.ends_with("ok=0 warn=0 critical=2\n"), "latest: {latest}");
}

// ── scenario 3 ──────────────────────────────────────────────────────────────

#[test]
fn scenario3_deleted_primary_object_restored_from_mirror() {
    let fx = Fixture::new();
    let good = b"restore-me-from-mirror".as_slice();
    let h = put_sharded(&fx.primary, good);
    put_sharded(&fx.mirror, good);
    let ppath = shard_path(&fx.primary, &h);
    fs::remove_file(&ppath).unwrap();
    assert!(!ppath.exists());

    let out = run_sweep(&fx.primary, &fx.mirror, &fx.reports, 1_760_000_000_300);

    // Restored → warn (recorded), the mirror still holds its verified copy.
    assert_eq!(out.exit_code, 1);
    assert_eq!(out.critical_count, 0);
    assert!(!fx.reports.join(ALERT_FILE).exists());

    // Primary object is back at its content address, hash-verified.
    assert_eq!(fs::read(&ppath).unwrap(), good);
    assert_eq!(sha256_file(&ppath).unwrap(), h);

    // The mirror copy was untouched (never a delete source or target).
    let mpath = shard_path(&fx.mirror, &h);
    assert_eq!(fs::read(&mpath).unwrap(), good);

    // Detection story present in the report.
    let rows = read_jsonl(&out.report_path);
    let row = finding_for(&rows, &ppath);
    assert_eq!(row.get("severity").and_then(|v| v.as_str()), Some("warn"));
    let det = row.get("detail").and_then(|v| v.as_str()).unwrap();
    assert!(det.contains("absent"), "detail records absence: {det}");
    assert!(det.contains("restored from peer"), "detail records restore: {det}");

    // A missing target needed no quarantine; nothing else was touched.
    assert!(quarantine_files(ppath.parent().unwrap()).is_empty());
    assert!(quarantine_files(mpath.parent().unwrap()).is_empty());
}
