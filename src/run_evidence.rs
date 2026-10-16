//! Run evidence — per-run JSONL telemetry for detection-ops (P1 W3/W4).
//!
//! One run = one evidence file (`$TALLOW_RUN_EVIDENCE_DIR/run-<id>.jsonl`),
//! written append-only as JSONL records `{"ts","seq","run_id","kind","payload"}`.
//! The sink is **environment-gated**: without `TALLOW_RUN_EVIDENCE_DIR` every
//! call is a cheap no-op, so ordinary runs pay nothing and nothing is written
//! implicitly (evidence is opt-in, like every other artifact surface here).
//!
//! Two consumer groups:
//!
//! - **Escalation traces (W3-S2):** `src/browser/antibot.rs` records one
//!   `"escalation"` record per retry decision (ladder position + trigger
//!   signals), so blocks are attributable per target in run evidence.
//! - **Detection-ops cycle (W4-D1):** the quiet-window gate, canary page
//!   render/verify, response scanning, and the alert sweep all record here —
//!   the pure modules ([`crate::quiet_window`], [`crate::canary_page`],
//!   [`crate::canary_monitor`], [`crate::canary_tokens`]) get their runtime
//!   hook through this module (see `tallow canary cycle` in
//!   `src/cli/canary_cmd.rs`), never tests alone.
//!
//! `run_id` is `TALLOW_TOR_STREAM_ID` when set (the same identity that keys
//! the per-run Tor circuit, so evidence and egress line up), else `run-<pid>`.

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// Environment variable enabling the evidence sink. Unset → no-op.
pub const RUN_EVIDENCE_DIR_ENV: &str = "TALLOW_RUN_EVIDENCE_DIR";

static SEQ: AtomicU64 = AtomicU64::new(0);

/// The run identity: the per-run stream id when set, else `run-<pid>`.
pub fn run_id() -> String {
    match std::env::var(crate::runtime::fetch::TOR_STREAM_ID_ENV) {
        Ok(v) if !v.trim().is_empty() => sanitize_id(v.trim()),
        _ => format!("run-{}", std::process::id()),
    }
}

fn sanitize_id(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect();
    if cleaned.is_empty() {
        format!("run-{}", std::process::id())
    } else {
        cleaned
    }
}

/// The evidence directory, when the sink is enabled.
pub fn evidence_dir() -> Option<PathBuf> {
    match std::env::var(RUN_EVIDENCE_DIR_ENV) {
        Ok(v) if !v.trim().is_empty() => Some(PathBuf::from(v.trim())),
        _ => None,
    }
}

/// Epoch milliseconds (evidence timestamps; no wall-clock formatting here).
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Append one record to the run's evidence file. Returns `false` (writing
/// nothing) when the sink is disabled or the write fails — evidence must
/// never abort the run it observes; callers that need hard failure check the
/// return.
pub fn record(kind: &str, payload: serde_json::Value) -> bool {
    let Some(dir) = evidence_dir() else {
        return false;
    };
    if std::fs::create_dir_all(&dir).is_err() {
        return false;
    }
    let path = dir.join(format!("run-{}.jsonl", run_id()));
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let line = serde_json::json!({
        "ts": now_ms(),
        "seq": seq,
        "run_id": run_id(),
        "kind": kind,
        "payload": payload,
    });
    let mut line = line.to_string();
    line.push('\n');
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut fh) => fh.write_all(line.as_bytes()).is_ok(),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Detection-ops wiring (W4-D1): quiet-window + canary modules, runtime-usable
// ---------------------------------------------------------------------------

use crate::canary_monitor::{self, LeakAlert, Observation};
use crate::canary_page::{self, CanaryPageConfig};
use crate::canary_tokens;
use crate::quiet_window::{self, QuietConfig};

/// Consult the quiet-window policy for one ingest decision and record it.
///
/// Wraps [`quiet_window::ingest_allowed`] (windows + consolidation cooldown):
/// `true` = ingest may proceed. The decision (inputs + verdict) lands in run
/// evidence so a quiet-window skip is attributable, never silent.
pub fn quiet_gate(cfg: &QuietConfig, last_ingest_ms: Option<i64>, now_ms: i64) -> bool {
    let allowed = quiet_window::ingest_allowed(cfg, last_ingest_ms, now_ms);
    record(
        "quiet_window",
        serde_json::json!({
            "check": "ingest_allowed",
            "last_ingest_ms": last_ingest_ms,
            "now_ms": now_ms,
            "allowed": allowed,
            "windows": cfg.windows.len(),
            "consolidation_ms": cfg.consolidation_ms,
        }),
    );
    allowed
}

/// Batch pending items into digest chunks and record the batching decision.
pub fn digest_pending(
    cfg: &QuietConfig,
    items: &[String],
) -> Result<Vec<Vec<String>>, quiet_window::QuietError> {
    let batches = quiet_window::digest_batches(cfg, items)?;
    record(
        "quiet_window",
        serde_json::json!({
            "check": "digest_batches",
            "pending": items.len(),
            "digest_size": cfg.digest_size,
            "batches": batches.len(),
            "should_digest": quiet_window::should_digest(cfg, items.len()),
        }),
    );
    Ok(batches)
}

/// Render a canary page, verify its embedded tokens, and record both.
///
/// Wraps [`canary_page::render_page`] + [`canary_page::verify_embed`]; returns
/// the rendered page plus the verified token count. A verification failure is
/// loud (Err), never a quiet pass.
pub fn canary_page_check(
    cfg: &CanaryPageConfig,
) -> Result<(String, usize), canary_page::CanaryPageError> {
    let page = canary_page::render_page(cfg)?;
    let verified = canary_page::verify_embed(cfg)?;
    record(
        "canary_page",
        serde_json::json!({
            "site": cfg.site,
            "title": cfg.title,
            "count": cfg.count,
            "page_bytes": page.len(),
            "verified_tokens": verified,
            "tokens_in_page": canary_page::tokens_in(&page).len(),
        }),
    );
    Ok((page, verified))
}

/// Scan observed text for the investigation's canaries and record the scan.
///
/// Wraps [`canary_tokens::scan`]; returns the hits (each with byte offset) so
/// callers can act, and records a `canary_scan` evidence row either way (a
/// clean scan is evidence too).
pub fn scan_observation(canaries: &[String], origin: &str, text: &str) -> Vec<canary_tokens::CanaryHit> {
    let hits = canary_tokens::scan(text, canaries);
    record(
        "canary_scan",
        serde_json::json!({
            "origin": origin,
            "text_bytes": text.len(),
            "canaries": canaries.len(),
            "hits": hits.len(),
        }),
    );
    hits
}

/// Sweep observations for leaked canaries and record the sweep + report.
///
/// Wraps [`canary_monitor::sweep`] + [`canary_monitor::alert_report`]; the
/// rendered report is returned (callers write it beside the evidence) and the
/// alert set lands in the JSONL so a leak is attributable per origin.
pub fn sweep_observations(observations: &[Observation], canaries: &[String]) -> (Vec<LeakAlert>, String) {
    let alerts = canary_monitor::sweep(observations, canaries);
    let report = canary_monitor::alert_report(&alerts);
    record(
        "canary_sweep",
        serde_json::json!({
            "observations": observations.len(),
            "canaries": canaries.len(),
            "alerts": alerts.len(),
            "alert_details": alerts
                .iter()
                .map(|a| serde_json::json!({
                    "canary": a.canary,
                    "origin": a.origin,
                    "offset": a.offset,
                    "severity": a.severity,
                }))
                .collect::<Vec<_>>(),
        }),
    );
    (alerts, report)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Record explicit unknowns ("we could not establish X") for the current run.
///
/// Fixes the record `kind` and the payload shape, so a limitation is always
/// attributable as one. An empty list is a successful **no-op** — a caller
/// with nothing to declare needs no branch. Returns `false` only when the sink
/// is enabled and the write failed; a disabled sink is not an error (same
/// contract as [`record`]).
pub fn record_limitations(items: &[String]) -> bool {
    if items.is_empty() {
        return true;
    }
    record(
        "limitations",
        serde_json::json!({
            "count": items.len(),
            "limitations": items,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Env mutation is process-global; serialize on the shared egress lock
    /// (T-128) AND a module-local guard so this module's tests cannot race
    /// each other even if the shared lock is held elsewhere.
    static LOCAL_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_evidence_dir<F: FnOnce(&std::path::Path)>(f: F) {
        let _shared = crate::runtime::egress_http::env_lock();
        let _local = LOCAL_ENV_LOCK.lock().expect("local env lock");
        let dir = std::env::temp_dir().join(format!(
            "tallow-run-evidence-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let prev = std::env::var(RUN_EVIDENCE_DIR_ENV).ok();
        unsafe { std::env::set_var(RUN_EVIDENCE_DIR_ENV, &dir) };
        f(&dir);
        match prev {
            Some(v) => unsafe { std::env::set_var(RUN_EVIDENCE_DIR_ENV, v) },
            None => unsafe { std::env::remove_var(RUN_EVIDENCE_DIR_ENV) },
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sink_is_a_no_op_without_the_env() {
        let _shared = crate::runtime::egress_http::env_lock();
        let _local = LOCAL_ENV_LOCK.lock().expect("local env lock");
        let prev = std::env::var(RUN_EVIDENCE_DIR_ENV).ok();
        unsafe { std::env::remove_var(RUN_EVIDENCE_DIR_ENV) };
        assert!(!record("test", serde_json::json!({"x": 1})));
        assert!(evidence_dir().is_none());
        if let Some(v) = prev {
            unsafe { std::env::set_var(RUN_EVIDENCE_DIR_ENV, v) };
        }
    }

    #[test]
    fn limitations_records_carry_their_items() {
        with_evidence_dir(|dir| {
            let items = vec![
                "selector 'h1.title' never matched".to_string(),
                "tier refused: no credential".to_string(),
            ];
            assert!(record_limitations(&items));
            let path = dir.join(format!("run-{}.jsonl", run_id()));
            let body = std::fs::read_to_string(&path).expect("evidence file");
            let line = body.lines().next().expect("one line");
            let v: serde_json::Value = serde_json::from_str(line).expect("json");
            assert_eq!(v["kind"], "limitations");
            assert_eq!(v["payload"]["count"], 2);
            assert_eq!(v["payload"]["limitations"][0], items[0]);
            assert_eq!(v["payload"]["limitations"][1], items[1]);
        });
    }

    #[test]
    fn empty_limitations_is_a_no_op() {
        with_evidence_dir(|dir| {
            assert!(record_limitations(&[]));
            let path = dir.join(format!("run-{}.jsonl", run_id()));
            assert!(
                !path.exists(),
                "an empty limitation set must write nothing at all"
            );
        });
    }

    #[test]
    fn records_append_as_jsonl() {
        with_evidence_dir(|dir| {
            assert!(record("unit", serde_json::json!({"a": 1})));
            assert!(record("unit", serde_json::json!({"a": 2})));
            let path = dir.join(format!("run-{}.jsonl", run_id()));
            let body = std::fs::read_to_string(&path).expect("evidence file");
            let lines: Vec<&str> = body.lines().collect();
            assert_eq!(lines.len(), 2, "two records must append two lines");
            for line in lines {
                let v: serde_json::Value = serde_json::from_str(line).expect("jsonl line");
                assert_eq!(v["kind"], "unit");
                assert!(v["ts"].as_i64().unwrap_or(0) > 0);
                assert_eq!(v["run_id"], run_id());
            }
        });
    }

    #[test]
    fn detection_ops_cycle_wires_through_and_records() {
        with_evidence_dir(|dir| {
            // quiet window: default config allows ingress now.
            let cfg = QuietConfig {
                windows: vec![],
                consolidation_ms: 0,
                digest_size: 3,
                interrupt_severity: 2,
            };
            assert!(quiet_gate(&cfg, None, now_ms()));
            let batches = digest_pending(
                &cfg,
                &["a".into(), "b".into(), "c".into(), "d".into()],
            )
            .expect("digest");
            assert_eq!(batches.len(), 2, "4 items / size 3 = 2 batches");

            // canary page: render + verify round-trips.
            let page_cfg = CanaryPageConfig {
                site: "sendtallow.com".into(),
                title: "Evidence page".into(),
                count: 3,
            };
            let (page, verified) = canary_page_check(&page_cfg).expect("canary page");
            assert_eq!(verified, 3);
            assert!(page.contains("TLW-"));

            // planting + scanning: the page's own tokens are the canaries.
            let canaries = canary_page::tokens_in(&page);
            assert_eq!(canaries.len(), 3);
            let mut obs = vec![Observation {
                origin: "unit/clean".into(),
                text: "nothing planted here".into(),
            }];
            let clean_hits = scan_observation(&canaries, "unit/clean", &obs[0].text);
            assert!(clean_hits.is_empty());
            // Control: an observation carrying a planted token MUST fire.
            obs.push(Observation {
                origin: "unit/leak-control".into(),
                text: format!("prefix {} suffix", canaries[0]),
            });
            let (alerts, report) = sweep_observations(&obs, &canaries);
            assert_eq!(alerts.len(), 1, "the planted control must alert: {report}");
            assert_eq!(alerts[0].origin, "unit/leak-control");
            assert!(report.contains(canary_monitor::ALERT_HEADER));

            let path = dir.join(format!("run-{}.jsonl", run_id()));
            let body = std::fs::read_to_string(&path).expect("evidence file");
            let kinds: Vec<String> = body
                .lines()
                .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("line")["kind"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string())
                .collect();
            for want in ["quiet_window", "canary_page", "canary_scan", "canary_sweep"] {
                assert!(
                    kinds.iter().any(|k| k == want),
                    "kind {want:?} must be recorded; got {kinds:?}"
                );
            }
        });
    }
}
