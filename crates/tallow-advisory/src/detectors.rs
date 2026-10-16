//! Detectors v1 — deterministic, explainable, read-only.
//!
//! Jobs detectors work on projected [`JobRun`]s; mesh detectors work on the
//! parsed `tallow-mesh-snapshot/v1` JSON. Every finding carries evidence and a
//! human suggestion. Nothing here acts.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use crate::findings::{Finding, Severity};
use crate::ledger::{JobRun, LedgerReport};

/// Expected cadence per recipe (minutes), from `--expect <file>`.
#[derive(Debug, Default, Clone)]
pub struct Expectations(pub BTreeMap<String, u64>);

impl Expectations {
    /// Parse `{"recipe": {"every_minutes": N}}` (also accepts a bare number).
    pub fn parse(v: &Value) -> Self {
        let mut m = BTreeMap::new();
        if let Some(obj) = v.as_object() {
            for (k, val) in obj {
                let n = val
                    .get("every_minutes")
                    .and_then(Value::as_u64)
                    .or_else(|| val.as_u64());
                if let Some(n) = n {
                    m.insert(k.clone(), n);
                }
            }
        }
        Self(m)
    }
}

/// Everything the detectors see (all read-only references).
pub struct Inputs<'a> {
    pub ledger: &'a LedgerReport,
    pub mesh: Option<&'a Value>,
    pub peers_allowlist: Option<&'a BTreeSet<String>>,
    pub expectations: Option<&'a Expectations>,
    pub now_ms: i64,
    pub lookback_days: u32,
}

pub fn run_all(inp: &Inputs) -> Vec<Finding> {
    let mut out = Vec::new();
    ledger_findings(inp, &mut out);
    jobs_findings(inp, &mut out);
    mesh_findings(inp, &mut out);
    out
}

// ---------------------------------------------------------------- ledger --

fn ledger_findings(inp: &Inputs, out: &mut Vec<Finding>) {
    let mut ev = BTreeMap::new();
    ev.insert("rows".into(), json!(inp.ledger.rows));
    ev.insert("errors".into(), json!(inp.ledger.chain_errors));
    if !inp.ledger.chain_ok {
        out.push(Finding::new(
            "ledger.chain",
            Severity::Critical,
            "ledger",
            format!(
                "receipt chain verification FAILED ({} error(s)) — the ledger cannot be trusted until explained",
                inp.ledger.chain_errors.len()
            ),
            "investigate before trusting any receipt (verify-all harness; do NOT append to this ledger)",
            ev,
        ));
    }
    if inp.ledger.rows == 0 {
        out.push(Finding::new(
            "ledger.empty",
            Severity::Info,
            "ledger",
            "no receipts recorded yet".to_string(),
            "nothing to do — this is informational until the first runs land",
            BTreeMap::new(),
        ));
    }
}

// ------------------------------------------------------------------ jobs --

fn window_runs<'a>(ledger: &'a LedgerReport, now_ms: i64, days: u32) -> Vec<&'a JobRun> {
    let cutoff = now_ms - (days as i64) * 86_400_000;
    ledger.runs.iter().filter(|r| r.ts_ms >= cutoff).collect()
}

fn per_recipe<'a>(runs: &[&'a JobRun]) -> BTreeMap<String, Vec<&'a JobRun>> {
    let mut m: BTreeMap<String, Vec<&JobRun>> = BTreeMap::new();
    for r in runs {
        m.entry(r.recipe.clone()).or_default().push(r);
    }
    for v in m.values_mut() {
        v.sort_by_key(|r| r.seq);
    }
    m
}

fn jobs_findings(inp: &Inputs, out: &mut Vec<Finding>) {
    let ledger = inp.ledger;
    let runs = window_runs(ledger, inp.now_ms, inp.lookback_days);
    let by_recipe = per_recipe(&runs);

    for (recipe, rs) in &by_recipe {
        let n = rs.len() as u64;
        let fails = rs.iter().filter(|r| !r.ok).count() as u64;

        // failure rate
        if n >= 3 && fails * 2 >= n {
            let mut ev = BTreeMap::new();
            ev.insert("runs".into(), json!(n));
            ev.insert("fails".into(), json!(fails));
            ev.insert("window_days".into(), json!(inp.lookback_days));
            out.push(Finding::new(
                "jobs.failure-rate",
                Severity::Warn,
                recipe.clone(),
                format!(
                    "{fails}/{n} runs failed in the last {} day(s)",
                    inp.lookback_days
                ),
                "inspect the failing receipts (exit codes, timeouts); consider pausing the recipe",
                ev,
            ));
        }

        // trailing consecutive failures
        let mut streak = 0u64;
        for r in rs.iter().rev() {
            if r.ok {
                break;
            }
            streak += 1;
        }
        if streak >= 3 {
            let mut ev = BTreeMap::new();
            ev.insert("consecutive_failures".into(), json!(streak));
            out.push(Finding::new(
                "jobs.consecutive-failures",
                Severity::Warn,
                recipe.clone(),
                format!("{streak} consecutive failures — the recipe is not recovering"),
                "check the environment it depends on (egress, endpoints, paths) before re-running",
                ev,
            ));
        }

        // retry storm
        let retries = rs.iter().filter(|r| r.attempt > 1).count() as u64;
        if retries >= 3 {
            let mut ev = BTreeMap::new();
            ev.insert("retry_attempts".into(), json!(retries));
            out.push(Finding::new(
                "jobs.retry-storm",
                Severity::Warn,
                recipe.clone(),
                format!("{retries} retry attempts in the window — something is flapping"),
                "identify the intermittent failure; consider backoff or a pause",
                ev,
            ));
        }

        // egress drift (security-relevant): report the most recent egress
        // transition in the window (latest adjacent pair that differs)
        let with_egress: Vec<&JobRun> = rs.iter().copied().filter(|r| r.egress.is_some()).collect();
        if with_egress.len() >= 2 {
            let mut transition: Option<(String, String, u64)> = None;
            for w in 1..with_egress.len() {
                if with_egress[w].egress != with_egress[w - 1].egress {
                    transition = Some((
                        with_egress[w - 1].egress.clone().unwrap(),
                        with_egress[w].egress.clone().unwrap(),
                        with_egress[w].seq,
                    ));
                }
            }
            if let Some((from, to, seq)) = transition {
                let mut ev = BTreeMap::new();
                ev.insert("from".into(), json!(from));
                ev.insert("to".into(), json!(to));
                ev.insert("seq".into(), json!(seq));
                out.push(Finding::new(
                    "jobs.egress-drift",
                    Severity::Warn,
                    recipe.clone(),
                    format!("egress policy changed '{from}' → '{to}' (at seq {seq})"),
                    "confirm this change is intended — egress is a privacy-relevant switch",
                    ev,
                ));
            }
        }

        // duration regression: latest first-attempt run vs median of prior
        // first-attempt runs
        let firsts: Vec<&JobRun> = rs.iter().copied().filter(|r| r.attempt == 1).collect();
        if firsts.len() >= 4 {
            let mut prior: Vec<i64> = firsts[..firsts.len() - 1]
                .iter()
                .map(|r| r.duration_ms)
                .collect();
            prior.sort_unstable();
            let med = prior[prior.len() / 2];
            let last = firsts[firsts.len() - 1].duration_ms;
            if med > 0 && last > 3 * med && last > 2_000 {
                let mut ev = BTreeMap::new();
                ev.insert("last_ms".into(), json!(last));
                ev.insert("median_ms".into(), json!(med));
                out.push(Finding::new(
                    "jobs.duration-regression",
                    Severity::Info,
                    recipe.clone(),
                    format!("latest run took {last} ms vs prior median {med} ms (>3x)"),
                    "watch the next few runs — slow drift may harden into timeouts",
                    ev,
                ));
            }
        }

        // missed schedule (needs expectations)
        if let Some(exp) = inp.expectations {
            if let Some(every) = exp.0.get(recipe) {
                if let Some(last) = rs.last() {
                    let age_ms = inp.now_ms - last.ts_ms;
                    let budget_ms = (*every as i64) * 60_000 * 2;
                    if age_ms > budget_ms {
                        let mut ev = BTreeMap::new();
                        ev.insert("last_run_age_min".into(), json!(age_ms / 60_000));
                        ev.insert("every_minutes".into(), json!(every));
                        out.push(Finding::new(
                            "jobs.stale-schedule",
                            Severity::Warn,
                            recipe.clone(),
                            format!(
                                "no run for {} min (cadence {} min, 2x budget exceeded)",
                                age_ms / 60_000,
                                every
                            ),
                            "check the scheduler is running and the recipe is still enabled",
                            ev,
                        ));
                    }
                }
            }
        }
    }

    // recipes known only from expectations but absent from the window
    if let Some(exp) = inp.expectations {
        for recipe in exp.0.keys() {
            if !by_recipe.contains_key(recipe) {
                let mut ev = BTreeMap::new();
                ev.insert("every_minutes".into(), json!(exp.0[recipe]));
                out.push(Finding::new(
                    "jobs.never-ran",
                    Severity::Warn,
                    recipe.clone(),
                    "recipe has an expected cadence but no runs in the window".to_string(),
                    "confirm it was ever started (scheduler enabled? recipe path correct?)",
                    ev,
                ));
            }
        }
    }
}

// ------------------------------------------------------------------ mesh --

fn mesh_peer_fp(p: &Value) -> String {
    p.get("fp")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn mesh_findings(inp: &Inputs, out: &mut Vec<Finding>) {
    let Some(m) = inp.mesh else { return };

    // snapshot freshness
    if let Some(ts) = m.get("generated_ts").and_then(Value::as_i64) {
        let age_s = ((inp.now_ms - ts) / 1000).max(0);
        if age_s > 3_600 {
            let mut ev = BTreeMap::new();
            ev.insert("age_s".into(), json!(age_s));
            out.push(Finding::new(
                "mesh.snapshot-stale",
                Severity::Critical,
                "mesh-snapshot",
                format!("mesh snapshot is {age_s}s old (>1h) — the mesh view is dark"),
                "check the snapshot writer timer / wg0 on the host",
                ev,
            ));
        } else if age_s > 120 {
            let mut ev = BTreeMap::new();
            ev.insert("age_s".into(), json!(age_s));
            out.push(Finding::new(
                "mesh.snapshot-stale",
                Severity::Warn,
                "mesh-snapshot",
                format!("mesh snapshot is {age_s}s old (>120s) — writer cycle may be missing"),
                "verify the writer timer after the 2.1 deploy window",
                ev,
            ));
        }
    }

    let peers = m
        .get("peers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    // interface down
    let up = m
        .get("iface")
        .and_then(|i| i.get("up"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !up {
        out.push(Finding::new(
            "mesh.iface-down",
            Severity::Warn,
            "mesh",
            "wg0 interface is not up in the snapshot".to_string(),
            "check the mesh unit on the host (wg-quick@wg0)",
            BTreeMap::new(),
        ));
    }

    // per-peer checks
    let mut seen_ips: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut seen_fps: BTreeSet<String> = BTreeSet::new();
    for p in &peers {
        let name = p
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("(unnamed)")
            .to_string();
        let fp = mesh_peer_fp(p);
        seen_fps.insert(fp.clone());
        let rx = p.get("rx_bytes").and_then(Value::as_i64).unwrap_or(0);
        let hs = p.get("handshake_age_s").and_then(Value::as_i64);
        let ips = p
            .get("allowed_ips")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        for ip in ips.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            seen_ips
                .entry(ip.to_string())
                .or_default()
                .push(name.clone());
        }

        if rx == 0 && hs.is_none() {
            let mut ev = BTreeMap::new();
            ev.insert("peer".into(), json!(name));
            out.push(Finding::new(
                "mesh.peer-never-connected",
                Severity::Info,
                name.clone(),
                "peer registered but has never completed a handshake".to_string(),
                "expected while awaiting the key ceremony / device enrollment (1.5 · W2)",
                ev,
            ));
        } else if hs.is_none() || hs.unwrap_or(0) > 900 {
            let mut ev = BTreeMap::new();
            ev.insert("peer".into(), json!(name));
            ev.insert("handshake_age_s".into(), json!(hs));
            out.push(Finding::new(
                "mesh.peer-silent",
                Severity::Warn,
                name.clone(),
                "previously active peer has no handshake for >15 min".to_string(),
                "check the peer's host connectivity; confirming silence is a human call",
                ev,
            ));
        }

        if let Some(list) = inp.peers_allowlist {
            if !fp.is_empty() && !list.contains(&fp) {
                let mut ev = BTreeMap::new();
                ev.insert("fp".into(), json!(fp));
                out.push(Finding::new(
                    "mesh.unexpected-peer",
                    Severity::Critical,
                    name.clone(),
                    "peer fingerprint is NOT in the expected list".to_string(),
                    "investigate immediately — unexpected mesh membership",
                    ev,
                ));
            }
        }
    }

    // allowlist members missing from the mesh
    if let Some(list) = inp.peers_allowlist {
        for fp in list {
            if !seen_fps.contains(fp) {
                let mut ev = BTreeMap::new();
                ev.insert("fp".into(), json!(fp));
                out.push(Finding::new(
                    "mesh.expected-missing",
                    Severity::Warn,
                    "mesh",
                    "expected peer is absent from the mesh registry".to_string(),
                    "check whether the peer was revoked or failed to enroll",
                    ev,
                ));
            }
        }
    }

    // duplicate allowed_ips
    for (ip, names) in &seen_ips {
        if names.len() > 1 {
            let mut ev = BTreeMap::new();
            ev.insert("ip".into(), json!(ip));
            ev.insert("peers".into(), json!(names));
            out.push(Finding::new(
                "mesh.duplicate-ip",
                Severity::Critical,
                "mesh",
                format!("allowed_ips {ip} is claimed by {} peers", names.len()),
                "fix the mesh registry — overlapping addresses break routing determinism",
                ev,
            ));
        }
    }

    // registry not deployed yet (informational until W2)
    if m.get("registry")
        .and_then(|r| r.get("present"))
        .and_then(Value::as_bool)
        == Some(false)
    {
        out.push(Finding::new(
            "mesh.registry-absent",
            Severity::Info,
            "mesh",
            "mesh registry not deployed yet".to_string(),
            "informational — rides the W2 window",
            BTreeMap::new(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::LedgerReport;

    const NOW: i64 = 1_790_565_000_000;

    fn run(
        seq: u64,
        recipe: &str,
        ok: bool,
        attempt: u64,
        duration_ms: i64,
        egress: Option<&str>,
    ) -> JobRun {
        JobRun {
            seq,
            ts_ms: NOW - (100 - seq as i64) * 60_000, // all inside window
            recipe: recipe.into(),
            ok,
            exit_code: if ok { 0 } else { 1 },
            duration_ms,
            attempt,
            timed_out: false,
            egress: egress.map(str::to_string),
        }
    }

    fn report(runs: Vec<JobRun>) -> LedgerReport {
        LedgerReport {
            path: "test".into(),
            rows: runs.len(),
            chain_ok: true,
            chain_errors: vec![],
            runs,
        }
    }

    fn inp<'a>(ledger: &'a LedgerReport, mesh: Option<&'a Value>) -> Inputs<'a> {
        Inputs {
            ledger,
            mesh,
            peers_allowlist: None,
            expectations: None,
            now_ms: NOW,
            lookback_days: 7,
        }
    }

    fn ids(fs: &[Finding]) -> Vec<&str> {
        fs.iter().map(|f| f.id).collect()
    }

    #[test]
    fn quiet_ledger_yields_nothing() {
        let l = report(vec![run(1, "a", true, 1, 1000, Some("tor"))]);
        let f = run_all(&inp(&l, None));
        assert!(f.is_empty());
    }

    #[test]
    fn failure_rate_and_streak() {
        let l = report(vec![
            run(1, "a", true, 1, 1000, None),
            run(2, "a", false, 1, 1000, None),
            run(3, "a", false, 1, 1000, None),
            run(4, "a", false, 1, 1000, None),
        ]);
        let f = run_all(&inp(&l, None));
        let got = ids(&f);
        assert!(got.contains(&"jobs.failure-rate"));
        assert!(got.contains(&"jobs.consecutive-failures"));
    }

    #[test]
    fn retry_storm_detected() {
        let l = report(vec![
            run(1, "a", false, 1, 1000, None),
            run(2, "a", false, 2, 1000, None),
            run(3, "a", false, 3, 1000, None),
            run(4, "a", false, 2, 1000, None),
        ]);
        let f = run_all(&inp(&l, None));
        assert!(ids(&f).contains(&"jobs.retry-storm"));
    }

    #[test]
    fn egress_drift_is_flagged_once() {
        let l = report(vec![
            run(1, "a", true, 1, 1000, Some("tor")),
            run(2, "a", true, 1, 1000, Some("tor")),
            run(3, "a", true, 1, 1000, Some("direct")),
        ]);
        let f = run_all(&inp(&l, None));
        let drift: Vec<_> = f.iter().filter(|x| x.id == "jobs.egress-drift").collect();
        assert_eq!(drift.len(), 1);
        assert_eq!(drift[0].evidence["from"], json!("tor"));
        assert_eq!(drift[0].evidence["to"], json!("direct"));
    }

    #[test]
    fn no_drift_when_stable_or_older_rows_lack_egress() {
        let l = report(vec![
            run(1, "a", true, 1, 1000, None), // pre-S2 row: no egress recorded
            run(2, "a", true, 1, 1000, Some("tor")),
            run(3, "a", true, 1, 1000, Some("tor")),
        ]);
        let f = run_all(&inp(&l, None));
        assert!(!ids(&f).contains(&"jobs.egress-drift"));
    }

    #[test]
    fn duration_regression_info_only() {
        let l = report(vec![
            run(1, "a", true, 1, 1000, None),
            run(2, "a", true, 1, 1000, None),
            run(3, "a", true, 1, 1200, None),
            run(4, "a", true, 1, 9000, None),
        ]);
        let f = run_all(&inp(&l, None));
        let d: Vec<_> = f
            .iter()
            .filter(|x| x.id == "jobs.duration-regression")
            .collect();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].severity, Severity::Info);
    }

    #[test]
    fn stale_schedule_with_expectations() {
        let mut exp = Expectations::default();
        exp.0.insert("a".into(), 60); // hourly
        let mut r = run(1, "a", true, 1, 1000, None);
        r.ts_ms = NOW - 5 * 3_600_000; // 5h ago
        let l = report(vec![r]);
        let mut i = inp(&l, None);
        i.expectations = Some(&exp);
        let f = run_all(&i);
        assert!(ids(&f).contains(&"jobs.stale-schedule"));
    }

    #[test]
    fn never_ran_recipe_detected() {
        let mut exp = Expectations::default();
        exp.0.insert("ghost".into(), 60);
        let l = report(vec![]);
        let mut i = inp(&l, None);
        i.expectations = Some(&exp);
        let f = run_all(&i);
        assert!(ids(&f).contains(&"jobs.never-ran"));
    }

    fn mesh(pairs: &[(&str, &str, i64, Option<i64>, i64)]) -> Value {
        let peers: Vec<Value> = pairs
            .iter()
            .map(|(name, fp, rx, hs, _)| {
                json!({"name": name, "fp": fp, "rx_bytes": rx, "handshake_age_s": hs,
                       "allowed_ips": "10.77.0.3/32", "connected": hs.is_some()})
            })
            .collect();
        json!({
            "schema": "tallow-mesh-snapshot/v1",
            "generated_ts": NOW - 5_000,
            "iface": {"name": "wg0", "up": true, "listen_port": 51820},
            "peers": peers,
            "registry": {"present": false}
        })
    }

    #[test]
    fn mesh_never_connected_is_info_only() {
        let l = report(vec![]);
        let m = mesh(&[("peer-1", "sha256:aa", 0, None, 0)]);
        let f = run_all(&inp(&l, Some(&m)));
        let nc: Vec<_> = f
            .iter()
            .filter(|x| x.id == "mesh.peer-never-connected")
            .collect();
        assert_eq!(nc.len(), 1);
        assert_eq!(nc[0].severity, Severity::Info);
    }

    #[test]
    fn mesh_silent_peer_warns() {
        let l = report(vec![]);
        let m = mesh(&[("peer-1", "sha256:aa", 500, Some(1200), 0)]);
        let f = run_all(&inp(&l, Some(&m)));
        assert!(ids(&f).contains(&"mesh.peer-silent"));
    }

    #[test]
    fn mesh_allowlist_mismatch() {
        let mut allow = BTreeSet::new();
        allow.insert("sha256:expected".to_string());
        let l = report(vec![]);
        let m = mesh(&[("peer-1", "sha256:aa", 0, None, 0)]);
        let mut i = inp(&l, Some(&m));
        i.peers_allowlist = Some(&allow);
        let f = run_all(&i);
        let got = ids(&f);
        assert!(got.contains(&"mesh.unexpected-peer"));
        assert!(got.contains(&"mesh.expected-missing"));
    }

    #[test]
    fn mesh_duplicate_ips_critical() {
        let l = report(vec![]);
        let m = mesh(&[
            ("peer-1", "sha256:aa", 1, Some(5), 0),
            ("peer-2", "sha256:bb", 1, Some(5), 0),
        ]);
        let f = run_all(&inp(&l, Some(&m)));
        assert!(ids(&f).contains(&"mesh.duplicate-ip"));
    }

    #[test]
    fn mesh_stale_snapshot() {
        let l = report(vec![]);
        let mut m = mesh(&[]);
        m["generated_ts"] = json!(NOW - 300_000);
        let f = run_all(&inp(&l, Some(&m)));
        let s: Vec<_> = f.iter().filter(|x| x.id == "mesh.snapshot-stale").collect();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].severity, Severity::Warn);
    }
}
