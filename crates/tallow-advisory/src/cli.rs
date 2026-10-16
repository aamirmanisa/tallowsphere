//! `tallow-advisory` CLI — scan + selftest. Read-only; prints only.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::advise::{exit_code, scan, ScanOptions};
use crate::detectors::{self, Expectations, Inputs};
use crate::findings::counts;
use crate::ledger::{JobRun, LedgerReport};

const USAGE: &str = "\
tallow-advisory — read-only anomaly advisory over jobs/mesh (3.6)

Usage:
  tallow-advisory scan --ledger <receipts.jsonl> [--mesh <mesh.json>]
                       [--peers <fps.json>] [--expect <cadence.json>]
                       [--days N] [--pubkey <hex64>] [--json]
  tallow-advisory selftest
  tallow-advisory --help

Exit codes: 0 clean/info · 4 warn · 5 critical · 2 usage · 1 error
Read-only by construction: no writes, no network, no automated actions.";

pub fn run(args: Vec<String>) -> i32 {
    let mut it = args.into_iter();
    let Some(cmd) = it.next() else {
        println!("{USAGE}");
        return 2;
    };
    match cmd.as_str() {
        "--help" | "-h" => {
            println!("{USAGE}");
            0
        }
        "selftest" => selftest(),
        "scan" => {
            let mut ledger: Option<PathBuf> = None;
            let mut mesh: Option<PathBuf> = None;
            let mut peers: Option<PathBuf> = None;
            let mut expect: Option<PathBuf> = None;
            let mut days: u32 = 7;
            let mut pubkey_hex: Option<String> = None;
            let mut json = false;
            let rest: Vec<String> = it.collect();
            let mut i = 0;
            while i < rest.len() {
                let a = &rest[i];
                let need = |i: usize| -> Option<&str> { rest.get(i + 1).map(String::as_str) };
                match a.as_str() {
                    "--ledger" => match need(i) {
                        Some(v) => ledger = Some(PathBuf::from(v)),
                        None => return usage_err("--ledger needs a path"),
                    },
                    "--mesh" => mesh = need(i).map(PathBuf::from),
                    "--peers" => peers = need(i).map(PathBuf::from),
                    "--expect" => expect = need(i).map(PathBuf::from),
                    "--days" => match need(i).and_then(|v| v.parse().ok()) {
                        Some(n) => days = n,
                        None => return usage_err("--days needs a number"),
                    },
                    "--pubkey" => match need(i) {
                        Some(v) => pubkey_hex = Some(v.to_string()),
                        None => return usage_err("--pubkey needs hex"),
                    },
                    "--json" => {
                        json = true;
                        i += 1;
                        continue;
                    }
                    other => return usage_err(&format!("unknown argument: {other}")),
                }
                i += 2;
            }
            let Some(ledger) = ledger else {
                return usage_err("scan requires --ledger");
            };
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            let opts = ScanOptions {
                ledger,
                mesh,
                peers,
                expectations: expect,
                days,
                pubkey_hex,
                json,
            };
            scan(&opts, now_ms, &mut std::io::stdout())
        }
        other => usage_err(&format!("unknown command: {other}")),
    }
}

fn usage_err(msg: &str) -> i32 {
    eprintln!("tallow-advisory: {msg}");
    println!("{USAGE}");
    2
}

/// Built-in scenario battery (human-facing proof; mirrors the unit tests).
fn selftest() -> i32 {
    let now = 1_790_565_000_000i64;
    let mk = |seq: u64, recipe: &str, ok: bool, attempt: u64, dur: i64, eg: Option<&str>| JobRun {
        seq,
        ts_ms: now - 60_000, // inside window
        recipe: recipe.into(),
        ok,
        exit_code: if ok { 0 } else { 1 },
        duration_ms: dur,
        attempt,
        timed_out: false,
        egress: eg.map(str::to_string),
    };
    let mkrep = |runs: Vec<JobRun>| LedgerReport {
        path: "<selftest>".into(),
        rows: runs.len(),
        chain_ok: true,
        chain_errors: vec![],
        runs,
    };
    fn base(l: &LedgerReport, now: i64) -> Inputs<'_> {
        Inputs {
            ledger: l,
            mesh: None,
            peers_allowlist: None,
            expectations: None,
            now_ms: now,
            lookback_days: 7,
        }
    }

    let mut pass = 0usize;
    let mut checks = 0usize;

    // 1. healthy ledger → quiet
    checks += 1;
    let healthy = mkrep(vec![mk(1, "a", true, 1, 1000, Some("tor"))]);
    let f = detectors::run_all(&base(&healthy, now));
    if f.is_empty() {
        println!("PASS  healthy ledger → no findings");
        pass += 1;
    } else {
        println!("FAIL  healthy ledger produced {} finding(s)", f.len());
    }

    // 2. sick ledger → warn class findings, deterministic order
    checks += 1;
    let sick = mkrep(vec![
        mk(1, "a", true, 1, 1000, Some("tor")),
        mk(2, "a", false, 1, 1000, Some("direct")),
        mk(3, "a", false, 2, 1000, Some("direct")),
        mk(4, "a", false, 3, 1000, Some("direct")),
    ]);
    let mut f1 = detectors::run_all(&base(&sick, now));
    crate::findings::sort_findings(&mut f1);
    let mut f2 = detectors::run_all(&base(&sick, now));
    crate::findings::sort_findings(&mut f2);
    let ids1: Vec<&str> = f1.iter().map(|x| x.id).collect();
    let ids2: Vec<&str> = f2.iter().map(|x| x.id).collect();
    let has_drift = ids1.contains(&"jobs.egress-drift");
    let has_fail = ids1.contains(&"jobs.failure-rate");
    if ids1 == ids2 && has_drift && has_fail && exit_code(&f1) == 4 {
        println!(
            "PASS  sick ledger → {} finding(s), deterministic, exit 4",
            f1.len()
        );
        pass += 1;
    } else {
        println!(
            "FAIL  sick ledger scenario (drift={has_drift} fail={has_fail} stable={})",
            ids1 == ids2
        );
    }

    // 3. expectations honoured
    checks += 1;
    let mut exp = Expectations::default();
    exp.0.insert("ghost".into(), 60);
    let empty = mkrep(vec![]);
    let mut i3 = base(&empty, now);
    i3.expectations = Some(&exp);
    let f3 = detectors::run_all(&i3);
    if f3.iter().any(|x| x.id == "jobs.never-ran") {
        println!("PASS  expected-but-absent recipe flagged");
        pass += 1;
    } else {
        println!("FAIL  never-ran not flagged");
    }

    let (c, w, n) = counts(&f1);
    println!(
        "selftest: {pass}/{checks} PASS (sample scenario: {c} critical · {w} warn · {n} info)"
    );
    if pass == checks {
        0
    } else {
        1
    }
}
