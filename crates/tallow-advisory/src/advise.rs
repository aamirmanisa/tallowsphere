//! Scan orchestration: read inputs, run detectors, render, pick exit code.

use std::collections::BTreeSet;
use std::path::PathBuf;

use ed25519_dalek::VerifyingKey;
use serde_json::{json, Value};

use crate::detectors::{self, Expectations, Inputs};
use crate::findings::{counts, sort_findings, Finding, Severity};
use crate::ledger;

/// Options for one advisory scan (all paths are READ-ONLY).
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub ledger: PathBuf,
    pub mesh: Option<PathBuf>,
    pub peers: Option<PathBuf>,
    pub expectations: Option<PathBuf>,
    pub days: u32,
    /// Verify against this ed25519 pubkey (hex). `None` = dev key (demo).
    pub pubkey_hex: Option<String>,
    pub json: bool,
}

/// Exit code contract: 5 critical · 4 warn · 0 clean/info-only.
pub fn exit_code(findings: &[Finding]) -> i32 {
    let (crit, warn, _) = counts(findings);
    if crit > 0 {
        5
    } else if warn > 0 {
        4
    } else {
        0
    }
}

fn load_allowlist(path: &PathBuf) -> Result<BTreeSet<String>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("peers file: {e}"))?;
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("peers file: {e}"))?;
    let arr = if let Some(a) = v.as_array() {
        a.clone()
    } else if let Some(a) = v.get("expected_fingerprints").and_then(Value::as_array) {
        a.clone()
    } else {
        return Err(
            "peers file: expected a JSON array or {\"expected_fingerprints\": [...]}".into(),
        );
    };
    Ok(arr
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect())
}

fn load_expectations(path: &PathBuf) -> Result<Expectations, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("expectations file: {e}"))?;
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("expectations file: {e}"))?;
    Ok(Expectations::parse(&v))
}

fn resolving_pubkey(hex: Option<&str>) -> Result<(VerifyingKey, bool), String> {
    match hex {
        Some(h) => {
            let raw = hex_decode_32(h).ok_or("pubkey: expected 64 hex chars (32 bytes)")?;
            let k = VerifyingKey::from_bytes(&raw).map_err(|e| format!("pubkey: {e}"))?;
            Ok((k, false))
        }
        None => Ok((
            tallow_registry::receipt::dev_actor_key().verifying_key(),
            true,
        )),
    }
}

fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Run a scan; print human or JSON output; return the exit code.
pub fn scan(opts: &ScanOptions, now_ms: i64, out: &mut dyn std::io::Write) -> i32 {
    let (pubkey, using_dev) = match resolving_pubkey(opts.pubkey_hex.as_deref()) {
        Ok(x) => x,
        Err(e) => {
            let _ = writeln!(out, "tallow-advisory: {e}");
            return 2;
        }
    };

    let ledger_report = match ledger::load(&opts.ledger, &pubkey) {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(out, "tallow-advisory: {e}");
            return 1;
        }
    };

    let mesh_value: Option<Value> = match &opts.mesh {
        Some(p) => match std::fs::read_to_string(p)
            .map_err(|e| format!("mesh snapshot: {e}"))
            .and_then(|t| {
                serde_json::from_str::<Value>(&t).map_err(|e| format!("mesh snapshot: {e}"))
            }) {
            Ok(v) => Some(v),
            Err(e) => {
                let _ = writeln!(out, "tallow-advisory: {e}");
                return 1;
            }
        },
        None => None,
    };

    let allowlist = match &opts.peers {
        Some(p) => match load_allowlist(p) {
            Ok(a) => Some(a),
            Err(e) => {
                let _ = writeln!(out, "tallow-advisory: {e}");
                return 2;
            }
        },
        None => None,
    };

    let expectations = match &opts.expectations {
        Some(p) => match load_expectations(p) {
            Ok(e) => Some(e),
            Err(e) => {
                let _ = writeln!(out, "tallow-advisory: {e}");
                return 2;
            }
        },
        None => None,
    };

    let inp = Inputs {
        ledger: &ledger_report,
        mesh: mesh_value.as_ref(),
        peers_allowlist: allowlist.as_ref(),
        expectations: expectations.as_ref(),
        now_ms,
        lookback_days: opts.days,
    };
    let mut findings = detectors::run_all(&inp);
    sort_findings(&mut findings);
    let (crit, warn, info) = counts(&findings);

    if opts.json {
        let doc = json!({
            "schema": "tallow-advisory/v1",
            "generated_ts": now_ms,
            "advisory_only": true,
            "ledger": {
                "path": ledger_report.path,
                "rows": ledger_report.rows,
                "chain_ok": ledger_report.chain_ok,
                "chain_errors": ledger_report.chain_errors,
                "job_runs": ledger_report.runs.len(),
            },
            "mesh": mesh_value.as_ref().map(|m| json!({
                "present": true,
                "generated_ts": m.get("generated_ts"),
            })).unwrap_or(json!({"present": false})),
            "findings": findings,
            "summary": {"critical": crit, "warn": warn, "info": info},
        });
        let _ = writeln!(out, "{}", serde_json::to_string_pretty(&doc).unwrap());
        return exit_code(&findings);
    }

    // human rendering
    let _ = writeln!(
        out,
        "tallow-advisory scan — advisory only · no writes · no actions taken"
    );
    let _ = writeln!(
        out,
        "ledger {} — {} row(s), chain {} — {} job.run(s)",
        ledger_report.path,
        ledger_report.rows,
        if ledger_report.chain_ok {
            "OK"
        } else {
            "BROKEN"
        },
        ledger_report.runs.len()
    );
    if using_dev {
        let _ = writeln!(
            out,
            "note: verifying against DEV pubkey (demo material) — pass --pubkey for real ledgers"
        );
    }
    if let Some(m) = &mesh_value {
        let age = m
            .get("generated_ts")
            .and_then(Value::as_i64)
            .map(|ts| format!("{}s", ((now_ms - ts) / 1000).max(0)))
            .unwrap_or_else(|| "?".into());
        let _ = writeln!(out, "mesh snapshot age {age}");
    }
    if findings.is_empty() {
        let _ = writeln!(out, "findings: none — all detectors quiet");
    } else {
        let _ = writeln!(out, "findings:");
        for f in &findings {
            let _ = writeln!(
                out,
                "  [{}] {} — {} — {}",
                f.severity.as_str(),
                f.id,
                f.subject,
                f.message
            );
            let _ = writeln!(out, "        suggest: {}", f.suggestion);
        }
    }
    let _ = writeln!(
        out,
        "summary: {crit} critical · {warn} warn · {info} info — exit {}",
        exit_code(&findings)
    );
    exit_code(&findings)
}

/// Severity of the whole scan (for programmatic callers).
pub fn worst(findings: &[Finding]) -> Option<Severity> {
    findings.iter().map(|f| f.severity).max()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decode_roundtrip() {
        let k = tallow_registry::receipt::dev_actor_key();
        let hex: String = k
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(hex_decode_32(&hex).is_some());
        assert!(hex_decode_32("zz").is_none());
        assert!(hex_decode_32(&hex[..62]).is_none());
    }

    #[test]
    fn exit_codes_by_severity() {
        let mk = |s: Severity| Finding::new("x", s, "s", "m", "sug", Default::default());
        assert_eq!(exit_code(&[]), 0);
        assert_eq!(exit_code(&[mk(Severity::Info)]), 0);
        assert_eq!(exit_code(&[mk(Severity::Warn)]), 4);
        assert_eq!(exit_code(&[mk(Severity::Critical), mk(Severity::Info)]), 5);
    }

    #[test]
    fn missing_ledger_is_clean_scan() {
        let p = std::env::temp_dir().join(format!("adv-missing-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let opts = ScanOptions {
            ledger: p,
            mesh: None,
            peers: None,
            expectations: None,
            days: 7,
            pubkey_hex: None,
            json: true,
        };
        let mut buf = Vec::new();
        let rc = scan(&opts, 1_790_565_000_000, &mut buf);
        assert_eq!(rc, 0); // empty ledger = info only
        let v: Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["summary"]["warn"], 0);
        assert_eq!(v["advisory_only"], true);
    }
}
