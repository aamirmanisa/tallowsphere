//! Read-only ledger access: verify the chain, project `job.run` rows.

use std::path::Path;

use ed25519_dalek::VerifyingKey;
use serde_json::Value;

/// One `job.run` receipt, projected for the detectors.
#[derive(Debug, Clone, PartialEq)]
pub struct JobRun {
    pub seq: u64,
    pub ts_ms: i64,
    pub recipe: String,
    pub ok: bool,
    pub exit_code: i64,
    pub duration_ms: i64,
    pub attempt: u64,
    pub timed_out: bool,
    pub egress: Option<String>,
}

/// Full read-only ledger picture.
#[derive(Debug)]
pub struct LedgerReport {
    pub path: String,
    pub rows: usize,
    pub chain_ok: bool,
    pub chain_errors: Vec<String>,
    pub runs: Vec<JobRun>,
}

/// Read + verify + project. `Err` only for I/O failures; a broken chain is
/// reported inside the struct (the advisory must be able to *talk about* a
/// broken ledger, not crash on it).
pub fn load(path: &Path, pubkey: &VerifyingKey) -> Result<LedgerReport, String> {
    let ledger = tallow_registry::Ledger::new(path.to_path_buf());
    let verdict = ledger.verify(pubkey);
    let receipts = ledger
        .iter()
        .map_err(|e| format!("ledger unreadable: {e}"))?;
    let mut runs = Vec::new();
    for r in &receipts {
        if r.kind != "job.run" {
            continue;
        }
        runs.push(project(r));
    }
    Ok(LedgerReport {
        path: path.display().to_string(),
        rows: verdict.rows,
        chain_ok: verdict.ok(),
        chain_errors: verdict.errors.clone(),
        runs,
    })
}

fn s(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn i(v: &Value, k: &str) -> i64 {
    v.get(k).and_then(Value::as_i64).unwrap_or(0)
}

fn project(r: &tallow_registry::Receipt) -> JobRun {
    let d = &r.data;
    let recipe = d
        .get("recipe")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| r.subject.clone())
        .unwrap_or_else(|| s(d, "file"));
    JobRun {
        seq: r.seq,
        ts_ms: r.ts_ms as i64,
        recipe,
        ok: d.get("ok").and_then(Value::as_bool).unwrap_or(false),
        exit_code: i(d, "exit_code"),
        duration_ms: i(d, "duration_ms"),
        attempt: d.get("attempt").and_then(Value::as_u64).unwrap_or(1),
        timed_out: d.get("timed_out").and_then(Value::as_bool).unwrap_or(false),
        egress: d.get("egress").and_then(Value::as_str).map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("tallow-adv-{}-{}", std::process::id(), name))
    }

    fn sign_ledger(path: &Path, key: &SigningKey, n: usize) {
        let _ = std::fs::remove_file(path);
        let ledger = tallow_registry::Ledger::new(path.to_path_buf());
        for i in 0..n {
            let prev = ledger.next_prev().unwrap();
            let seq = ledger.next_seq().unwrap();
            let r = tallow_registry::Receipt::sign_new(
                seq,
                "job.run",
                "tallow-jobs",
                Some("price-monitor"),
                json!({"recipe": "price-monitor", "ok": true, "exit_code": 0,
                       "duration_ms": 1000, "attempt": 1, "timed_out": false,
                       "egress": "tor"}),
                prev,
                key,
            );
            ledger.append(&r).unwrap();
            let _ = i;
        }
    }

    #[test]
    fn loads_and_projects_signed_rows() {
        let key = tallow_registry::receipt::dev_actor_key();
        let p = tmp("proj.jsonl");
        sign_ledger(&p, &key, 2);
        let rep = load(&p, &key.verifying_key()).unwrap();
        assert_eq!(rep.rows, 2);
        assert!(rep.chain_ok);
        assert_eq!(rep.runs.len(), 2);
        assert_eq!(rep.runs[0].recipe, "price-monitor");
        assert!(rep.runs[0].ok);
        assert_eq!(rep.runs[0].egress.as_deref(), Some("tor"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn tampered_row_breaks_chain_but_still_reports() {
        let key = tallow_registry::receipt::dev_actor_key();
        let p = tmp("tamper.jsonl");
        sign_ledger(&p, &key, 2);
        let text = std::fs::read_to_string(&p).unwrap();
        let tampered = text.replacen("\"ok\":true", "\"ok\":false", 1);
        std::fs::write(&p, tampered).unwrap();
        let rep = load(&p, &key.verifying_key()).unwrap();
        assert!(!rep.chain_ok);
        assert!(!rep.chain_errors.is_empty());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn missing_file_is_empty_ledger_ok() {
        let key = tallow_registry::receipt::dev_actor_key();
        let p = tmp("missing.jsonl");
        let _ = std::fs::remove_file(&p);
        let rep = load(&p, &key.verifying_key()).unwrap();
        assert_eq!(rep.rows, 0);
        assert!(rep.chain_ok);
        assert!(rep.runs.is_empty());
    }
}
