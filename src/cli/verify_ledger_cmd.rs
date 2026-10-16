//! `tallow verify-ledger` CLI subcommand — recompute a ledger's hash chain
//! and flag tampering / gaps.
//!
//! The ledger is a SQLite database written by the agent ledger backend
//! (`crate::agent_ledger_sqlite`, schema table `ledger_events`). This command
//! reads every event in append order, recomputes the sha256 chain exactly as
//! the writer does (`crate::ledger_verify::verify_events`), and reports the
//! first violation — broken link / hash mismatch / gap-restart — with a
//! stable, human-readable reason.
//!
//! Usage:
//!   tallow verify-ledger <ledger.db>
//!
//! Exit behavior: a verified chain prints the report and exits 0; any failure
//! (open/read error or an invalid chain) returns an error, which the CLI
//! surfaces with exit code 1. There is no partial success — a chain is either
//! verified end-to-end or reported as broken.

use std::path::Path;

use crate::agent_ledger::LedgerBackend;
use crate::agent_ledger_sqlite::SqliteLedger;
use crate::ledger_verify::{VerifyReport, render_report, verify_events};

/// Load a ledger database and verify its hash chain. Pure over its inputs: no
/// printing, no process exits — callers decide presentation.
pub fn load_and_verify(path: &Path) -> Result<VerifyReport, String> {
    if !path.exists() {
        return Err(format!(
            "cannot open ledger '{}': file not found (verify-ledger never creates a ledger)",
            path.display()
        ));
    }
    let ledger = SqliteLedger::open(path)
        .map_err(|e| format!("cannot open ledger '{}': {e}", path.display()))?;
    let events = ledger
        .read_all()
        .map_err(|e| format!("cannot read ledger '{}': {e}", path.display()))?;
    Ok(verify_events(&events))
}

/// Run the `tallow verify-ledger <path>` subcommand (`args` is everything
/// after `verify-ledger`).
pub fn run_verify_ledger_cmd(args: &[String]) -> Result<(), String> {
    let mut path: Option<&str> = None;
    for a in args {
        match a.as_str() {
            "-h" | "--help" | "help" => {
                print_help();
                return Ok(());
            }
            other if other.starts_with('-') => {
                return Err(format!(
                    "unknown flag `{other}`;\nusage: tallow verify-ledger <ledger.db>"
                ));
            }
            other => {
                if path.is_some() {
                    return Err("verify-ledger takes exactly one ledger path".into());
                }
                path = Some(other);
            }
        }
    }
    let Some(path) = path else {
        print_help();
        return Ok(());
    };

    let report = load_and_verify(Path::new(path))?;
    println!("{}", render_report(&report));
    if report.ok {
        println!(
            "verify-ledger: OK — {} event(s), head {}",
            report.event_count,
            short_head(&report.head_hash)
        );
        Ok(())
    } else {
        let reason = report
            .first_failure
            .as_ref()
            .map(|f| f.reason.as_str())
            .unwrap_or("unknown failure");
        Err(format!(
            "verify-ledger: FAILED after {} event(s): {reason}",
            report.event_count
        ))
    }
}

fn short_head(h: &str) -> &str {
    &h[..h.len().min(12)]
}

fn print_help() {
    println!(
        "tallow verify-ledger — recompute a ledger hash chain and flag tampering/gaps\n\
         \n\
         Usage:\n\
           tallow verify-ledger <ledger.db>\n\
         \n\
         Reads every event from the SQLite ledger, recomputes the sha256 hash chain\n\
         (link → hash → gap/restart checks) and prints the verification report.\n\
         Exit 0 = chain verified; exit 1 = open/read error or a broken chain."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_ledger::LedgerBackend;
    use crate::ledger_events::{EventKind, chain_next};

    fn temp_ledger(n: usize) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ledger.db");
        let mut ledger = SqliteLedger::open(&path).expect("open");
        let mut prev: Option<crate::ledger_events::EventEnvelope> = None;
        for i in 0..n {
            let ev = chain_next(
                prev.as_ref(),
                EventKind::Fetch,
                "agent:test",
                "run-verify",
                &format!("{{\"i\":{i}}}"),
            );
            ledger.append(&ev).expect("append");
            prev = Some(ev);
        }
        (dir, path)
    }

    #[test]
    fn empty_ledger_verifies_ok() {
        let (_d, path) = temp_ledger(0);
        let report = load_and_verify(&path).expect("verify");
        assert!(report.ok);
        assert_eq!(report.event_count, 0);
    }

    #[test]
    fn clean_chain_verifies_ok() {
        let (_d, path) = temp_ledger(5);
        let report = load_and_verify(&path).expect("verify");
        assert!(
            report.ok,
            "clean chain must verify: {:?}",
            report.first_failure
        );
        assert_eq!(report.event_count, 5);
    }

    #[test]
    fn tampered_payload_is_caught() {
        let (_d, path) = temp_ledger(4);
        // Flip the payload of the 2nd event directly in the database — the
        // stored hash no longer commits to the payload, so verification must
        // fail with a hash-mismatch at that index.
        let conn = rusqlite::Connection::open(&path).expect("open raw");
        let n = conn
            .execute(
                "UPDATE ledger_events SET payload = '{\"i\":999}' WHERE seq = 2",
                [],
            )
            .expect("tamper");
        assert_eq!(n, 1, "exactly one row must be tampered");
        drop(conn);

        let report = load_and_verify(&path).expect("verify");
        assert!(!report.ok, "tampered chain must fail");
        let reason = report.first_failure.expect("failure recorded").reason;
        assert!(reason.contains("hash mismatch"), "reason: {reason}");
    }

    #[test]
    fn run_reports_ok_for_clean_chain() {
        let (_d, path) = temp_ledger(3);
        let args = vec![path.display().to_string()];
        assert!(run_verify_ledger_cmd(&args).is_ok());
    }

    #[test]
    fn run_errors_for_missing_file() {
        // The real hazard: a nonexistent path in a WRITABLE directory used to
        // auto-create an empty ledger and report OK (silent success + side
        // effect). The command must refuse without creating anything.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("does-not-exist.db");
        let args = vec![path.display().to_string()];
        let err = run_verify_ledger_cmd(&args).expect_err("missing ledger must fail");
        assert!(err.contains("not found"), "error: {err}");
        assert!(!path.exists(), "verify-ledger must not create the ledger");
    }
}
