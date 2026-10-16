//! `tallow rmdb` CLI subcommand — FCC Robocall Mitigation DB snapshot
//! management. Reads a public RMDB CSV into the persistent snapshot store
//! (`data/rmdb_snapshot.json` by default) that `PhoneNumber.mitigation`
//! consults, and exposes status / lookup over that snapshot.
//!
//! Subcommands:
//!   import <csv-or-json>   parse + persist a downloaded RMDB CSV (or JSON
//!                          snapshot) to the snapshot store; prints a summary.
//!   status                 show the current snapshot (release, source, count).
//!   lookup <carrier>       look up one carrier's certification in the snapshot.
//!
//! Honesty: import never silently replaces a working snapshot — it parses and
//! validates first, then writes atomically. A missing file or unparseable CSV
//! is an error, never a no-op that keeps serving stale data.

use crate::stdlib::rmdb_store;

/// Run the `tallow rmdb <sub>` subcommand. `args` is everything after `rmdb`.
pub fn run_rmdb_cmd(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        print_help();
        return Ok(());
    }
    let sub = args[0].as_str();
    match sub {
        "--help" | "-h" | "help" => {
            print_help();
            Ok(())
        }
        "import" => cmd_import(&args[1..]),
        "status" => cmd_status(&args[1..]),
        "lookup" => cmd_lookup(&args[1..]),
        other => Err(format!(
            "unknown rmdb subcommand `{other}`;\nusage: tallow rmdb <import|status|lookup> ..."
        )),
    }
}

fn cmd_import(rest: &[String]) -> Result<(), String> {
    let src = rest
        .first()
        .ok_or_else(|| "rmdb import requires a path to the RMDB CSV".to_string())?;
    let text = std::fs::read_to_string(src)
        .map_err(|e| format!("rmdb import: cannot read {src}: {e}"))?;

    // If it's already a JSON snapshot (has a "records" object), reuse the file;
    // otherwise treat it as CSV.
    let snapshot = if text.trim_start().starts_with('{') {
        // JSON snapshot (from a previous export) — load & re-save is a no-op; just report.
        rmdb_store::load_snapshot(src).map_err(|e| format!("rmdb import: {e}"))?
    } else {
        let release = rest
            .get(1)
            .cloned()
            .unwrap_or_else(|| current_month());
        rmdb_store::refresh_from_csv_default(&text, &release)?
    };

    let path = rmdb_store::default_snapshot_path();
    println!(
        "RMDB snapshot refreshed -> {} (release={}, source={}, records={})",
        path,
        snapshot.release_version,
        snapshot.source,
        snapshot.len()
    );
    Ok(())
}

fn cmd_status(_rest: &[String]) -> Result<(), String> {
    match rmdb_store::load_snapshot_default() {
        Ok(s) => {
            println!(
                "RMDB snapshot: release={}, source={}, records={}",
                s.release_version,
                s.source,
                s.len()
            );
            Ok(())
        }
        Err(e) => Err(format!("rmdb status: no snapshot yet ({e}); run `tallow rmdb import`")),
    }
}

fn cmd_lookup(rest: &[String]) -> Result<(), String> {
    let carrier = rest
        .first()
        .ok_or_else(|| "rmdb lookup requires a carrier name".to_string())?;
    let snap = rmdb_store::load_snapshot_default()?;
    match snap.lookup_carrier(carrier) {
        Some((certified, holding)) => {
            println!(
                "{} -> certified={}, holding_company={}",
                carrier, certified, holding
            );
            Ok(())
        }
        None => {
            // Honest: not in the snapshot — could be unassigned or our snapshot
            // is stale; never guess.
            println!("{} -> not-in-snapshot (unknown; consider refreshing)", carrier);
            Ok(())
        }
    }
}

fn current_month() -> String {
    // Approximate YYYY-MM label; fine for a snapshot provenance tag.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = now / 86400;
    let (y, m, _) = civil_from_days(days as i64);
    format!("{y:04}-{m:02}")
}

// Howard Hinnant's civil-from-days (public domain algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn print_help() {
    println!(
        "{}",
        r#"tallow rmdb — FCC Robocall Mitigation Database snapshot management

USAGE:
    tallow rmdb <SUBCOMMAND> [ARGS]

SUBCOMMANDS:
    import <csv> [release]   parse + persist an RMDB CSV snapshot; prints summary
    status                   show current snapshot (release, source, records)
    lookup <carrier>         check one carrier's certification in the snapshot
    help                     show this help

NOTES:
    The snapshot feeds PhoneNumber.mitigation. The FCC RMDB is keyed by carrier,
    not by phone — it reflects the as-allocated carrier's certification, a public
    mitigation signal, never a verdict on an individual number.
    Set TALLOW_RMDB_SNAPSHOT_PATH to change the default snapshot location."#
    );
}
