//! `tallow fixity-sweep` CLI subcommand — run one fixity sweep over the
//! primary + mirror content stores and file the report set.
//!
//! This is the CLI glue pair of the fixity flow (Batch-07 §9) between
//! `deploy/tallow-fixity.service` (via `scripts/fixity_sweep.sh`) and the
//! job layer [`crate::fixity_job`]: it is the single place the wall clock is
//! read (the job layer takes `now_ms` as a parameter), calls
//! [`crate::fixity_job::run_sweep`], prints the report path, the finding
//! counts and the exit-code meaning, and returns the sweep's own exit code.
//!
//! Usage:
//!   tallow fixity-sweep --primary <dir> --mirror <dir> --reports <dir>
//!
//! Exit codes (design D3 alerting contract, see [`crate::fixity::exit_code`]):
//! - `0` — all ok (or nothing to audit);
//! - `1` — warn finding(s), no residual critical (damage was detected and
//!   auto-repaired from a verified peer, or a read/malformed-object warning);
//! - `2` — critical finding(s): at least one object has no verified-good copy
//!   anywhere (`reports/ALERT` written, nothing deleted), **or** the report
//!   set could not be written (a sweep that cannot file its evidence is a
//!   critical-class failure).
//!
//! `main.rs` dispatch (parent wires): `args` is everything after
//! `fixity-sweep`. [`parse_args`] is the frozen parse surface;
//! [`run_fixity_sweep_args`] is an additive convenience that handles
//! `-h`/`--help` (prints usage, exit 0) and maps argument errors to exit 64
//! (`USAGE_ERROR` in `main.rs`'s exit-code table).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Usage / `--help` text (also embedded in every [`parse_args`] error). The
/// environment contract below is consumed by `scripts/fixity_sweep.sh`, not
/// by this binary.
pub fn usage() -> &'static str {
    "\
tallow fixity-sweep — hash-audit the primary + mirror stores, auto-repair from a verified peer, write the report set

Usage:
  tallow fixity-sweep --primary <dir> --mirror <dir> --reports <dir>

Options:
  --primary <dir>   sharded primary store root (raw objects)
  --mirror <dir>    sharded mirror store root (peer copy)
  --reports <dir>   report directory (fixity-<ts>.json, latest.json, ALERT, cursor.json)
  -h, --help        print this help

Exit codes: 0 all ok · 1 warn (damage detected and auto-repaired) · 2 critical (no verified-good copy anywhere — ALERT written — or the report set could not be written).
Environment (set by deploy/tallow-fixity.service for scripts/fixity_sweep.sh):
  TALLOW_FIXITY_PRIMARY  TALLOW_FIXITY_MIRROR  TALLOW_FIXITY_REPORTS
"
}

/// Current unix time in milliseconds. [`crate::fixity_job::run_sweep`] takes
/// the clock as an argument (its tests stay deterministic); this CLI glue is
/// the single wall-clock read. A pre-1970 clock clamps to 0 — this function
/// never panics (the sweep's infallible contract extends to its callers).
fn now_ms() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// Human wording for a sweep exit code (frozen mapping: 0 ok / 1 warn /
/// 2 critical). `critical_count` disambiguates the two `2` causes.
fn exit_meaning(code: i32, critical_count: usize) -> &'static str {
    match code {
        0 => "ok — every audited object verified against its content address",
        1 => {
            "warn — damage was detected and auto-repaired from a verified peer (or \
             read/malformed-object warnings); no residual critical"
        }
        2 if critical_count > 0 => {
            "critical — at least one object has no verified-good copy anywhere; \
             ALERT written, nothing deleted"
        }
        _ => "critical — the report set could not be written (sweep evidence unfiled)",
    }
}

/// Run one fixity sweep and print its outcome. `primary`, `mirror` and
/// `reports` are the store/report roots; `now_ms` is the current wall clock.
/// Returns the sweep's exit code (`0`/`1`/`2`, see module docs) — the binary
/// exits with it, so the systemd unit sees the sweep verdict.
pub fn run_fixity_sweep(primary: &Path, mirror: &Path, reports: &Path) -> i32 {
    let outcome = crate::fixity_job::run_sweep(primary, mirror, reports, now_ms());
    println!("fixity-sweep: report   {}", outcome.report_path.display());
    println!(
        "fixity-sweep: findings={} critical={} (primary={}, mirror={})",
        outcome.findings_count,
        outcome.critical_count,
        primary.display(),
        mirror.display()
    );
    println!(
        "fixity-sweep: exit {} — {}",
        outcome.exit_code,
        exit_meaning(outcome.exit_code, outcome.critical_count)
    );
    outcome.exit_code
}

/// Parse `--primary/--mirror/--reports` from the arguments after
/// `fixity-sweep`. Both `--flag value` and `--flag=value` are accepted; a
/// missing/empty value, a repeated flag, or any unknown argument is an `Err`
/// whose message embeds the full usage text. All three paths are required.
pub fn parse_args(args: &[String]) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    let mut primary: Option<PathBuf> = None;
    let mut mirror: Option<PathBuf> = None;
    let mut reports: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        // `--flag=value` form; a bare value token is never reached here (it is
        // consumed by the flag that precedes it).
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v)),
            _ => (arg, None),
        };
        match flag {
            "--primary" | "--mirror" | "--reports" => {
                let value: &str = match inline {
                    Some(v) => v,
                    None => {
                        i += 1;
                        match args.get(i) {
                            Some(v) if !v.starts_with("--") => v.as_str(),
                            _ => {
                                return Err(parse_error(format!("`{flag}` requires a value")));
                            }
                        }
                    }
                };
                if value.is_empty() {
                    return Err(parse_error(format!(
                        "`{flag}` requires a non-empty value"
                    )));
                }
                let slot = match flag {
                    "--primary" => &mut primary,
                    "--mirror" => &mut mirror,
                    _ => &mut reports,
                };
                if slot.is_some() {
                    return Err(parse_error(format!("`{flag}` given more than once")));
                }
                *slot = Some(PathBuf::from(value));
            }
            other => return Err(parse_error(format!("unknown argument `{other}`"))),
        }
        i += 1;
    }

    let missing: Vec<&str> = [
        ("--primary", primary.is_none()),
        ("--mirror", mirror.is_none()),
        ("--reports", reports.is_none()),
    ]
    .into_iter()
    .filter(|(_, m)| *m)
    .map(|(n, _)| n)
    .collect();
    if !missing.is_empty() {
        return Err(parse_error(format!(
            "missing required argument(s): {}",
            missing.join(", ")
        )));
    }
    match (primary, mirror, reports) {
        (Some(p), Some(m), Some(r)) => Ok((p, m, r)),
        // Unreachable: `missing` was empty above.
        _ => Err(parse_error("missing required arguments".to_string())),
    }
}

/// Parse error body: the specific message followed by the full usage text, so
/// every failure path is self-explanatory.
fn parse_error(msg: String) -> String {
    format!("fixity-sweep: {msg}\n\n{}", usage())
}

/// Convenience entry point for the `main.rs` dispatcher. `args` is everything
/// after `fixity-sweep`:
/// - `-h`/`--help` (or `help`) → prints usage, returns `0`;
/// - argument error → prints the error + usage to stderr, returns `64`
///   (`main.rs` `exit_codes::USAGE_ERROR`);
/// - otherwise runs the sweep and returns its exit code (`0`/`1`/`2`).
///
/// Additive to the frozen §9 surface (parent may wire either this or
/// [`parse_args`] + [`run_fixity_sweep`] directly).
pub fn run_fixity_sweep_args(args: &[String]) -> i32 {
    if args.iter().any(|a| a == "-h" || a == "--help" || a == "help") {
        print!("{}", usage());
        return 0;
    }
    match parse_args(args) {
        Ok((primary, mirror, reports)) => run_fixity_sweep(&primary, &mirror, &reports),
        Err(e) => {
            eprintln!("{e}");
            64
        }
    }
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_args_accepts_flag_value_and_equals_forms() {
        let got =
            parse_args(&args(&["--primary", "/p", "--mirror=/m", "--reports", "/r"]))
                .expect("all three flags present");
        assert_eq!(got.0, PathBuf::from("/p"));
        assert_eq!(got.1, PathBuf::from("/m"));
        assert_eq!(got.2, PathBuf::from("/r"));
    }

    #[test]
    fn parse_args_missing_args_error_carries_usage() {
        let e = parse_args(&args(&["--primary", "/p"])).expect_err("mirror+reports missing");
        assert!(e.contains("--mirror"), "err: {e}");
        assert!(e.contains("--reports"), "err: {e}");
        assert!(e.contains("Usage:"), "err must carry usage text: {e}");
    }

    #[test]
    fn parse_args_rejects_unknown_flag_duplicate_and_flag_as_value() {
        let e = parse_args(&args(&["--bogus"])).expect_err("unknown flag");
        assert!(e.contains("unknown argument"), "err: {e}");

        let e = parse_args(&args(&["--primary", "/a", "--primary", "/b"])).expect_err("duplicate");
        assert!(e.contains("more than once"), "err: {e}");

        let e = parse_args(&args(&["--primary", "--mirror"])).expect_err("flag as value");
        assert!(e.contains("requires a value"), "err: {e}");

        let e = parse_args(&args(&["--primary="])).expect_err("empty value");
        assert!(e.contains("non-empty"), "err: {e}");
    }

    #[test]
    fn help_path_exits_zero_and_usage_documents_contract() {
        assert_eq!(run_fixity_sweep_args(&args(&["--help"])), 0);
        assert_eq!(run_fixity_sweep_args(&args(&["-h"])), 0);
        let u = usage();
        assert!(u.contains("tallow fixity-sweep"), "usage: {u}");
        assert!(u.contains("TALLOW_FIXITY_PRIMARY"), "usage: {u}");
        assert!(u.contains("TALLOW_FIXITY_MIRROR"), "usage: {u}");
        assert!(u.contains("TALLOW_FIXITY_REPORTS"), "usage: {u}");
    }

    #[test]
    fn usage_error_maps_to_64() {
        assert_eq!(run_fixity_sweep_args(&args(&["--nope"])), 64);
        assert_eq!(run_fixity_sweep_args(&args(&[])), 64);
    }

    #[test]
    fn empty_stores_sweep_exits_zero_and_files_report() {
        let d = tempfile::tempdir().unwrap();
        let primary = d.path().join("primary");
        let mirror = d.path().join("mirror");
        let reports = d.path().join("reports");
        std::fs::create_dir_all(&primary).unwrap();
        std::fs::create_dir_all(&mirror).unwrap();

        assert_eq!(run_fixity_sweep(&primary, &mirror, &reports), 0);

        // A fixity-<ts>.json report + latest.json must exist; no ALERT.
        let names: Vec<String> = std::fs::read_dir(&reports)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().any(|n| n.starts_with("fixity-") && n.ends_with(".json")),
            "report set: {names:?}"
        );
        assert!(names.iter().any(|n| n == "latest.json"), "report set: {names:?}");
        assert!(!reports.join("ALERT").exists());
    }

    #[test]
    fn critical_finding_maps_to_exit_two_and_writes_alert() {
        let d = tempfile::tempdir().unwrap();
        let primary = d.path().join("primary");
        let mirror = d.path().join("mirror");
        let reports = d.path().join("reports");

        // Same content address, corrupted bytes on BOTH sides → no good copy
        // anywhere → critical (design D3).
        let h = crate::replication::sha256_hex(b"good bytes");
        for root in [&primary, &mirror] {
            let p = root.join(&h[0..2]).join(&h[2..4]).join(&h);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"rotted").unwrap();
        }

        assert_eq!(run_fixity_sweep(&primary, &mirror, &reports), 2);
        assert!(reports.join("ALERT").exists(), "critical sweep writes ALERT");
    }
}
