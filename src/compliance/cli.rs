//! CLI runners for `tallow compliance …` (row #179).
//!
//! `src/main.rs` owns the clap surface and calls one of these functions per
//! leg; the runners own input parsing, rendering and the exit-code contract:
//!
//! - `0` — generated, and no early-warning leg is outstanding/overdue;
//! - `1` — generated, but at least one leg is overdue (the operator needs to
//!   act: this is the signal a dashboard/CI job keys on);
//! - `2` — could not run (unreadable input, refused draft, bad key file).
//!
//! Nothing here opens a socket; every path is local (`submission_posture()`
//! states it per report).

use std::path::Path;

use super::clocks::{self, ClockInput};
use super::incident::{self, IncidentDraft};
use super::znism;
use tallow::config::lint::LintOptions;
use tallow::config::load::{load_default, load_file};

/// Exit code when a report was generated with no outstanding warning leg.
pub const EXIT_OK: i32 = 0;
/// Exit code when a report was generated but a leg is overdue.
pub const EXIT_OVERDUE: i32 = 1;
/// Exit code when the command could not run.
pub const EXIT_COULD_NOT_RUN: i32 = 2;

/// Now, in Unix seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn emit(rendered: String, out: Option<&Path>) -> Result<(), String> {
    match out {
        Some(path) => std::fs::write(path, rendered.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", path.display())),
        None => {
            print!("{rendered}");
            Ok(())
        }
    }
}

fn read_spec(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// `tallow compliance clocks --spec <json> [--now <ts>] [--format text|json] [--out <path>]`
pub fn run_clocks(spec: &Path, now: Option<i64>, format: &str, out: Option<&Path>) -> i32 {
    let text = match read_spec(spec) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("tallow compliance clocks: {e}");
            return EXIT_COULD_NOT_RUN;
        }
    };
    let input: ClockInput = match serde_json::from_str(&text) {
        Ok(i) => i,
        Err(e) => {
            eprintln!(
                "tallow compliance clocks: {}: invalid spec: {e}",
                spec.display()
            );
            return EXIT_COULD_NOT_RUN;
        }
    };
    let now = now.unix_or_else(now_unix);
    let table = match clocks::compute(&input, now) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("tallow compliance clocks: refused: {e}");
            return EXIT_COULD_NOT_RUN;
        }
    };
    let rendered = match format {
        "json" => format!(
            "{}\n",
            serde_json::to_string_pretty(&table.to_json()).unwrap_or_default()
        ),
        _ => table.render_text(),
    };
    if let Err(e) = emit(rendered, out) {
        eprintln!("tallow compliance clocks: {e}");
        return EXIT_COULD_NOT_RUN;
    }
    if table.overdue_count() > 0 {
        EXIT_OVERDUE
    } else {
        EXIT_OK
    }
}

/// Spec file for the CERT-In generator: the draft fields plus the
/// jurisdictions whose clocks ride along in the payload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IncidentSpec {
    #[serde(flatten)]
    draft: IncidentDraft,
    /// Declared jurisdictions (default: India only).
    #[serde(default)]
    jurisdictions: Vec<clocks::Jurisdiction>,
}

/// `tallow compliance incident --spec <json> [--ledger <jsonl>] [--key <path>]
///  [--now <ts>] [--format text|json] [--out <path>]`
pub fn run_incident(
    spec: &Path,
    ledger: Option<&Path>,
    key: Option<&Path>,
    now: Option<i64>,
    format: &str,
    out: Option<&Path>,
) -> i32 {
    let text = match read_spec(spec) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("tallow compliance incident: {e}");
            return EXIT_COULD_NOT_RUN;
        }
    };
    let spec: IncidentSpec = match serde_json::from_str(&text) {
        Ok(i) => i,
        Err(e) => {
            eprintln!(
                "tallow compliance incident: {}: invalid spec: {e}",
                spec.display()
            );
            return EXIT_COULD_NOT_RUN;
        }
    };
    let jurisdictions = if spec.jurisdictions.is_empty() {
        vec![clocks::Jurisdiction::India]
    } else {
        spec.jurisdictions.clone()
    };
    let now = now.unix_or_else(now_unix);
    let mut report = match incident::build(&spec.draft, ledger, &jurisdictions, now) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tallow compliance incident: refused: {e}");
            return EXIT_COULD_NOT_RUN;
        }
    };
    if let Some(key) = key {
        let seed = match incident::load_signing_seed(key) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("tallow compliance incident: {e}");
                return EXIT_COULD_NOT_RUN;
            }
        };
        if let Err(e) = report.sign_with_seed(seed, &spec.draft) {
            eprintln!("tallow compliance incident: signing failed: {e}");
            return EXIT_COULD_NOT_RUN;
        }
    }
    let rendered = match format {
        "json" => format!(
            "{}\n",
            serde_json::to_string_pretty(&report.to_json()).unwrap_or_default()
        ),
        _ => report.render_text(),
    };
    if let Err(e) = emit(rendered, out) {
        eprintln!("tallow compliance incident: {e}");
        return EXIT_COULD_NOT_RUN;
    }
    let overdue = report.clocks.overdue_count() > 0;
    if overdue {
        EXIT_OVERDUE
    } else {
        EXIT_OK
    }
}

/// `tallow compliance znism-pack [--config <path>] [--now <ts>]
///  [--format text|json] [--out <path>]`
pub fn run_znism(config: Option<&Path>, now: Option<i64>, format: &str, out: Option<&Path>) -> i32 {
    let load = match config {
        Some(path) => {
            if !path.exists() {
                eprintln!(
                    "tallow compliance znism-pack: no config artifact at {}",
                    path.display()
                );
                return EXIT_COULD_NOT_RUN;
            }
            load_file(path)
        }
        None => match load_default() {
            Ok(l) => l,
            Err(e) => {
                eprintln!("tallow compliance znism-pack: {e}");
                return EXIT_COULD_NOT_RUN;
            }
        },
    };
    // Metadata only (never reads secret values) — same options the lint CLI uses.
    let options = LintOptions {
        probe_secret_targets: true,
        ..LintOptions::default()
    };
    let now = now.unix_or_else(now_unix);
    let pack = znism::build_pack(&load, &options, now);
    let rendered = match format {
        "json" => format!(
            "{}\n",
            serde_json::to_string_pretty(&pack.to_json()).unwrap_or_default()
        ),
        _ => pack.render_text(),
    };
    if let Err(e) = emit(rendered, out) {
        eprintln!("tallow compliance znism-pack: {e}");
        return EXIT_COULD_NOT_RUN;
    }
    // A pack is always a generated artifact; gaps are reported inside it, not
    // as a failure — the exit code says "did the tool run", not "are you
    // compliant" (that reading would be a compliance claim it cannot make).
    EXIT_OK
}

/// Small helper so `--now` defaults are expressed once.
trait NowOr {
    fn unix_or_else(&self, f: impl Fn() -> i64) -> i64;
}

impl NowOr for Option<i64> {
    fn unix_or_else(&self, f: impl Fn() -> i64) -> i64 {
        self.unwrap_or_else(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::parse_timestamp;

    fn t0() -> i64 {
        parse_timestamp("2026-09-14T00:00:00Z").unwrap()
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tallow-compliance-cli-{}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn clocks_runner_returns_overdue_only_when_a_leg_is_missed() {
        let dir = scratch("clocks");
        let spec = dir.join("spec.json");
        std::fs::write(
            &spec,
            format!(
                r#"{{"awareness_at": {}, "kind": "severe-incident", "jurisdictions": ["in"]}}"#,
                t0()
            ),
        )
        .unwrap();
        let out = dir.join("out.json");
        assert_eq!(
            run_clocks(&spec, Some(t0() + 3600), "json", Some(&out)),
            EXIT_OK
        );
        let rendered = std::fs::read_to_string(&out).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["deadlines"][0]["regime"], "cert_in");
        assert_eq!(
            run_clocks(&spec, Some(t0() + 6 * 3600 + 1), "text", Some(&out)),
            EXIT_OVERDUE
        );
        assert!(std::fs::read_to_string(&out).unwrap().contains("OVERDUE"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clocks_runner_refuses_bad_specs_and_bad_paths() {
        let dir = scratch("clocks-bad");
        let missing = dir.join("nope.json");
        assert_eq!(
            run_clocks(&missing, Some(t0()), "text", None),
            EXIT_COULD_NOT_RUN
        );
        let bad = dir.join("bad.json");
        std::fs::write(&bad, "{\"awareness_at\": 1, \"kind\": \"breach\"}").unwrap();
        assert_eq!(
            run_clocks(&bad, Some(t0()), "text", None),
            EXIT_COULD_NOT_RUN
        );
        // A well-formed spec whose awareness is in the future is refused too.
        let future = dir.join("future.json");
        std::fs::write(
            &future,
            format!(
                r#"{{"awareness_at": {}, "kind": "severe-incident", "jurisdictions": ["in"]}}"#,
                t0()
            ),
        )
        .unwrap();
        assert_eq!(
            run_clocks(&future, Some(t0() - 1), "text", None),
            EXIT_COULD_NOT_RUN
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn incident_runner_writes_a_signed_payload_and_keeps_the_6h_clock() {
        let dir = scratch("incident");
        let spec = dir.join("incident.json");
        std::fs::write(
            &spec,
            format!(
                r#"{{"incident_id": "INC-9", "class": "ransomware", "awareness_at": {},
                     "description": "file server encrypted", "affected_systems": [],
                     "mitigation": [], "contact": {{"name": "Ops", "organisation": "Ex",
                     "email": "soc@example.invalid"}}, "jurisdictions": ["in"]}}"#,
                t0()
            ),
        )
        .unwrap();
        let key = dir.join("key.bin");
        std::fs::write(&key, [5u8; 32]).unwrap();
        let out = dir.join("incident.out.json");
        assert_eq!(
            run_incident(
                &spec,
                None,
                Some(&key),
                Some(t0() + 3600),
                "json",
                Some(&out)
            ),
            EXIT_OK
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(parsed["cert_in_deadline"]["term"], "6h");
        assert_eq!(parsed["signature"]["alg"], "ed25519");
        assert_eq!(parsed["submission"]["auto_submitted"], false);
        // One second past the window: generated, but exit 1.
        assert_eq!(
            run_incident(
                &spec,
                None,
                None,
                Some(t0() + 6 * 3600 + 1),
                "text",
                Some(&out)
            ),
            EXIT_OVERDUE
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn znism_runner_builds_a_pack_from_a_config_file() {
        let dir = scratch("znism");
        let config = dir.join("config.toml");
        std::fs::write(&config, "profile = \"workstation\"\ntelemetry = false\n").unwrap();
        let out = dir.join("pack.json");
        assert_eq!(
            run_znism(Some(&config), Some(t0()), "json", Some(&out)),
            EXIT_OK
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(parsed["pack"], znism::ZNISM_PACK_ID);
        assert_eq!(parsed["counts"]["rows"], parsed["counts"]["rows"]);
        assert!(parsed["counts"]["rows"].as_u64().unwrap() >= 24);
        assert_eq!(
            run_znism(Some(&dir.join("absent.toml")), Some(t0()), "text", None),
            EXIT_COULD_NOT_RUN
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
