//! `tallow plan` — dry-run a `tallow.request_plan.v1` manifest.
//!
//! `plan dry-run <file>` prints exactly what **would** be fetched and performs
//! no egress at all. That is the whole point of the verb: the plan format
//! already mandates a `compliance` block on every request, so a manifest can be
//! reviewed — and refused — before anything is fetched.
//!
//! This module deliberately never names [`crate::request_plan::execute_get`],
//! the one egress entry point. "Dry run" that can reach the network is not a dry
//! run, and the test at the bottom makes that structural rather than a promise.
//!
//! Exit codes, mirroring the set declared at the top of `src/main.rs`:
//! `0` = the plan is well-formed and was not fetched · `1` = the plan is not a
//! valid v1 manifest (the offending request is named) · `64` = usage error or
//! unreadable file.

use serde::Deserialize;

const EXIT_OK: i32 = 0;
const EXIT_INVALID: i32 = 1;
const EXIT_USAGE: i32 = 64;

/// The only `schema_version` this verb accepts.
const PLAN_SCHEMA: &str = "tallow.request_plan.v1";

/// A `tallow.request_plan.v1` manifest — only the fields this verb reads.
#[derive(Deserialize)]
struct Plan {
    #[serde(default)]
    schema_version: String,
    #[serde(default)]
    manifest_id: String,
    /// The manifest's own count. Checked against the array: a manifest whose
    /// arithmetic disagrees with its contents has already lost the reviewer it
    /// was written for.
    #[serde(default)]
    request_count: Option<usize>,
    #[serde(default)]
    requests: Vec<Request>,
}

#[derive(Deserialize)]
struct Request {
    #[serde(default)]
    index: i64,
    #[serde(default)]
    target_id: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    method: String,
    /// The mandate: every request must declare its legal basis before it can be
    /// fetched. `None` here is exactly the case `plan dry-run` exists to catch.
    #[serde(default)]
    compliance: Option<serde_json::Value>,
}

/// `plan dry-run <file>` · `plan --help`.
pub fn run_plan_args(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("dry-run") => dry_run(&args[1..]),
        Some("-h") | Some("--help") => {
            print_usage();
            EXIT_OK
        }
        Some(other) => {
            eprintln!("plan: unknown subcommand {other:?}");
            print_usage();
            EXIT_USAGE
        }
        None => {
            print_usage();
            EXIT_USAGE
        }
    }
}

fn print_usage() {
    eprintln!("usage: tallow plan dry-run <FILE.request-plan.v1.json>");
    eprintln!();
    eprintln!("Prints what a `tallow.request_plan.v1` manifest would fetch.");
    eprintln!("Performs no egress. Refuses a manifest whose requests omit their");
    eprintln!("`compliance` block. Exit codes: 0 ok, 1 invalid, 64 usage.");
}

/// `plan dry-run <file>`: resolve the path, read it, decide.
fn dry_run(args: &[String]) -> i32 {
    let path = match args.iter().find(|a| !a.starts_with('-')) {
        Some(p) => p,
        None => {
            eprintln!("plan dry-run: expected a manifest path");
            print_usage();
            return EXIT_USAGE;
        }
    };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("plan dry-run: cannot read {path}: {e}");
            return EXIT_USAGE;
        }
    };
    dry_run_text(path, &text)
}

/// The decision, split out so it is testable without the filesystem. Returns
/// the process exit code and prints the manifest's contents.
fn dry_run_text(path: &str, text: &str) -> i32 {
    let plan: Plan = match serde_json::from_str(text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("plan dry-run: {path}: not a readable manifest: {e}");
            return EXIT_INVALID;
        }
    };
    if plan.schema_version != PLAN_SCHEMA {
        eprintln!(
            "plan dry-run: {path}: unsupported schema_version {:?} (expected {PLAN_SCHEMA:?})",
            plan.schema_version
        );
        return EXIT_INVALID;
    }
    if plan.requests.is_empty() {
        eprintln!("plan dry-run: {path}: the manifest carries no requests");
        return EXIT_INVALID;
    }
    if let Some(declared) = plan.request_count {
        if declared != plan.requests.len() {
            eprintln!(
                "plan dry-run: {path}: request_count says {declared} but {} request(s) are present",
                plan.requests.len()
            );
            return EXIT_INVALID;
        }
    }

    // The mandate. One undeclared request refuses the whole manifest: a partial
    // dry-run would invite fetching the compliant subset and calling it consent.
    let undeclared: Vec<String> = plan
        .requests
        .iter()
        .filter(|r| r.compliance.is_none())
        .map(|r| format!("[{}] {} — {}", r.index, r.target_id, r.url))
        .collect();
    if !undeclared.is_empty() {
        eprintln!(
            "plan dry-run: {path}: {} request(s) declare no compliance block:",
            undeclared.len()
        );
        for u in &undeclared {
            eprintln!("  {u}");
        }
        return EXIT_INVALID;
    }

    println!("plan dry-run: {path}");
    println!("  manifest_id: {}", plan.manifest_id);
    println!(
        "  would fetch {} request(s); egress performed: none",
        plan.requests.len()
    );
    for r in &plan.requests {
        println!(
            "  [{}] {} {}  ({})",
            r.index,
            if r.method.is_empty() {
                "GET"
            } else {
                &r.method
            },
            r.url,
            r.target_id
        );
    }
    EXIT_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped specimen — the same manifest the plan's P3.T2 verification
    /// names (`examples/request_plan_get_only/`).
    const SPECIMEN: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/request_plan_get_only/request-plan.v1.json"
    ));

    #[test]
    fn the_shipped_manifest_dry_runs() {
        assert_eq!(dry_run_text("specimen", SPECIMEN), EXIT_OK);
    }

    #[test]
    fn a_request_without_a_compliance_block_refuses_the_whole_plan() {
        let bad = r#"{"schema_version":"tallow.request_plan.v1","manifest_id":"m",
                      "requests":[{"index":0,"target_id":"t","url":"https://x.invalid/a"}]}"#;
        assert_eq!(dry_run_text("bad", bad), EXIT_INVALID);
        // And the compliant sibling still passes, so the refusal is specific to
        // the missing block rather than a blanket rejection.
        let good = r#"{"schema_version":"tallow.request_plan.v1","manifest_id":"m",
                      "requests":[{"index":0,"target_id":"t","url":"https://x.invalid/a",
                                   "compliance":{"legal_basis":"legitimate_interest"}}]}"#;
        assert_eq!(dry_run_text("good", good), EXIT_OK);
    }

    #[test]
    fn a_count_that_disagrees_with_the_contents_is_refused() {
        let bad = r#"{"schema_version":"tallow.request_plan.v1","manifest_id":"m","request_count":7,
                      "requests":[{"index":0,"target_id":"t","url":"https://x.invalid/a",
                                   "compliance":{"legal_basis":"legitimate_interest"}}]}"#;
        assert_eq!(dry_run_text("bad", bad), EXIT_INVALID);
    }

    #[test]
    fn a_wrong_schema_version_is_refused() {
        let bad = r#"{"schema_version":"tallow.request_plan.v2","requests":[
                      {"index":0,"url":"https://x.invalid/a","compliance":{}}]}"#;
        assert_eq!(dry_run_text("bad", bad), EXIT_INVALID);
    }

    #[test]
    fn an_empty_manifest_is_refused_rather_than_reported_clean() {
        let empty = r#"{"schema_version":"tallow.request_plan.v1","requests":[]}"#;
        assert_eq!(dry_run_text("empty", empty), EXIT_INVALID);
    }

    #[test]
    fn usage_paths() {
        assert_eq!(run_plan_args(&[]), EXIT_USAGE);
        assert_eq!(run_plan_args(&["nope".to_string()]), EXIT_USAGE);
        assert_eq!(run_plan_args(&["--help".to_string()]), EXIT_OK);
        assert_eq!(
            run_plan_args(&["dry-run".to_string(), "/nonexistent/plan.json".to_string()]),
            EXIT_USAGE
        );
    }

    /// A "dry run" that can reach the network is not a dry run. This is the
    /// static form of the plan's `ss -tnp` proof — the module must not name the
    /// egress entry point, an HTTP client, or the egress layer. The needles are
    /// assembled so this test's own source cannot satisfy them.
    ///
    /// Comments are stripped first: this module's own doc comment names the
    /// egress entry point in a rustdoc link, and the invariant is "never CALLS
    /// it", not "never mentions it". (The first version of this test failed on
    /// its own documentation.)
    #[test]
    fn the_dry_run_module_cannot_egress() {
        let src: String = include_str!("plan_cmd.rs")
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !(t.starts_with("//") || t.starts_with("//!"))
            })
            .collect::<Vec<_>>()
            .join("\n");
        for needle in [
            concat!("execute", "_get"),
            concat!("ur", "eq"),
            concat!("egress", "_http"),
            concat!("reqwest", "::"),
        ] {
            assert!(
                !src.contains(needle),
                "plan dry-run must never reference {needle}"
            );
        }
    }
}
