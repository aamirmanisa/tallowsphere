//! CLI-level tests for `tallow fingerprint-audit` (matrix row #209; report ag03
//! R-2 audit CLI).
//!
//! These run the real compiled binary (`CARGO_BIN_EXE_tallow`), which is built
//! from this tree — the subcommand is registered in `src/main.rs` (`:152`;
//! dispatch at `:2455`), so the assertions below run unconditionally. (R4-3
//! removed the stale pre-merge feature-detect/SKIP branch: the flag has been
//! registered for waves, so the skip could no longer trigger — and a silent
//! skip here would only mask a genuine registration regression.)
//!
//! Asserts the full CLI contract: JSON schema, exit codes (0 / 2 / 64),
//! sectioned text output, cohort-k.
//!
//! Runnable with: `cargo test --test fingerprint_audit_cli --offline`

use std::process::{Command, Output};

fn tallow(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(args)
        .output()
        .expect("spawn tallow")
}

#[test]
fn cli_help_lists_fingerprint_audit() {
    let out = tallow(&["--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("fingerprint-audit"),
        "top-level help should list the subcommand:\n{stdout}"
    );
}

#[test]
fn cli_json_audit_roundtrip_default() {
    let out = tallow(&["fingerprint-audit", "--format", "json", "--mtu", "1500"]);
    assert!(
        out.status.success(),
        "audit should pass by default; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(doc["schema"], "tallow.fingerprint_audit.v1");
    // Real JA4 of the code-built ClientHello for both transports.
    assert!(doc["tls_config"]["tcp"]["ja4"].is_string(), "{doc}");
    assert!(doc["tls_config"]["quic"]["ja4"].is_string(), "{doc}");
    // Default profile is coherent with the default TLS profile.
    assert_eq!(doc["browser"]["critical_count"], 0);
    assert_eq!(doc["verdict"]["exit_code"], 0);
    // Honest cohort state without a dataset.
    assert_eq!(doc["cohort_k"]["state"], "undefined");
    assert!(doc["cohort_k"]["k"].is_null());
    // JA4T is labeled as derived.
    assert_eq!(doc["ja4t"]["state"], "derived");
    assert!(doc["ja4t"]["note"]
        .as_str()
        .unwrap_or_default()
        .contains("NOT observed"));
}

#[test]
fn cli_json_audit_is_deterministic() {
    let a = tallow(&["fingerprint-audit", "--format", "json", "--mtu", "1500"]);
    let b = tallow(&["fingerprint-audit", "--format", "json", "--mtu", "1500"]);
    assert!(a.status.success() && b.status.success());
    assert_eq!(
        a.stdout, b.stdout,
        "two identical offline runs must produce byte-identical reports"
    );
}

#[test]
fn cli_usage_error_exits_64() {
    let out = tallow(&["fingerprint-audit", "--definitely-not-a-flag"]);
    assert_eq!(
        out.status.code(),
        Some(64),
        "usage errors exit 64; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_critical_mismatch_exits_2() {
    // Chrome browser attributes + a Firefox TLS profile must be flagged as a
    // critical TLS↔UA/Client-Hints mismatch and fail the audit (exit 2).
    let out = tallow(&[
        "fingerprint-audit",
        "--profile",
        "firefox_132",
        "--format",
        "json",
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "critical findings exit 2; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert!(
        doc["browser"]["critical_count"].as_u64().unwrap_or(0) >= 1,
        "{doc}"
    );
}

#[test]
fn cli_text_output_sections() {
    let out = tallow(&["fingerprint-audit"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    for needle in [
        "tallow fingerprint-audit",
        "TLS configuration",
        "Profile (stdlib TLS)",
        "Browser attribute coherence",
        "JA4T (derived",
        "Cohort-k",
        "Egress",
        "verdict:",
    ] {
        assert!(text.contains(needle), "missing `{needle}` in:\n{text}");
    }
}

#[test]
fn cli_cohort_k_with_dataset() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cohort.json");
    // 3 entries share the default profile's JA4; 2 are different.
    std::fs::write(
        &path,
        r#"["t13d1516h2_8daaf6152771_e9e4f3b7","t13d1516h2_8daaf6152771_e9e4f3b7","t13d1516h2_8daaf6152771_e9e4f3b7","other_a","other_b"]"#,
    )
    .expect("write cohort");
    let out = tallow(&[
        "fingerprint-audit",
        "--cohort",
        path.to_str().expect("utf8 path"),
        "--format",
        "json",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert_eq!(doc["cohort_k"]["state"], "computed");
    assert_eq!(doc["cohort_k"]["k"], 3);
    assert_eq!(doc["cohort_k"]["dataset_size"], 5);
    assert_eq!(doc["cohort_k"]["verdict"], "low");
}
