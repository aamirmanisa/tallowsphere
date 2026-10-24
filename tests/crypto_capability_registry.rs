//! Gate: the crypto capability report must match the code it claims to describe.
//!
//! The failure this prevents is the one that already happened once in this
//! repository's own documentation: `stdlib/crypto.tl` and
//! `src/stdlib/crypto.rs` grew real FROST (RFC 9591, vector-tested) and BBS+
//! implementations while stale `*_experimental` arms and comments still read as
//! "not implemented". A reader — human or agent — then plans work that is
//! already done, or claims a gap that does not exist.
//!
//! So the contract is mechanical: every function declared at column 0 in
//! `stdlib/crypto.tl` appears exactly once in the report, carries a status from
//! a closed set, and any non-`implemented` status carries a reason. When a
//! function is gated behind a feature, the test also requires the feature name
//! in that reason, so the report cannot degrade into a bare label.

use std::collections::BTreeSet;
use std::process::Command;

fn manifest_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn declared_functions() -> BTreeSet<String> {
    let src = std::fs::read_to_string(manifest_dir().join("stdlib/crypto.tl"))
        .expect("stdlib/crypto.tl must exist");
    src.lines()
        .filter_map(|l| l.strip_prefix("fn "))
        .map(|rest| {
            rest.chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect::<String>()
        })
        .filter(|n| !n.is_empty())
        .collect()
}

fn crypto_record() -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["doctor", "--capabilities", "json"])
        .output()
        .expect("run tallow doctor --capabilities json");
    assert!(
        out.status.success(),
        "doctor --capabilities failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("report must be valid JSON");
    report["modules"]
        .as_array()
        .expect("modules array")
        .iter()
        .find(|m| m["module"] == "crypto")
        .expect("the report must contain a crypto module")
        .clone()
}

#[test]
fn every_declared_function_is_reported_exactly_once() {
    let declared = declared_functions();
    assert_eq!(
        declared.len(),
        28,
        "the declared crypto surface changed size ({}) — update this gate deliberately",
        declared.len()
    );

    let rec = crypto_record();
    let reported: Vec<String> = rec["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .map(|f| f["name"].as_str().expect("function name").to_string())
        .collect();

    let reported_set: BTreeSet<String> = reported.iter().cloned().collect();
    assert_eq!(
        reported_set.len(),
        reported.len(),
        "a function is reported twice"
    );
    assert_eq!(
        reported_set, declared,
        "the report and stdlib/crypto.tl disagree"
    );
}

#[test]
fn statuses_are_from_a_closed_set_and_carry_evidence() {
    let rec = crypto_record();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for f in rec["functions"].as_array().expect("functions") {
        let name = f["name"].as_str().unwrap_or("<unnamed>");
        let status = f["status"].as_str().unwrap_or("<missing>");
        seen.insert(status.to_string());
        assert!(
            matches!(
                status,
                "implemented" | "experimental" | "simulated" | "gated" | "unavailable"
            ),
            "{name}: unexpected status {status}"
        );
        if status != "implemented" {
            let reason = f["reason"].as_str().unwrap_or("");
            assert!(
                !reason.is_empty(),
                "{name} is {status} but carries no reason — a label without evidence"
            );
            if status == "gated" {
                assert!(
                    reason.contains("features"),
                    "{name} is gated but the reason does not name the feature: {reason}"
                );
            }
        }
    }
    assert!(
        seen.contains("implemented"),
        "a crypto surface with nothing implemented is not plausible; statuses seen: {seen:?}"
    );
}

#[test]
fn the_report_does_not_claim_gaps_that_were_already_closed() {
    // Measured 2026-10-24: FROST is RFC 9591 with the appendix E.1 vectors, and
    // BBS+ passes its draft proof vectors. If any of these regress to a stub,
    // this test is the place that notices.
    let rec = crypto_record();
    let fns = rec["functions"].as_array().expect("functions");
    for expected in [
        "frost_dkg",
        "frost_sign",
        "frost_verify",
        "bbs_issue",
        "bbs_prove",
        "bbs_verify",
        "noise_handshake",
        "spake2_exchange",
    ] {
        let f = fns
            .iter()
            .find(|f| f["name"] == expected)
            .unwrap_or_else(|| panic!("{expected} missing from the report"));
        assert_eq!(
            f["status"], "implemented",
            "{expected} regressed to {}: {}",
            f["status"], f["reason"]
        );
    }

    let frost = std::fs::read_to_string(manifest_dir().join("src/frost.rs")).expect("src/frost.rs");
    assert!(
        frost.contains("RFC 9591"),
        "src/frost.rs no longer identifies the standard it implements"
    );
}

#[test]
fn the_legacy_experimental_arms_are_still_listed() {
    let rec = crypto_record();
    let arms: Vec<String> = rec["experimental_arms"]
        .as_array()
        .expect("experimental_arms array")
        .iter()
        .map(|v| v.as_str().expect("arm name").to_string())
        .collect();
    for expected in [
        "bbs_issue_experimental",
        "threshold_dkg_experimental",
        "blind_sign_experimental",
    ] {
        assert!(
            arms.iter().any(|a| a == expected),
            "{expected} must stay visible: it is a legacy approximation that must not be \
             mistaken for the real implementation. Listed: {arms:?}"
        );
    }
}
