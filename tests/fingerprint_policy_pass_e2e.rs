//! End-to-end acceptance tests for the compile-time fingerprint policy gate
//! `@fingerprint_policy` (matrix row #33; report ag03 R-1).
//!
//! These drive the **real compiled binary** (`CARGO_BIN_EXE_tallow check`) over
//! fixture `.tl` programs written into `CARGO_TARGET_TMPDIR`, so the whole
//! pipeline (annotations → typecheck → policy passes → diagnostics) is
//! exercised — the unit set in `src/fingerprint_policy_pass.rs` covers the
//! pass in isolation, this file is the CLI-level spec:
//!
//! * E5100 — feature-using / browser / network program without a declaration
//! * E5101 — malformed declaration
//! * E5102 — randomization (`Fingerprint.rotate`) under `.normalize`
//! * E5103 — gated feature under `policy: .none`
//! * E5104 — grey-zone fragment surface in `network: .monitored` (default);
//!   the same program passes with `network: .hostile`
//! * W5100 — declared-bot identity hygiene (warning only; exit stays 0)
//!
//! Offline and deterministic: no network, fixed fixtures.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

fn fixture(name: &str, source: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fp_policy_e2e");
    fs::create_dir_all(&dir).expect("create fixture dir");
    let path = dir.join(name);
    fs::write(&path, source).expect("write fixture");
    path
}

fn check(path: &PathBuf) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("check")
        .arg(path)
        .output()
        .expect("spawn tallow check")
}

fn combined(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

const DECLARED: &str = r#"@fingerprint_policy(policy: .normalize, bot_identity: "TallowScraper/0.1 (+https://example.org/bot)")"#;

#[test]
fn e5100_feature_user_without_declaration_is_refused() {
    let path = fixture(
        "undeclared.tl",
        "fn main() {\n    let fp = Fingerprint.generate();\n    print(fp);\n}\n",
    );
    let out = check(&path);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(1), "check must fail:\n{text}");
    assert!(text.contains("E5100"), "expected E5100:\n{text}");
    assert!(
        text.contains("no `@fingerprint_policy`") || text.contains("@fingerprint_policy"),
        "diagnostic must name the missing declaration:\n{text}"
    );
}

#[test]
fn e5101_malformed_declaration_is_refused() {
    let path = fixture(
        "malformed.tl",
        "@fingerprint_policy(policy: .randomize, bot_identity: \"TallowScraper/0.1 (+https://example.org/bot)\")\nfn main() {\n    let fp = Fingerprint.generate();\n    print(fp);\n}\n",
    );
    let out = check(&path);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(1), "check must fail:\n{text}");
    assert!(text.contains("E5101"), "expected E5101:\n{text}");
}

#[test]
fn e5102_randomization_under_normalize_is_refused() {
    let path = fixture(
        "randomize.tl",
        &format!(
            "{DECLARED}\nfn main() {{\n    let fp = Fingerprint.rotate();\n    print(fp);\n}}\n"
        ),
    );
    let out = check(&path);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(1), "check must fail:\n{text}");
    assert!(text.contains("E5102"), "expected E5102:\n{text}");
}

#[test]
fn e5103_feature_under_policy_none_is_refused() {
    let path = fixture(
        "none_feature.tl",
        "@fingerprint_policy(policy: .none, bot_identity: \"TallowScraper/0.1 (+https://example.org/bot)\")\nfn main() {\n    let r = AntiDetect.check();\n    print(r);\n}\n",
    );
    let out = check(&path);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(1), "check must fail:\n{text}");
    assert!(text.contains("E5103"), "expected E5103:\n{text}");
}

#[test]
fn e5104_grey_zone_refused_in_monitored_and_allowed_in_hostile() {
    let body = "fn main() {\n    let r = TlsFragment.fragment_hello(\"example.org\");\n    print(r);\n}\n";
    let monitored = fixture("fragment_monitored.tl", &format!("{DECLARED}\n{body}"));
    let out = check(&monitored);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(1), "monitored must fail:\n{text}");
    assert!(text.contains("E5104"), "expected E5104:\n{text}");

    let hostile = fixture(
        "fragment_hostile.tl",
        &format!(
            "@fingerprint_policy(policy: .normalize, bot_identity: \"TallowScraper/0.1 (+https://example.org/bot)\", network: .hostile)\n{body}"
        ),
    );
    let out = check(&hostile);
    let text = combined(&out);
    assert_eq!(
        out.status.code(),
        Some(0),
        "hostile opt-in must pass the policy gate:\n{text}"
    );
    assert!(!text.contains("E5104"), "no E5104 under .hostile:\n{text}");
}

#[test]
fn valid_declaration_passes_and_hygiene_warns_without_failing() {
    let valid = fixture(
        "valid.tl",
        &format!(
            "@fingerprint_policy(policy: .cohort_uniform, bot_identity: \"TallowScraper/0.1 (+https://example.org/bot)\")\nfn main() {{\n    let p = StealthProfile.create(\"chrome_windows\");\n    print(p);\n}}\n"
        ),
    );
    let out = check(&valid);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(0), "valid declaration must pass:\n{text}");
    for code in ["E5100", "E5101", "E5102", "E5103", "E5104"] {
        assert!(!text.contains(code), "unexpected {code}:\n{text}");
    }

    let hygiene = fixture(
        "hygiene.tl",
        "@fingerprint_policy(policy: .normalize, bot_identity: \"TallowScraper\")\nfn main() {\n    let p = StealthProfile.create(\"chrome_windows\");\n    print(p);\n}\n",
    );
    let out = check(&hygiene);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(0), "W5100 is a warning, not an error:\n{text}");
    assert!(text.contains("W5100"), "expected W5100:\n{text}");
}
