//! R1 vault access wiring — CLI accept tests (design §6 #7–9 + audience/embargo).
//!
//! Spawns the real compiled binary (`CARGO_BIN_EXE_tallow`) against per-test
//! temp dirs; no daemon, no network. The export gate must refuse *before* the
//! output path is touched, and receipts land in the KT log when one is given.

use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tallow");
const PW: &str = "r1-cli-test-pw";

struct Run {
    code: i32,
    #[allow(dead_code)]
    stdout: String,
    stderr: String,
}

fn run(dir: &Path, args: &[&str]) -> Run {
    let output = Command::new(BIN)
        .args(args)
        .current_dir(dir)
        .env("TALLOW_VAULT_PASSWORD", PW)
        .env("TALLOW_SECURITY_EVENTS", dir.join("security-events.jsonl"))
        .output()
        .unwrap_or_else(|err| panic!("spawn {BIN} {args:?}: {err}"));
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn tmpdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tallow-r1-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn setup_vault(dir: &Path, vault: &str, entries: &[&str]) {
    assert_eq!(run(dir, &["vault", "create", vault, "--name", "T"]).code, 0);
    for e in entries {
        assert_eq!(
            run(
                dir,
                &[
                    "vault",
                    "add",
                    vault,
                    "--entry-type",
                    "note",
                    "--name",
                    e,
                    "--content",
                    "x",
                ],
            )
            .code,
            0
        );
    }
}

fn write_config(dir: &Path, body: &str) {
    std::fs::write(dir.join("tallow.toml"), body).unwrap();
}

#[test]
fn export_requires_explicit_audience() {
    let d = tmpdir("aud");
    setup_vault(&d, "v.twv", &["n1"]);
    let r = run(
        &d,
        &["vault", "export", "v.twv", "out.json", "--format", "json"],
    );
    assert_eq!(r.code, 4, "stderr: {}", r.stderr);
    assert!(r.stderr.contains("deny.audience-required"), "{}", r.stderr);
    assert!(!d.join("out.json").exists());
    let r = run(
        &d,
        &[
            "vault",
            "export",
            "v.twv",
            "out.json",
            "--format",
            "json",
            "--audience",
            "nope",
        ],
    );
    assert_eq!(r.code, 4, "stderr: {}", r.stderr);
    assert!(r.stderr.contains("deny.audience-invalid"), "{}", r.stderr);
    assert!(!d.join("out.json").exists());
}

#[test]
fn sealed_entry_is_never_released() {
    let d = tmpdir("sealed");
    setup_vault(&d, "v.twv", &["prod-root-key"]);
    write_config(&d, "[access.entry_class]\n\"prod-root-key\" = \"sealed\"\n");
    let r = run(
        &d,
        &[
            "vault",
            "export",
            "v.twv",
            "out.json",
            "--format",
            "json",
            "--audience",
            "public",
        ],
    );
    assert_eq!(r.code, 4, "stderr: {}", r.stderr);
    assert!(r.stderr.contains("deny.sealed"), "{}", r.stderr);
    assert!(
        !d.join("out.json").exists(),
        "refusal must not create the output"
    );
    let r = run(&d, &["vault", "get", "v.twv", "prod-root-key"]);
    assert_eq!(r.code, 4, "stderr: {}", r.stderr);
    assert!(
        r.stderr.contains("read denied: deny.sealed"),
        "{}",
        r.stderr
    );
}

#[test]
fn open_vault_exports_with_receipt_and_redaction() {
    let d = tmpdir("open");
    setup_vault(&d, "v.twv", &["note-a", "note-b"]);
    write_config(
        &d,
        "[access.entry_class]\n\"note-a\" = \"open\"\n\"note-b\" = \"open\"\n\n[redaction]\nremove = [\"folders\"]\n",
    );
    let r = run(
        &d,
        &[
            "vault",
            "export",
            "v.twv",
            "out.json",
            "--format",
            "json",
            "--audience",
            "public",
            "--kt-log",
            "kt.jsonl",
        ],
    );
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(r.stderr.contains("receipt: "), "{}", r.stderr);
    let out = std::fs::read_to_string(d.join("out.json")).unwrap();
    assert!(out.contains("\"items\""), "export missing items: {out}");
    assert!(
        !out.contains("folders"),
        "redaction rule not applied: {out}"
    );
    let kt = std::fs::read_to_string(d.join("kt.jsonl")).unwrap();
    assert!(
        kt.contains("\"entry_hash\""),
        "kt chain entry missing: {kt}"
    );
    let payloads = std::fs::read_to_string(d.join("kt.jsonl.payloads.jsonl")).unwrap();
    assert!(payloads.contains("vault_export"), "{payloads}");
    assert!(payloads.contains("receipt_hash"), "{payloads}");
}

#[test]
fn unclassified_export_refused_but_list_still_works() {
    let d = tmpdir("unc");
    setup_vault(&d, "v.twv", &["n1"]);
    let r = run(
        &d,
        &[
            "vault",
            "export",
            "v.twv",
            "out.json",
            "--format",
            "json",
            "--audience",
            "operator",
        ],
    );
    assert_eq!(r.code, 4, "stderr: {}", r.stderr);
    assert!(r.stderr.contains("deny.no-export-path"), "{}", r.stderr);
    assert!(!d.join("out.json").exists());
    let r = run(&d, &["vault", "list", "v.twv"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
}

#[test]
fn embargo_refuses_even_open_material() {
    let d = tmpdir("emb");
    setup_vault(&d, "v.twv", &["note-a"]);
    write_config(
        &d,
        "[access]\nembargo_until_ms = 9999999999999\n\n[access.entry_class]\n\"note-a\" = \"open\"\n",
    );
    let r = run(
        &d,
        &[
            "vault",
            "export",
            "v.twv",
            "out.json",
            "--format",
            "json",
            "--audience",
            "public",
        ],
    );
    assert_eq!(r.code, 4, "stderr: {}", r.stderr);
    assert!(r.stderr.contains("deny.embargo-active"), "{}", r.stderr);
    assert!(!d.join("out.json").exists());
}

#[test]
fn recovery_split_gated_and_receipted() {
    let d = tmpdir("recsplit");
    setup_vault(&d, "v.twv", &["n1"]);
    // Unclassified: key-material release refused, no share files created.
    let r = run(
        &d,
        &[
            "vault",
            "recovery-split",
            "v.twv",
            "--threshold",
            "2",
            "--shares",
            "3",
        ],
    );
    assert_eq!(r.code, 4, "stderr: {}", r.stderr);
    assert!(r.stderr.contains("deny.no-export-path"), "{}", r.stderr);
    assert!(!d.join("v.twv.share-1").exists());
    // Classified open: gated release + receipt + KT entry.
    write_config(&d, "[access.entry_class]\n\"n1\" = \"open\"\n");
    let r = run(
        &d,
        &[
            "vault",
            "recovery-split",
            "v.twv",
            "--threshold",
            "2",
            "--shares",
            "3",
            "--kt-log",
            "kt.jsonl",
        ],
    );
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(r.stderr.contains("receipt: "), "{}", r.stderr);
    assert!(d.join("v.twv.share-1").exists());
    assert!(d.join("v.twv.share-3").exists());
    let payloads = std::fs::read_to_string(d.join("kt.jsonl.payloads.jsonl")).unwrap();
    assert!(payloads.contains("vault_recovery_split"), "{payloads}");
    assert!(payloads.contains("receipt_hash"), "{payloads}");
}

#[test]
fn custody_split_gated_before_any_kit_material() {
    let d = tmpdir("custsplit");
    setup_vault(&d, "v.twv", &["n1"]);
    let r = run(
        &d,
        &[
            "vault",
            "custody-split",
            "v.twv",
            "--custodian",
            "custodian-a",
            "--custodian",
            "custodian-b",
            "--out-dir",
            "kit",
            "--kt-log",
            "kt.jsonl",
        ],
    );
    assert_eq!(r.code, 4, "stderr: {}", r.stderr);
    assert!(r.stderr.contains("deny.no-export-path"), "{}", r.stderr);
    assert!(!d.join("kit").join("custody-manifest.json").exists());
    write_config(&d, "[access.entry_class]\n\"n1\" = \"open\"\n");
    let r = run(
        &d,
        &[
            "vault",
            "custody-split",
            "v.twv",
            "--custodian",
            "custodian-a",
            "--custodian",
            "custodian-b",
            "--out-dir",
            "kit",
            "--kt-log",
            "kt.jsonl",
        ],
    );
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(d.join("kit").join("custody-manifest.json").exists());
}
