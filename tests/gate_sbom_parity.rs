//! Differential test: `tallow gate sbom` must agree with `scripts/sbom-gen.py`
//! on the live tree, in all three modes.
//!
//! The `--check` mode is the one that matters: it compares the *exact bytes* of
//! the committed snapshot against a regenerated artifact, so a rendering
//! difference that a human would call cosmetic is a behavioural difference here
//! — it reports drift on a tree that is not drifted. Both implementations are
//! compared on stdout, stderr and exit code.
//!
//! Note on the tree: `scripts/sbom.snapshot.json` is currently stale
//! (`lockfileSha256` differs although `packageCount` matches at 751), so the
//! `--check` comparison runs against a genuinely drifted snapshot. That is the
//! interesting case — it exercises the diff output, not just the happy path.

use std::path::Path;
use std::process::{Command, Output};

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn python(args: &[&str]) -> Output {
    Command::new("python3")
        .arg(root().join("scripts/sbom-gen.py"))
        .args(args)
        .current_dir(root())
        .output()
        .expect("python3 must be available for the differential check")
}

fn rust(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("gate")
        .arg("sbom")
        .args(args)
        .current_dir(root())
        .output()
        .expect("the tallow binary must run")
}

fn compare(args: &[&str], label: &str) {
    let py = python(args);
    let rs = rust(args);
    assert_eq!(
        py.status.code(),
        rs.status.code(),
        "[{label}] exit codes differ: python {:?} rust {:?}\npy stderr: {}\nrs stderr: {}",
        py.status.code(),
        rs.status.code(),
        String::from_utf8_lossy(&py.stderr),
        String::from_utf8_lossy(&rs.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&py.stdout),
        String::from_utf8_lossy(&rs.stdout),
        "[{label}] stdout differs ({} vs {} bytes)",
        py.stdout.len(),
        rs.stdout.len()
    );
    assert_eq!(
        String::from_utf8_lossy(&py.stderr),
        String::from_utf8_lossy(&rs.stderr),
        "[{label}] stderr differs"
    );
}

#[test]
fn generator_output_matches_python_original() {
    if !root().join("scripts/sbom-gen.py").is_file() {
        eprintln!("scripts/sbom-gen.py is gone; the port is the only implementation");
        return;
    }
    compare(&[], "generate");
}

#[test]
fn drift_check_matches_python_original() {
    if !root().join("scripts/sbom-gen.py").is_file() {
        eprintln!("scripts/sbom-gen.py is gone; the port is the only implementation");
        return;
    }
    compare(&["--check", "scripts/sbom.snapshot.json"], "check");
}

#[test]
fn missing_snapshot_is_an_error_in_both() {
    if !root().join("scripts/sbom-gen.py").is_file() {
        return;
    }
    compare(&["--check", "scripts/does-not-exist.json"], "missing-snapshot");
}
