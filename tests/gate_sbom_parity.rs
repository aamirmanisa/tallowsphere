//! Differential test: `tallow gate sbom` must agree with `scripts/sbom-gen.py`
//! on the live tree, in all three modes.
//!
//! The `--check` mode is the one that matters: it compares the *exact bytes* of
//! the committed snapshot against a regenerated artifact, so a rendering
//! difference that a human would call cosmetic is a behavioural difference here
//! — it reports drift on a tree that is not drifted. Both implementations are
//! compared on stdout, stderr and exit code.
//!
//! Note on the tree: `scripts/sbom.snapshot.json` was stale when this file was
//! written (`lockfileSha256` differed while `packageCount` matched at 751), so the
//! `--check` comparison was designed against a genuinely drifted snapshot. It is
//! current again as of 2026-10-31 (`sha256sum Cargo.lock` =
//! 50b0881b…3f44cd878, which is `lockfileSha256` in the snapshot), so what this
//! file exercises today is the happy path on both sides.
//!
//! What it does NOT do: it never asserts that drift is *absent*. It compares two
//! implementations of the same generator on the same tree, so on a drifted tree
//! both exit 1 with identical output and every test here passes. That is why
//! `python3 scripts/sbom-gen.py --check …` is now also a step of the release gate
//! (measured 2026-10-31: the release workflow ran no SBOM check at all).

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
