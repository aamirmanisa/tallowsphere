//! Differential test: `tallow gate census-surface` must agree with
//! `scripts/census_surface.py` on the live tree.
//!
//! Kept while the Python original is still present. During the port this
//! comparison caught a real undercount: the registry spells entries as
//! `Page.resolve_antibot (opts map)`, the Python's `re.match(r"Page\.(\w+)")`
//! takes the ident prefix, and a Rust port requiring the ident to be the whole
//! remainder found 1 Page entry where the original found 3 — the exact
//! "checker that undercounts its population" defect the gate exists to catch.

use std::path::Path;
use std::process::Command;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn rust_gate_matches_python_original() {
    let py = root().join("scripts/census_surface.py");
    if !py.is_file() {
        eprintln!("scripts/census_surface.py is gone; the port is the only implementation");
        return;
    }
    let python = Command::new("python3")
        .arg(&py)
        .current_dir(root())
        .output()
        .expect("python3 must be available for the differential check");
    let rust = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["gate", "census-surface"])
        .current_dir(root())
        .output()
        .expect("the tallow binary must run");

    assert_eq!(
        python.status.code(),
        rust.status.code(),
        "exit codes differ: python {:?} rust {:?}\npython stderr: {}\nrust stderr: {}",
        python.status.code(),
        rust.status.code(),
        String::from_utf8_lossy(&python.stderr),
        String::from_utf8_lossy(&rust.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&python.stdout).trim_end(),
        String::from_utf8_lossy(&rust.stdout).trim_end(),
        "output differs between the Python original and the Rust port"
    );
}
