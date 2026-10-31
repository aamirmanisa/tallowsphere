//! Differential test: `tallow gate docs-examples` must agree with
//! `scripts/docs_examples.py` on the live tree.
//!
//! Both implementations must resolve the *same* binary. Each prefers
//! `target/debug/tallow` in this repo, so on a built tree they execute the same
//! examples with the same interpreter. On a tree where the binary is absent both
//! must refuse rather than fall back to a `tallow` on PATH — that fallback was
//! measured on this box to produce a false "expected failure ['E0125'], but did
//! not print" for a spec example that is correct.

use std::path::Path;
use std::process::Command;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn rust_gate_matches_python_original() {
    let py = root().join("scripts/docs_examples.py");
    if !py.is_file() {
        eprintln!("scripts/docs_examples.py is gone; the port is the only implementation");
        return;
    }
    let binary_present = ["target/debug/tallow", "target/release/tallow"]
        .iter()
        .any(|rel| root().join(rel).exists());
    if !binary_present {
        eprintln!("no repo binary built; the comparison would exercise only the refusal path");
    }

    let python = Command::new("python3")
        .arg(&py)
        .current_dir(root())
        .output()
        .expect("python3 must be available for the differential check");
    let rust = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["gate", "docs-examples"])
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
