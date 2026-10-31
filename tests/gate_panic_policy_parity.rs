//! Differential test: `tallow gate panic-policy` must agree with
//! `scripts/panic_policy_check.py` on the live tree.
//!
//! Kept while the Python original is still present. The comparison earned its
//! keep immediately: the first Rust version carried `catch_unwind(` inside its
//! own test-string literals, so the gate — correctly applying its own rule that
//! every call site under `src/` must be declared — reported three undocumented
//! call sites in the file that enforces the rule. The Python oracle and the port
//! agreed (both FAIL), which is what exposed it as a defect in the new file
//! rather than in the scan. Fixtures are now built at runtime.

use std::path::Path;
use std::process::Command;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn rust_gate_matches_python_original() {
    let py = root().join("scripts/panic_policy_check.py");
    if !py.is_file() {
        eprintln!("scripts/panic_policy_check.py is gone; the port is the only implementation");
        return;
    }
    let python = Command::new("python3")
        .arg(&py)
        .current_dir(root())
        .output()
        .expect("python3 must be available for the differential check");
    let rust = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["gate", "panic-policy"])
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
