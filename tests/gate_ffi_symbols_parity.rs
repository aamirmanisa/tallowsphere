//! Differential test: `tallow gate ffi-symbols` must agree with the Python
//! original it is replacing, on the live tree.
//!
//! The port is only trustworthy if it reproduces the original exactly — same
//! summary line, same problem lines, same exit code. This test runs both against
//! the current tree and compares. It is deliberately kept while the Python
//! script is still present; once the Python is deleted the test's Python arm
//! becomes a no-op and the unit tests in `src/gate/ffi_symbols.rs` carry the
//! coverage.
//!
//! Two defects were caught by exactly this comparison during the port:
//!   * a crate panic (index out of bounds) that the original never hit;
//!   * `310 + 21 = 331` where the original's `defined |= ...` is a set union
//!     and prints 329, because two symbols are in both sets.

use std::path::Path;
use std::process::Command;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn rust_gate_matches_python_original() {
    let py = root().join("scripts/check_ffi_symbols.py");
    if !py.is_file() {
        eprintln!("scripts/check_ffi_symbols.py is gone; the port is the only implementation");
        return;
    }
    let python = Command::new("python3")
        .arg(&py)
        .current_dir(root())
        .output()
        .expect("python3 must be available for the differential check");
    let rust = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["gate", "ffi-symbols"])
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
