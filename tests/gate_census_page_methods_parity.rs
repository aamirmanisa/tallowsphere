//! Differential test: `tallow gate census-page-methods` must agree with
//! `scripts/census_page_methods.py` on the live tree.
//!
//! Kept while the Python original is still present. Exit code 2 is meaningful
//! here — the parse found nothing, which is a failure of the scan rather than of
//! the surface — so the comparison checks codes as well as output.

use std::path::Path;
use std::process::Command;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn rust_gate_matches_python_original() {
    let py = root().join("scripts/census_page_methods.py");
    if !py.is_file() {
        eprintln!("scripts/census_page_methods.py is gone; the port is the only implementation");
        return;
    }
    let python = Command::new("python3")
        .arg(&py)
        .current_dir(root())
        .output()
        .expect("python3 must be available for the differential check");
    let rust = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["gate", "census-page-methods"])
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
