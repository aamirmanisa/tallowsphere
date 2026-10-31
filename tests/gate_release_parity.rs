//! Differential tests: `tallow gate release-body` and `tallow gate test-summary`
//! must agree with their Python originals in stdout, stderr and exit code.
//!
//! Both are byte-sensitive in ways that look cosmetic and are not:
//!
//! * `release_body.py` ends its output with a blank line, because `print()`
//!   appends a newline to a block that already ends in one. The first Rust port
//!   emitted a single `\n` at EOF and one fewer blank line before the `---`
//!   rule — every version differed, exit codes agreed, and only the byte
//!   comparison caught it.
//! * `test_summary.py` groups thousands with `{:,}`. Rust's format machinery has
//!   no integer grouping flag at all, so the port carries an explicit formatter.
//!   A port that printed `9529` instead of `9,529` would still "pass" a
//!   human-readable review.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn run_py(script: &str, args: &[&str]) -> Option<Output> {
    let p = root().join("scripts").join(script);
    if !p.is_file() {
        return None;
    }
    Some(
        Command::new("python3")
            .arg(&p)
            .args(args)
            .current_dir(root())
            .output()
            .expect("python3 must be available"),
    )
}

fn run_rust(gate: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("gate")
        .arg(gate)
        .args(args)
        .current_dir(root())
        .output()
        .expect("the tallow binary must run")
}

fn assert_same(label: &str, py: &Output, rs: &Output) {
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
        "[{label}] stdout differs"
    );
    assert_eq!(
        String::from_utf8_lossy(&py.stderr),
        String::from_utf8_lossy(&rs.stderr),
        "[{label}] stderr differs"
    );
}

const RELEASE_VERSIONS: [&str; 5] = ["v1.5.8", "v1.5.7", "v1.5.3", "v1.5.0", "v1.4.0"];

#[test]
fn release_body_matches_python_for_every_section() {
    for v in RELEASE_VERSIONS {
        let Some(py) = run_py("release_body.py", &[v]) else {
            eprintln!("scripts/release_body.py is gone; the port is the only implementation");
            return;
        };
        let rs = run_rust("release-body", &[v]);
        assert_same(v, &py, &rs);
    }
}

#[test]
fn release_body_check_mode_matches() {
    let Some(py) = run_py("release_body.py", &["v1.5.8", "--check"]) else {
        return;
    };
    let rs = run_rust("release-body", &["v1.5.8", "--check"]);
    assert_same("check", &py, &rs);
}

#[test]
fn release_body_missing_section_matches() {
    let Some(py) = run_py("release_body.py", &["v9.9.9"]) else {
        return;
    };
    let rs = run_rust("release-body", &["v9.9.9"]);
    assert_same("missing", &py, &rs);
}

#[test]
fn release_body_usage_error_matches() {
    let Some(py) = run_py("release_body.py", &[]) else {
        return;
    };
    let rs = run_rust("release-body", &[]);
    // argparse's usage text is its own; only the exit code is contractual.
    assert_eq!(py.status.code(), rs.status.code(), "exit codes differ");
    assert_eq!(py.status.code(), Some(64));
}

#[test]
fn test_summary_matches_python() {
    let tmp = std::env::temp_dir().join(format!("tallow-tsum-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let lib = tmp.join("lib.log");
    let conf = tmp.join("conf.log");
    std::fs::write(
        &lib,
        "running 5 tests\ntest result: ok. 9529 passed; 0 failed; 3 ignored; 0 measured\n",
    )
    .unwrap();
    std::fs::write(&conf, "ran 62 cases; 0 failure(s)\n").unwrap();
    let (l, c) = (lib.to_string_lossy().into_owned(), conf.to_string_lossy().into_owned());
    let args = [
        "--lib".to_string(),
        l,
        "--conformance".to_string(),
        c,
        "--sha".to_string(),
        "deadbeefcafe".to_string(),
    ];
    let argrefs: Vec<&str> = args.iter().map(String::as_str).collect();

    let Some(py) = run_py("test_summary.py", &argrefs) else {
        return;
    };
    let rs = run_rust("test-summary", &argrefs);
    assert_same("test-summary", &py, &rs);

    // A log with no `test result:` line must refuse in both, not report zero.
    std::fs::write(&lib, "running 0 tests\n").unwrap();
    let Some(py) = run_py("test_summary.py", &argrefs) else {
        return;
    };
    let rs = run_rust("test-summary", &argrefs);
    assert_same("test-summary-no-measurement", &py, &rs);
    assert_eq!(py.status.code(), Some(1));

    let _ = PathBuf::from(&tmp).is_dir();
    let _ = std::fs::remove_dir_all(&tmp);
}
