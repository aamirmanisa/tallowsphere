//! A closed stdout must end the process the way a Unix tool ends: killed by
//! SIGPIPE, quietly. Not a panic, and certainly not the ICE banner.
//!
//! Register #103. Rust ignores SIGPIPE by default, so the write after the
//! reader goes away returns EPIPE and `println!` panics; with `panic = "abort"`
//! in the release profile the process dies of SIGABRT (shell: "Aborted (core
//! dumped)") and the panic hook prints an internal-compiler-error report.
//!
//! Race-free reproducer: `--version | true`. `true` exits without reading, so
//! the read end is closed before tallow's first write — measured 10/10 against
//! the unfixed release binary, versus 2/10 for `| head -1` (which sometimes
//! wins the race and never sees EPIPE). `pipefail` makes the pipeline report
//! tallow's fate instead of `true`'s success: SIGPIPE is 141, SIGABRT is 134.

use std::path::{Path, PathBuf};
use std::process::Command;

const RUNS: usize = 10;
const SIGPIPE_EXIT: i32 = 128 + 13;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn tallow_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("TALLOW_BIN") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    // Prefer the NEWEST binary (#100): a stale release build would make this
    // test testify about a tree that predates the fix.
    let release = repo_root().join("target/release/tallow");
    let debug = repo_root().join("target/debug/tallow");
    let mtime = |p: &PathBuf| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    match (mtime(&release), mtime(&debug)) {
        (Some(r), Some(d)) if r >= d => release,
        (Some(_), Some(_)) => debug,
        (Some(_), None) => release,
        (None, Some(_)) => debug,
        (None, None) => debug,
    }
}

fn quote(p: &Path) -> String {
    format!("'{}'", p.display())
}

#[test]
fn closing_stdout_kills_with_sigpipe_instead_of_panicking() {
    let bin = tallow_bin();
    assert!(
        bin.exists(),
        "no tallow binary at {} — build it first (cargo build --bin tallow)",
        bin.display()
    );

    // `--version` is the shortest output path, so this is the first write and
    // nothing else can mask the disposition.
    let script = format!("set -o pipefail; {} --version | true", quote(&bin));
    let mut failures = Vec::new();

    for run in 0..RUNS {
        let out = Command::new("bash")
            .arg("-c")
            .arg(&script)
            .output()
            .expect("failed to run bash");
        let stderr = String::from_utf8_lossy(&out.stderr);
        let code = out.status.code();
        let panicked = stderr.contains("ICE") || stderr.contains("Broken pipe");
        if panicked || code != Some(SIGPIPE_EXIT) {
            failures.push(format!(
                "run {run}: exit {code:?}, stderr: {}",
                stderr.trim().replace('\n', " | ")
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {RUNS} runs did not end with SIGPIPE ({SIGPIPE_EXIT}):\n{}",
        failures.len(),
        failures.join("\n")
    );
}
