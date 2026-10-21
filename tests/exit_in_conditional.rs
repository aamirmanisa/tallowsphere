//! `exit` inside a conditional, on the compiled plane.
//!
//! `process.exit(n)` and bare `exit(n)` emit `unreachable`. The enclosing `if`
//! then appended its own `br label %merge` after that terminator, which LLVM
//! rejects — reporting it as an instruction-numbering error, which names the
//! symptom and not the cause. Any program that exited from inside a conditional
//! therefore lost its native plane.

use std::path::PathBuf;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tallow"))
}

fn program(tag: &str, source: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("tallow-exit-cond-{tag}.tl"));
    std::fs::write(&path, source).expect("write program");
    path
}

fn native(path: &PathBuf) -> std::process::Output {
    std::process::Command::new(bin())
        .args(["run", "--require-native"])
        .arg(path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow")
}

#[test]
fn process_exit_inside_an_if_keeps_the_native_plane() {
    let prog = program(
        "process",
        "fn main() {\n    var found: i64 = 1\n    if found > 0 {\n        process.exit(1)\n    }\n}\n",
    );
    let out = native(&prog);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains("native build unavailable"),
        "the native plane must survive an exit inside a conditional; got: {err}"
    );
    assert_eq!(out.status.code(), Some(1), "the exit code must be the one asked for");
}

#[test]
fn bare_exit_inside_a_loop_carries_its_code() {
    let prog = program(
        "loop",
        "fn main() {\n    for i in 0..2 {\n        if i > 0 {\n            exit(3)\n        }\n    }\n}\n",
    );
    let out = native(&prog);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("native build unavailable"), "got: {err}");
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn a_conditional_that_does_not_exit_still_branches_normally() {
    let prog = program(
        "normal",
        "fn main() {\n    let x: i64 = 5\n    if x > 1 {\n        print(\"big\")\n    } else {\n        print(\"small\")\n    }\n}\n",
    );
    let out = native(&prog);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "big\n");
}
