//! A `match` with no arm for the value must fail on both planes.
//!
//! Native used to fall through to the result type's default — `(null)` for a string
//! match, exit 0 — and for a single-arm string match it folded the guard away and ran
//! the arm body unconditionally (`"x" match { "a" -> "A" }` printed `A`). Both are
//! silent wrong answers from a shipped binary (register #123). The interpreter has
//! always raised `runtime error: non-exhaustive match`; now native calls the same
//! diagnostic through `tallow_no_match` and exits 1.

use std::process::Output;

const INT_NO_MATCH: &str = r#"
fn main() {
    let x = 9
    let s = x match { 1 -> "one" 2 -> "two" }
    print(s)
}
"#;

const STR_NO_MATCH: &str = r#"
fn main() {
    let s = "x"
    let r = s match { "a" -> "A" }
    print(r)
}
"#;

const STR_WITH_DEFAULT: &str = r#"
fn main() {
    let a = "a"
    let b = "x"
    print(a match { "a" -> "hit" _ -> "miss" })
    print(b match { "a" -> "hit" _ -> "miss" })
}
"#;

fn run(program: &str, plane: &str) -> Output {
    // The program text is part of the name: tests run in parallel, and a name keyed
    // only on the plane + pid lets one test's fixture clobber another's.
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    program.hash(&mut h);
    let path = std::env::temp_dir().join(format!(
        "tallow-exhaustive-{:016x}-{}.tl",
        h.finish(),
        plane.trim_start_matches('-')
    ));
    std::fs::write(&path, program).expect("write program");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["run", plane, path.to_str().expect("utf-8 path")])
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);
    out
}

fn assert_both_planes_reject(program: &str) {
    for plane in ["--interpret", "--require-native"] {
        let out = run(program, plane);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            out.status.code(),
            Some(1),
            "[{plane}] expected a failing exit, got {:?}: {stdout}{stderr}",
            out.status.code()
        );
        assert!(
            stderr.contains("non-exhaustive match"),
            "[{plane}] expected the diagnostic, got: {stderr}"
        );
        assert!(
            !stdout.contains("(null)") && !stdout.contains("A\n"),
            "[{plane}] a value leaked out of a non-exhaustive match: {stdout}"
        );
    }
}

#[test]
fn int_subject_without_a_matching_arm_fails_on_both_planes() {
    assert_both_planes_reject(INT_NO_MATCH);
}

#[test]
fn string_subject_without_a_matching_arm_fails_on_both_planes() {
    assert_both_planes_reject(STR_NO_MATCH);
}

#[test]
fn string_match_still_selects_and_defaults_correctly() {
    let interp = run(STR_WITH_DEFAULT, "--interpret");
    let native = run(STR_WITH_DEFAULT, "--require-native");
    let i = String::from_utf8_lossy(&interp.stdout).to_string();
    let n = String::from_utf8_lossy(&native.stdout).to_string();
    let native_err = String::from_utf8_lossy(&native.stderr).to_string();
    assert!(interp.status.success(), "interpreter: {i}");
    assert!(native.status.success(), "native: {n}\n{native_err}");
    assert_eq!(i, "hit\nmiss\n");
    assert_eq!(n, i, "the planes disagree on string match selection");
}
