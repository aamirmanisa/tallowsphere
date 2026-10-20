//! Function values must be callable on both planes (register #124).
//!
//! A `fn(..)`-typed binding used to be uncallable natively: the backend emitted a call
//! to the binding's name, which is not a symbol, and `apply(add, 2, 40)` returned 2 with
//! exit 0. Function values now carry the closure ABI — a pointer called as
//! `i64 (ptr env, args…)` — with a thunk generated per named function and a null env for
//! non-capturing values. A capturing closure crosses a boundary as the same pair,
//! with a heap-allocated environment, and still renders identically on both planes.

const NAMED: &str = r#"
fn add(a: i64, b: i64) -> i64 { a + b }
fn apply(f: fn(i64, i64) -> i64, a: i64, b: i64) -> i64 { f(a, b) }

fn main() {
    print(apply(add, 2, 40))
    let g = add
    print(g(20, 22))
}
"#;

const CLOSURE_VALUE: &str = r#"
fn apply(f: fn(i64) -> i64, x: i64) -> i64 { f(x) }

fn main() {
    print(apply({ y -> y * 3 }, 14))
}
"#;

const CAPTURING_ACROSS: &str = r#"
fn apply(f: fn(i64) -> i64, x: i64) -> i64 { f(x) }

fn main() {
    let triple = 3
    print(apply({ y -> y * triple }, 14))
}
"#;

fn run(program: &str, args: &[&str], name: &str) -> std::process::Output {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    program.hash(&mut h);
    let path = std::env::temp_dir().join(format!("tallow-fnvalue-{:016x}-{name}.tl", h.finish()));
    std::fs::write(&path, program).expect("write program");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .args(args)
        .arg(&path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);
    out
}

fn assert_renders(program: &str, expected: &str, name: &str) {
    for plane in [&["--interpret"][..], &["--require-native"][..]] {
        let out = run(program, plane, name);
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(out.status.success(), "[{plane:?}] failed: {stdout}{stderr}");
        assert!(
            !stderr.contains("native build unavailable"),
            "[{plane:?}] fell back to the interpreter: {stderr}"
        );
        assert_eq!(stdout, expected, "[{plane:?}] {name}");
    }
}

#[test]
fn a_named_function_value_is_callable_on_both_planes() {
    assert_renders(NAMED, "42\n42\n", "named");
}

#[test]
fn a_non_capturing_closure_is_callable_through_a_parameter() {
    assert_renders(CLOSURE_VALUE, "42\n", "closure-value");
}

#[test]
fn a_capturing_closure_crosses_a_call_boundary() {
    // #127: the value is a {code, env} pair and the environment is heap-allocated,
    // so a capturing closure stays callable after the defining frame is gone.
    assert_renders(CAPTURING_ACROSS, "42\n", "capturing");

    let stored = r#"
fn apply(f: fn(i64) -> i64, x: i64) -> i64 { f(x) }

fn main() {
    let multiplier = 3
    let triple = { y -> y * multiplier }
    print(apply(triple, 14))
}
"#;
    assert_renders(stored, "42\n", "capturing-stored");
}
