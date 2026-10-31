//! Awaited spawn payloads must keep their static kind on both planes.
//!
//! Measured before the fix (`target/debug/tallow`, git 0d8de9383c dirty):
//!
//!     fn work() -> String { return "hello" }
//!     --interpret      -> hello
//!     --require-native -> <pointer bits as i64>, exit 0
//!
//!     fn work() -> Map { return {"n": 50} }
//!     --interpret      -> nil
//!     --require-native -> <pointer bits as i64>, exit 0
//!
//! The Await arm loaded TallowResult.value as i64 unconditionally; the
//! interpreter's spawn join dropped Map on the JSON wire. i64 double-await
//! was already correct (50/50) and must stay that way.
//!
//! Both legs: `run --interpret` and `run --require-native`. Never unflagged
//! `run` — it hides native fallback.

use std::hash::{Hash, Hasher};
use std::process::Output;

fn run(program: &str, plane: &str) -> Output {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    program.hash(&mut h);
    plane.hash(&mut h);
    let path = std::env::temp_dir().join(format!(
        "tallow-await-kind-{:016x}-{}.tl",
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

fn assert_planes(program: &str, expected: &str) {
    let interp = run(program, "--interpret");
    let native = run(program, "--require-native");
    let i_out = String::from_utf8_lossy(&interp.stdout).to_string();
    let n_out = String::from_utf8_lossy(&native.stdout).to_string();
    let i_err = String::from_utf8_lossy(&interp.stderr).to_string();
    let n_err = String::from_utf8_lossy(&native.stderr).to_string();
    assert!(
        interp.status.success(),
        "--interpret failed (exit {:?}): stdout={i_out:?} stderr={i_err}",
        interp.status.code()
    );
    assert!(
        native.status.success(),
        "--require-native failed (exit {:?}): stdout={n_out:?} stderr={n_err}",
        native.status.code()
    );
    assert!(
        !n_err.contains("native build unavailable"),
        "--require-native fell back: {n_err}"
    );
    assert_eq!(
        i_out, expected,
        "--interpret stdout diverged from the pinned block"
    );
    assert_eq!(
        n_out, i_out,
        "planes disagree: interpret={i_out:?} native={n_out:?}"
    );
}

const I64: &str = r#"
fn work() -> i64 { return 50 }
fn main() {
    let h = spawn work()
    let v = h.await
    print(v)
}
"#;

const STRING: &str = r#"
fn work() -> String { return "hello" }
fn main() {
    let h = spawn work()
    let v = h.await
    print(v)
}
"#;

const MAP: &str = r#"
fn work() -> Map { return {"n": 50} }
fn main() {
    let h = spawn work()
    let v = h.await
    print(v.len)
    print(v["n"])
}
"#;

const BOOL: &str = r#"
fn work() -> bool { return true }
fn main() {
    let h = spawn work()
    let v = h.await
    print(v)
}
"#;

const DOUBLE_AWAIT_I64: &str = r#"
fn work() -> i64 { return 50 }
fn main() {
    let h = spawn work()
    let a = h.await
    let b = h.await
    print(a)
    print(b)
}
"#;

const DOUBLE_AWAIT_STRING: &str = r#"
fn work() -> String { return "hello" }
fn main() {
    let h = spawn work()
    let a = h.await
    let b = h.await
    print(a)
    print(b)
}
"#;

#[test]
fn i64_payload_agrees_on_both_planes() {
    assert_planes(I64, "50\n");
}

#[test]
fn string_payload_agrees_on_both_planes() {
    assert_planes(STRING, "hello\n");
}

#[test]
fn map_payload_len_and_key_agree_on_both_planes() {
    assert_planes(MAP, "1\n50\n");
}

#[test]
fn bool_payload_agrees_on_both_planes() {
    assert_planes(BOOL, "true\n");
}

#[test]
fn i64_payload_printed_twice_from_two_awaits() {
    assert_planes(DOUBLE_AWAIT_I64, "50\n50\n");
}

#[test]
fn string_payload_printed_twice_from_two_awaits() {
    assert_planes(DOUBLE_AWAIT_STRING, "hello\nhello\n");
}
