//! Malformed stdlib method calls must fail by name, not answer with zero.
//!
//! Ten codegen arms ended with `return Ok(LLValue::new("0", I64))` when a required
//! argument was missing or the wrong shape — `"abc".ends_with()` compiled and
//! printed 0 instead of reporting the bad call. Where the interpreter has a defined
//! answer for the short form (`count()` is the length) the native plane now matches
//! it; where the interpreter raises a type error, the native plane refuses by name.

use std::process::Command;

fn run(flag: &str, source: &str, tag: &str) -> (bool, String) {
    let path = std::env::temp_dir().join(format!("tallow-ref-{}-{tag}.tl", std::process::id()));
    std::fs::write(&path, source).expect("write program");
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(flag)
        .arg(&path)
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

const COUNT: &str = r#"fn main() {
    print("abcdef".count())
}
"#;

#[test]
fn count_without_argument_is_the_length_on_both_planes() {
    let (n_ok, n_out) = run("--require-native", COUNT, "n");
    let (i_ok, i_out) = run("--interpret", COUNT, "i");
    assert!(n_ok && i_ok, "native:\n{n_out}\ninterp:\n{i_out}");
    assert!(n_out.contains('6'), "native count() must be 6:\n{n_out}");
    assert!(i_out.contains('6'), "interp count() must be 6:\n{i_out}");
}

const ENDS_WITH: &str = r#"fn main() {
    print("abcdef".ends_with())
}
"#;

#[test]
fn missing_argument_is_refused_by_name_on_both_planes() {
    let (n_ok, n_out) = run("--require-native", ENDS_WITH, "n2");
    let (i_ok, i_out) = run("--interpret", ENDS_WITH, "i2");
    assert!(!n_ok, "native must refuse:\n{n_out}");
    assert!(!i_ok, "interpreter must refuse:\n{i_out}");
    assert!(
        n_out.contains("ends_with requires one argument"),
        "native refusal must name the method:\n{n_out}"
    );
}
