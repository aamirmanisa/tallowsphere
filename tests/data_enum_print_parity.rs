//! Printing a payload-carrying enum must never emit raw bytes (register #125).
//!
//! `print(Status.Pending(reason: "why"))` used to print a control byte natively: the
//! value is a tagged struct, and the string printer walked its tag. Native now refuses
//! to compile that print, so `tallow run` falls back to the interpreter (which renders
//! `Pending("why")`) and `--require-native` reports why instead of producing garbage.

const PROGRAM: &str = r#"
enum Status {
    Active,
    Pending(reason: String)
}

fn main() {
    print(Status.Pending(reason: "why"))
}
"#;

fn run(program: &str, args: &[&str], name: &str) -> std::process::Output {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    program.hash(&mut h);
    let path = std::env::temp_dir().join(format!("tallow-dataenum-{:016x}-{name}.tl", h.finish()));
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

#[test]
fn printing_a_payload_variant_renders_it_or_refuses_loudly() {
    // The default path must produce the interpreter's rendering, never a byte.
    let default = run(PROGRAM, &[], "default");
    let stdout = String::from_utf8_lossy(&default.stdout).to_string();
    assert!(default.status.success(), "default run failed: {stdout}");
    assert_eq!(stdout.trim(), "Pending(\"why\")", "rendering changed: {stdout:?}");

    // The native-only path must refuse with a reason, not print garbage.
    let native = run(PROGRAM, &["--require-native"], "native");
    let stderr = String::from_utf8_lossy(&native.stderr).to_string();
    assert_eq!(native.status.code(), Some(1), "expected refusal: {stderr}");
    assert!(
        stderr.contains("cannot print a data-carrying enum natively"),
        "expected the refusal message, got: {stderr}"
    );
    assert!(
        stderr.contains("struct, not a string"),
        "the refusal message carries continuation padding: {stderr}"
    );
    let native_stdout = String::from_utf8_lossy(&native.stdout).to_string();
    assert!(
        !native_stdout.chars().any(|c| c.is_control()),
        "a control byte leaked: {native_stdout:?}"
    );
}
