//! A `Result` used as a condition is `Ok => true`, `Err => false` on both
//! planes (`interp.rs::Value::is_truthy`). The native catch-all read the box
//! pointer, which is non-null for both — so `if f(false)` took the true branch.

const PROGRAM: &str = r#"
fn f(ok: bool) -> Result<String> {
    if ok {
        return Ok("x")
    }
    return Err("bad")
}

fn main() {
    if f(true) { print("t1") } else { print("t0") }
    if f(false) { print("f1") } else { print("f0") }
}
"#;

fn run(program: &std::path::Path, extra: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .args(extra)
        .arg(program)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow")
}

#[test]
fn result_truthiness_is_ok_on_both_planes() {
    let path = std::env::temp_dir().join(format!("tallow-res-truth-{}.tl", std::process::id()));
    std::fs::write(&path, PROGRAM).expect("write program");

    let interpreted = run(&path, &["--interpret"]);
    let native = run(&path, &["--require-native"]);
    let _ = std::fs::remove_file(&path);

    let interp_out = String::from_utf8_lossy(&interpreted.stdout).to_string();
    let native_out = String::from_utf8_lossy(&native.stdout).to_string();
    let native_err = String::from_utf8_lossy(&native.stderr).to_string();

    assert!(
        interpreted.status.success(),
        "interpreter leg failed:\n{interp_out}\n{}",
        String::from_utf8_lossy(&interpreted.stderr)
    );
    assert!(
        native.status.success(),
        "native leg failed:\n{native_out}\n{native_err}"
    );
    assert!(
        !native_err.contains("native build unavailable"),
        "native leg fell back to the interpreter:\n{native_err}"
    );

    let expected = "t1\nf0\n";
    assert_eq!(interp_out, expected, "interpreter truthiness moved");
    assert_eq!(
        native_out, expected,
        "the native plane treats Err as truthy: {native_out:?}"
    );
}
