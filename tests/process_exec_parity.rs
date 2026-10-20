//! `process.exec` on both planes: the declared `Output` must carry the child's
//! real stdout, stderr and status.
//!
//! The native arm used to refuse because it could only read an exit status;
//! before that it returned a bare number that every field read turned into 0.
//! This is the acceptance gate for the popen FFI (`src/runtime/process_ffi.rs`).

const PROGRAM: &str = r#"
fn main() {
    let out = process.exec("/bin/sh", ["-c", "printf out; printf err 1>&2; exit 3"])
    print(out.stdout)
    print(out.stderr)
    print(out.exit_code)
    print(out.success)
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
fn process_exec_captures_the_same_output_on_both_planes() {
    let path = std::env::temp_dir().join(format!("tallow-process-{}.tl", std::process::id()));
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
        "native leg failed — the popen lowering is not reachable:\n{native_out}\n{native_err}"
    );
    assert!(
        !native_err.contains("native build unavailable"),
        "native leg fell back to the interpreter:\n{native_err}"
    );

    let expected = "out\nerr\n3\nfalse\n";
    assert_eq!(interp_out, expected, "the interpreter's Output moved");
    assert_eq!(
        native_out, expected,
        "the native plane reports different Output fields: {native_out:?}"
    );
}
