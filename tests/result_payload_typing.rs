//! `let x = f()?` must keep the PAYLOAD's kind, not fall back to "bare i64".
//!
//! The native `?` lowering had no way to learn the payload type of a call — it
//! asked `infer_kind`, which has no `Call` arm — so it always produced an i64.
//! A `Result<bool>` payload printed `1` and a `Result<String>` payload printed
//! the pointer as a decimal integer, while the interpreter printed `true` and
//! `hello`. Nothing crashed: the wrong value was simply printed, which is worse.
//!
//! The fix has two halves, both in `codegen.rs`: `collect_fn_return_kinds` now
//! records primitive return kinds (it only recorded String/Bytes/struct), and
//! the `?` lowering consults the callee's signature when `infer_kind` is silent,
//! returning `i1` for a bool payload and a string pointer for a String payload.

const PROGRAM: &str = r#"
fn flag() -> Result<bool> {
    Ok(true)
}

fn label() -> Result<String> {
    Ok("hello")
}

fn count() -> Result<i64> {
    Ok(7)
}

fn main() {
    let b = flag()?
    print("bool=" + b.to_string())
    let s = label()?
    print("str=" + s)
    print("len=" + s.len().to_string())
    let n = count()?
    print("int=" + n.to_string())
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
fn a_question_mark_payload_keeps_its_kind_on_both_planes() {
    let path = std::env::temp_dir().join(format!("tallow-res-payload-{}.tl", std::process::id()));
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

    let expected = "bool=true\nstr=hello\nlen=5\nint=7\n";
    assert_eq!(interp_out, expected, "interpreter payload typing moved");
    assert_eq!(
        native_out, expected,
        "the native plane lost the payload kind: {native_out:?}"
    );
}
