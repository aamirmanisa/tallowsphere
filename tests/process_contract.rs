//! The `process` module must behave as its declaration says, or refuse by name.
//!
//! Three defects were fixed here:
//!   * `Process.is_running` was declared with an empty body and lowered nowhere.
//!   * The runtime produced `ChildProcess`/`ProcessResult` while `stdlib/process.tl`
//!     declared `Process`/`Output` — the declared types were unnameable.
//!   * `args: []String` was never flattened: `process.exec("echo", ["hello"])`
//!     handed the child the literal string `["hello"]`.
//! And one refusal: native `process.exec` cannot capture stdout, so instead of
//! returning a bare number that every field read turned into 0, it errors.

use std::process::Command;

fn run(flag: &str, source: &str, tag: &str) -> (bool, String) {
    let path = std::env::temp_dir().join(format!("tallow-proc-{}-{tag}.tl", std::process::id()));
    std::fs::write(&path, source).expect("write program");
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(flag)
        .arg(&path)
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

const LIFECYCLE: &str = r#"import tallow.process

fn main() {
    let p = process.spawn("sleep", ["5"])
    print("pid=" + p.pid)
    print("alive=" + p.is_running())
    p.kill()
    print("alive_after_kill=" + p.is_running())
}
"#;

#[test]
fn spawn_kill_and_is_running_are_real() {
    let (ok, out) = run("--interpret", LIFECYCLE, "life");
    assert!(ok, "interpreter leg failed:\n{out}");
    assert!(out.contains("alive=true"), "must be alive after spawn:\n{out}");
    assert!(
        out.contains("alive_after_kill=false"),
        "kill must reap, so is_running flips to false:\n{out}"
    );
}

const EXEC: &str = r#"import tallow.process

fn main() {
    let o = process.exec("echo", ["hello"])
    print("out=[" + o.stdout + "]")
    print("code=" + o.exit_code)
    print("ok=" + o.success)
}
"#;

#[test]
fn exec_flattens_argument_arrays_and_returns_the_declared_struct() {
    let (ok, out) = run("--interpret", EXEC, "exec");
    assert!(ok, "interpreter leg failed:\n{out}");
    assert!(
        out.contains("out=[hello\n]"),
        "the array must be expanded, not stringified:\n{out}"
    );
    assert!(out.contains("code=0"), "exit_code must be a field:\n{out}");
    assert!(out.contains("ok=true"), "success must be a field:\n{out}");
}

#[test]
fn native_exec_returns_the_same_real_output_as_the_interpreter() {
    // This test used to assert that the compiled path *refused* `process.exec`,
    // because the lowering could not capture a child's output. That is no longer
    // true: the native leg runs the process and fills the declared struct, so a
    // refusal would now be the defect. Assert the stronger property instead —
    // both planes produce identical, real fields.
    let (ok, out) = run("--require-native", EXEC, "native");
    assert!(ok, "native leg failed:\n{out}");
    assert!(
        out.contains("out=[hello\n]"),
        "compiled exec must capture real stdout, not a zeroed field:\n{out}"
    );
    assert!(out.contains("code=0"), "exit_code must be real:\n{out}");
    assert!(out.contains("ok=true"), "success must be real:\n{out}");
}
