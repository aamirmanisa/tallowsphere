//! `fs.read_file` on the compiled plane.
//!
//! The emitter used to print its error message from the *ok* block using a
//! buffer defined in the *fail* block. That is invalid IR (LLVM 18 died in the
//! register coalescer: "Instruction does not dominate all uses"), so every
//! program that read a file silently lost its native plane; and if the IR had
//! been valid it would have printed that buffer and exited 1 after every
//! successful read. Both are pinned here, from the outside.

use std::path::PathBuf;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tallow"))
}

fn fixture(tag: &str, body: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("tallow-read-file-{tag}.txt"));
    std::fs::write(&path, body).expect("write fixture");
    path
}

fn program(tag: &str, source: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("tallow-read-file-{tag}.tl"));
    std::fs::write(&path, source).expect("write program");
    path
}

fn run(path: &PathBuf, plane: &[&str]) -> std::process::Output {
    let mut cmd = std::process::Command::new(bin());
    cmd.args(plane).arg(path).env("TALLOW_ALLOW_DIRECT", "1");
    cmd.output().expect("run tallow")
}

#[test]
fn a_read_file_program_has_a_native_plane_and_matches_the_interpreter() {
    let data = fixture("data", "alpha beta\ngamma delta\n");
    let src = format!(
        r#"fn main() {{
    let s = fs.read_file("{}")
    print(s.len())
    print(s.split("\n").len())
}}
"#,
        data.display()
    );
    let prog = program("ok", &src);

    let native = run(&prog, &["run", "--require-native"]);
    let native_err = String::from_utf8_lossy(&native.stderr);
    assert!(
        native.status.success(),
        "native refused: {native_err}"
    );
    assert!(
        !native_err.contains("native build unavailable"),
        "the native plane must actually run, got: {native_err}"
    );

    let interp = run(&prog, &["run", "--interpret"]);
    assert!(interp.status.success());
    assert_eq!(
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&interp.stdout),
        "both planes must produce the same answer"
    );
    assert_eq!(String::from_utf8_lossy(&native.stdout), "23\n3\n");
}

#[test]
fn a_missing_file_fails_loudly_on_the_native_plane() {
    let prog = program(
        "missing",
        r#"fn main() {
    print(fs.read_file("/tmp/tallow-definitely-missing-read-file"))
}
"#,
    );
    let out = run(&prog, &["run", "--require-native"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a missing file must exit 1, stdout was {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("No such file"),
        "the message must name the syscall error, got: {text}"
    );
}
