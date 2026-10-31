//! String indexing is by Unicode scalar, bounds-checked, on both planes.
//!
//! Native used to load one UTF-8 byte with no abort (`"αβ"[0]` printed `Î`,
//! `"hello"[9]` printed `(null)` and exited 0). The interpreter indexes
//! `s.chars().nth(i)` and aborts with `runtime error: index N out of bounds`.
//! This suite pins both the in-bounds answers and the abort.

use std::path::{Path, PathBuf};
use std::process::Command;

fn tallow_bin() -> PathBuf {
    match std::env::var_os("TALLOW_BIN") {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/debug/tallow"),
    }
}

fn write_prog(name: &str, source: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("string_index_bounds");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, source).unwrap();
    path
}

fn run_plane(path: &Path, native: bool) -> std::process::Output {
    let mut cmd = Command::new(tallow_bin());
    cmd.arg("run");
    if native {
        cmd.arg("--require-native");
    } else {
        cmd.arg("--interpret");
    }
    cmd.arg(path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("spawn tallow")
}

fn stdout_of(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_of(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

const IN_BOUNDS: &str = r#"
fn main() {
    print("hello"[0])
    print("αβ"[0])
    print("héllo"[1])
}
"#;

const PINNED: &str = "h\nα\né\n";

#[test]
fn in_bounds_chars_match_on_both_planes() {
    let path = write_prog("in_bounds.tl", IN_BOUNDS);
    let interp = run_plane(&path, false);
    let native = run_plane(&path, true);
    assert_eq!(
        interp.status.code(),
        Some(0),
        "interpret: {}",
        stderr_of(&interp)
    );
    assert_eq!(
        native.status.code(),
        Some(0),
        "native: {}",
        stderr_of(&native)
    );
    assert!(
        !stderr_of(&native).contains("native build unavailable"),
        "native fell back: {}",
        stderr_of(&native)
    );
    assert_eq!(stdout_of(&interp), PINNED);
    assert_eq!(stdout_of(&native), PINNED);
    assert_eq!(stdout_of(&interp), stdout_of(&native));
}

fn assert_oob(source: &str, index: i64, name: &str) {
    let path = write_prog(name, source);
    for native in [false, true] {
        let out = run_plane(&path, native);
        let plane = if native { "native" } else { "interpret" };
        assert_ne!(
            out.status.code(),
            Some(0),
            "{plane} index {index} must abort, stdout={}",
            stdout_of(&out)
        );
        let err = stderr_of(&out);
        assert!(
            err.contains("out of bounds"),
            "{plane} missing out-of-bounds: {err}"
        );
        assert!(
            err.contains(&format!("index {index}")),
            "{plane} missing index {index}: {err}"
        );
        assert!(
            err.contains("runtime error:"),
            "{plane} missing runtime error prefix: {err}"
        );
        if native {
            assert!(
                !err.contains("native build unavailable"),
                "native fell back: {err}"
            );
        }
    }
}

#[test]
fn index_9_aborts_on_both_planes() {
    assert_oob(
        r#"
fn main() {
    print("hello"[9])
}
"#,
        9,
        "oob9.tl",
    );
}

#[test]
fn index_99_aborts_on_both_planes() {
    assert_oob(
        r#"
fn main() {
    print("hello"[99])
}
"#,
        99,
        "oob99.tl",
    );
}
