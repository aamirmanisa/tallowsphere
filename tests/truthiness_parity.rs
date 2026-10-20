//! Truthiness must mean the same thing on both planes (register #122).
//!
//! The interpreter tests emptiness (`""` and `[]` are falsy, spec §4.2). Native used
//! to test pointer non-nullness, so both were truthy. The fix needs the expression,
//! not just the value: `LLType::I8Ptr` covers strings, native arrays and opaque
//! handles, so the condition site asks what the expression is and tests accordingly.

const PROGRAM: &str = r#"
fn main() {
    let empty_text = ""
    let text = "x"
    let empty_list = []
    let list = [1, 2]
    print(if 0 { "T" } else { "F" })
    print(if "" { "T" } else { "F" })
    print(if nil { "T" } else { "F" })
    print(if [] { "T" } else { "F" })
    print(if 1 { "T" } else { "F" })
    print(if "x" { "T" } else { "F" })
    print(if empty_text { "T" } else { "F" })
    print(if text { "T" } else { "F" })
    print(if empty_list { "T" } else { "F" })
    print(if list { "T" } else { "F" })
}
"#;

fn run(plane: &str) -> std::process::Output {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    PROGRAM.hash(&mut h);
    let path = std::env::temp_dir().join(format!(
        "tallow-truthy-{:016x}-{}.tl",
        h.finish(),
        plane.trim_start_matches('-')
    ));
    std::fs::write(&path, PROGRAM).expect("write program");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["run", plane, path.to_str().expect("utf-8 path")])
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);
    out
}

#[test]
fn emptiness_is_falsy_on_both_planes() {
    let expected = "F\nF\nF\nF\nT\nT\nF\nT\nF\nT\n";
    for plane in ["--interpret", "--require-native"] {
        let out = run(plane);
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(out.status.success(), "[{plane}] failed:\n{stdout}{stderr}");
        assert!(
            !stderr.contains("native build unavailable"),
            "[{plane}] fell back to the interpreter:\n{stderr}"
        );
        assert_eq!(stdout, expected, "[{plane}] truthiness differs");
    }
}
