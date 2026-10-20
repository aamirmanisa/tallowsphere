//! `native fn` declarations (register #129).
//!
//! A function whose implementation is supplied at link time can now be declared:
//! `native fn tallow_string_free(s: String)` has no body, passes `tallow check`,
//! and a call binds to a symbol of exactly that name — no `tallow.` mangling.
//! The interpreter has nothing to execute, so it refuses with a diagnostic that
//! names the function instead of running an empty body and inventing a value.

const FREE_SYMBOL: &str = r#"
native fn tallow_string_free(s: String)

fn main() {
    let s = "ab" + "cd"
    print(s)
    tallow_string_free(s)
    print("freed")
}
"#;

const MISSING_SYMBOL: &str = r#"
native fn tallow_no_such_symbol_here(a: i64) -> i64

fn main() {
    print(tallow_no_such_symbol_here(1))
}
"#;

fn write(program: &str, name: &str) -> std::path::PathBuf {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    program.hash(&mut h);
    let path =
        std::env::temp_dir().join(format!("tallow-nativefn-{:016x}-{name}.tl", h.finish()));
    std::fs::write(&path, program).expect("write program");
    path
}

fn run(name: &str, args: &[&str], program: &str) -> std::process::Output {
    let path = write(program, name);
    std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(args)
        .arg(path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow")
}

#[test]
fn a_native_declaration_passes_check() {
    let out = run("check", &["check"], FREE_SYMBOL);
    assert!(
        out.status.success(),
        "native fn should check: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn the_interpreter_refuses_a_native_call_by_name() {
    let out = run("interpret", &["run", "--interpret"], FREE_SYMBOL);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "interpreter must not succeed");
    assert!(
        err.contains("native function `tallow_string_free` has no interpreter implementation"),
        "expected a named refusal, got: {err}"
    );
}

#[test]
fn a_native_call_binds_to_its_symbol_and_runs() {
    let out = run("native", &["run", "--require-native"], FREE_SYMBOL);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "native call should link against libtallow.a: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(stdout.trim(), "abcd\nfreed");
}

#[test]
fn a_missing_symbol_fails_by_name_at_link_time() {
    let out = run("missing", &["run", "--require-native"], MISSING_SYMBOL);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "a missing symbol must not run");
    assert!(
        err.contains("tallow_no_such_symbol_here"),
        "the failure must name the symbol, got: {err}"
    );
}
