//! G03 — named and default arguments: interpreter ↔ native parity, and the
//! refusal both planes must produce for a call shape that is not legal.
//!
//! The implementation is a front-end normalisation (`src/callnorm.rs`): every
//! statically resolvable call is rewritten into a fully positional one before
//! type checking, so the two execution planes are fed the same AST. That makes
//! the parity claim structural rather than a coincidence of two engines — which
//! is exactly why it still has to be measured: a normalisation that silently
//! failed to reach one plane (a call emitted by codegen from the *original*
//! node, say) would look correct in the interpreter and wrong here.
//!
//! Assertions, in increasing strength:
//!
//! 1. **both legs exit 0** — the native leg runs under `--require-native`, so a
//!    silent interpreter fallback cannot masquerade as a native pass.
//! 2. **byte-identical stdout** — interpreter vs compiled binary.
//! 3. **stdout == the pinned reference** — so a shared drift still fails.
//!
//! The pinned reference also encodes the default-evaluation rule chosen in
//! `src/callnorm.rs`: a default is evaluated at call time, so `announce()`
//! prints once per call (`probe1` and `probe2` are both preceded by the
//! marker). A declaration-time evaluation would print it zero or one time.

use std::path::{Path, PathBuf};
use std::process::Command;

const FIXTURE: &str = "tests/parity/parity_programs/23_named_default_args.tl";

/// Pinned, not derived.
const EXPECTED: &str = "\
example.test:443
example.test:443:plain
example.test:8443
example.test:8443:plain
(default evaluated)
probe1 7
(default evaluated)
probe2 7
";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn tallow_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("TALLOW_BIN") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    // Newest of debug/release: a stale release build makes the test testify
    // about a tree from days ago.
    let release = repo_root().join("target/release/tallow");
    let debug = repo_root().join("target/debug/tallow");
    let mtime = |p: &PathBuf| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    match (mtime(&release), mtime(&debug)) {
        (Some(r), Some(d)) if r >= d => release,
        (Some(_), Some(_)) => debug,
        (Some(_), None) => release,
        (None, Some(_)) => debug,
        (None, None) => debug,
    }
}

struct Out {
    rc: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[String]) -> Out {
    let out = Command::new(tallow_bin())
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("spawn tallow");
    Out {
        rc: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Cross target ⇒ `is_cross` ⇒ the tree-walking interpreter path.
fn run_interp(file: &Path) -> Out {
    run(&[
        "run".into(),
        file.display().to_string(),
        "--target".into(),
        "x86_64-linux".into(),
    ])
}

/// `--require-native` refuses the interpreter fallback, so a pass is a real
/// compiled-path pass.
fn run_native(file: &Path) -> Out {
    run(&[
        "run".into(),
        "--require-native".into(),
        file.display().to_string(),
    ])
}

fn fixture() -> PathBuf {
    repo_root().join(FIXTURE)
}

#[test]
fn both_planes_agree_on_named_and_default_arguments() {
    let interp = run_interp(&fixture());
    assert_eq!(
        interp.rc, 0,
        "interpreter leg failed\n--- stderr ---\n{}",
        interp.stderr
    );

    let native = run_native(&fixture());
    assert_eq!(
        native.rc, 0,
        "native leg failed (a fallback here would defeat the point)\n--- stderr ---\n{}",
        native.stderr
    );

    assert_eq!(
        native.stdout, interp.stdout,
        "the two planes disagree on named/default arguments"
    );
    assert_eq!(
        interp.stdout, EXPECTED,
        "stdout drifted from the pinned reference"
    );
}

/// A named-then-positional call is illegal in both planes — and it is refused
/// before either plane starts, by the front-end pass.
#[test]
fn named_then_positional_is_refused_with_a_reason() {
    let dir = std::env::temp_dir().join(format!("tallow-g03-refusal-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let file = dir.join("named_then_positional.tl");
    std::fs::write(
        &file,
        "fn connect(host: String, port: i64 = 443, tls: bool = true) -> i64 { return port }\n\
         fn main() {\n\
         \x20   print(connect(tls: false, \"example.test\"))\n\
         }\n",
    )
    .expect("write fixture");

    let out = run(&["check".into(), file.display().to_string()]);
    assert_ne!(out.rc, 0, "a named-then-positional call must not check");
    assert!(
        out.stderr.contains("E0121"),
        "expected E0121 in stderr, got:\n{}",
        out.stderr
    );
    assert!(
        out.stderr
            .contains("positional argument after a named argument"),
        "the refusal must say what is wrong, got:\n{}",
        out.stderr
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// An unknown argument name must name the parameters, not just call the
/// argument unknown.
#[test]
fn unknown_argument_name_lists_the_parameters() {
    let dir = std::env::temp_dir().join(format!("tallow-g03-unknown-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let file = dir.join("unknown_name.tl");
    std::fs::write(
        &file,
        "fn connect(host: String, port: i64 = 443, tls: bool = true) -> i64 { return port }\n\
         fn main() {\n\
         \x20   print(connect(\"example.test\", prot: 8443))\n\
         }\n",
    )
    .expect("write fixture");

    let out = run(&["check".into(), file.display().to_string()]);
    assert_ne!(out.rc, 0);
    assert!(out.stderr.contains("E0122"), "stderr:\n{}", out.stderr);
    for name in ["host", "port", "tls"] {
        assert!(
            out.stderr.contains(name),
            "the refusal must list parameter `{name}`, got:\n{}",
            out.stderr
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
