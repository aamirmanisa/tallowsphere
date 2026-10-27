//! G10 — newtypes: interpreter ↔ native parity, and the refusals that make a
//! newtype something other than an alias.
//!
//! The acceptance bar for this item was never "`newtype` parses". It was that a
//! newtype is *not* transparent:
//!
//! * `UserId("x")` constructs, and the constructor has the nominal type;
//! * a bare `"x"` where a `UserId` is required is refused, naming the newtype
//!   **and** the constructor;
//! * a `UserId` where a `String` is required is refused, naming `.inner`;
//! * two newtypes over the same target are distinct (`UserId` vs `Handle`);
//! * the two execution planes agree byte for byte.
//!
//! The implementation splits in two: the checker holds the nominal type
//! (`Type::Newtype`), and `src/newtypes.rs` erases it — `UserId(x)` → `x`,
//! `v.inner` → `v` — after checking and before either plane runs. That single
//! erasure is why the parity claim is structural rather than two engines
//! agreeing by luck, which is exactly why it is still measured here: a lowering
//! that failed to reach the native leg would look right in the interpreter.
//!
//! Assertions, in increasing strength:
//!
//! 1. **both legs exit 0** — the native leg runs under `--require-native`, so a
//!    silent interpreter fallback cannot masquerade as a native pass.
//! 2. **byte-identical stdout** — interpreter vs compiled binary.
//! 3. **stdout == the pinned reference** — so a shared drift still fails.

use std::path::{Path, PathBuf};
use std::process::Command;

const FIXTURE: &str = "tests/parity/parity_programs/24_newtypes.tl";

/// Pinned, not derived. `.inner` is the documented escape hatch, and these
/// lines are what the wrapped values look like once erased.
const EXPECTED: &str = "\
port 8443
user:ada
inner ada
user:ada
handle h-1
meter 3
user:ada
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
    // Newest of debug/release: a stale release build testifies about a tree
    // from days ago.
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

fn check_source(name: &str, source: &str) -> Out {
    let dir = std::env::temp_dir().join(format!("tallow-g10-{}-{}", name, std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let file = dir.join(format!("{name}.tl"));
    std::fs::write(&file, source).expect("write fixture");
    let out = run(&["check".into(), file.display().to_string()]);
    let _ = std::fs::remove_dir_all(&dir);
    out
}

#[test]
fn both_planes_agree_on_newtypes() {
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
        "the two planes disagree on newtype erasure"
    );
    assert_eq!(
        interp.stdout, EXPECTED,
        "stdout drifted from the pinned reference"
    );
}

/// `"x"` where a `UserId` is required: the refusal must name the expected
/// newtype and the constructor that would produce one. "type mismatch" is not
/// enough — the reader has to be told which construct is missing.
#[test]
fn bare_string_where_a_newtype_is_required_names_newtype_and_constructor() {
    let out = check_source(
        "bare-value",
        "newtype UserId = String\n\
         fn take(id: UserId) {}\n\
         fn main() { take(\"x\") }\n",
    );
    assert_ne!(out.rc, 0, "a bare String must not fill a UserId slot");
    assert!(out.stderr.contains("E0117"), "stderr:\n{}", out.stderr);
    assert!(
        out.stderr.contains("newtype `UserId`"),
        "the refusal must name the expected newtype, got:\n{}",
        out.stderr
    );
    assert!(
        out.stderr.contains("UserId(<String>)"),
        "the refusal must name the constructor, got:\n{}",
        out.stderr
    );
}

/// The other direction: a `UserId` is not a `String`, and the refusal names the
/// unwrap rather than inventing a conversion.
#[test]
fn newtype_where_its_target_is_required_names_the_unwrap() {
    let out = check_source(
        "reverse",
        "newtype UserId = String\n\
         fn take(s: String) {}\n\
         fn main(id: UserId) { take(id) }\n",
    );
    assert_ne!(out.rc, 0, "a UserId must not become a String implicitly");
    assert!(out.stderr.contains("E0117"), "stderr:\n{}", out.stderr);
    assert!(
        out.stderr.contains(".inner"),
        "the refusal must name the unwrap, got:\n{}",
        out.stderr
    );
}

/// Two newtypes over the same target are not interchangeable: the refusal
/// names both.
#[test]
fn a_second_newtype_over_the_same_target_is_rejected() {
    let out = check_source(
        "sibling",
        "newtype UserId = String\n\
         newtype Handle = String\n\
         fn take(id: UserId) {}\n\
         fn main(h: Handle) { take(h) }\n",
    );
    assert_ne!(out.rc, 0, "Handle must not fill a UserId slot");
    assert!(out.stderr.contains("E0117"), "stderr:\n{}", out.stderr);
    assert!(out.stderr.contains("Handle"), "stderr:\n{}", out.stderr);
    assert!(out.stderr.contains("UserId"), "stderr:\n{}", out.stderr);
}
