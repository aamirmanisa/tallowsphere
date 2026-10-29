//! G14 — doctests: the fenced examples in `///` comments, executed.
//!
//! The contract is `docs/spec/DOCTESTS.md`: `tallow test --doc <path>` extracts
//! every ```tallow / ```tl block from a `///` doc comment using the grammar of
//! `scripts/docs_examples.py` (`run`, `run:fail:<CODE>`, `skip:<reason>`;
//! unmarked = failure) and runs each executed block on **both planes** —
//! `--interpret` and `--require-native` — requiring the same exit status and
//! the same stdout.
//!
//! Every case here drives the real binary (`CARGO_BIN_EXE_tallow`), the way
//! `tests/pattern_destructure.rs` drives the two planes directly. The one
//! exception is the divergence case: the planes are *supposed* to agree, so a
//! disagreement cannot be produced by a real program. It is produced by
//! `TALLOW_BIN`, the runner override `scripts/docs_examples.py` also honours,
//! pointing at a stub that lies on one plane — the point is that the checker
//! notices, not that the lie is reachable in normal use.
//!
//! Run: `cargo test --test doctest`

use std::path::{Path, PathBuf};
use std::process::Command;

struct Out {
    rc: i32,
    stdout: String,
    stderr: String,
}

fn tallow_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tallow"))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// One fixture directory per test, keyed by tag and pid so parallel cases and
/// stale leftovers never collide.
fn fixture_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tallow-g14-doctest-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create fixture dir");
    dir
}

fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("write fixture");
    path
}

/// `tallow test --doc <path>`, optionally with an extra environment entry for
/// the child (used only by the divergence case; `TALLOW_BIN` names the runner
/// the doctest checker spawns, never the checker itself).
fn doctest(path: &Path, env: Option<(&str, &Path)>) -> Out {
    let mut cmd = Command::new(tallow_bin());
    cmd.arg("test")
        .arg("--doc")
        .arg(path)
        .current_dir(repo_root());
    if let Some((key, value)) = env {
        cmd.env(key, value);
    }
    let out = cmd.output().expect("spawn tallow test --doc");
    Out {
        rc: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn combined(out: &Out) -> String {
    format!("{}{}", out.stdout, out.stderr)
}

// ── 1. a passing block ───────────────────────────────────────────────────────

#[test]
fn a_run_block_that_agrees_on_both_planes_passes() {
    let dir = fixture_dir("pass");
    write(
        &dir,
        "pass.tl",
        r#"/// Doubles a value.
///
/// ```tallow run
/// fn double(x: Int) -> Int { x * 2 }
/// fn main() { print(double(21)) }
/// ```
fn double(x: Int) -> Int { x * 2 }
"#,
    );

    let out = doctest(&dir, None);
    let text = combined(&out);
    assert_eq!(out.rc, 0, "a passing doctest exited {}:\n{text}", out.rc);
    assert!(
        text.contains("pass.tl:3"),
        "the report did not name the block's file:line:\n{text}"
    );
    assert!(
        text.contains("doctest: 1 executed, 0 skipped, 0 failed"),
        "the summary did not count the run block:\n{text}"
    );
}

// ── 2. a `run:fail:` block ──────────────────────────────────────────────────

#[test]
fn a_run_fail_block_passes_when_both_planes_fail_with_the_code() {
    let dir = fixture_dir("runfail");
    // E0152 is the destructuring refusal (tests/pattern_destructure.rs): a
    // scalar cannot bind a tuple pattern. Both planes refuse it, so the marker
    // is honoured and the block passes.
    write(
        &dir,
        "fail.tl",
        r#"/// ```tallow run:fail:E0152
/// fn main() {
///     let (a, b) = 42
///     print(a)
/// }
/// ```
fn nothing() {}
"#,
    );

    let out = doctest(&dir, None);
    let text = combined(&out);
    assert_eq!(out.rc, 0, "a run:fail doctest exited {}:\n{text}", out.rc);
    assert!(
        text.contains("run:fail:E0152"),
        "the report did not spell the marker:\n{text}"
    );
    assert!(
        text.contains("doctest: 1 executed, 0 skipped, 0 failed"),
        "the summary did not count the run:fail block:\n{text}"
    );
}

// ── 3. an unmarked block is a failure ───────────────────────────────────────

#[test]
fn an_unmarked_fence_fails() {
    let dir = fixture_dir("unmarked");
    write(
        &dir,
        "unmarked.tl",
        r#"/// ```tallow
/// fn main() { print("nobody ran this") }
/// ```
fn nothing() {}
"#,
    );

    let out = doctest(&dir, None);
    let text = combined(&out);
    assert_ne!(out.rc, 0, "an unmarked fence passed:\n{text}");
    assert!(
        text.contains("unmarked.tl:1"),
        "the failure did not carry file:line:\n{text}"
    );
    assert!(
        text.contains("unmarked fence"),
        "the failure did not name the rule:\n{text}"
    );
    assert!(
        text.contains("doctest: 0 executed, 0 skipped, 1 failed"),
        "an unmarked fence was counted as anything but a failure:\n{text}"
    );
}

// ── 4. a `skip:` block is not executed ─────────────────────────────────────

#[test]
fn a_skip_block_is_not_executed_and_needs_a_reason() {
    let dir = fixture_dir("skip");
    write(
        &dir,
        "skip.tl",
        r#"/// ```tallow skip:illustrative; needs a live browser
/// this is not even a program
/// ```
fn nothing() {}
"#,
    );

    let out = doctest(&dir, None);
    let text = combined(&out);
    assert_eq!(out.rc, 0, "a skip block failed the run:\n{text}");
    assert!(
        text.contains("doctest: 0 executed, 1 skipped, 0 failed"),
        "the summary did not count the skip:\n{text}"
    );
    assert!(
        !text.contains("runtime error") && !text.contains("parse error"),
        "a skipped block was executed anyway:\n{text}"
    );

    // A `skip` with no reason is a failure: the reason is what keeps the
    // skip from being an undocumented hole.
    let bare = fixture_dir("skip-bare");
    write(
        &bare,
        "bare.tl",
        "/// ```tallow skip:\n/// print(1)\n/// ```\nfn nothing() {}\n",
    );
    let out = doctest(&bare, None);
    let text = combined(&out);
    assert_ne!(out.rc, 0, "a `skip` with no reason passed:\n{text}");
    assert!(
        text.contains("`skip` without a reason"),
        "the failure did not name the rule:\n{text}"
    );
}

// ── 5. a block the native backend cannot lower never falls back ────────────

/// Write an executable stub runner that behaves like `tallow run` on one plane
/// and not the other. Used by the two cases that need a `--require-native` leg
/// the real compiler will not produce (see each test for why).
fn stub_runner(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("write stub runner");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod stub runner");
    }
    path
}

#[test]
fn an_unlowerable_block_fails_with_the_native_refusal() {
    // `--require-native` must refuse with the refusal text instead of falling
    // back to the interpreter, so the doctest fails and the report carries that
    // text. Every real native gap in this tree sits behind a stdlib module, and
    // a doctest block is standalone (no imports), so no import-free block is
    // guaranteed unlowerable. The refusal is therefore produced by the runner
    // override `TALLOW_BIN` — the same escape hatch `scripts/docs_examples.py`
    // honours — with the sentence `tallow run` actually prints.
    let dir = fixture_dir("unlowerable");
    write(
        &dir,
        "unlowerable.tl",
        "/// ```tallow run\n/// fn main() { print(1) }\n/// ```\nfn nothing() {}\n",
    );
    let stub = stub_runner(
        &dir,
        "refusing.sh",
        r#"#!/bin/sh
case "$2" in
  --interpret) printf '1\n'; exit 0 ;;
  --require-native) echo "* native build unavailable (no lowering for method 'openapi_load'); --require-native refuses the interpreter fallback" >&2; exit 1 ;;
esac
exit 3
"#,
    );

    let out = doctest(&dir, Some(("TALLOW_BIN", &stub)));
    let text = combined(&out);
    assert_ne!(out.rc, 0, "an unlowerable block passed:\n{text}");
    assert!(
        text.contains("the planes disagree"),
        "the failure did not name the two-plane rule:\n{text}"
    );
    assert!(
        text.contains("native refused:") && text.contains("native build unavailable"),
        "the failure did not carry the native refusal text:\n{text}"
    );
    assert!(
        text.contains("unlowerable.tl:1"),
        "the refusal did not carry file:line:\n{text}"
    );
}

// ── 6. two planes that disagree must fail ──────────────────────────────────

#[test]
fn a_two_plane_divergence_fails() {
    let dir = fixture_dir("diverge");
    write(
        &dir,
        "diverge.tl",
        "/// ```tallow run\n/// fn main() { print(1) }\n/// ```\nfn nothing() {}\n",
    );

    // A runner that answers differently on each plane. The checker must catch
    // it — a doctest that passes on one plane lies about the other.
    let stub = stub_runner(
        &dir,
        "liar.sh",
        r#"#!/bin/sh
case "$2" in
  --interpret) printf 'from the interpreter\n'; exit 0 ;;
  --require-native) printf 'from the native build\n'; exit 0 ;;
esac
exit 3
"#,
    );

    let out = doctest(&dir, Some(("TALLOW_BIN", &stub)));
    let text = combined(&out);
    assert_ne!(out.rc, 0, "a two-plane divergence passed:\n{text}");
    assert!(
        text.contains("the planes disagree"),
        "the failure did not name the two-plane rule:\n{text}"
    );
    assert!(
        text.contains("diverge.tl:1"),
        "the divergence did not carry file:line:\n{text}"
    );
    assert!(
        text.contains("doctest: 1 executed, 0 skipped, 1 failed"),
        "the divergent block was not counted as a failure:\n{text}"
    );
}
