//! P2.T3/T4 — `StructuredData.extract`: interpreter ↔ native parity and refusal parity.
//!
//! The binding this pins: P2.T1 was the last unbound schema-first native. The interpreter
//! reached the value through the stdlib facade while the compiled path had no lowering at
//! all, so `--require-native` refused and a plain run fell back to the tree-walker. Both
//! engines now read one HTML document the same way (commit `7fd59db4`).
//!
//! Three assertions, in increasing strength — the shape `tests/regex_engine_parity.rs`
//! established for this class, because assertion 2 alone cannot catch two engines that
//! agree on the *wrong* answer:
//!
//! 1. **both legs exit 0** — the native leg runs under `--require-native`, so a silent
//!    interpreter fallback cannot masquerade as a native pass.
//! 2. **byte-identical stdout** — interpreter vs compiled binary.
//! 3. **stdout == the pinned reference** — so a shared drift still fails.
//!
//! T4 is the second test: a non-string argument must produce the same refusal from both
//! engines, not merely a failure from both.
//!
//! **This test found a real defect the first time it ran**, which is why it exists. The
//! interpreter did NOT refuse `StructuredData.extract(42)`: its arm coerced the argument
//! with `v.as_string()`, parsed `"42"` as HTML, and returned a plausible
//! `has_json_ld: false` — exit code 0, wrong answer, no complaint. That is the same
//! "plausible success" class the regex parity test was written for. The arm now refuses,
//! naming the same cause as the compiled leg (`interp.rs`, `codegen.rs`).
//!
//! Two facts from that investigation, recorded because they bound how much this test can
//! promise:
//!
//! * **`tallow check` passes on the bad argument** (`1 items, 1 warning`) — the type
//!   checker does not enforce the declared `html: String`, so nothing catches this before
//!   run time. Refusing at run time is a floor, not the fix; the fix belongs in the checker.
//! * **`v.as_string()` appears 549 times in `interp.rs`.** Coercing arguments is the
//!   interpreter's house convention, not a stray line — so this arm is deliberately the
//!   strict one, and whether the other 548 should behave the same is a language-level
//!   question that belongs to its own audit, not to this binding's parity test.
//!
//! `open_graph` is covered too. The interpreter holds a real `Value::Map` and the AOT field
//! holds the same map in the runtime's one Map layout, so `A_og_len`/`A_og_title` (`1`,
//! `Hello`) and `D_og_len`/`D_og_title` pin the entry count and a string-keyed lookup, while
//! `B_og_len` pins the empty map. Until the field's declared kind carried its key type and
//! the map branch stopped requiring a bare variable receiver, `.len` in AOT read the
//! serialized buffer's byte length and indexing read a key slot as if it were an array
//! element; those two lines are what would fail if that returned.
//!
//! The four documents still do their job of making agreement hard to reach by accident: A
//! and D are the two attribute orders of the same tag, B has no structured data at all, and
//! C has two JSON-LD blocks so "only the first survives" predicts a different count.

use std::path::{Path, PathBuf};
use std::process::Command;

const FIXTURE: &str = "tests/parity/parity_programs/17_structured_data.tl";
const REFUSAL_FIXTURE: &str = "tests/parity/parity_programs/18_structured_data_refusal.tl";

/// The interpreter's answer for the four documents, pinned and not derived.
/// A: JSON-LD present · B: nothing structured · C: two blocks · D: og tag, reversed attrs.
const EXPECTED: &str = "\
A_has
true
A_len
1
A_og_len
1
A_og_title
Hello
B_has
false
B_len
0
B_og_len
0
C_has
true
C_len
2
D_has
false
D_len
0
D_og_len
1
D_og_title
Hello
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
    let release = repo_root().join("target/release/tallow");
    if release.is_file() {
        release
    } else {
        repo_root().join("target/debug/tallow")
    }
}

struct Out {
    rc: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[String], cwd: &Path) -> Out {
    let out = Command::new(tallow_bin())
        .args(args)
        .current_dir(cwd)
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
    let args: Vec<String> = vec![
        "run".into(),
        file.display().to_string(),
        "--target".into(),
        "x86_64-linux".into(),
    ];
    run(&args, &repo_root())
}

/// `--require-native` refuses the interpreter fallback, so a pass here is a real
/// compiled-path pass.
fn run_native(file: &Path) -> Out {
    let args: Vec<String> = vec![
        "run".into(),
        "--require-native".into(),
        file.display().to_string(),
    ];
    run(&args, &repo_root())
}

#[test]
fn structured_data_engines_agree_byte_for_byte() {
    let fixture = repo_root().join(FIXTURE);
    assert!(fixture.is_file(), "fixture missing: {}", fixture.display());

    let interp = run_interp(&fixture);
    assert_eq!(
        interp.rc, 0,
        "interpreter leg failed (rc={}): {}",
        interp.rc, interp.stderr
    );
    assert!(
        !interp.stderr.contains("panicked"),
        "interpreter leg panicked: {}",
        interp.stderr
    );

    let native = run_native(&fixture);
    assert_eq!(
        native.rc, 0,
        "native leg failed (rc={}); stderr={}",
        native.rc, native.stderr
    );
    // A refusal here means the compiled path cannot lower StructuredData.extract —
    // the exact divergence this test exists to catch, not an acceptable skip.
    assert!(
        !native.stderr.contains("native build unavailable")
            && !native.stderr.contains("interpreter fallback"),
        "native leg fell back to the interpreter: {}",
        native.stderr
    );

    // (2) byte-for-byte agreement between the engines.
    assert_eq!(
        native.stdout, interp.stdout,
        "interp↔native stdout divergence\n--- interp ---\n{}\n--- native ---\n{}",
        interp.stdout, native.stdout
    );

    // (3) and both agree with the pinned reference — a shared drift still fails.
    assert_eq!(
        interp.stdout, EXPECTED,
        "reference block drifted (interpreter is the reference engine)"
    );
    assert_eq!(
        native.stdout, EXPECTED,
        "native output is not the reference block"
    );
}

/// T4: the same refusal, not merely two failures.
#[test]
fn a_non_string_argument_is_refused_by_both_engines_the_same_way() {
    let fixture = repo_root().join(REFUSAL_FIXTURE);
    assert!(fixture.is_file(), "fixture missing: {}", fixture.display());

    let interp = run_interp(&fixture);
    let native = run_native(&fixture);

    assert_ne!(
        interp.rc, 0,
        "the interpreter must refuse a non-string argument"
    );
    assert_ne!(
        native.rc, 0,
        "the native path must refuse a non-string argument"
    );

    // The cause, named identically by both. This leg refuses at LOWERING time and the
    // interpreter at run time, so the kind of failure differs; the phrase is what must
    // match, and it is the part that says *why*.
    let cause = "expected an HTML string argument";
    assert!(
        interp.stderr.contains(cause),
        "interpreter refusal does not name the cause ({cause}): {}",
        interp.stderr
    );
    assert!(
        native.stderr.contains(cause),
        "native refusal does not name the cause ({cause}): {}",
        native.stderr
    );

    // And neither may have produced output before refusing.
    assert!(
        native.stdout.trim().is_empty(),
        "the native path emitted output before refusing: {:?}",
        native.stdout
    );
}
