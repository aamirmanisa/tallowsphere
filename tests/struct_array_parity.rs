//! Native/interpreter parity for field access through an array of structs.
//!
//! Register #99: `xs[0].field` returned a literal 0 in the native backend
//! while the interpreter returned the field — a silent wrong answer, the class
//! of bug that parity tests exist to catch. The interpreter leg runs with a
//! cross target so it really is the tree-walking interpreter; the native leg
//! uses `--require-native` so a fallback cannot mask a regression.

use std::path::{Path, PathBuf};
use std::process::Command;

const FIXTURE: &str = "tests/fixtures/struct_array_fields.tl";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn tallow_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("TALLOW_BIN") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    // Prefer the NEWEST binary. A stale release build silently makes a parity
    // test testify about a tree from days ago: measured 2026-10-17, the release
    // binary was 2026-10-16 18:46 while the debug binary carrying the fix was
    // 2026-10-18 00:45, so the "regression" was the harness, not the code.
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

fn run_interp(file: &Path) -> Out {
    // `--interpret` is the explicit tree-walking path. `--target` was used here
    // before and is not the same thing: it cross-compiles, and on a target the
    // host cannot execute the run falls back to the interpreter anyway, so the
    // leg reported "parity" without ever naming which engine ran.
    run(
        &["run".into(), "--interpret".into(), file.display().to_string()],
        &repo_root(),
    )
}

fn run_native(file: &Path) -> Out {
    run(
        &[
            "run".into(),
            "--require-native".into(),
            file.display().to_string(),
        ],
        &repo_root(),
    )
}

fn lines(out: &Out) -> Vec<String> {
    out.stdout.lines().map(|l| l.trim().to_string()).collect()
}

#[test]
fn array_element_fields_agree_across_engines() {
    let fixture = repo_root().join(FIXTURE);
    assert!(fixture.is_file(), "fixture missing: {}", fixture.display());

    let interp = run_interp(&fixture);
    assert_eq!(interp.rc, 0, "interpreter leg failed: {}", interp.stderr);

    let native = run_native(&fixture);
    assert_eq!(native.rc, 0, "native leg failed: {}", native.stderr);
    assert!(
        !native.stderr.contains("native build unavailable")
            && !native.stderr.contains("interpreter fallback"),
        "native leg fell back to the interpreter: {}",
        native.stderr
    );

    let expected = ["2", "16", "16", "bb", "16", "bb"];
    assert_eq!(
        lines(&native),
        expected,
        "native output must read fields through the array element"
    );
    assert_eq!(
        lines(&native),
        lines(&interp),
        "engines must agree byte for byte"
    );
}
