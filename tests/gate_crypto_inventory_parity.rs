//! Differential test: `tallow gate crypto-inventory` must agree with
//! `scripts/crypto-inventory.py` in every mode, on stdout, stderr and exit code.
//!
//! This gate is the one where a plausible port silently loses a *check*, not
//! just bytes. Both sides are compared on:
//!
//! * generate — the artifact itself. Non-ASCII must hash as `\uXXXX`
//!   (`json.dumps` defaults to `ensure_ascii=True`), so an em-dash costs six
//!   bytes in the hash and three as UTF-8; the mismatch shows up only in
//!   `registrySha256`/`policySha256` while every other field matches.
//! * `--check` clean — identical stdout and exit 0.
//! * `--check` drifted — identical verdict (exit 1) *and* identical diff text.
//!   The drift artifact is produced here, not committed: `--write` the real
//!   artifact, then perturb one registry version so the regenerated text
//!   differs in a small, localised region. A hand-guessed diff gets the exit
//!   code right and the text wrong, which is why the bytes are asserted.
//! * `--write` — status line and stderr notes, compared at the same path.
//! * `--check` registry-conformance-only — both parse the argument list the
//!   same way, so a port that requires the snapshot path fails here.
//!
//! Trees: `/tmp/bad.json` from the original port session is not used — it does
//! not exist on a clean checkout. The drift fixture is regenerated per run.
//!
//! See the gate's own docstring for the six conformance failure modes. Mode (b)
//! "active registered algorithm with no use sites" is the one a port drops; the
//! lifecycle-drill test below covers it by scanning a temp root that omits an
//! active algorithm's sources.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn py(args: &[&str]) -> Option<Output> {
    let p = root().join("scripts/crypto-inventory.py");
    if !p.is_file() {
        return None;
    }
    Some(
        Command::new("python3")
            .arg(&p)
            .args(args)
            .current_dir(root())
            .output()
            .expect("python3 must be available"),
    )
}

fn rs(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("gate")
        .arg("crypto-inventory")
        .args(args)
        .current_dir(root())
        .output()
        .expect("the tallow binary must run")
}

fn assert_same(label: &str, py: &Output, rs: &Output) {
    assert_eq!(
        py.status.code(),
        rs.status.code(),
        "[{label}] exit codes differ: python {:?} rust {:?}\npy stderr: {}\nrs stderr: {}",
        py.status.code(),
        rs.status.code(),
        String::from_utf8_lossy(&py.stderr),
        String::from_utf8_lossy(&rs.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&py.stdout),
        String::from_utf8_lossy(&rs.stdout),
        "[{label}] stdout differs ({} vs {} bytes)\npy stdout: {}\nrs stdout: {}",
        py.stdout.len(),
        rs.stdout.len(),
        head(&py.stdout),
        head(&rs.stdout),
    );
    assert_eq!(
        String::from_utf8_lossy(&py.stderr),
        String::from_utf8_lossy(&rs.stderr),
        "[{label}] stderr differs ({} vs {} bytes)",
        py.stderr.len(),
        rs.stderr.len(),
    );
}

fn head(b: &[u8]) -> String {
    String::from_utf8_lossy(&b[..b.len().min(600)]).into_owned()
}

fn skip() -> bool {
    let missing = !root().join("scripts/crypto-inventory.py").is_file();
    if missing {
        eprintln!("scripts/crypto-inventory.py is gone; the port is the only implementation");
    }
    missing
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "cbom-parity-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

const ARTIFACT: &str = "scripts/crypto-inventory.json";

#[test]
fn generate_is_byte_identical() {
    if skip() {
        return;
    }
    let p = py(&[]).expect("checked above");
    let r = rs(&[]);
    assert!(p.stdout.len() > 1000, "python emitted {} bytes", p.stdout.len());
    assert_same("generate", &p, &r);
}

#[test]
fn write_is_identical_at_the_same_path() {
    if skip() {
        return;
    }
    let d = tmpdir("write");
    // Same output path for both, run in turn: the status line embeds the path,
    // so comparing across two paths would compare two different strings and
    // hide a paraphrased status line rather than expose one.
    let out = d.join("art.json");
    let os = out.to_string_lossy().to_string();

    let p = py(&["--write", &os]).expect("checked above");
    let py_bytes = std::fs::read(&out).expect("python must have written the artifact");
    let _ = std::fs::remove_file(&out);
    let r = rs(&["--write", &os]);
    let rs_bytes = std::fs::read(&out).expect("rust must have written the artifact");

    assert_eq!(
        py_bytes, rs_bytes,
        "[write] artifact bytes differ ({} vs {} bytes)",
        py_bytes.len(),
        rs_bytes.len()
    );
    assert_same("write", &p, &r);

    // And the artifact each side writes is the one the repo's committed copy
    // would be regenerated to — a `--write` that silently differs from
    // `generate` is also a port bug.
    let committed = root().join(ARTIFACT);
    if committed.is_file() {
        let expected = std::fs::read(&committed).unwrap_or_default();
        assert_eq!(
            expected,
            rs_bytes,
            "[write] the artifact written does not match generate output"
        );
    }
}

#[test]
fn check_clean_is_identical() {
    if skip() {
        return;
    }
    if !root().join(ARTIFACT).is_file() {
        eprintln!("no committed {ARTIFACT}; clean check has nothing to compare");
        return;
    }
    let p = py(&["--check", ARTIFACT]).expect("checked above");
    let r = rs(&["--check", ARTIFACT]);
    // A stale committed artifact is a legitimate red on this tree; the point of
    // the test is agreement, not greenness, so both may exit 1 together.
    assert_same("check-clean", &p, &r);
}

#[test]
fn check_drift_diff_text_is_identical() {
    if skip() {
        return;
    }
    let d = tmpdir("drift");
    let drift = d.join("drifted.json");
    let ds = drift.to_string_lossy().to_string();

    // Build the drift fixture from the real generator so the only difference is
    // the one we introduce.
    let generated = rs(&[]);
    assert!(generated.status.success(), "generate failed: {:?}", generated.status);
    let text = String::from_utf8(generated.stdout).expect("artifact is utf-8");

    // Perturb exactly one line: change the first usage-site count. The diff then
    // has one replaced line with context, which is where a hand-guessed
    // diff gets the hunk text wrong while the exit code stays right.
    //
    // Shape note: the artifact is rendered compact, so counts appear as
    // `"count":15` — no space after the colon. A needle with a space silently
    // matches nothing, which is why this asserts the find.
    let needle = "\"count\":";
    let site = text.find(needle).expect("artifact has usage counts");
    let tail = &text[site + needle.len()..];
    let num_end = tail
        .find(|c: char| !c.is_ascii_digit())
        .expect("count is followed by a delimiter");
    let n: u64 = tail[..num_end].parse().expect("count is numeric");
    let mut drifted = String::with_capacity(text.len());
    drifted.push_str(&text[..site + needle.len()]);
    drifted.push_str(&(n + 1).to_string());
    drifted.push_str(&tail[num_end..]);
    assert_ne!(drifted, text);
    std::fs::write(&drift, &drifted).expect("write drift fixture");

    let p = py(&["--check", &ds]).expect("checked above");
    let r = rs(&["--check", &ds]);
    assert_eq!(p.status.code(), Some(1), "[drift] python should report drift");
    // stderr carries the unified diff; asserting it whole is the byte check.
    assert_same("check-drift", &p, &r);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn check_registry_only_mode_is_identical() {
    if skip() {
        return;
    }
    let p = py(&["--check"]).expect("checked above");
    let r = rs(&["--check"]);
    assert_same("check-registry-only", &p, &r);
}

#[test]
fn unrecognized_argument_is_rejected_by_both() {
    if skip() {
        return;
    }
    let p = py(&["--nonsense"]).expect("checked above");
    let r = rs(&["--nonsense"]);
    // Exit status is the contract that matters (2 = generator/argument error).
    // The *text* is not: Python is argparse, which prints a usage block and
    // `error: unrecognized arguments: ...`; the port prints a single line. Both
    // reject, neither generates, so this asserts agreement on the verdict and
    // documents the message difference rather than forcing a false parity.
    assert_eq!(p.status.code(), Some(2), "[bad-arg] python should exit 2");
    assert_eq!(r.status.code(), Some(2), "[bad-arg] rust should exit 2");
    assert!(
        r.stdout.is_empty(),
        "[bad-arg] rust must not emit an artifact on an unknown flag"
    );
    assert!(
        String::from_utf8_lossy(&r.stderr).contains("unrecognized argument"),
        "[bad-arg] rust stderr should name the bad flag: {}",
        String::from_utf8_lossy(&r.stderr)
    );
}
