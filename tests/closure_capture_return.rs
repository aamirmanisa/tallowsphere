//! C3b / B5 — closure capture & return semantics (interpreter ↔ native).
//!
//! Owned by lane C3b (`artifacts/to-100-2026-09-16/C3b-report.md`); fixtures are
//! inline `.tl` sources so this file is the only writer. Every compiled/native
//! run is capped per the Batch-4 INCIDENT rule:
//! `ulimit -v 2000000` (2 GB) + `timeout 120` around the child.
//!
//! Contract under test:
//!  · a closure value holds its captured bindings as private state — calls
//!    accumulate (`var n = 0; let inc = { -> n = n + 1 }` → 1 then 2), while the
//!    enclosing frame's binding keeps its creation-time value (capture is a
//!    snapshot: `closure_snapshot_semantics` in `src/interp.rs` stays green).
//!  · a function that RETURNS a closure is lifted by the interpreter; the native
//!    backend refuses loudly (build error naming the function) and `tallow run`
//!    falls back to the interpreter — never a silent wrong value
//!    (`tests/parity/parity_programs/08_closure_return.tl`).

use std::path::PathBuf;
use std::process::Command;

const TALLOW_BIN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target/debug/tallow");

/// A cross target forces the tree-walking interpreter (same trick the parity
/// runner uses: the `is_cross` guard skips the native path).
const INTERP_ARGS: &[&str] = &["--target", "x86_64-linux"];
/// Refuse the interpreter fallback: native only, non-zero when unavailable.
const NATIVE_ARGS: &[&str] = &["--require-native"];

struct Run {
    rc: i32,
    out: String,
    err: String,
}

impl Run {
    fn stdout(&self) -> String {
        self.out.clone()
    }
    fn label(&self) -> String {
        format!("rc={} stdout={:?} stderr={:?}", self.rc, self.out, self.err)
    }
}

/// Write `src` as a fixture and run it through `target/debug/tallow run`, with
/// the incident memory/time caps applied to the child.
fn run_tl(tag: &str, src: &str, extra: &[&str]) -> Run {
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "c3b-closure-{tag}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("temp fixture dir");
    let file = dir.join("prog.tl");
    std::fs::write(&file, src).expect("write fixture");

    let mut shell = format!(
        "ulimit -v 2000000; exec '{}' run '{}'",
        TALLOW_BIN,
        file.display()
    );
    for a in extra {
        shell.push_str(&format!(" '{a}'"));
    }

    let output = Command::new("timeout")
        .arg("120")
        .arg("bash")
        .arg("-c")
        .arg(&shell)
        .output()
        .expect("spawn tallow (bash wrapper)");

    Run {
        rc: output.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&output.stdout).to_string(),
        err: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn lines(s: &str) -> Vec<String> {
    s.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

// ── GAP-B: captured-variable state inside one closure value ─────────────────

/// Same-scope counter closure: the closure accumulates its own state; the
/// enclosing frame keeps the creation-time value (snapshot).
const STATEFUL_COUNTER: &str = r#"
fn main() {
    var n = 0
    let inc = { -> n = n + 1 }
    print(inc())
    print(inc())
    print("outer n = {n}")
}
"#;

#[test]
fn interp_stateful_closure_accumulates() {
    let r = run_tl("interp-stateful", STATEFUL_COUNTER, INTERP_ARGS);
    assert_eq!(r.rc, 0, "interpreter run failed: {}", r.label());
    assert_eq!(
        lines(&r.stdout()),
        vec!["1", "2", "outer n = 0"],
        "closure state must persist across calls; got {}",
        r.label()
    );
}

#[test]
fn native_matches_interp_on_stateful_closure() {
    let i = run_tl("interp-stateful-parity", STATEFUL_COUNTER, INTERP_ARGS);
    let n = run_tl("native-stateful-parity", STATEFUL_COUNTER, NATIVE_ARGS);
    assert_eq!(i.rc, 0, "interpreter run failed: {}", i.label());
    assert_eq!(
        n.rc, 0,
        "native backend must build this same-scope stateful closure (no boundary \
         crossing): {}",
        n.label()
    );
    assert_eq!(
        lines(&n.stdout()),
        lines(&i.stdout()),
        "native/interp divergence on a stateful same-scope closure — interp {:?} \
         vs native {:?}",
        i.stdout(),
        n.stdout()
    );
}

/// Two closures built by the same factory must not share state.
const TWO_COUNTERS: &str = r#"
fn make_counter() {
    var n = 0
    return { -> n = n + 1 }
}
fn main() {
    let c1 = make_counter()
    let c2 = make_counter()
    print(c1())
    print(c2())
    print(c1())
}
"#;

#[test]
fn interp_returned_closures_have_independent_state() {
    let r = run_tl("interp-two-counters", TWO_COUNTERS, INTERP_ARGS);
    assert_eq!(r.rc, 0, "interpreter run failed: {}", r.label());
    assert_eq!(
        lines(&r.stdout()),
        vec!["1", "1", "2"],
        "each returned closure needs its own state cell; got {}",
        r.label()
    );
}

/// Read-only capture through a returned closure (the case the native backend
/// hands to the interpreter).
const RETURNED_READER: &str = r#"
fn make_adder(x: i64) {
    return { y -> y + x }
}
fn main() {
    let add5 = make_adder(5)
    print("add5(10) = {add5(10)}")
}
"#;

#[test]
fn interp_returned_closure_reads_its_capture() {
    let i = run_tl("interp-returned-reader", RETURNED_READER, INTERP_ARGS);
    assert_eq!(i.rc, 0, "interpreter run failed: {}", i.label());
    assert!(
        i.stdout().contains("add5(10) = 15"),
        "returned closure must read its capture: {}",
        i.label()
    );
}

#[test]
fn native_refuses_returned_closure_loudly_then_falls_back() {
    // `--require-native` must refuse with a message naming the function (never a
    // silent wrong value).
    let refused = run_tl("native-refused", RETURNED_READER, NATIVE_ARGS);
    assert_ne!(
        refused.rc, 0,
        "--require-native must not accept a returned closure (fail-loud contract): {}",
        refused.label()
    );
    let msg = format!("{}{}", refused.stdout(), refused.err);
    assert!(
        msg.contains("returns a closure"),
        "refusal must name the cause 'returns a closure': {msg}"
    );

    // Plain `tallow run` falls back to the interpreter and stays correct.
    let fallback = run_tl("native-fallback", RETURNED_READER, &[]);
    assert_eq!(fallback.rc, 0, "fallback run failed: {}", fallback.label());
    assert!(
        fallback.stdout().contains("add5(10) = 15"),
        "fallback must produce the interpreter result: {}",
        fallback.label()
    );
}

/// Capture is a snapshot of the *enclosing frame* at creation time — the
/// documented behaviour this slice must not change.
const SNAPSHOT: &str = r#"
fn main() {
    var n = 1
    let get = { -> n }
    n = 5
    print("get = {get()}")
}
"#;

#[test]
fn capture_stays_a_creation_time_snapshot_in_both_engines() {
    let i = run_tl("interp-snapshot", SNAPSHOT, INTERP_ARGS);
    let n = run_tl("native-snapshot", SNAPSHOT, NATIVE_ARGS);
    assert_eq!(i.rc, 0, "interpreter run failed: {}", i.label());
    assert!(
        i.stdout().contains("get = 1"),
        "enclosing-frame capture must stay a creation snapshot: {}",
        i.label()
    );
    assert_eq!(n.rc, 0, "native run failed: {}", n.label());
    assert_eq!(
        lines(&n.stdout()),
        lines(&i.stdout()),
        "native/interp divergence on snapshot semantics: interp {:?} native {:?}",
        i.stdout(),
        n.stdout()
    );
}

/// Control: a non-capturing closure in both engines (regression guard for the
/// simplest closure path).
const NON_CAPTURING: &str = r#"
fn main() {
    let double = { x -> x * 2 }
    print(double(21))
}
"#;

#[test]
fn non_capturing_closure_matches_in_both_engines() {
    let i = run_tl("interp-plain", NON_CAPTURING, INTERP_ARGS);
    let n = run_tl("native-plain", NON_CAPTURING, NATIVE_ARGS);
    assert_eq!(i.rc, 0, "interpreter run failed: {}", i.label());
    assert_eq!(n.rc, 0, "native run failed: {}", n.label());
    assert_eq!(lines(&i.stdout()), vec!["42"], "interp: {}", i.label());
    assert_eq!(
        lines(&n.stdout()),
        vec!["42"],
        "native: {}",
        n.label()
    );
}
