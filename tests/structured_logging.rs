//! Structured logging (G52) — the six gates from `docs/spec/STRUCTURED-LOGGING.md`.
//!
//! Every case drives the real binary on the interpreter plane (`run --interpret`).
//! That is the plane `log.record` is specified for: the compiled `log.*` arm
//! predates the level/format configuration (it prints a bare `[LEVEL] ` prefix to
//! stdout and ignores `set_format`/`set_level`), so `record` is interpreter-only
//! until that arm is brought up to date. Running the binary — not the library —
//! is the point: the level/format/sink/trace state is process-wide statics, and a
//! fresh process is the only way to observe the defaults.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

static SEQ: AtomicU32 = AtomicU32::new(0);

struct Run {
    stdout: String,
    stderr: String,
    code: Option<i32>,
}

fn run_program(source: &str) -> Run {
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "tallow-structured-logging-{}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path: PathBuf = dir.join("program.tl");
    let mut f = std::fs::File::create(&path).expect("write program");
    f.write_all(source.as_bytes()).expect("write program");
    drop(f);

    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(&path)
        .arg("--interpret")
        .output()
        .expect("spawn tallow");
    let _ = std::fs::remove_dir_all(&dir);
    Run {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code(),
    }
}

/// The log lines the run emitted, in order.
///
/// The interpreter prints engine markers (and the privacy pass may print
/// warnings) on the same stderr, so a log line is recognised by its shape: a
/// JSON object, or a line opening with `[LEVEL]`.
fn log_lines(run: &Run) -> Vec<String> {
    run.stderr
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            let json = t.starts_with('{') && t.ends_with('}');
            let text = ["[DEBUG] ", "[INFO] ", "[WARN] ", "[ERROR] ", "[FATAL] "]
                .iter()
                .any(|p| t.starts_with(p));
            json || text
        })
        .map(|l| l.to_string())
        .collect()
}

fn parse_json(line: &str) -> serde_json::Value {
    serde_json::from_str(line).unwrap_or_else(|e| panic!("not JSON: {line}\n  error: {e}"))
}

// ── 1. json: fields merged at the top level, with their types ────────────────

#[test]
fn json_record_merges_fields_with_types_and_has_no_trace_when_unset() {
    let run = run_program(
        r#"
        fn main() {
            log.set_format("json")
            let fields = {"msg": "x", "task": "t1", "n": 3}
            log.record("info", fields)
        }
        "#,
    );
    let lines = log_lines(&run);
    assert_eq!(
        lines.len(),
        1,
        "expected one record line, got {lines:?}\nstderr:\n{}",
        run.stderr
    );

    let v = parse_json(&lines[0]);
    assert_eq!(v["level"], serde_json::json!("INFO"), "level: {v}");
    assert!(v["ts"].is_string(), "ts must be a string: {v}");
    assert!(v["ts"].as_str().unwrap().contains('T'), "ts shape: {v}");
    assert_eq!(v["msg"], serde_json::json!("x"), "msg: {v}");
    assert_eq!(v["task"], serde_json::json!("t1"), "task: {v}");
    // The integer field must arrive as a JSON number, not the string "3".
    assert!(
        v["n"].is_number(),
        "n must be a number, got {}: {v}",
        v["n"]
    );
    assert_eq!(v["n"], serde_json::json!(3));
    assert!(
        v.get("trace").is_none(),
        "trace must be absent while unset: {v}"
    );
}

// ── 2. trace: set, read, carried by every line, cleared by nil ───────────────

#[test]
fn trace_is_set_carried_by_every_line_and_cleared_by_nil() {
    let run = run_program(
        r#"
        fn main() {
            log.set_format("json")
            log.set_trace("run-7")
            log.info("plain")
            let fields = {"msg": "structured", "k": "v"}
            log.record("info", fields)
            print(log.trace())
            log.set_trace(nil)
            log.info("after")
        }
        "#,
    );
    let lines = log_lines(&run);
    assert_eq!(
        lines.len(),
        3,
        "expected three log lines, got {lines:?}\nstderr:\n{}",
        run.stderr
    );

    let a = parse_json(&lines[0]);
    assert_eq!(a["trace"], serde_json::json!("run-7"), "log.info: {a}");
    let b = parse_json(&lines[1]);
    assert_eq!(b["trace"], serde_json::json!("run-7"), "log.record: {b}");

    assert!(
        run.stdout.contains("run-7"),
        "log.trace() must return the id, stdout was: {:?}",
        run.stdout
    );

    let c = parse_json(&lines[2]);
    assert!(
        c.get("trace").is_none(),
        "set_trace(nil) must remove the field: {c}"
    );
}

// ── 3. reserved keys are refused by name, and nothing is emitted ─────────────

#[test]
fn reserved_field_names_are_refused_and_emit_nothing() {
    for reserved in ["level", "ts", "trace"] {
        // The `before` line proves the emission path works in this run; the
        // refused record must add nothing, and the run stops at the refusal
        // (`after` is never reached) — a refusal is an error, not a skip.
        let source = format!(
            r#"
            fn main() {{
                log.set_format("json")
                log.info("before")
                let bad = {{"{reserved}": "hijack"}}
                log.record("info", bad)
                log.info("after")
            }}
            "#
        );
        let run = run_program(&source);
        assert_ne!(run.code, Some(0), "a refused record must fail the run");

        let lines = log_lines(&run);
        assert_eq!(
            lines.len(),
            1,
            "the refused record must emit no line, got {lines:?}\nstderr:\n{}",
            run.stderr
        );
        assert!(
            lines[0].contains("\"msg\":\"before\""),
            "the only emitted line must be the earlier log.info: {}",
            lines[0]
        );
        assert!(
            run.stderr.contains(reserved) && run.stderr.contains("reserved"),
            "the error must name '{reserved}' as reserved:\n{}",
            run.stderr
        );
    }
}

// ── 4. Private/Secret values render as markers, never as the payload ────────

#[test]
fn private_and_secret_fields_render_as_markers() {
    let run = run_program(
        r#"
        type Email = private String
        type Token = secret String
        fn main() {
            log.set_format("json")
            let e = "a@b.c" as Email
            let t = "s3cr3t-token" as Token
            let fields = {"msg": "m", "email": e, "token": t}
            log.record("info", fields)
        }
        "#,
    );
    let lines = log_lines(&run);
    assert_eq!(
        lines.len(),
        1,
        "expected one record line, got {lines:?}\nstderr:\n{}",
        run.stderr
    );

    let v = parse_json(&lines[0]);
    assert_eq!(v["email"], serde_json::json!("[REDACTED]"), "email: {v}");
    assert_eq!(v["token"], serde_json::json!("[SECRET]"), "token: {v}");
    assert!(
        !lines[0].contains("a@b.c") && !lines[0].contains("s3cr3t-token"),
        "the payload must not appear anywhere in the line: {}",
        lines[0]
    );
}

// ── 5. text: k=v pairs in insertion order ───────────────────────────────────

#[test]
fn text_record_renders_key_value_pairs_in_insertion_order() {
    let run = run_program(
        r#"
        fn main() {
            log.set_format("text")
            let fields = {"z": 1, "a": "two", "m": true}
            log.record("info", fields)
        }
        "#,
    );
    let lines = log_lines(&run);
    assert_eq!(
        lines.len(),
        1,
        "expected one record line, got {lines:?}\nstderr:\n{}",
        run.stderr
    );

    let line = &lines[0];
    assert!(line.starts_with("[INFO] ["), "text prefix: {line}");
    let z = line
        .find("z=1")
        .unwrap_or_else(|| panic!("missing z=1: {line}"));
    let a = line
        .find("a=two")
        .unwrap_or_else(|| panic!("missing a=two: {line}"));
    let m = line
        .find("m=true")
        .unwrap_or_else(|| panic!("missing m=true: {line}"));
    assert!(
        z < a && a < m,
        "k=v order must follow insertion order: {line}"
    );
    // No trace slot while the trace id is unset.
    assert!(
        !line.contains("[run-"),
        "an unset trace id must not render a slot: {line}"
    );
}

// ── 6. level filtering applies to record exactly as to log.info ─────────────

#[test]
fn level_filter_suppresses_a_record_below_the_minimum() {
    let run = run_program(
        r#"
        fn main() {
            log.set_format("json")
            log.set_level("warn")
            let hidden = {"msg": "hidden"}
            log.record("info", hidden)
            let shown = {"msg": "shown"}
            log.record("warn", shown)
        }
        "#,
    );
    let lines = log_lines(&run);
    assert_eq!(
        lines.len(),
        1,
        "only the warn record may appear, got {lines:?}\nstderr:\n{}",
        run.stderr
    );
    let v = parse_json(&lines[0]);
    assert_eq!(v["level"], serde_json::json!("WARN"), "level: {v}");
    assert_eq!(v["msg"], serde_json::json!("shown"), "msg: {v}");
}

// ── Beyond the six gates: the trace-id length limit ─────────────────────────
#[test]
fn a_64_character_trace_id_is_accepted_and_65_is_refused() {
    let ok = "a".repeat(64);
    let run = run_program(&format!(
        r#"
        fn main() {{
            log.set_trace("{ok}")
            print(log.trace())
        }}
        "#
    ));
    assert_eq!(
        run.code,
        Some(0),
        "64 characters must be accepted:\n{}",
        run.stderr
    );
    assert!(
        run.stdout.contains(&ok),
        "log.trace() must return the full id: {:?}",
        run.stdout
    );

    let too_long = "a".repeat(65);
    let run = run_program(&format!(
        r#"
        fn main() {{
            log.set_trace("{too_long}")
        }}
        "#
    ));
    assert_ne!(run.code, Some(0), "65 characters must be refused");
    assert!(
        run.stderr.contains("65") && run.stderr.contains("64"),
        "the refusal must state the limit and the length:\n{}",
        run.stderr
    );
}

// ── Beyond the six gates: the shape a refused nested value produces ─────────
#[test]
fn nested_field_values_are_refused_by_name_never_stringified() {
    let run = run_program(
        r#"
        fn main() {
            log.set_format("json")
            let fields = {"msg": "m", "nested": [1, 2, 3]}
            log.record("info", fields)
        }
        "#,
    );
    assert_ne!(run.code, Some(0), "a nested value must fail the run");
    assert!(
        run.stderr.contains("nested") && run.stderr.contains("Array"),
        "the refusal must name the field and the kind:\n{}",
        run.stderr
    );
    assert!(
        log_lines(&run).is_empty(),
        "nothing may be emitted: {:?}",
        log_lines(&run)
    );
}
