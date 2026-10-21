//! Unwrapping an optional on the compiled plane (register #134), and the two
//! failure modes that made it dangerous to do with a cast (#133, #136).
//!
//! `match` is the only unwrap the language has. This pins:
//!   * `Some(x)` / `None` produce the same answers on both planes, for i64 and
//!     String payloads;
//!   * a `Result` discarded as a statement stops being silent — stdout stays
//!     empty and the process exits 1 on both planes (#133);
//!   * binding a `T?` to a `T` is rejected at check time (#136).

const MATCH: &str = r#"
fn div(a: i64, b: i64) -> i64? {
    if b == 0 { return nil }
    return a / b
}

fn name_of(s: String) -> String? {
    if s == "" { return nil }
    return s
}

fn main() {
    let v = div(8, 2) match {
        Some(x) -> x
        None -> 0
    }
    print(v)

    let w = div(8, 0) match {
        Some(x) -> x
        None -> 0
    }
    print(w)

    let t = name_of("ok") match {
        Some(s) -> s
        None -> "none"
    }
    print(t)
}
"#;

const DROPPED_ERR: &str = r#"
fn bad() -> Result<i64> {
    bail "boom"
}

fn main() {
    bad()
    print("after")
}
"#;

const DROPPED_OK: &str = r#"
fn good() -> Result<i64> {
    Ok(7)
}

fn main() {
    good()
    print("after")
}
"#;

const UNWRAP_BIND: &str = r#"
fn src(n: i64) -> i64? {
    return n
}

fn main() {
    let v: i64 = src(0)
    print(v)
}
"#;

fn run(program: &str, tag: &str, args: &[&str]) -> std::process::Output {
    let path = std::env::temp_dir().join(format!("tallow-optional-match-{tag}.tl"));
    std::fs::write(&path, program).expect("write program");
    std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(args)
        .arg(&path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow")
}

#[test]
fn match_unwraps_an_optional_on_both_planes() {
    let want = "4\n0\nok\n";
    let native = run(MATCH, "native", &["run", "--require-native"]);
    assert!(
        native.status.success(),
        "native plane refused: {}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&native.stdout), want);

    let interp = run(MATCH, "interp", &["run", "--interpret"]);
    assert!(interp.status.success(), "interpreter refused");
    assert_eq!(String::from_utf8_lossy(&interp.stdout), want);
}

#[test]
fn a_dropped_err_fails_loudly_on_both_planes() {
    for (plane, args) in [
        ("native", ["run", "--require-native"].as_slice()),
        ("interp", ["run", "--interpret"].as_slice()),
    ] {
        let out = run(DROPPED_ERR, &format!("dropped-{plane}"), args);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{plane}: a discarded Err must exit 1, stdout was {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "",
            "{plane}: stdout must stay clean on the failure path"
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("boom"),
            "{plane}: the message must name the error"
        );
    }
}

#[test]
fn a_dropped_ok_still_continues() {
    for (plane, args) in [
        ("native", ["run", "--require-native"].as_slice()),
        ("interp", ["run", "--interpret"].as_slice()),
    ] {
        let out = run(DROPPED_OK, &format!("dropped-ok-{plane}"), args);
        assert!(
            out.status.success(),
            "{plane}: a discarded Ok must not fail: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout), "after\n");
    }
}

#[test]
fn binding_an_optional_to_a_plain_type_is_rejected() {
    let out = run(UNWRAP_BIND, "unwrap-bind", &["check"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "check must reject an unchecked unwrap");
    assert!(
        err.contains("E0116"),
        "the diagnostic must name the rule, got: {err}"
    );
}
