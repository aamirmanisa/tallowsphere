//! OPAQUE across planes: a registration made natively must be usable by the
//! interpreter and vice versa.
//!
//! Note on lengths: the protocol messages are serialized as JSON byte arrays, so
//! their hex length varies between runs with the byte values. Nothing here
//! compares lengths — only the session keys, which must match exactly.

use std::process::Command;

fn write(src: &str, name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tallow-opqnat-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tempdir");
    let p = dir.join(name);
    std::fs::write(&p, src).expect("write program");
    p
}

fn run(src: &str, name: &str, interpret: bool) -> (bool, Vec<String>, String) {
    let p = write(src, name);
    let mut c = Command::new(env!("CARGO_BIN_EXE_tallow"));
    c.arg("run");
    c.arg(if interpret { "--interpret" } else { "--require-native" });
    let out = c.arg(&p).output().expect("run tallow");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let lines: Vec<String> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('*') && !l.starts_with("runtime archive"))
        .map(str::to_string)
        .collect();
    (
        out.status.success(),
        lines,
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn the_native_plane_really_lowers_the_opaque_flow() {
    let src = "fn main() {\n    let s = crypto.opaque_setup()\n    let r = crypto.opaque_register_start(\"pw\")\n    print(r.request.len > 0)\n    print(s.len > 0)\n}\n";
    let (ok, out, err) = run(src, "lowered.tl", false);
    assert!(ok, "--require-native must succeed: {out:?}\n{err}");
    assert!(
        !err.contains("no native lowering"),
        "the lowering must exist, not fall back: {err}"
    );
    assert_eq!(out, vec!["true", "true"]);
}

/// Registration on one plane, login on the other.
fn cross_plane(register_natively: bool) -> (String, String) {
    let setup_and_record = r#"fn main() {
    let setup = crypto.opaque_setup()
    let reg = crypto.opaque_register_start("correct horse")
    let rsp = crypto.opaque_register_respond(setup, reg.request, "alice")
    let up = crypto.opaque_register_finish(reg.state, "correct horse", rsp.response)
    let record = crypto.opaque_register_store(up.upload)
    print(setup)
    print(record)
}
"#;
    let (ok, out, err) = run(setup_and_record, "reg.tl", !register_natively);
    assert!(ok, "registration failed: {err}");
    assert_eq!(out.len(), 2, "expected setup and record, got {out:?}");
    (out[0].clone(), out[1].clone())
}

fn login(setup: &str, record: &str, interpret: bool) -> Vec<String> {
    let src = format!(
        r#"fn main() {{
    let l1 = crypto.opaque_login_start("correct horse")
    let l2 = crypto.opaque_login_respond("{setup}", "{record}", l1.request, "alice")
    let l3 = crypto.opaque_login_finish(l1.state, "correct horse", l2.response)
    let srv = crypto.opaque_login_server_finish(l2.state, l3.finalization)
    if l3.session_key == srv {{ print("session_match") }} else {{ print("session_mismatch") }}
    print(l3.session_key.len)
}}
"#
    );
    let (ok, out, err) = run(&src, if interpret { "login_i.tl" } else { "login_n.tl" }, interpret);
    assert!(ok, "login failed ({interpret}): {err}");
    out
}

#[test]
fn a_native_registration_logs_in_from_the_interpreter() {
    let (setup, record) = cross_plane(true);
    assert_eq!(login(&setup, &record, true), vec!["session_match", "128"]);
}

#[test]
fn an_interpreter_registration_logs_in_natively() {
    let (setup, record) = cross_plane(false);
    assert_eq!(login(&setup, &record, false), vec!["session_match", "128"]);
}
