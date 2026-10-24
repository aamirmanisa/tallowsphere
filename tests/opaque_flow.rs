//! OPAQUE (RFC 9807) end-to-end through the language surface.
//!
//! The protocol correctness is covered by unit tests in `src/opaque.rs`; this
//! file proves the marshalling — that a caller can drive a full registration and
//! login through Tallow values and both sides derive the same session key, and
//! that a wrong password is refused rather than silently accepted.

use std::process::Command;

fn tallow() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tallow"))
}

fn run(src: &str, name: &str) -> (bool, String, String) {
    let dir = std::env::temp_dir().join(format!("tallow-opaque-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tempdir");
    let p = dir.join(name);
    std::fs::write(&p, src).expect("write program");
    let out = tallow()
        .args(["run", "--interpret"])
        .arg(&p)
        .output()
        .expect("run tallow");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn lines(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .map(str::to_string)
        .collect()
}

const REGISTER_AND_LOGIN: &str = r#"fn main() {
    print(crypto.opaque_suite())
    let setup = crypto.opaque_setup()
    let reg = crypto.opaque_register_start("correct horse battery staple")
    let rsp = crypto.opaque_register_respond(setup, reg.request, "alice")
    let up = crypto.opaque_register_finish(reg.state, "correct horse battery staple", rsp.response)
    let record = crypto.opaque_register_store(up.upload)

    let l1 = crypto.opaque_login_start("correct horse battery staple")
    let l2 = crypto.opaque_login_respond(setup, record, l1.request, "alice")
    let l3 = crypto.opaque_login_finish(l1.state, "correct horse battery staple", l2.response)
    let srv = crypto.opaque_login_server_finish(l2.state, l3.finalization)

    if l3.session_key == srv { print("session_match") } else { print("session_mismatch") }
    print(l3.session_key.len)
    print(l3.export_key.len)
}
"#;

#[test]
fn a_full_registration_and_login_agrees_on_the_session_key() {
    let (ok, stdout, stderr) = run(REGISTER_AND_LOGIN, "flow.tl");
    assert!(ok, "run failed\n{stdout}\n{stderr}");
    let l = lines(&stdout);
    assert!(
        l[0].contains("RFC 9807"),
        "the suite must identify the standard, got {}",
        l[0]
    );
    assert_eq!(l[1], "session_match", "client and server must agree");
    assert_eq!(l[2], "128", "64-byte session key in hex");
    assert_eq!(l[3], "128", "64-byte export key in hex");
}

#[test]
fn the_wrong_password_never_reaches_a_session_key() {
    let src = r#"fn main() {
    let setup = crypto.opaque_setup()
    let reg = crypto.opaque_register_start("right")
    let rsp = crypto.opaque_register_respond(setup, reg.request, "bob")
    let up = crypto.opaque_register_finish(reg.state, "right", rsp.response)
    let record = crypto.opaque_register_store(up.upload)

    let l1 = crypto.opaque_login_start("wrong")
    let l2 = crypto.opaque_login_respond(setup, record, l1.request, "bob")
    let l3 = crypto.opaque_login_finish(l1.state, "wrong", l2.response)
    print(l3.session_key)
}
"#;
    let (ok, stdout, stderr) = run(src, "wrongpw.tl");
    assert!(!ok, "a wrong password must fail; stdout={stdout}");
    assert!(
        stderr.contains("opaque"),
        "the refusal must come from the OPAQUE path, got {stderr}"
    );
}
