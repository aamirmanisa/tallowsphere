//! G01 P0.3, runtime half — `scope.grant(<Effect>)` must exist when a correct
//! program runs.
//!
//! The checker already types `Grant<Net>` and refuses a grant outside `main`,
//! an unknown effect, and a row nothing backs. Until this landed the runtime
//! had no `scope` at all, so every program that legally minted authority died
//! with `undefined variable: scope` — a compile-time model enforced against a
//! runtime that could not execute it.
//!
//! The egress half is not weakened and is not re-proved here: the register is
//! the same file, consulted at the same place, and `tests/scope_gate.rs`
//! (`an_unlisted_host_is_refused`, `the_shipped_register_parses_and_is_deny_by_default`)
//! remains the proof.

use std::io::Read;
use std::net::TcpListener;
use std::process::Command;
use std::thread;

fn fixture(name: &str) -> String {
    format!(
        "{}/tests/fixtures/effect_rows/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn tallow() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tallow"))
}

#[test]
fn trust_root_mints_a_grant_and_the_program_runs() {
    // The fixture connects to this listener, so the test proves the program ran
    // past `scope.grant` *and* opened the socket it declared — with no external
    // egress.
    let listener = TcpListener::bind("127.0.0.1:45991").expect("bind loopback listener");

    let accepted = thread::spawn(move || {
        let (mut stream, peer) = listener.accept().expect("fixture never connected");
        let mut buf = [0u8; 1];
        let _ = stream.read(&mut buf);
        peer
    });

    let out = tallow()
        .arg("run")
        .arg("--target")
        .arg("x86_64-linux")
        .arg(fixture("scope_grant_loopback.tl"))
        .output()
        .expect("run tallow");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

    assert!(
        out.status.success(),
        "a program that legally mints a grant must run:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stderr.contains("undefined variable: scope"),
        "the authority producer must exist at run time:\n{stderr}"
    );
    assert!(
        stdout.contains("granted"),
        "the program must reach its own output:\n{stdout}"
    );
    let peer = accepted.join().expect("listener thread");
    assert_eq!(peer.ip().to_string(), "127.0.0.1");
}

#[test]
fn an_unknown_effect_is_still_a_check_time_error() {
    let out = tallow()
        .arg("check")
        .arg(fixture("scope_grant_unknown_effect.tl"))
        .output()
        .expect("check tallow");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !out.status.success(),
        "scope.grant(Bogus) must not compile:\n{stderr}"
    );
    assert!(
        stderr.contains("E0143"),
        "the refusal must be the checker's unknown-effect code:\n{stderr}"
    );
    assert!(
        !stderr.contains("undefined variable"),
        "the checker must answer before any runtime path is reached:\n{stderr}"
    );
}

#[test]
fn a_grant_cannot_be_forged_from_a_literal() {
    // The runtime value is opaque only if source cannot build one. `Grant` is
    // not a declared struct, and an integer in its place is E0117.
    let denied = tallow()
        .arg("check")
        .arg(fixture("grant_is_not_forgeable.tl"))
        .output()
        .expect("check forge fixture");
    let stderr = String::from_utf8_lossy(&denied.stderr).into_owned();
    assert!(
        !denied.status.success() && stderr.contains("E0117"),
        "a forged grant must stay a type error:\n{stderr}"
    );
}
