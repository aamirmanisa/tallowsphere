//! N01/N10/N11 — the topology slice, measured against a real loopback
//! listener.
//!
//! A SYN scan is a real packet exchange: the listener's port must come back
//! `open`, and a closed port must come back `closed` (RST) rather than being
//! swept into `filtered`. The connect scan is the unprivileged path and must
//! reach the same verdicts. The SYN test needs CAP_NET_RAW and skips loudly if
//! the environment denies it — a skipped test that says why is evidence; a
//! silently passing one is not.

use std::net::TcpListener;
use std::process::Command;
use std::thread;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/topology/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn run(name: &str) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg("--target")
        .arg("x86_64-linux")
        .arg(fixture(name))
        .output()
        .expect("run tallow");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn a_connect_scan_separates_open_from_closed() {
    let listener = TcpListener::bind("127.0.0.1:45992").expect("bind 45992");
    let _accepted = thread::spawn(move || {
        let _ = listener.accept();
    });

    let (ok, stdout, stderr) = run("scan_connect.tl");
    assert!(ok, "connect scan must run:\nstdout: {stdout}\nstderr: {stderr}");
    assert!(
        stdout.contains("open=[45992]"),
        "the listening port must be open and the closed ones must not:\n{stdout}"
    );
    assert!(
        stdout.contains("closed=[45993, 45994]"),
        "closed ports must be reported closed, not filtered:\n{stdout}"
    );
}

#[test]
fn a_syn_scan_separates_open_from_closed() {
    // Raw sockets need CAP_NET_RAW. Root has it; a sandbox may not. Skip with
    // the measured reason rather than pretending the scan ran.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: raw SYN scan needs CAP_NET_RAW (not root)");
        return;
    }

    let listener = TcpListener::bind("127.0.0.1:45995").expect("bind 45995");
    let _accepted = thread::spawn(move || {
        let _ = listener.accept();
    });

    let (ok, stdout, stderr) = run("scan_loopback.tl");
    assert!(ok, "syn scan must run:\nstdout: {stdout}\nstderr: {stderr}");
    assert!(
        stdout.contains("plan packets=3"),
        "the planner must count one probe per port:\n{stdout}"
    );
    assert!(
        stdout.contains("syn open=[45995]"),
        "the listener must be seen open by a half-open scan:\n{stdout}"
    );
    assert!(
        stdout.contains("closed=[45996, 45997]"),
        "CLOSED means a RST came back; silence is filtered:\n{stdout}"
    );
}

#[test]
fn an_unauthorized_target_is_refused_before_a_packet_is_sent() {
    // The scanner must not be a second, weaker door than the register. A host
    // that is not listed cannot be planned or scanned at all.
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg("--target")
        .arg("x86_64-linux")
        .arg(fixture("unauthorized_target.tl"))
        .output()
        .expect("run tallow");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !out.status.success(),
        "an unlisted target must not scan:\n{stderr}"
    );
    assert!(
        stderr.contains("not authorized"),
        "the refusal must come from the scope register:\n{stderr}"
    );
    assert!(
        stderr.contains("scope:not-listed"),
        "the register's own refusal code must be carried through:\n{stderr}"
    );
}
