//! N09 — IPv6 scanning, measured against a real `[::1]` listener.
//!
//! Three claims are checked, each against something that can fail:
//!
//! * a listening TCP port on `[::1]` comes back `open`, and a closed one comes
//!   back `closed` (a RST), so the v6 connect path distinguishes the two the way
//!   the v4 path does;
//! * `v6_discover("::1")` reports `alive=true` with confidence 0.9 from an
//!   ICMPv6 echo reply (skipped loudly, with the reason, if CAP_NET_RAW is
//!   denied — a probe that never ran is not evidence of a dead host);
//! * the scope gate runs before any probe: an IPv6 literal the register does
//!   not list is refused, and a listener bound to that address never sees a
//!   connection.
//!
//! The register is resolved relative to the process working directory, so the
//! positive tests run the binary with `tests/fixtures/topology_ipv6` as cwd,
//! where a test-scoped register grants `::1`. The workspace register is not
//! edited: whether `::1` is scannable is the operator's grant to make.

use std::io::ErrorKind;
use std::net::TcpListener;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const OPEN_PORT: u16 = 46021;
const CLOSED_PORT: u16 = 46023;
/// A port of its own, so the refusal test does not race the open-port test for
/// the same `[::1]` socket (tests in one binary run in parallel).
const UNLISTED_PORT: u16 = 46031;

fn fixture_dir() -> String {
    format!(
        "{}/tests/fixtures/topology_ipv6",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// Run a fixture with an explicit working directory, because that is what
/// decides which scope register the child reads.
fn run(name: &str, cwd: &str) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg("--target")
        .arg("x86_64-linux")
        .arg(format!("{}/{}", fixture_dir(), name))
        .current_dir(cwd)
        .output()
        .expect("run tallow");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Bind `[::1]` and report over a channel whether anything connects.
fn watch_v6_listener(port: u16) -> mpsc::Receiver<bool> {
    let listener = TcpListener::bind(("::1", port)).expect("bind an IPv6 loopback listener");
    listener
        .set_nonblocking(true)
        .expect("non-blocking listener");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match listener.accept() {
                Ok(_) => {
                    let _ = tx.send(true);
                    return;
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() > deadline {
                        let _ = tx.send(false);
                        return;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => {
                    let _ = tx.send(false);
                    return;
                }
            }
        }
    });
    rx
}

#[test]
fn a_listening_ipv6_port_comes_back_open() {
    let seen = watch_v6_listener(OPEN_PORT);

    let (ok, stdout, stderr) = run("scan_v6_connect.tl", &fixture_dir());
    assert!(
        ok,
        "the IPv6 connect scan must run:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains(&format!("open=[{OPEN_PORT}]")),
        "the [::1]:{OPEN_PORT} listener must be reported open:\n{stdout}"
    );
    assert!(
        stdout.contains("technique=connect"),
        "the verdict must carry the technique that produced it:\n{stdout}"
    );
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(3)).ok(),
        Some(true),
        "the probe is a real connect(): the listener must have seen it"
    );
}

#[test]
fn a_closed_ipv6_port_comes_back_closed() {
    // Nothing listens on CLOSED_PORT; on loopback a refused connect must be
    // reported closed rather than swept into filtered.
    let (ok, stdout, stderr) = run("closed_v6.tl", &fixture_dir());
    assert!(
        ok,
        "the IPv6 connect scan must run:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains(&format!("closed=[{CLOSED_PORT}]")),
        "a refused IPv6 connect must be reported closed:\n{stdout}"
    );
    assert!(
        stdout.contains("open=[]"),
        "no port is open, and the empty result must be explicit:\n{stdout}"
    );
}

#[test]
fn ipv6_discovery_reports_loopback_alive_from_an_icmpv6_reply() {
    // A raw ICMPv6 socket needs CAP_NET_RAW. Skip with the measured reason
    // rather than pretending the probe ran.
    if !is_root() {
        eprintln!("skipping: ICMPv6 discovery needs CAP_NET_RAW (not root)");
        return;
    }

    let (ok, stdout, stderr) = run("discover_v6.tl", &fixture_dir());
    assert!(
        ok,
        "IPv6 discovery must run:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("alive=true"),
        "loopback must answer an ICMPv6 echo request:\n{stdout}"
    );
    assert!(
        stdout.contains("confidence=0.9"),
        "a reply proves presence, so it carries 0.9 as in v4 discovery:\n{stdout}"
    );
    assert!(
        stdout.contains("rtt_ms=") && !stdout.contains("rtt_ms=nil"),
        "a reply must carry a measured RTT:\n{stdout}"
    );
}

#[test]
fn an_unlisted_ipv6_target_is_refused_before_a_probe() {
    // 2001:db8::1 is RFC 3849 documentation space and is absent from the
    // fixture register by design.
    let (ok, stdout, stderr) = run("unauthorized_v6.tl", &fixture_dir());
    assert!(
        !ok,
        "an unlisted IPv6 target must not scan:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("not authorized") && stderr.contains("scope:not-listed"),
        "the refusal must come from the register's own decision:\n{stderr}"
    );
    assert!(
        stdout.is_empty(),
        "nothing may be produced for a refused target:\n{stdout}"
    );
}

#[test]
fn an_unlisted_ipv6_loopback_is_refused_before_the_socket_is_used() {
    // Run from deny_v6/, a register that grants the IPv4 loopback and NOT ::1.
    // (The workspace register grants ::1 since 2026-10-26 — the operator's
    // decision — so this test can no longer borrow it; it was re-pointed here,
    // which is exactly the signal its previous comment anticipated.)
    // A listener is bound on [::1]:46031 first, so "before any probe" is
    // measured: if the gate let the scan through, the accept would fire.
    let seen = watch_v6_listener(UNLISTED_PORT);

    let deny_dir = format!("{}/deny_v6", fixture_dir());
    let (ok, stdout, stderr) = run("unlisted_loopback_v6.tl", &deny_dir);
    assert!(
        !ok,
        "::1 is not in the workspace register and must not scan:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("scope:not-listed"),
        "the literal must reach the register as a host key (not a malformed \
         or truncated one), and the register must refuse it:\n{stderr}"
    );
    assert!(
        stdout.is_empty(),
        "a refused scan must print nothing:\n{stdout}"
    );
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(3)).ok(),
        Some(false),
        "a refused scan must not have opened a connection to the listener"
    );
}

#[test]
fn a_raw_syn_scan_on_an_ipv6_literal_names_the_connect_path() {
    // Item 4: no IPV6_HDRINCL, so a raw IPv6 SYN is refused — and the refusal
    // must name v6_connect_scan rather than returning an empty ScanResult that
    // would read as "nothing is open".
    let (ok, stdout, stderr) = run("syn_v6_refused.tl", &fixture_dir());
    assert!(
        !ok,
        "a raw SYN scan must not silently succeed on an IPv6 literal:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("IPV6_HDRINCL"),
        "the refusal must name the missing mechanism:\n{stderr}"
    );
    assert!(
        stderr.contains("v6_connect_scan"),
        "the refusal must name the working alternative:\n{stderr}"
    );
    assert!(
        !stdout.contains("open=[]"),
        "a refusal is not an empty scan:\n{stdout}"
    );
}

/// Raw sockets need CAP_NET_RAW, which only root has. Non-Unix targets have no
/// raw-socket path at all, so this reports `false` and the test skips with its
/// stated reason instead of failing to compile on a `libc` call Windows lacks.
///
/// Deliberately at the end of the file: inserting it above the test would shift
/// cited lines and break the DONE-backlog evidence gate.
#[cfg(unix)]
fn is_root() -> bool {
    // SAFETY: `geteuid` takes no arguments, touches no memory, cannot fail.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}
