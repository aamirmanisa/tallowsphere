//! The egress ledger, end to end through the shipped binary.
//!
//! Unit tests pin the decision function; this file pins the wiring: a real fetch
//! against a fixture server, with `TALLOW_EGRESS_LEDGER` set, must (a) write what
//! it did, (b) stop the host after a 403, and (c) refuse the next request without
//! opening a socket.
//!
//! The fetch is `http.batch`, not `http.get`, for a measured reason: `http.get`
//! performs no request when its result fields are read directly (prints -1, the
//! target sees zero connections), while `http.batch` does perform it. That defect
//! is written up in docs/operations/ci-preexisting-failures-2026-10-23.md §5. The
//! ledger watches both paths; these tests prove the control.
//!
//! The failure this guards against is specific: a ledger that is implemented but
//! never consulted, which looks like governance and enforces nothing.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Fixture: the first request gets 403, every later one gets 200. The hit count
/// is how the test proves the second request never reached the server.
fn fixture() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let n = counter.fetch_add(1, Ordering::SeqCst);
            let mut reader = BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                    break;
                }
            }
            let (status, body) = if n == 0 {
                ("403 Forbidden", "no")
            } else {
                ("200 OK", "ok")
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.flush();
        }
    });
    (port, hits)
}

/// Fixture: always 200. Used for the budget rule, where the stop rule must not
/// interfere.
fn fixture_ok() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            counter.fetch_add(1, Ordering::SeqCst);
            let mut reader = BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                    break;
                }
            }
            let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            let _ = s.write_all(resp.as_bytes());
            let _ = s.flush();
        }
    });
    (port, hits)
}

/// The scope register is deny-by-default and the native HTTP path enforces it.
/// A fixture on loopback must be authorized explicitly, exactly as a real target
/// is — otherwise the batch is refused before egress and the ledger has nothing
/// to record.
fn authorize_loopback(dir: &std::path::Path) {
    let cfg = dir.join("configs/tallow/scope");
    std::fs::create_dir_all(&cfg).expect("scope dir");
    std::fs::write(
        cfg.join("authorized-hosts.toml"),
        "[[authorized]]\nhost = \"127.0.0.1\"\nbasis = \"ownership\"\ngranted_by = \"test\"\ngranted_at = \"2026-01-01\"\nexpires_at = \"2027-01-01\"\nmethods = [\"GET\", \"HEAD\"]\nnotes = \"fixture server owned by the test\"\n",
    )
    .expect("scope register");
}

fn run(dir: &std::path::Path, source: &str, name: &str, ledger: &std::path::Path, budget: u32) -> (bool, String) {
    let file = dir.join(format!("{name}.tl"));
    std::fs::write(&file, source).expect("write");
    authorize_loopback(dir);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(&file)
        .current_dir(dir)
        .env("TALLOW_EGRESS_LEDGER", ledger)
        .env("TALLOW_EGRESS_BUDGET", budget.to_string())
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

const PROGRAM: &str = r#"
@legal(basis: .public_data, purpose: "egress ledger test", personal_data: false)
@cra_class(.default)
@persona(id: "egress-test", cover_class: .researcher, compartment: "egress", fingerprint_seed: "egress-1")
@burn_plan(persona: "egress-test", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowTest/1.0 (+https://tallow.invalid/bot)")
fn main() {
    let rs = http.batch(["http://127.0.0.1:PORT/one"], 1)
    print(len(rs))
}
"#;

#[test]
fn a_403_stops_the_host_across_runs_and_the_second_request_never_leaves() {
    let (port, hits) = fixture();
    let dir = std::env::temp_dir().join(format!("tallow-egress-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let ledger = dir.join("egress.jsonl");
    let _ = std::fs::remove_file(&ledger);

    let source = PROGRAM.replace("PORT", &port.to_string());

    // First run: the server answers 403 and the ledger records a stop.
    let (ok, output) = run(&dir, &source, "first", &ledger, 10);
    assert!(ok, "the batch program succeeds and reports a result: {output}");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "one request was made; program output: {output}");

    let text = std::fs::read_to_string(&ledger).expect("ledger written");
    assert!(text.contains("\"status\":403"), "the 403 is recorded: {text}");
    assert!(
        text.contains("\"stopped\":\"target returned 403"),
        "the stop is recorded: {text}"
    );

    // Second run, same ledger: the host is stopped and nothing is sent.
    let (ok, output) = run(&dir, &source, "second", &ledger, 10);
    assert!(ok, "the refused batch still returns a result: {output}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the refused run must not reach the server"
    );

    let text = std::fs::read_to_string(&ledger).expect("ledger written");
    assert!(
        text.contains("\"decision\":\"refused:"),
        "the refusal is journalled: {text}"
    );
    assert!(text.contains("/one"), "the refusal names the URL: {text}");
}

#[test]
fn the_budget_refuses_the_request_after_the_limit() {
    let (port, hits) = fixture_ok();
    let dir = std::env::temp_dir().join(format!("tallow-egress-budget-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let ledger = dir.join("budget.jsonl");
    let _ = std::fs::remove_file(&ledger);

    let source = PROGRAM.replace("PORT", &port.to_string());
    let (ok, output) = run(&dir, &source, "budget-first", &ledger, 1);
    assert!(ok, "the first request fits the budget: {output}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let (ok, output) = run(&dir, &source, "budget-second", &ledger, 1);
    assert!(ok, "the refused batch still returns a result: {output}");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "nothing left the box");

    let text = std::fs::read_to_string(&ledger).expect("ledger written");
    assert!(
        text.contains("budget 1 exhausted for 127.0.0.1"),
        "the refusal names the budget and the host: {text}"
    );
}
