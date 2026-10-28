//! N18 — the method matrix, measured against a loopback fixture server.
//!
//! The fixture-server style is the one this repository already uses for an intel
//! entry point that opens a socket: a `TcpListener` bound in the test, a `.tl`
//! program run through the real `tallow` binary, and assertions on what the binary
//! printed (`tests/topology_scan.rs`). There is no `tests/intel_api_fixtures.rs` at
//! this revision — the api fixtures are `.tl` programs plus the driver that runs
//! them — so this file is the driver for `tests/fixtures/intel_api/method_matrix.tl`.
//!
//! What each case pins:
//!
//! * OPTIONS answered with `Allow` + `Access-Control-Allow-Origin: *` derives `open`
//!   and the evidence line names OPTIONS as the producer.
//! * OPTIONS 405 falls back to HEAD, says so, records the HEAD status, and leaves CORS
//!   `unknown` — a preflight that was never answered is not a policy.
//! * `WWW-Authenticate: Bearer` classifies `bearer`; a 401 with no such header is
//!   `other(unspecified)`, never `basic`.
//! * An unlisted host is refused by name (`scope:not-listed`) before a request.
//!
//! Every assertion reads a field the binary actually printed; nothing is inferred from
//! the fixture's intent.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

const PORT: u16 = 46111;

/// One recorded request line, so the test can prove HEAD was actually sent.
type Log = Arc<Mutex<Vec<String>>>;

/// The canned response for one `(method, path)`.
///
/// A 405 here is a *response*, not a failure: the matrix must record it and fall back,
/// which is exactly the behaviour the fixture exists to expose.
fn route(method: &str, path: &str) -> (&'static str, Vec<&'static str>) {
    match (method, path) {
        ("OPTIONS", "/public") => (
            "HTTP/1.1 204 No Content",
            vec![
                "Allow: GET, POST, OPTIONS",
                "Access-Control-Allow-Origin: *",
                "Access-Control-Allow-Methods: GET, POST, OPTIONS",
                "Server: fixture-matrix/1.0",
            ],
        ),
        ("OPTIONS", "/no-options") => (
            "HTTP/1.1 405 Method Not Allowed",
            vec!["Allow: GET, HEAD", "Server: fixture-matrix/1.0"],
        ),
        ("HEAD", "/no-options") => (
            "HTTP/1.1 200 OK",
            vec!["Server: fixture-matrix/1.0", "Content-Type: text/html"],
        ),
        ("OPTIONS", "/bearer") => (
            "HTTP/1.1 401 Unauthorized",
            vec![
                "WWW-Authenticate: Bearer realm=\"fixture\"",
                "Server: fixture-matrix/1.0",
            ],
        ),
        // A 401 with no challenge header: the server wanted credentials and did not say
        // which kind. `basic` here would be an invention.
        ("OPTIONS", "/bare-401") => (
            "HTTP/1.1 401 Unauthorized",
            vec!["Server: fixture-matrix/1.0"],
        ),
        _ => ("HTTP/1.1 404 Not Found", vec!["Server: fixture-matrix/1.0"]),
    }
}

/// Bind the fixture port and serve every connection in a background thread.
///
/// The thread runs until the process exits — the child binary is a separate process, so
/// the listener has to outlive the `run()` call that drives it.
fn serve() -> Log {
    let listener =
        TcpListener::bind(("127.0.0.1", PORT)).expect("bind the method-matrix fixture port");
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&log);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut sock) = stream else { continue };
            sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut buf: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                match sock.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let text = String::from_utf8_lossy(&buf).into_owned();
            let request_line = text.lines().next().unwrap_or("").trim().to_string();
            let mut parts = request_line.split(' ');
            let method = parts.next().unwrap_or("").to_string();
            let path = parts.next().unwrap_or("").to_string();
            seen.lock().unwrap().push(format!("{method} {path}"));

            let (status, headers) = route(&method, &path);
            let mut resp = format!("{status}\r\n");
            for h in headers {
                resp.push_str(&format!("{h}\r\n"));
            }
            resp.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = sock.write_all(resp.as_bytes());
            let _ = sock.flush();
        }
    });
    log
}

struct Run {
    ok: bool,
    stdout: String,
    stderr: String,
    log: Log,
}

/// Run a fixture program. The fixture server, when the case needs one, is bound by the
/// caller — a case that must be refused before the socket needs no server, and binding a
/// port there would only prove the test bound something.
fn run_program(name: &str) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg("--target")
        .arg("x86_64-linux")
        .arg(format!(
            "{}/tests/fixtures/intel_api/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run tallow");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn run_fixture(name: &str) -> Run {
    let log = serve();
    let (ok, stdout, stderr) = run_program(name);
    Run {
        ok,
        stdout,
        stderr,
        log,
    }
}

/// One server, one child run: the four cases read different fields of the same matrix.
/// Re-running the binary per assertion would quadruple the wall clock and add nothing.
fn matrix() -> &'static Run {
    static MATRIX: OnceLock<Run> = OnceLock::new();
    MATRIX.get_or_init(|| {
        let run = run_fixture("method_matrix.tl");
        assert!(
            run.ok,
            "method_matrix.tl must run:\nstdout:\n{}\nstderr:\n{}",
            run.stdout, run.stderr
        );
        run
    })
}

/// The `row ...` line for one path.
fn row(path: &str) -> String {
    let out = &matrix().stdout;
    out.lines()
        .find(|l| l.starts_with(&format!("row path={path} ")))
        .unwrap_or_else(|| panic!("no row for {path} in:\n{out}"))
        .to_string()
}

/// The evidence line recorded for one path.
fn evidence(path: &str) -> String {
    let out = &matrix().stdout;
    // Evidence lines follow their row in declaration order, so match on the URL instead of
    // on position: the URL is the row's own identity.
    out.lines()
        .find(|l| l.starts_with("ev ") && l.contains(&format!(":46111{path} ")))
        .unwrap_or_else(|| panic!("no evidence line for {path} in:\n{out}"))
        .to_string()
}

#[test]
fn options_with_allow_and_wildcard_cors_derives_open() {
    let r = row("/public");
    assert!(r.contains("method=OPTIONS"), "OPTIONS answered; got: {r}");
    assert!(
        r.contains("status=204"),
        "the recorded status is the OPTIONS one: {r}"
    );
    assert!(
        r.contains("allow=GET, POST, OPTIONS"),
        "Allow must be recorded verbatim, ordering included: {r}"
    );
    assert!(
        r.contains("cors=open"),
        "* with no credentials is open: {r}"
    );
    assert!(
        r.contains("from=options"),
        "the CORS verdict must name its source method: {r}"
    );
    assert!(
        r.contains("declared=GET,POST"),
        "both declared methods belong to the one path probe: {r}"
    );

    let ev = evidence("/public");
    assert!(
        ev.contains("OPTIONS http://127.0.0.1:46111/public -> 204"),
        "evidence must name the method, the URL and the status: {ev}"
    );
    assert!(
        ev.contains("allow<-Allow: GET, POST, OPTIONS"),
        "the Allow claim must cite the Allow header: {ev}"
    );
    assert!(
        ev.contains("cors<-Access-Control-Allow-Origin: *"),
        "the CORS claim must cite the header it came from: {ev}"
    );
    assert!(
        ev.contains("server<-Server: fixture-matrix/1.0"),
        "the Server claim must cite the Server header: {ev}"
    );
}

#[test]
fn a_refused_options_falls_back_to_head_and_says_so() {
    let r = row("/no-options");
    assert!(
        r.contains("method=HEAD"),
        "405 must fall back to HEAD; got: {r}"
    );
    assert!(
        r.contains("status=200"),
        "the row records what HEAD returned: {r}"
    );
    assert!(
        r.contains("cors=unknown"),
        "a refused preflight yields no CORS verdict: {r}"
    );
    assert!(
        r.contains("from=none"),
        "no method may be credited with a CORS verdict it did not give: {r}"
    );

    let ev = evidence("/no-options");
    assert!(
        ev.contains("OPTIONS refused 405"),
        "the evidence must name the refusal status: {ev}"
    );
    assert!(
        ev.contains("fell back to HEAD"),
        "the weaker instrument must be named, not disguised: {ev}"
    );
    assert!(
        ev.contains("cors: unknown"),
        "the unknown must be explained, not left blank: {ev}"
    );

    // The fallback is a real request, not a claim: the server's log proves a HEAD arrived.
    let log = matrix().log.lock().unwrap().clone();
    assert!(
        log.iter().any(|l| l == "OPTIONS /no-options"),
        "OPTIONS must actually have been sent: {log:?}"
    );
    assert!(
        log.iter().any(|l| l == "HEAD /no-options"),
        "the fallback must actually have been sent: {log:?}"
    );

    // A template has no value to request, so it is counted, never probed.
    let head = matrix()
        .stdout
        .lines()
        .find(|l| l.starts_with("matrix "))
        .expect("the matrix summary line");
    assert!(
        head.contains("templated=1"),
        "the templated path must be counted: {head}"
    );
    assert!(
        !log.iter().any(|l| l.contains("/users/")),
        "a template must never reach the wire: {log:?}"
    );
    assert!(
        head.contains("head=1"),
        "one fallback, counted once: {head}"
    );
}

#[test]
fn the_auth_class_comes_from_the_challenge_header_only() {
    let bearer = row("/bearer");
    assert!(
        bearer.contains("auth=bearer"),
        "`WWW-Authenticate: Bearer` is bearer: {bearer}"
    );
    let ev = evidence("/bearer");
    assert!(
        ev.contains("auth<-WWW-Authenticate: Bearer realm=\"fixture\""),
        "the class must cite the header verbatim: {ev}"
    );

    let bare = row("/bare-401");
    assert!(
        bare.contains("auth=other(unspecified)"),
        "a 401 with no challenge is unspecified, not guessed: {bare}"
    );
    assert!(
        !bare.contains("auth=basic"),
        "a bare 401 must never be reported as basic: {bare}"
    );
    let ev = evidence("/bare-401");
    assert!(
        ev.contains("401 with no WWW-Authenticate"),
        "the absence must be stated as the ground: {ev}"
    );
}

#[test]
fn an_unlisted_host_is_refused_by_name_not_by_empty_data() {
    // No fixture server here on purpose: if the gate were bypassed, the probe to
    // 203.0.113.7 would fail as a transport error and this test would catch that instead
    // of a scope refusal.
    let (ok, stdout, stderr) = run_program("method_matrix_unauthorized.tl");
    assert!(
        !ok,
        "an unlisted target must not produce a matrix:\nstdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("count="),
        "no row may be printed for a refused target:\n{stdout}"
    );
    assert!(
        stderr.contains("api:method-matrix-scope"),
        "the refusal must carry the matrix's own code; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("scope:not-listed"),
        "the register's own code must be carried through; stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("api:method-matrix-net"),
        "a scope refusal must happen before the socket, not after a failed connect:\n{stderr}"
    );
}
