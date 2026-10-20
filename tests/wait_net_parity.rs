//! `Page.wait_for_response` — the `found = true` path (#120 follow-up).
//!
//! The earlier probes could only prove the shape of the result, because a wait
//! issued after `goto` always misses events that arrived during the load. This
//! harness makes the event arrive *after* the wait is already blocking: the page
//! schedules a `fetch()` on a timer, the browser keeps running while the native
//! wait blocks, and the response lands inside the wait window.
//!
//! Run with `TALLOW_ALLOW_DIRECT=1` (loopback through SOCKS is refused by Tor).

use std::io::{Read, Write};
use std::net::TcpListener;

const WAIT_RESPONSE: &str = r#"page.wait_for_response("*slow.txt*", 8000)"#;
const WAIT_REQUEST: &str = r#"page.wait_for_request("*slow.txt*", 8000)"#;
const WAIT_EVENT: &str = r#"page.wait_for_event("Network.requestWillBeSent", 8000)"#;

const PAGE: &str = "<!doctype html><html><head><title>slow-fetch</title></head><body>\
<script>setTimeout(function(){ fetch('/slow.txt') }, 2500)</script>\
</body></html>";

fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let req = String::from_utf8_lossy(&buf);
            let (body, delay_ms): (&str, u64) = if req.starts_with("GET /slow.txt") {
                ("slow-body", 300)
            } else {
                (PAGE, 0)
            };
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

fn program(url: &str, wait_call: &str) -> String {
    format!(
        r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "wait_for_response true path on loopback", personal_data: false)
@persona(id: "wait-net", cover_class: .researcher, compartment: "waitnet", fingerprint_seed: "wait-net-1019")
@burn_plan(persona: "wait-net", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowWaitNet/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("{url}")
    let r = {wait_call}
    print(r.result)
    print(r.received)
    print(r.url)
    print(r.method)
    print(r.status)
    print(r.event)
    page.close()
    browser.close()
}}
"#
    )
}

fn run_against_delayed_fetch(wait_call: &str) -> Vec<String> {
    let port = serve();
    let url = format!("http://127.0.0.1:{port}/");
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "tallow-waitnet-{}-{}.tl",
        std::process::id(),
        wait_call.len()
    ));
    std::fs::write(&path, program(&url, wait_call)).expect("write program");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg("--require-native")
        .arg(&path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(out.status.success(), "native run failed:\n{stdout}\n{stderr}");
    assert!(
        !stderr.contains("native build unavailable"),
        "native leg fell back to the interpreter:\n{stderr}"
    );
    let lines: Vec<String> = stdout.lines().map(|l| l.trim().to_string()).collect();
    assert_eq!(
        lines.len(),
        6,
        "expected result/received/url/method/status/event, got:\n{stdout}"
    );
    assert_eq!(
        lines[0], "true",
        "the wait missed an event that arrived while it was blocking:\n{stdout}"
    );
    lines
}

#[test]
fn wait_for_response_sees_a_request_the_page_makes_after_load() {
    // The interpreter's `wait_result_fields` for a response wait sets both
    // `url` and `received` (the observed bool) and leaves the rest nil.
    let lines = run_against_delayed_fetch(WAIT_RESPONSE);
    assert!(
        lines[2].contains("slow.txt"),
        "the matched URL was not reported: {lines:?}"
    );
    assert_eq!(lines[1], "true", "wait_for_response must set received");
    assert_eq!(lines[3], "nil", "method is not part of a response wait");
    assert_eq!(lines[4], "nil", "status is not part of a response wait");
    assert_eq!(lines[5], "nil", "event is not part of a response wait");
}

#[test]
fn wait_for_request_sees_a_request_the_page_makes_after_load() {
    // A request wait reports `url` and leaves `received` absent — it used to
    // write the URL into that `bool?` slot.
    let lines = run_against_delayed_fetch(WAIT_REQUEST);
    assert!(
        lines[2].contains("slow.txt"),
        "the matched URL was not reported: {lines:?}"
    );
    assert_eq!(lines[1], "nil", "received must stay absent on a request wait");
    assert_eq!(lines[3], "nil", "method is not part of a request wait");
    assert_eq!(lines[5], "nil", "event is not part of a request wait");
}

#[test]
fn wait_for_event_sees_an_event_the_page_causes_after_load() {
    // `event` carries the event's *name*; it used to be filled into `received`
    // and `method` as well.
    let lines = run_against_delayed_fetch(WAIT_EVENT);
    assert_eq!(
        lines[5], "Network.requestWillBeSent",
        "the event name must land in `event`: {lines:?}"
    );
    assert_eq!(lines[1], "nil", "received must stay absent on an event wait");
    assert_eq!(lines[2], "nil", "url must stay absent on an event wait");
    assert_eq!(lines[3], "nil", "method must stay absent on an event wait");
}
