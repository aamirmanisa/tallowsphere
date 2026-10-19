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

const PAGE: &str = "<!doctype html><html><head><title>slow-fetch</title></head><body>\
<script>setTimeout(function(){ fetch('/slow.txt') }, 400)</script>\
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

fn program(url: &str) -> String {
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
    let r = page.wait_for_response("slow.txt", 8000)
    print(r.result)
    print(r.url)
    page.close()
    browser.close()
}}
"#
    )
}

// Known gap, measured: the native leg misses the event and prints false even
// though the fetch is made while the wait is blocking. The likely cause is the
// #105 class of bug — the CDP read loop is spawned on one runtime while the FFI
// blocks on another, so replies never route. The interpreter leg cannot be
// compared directly here (it needs `match`), so this stays ignored until the
// runtime ownership is fixed; a green run of this test is the acceptance
// criterion for that fix.
#[ignore = "native wait_for_response misses events that arrive while it blocks (#120 follow-up)"]
#[test]
fn wait_for_response_sees_a_request_the_page_makes_after_load() {
    let port = serve();
    let url = format!("http://127.0.0.1:{port}/");
    let dir = std::env::temp_dir();
    let path = dir.join(format!("tallow-waitnet-{}.tl", std::process::id()));
    std::fs::write(&path, program(&url)).expect("write program");

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
    assert!(
        stdout.starts_with("true\n"),
        "the wait missed an event that arrived while it was blocking:\n{stdout}"
    );
    assert!(
        stdout.contains("slow.txt"),
        "the matched URL was not reported:\n{stdout}"
    );
}
