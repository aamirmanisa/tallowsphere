//! Page document methods, end to end through the interpreter.
//!
//! Drives `page.content()`, `page.set_content()`, `page.wait_for_function()`
//! and `page.wait_for_timeout()` from real `.tl` source, through the CLI, so
//! the test covers parser → typeck → policy annotations → interpreter →
//! `("Page", …)` dispatch → CDP. A Rust-level test would skip the dispatch,
//! which is the layer register #88 is about.
//!
//! Two things this pins beyond the four methods:
//!
//! * the DOM is read *after* scripts ran (`RENDERED-BY-JS`), not as the server
//!   sent it — the empty-body class of #106;
//! * `page.goto` reaches a loopback HTTP page at all. HTTPS Everywhere used to
//!   rewrite `http://127.0.0.1:PORT/` to `https://…`, so every local page came
//!   back as `chrome-error://chromewebdata/`, which reads like a network fault.
//!
//! `TALLOW_ALLOW_DIRECT=1` is mandatory for the same reason as in
//! `nav_direct.rs`: the browser zone routes loopback through SOCKS by design
//! (SSRF lockdown) and Tor refuses loopback destinations.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

const PAGE: &str = "<!doctype html><html><head><title>page-methods</title></head>\
<body><div id=\"app\">loading</div>\
<script>document.getElementById(\"app\").textContent=\"RENDERED-BY-JS\";</script>\
</body></html>";

fn serve(body: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
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
        r#"@cra_class(.default)
@legal(basis: .research, purpose: "local loopback page-method test; no external egress", personal_data: false)
@persona(id: "pagemethods-test", cover_class: .researcher, compartment: "pagemethods", fingerprint_seed: "pagemethods-test-1018")
@burn_plan(persona: "pagemethods-test", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowPageMethodsTest/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("{url}")
    print("URL=" + page.url())
    print("CONTENT=" + page.content())
    print("SET=" + page.set_content("<h1 id='replaced'>REPLACED-BY-SET-CONTENT</h1>"))
    print("AFTER=" + page.content())
    print("WAITFN=" + page.wait_for_function("document.getElementById('replaced') !== null", 2000))
    print("TIMEOUT=" + page.wait_for_timeout(120))
    browser.close()
}}
"#
    )
}

#[test]
fn page_document_methods_work_from_tallow_source() {
    let port = serve(PAGE);
    let url = format!("http://127.0.0.1:{port}/");
    let path = std::env::temp_dir().join(format!("tallow-pagemethods-{}.tl", std::process::id()));
    std::fs::write(&path, program(&url)).expect("write program");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["run", "--interpret", path.to_str().unwrap()])
        .env("TALLOW_ALLOW_DIRECT", "1")
        .env("TALLOW_NO_STEALTH", "1")
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "program failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // The URL the browser actually loaded, not the one requested: a forced
    // https:// upgrade shows up here as chrome-error://chromewebdata/.
    assert!(
        stdout.contains(&format!("URL=http://127.0.0.1:{port}/")),
        "goto did not land on the loopback page:\n{stdout}"
    );
    assert!(
        stdout.contains("RENDERED-BY-JS"),
        "content() did not return the post-script DOM:\n{stdout}"
    );
    assert!(
        stdout.contains("loaded: true") && stdout.contains("content_length: 46"),
        "set_content() did not report what it wrote:\n{stdout}"
    );
    assert!(
        stdout.contains("REPLACED-BY-SET-CONTENT"),
        "content() after set_content() did not see the new document:\n{stdout}"
    );
    assert!(
        stdout.contains("WaitResult { result: true"),
        "wait_for_function() did not resolve true:\n{stdout}"
    );
    // The sleep reports what elapsed, not what was requested.
    assert!(
        stdout.contains("waited_ms: 120"),
        "wait_for_timeout() did not report its request:\n{stdout}"
    );
    for broken in ["undefined function", "invalid page handle", "chrome-error://"] {
        assert!(!stdout.contains(broken), "output contains {broken}:\n{stdout}");
    }
}
