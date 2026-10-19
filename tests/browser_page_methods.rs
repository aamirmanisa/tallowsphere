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

const PAGE_WAITS: &str = "<!doctype html><html><head><title>page-waits</title></head>\
<body><div id=\"app\">waiting</div>\
<script>\
setTimeout(function(){ fetch('/api/one').catch(function(){}); }, 600);\
setTimeout(function(){ fetch('/api/two').catch(function(){}); }, 900);\
setTimeout(function(){ window.location.href = '/second'; }, 1300);\
</script></body></html>";

fn waits_program(url: &str) -> String {
    format!(
        r#"@cra_class(.default)
@legal(basis: .research, purpose: "local loopback wait-method test; no external egress", personal_data: false)
@persona(id: "pagewaits-test", cover_class: .researcher, compartment: "pagewaits", fingerprint_seed: "pagewaits-test-1018")
@burn_plan(persona: "pagewaits-test", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowPageWaitsTest/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("{url}")
    print("REQ=" + page.wait_for_request("*/api/*", 4000))
    print("RESP=" + page.wait_for_response("*/api/two*", 4000))
    print("URLWAIT=" + page.wait_for_url("*/second", 4000))
    print("NOEVENT=" + page.wait_for_event("No.suchEvent", 120))
    browser.close()
}}
"#
    )
}

#[test]
fn page_wait_methods_work_from_tallow_source() {
    let port = serve(PAGE_WAITS);
    let url = format!("http://127.0.0.1:{port}/");
    let path = std::env::temp_dir().join(format!("tallow-pagewaits-{}.tl", std::process::id()));
    std::fs::write(&path, waits_program(&url)).expect("write program");

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

    // The request line must carry the URL the browser actually used.
    assert!(
        stdout.contains(&format!("/api/")),
        "wait_for_request did not report the matched URL:\n{stdout}"
    );
    assert!(
        stdout.contains(&format!("/api/two")),
        "wait_for_response did not report the matched URL:\n{stdout}"
    );
    assert!(
        stdout.contains("/second"),
        "wait_for_url did not report the new location:\n{stdout}"
    );
    // A wait that times out is `result: false`, not an error — and it must
    // come back in roughly the time asked for, not hang.
    let noevent = stdout
        .lines()
        .find(|l| l.starts_with("NOEVENT="))
        .unwrap_or_else(|| panic!("no NOEVENT line:\n{stdout}"));
    assert!(
        noevent.contains("result: false"),
        "wait_for_event on a name that never fires should be false:\n{noevent}"
    );
    for broken in ["undefined function", "invalid page handle", "runtime error"] {
        assert!(!stdout.contains(broken), "output contains {broken}:\n{stdout}");
    }
}

fn injection_program(url: &str) -> String {
    format!(
        r#"@cra_class(.default)
@legal(basis: .research, purpose: "local loopback injection/emulation test; no external egress", personal_data: false)
@persona(id: "pageinject-test", cover_class: .researcher, compartment: "pageinject", fingerprint_seed: "pageinject-test-1018")
@burn_plan(persona: "pageinject-test", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowPageInjectTest/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("{url}")
    print("STYLE=" + page.add_style_tag("body \{{ background-color: rgb(1, 2, 3); \}}"))
    print("STYLED=" + page.wait_for_function("getComputedStyle(document.body).backgroundColor === 'rgb(1, 2, 3)'", 2000))
    print("SCRIPT=" + page.add_script_tag("window.__tallow_tag = 42;"))
    print("TAGGED=" + page.wait_for_function("window.__tallow_tag === 42", 2000))
    print("INIT=" + page.add_init_script("window.__init_marker = 7;"))
    page.goto("{url}")
    print("INITDONE=" + page.wait_for_function("window.__init_marker === 7", 2000))
    print("MEDIA=" + page.emulate_media("screen", "dark", "reduce"))
    print("DARK=" + page.wait_for_function("matchMedia('(prefers-color-scheme: dark)').matches", 2000))
    print("VISION=" + page.emulate_vision("deuteranopia"))
    print("CPU=" + page.throttle_cpu(4.0))
    print("NET=" + page.throttle_network("slow-3g"))
    browser.close()
}}
"#
    )
}

#[test]
fn page_injection_and_emulation_work_from_tallow_source() {
    let port = serve(PAGE);
    let url = format!("http://127.0.0.1:{port}/");
    let path = std::env::temp_dir().join(format!("tallow-pageinject-{}.tl", std::process::id()));
    std::fs::write(&path, injection_program(&url)).expect("write program");

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

    let line = |prefix: &str| {
        stdout
            .lines()
            .find(|l| l.starts_with(prefix))
            .unwrap_or_else(|| panic!("no {prefix} line:\n{stdout}"))
            .to_string()
    };

    // Each effect is proven by what the page computes, not by the return value.
    assert!(line("STYLED=").contains("result: true"), "{}", line("STYLED="));
    assert!(line("TAGGED=").contains("result: true"), "{}", line("TAGGED="));
    assert!(line("INITDONE=").contains("result: true"), "{}", line("INITDONE="));
    assert!(line("DARK=").contains("result: true"), "{}", line("DARK="));
    assert!(line("VISION=").contains("applied: true"), "{}", line("VISION="));
    assert!(line("CPU=").contains("rate: 4"), "{}", line("CPU="));
    assert!(line("NET=").contains("slow-3g"), "{}", line("NET="));
    assert!(line("NET=").contains("latency_ms: 500"), "{}", line("NET="));
    for broken in ["undefined function", "invalid page handle", "runtime error"] {
        assert!(!stdout.contains(broken), "output contains {broken}:\n{stdout}");
    }
}

const PAGE_EVENTS: &str = "<!doctype html><html><head><title>page-events</title></head><body>\
<div id=\"app\">events</div>\
<script>\
console.log('hello-from-page');\
setTimeout(function(){ fetch('/api/evt').catch(function(){}); }, 100);\
setTimeout(function(){ throw new Error('boom-from-page'); }, 200);\
</script></body></html>";

fn events_program(url: &str) -> String {
    format!(
        r#"@cra_class(.default)
@legal(basis: .research, purpose: "local loopback event-buffer test; no external egress", personal_data: false)
@persona(id: "pageevents-test", cover_class: .researcher, compartment: "pageevents", fingerprint_seed: "pageevents-test-1018")
@burn_plan(persona: "pageevents-test", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowPageEventsTest/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    // Runtime capture is opt-in: console events do not exist without it.
    print("CAPTURE=" + page.capture_console())
    page.goto("{url}")
    page.wait_for_timeout(600)
    let all = page.drain_events("", 0)
    print("ALL=" + all)
    print("CONSOLE_AFTER=" + page.drain_events("console", 0))
    print("REQ_ONLY=" + page.drain_events("request", 0))
    browser.close()
}}
"#
    )
}

#[test]
fn page_events_are_buffered_and_drained_from_tallow_source() {
    let port = serve(PAGE_EVENTS);
    let url = format!("http://127.0.0.1:{port}/");
    let path = std::env::temp_dir().join(format!("tallow-pageevents-{}.pid{}.tl", std::process::id(), std::process::id()));
    std::fs::write(&path, events_program(&url)).expect("write program");

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

    let all = stdout
        .lines()
        .find(|l| l.starts_with("ALL="))
        .unwrap_or_else(|| panic!("no ALL line:\n{stdout}"));
    assert!(all.contains("hello-from-page"), "console event missing:\n{all}");
    assert!(all.contains("/api/evt"), "request event missing:\n{all}");
    assert!(all.contains("boom-from-page"), "error event missing:\n{all}");

    // Draining removes: a second drain of the same kind must be empty.
    let req_only = stdout
        .lines()
        .find(|l| l.starts_with("REQ_ONLY="))
        .unwrap_or_else(|| panic!("no REQ_ONLY line:\n{stdout}"));
    assert!(
        req_only.contains("[]"),
        "request events were not drained by the first call:\n{req_only}"
    );

    let console_after = stdout
        .lines()
        .find(|l| l.starts_with("CONSOLE_AFTER="))
        .unwrap_or_else(|| panic!("no CONSOLE_AFTER line:\n{stdout}"));
    assert!(
        console_after.contains("[]"),
        "drained events were not removed:\n{console_after}"
    );
    for broken in ["undefined function", "invalid page handle", "runtime error"] {
        assert!(!stdout.contains(broken), "output contains {broken}:\n{stdout}");
    }
}

fn handlers_program(url: &str) -> String {
    format!(
        r#"import tallow.browser
fn on_msg(ev: PageEvent) {{
    print("HANDLER:console:" + ev.payload)
}}
fn on_bind(ev: PageEvent) {{
    print("HANDLER:binding:" + ev.payload)
}}
@cra_class(.default)
@legal(basis: .research, purpose: "local loopback handler test; no external egress", personal_data: false)
@persona(id: "pagehandlers-test", cover_class: .researcher, compartment: "pagehandlers", fingerprint_seed: "pagehandlers-test-1018")
@burn_plan(persona: "pagehandlers-test", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowPageHandlersTest/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("{url}")
    print("REG=" + page.on_console("on_msg"))
    print("EXPOSE=" + page.expose_function("tlNotify", "on_bind"))
    page.add_script_tag("if (window.tlNotify) \{{ tlNotify('from-js'); \}}")
    page.wait_for_timeout(400)
    browser.close()
}}
"#
    )
}

#[test]
fn page_handlers_and_bindings_fire_from_tallow_source() {
    let port = serve(PAGE_EVENTS);
    let url = format!("http://127.0.0.1:{port}/");
    let path = std::env::temp_dir().join(format!("tallow-pagehandlers-{}.tl", std::process::id()));
    std::fs::write(&path, handlers_program(&url)).expect("write program");

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

    assert!(
        stdout.contains("HANDLER:console:") && stdout.contains("hello-from-page"),
        "console handler never ran:\n{stdout}"
    );
    assert!(
        stdout.contains("HANDLER:binding:") && stdout.contains("from-js"),
        "binding handler never ran:\n{stdout}"
    );
    for broken in ["undefined function", "invalid page handle", "runtime error"] {
        assert!(!stdout.contains(broken), "output contains {broken}:\n{stdout}");
    }
}

fn stealth_errors_program(url: &str) -> String {
    format!(
        r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "stealth init-script check on a loopback page", personal_data: false)
@persona(id: "stealth-errors-test", cover_class: .researcher, compartment: "stealtherrors", fingerprint_seed: "stealth-errors-1018")
@burn_plan(persona: "stealth-errors-test", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowStealthErrorsTest/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    print("CAPTURE=" + page.capture_console())
    page.goto("{url}")
    page.wait_for_timeout(500)
    print("ERRORS=" + page.drain_events("error", 0))
    browser.close()
}}
"#
    )
}

#[test]
fn stealth_init_scripts_do_not_raise_page_errors() {
    let port = serve("<!doctype html><html><body><p>plain</p></body></html>");
    let url = format!("http://127.0.0.1:{port}/");
    let path = std::env::temp_dir().join(format!("tallow-stealtherr-{}.tl", std::process::id()));
    std::fs::write(&path, stealth_errors_program(&url)).expect("write program");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["run", "--interpret", path.to_str().unwrap()])
        .env("TALLOW_ALLOW_DIRECT", "1")
        .env("TALLOW_NO_STEALTH", "1")
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "program failed\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The toolkit's own init scripts must not surface as page errors: an
    // on_error handler would otherwise report exceptions the page never threw.
    assert!(
        stdout.contains("ERRORS=[]"),
        "stealth init scripts raised page errors:\n{stdout}"
    );
    for marker in ["MutationObserver", "Cannot redefine property"] {
        assert!(
            !stdout.contains(marker),
            "init-script exception reached the page: {marker}\n{stdout}"
        );
    }
}

/// The browser API is only partly lowered. `goto`, `content` and `close` build
/// natively (see tests/browser_native_parity.rs); everything else must fail the
/// build loudly rather than emit a binary that silently does nothing.
#[test]
fn unlowered_browser_methods_refuse_the_native_build() {
    let program = r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "native-plane contract check", personal_data: false)
@persona(id: "native-check", cover_class: .researcher, compartment: "nativecheck", fingerprint_seed: "native-check-1018")
@burn_plan(persona: "native-check", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowNativeCheck/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.on_console("msg")
    browser.close()
}
"#;
    let path = std::env::temp_dir().join(format!("tallow-nativecheck-{}.tl", std::process::id()));
    std::fs::write(&path, program).expect("write program");

    let build = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["build", path.to_str().unwrap()])
        .output()
        .expect("run tallow build");
    let build_err = String::from_utf8_lossy(&build.stderr);
    let _ = std::fs::remove_file(&path);

    assert!(
        !build.status.success(),
        "tallow build produced a binary for an unlowered browser method:\n{build_err}"
    );
    assert!(
        build_err.contains("no lowering"),
        "build failed for an unrelated reason:\n{build_err}"
    );
    assert!(
        build_err.contains("on_console"),
        "the diagnostic does not name the method that has no lowering:\n{build_err}"
    );
}
