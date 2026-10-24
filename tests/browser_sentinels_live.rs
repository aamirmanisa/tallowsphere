//! The sentinels against a live browser.
//!
//! Each of these fails if the corresponding element goes back to reporting
//! state instead of performing it:
//!
//! * `DeviceEmulator.set_viewport` — the page must actually report the new
//!   inner width, read back from the page itself, not from the struct returned.
//! * `DeviceEmulator.set_user_agent` — `navigator.userAgent` in the page must
//!   carry the marker.
//! * `NetworkInterceptor` — a blocked request must not reach the fixture server,
//!   proven by the server's own connection count rather than by the return value.
//! * `TraceRecorder` — stopping must produce a non-empty trace document on disk.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const PAGE: &str = "<!doctype html><html><head><title>sentinels</title></head>\
<body><p>ok</p></body></html>";

/// A fixture server that counts every connection it accepts.
fn serve(counter: Arc<AtomicUsize>, paths: Arc<Mutex<Vec<String>>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            counter.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            if let Some(line) = request.lines().next() {
                paths.lock().unwrap().push(line.to_string());
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                PAGE.len(),
                PAGE
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    port
}

fn run(source: &str, name: &str) -> (bool, String) {
    let dir = std::env::temp_dir().join(format!("sentinel-live-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let file = dir.join(format!("{name}.tl"));
    std::fs::write(&file, source).expect("write");
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(&file)
        .current_dir(&dir)
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

#[test]
fn emulation_reaches_the_page_and_is_read_back_from_it() {
    let counter = Arc::new(AtomicUsize::new(0));
    let paths = Arc::new(Mutex::new(Vec::new()));
    let port = serve(Arc::clone(&counter), Arc::clone(&paths));
    let src = format!(
        r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "browser sentinel integration", personal_data: false)
@persona(id: "sentinel", cover_class: .researcher, compartment: "sentinel", fingerprint_seed: "sentinel-1020")
@burn_plan(persona: "sentinel", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowSentinel/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let b = Browser.launch(true)
    let p = b.new_page()
    p.goto("http://127.0.0.1:{port}/")
    // The window size is the runner's, not ours: read it rather than assume it.
    // A CI runner opened at 800 wide made a hardcoded "1920" assertion fail for
    // a reason that had nothing to do with the emulation.
    let before = p.evaluate("document.documentElement.clientWidth")
    print(before)
    let vp = DeviceEmulator.set_viewport(800, 600, 1.0)
    print(vp.applied)
    print(p.evaluate("document.documentElement.clientWidth"))
    let ua = DeviceEmulator.set_user_agent("TallowSentinel/1.0")
    print(ua.applied)
    print(p.evaluate("navigator.userAgent"))
    DeviceEmulator.clear()
    print(p.evaluate("document.documentElement.clientWidth"))
    p.close()
    b.close()
}}
"#
    );
    let (ok, all) = run(&src, "emu");
    assert!(ok, "{all}");
    let lines: Vec<&str> = all.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let width = |v: &str| -> Option<i64> {
        v.strip_prefix("Ok(")?.strip_suffix(")")?.trim().parse::<i64>().ok()
    };
    let widths: Vec<i64> = lines.iter().filter_map(|l| width(l)).collect();
    assert!(lines.contains(&"true"), "applied must be true: {all}");
    assert!(
        lines.iter().any(|l| l.contains("TallowSentinel/1.0")),
        "navigator.userAgent must carry the marker: {all}"
    );
    // Three widths: before, during, after clear.
    assert_eq!(widths.len(), 3, "expected before/during/after widths: {all}");
    let (before, during, after) = (widths[0], widths[1], widths[2]);
    assert_eq!(during, 800, "the page must report an 800px layout viewport: {all}");
    assert_ne!(before, during, "the header must actually change the width: {all}");
    assert_eq!(
        after, before,
        "clear() must restore the width the page had before the override: {all}"
    );
}

#[test]
fn a_blocked_request_never_reaches_the_server() {
    let counter = Arc::new(AtomicUsize::new(0));
    let paths = Arc::new(Mutex::new(Vec::new()));
    let port = serve(Arc::clone(&counter), Arc::clone(&paths));
    let src = format!(
        r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "browser sentinel integration", personal_data: false)
@persona(id: "sentinel", cover_class: .researcher, compartment: "sentinel", fingerprint_seed: "sentinel-1020")
@burn_plan(persona: "sentinel", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowSentinel/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let b = Browser.launch(true)
    let p = b.new_page()
    p.goto("http://127.0.0.1:{port}/")
    let base = p.evaluate("document.title")
    print(base)
    let i = NetworkInterceptor.create()
    print(i.active)
    let blocked = NetworkInterceptor.block_pattern(i, "*blocked*")
    print(blocked.rule_count)
    let r = p.goto("http://127.0.0.1:{port}/blocked-page")
    print(r)
    p.close()
    b.close()
}}
"#
    );
    let (ok, all) = run(&src, "block");
    assert!(ok, "{all}");
    assert!(
        all.contains("sentinels"),
        "the first page must load normally: {all}"
    );
    assert!(
        all.contains("ERR_BLOCKED_BY_CLIENT"),
        "the blocked navigation must fail as blocked, not silently succeed: {all}"
    );
    // The fixture is the authority here, not the interceptor's return value:
    // whatever Chrome reports, the server must never have seen the request.
    let seen = paths.lock().unwrap().clone();
    assert!(
        !seen.iter().any(|p| p.contains("blocked-page")),
        "the blocked request reached the fixture server: {seen:?}"
    );
    assert!(
        seen.iter().any(|p| p.contains("GET / ")),
        "the control request must have reached the server: {seen:?}"
    );
}

#[test]
fn a_trace_is_written_to_disk_and_is_not_empty() {
    let counter = Arc::new(AtomicUsize::new(0));
    let paths = Arc::new(Mutex::new(Vec::new()));
    let port = serve(Arc::clone(&counter), Arc::clone(&paths));
    let src = format!(
        r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "browser sentinel integration", personal_data: false)
@persona(id: "sentinel", cover_class: .researcher, compartment: "sentinel", fingerprint_seed: "sentinel-1020")
@burn_plan(persona: "sentinel", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowSentinel/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let b = Browser.launch(true)
    let p = b.new_page()
    p.goto("http://127.0.0.1:{port}/")
    let t = TraceRecorder.start("live")
    print(t.recording)
    TraceRecorder.record_action(t, "click", "body")
    p.evaluate("1 + 1")
    let done = TraceRecorder.stop(t)
    print(done.action_count)
    print(done.network)
    p.close()
    b.close()
}}
"#
    );
    let (ok, all) = run(&src, "trace");
    assert!(ok, "{all}");
    assert!(all.contains("true"), "recording must start: {all}");
    // The trace path is printed in the `network` field by TraceRecorder.stop.
    let path = all
        .lines()
        .map(str::trim)
        .find(|l| l.contains(".tallow-traces"))
        .map(|l| l.trim_matches(|c| c == '"' || c == '[' || c == ']' || c == ','));
    // The collected-chunk count is the primary evidence; the file is the
    // artefact the caller keeps.
    let counts: Vec<i64> = all
        .lines()
        .map(str::trim)
        .filter_map(|l| l.parse::<i64>().ok())
        .collect();
    assert!(
        counts.iter().any(|c| *c > 0),
        "the trace must collect at least one chunk: {all}"
    );
    let path = path.unwrap_or_else(|| panic!("no trace path in output: {all}"));
    let body = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("trace {path}: {e}"));
    assert!(body.len() > 2, "trace document is empty: {body}");
    assert!(body.starts_with('['), "trace must be a JSON array: {body}");
}
