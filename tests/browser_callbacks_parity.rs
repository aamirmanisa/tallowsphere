//! Callback delivery on both planes: `on_console` and `expose_binding`.
//!
//! Both legs must produce the same bytes. The interesting part is *when* the
//! handler runs: generated code pumps at the head of every `Page` call, exactly
//! where the interpreter's `pump_page_handlers` runs, so a page event fired
//! between two calls is delivered before the second one.
//!
//! Run with `TALLOW_ALLOW_DIRECT=1` (loopback through SOCKS is refused by Tor).

use std::io::{Read, Write};
use std::net::TcpListener;

const PAGE: &str = "<!doctype html><html><head><title>cb</title></head><body>cb</body>\
<script>\
setTimeout(function(){ console.log('cb-marker') }, 200);\
setTimeout(function(){ if (typeof note === 'function') { note('from-js') } }, 250);\
</script></html>";

const HANDLERS: &str = r#"
fn on_console_ev(e: PageEvent) {
    print(e.kind)
    print(e.payload)
}

fn on_binding_ev(e: PageEvent) {
    print(e.kind)
    print(e.payload)
}
"#;

/// Native leg: direct field access (Ok/Err matching is not available natively).
fn native_program(url: &str) -> String {
    format!(
        r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "callback parity on loopback", personal_data: false)
@persona(id: "cb-parity", cover_class: .researcher, compartment: "cbparity", fingerprint_seed: "cb-parity-1020")
@burn_plan(persona: "cb-parity", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowCbParity/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    let listener = page.on_console("on_console_ev")
    print(listener.kind)
    let binding = page.expose_binding("note", "on_binding_ev")
    print(binding.name)
    page.goto("{url}")
    page.wait_for_timeout(900)
    let t = page.title()
    print("after-wait")
    page.close()
    browser.close()
}}
{HANDLERS}"#
    )
}

/// Interpreter leg: the same program, with Result matching where the native
/// plane must use direct access.
fn interp_program(url: &str) -> String {
    format!(
        r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "callback parity on loopback", personal_data: false)
@persona(id: "cb-parity", cover_class: .researcher, compartment: "cbparity", fingerprint_seed: "cb-parity-1020")
@burn_plan(persona: "cb-parity", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowCbParity/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.on_console("on_console_ev") match {{
        Ok(listener) -> print(listener.kind)
        Err(e) -> print(e)
    }}
    page.expose_binding("note", "on_binding_ev") match {{
        Ok(binding) -> print(binding.name)
        Err(e) -> print(e)
    }}
    page.goto("{url}")
    page.wait_for_timeout(900)
    print(page.title() match {{
        Ok(t) -> "after-wait"
        Err(e) -> e
    }})
    page.close()
    browser.close()
}}
{HANDLERS}"#
    )
}

fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                PAGE.len(),
                PAGE
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}


/// Blank the fields a CDP payload cannot keep stable across two runs: the
/// `scriptId` (the interpreter and the compiled program inject different script
/// ids) and the event `timestamp`. Both may arrive quoted or bare, so the scan
/// swallows an optional quote on each side. Everything else must match.
fn normalize_volatile(stdout: &str) -> String {
    let mut out = String::new();
    for line in stdout.lines() {
        let mut line = line.to_string();
        for key in ["\"scriptId\":", "\"timestamp\":"] {
            if let Some(at) = line.find(key) {
                let mut start = at + key.len();
                let bytes = line.as_bytes();
                if start < bytes.len() && bytes[start] == b'"' {
                    start += 1;
                }
                let mut end = start;
                while end < bytes.len()
                    && (bytes[end].is_ascii_digit()
                        || bytes[end] == b'.'
                        || bytes[end] == b'-'
                        || bytes[end] == b'+')
                {
                    end += 1;
                }
                if end < bytes.len() && bytes[end] == b'"' {
                    end += 1;
                }
                if end > start {
                    line.replace_range(start..end, "N");
                }
            }
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

fn run(flag: &str, program: &str, tag: &str) -> String {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "tallow-cb-parity-{}-{tag}.tl",
        std::process::id()
    ));
    std::fs::write(&path, program).expect("write program");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(flag)
        .arg(&path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(out.status.success(), "{tag} leg failed:\n{stdout}\n{stderr}");
    assert!(
        !stderr.contains("native build unavailable"),
        "{tag} leg fell back to the interpreter:\n{stderr}"
    );
    stdout
}

#[test]
fn console_and_binding_handlers_deliver_the_same_bytes_on_both_planes() {
    let port = serve();
    let url = format!("http://127.0.0.1:{port}/");

    let native = run("--require-native", &native_program(&url), "native");
    let interp = run("--interpret", &interp_program(&url), "interp");

    let (native_norm, interp_norm) = (normalize_volatile(&native), normalize_volatile(&interp));
    assert_eq!(
        native_norm, interp_norm,
        "the planes disagree:\n--- native ---\n{native_norm}\n--- interp ---\n{interp_norm}"
    );
    // Receipts, then one console event, then one binding event, then the marker.
    assert!(
        native.contains("console") && native.contains("cb-marker"),
        "the console handler never ran:\n{native}"
    );
    assert!(
        native.contains("binding") && native.contains("from-js"),
        "the binding handler never ran:\n{native}"
    );
    assert!(
        native.trim_end().ends_with("after-wait"),
        "handler output must precede the following statement:\n{native}"
    );
}
