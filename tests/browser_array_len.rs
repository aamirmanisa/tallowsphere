//! Native arrays must report the true length above N=1.
//!
//! Every earlier array probe used exactly one element (one cookie, one console
//! event, one egress step). At N=1 a broken length — returning 1 for any
//! non-empty array — is indistinguishable from a correct one. This test makes
//! the page emit TWO console events and requires `drain_events(...).len == 2` on
//! both planes.

use std::io::{Read, Write};
use std::net::TcpListener;

const PAGE: &str = "<!doctype html><html><head><title>two</title></head><body>two</body>\
<script>\
setTimeout(function(){ console.log('first-event') }, 150);\
setTimeout(function(){ console.log('second-event') }, 250);\
</script></html>";

fn program(url: &str, interp: bool) -> String {
    let capture = if interp {
        r#"    page.capture_console() match {
        Ok(c) -> print(c)
        Err(e) -> print(e)
    }"#
    } else {
        "    let cap = page.capture_console()"
    };
    format!(
        r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "array length at N=2", personal_data: false)
@persona(id: "drain2", cover_class: .researcher, compartment: "drain2", fingerprint_seed: "drain2-1020")
@burn_plan(persona: "drain2", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowDrain2/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
{capture}
    page.goto("{url}")
    page.wait_for_timeout(900)
    let evs = page.drain_events("console")
    print(evs.len)
    page.close()
    browser.close()
}}
"#
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

fn run(flag: &str, source: &str, tag: &str) -> String {
    let path = std::env::temp_dir().join(format!("tallow-arrlen-{}-{tag}.tl", std::process::id()));
    std::fs::write(&path, source).expect("write program");
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
        "{tag} leg refused the build:\n{stderr}"
    );
    stdout
}

#[test]
fn drain_events_len_is_two_on_both_planes() {
    let port = serve();
    let url = format!("http://127.0.0.1:{port}/");

    let native = run("--require-native", &program(&url, false), "native");
    let interp = run("--interpret", &program(&url, true), "interp");

    // The interp leg prints capture_console's `true` first.
    let interp_last = interp.lines().last().unwrap_or_default().trim();
    assert_eq!(
        native.trim(),
        "2",
        "native array length is wrong at N=2:\n{native}"
    );
    assert_eq!(
        interp_last, "2",
        "interpreter array length is wrong at N=2:\n{interp}"
    );
}
