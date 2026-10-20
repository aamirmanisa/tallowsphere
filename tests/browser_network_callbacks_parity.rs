//! `on_request` and `on_response` must deliver events identically on both planes.
//!
//! Neither method was named by any test. Handlers are registered by name (the
//! callback ABI never re-enters compiled code), and the assertion is on the marker
//! lines the handlers print — so a plane that silently drops the registration
//! produces a different stdout rather than an error nobody reads.

use std::io::{Read, Write};
use std::net::TcpListener;

const PAGE: &str = "<!doctype html><html><head><title>net</title></head><body>\
<img src=\"/pixel.png\" alt=\"\"><p>body</p></body></html>";

fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let req = String::from_utf8_lossy(&buf).to_string();
            let (ctype, body) = if req.contains("pixel.png") {
                ("image/png", String::new())
            } else {
                ("text/html; charset=utf-8", PAGE.to_string())
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

const HANDLERS: &str = r#"
fn on_req_ev(e: PageEvent) {
    print("req-event")
}

fn on_resp_ev(e: PageEvent) {
    print("resp-event")
}
"#;

fn native_program(url: &str) -> String {
    format!(
        r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "network callback parity on loopback", personal_data: false)
@persona(id: "netcb", cover_class: .researcher, compartment: "netcb", fingerprint_seed: "netcb-1020")
@burn_plan(persona: "netcb", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowNetCb/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    let listener = page.on_request("on_req_ev")
    print(listener.kind)
    let listener2 = page.on_response("on_resp_ev")
    print(listener2.kind)
    page.goto("{url}")
    page.wait_for_timeout(900)
    print("after-wait")
    page.close()
    browser.close()
}}
{HANDLERS}"#
    )
}

fn interp_program(url: &str) -> String {
    format!(
        r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "network callback parity on loopback", personal_data: false)
@persona(id: "netcb", cover_class: .researcher, compartment: "netcb", fingerprint_seed: "netcb-1020")
@burn_plan(persona: "netcb", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowNetCb/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.on_request("on_req_ev") match {{
        Ok(listener) -> print(listener.kind)
        Err(e) -> print(e)
    }}
    page.on_response("on_resp_ev") match {{
        Ok(listener) -> print(listener.kind)
        Err(e) -> print(e)
    }}
    page.goto("{url}")
    page.wait_for_timeout(900)
    print("after-wait")
    page.close()
    browser.close()
}}
{HANDLERS}"#
    )
}

fn run(flag: &str, source: &str, tag: &str) -> Vec<String> {
    let path = std::env::temp_dir().join(format!("tallow-netcb-{}-{tag}.tl", std::process::id()));
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
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("* running in the interpreter"))
        .map(str::to_string)
        .collect()
}

#[test]
fn request_and_response_callbacks_fire_on_both_planes() {
    let port = serve();
    let url = format!("http://127.0.0.1:{port}/");

    let native = run("--require-native", &native_program(&url), "native");
    let interp = run("--interpret", &interp_program(&url), "interp");

    assert_eq!(native, interp, "planes disagree:\nnative={native:?}\ninterp={interp:?}");
    assert!(
        native.iter().any(|l| l.contains("req-event")),
        "on_request never fired: {native:?}"
    );
    assert!(
        native.iter().any(|l| l.contains("resp-event")),
        "on_response never fired: {native:?}"
    );
    assert_eq!(native.last().map(String::as_str), Some("after-wait"));
}
