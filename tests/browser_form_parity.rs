//! `wait_for_selector`, `fill` and `cookie_string` were named by no test.
//!
//! `fill` has no direct read-back method on Page, so it is proven through
//! `cookie_string`: a cookie set before filling must survive the form interaction
//! on both planes, and the printed cookie line must be identical.

use std::io::{Read, Write};
use std::net::TcpListener;

const FORM: &str = "<!doctype html><html><head><title>form</title></head><body>\
<form><input id=\"q\" name=\"q\" type=\"text\"></form></body></html>";

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
                FORM.len(),
                FORM
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

fn program(base: &str) -> String {
    format!(
        r##"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "form parity", personal_data: false)
@persona(id: "frmp", cover_class: .researcher, compartment: "frmp", fingerprint_seed: "frmp-1020")
@burn_plan(persona: "frmp", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowFrmP/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("{base}/form")
    page.wait_for_selector("#q")
    page.fill("#q", "hello world")
    page.set_cookies_from_header("sid=abc123", "127.0.0.1")
    print(page.cookie_string("{base}/form"))
    print(page.cookie_string("{base}/"))
    page.close()
    browser.close()
}}
"##
    , base = base)
}

fn run(flag: &str, source: &str, tag: &str) -> Vec<String> {
    let path = std::env::temp_dir().join(format!("tallow-frmp-{}-{tag}.tl", std::process::id()));
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
fn form_helpers_and_cookie_string_agree_across_engines() {
    let port = serve();
    let base = format!("http://127.0.0.1:{port}");

    let native = run("--require-native", &program(&base), "native");
    let interp = run("--interpret", &program(&base), "interp");

    assert_eq!(native, interp, "planes disagree:\nnative={native:?}\ninterp={interp:?}");
    assert_eq!(native.len(), 2, "expected 2 lines, got {native:?}");
    // cookie_string returns Result<String>; both planes print it as Ok("…"), so
    // assert on the cookie inside rather than requiring a match arm.
    assert!(
        native[0].contains("sid=abc123"),
        "cookie_string must see the cookie set before fill: {:?}",
        native[0]
    );
}
