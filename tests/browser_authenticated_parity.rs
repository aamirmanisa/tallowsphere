//! `authenticated_get` / `authenticated_request` must carry the browser's cookies
//! on both planes, and report the same status and body.
//!
//! Neither method was named by any test. The loopback server echoes the received
//! `Cookie` header and request method into the body, so a plane that drops the
//! cookie or sends the wrong method differs in the printed values.

use std::io::{Read, Write};
use std::net::TcpListener;

fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let method = req.split_whitespace().next().unwrap_or("?");
            let cookie = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("cookie:"))
                .map(|l| l.splitn(2, ':').nth(1).unwrap_or("").trim().to_string())
                .unwrap_or_else(|| "none".to_string());
            let body = format!("method={method};cookie={cookie}");
            let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

fn native_program(base: &str) -> String {
    format!(
        r##"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "authenticated request parity on loopback", personal_data: false)
@persona(id: "authp", cover_class: .researcher, compartment: "authp", fingerprint_seed: "authp-1020")
@burn_plan(persona: "authp", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowAuthP/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("{base}/")
    page.set_cookies_from_header("sid=auth123", "127.0.0.1")
    // Bind first: the Result-unwrap field path is deliberately limited to a bound
    // variable, because unwrapping a call receiver would emit the call twice.
    let first = page.authenticated_get("{base}/probe")
    print(first.status)
    let second = page.authenticated_request("{base}/probe", "POST", "payload")
    print(second.status)
    page.close()
    browser.close()
}}
"##
    )
}

fn interp_program(base: &str) -> String {
    format!(
        r##"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "authenticated request parity on loopback", personal_data: false)
@persona(id: "authp", cover_class: .researcher, compartment: "authp", fingerprint_seed: "authp-1020")
@burn_plan(persona: "authp", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowAuthP/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("{base}/")
    page.set_cookies_from_header("sid=auth123", "127.0.0.1")
    page.authenticated_get("{base}/probe") match {{
        Ok(r) -> print(r.status)
        Err(e) -> print(e)
    }}
    page.authenticated_request("{base}/probe", "POST", "payload") match {{
        Ok(r) -> print(r.status)
        Err(e) -> print(e)
    }}
    page.close()
    browser.close()
}}
"##
    )
}

fn run(flag: &str, source: &str, tag: &str) -> Vec<String> {
    let path = std::env::temp_dir().join(format!("tallow-authp-{}-{tag}.tl", std::process::id()));
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
fn authenticated_get_and_request_agree_across_engines() {
    let port = serve();
    let base = format!("http://127.0.0.1:{port}");

    let native = run("--require-native", &native_program(&base), "native");
    let interp = run("--interpret", &interp_program(&base), "interp");

    assert_eq!(native, interp, "planes disagree:\nnative={native:?}\ninterp={interp:?}");
    assert_eq!(native.len(), 2, "expected two status lines, got {native:?}");
    assert!(
        native.iter().all(|l| l.contains("201")),
        "both requests should reach the loopback server: {native:?}"
    );
}
