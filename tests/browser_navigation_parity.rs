//! Navigation and scroll methods must behave identically on both planes.
//!
//! `go_back`, `go_forward`, `scroll_by` and `scroll_to_bottom` were named by no test
//! anywhere in the tree. History is observable through `url()`, so this asserts
//! values rather than exit codes: after the round trip the URL must be the one the
//! browser actually landed on, on both planes.

use std::io::{Read, Write};
use std::net::TcpListener;

fn page(title: &str) -> String {
    format!(
        "<!doctype html><html><head><title>{title}</title></head><body>\
<div style=\"height:4000px\">tall</div><div id=\"bottom\">end</div></body></html>"
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
            let req = String::from_utf8_lossy(&buf).to_string();
            let body = if req.contains("/second") {
                page("second")
            } else {
                page("first")
            };
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

fn program(base: &str) -> String {
    format!(
        r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "navigation parity", personal_data: false)
@persona(id: "navp", cover_class: .researcher, compartment: "navp", fingerprint_seed: "navp-1020")
@burn_plan(persona: "navp", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowNavP/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("{base}/first")
    print(page.url())
    page.goto("{base}/second")
    print(page.url())
    page.go_back()
    print(page.url())
    page.go_forward()
    print(page.url())
    page.scroll_by(0.0, 120.0)
    page.scroll_to_bottom()
    print("scrolled")
    page.close()
    browser.close()
}}
"#
    )
}

fn run(flag: &str, source: &str, tag: &str) -> Vec<String> {
    let path = std::env::temp_dir().join(format!("tallow-navp-{}-{tag}.tl", std::process::id()));
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
fn navigation_and_scroll_agree_across_engines() {
    let port = serve();
    let base = format!("http://127.0.0.1:{port}");

    let native = run("--require-native", &program(&base), "native");
    let interp = run("--interpret", &program(&base), "interp");

    assert_eq!(native, interp, "planes disagree:\nnative={native:?}\ninterp={interp:?}");
    assert_eq!(native.len(), 5, "expected 5 lines, got {native:?}");
    // `url()` is Result<String>, so the printed line is `Ok("…")`; match the path
    // inside rather than pretending it is a bare string.
    assert!(native[0].contains("/first"), "first URL: {:?}", native[0]);
    assert!(native[1].contains("/second"), "second URL: {:?}", native[1]);
    assert!(native[2].contains("/first"), "back must return to /first: {:?}", native[2]);
    assert!(native[3].contains("/second"), "forward must return to /second: {:?}", native[3]);
    assert_eq!(native[4], "scrolled");
}
