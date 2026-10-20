//! `get_cookies` must report its true length at N = 0, 1 and 3.
//!
//! It was previously unexercised. A cookie array is also the case where a wrong
//! length silently changes behaviour (a loop over cookies returns early) rather
//! than crashing. `Element.classes` has no lowering and is pinned as a refusal in
//! tests/browser_unlowered_gaps.rs.

use std::io::{Read, Write};
use std::net::TcpListener;

const PAGE: &str = "<!doctype html><html><head><title>c</title></head><body>\
<div id=\"c0\"></div><div id=\"c1\" class=\"a\"></div><div id=\"c3\" class=\"a b c\"></div>\
</body></html>";

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

fn program(url: &str) -> String {
    format!(
        r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "cookie/class array parity", personal_data: false)
@persona(id: "arrc", cover_class: .researcher, compartment: "arrc", fingerprint_seed: "arrc-1020")
@burn_plan(persona: "arrc", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowArrC/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("{url}")
    print(page.get_cookies().len)
    page.set_cookies_from_header("a=1", "127.0.0.1")
    print(page.get_cookies().len)
    page.set_cookies_from_header("a=1; b=2; c=3", "127.0.0.1")
    print(page.get_cookies().len)
    page.close()
    browser.close()
}}
"#
    )
}

fn run(flag: &str, source: &str, tag: &str) -> Vec<String> {
    let path = std::env::temp_dir().join(format!("tallow-arrc-{}-{tag}.tl", std::process::id()));
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
fn cookie_and_class_arrays_are_correct_at_zero_one_and_three() {
    let port = serve();
    let url = format!("http://127.0.0.1:{port}/");

    let native = run("--require-native", &program(&url), "native");
    let interp = run("--interpret", &program(&url), "interp");

    assert_eq!(native, interp, "planes disagree:\nnative={native:?}\ninterp={interp:?}");
    assert_eq!(
        native,
        vec!["0", "1", "3"],
        "cookie array lengths wrong at N=0/1/3"
    );
}
