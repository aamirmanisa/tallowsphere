//! Array length and element identity must be right at N = 0, 1 and 3.
//!
//! Every earlier probe used exactly one element, where a length that returns 1 for
//! any non-empty array is indistinguishable from a correct one. N=2 caught the
//! `.len`-as-`strlen` class of bug once; this pins the three boundary sizes at
//! once, and checks the elements, not just the count — a length can be right while
//! the slots are shifted by the count prefix.

use std::io::{Read, Write};
use std::net::TcpListener;

const PAGE: &str = "<!doctype html><html><head><title>n</title></head><body>\
<a class=\"hit\" id=\"a1\">one</a>\
<a class=\"hit\" id=\"a2\">two</a>\
<a class=\"hit\" id=\"a3\">three</a>\
<a id=\"only\">single</a>\
</body></html>";

fn program(url: &str, interp: bool) -> String {
    // Both planes yield the array itself, so one program serves both legs.
    // This test used to carry two variants: the interpreter needed
    // `match { Ok(v) -> v … }` because `query_selector_all` wrapped its result,
    // while the compiled plane indexed the bare array directly. The wrapper was
    // the defect (it also made `query_selector_all(sel).len` report 0 at N=1),
    // so the asymmetry — and the second variant — are gone.
    let body = r##"    print(page.query_selector_all(".missing").len)
    print(page.query_selector_all("#only").len)
    let all = page.query_selector_all(".hit")
    print(all.len)
    print(all[0].text())
    print(all[2].text())"##;
    let body = body.replace("{url}", url);
    format!(
        r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "array parity n=0/1/3", personal_data: false)
@persona(id: "arrn", cover_class: .researcher, compartment: "arrn", fingerprint_seed: "arrn-1020")
@burn_plan(persona: "arrn", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowArrN/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("{url}")
{body}
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

fn run(flag: &str, source: &str, tag: &str) -> Vec<String> {
    let path = std::env::temp_dir().join(format!("tallow-arrn-{}-{tag}.tl", std::process::id()));
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
fn query_selector_all_is_correct_at_zero_one_and_three() {
    let port = serve();
    let url = format!("http://127.0.0.1:{port}/");

    let native = run("--require-native", &program(&url, false), "native");
    let interp = run("--interpret", &program(&url, true), "interp");

    assert_eq!(native, interp, "planes disagree:\nnative={native:?}\ninterp={interp:?}");
    assert_eq!(
        native,
        vec!["0", "1", "3", "Ok(\"one\")", "Ok(\"three\")"],
        "length or element contents wrong at N=0/1/3"
    );
}
