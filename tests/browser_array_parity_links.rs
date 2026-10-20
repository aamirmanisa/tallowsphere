//! `extract_all_text` must report true lengths at
//! N = 0, 1 and 3, on both planes, with correct element contents.
//!
//! `query_selector_all` is covered separately. This lowering was previously
//! exercised only at N = 1 — the size at which a count-prefix bug and a correct
//! array are indistinguishable. `Page.links` is NOT here: it has no lowering and no
//! FFI, so it is pinned as a refusal in tests/browser_unlowered_gaps.rs instead.

use std::io::{Read, Write};
use std::net::TcpListener;

fn body(n: usize) -> String {
    let links = (1..=n)
        .map(|i| format!("<a class=\"hit\" href=\"/p{i}\">link{i}</a>"))
        .collect::<String>();
    format!(
        "<!doctype html><html><head><title>n{n}</title></head><body>{links}<p id=\"solo\">only</p></body></html>"
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
            let request = String::from_utf8_lossy(&buf).to_string();
            let n = if request.contains("/one") {
                1
            } else if request.contains("/three") {
                3
            } else {
                0
            };
            let page = body(n);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                page.len(),
                page
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

fn program(base: &str, interp: bool) -> String {
    let three = if interp {
        r#"    let all = page.extract_all_text(".hit") match { Ok(v) -> v Err(e) -> { print(e) Nil } }
    print(all.len)"#
    } else {
        r#"    let all = page.extract_all_text(".hit")
    print(all.len)"#
    };
    format!(
        r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "array parity across sizes", personal_data: false)
@persona(id: "arr3", cover_class: .researcher, compartment: "arr3", fingerprint_seed: "arr3-1020")
@burn_plan(persona: "arr3", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowArr3/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("{base}/none")
    print(page.extract_all_text(".hit").len)
    page.goto("{base}/one")
    print(page.extract_all_text(".hit").len)
    page.goto("{base}/three")
{three}
    print(all[0])
    print(all[2])
    page.close()
    browser.close()
}}
"#
    )
}

fn run(flag: &str, source: &str, tag: &str) -> Vec<String> {
    let path = std::env::temp_dir().join(format!("tallow-arr3-{}-{tag}.tl", std::process::id()));
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
fn string_array_parity_at_zero_one_and_three() {
    let port = serve();
    let base = format!("http://127.0.0.1:{port}");

    let native = run("--require-native", &program(&base, false), "native");
    let interp = run("--interpret", &program(&base, true), "interp");

    assert_eq!(native, interp, "planes disagree:\nnative={native:?}\ninterp={interp:?}");
    assert_eq!(
        native,
        vec!["0", "1", "3", "link1", "link3"],
        "links/extract_all_text lengths or contents wrong at N=0/1/3"
    );
}
