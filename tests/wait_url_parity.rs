//! `Page.wait_for_url` on both engines — #120 acceptance.
//!
//! The result is a `Result<WaitResult>`, and the two engines expose it
//! differently (documented divergence #116): the interpreter keeps the wrapper,
//! so the payload needs `match`; the native plane hands the payload back for
//! direct field access. The observable answer must still be identical, which is
//! what this test holds: `result` and `url` from a real page.
//!
//! Run with `TALLOW_ALLOW_DIRECT=1` (loopback through SOCKS is refused by Tor).

use std::io::Write;
use std::net::TcpListener;

const PAGE: &str = "<!doctype html><html><head><title>wait-url-page</title></head>\
<body><p id='x'>hello</p></body></html>";

fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
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

fn prelude(url: &str) -> String {
    format!(
        r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "wait_for_url parity on loopback", personal_data: false)
@persona(id: "wait-parity", cover_class: .researcher, compartment: "waitparity", fingerprint_seed: "wait-parity-1019")
@burn_plan(persona: "wait-parity", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowWaitParity/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("{url}")
"#
    )
}

/// Interpreter idiom: the wrapper is preserved, so unwrap it.
fn interpreted_program(url: &str) -> String {
    format!(
        r#"{}    page.wait_for_url("{url}", 5000) match {{
        Ok(r) -> {{
            print(r.result)
            print(r.url)
        }}
        Err(e) -> print(e)
    }}
    page.close()
    browser.close()
}}
"#,
        prelude(url)
    )
}

/// Native idiom: direct field access on the payload.
fn native_program(url: &str) -> String {
    format!(
        r#"{}    let r = page.wait_for_url("{url}", 5000)
    print(r.result)
    print(r.url)
    page.close()
    browser.close()
}}
"#,
        prelude(url)
    )
}

fn run(source: &str, extra: &[&str]) -> std::process::Output {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "tallow-waitparity-{}-{}.tl",
        std::process::id(),
        extra.join("_")
    ));
    std::fs::write(&path, source).expect("write program");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .args(extra)
        .arg(&path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);
    out
}

#[test]
fn wait_for_url_reports_the_same_page_in_both_engines() {
    let port = serve();
    let url = format!("http://127.0.0.1:{port}/");

    let interpreted = run(&interpreted_program(&url), &["--interpret"]);
    let native = run(&native_program(&url), &["--require-native"]);

    let interp_out = String::from_utf8_lossy(&interpreted.stdout).to_string();
    let native_out = String::from_utf8_lossy(&native.stdout).to_string();
    let native_err = String::from_utf8_lossy(&native.stderr).to_string();

    assert!(
        interpreted.status.success(),
        "interpreter leg failed:\n{interp_out}\n{}",
        String::from_utf8_lossy(&interpreted.stderr)
    );
    assert!(
        native.status.success(),
        "native leg failed — the WaitResult payload is not readable:\n{native_out}\n{native_err}"
    );
    assert!(
        !native_err.contains("native build unavailable"),
        "native leg fell back to the interpreter:\n{native_err}"
    );

    assert_eq!(
        interp_out, "true\n".to_string() + &url + "\n",
        "the interpreter no longer reports a matched URL"
    );
    assert_eq!(
        native_out, interp_out,
        "the engines disagree on WaitResult: native printed {native_out:?}"
    );
}
