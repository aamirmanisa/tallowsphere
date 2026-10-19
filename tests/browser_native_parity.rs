//! Native plane for the browser API — first slice: `Page.goto`.
//!
//! The backend refuses to emit a value it cannot produce (a native `goto` used
//! to return a bare status where the interpreter returns
//! `Ok(NavigationResult)`). This test holds the two legs to the same observable
//! result: both must load the same page and report the same title and URL, and
//! the native leg must not fall back to the interpreter.
//!
//! Run with `TALLOW_ALLOW_DIRECT=1` (loopback through SOCKS is refused by Tor).

use std::io::{Read, Write};
use std::net::TcpListener;

const PAGE: &str = "<!doctype html><html><head><title>native-parity-page</title></head>\
<body><p id='x'>hello</p></body></html>";

fn serve(body: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
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

fn program(url: &str) -> String {
    format!(
        r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "native goto parity on loopback", personal_data: false)
@persona(id: "nav-parity", cover_class: .researcher, compartment: "navparity", fingerprint_seed: "nav-parity-1018")
@burn_plan(persona: "nav-parity", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowNavParity/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("{url}")
    page.add_init_script("window.__tallowParityInit = 1")
    page.add_script_tag("window.__tallowParityTag = 1")
    page.capture_console()
    page.throttle_cpu(1.0)
    page.throttle_network("4g")
    print("TITLE=" + page.title())
    print("URL=" + page.url())
    print(page.content())
    page.close()
    browser.close()
}}
"#
    )
}

fn run(program: &std::path::Path, extra: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .args(extra)
        .arg(program)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .env("TALLOW_NO_STEALTH", "1")
        .output()
        .expect("run tallow")
}

#[test]
fn goto_loads_the_same_page_in_both_engines() {
    let port = serve(PAGE);
    let url = format!("http://127.0.0.1:{port}/");
    let path = std::env::temp_dir().join(format!("tallow-navparity-{}.tl", std::process::id()));
    std::fs::write(&path, program(&url)).expect("write program");

    let interpreted = run(&path, &["--interpret"]);
    let native = run(&path, &["--require-native"]);
    let _ = std::fs::remove_file(&path);

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
        "--require-native refused the program; the goto lowering is not reachable:\n{native_out}\n{native_err}"
    );
    assert!(
        !native_err.contains("native build unavailable"),
        "native leg fell back to the interpreter:\n{native_err}"
    );

    // Both legs must have navigated and read the same document. The printed
    // wrapper differs (`Ok("…")` natively — register #116), so the assertion is
    // on the content both engines agree about.
    for (leg, out) in [("interpreter", &interp_out), ("native", &native_out)] {
        assert!(
            out.contains("native-parity-page"),
            "{leg} did not read the title:\n{out}"
        );
        assert!(
            out.contains(&url),
            "{leg} reported the wrong URL (expected {url}):\n{out}"
        );
        // `content()` is a second lowered method: both planes must read the
        // same DOM, not merely the same URL.
        assert!(
            out.contains("hello</p>"),
            "{leg} did not read the body through content():\n{out}"
        );
    }
}
