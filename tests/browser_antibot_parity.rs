//! `Page.resolve_antibot` must produce the same report on both planes.
//!
//! The native lowering was withdrawn three times because it disagreed with the
//! interpreter, and the disagreement was not where it looked: the orchestrator
//! produced five steps on both planes while the compiled program read the length
//! as 1 (`.len` compiled to `strlen` over the count slot) and then printed every
//! engine as `0` (field reads on a non-variable receiver fell through to a
//! literal). Both are fixed; this test is what keeps them fixed.
//!
//! It asserts values, not shape: the resolved flag, the status, the attempt
//! count, the number of steps, and every engine name, byte-identical across
//! planes.

use std::io::{Read, Write};
use std::net::TcpListener;

const PAGE: &str = "<!doctype html><html><head><title>antibot</title></head>\
<body>antibot</body></html>";

/// The two planes need different shapes for a Result-returning browser call:
/// the interpreter requires `match { Ok(rep) -> … }`, while the native build
/// refuses to Ok/Err-match an opaque browser handle and requires direct field
/// access. That asymmetry is itself a contract worth pinning — a change to either
/// side should show up here.
fn program(url: &str, interp: bool) -> String {
    let body = if interp {
        r#"    page.resolve_antibot("{url}") match {{
        Ok(rep) -> {{
            print(rep.resolved)
            print(rep.final_status)
            print(rep.attempts)
            print(rep.steps.len)
            var k = 0
            while k < rep.steps.len {{
                print(rep.steps[k].engine)
                k = k + 1
            }}
        }}
        Err(e) -> print(e)
    }}"#
    } else {
        r#"    let rep = page.resolve_antibot("{url}")
    print(rep.resolved)
    print(rep.final_status)
    print(rep.attempts)
    print(rep.steps.len)
    var k = 0
    while k < rep.steps.len {{
        print(rep.steps[k].engine)
        k = k + 1
    }}"#
    };
    // The bodies are raw strings: `{url}` needs substituting by hand, and the
    // doubled braces that were escapes inside `format!` must be collapsed.
    let body = body
        .replace("{{", "{")
        .replace("}}", "}")
        .replace("{url}", url);
    format!(
        r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "resolve_antibot parity", personal_data: false)
@persona(id: "antibot", cover_class: .researcher, compartment: "antibot", fingerprint_seed: "antibot-1020")
@burn_plan(persona: "antibot", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowAntibot/1.0 (+https://tallow.invalid/bot)")
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

fn run(flag: &str, source: &str, tag: &str) -> String {
    let path = std::env::temp_dir().join(format!("tallow-antibot-{}-{tag}.tl", std::process::id()));
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
    assert!(
        !stderr.contains("interpreter fallback"),
        "{tag} leg fell back:\n{stderr}"
    );
    stdout
}

/// The interpreter announces itself on stdout; drop that banner and blank lines.
fn report(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("* running in the interpreter"))
        .map(str::to_string)
        .collect()
}

#[test]
fn resolve_antibot_reports_identical_values_on_both_planes() {
    let port = serve();
    let url = format!("http://127.0.0.1:{port}/");

    let native = report(&run("--require-native", &program(&url, false), "native"));
    let interp = report(&run("--interpret", &program(&url, true), "interp"));

    assert_eq!(
        native, interp,
        "native and interpreter disagree:\nnative={native:?}\ninterp={interp:?}"
    );

    // Pin the substance, so both planes drifting together cannot pass silently.
    assert_eq!(native.len(), 9, "expected 4 fields + 5 engines: {native:?}");
    assert_eq!(native[0], "true", "resolved");
    assert_eq!(native[1], "200", "final_status");
    assert_eq!(native[3], "5", "steps.len");
    assert_eq!(
        &native[4..],
        &[
            "egress",
            "captcha.detect",
            "warmup",
            "escalation",
            "classify"
        ],
        "engine order"
    );
}
