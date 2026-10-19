//! `resolve_antibot(url, opts)` must never silently ignore `opts`.
//!
//! The interpreter consumes `{solver_key, solver_service}` into
//! `AntiBotSettings.captcha_solver` (via the stdlib path, which defaults the
//! service to 2captcha when omitted); the native lowering cannot, so it refuses
//! at build time. Both behaviours are pinned here, because "accepted and dropped" is
//! the failure mode that ships wrong answers: a caller would configure a solver,
//! see no error, and only later notice the captcha was never solved.

use std::io::{Read, Write};
use std::net::TcpListener;

const PAGE: &str = "<!doctype html><html><head><title>opts</title></head><body>opts</body></html>";

fn program(url: &str, opts: &str) -> String {
    format!(
        r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "resolve_antibot opts", personal_data: false)
@persona(id: "opts", cover_class: .researcher, compartment: "opts", fingerprint_seed: "opts-1020")
@burn_plan(persona: "opts", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowOpts/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("{url}")
    print(page.resolve_antibot("{url}", {opts}))
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

fn run(flag: &str, source: &str) -> (bool, String, String) {
    let path = std::env::temp_dir().join(format!("tallow-opts-{}.tl", std::process::id()));
    std::fs::write(&path, source).expect("write program");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(flag)
        .arg(&path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn native_refuses_opts_instead_of_ignoring_them() {
    let port = serve();
    let url = format!("http://127.0.0.1:{port}/");
    let src = program(&url, r#"{"solver_key": "k", "solver_service": "https://solver.invalid"}"#);
    let (ok, stdout, stderr) = run("--require-native", &src);
    let combined = format!("{stdout}{stderr}");
    assert!(!ok, "native build accepted opts it cannot honour:\n{combined}");
    assert!(
        combined.contains("opts") && combined.contains("not"),
        "the refusal must name opts and its limitation:\n{combined}"
    );
}

#[test]
fn interpreter_consumes_a_full_opts_map() {
    let port = serve();
    let url = format!("http://127.0.0.1:{port}/");
    let src = program(&url, r#"{"solver_key": "k", "solver_service": "https://solver.invalid"}"#);
    let (ok, stdout, stderr) = run("--interpret", &src);
    let combined = format!("{stdout}{stderr}");
    assert!(ok, "interpreter rejected a complete opts map:\n{combined}");
    assert!(
        combined.contains("Ok(AntibotResolveReport"),
        "resolved report expected with opts:\n{combined}"
    );
}
