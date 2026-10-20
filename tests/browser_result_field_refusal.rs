//! Field access on an unbound Result-returning call must refuse on the native plane.
//!
//! `page.authenticated_get(url).status` used to print 0 natively while the
//! interpreter printed the real status: the read landed on the `%struct.TallowResult`
//! wrapper and fell through to a literal zero. That is the silent-third-state the
//! project forbids, so codegen now refuses the shape by name.
//!
//! Both planes reject the shape; only the native message names the fix. The test
//! pins that neither returns a silent zero.

use std::io::{Read, Write};
use std::net::TcpListener;

fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let response = "HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
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
@legal(basis: .research, purpose: "unbound result field refusal", personal_data: false)
@persona(id: "ufr", cover_class: .researcher, compartment: "ufr", fingerprint_seed: "ufr-1020")
@burn_plan(persona: "ufr", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowUfr/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("{base}/")
    print(page.authenticated_get("{base}/probe").status)
    page.close()
    browser.close()
}}
"#
    )
}

fn run(flag: &str, base: &str, tag: &str) -> (bool, String) {
    let path = std::env::temp_dir().join(format!("tallow-ufr-{}-{tag}.tl", std::process::id()));
    std::fs::write(&path, program(base)).expect("write program");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(flag)
        .arg(&path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

#[test]
fn unbound_result_field_is_refused_on_both_planes() {
    let port = serve();
    let base = format!("http://127.0.0.1:{port}");

    let (native_ok, native_out) = run("--require-native", &base, "native");
    assert!(
        !native_ok,
        "native must refuse the unbound field read, got success:\n{native_out}"
    );
    assert!(
        native_out.contains("bind the result first"),
        "refusal must name the fix, got:\n{native_out}"
    );

    // The interpreter rejects the same shape too, but with a generic type error
    // rather than a fix. What matters is that neither plane returns a silent 0.
    let (interp_ok, interp_out) = run("--interpret", &base, "interp");
    assert!(
        !interp_ok,
        "interpreter must not silently accept the unbound field read:\n{interp_out}"
    );
    assert!(
        interp_out.contains(".status"),
        "interpreter refusal should name the field, got:\n{interp_out}"
    );
}
