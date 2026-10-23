//! WordPress automation tests against a local fixture.
//!
//! Ignored by default for two reasons:
//!
//! 1. They need `scripts/wordpress_fixture.sh up` — a real WordPress on
//!    127.0.0.1:8099.
//! 2. Tallow's browser zone sends every request through Tor, and Tor cannot
//!    reach a loopback service, so the run needs `TALLOW_ALLOW_DIRECT=1`. That
//!    opt-out is an operator decision (egress leaves from the box IP), not
//!    something a test should switch on by itself.
//!
//! Run:
//!   scripts/wordpress_fixture.sh up
//!   TALLOW_ALLOW_DIRECT=1 cargo test --test wordpress_login -- --ignored --nocapture

use std::process::Command;

const ADMIN_PASS: &str = "Adm1nPass2026";

fn fixture_url() -> String {
    std::env::var("WP_URL").unwrap_or_else(|_| "http://127.0.0.1:8099".to_string())
}

fn reachable(url: &str) -> bool {
    Command::new("curl")
        .args(["-sf", "-o", "/dev/null", &format!("{url}/wp-login.php")])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_tl(source: &str, name: &str) -> String {
    let dir = std::env::temp_dir().join(format!("tallow-wp-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("fixture dir");
    let program = dir.join(format!("{name}.tl"));
    std::fs::write(&program, source).expect("write program");
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(&program)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(out.status.success(), "{name} failed\n{stdout}\n{stderr}");
    stdout
}

fn program(url: &str) -> String {
    format!(
        r#"
@legal(
    basis:         .public_data,
    purpose:       "verify wordpress helpers against a local fixture",
    personal_data: false,
    robots_txt:    .respect,
    rate_limit:    1.per_second
)
fn main() {{
    let b = Browser.launch(true) match {{ Ok(b) -> b, Err(e) -> {{ bail "launch: {{e}}" }} }}
    let p = b.new_page() match {{ Ok(p) -> p, Err(e) -> {{ bail "page: {{e}}" }} }}
    p.goto("{url}/wp-login.php") match {{ Ok(_) -> (), Err(e) -> {{ bail "goto: {{e}}" }} }}
    print(p.is_wordfence_challenge())
    print(p.wp_is_logged_in())
    let wrong = p.wp_login("admin", "wrong-password") match {{ Ok(r) -> r, Err(e) -> {{ bail "login: {{e}}" }} }}
    print(wrong.status)
    let right = p.wp_login("admin", "{ADMIN_PASS}") match {{ Ok(r) -> r, Err(e) -> {{ bail "login2: {{e}}" }} }}
    print(right.status)
    print(p.wp_is_logged_in())
    p.goto("{url}/wp-admin/") match {{ Ok(_) -> (), Err(e) -> {{ bail "admin: {{e}}" }} }}
    let nonces = p.wp_extract_all_nonces() match {{ Ok(n) -> n, Err(e) -> {{ bail "nonces: {{e}}" }} }}
    print(nonces.len() > 0)
}}
"#
    )
}

#[test]
#[ignore = "needs scripts/wordpress_fixture.sh up and TALLOW_ALLOW_DIRECT=1"]
fn wordpress_login_flow_against_local_fixture() {
    let url = fixture_url();
    assert!(
        reachable(&url),
        "no WordPress at {url} — run scripts/wordpress_fixture.sh up first"
    );
    let out = run_tl(&program(&url), "wp_login");
    let lines: Vec<&str> = out.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    assert!(
        lines.iter().any(|l| l.contains("false")),
        "wordfence/logged-in probes: {out}"
    );
    assert!(lines.contains(&"failed"), "wrong password must fail: {out}");
    assert!(lines.contains(&"success"), "right password must succeed: {out}");
    assert!(
        lines.iter().any(|l| *l == "true"),
        "logged-in state or nonces must be true: {out}"
    );
}
