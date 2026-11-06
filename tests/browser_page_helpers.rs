//! End-to-end tests for the live-page helpers (`browser.page_*`).
//!
//! These run the shipped binary against a local loopback fixture, so they
//! exercise the real path: interpreter → current-page registry → CDP →
//! Chromium. That is the path the manual probes used during the 2026-10-22
//! surface pass took, and until now none of it lived in `cargo test`.
//!
//! A machine without Chrome skips instead of failing — the helpers need a
//! browser, and pretending otherwise would make CI red for an absent
//! dependency rather than a broken feature.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

fn chrome_available() -> bool {
    let path = tallow::browser::process::find_chrome_path();
    path.is_file()
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tallow-page-helpers-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create fixture dir");
    dir
}

/// Run a `.tl` program through the shipped binary and return stdout.
///
/// The child runs from the workspace root: the scope gate resolves
/// `configs/tallow/scope/authorized-hosts.toml` relative to cwd. Loopback
/// navigation also needs `TALLOW_ALLOW_DIRECT=1` — the browser zone otherwise
/// routes 127.0.0.1 through Tor, which refuses it.
fn run_program(source: &str, name: &str) -> String {
    let dir = fixture_dir();
    let program = dir.join(format!("{name}.tl"));
    std::fs::write(&program, source).expect("write program");
    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(&program)
        .current_dir(workspace_root())
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        output.status.success(),
        "{name} failed\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    stdout
}

const FIXTURE_HTML: &str = concat!(
    "<html><head><title>Fixture</title>",
    "<script type=\"application/ld+json\">{\"@type\":\"Article\",\"name\":\"T\"}</script>",
    "</head><body><h1>Hello</h1>",
    "<p class=\"x\">A</p><p class=\"x\">B</p>",
    "<a rel=\"next\" href=\"/page/2\">Next</a></body></html>"
);

/// Serve the extractor fixture on loopback. `file://` is not in the
/// authorization register, so `page.goto` would refuse before CDP; 127.0.0.1
/// is the grant this workspace already ships.
fn serve_fixture() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                FIXTURE_HTML.len(),
                FIXTURE_HTML
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://127.0.0.1:{port}/")
}

/// Plan annotations attach to the next item. E5004/E5100 require them on
/// `main`, not on a helper — so the helper sits below `main`.
const PLAN: &str = r#"
@cra_class(.default)
@legal(
    basis:         .public_data,
    purpose:       "exercise live page helpers against a local fixture",
    personal_data: false,
    robots_txt:    .respect,
    rate_limit:    1.per_second
)
@persona(id: "page-helpers", cover_class: .researcher, compartment: "helpers", fingerprint_seed: "page-helpers-1102")
@burn_plan(persona: "page-helpers", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowPageHelpers/1.0 (+https://tallow.invalid/bot)", network: .monitored)
@stealth(profile: .chrome_windows, evasions: .all)
"#;

/// `open_page` returns `Page`, so it cannot `bail` (E0126). Unwrap launch /
/// new_page / goto the same way the sibling live suites do.
///
/// It carries its own `@legal` because the plan annotations above attach to
/// `main`, and E0100 requires the annotation on *every* function that touches
/// the network — a helper is not exempt just because `main` is annotated.
const OPEN_PAGE: &str = r#"
@legal(basis: .public_data, purpose: "module-level page helper parity", personal_data: false)
@stealth(profile: .chrome_windows, evasions: .all)
fn open_page(url: String) -> Result<Page> {
    // `Browser.launch` returns `Result<Browser>`. Calling `.new_page()` on a
    // failed launch reports only "unknown method: .new_page() on Err", which
    // cannot tell a launch failure from a broken helper -- that message made
    // the 2026-11-05 shard-1 flake undiagnosable. Each step is matched so its
    // Err arm bails with a message that names the step and the cause.
    let launched: Result<Browser> = Browser.launch(true)
    let b = launched match {
        Ok(v) -> v
        Err(e) -> {
            bail "browser.launch failed: {e}"
        }
    }
    let opened: Result<Page> = b.new_page()
    let p = opened match {
        Ok(v) -> v
        Err(e) -> {
            bail "new_page failed: {e}"
        }
    }
    let navigated: Result<Page> = p.goto(url)
    navigated match {
        Ok(_) -> {}
        Err(e) -> {
            bail "goto {url} failed: {e}"
        }
    }
    return Ok(p)
}
"#;

fn live_program(url: &str, body: &str) -> String {
    // `open_page` now returns `Result<Page>` and bails with a named cause, so
    // `main` is fallible too: `?` turns a launch/navigation failure into this
    // program's own error message instead of a panic two frames later.
    format!("{PLAN}\nfn main() -> Result<i64> {{\n    let p = open_page(\"{url}\")?\n    {body}\n    Ok(0)\n}}\n{OPEN_PAGE}")
}

#[test]
fn extractors_read_the_live_document() {
    if !chrome_available() {
        eprintln!("skipping: no Chrome on this machine");
        return;
    }
    let url = serve_fixture();
    let program = live_program(
        &url,
        "print(browser.page_extract_all_text(\"p.x\"))\n    print(browser.page_extract_all_attrs(\"p.x\", [\"class\"]))\n    print(browser.page_extract_all_text(\"h1\"))",
    );
    let out = run_program(&program, "extractors");
    assert!(out.contains("[\"A\", \"B\"]"), "text extraction: {out}");
    assert!(out.contains("class"), "attribute extraction: {out}");
    assert!(out.contains("[\"Hello\"]"), "h1 extraction: {out}");
}

#[test]
fn structured_data_and_snapshot_read_the_live_document() {
    if !chrome_available() {
        eprintln!("skipping: no Chrome on this machine");
        return;
    }
    let url = serve_fixture();
    let program = live_program(
        &url,
        "let sd = browser.page_structured_data()\n    print(sd.has_json_ld)\n    let dom = browser.page_capture_dom_snapshot()\n    print(dom.len() > 100)",
    );
    let out = run_program(&program, "structured");
    assert!(out.contains("true"), "json-ld detection: {out}");
}

#[test]
fn pagination_and_consent_answer_on_a_fixture() {
    if !chrome_available() {
        eprintln!("skipping: no Chrome on this machine");
        return;
    }
    let url = serve_fixture();
    let program = live_program(
        &url,
        "let pg = browser.page_detect_pagination()\n    print(pg.strategy)\n    print(browser.page_handle_cookie_consent(\"accept\"))",
    );
    let out = run_program(&program, "pagination");
    assert!(out.contains("next_button"), "pagination strategy: {out}");
    // No banner on this fixture: false is the correct answer, not a failure.
    assert!(out.contains("false"), "consent answer: {out}");
}

#[test]
fn evaluate_preserves_javascript_types() {
    if !chrome_available() {
        eprintln!("skipping: no Chrome on this machine");
        return;
    }
    let url = serve_fixture();
    let program = live_program(
        &url,
        "print(p.evaluate(\"typeof document.title\"))\n    print(p.evaluate(\"1 + 41\"))\n    print(p.evaluate(\"document.querySelectorAll('p.x').length\"))",
    );
    let out = run_program(&program, "evaluate");
    assert!(out.contains("\"string\""), "string result: {out}");
    assert!(out.contains("42"), "number result: {out}");
    assert!(!out.contains("\"\"string\"\""), "double-quoted string: {out}");
}

/// The module-level `browser.page_*` helpers act on the current page in both
/// engines: the interpreter through its thread-local registry, compiled code
/// through `tallow_current_page()`. Same program, both engines, same bytes out.
#[test]
fn module_level_helpers_agree_across_engines() {
    if !chrome_available() {
        eprintln!("skipping: no Chrome on this machine");
        return;
    }
    let program = r#"
@cra_class(.default)
@legal(basis: .public_data, purpose: "module-level page helper parity", personal_data: false)
@persona(id: "page-parity", cover_class: .researcher, compartment: "parity", fingerprint_seed: "page-parity-1023")
@burn_plan(persona: "page-parity", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowParity/1.0 (+https://tallow.invalid/bot)", network: .monitored)
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {
    let b = Browser.launch(true)
    let p = b.new_page()
    browser.page_set_content("<h1>Hi</h1><p class='x'>A</p>")
    print(browser.page_content().len > 20)
    print(browser.page_capture_dom_snapshot().len > 20)
    print(browser.page_text_redacted().len > 10)
    print(browser.page_handle_cookie_consent("reject"))
    b.close()
}
"#;
    let dir = fixture_dir();
    let file = dir.join("module_level_parity.tl");
    std::fs::write(&file, program).expect("write program");

    let run = |extra: &[&str]| -> String {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_tallow"));
        cmd.arg("run");
        for a in extra {
            cmd.arg(a);
        }
        cmd.arg(&file);
        let out = cmd.output().expect("run tallow");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(out.status.success(), "run failed\n{stdout}\n{stderr}");
        stdout
    };

    let native = run(&[]);
    let interpreted = run(&["--interpret"]);
    // The interpreter prefixes a banner line; compare the printed values only.
    let values = |s: &str| -> Vec<String> {
        s.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('*'))
            .map(str::to_string)
            .collect()
    };
    assert_eq!(
        values(&native),
        values(&interpreted),
        "native and interpreter disagree\nnative: {native}\ninterp: {interpreted}"
    );
}

/// The six struct-returning module-level helpers now return what
/// `stdlib/browser.tl` declares, instead of echoing a primitive — measured
/// because the interpreter used to answer `Ok(Float)` for `page_throttle_cpu`
/// where the declaration says `CpuThrottle`, and `Ok(Bool)` for the waiters
/// where it says `WaitResult`.
///
/// This asserts the INTERPRETER, deliberately: the native backend cannot yet
/// type a match-arm binding that came from one of these calls, so it refuses
/// the build by name and `tallow run` falls back here. Asserting the
/// interpreter is asserting what every program actually gets.
///
/// The interpreter still wraps these helpers in `Ok` (measured: `.loaded` on
/// the bare call is `unknown method: .loaded() on Ok`). `bail` is legal only
/// in a `Result`-returning function (E0126), so the body lives in `run`.
#[test]
fn struct_returning_helpers_return_the_declared_fields() {
    if !chrome_available() {
        eprintln!("skipping: no Chrome on this machine");
        return;
    }
    let program = r#"
@cra_class(.default)
@legal(basis: .public_data, purpose: "declared-struct parity for module-level page helpers", personal_data: false)
@persona(id: "struct-parity", cover_class: .researcher, compartment: "parity", fingerprint_seed: "struct-parity-1023")
@burn_plan(persona: "struct-parity", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowParity/1.0 (+https://tallow.invalid/bot)", network: .monitored)
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {
    run() match { Ok(_) -> (), Err(e) -> { print(e) } }
}
@legal(basis: .public_data, purpose: "declared-struct parity for module-level page helpers", personal_data: false)
@stealth(profile: .chrome_windows, evasions: .all)
fn run() -> Result<i64> {
    let b = Browser.launch(true)
    let p = b.new_page()
    let set = browser.page_set_content("<h1>Hi</h1>") match { Ok(v) -> v, Err(e) -> { bail "set: {e}" } }
    print(set.loaded)
    print(set.content_length > 10)
    let ct = browser.page_throttle_cpu(2.0) match { Ok(v) -> v, Err(e) -> { bail "cpu: {e}" } }
    print(ct.applied)
    print(ct.rate)
    let mm = browser.page_emulate_media("screen", "dark", "reduce") match { Ok(v) -> v, Err(e) -> { bail "media: {e}" } }
    print(mm.color_scheme)
    print(mm.reduced_motion)
    let w = browser.page_wait_for_url("*", 500) match { Ok(v) -> v, Err(e) -> { bail "url: {e}" } }
    print(w.matched)
    let f = browser.page_wait_for_function("typeof window !== 'undefined'", 2000) match { Ok(v) -> v, Err(e) -> { bail "fn: {e}" } }
    print(f.result)
    let tag = browser.page_add_style_tag("h1") match { Ok(v) -> v, Err(e) -> { bail "tag: {e}" } }
    print(tag.kind)
    b.close()
    Ok(0)
}
"#;
    let dir = fixture_dir();
    let file = dir.join("struct_returning.tl");
    std::fs::write(&file, program).expect("write program");
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg("--interpret")
        .arg(&file)
        .current_dir(workspace_root())
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(out.status.success(), "failed\n{stdout}\n{stderr}");
    let got: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .collect();
    assert_eq!(
        got,
        vec!["true", "true", "true", "2", "dark", "reduce", "true", "true", "style"],
        "declared fields:\n{stdout}"
    );
}
