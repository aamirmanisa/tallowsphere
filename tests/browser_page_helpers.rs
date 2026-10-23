//! End-to-end tests for the live-page helpers (`browser.page_*`).
//!
//! These run the shipped binary against a local `file://` fixture, so they
//! exercise the real path: interpreter → current-page registry → CDP →
//! Chromium. That is the path the manual probes used during the 2026-10-22
//! surface pass took, and until now none of it lived in `cargo test`.
//!
//! A machine without Chrome skips instead of failing — the helpers need a
//! browser, and pretending otherwise would make CI red for an absent
//! dependency rather than a broken feature.

use std::path::PathBuf;
use std::process::Command;

fn chrome_available() -> bool {
    let path = tallow::browser::process::find_chrome_path();
    path.is_file()
}

fn fixture_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tallow-page-helpers-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create fixture dir");
    dir
}

/// Run a `.tl` program through the shipped binary and return stdout.
fn run_program(source: &str, name: &str) -> String {
    let dir = fixture_dir();
    let program = dir.join(format!("{name}.tl"));
    std::fs::write(&program, source).expect("write program");
    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(&program)
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

fn fixture_html() -> String {
    let dir = fixture_dir();
    let file = dir.join("fixture.html");
    std::fs::write(
        &file,
        concat!(
            "<html><head><title>Fixture</title>",
            "<script type=\"application/ld+json\">{\"@type\":\"Article\",\"name\":\"T\"}</script>",
            "</head><body><h1>Hello</h1>",
            "<p class=\"x\">A</p><p class=\"x\">B</p>",
            "<a rel=\"next\" href=\"/page/2\">Next</a></body></html>"
        ),
    )
    .expect("write fixture");
    format!("file://{}", file.display())
}

const PRELUDE: &str = r#"
@legal(
    basis:         .public_data,
    purpose:       "exercise live page helpers against a local fixture",
    personal_data: false,
    robots_txt:    .respect,
    rate_limit:    1.per_second
)
fn open_page(url: String) -> Page {
    let b = Browser.launch(true) match { Ok(b) -> b, Err(e) -> { bail "launch: {e}" } }
    let p = b.new_page() match { Ok(p) -> p, Err(e) -> { bail "page: {e}" } }
    p.goto(url) match { Ok(_) -> (), Err(e) -> { bail "goto: {e}" } }
    return p
}
"#;

#[test]
fn extractors_read_the_live_document() {
    if !chrome_available() {
        eprintln!("skipping: no Chrome on this machine");
        return;
    }
    let url = fixture_html();
    let program = format!(
        "{PRELUDE}\nfn main() {{\n    let p = open_page(\"{url}\")\n    print(browser.page_extract_all_text(\"p.x\"))\n    print(browser.page_extract_all_attrs(\"p.x\", [\"class\"]))\n    print(browser.page_extract_all_text(\"h1\"))\n}}\n"
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
    let url = fixture_html();
    let program = format!(
        "{PRELUDE}\nfn main() {{\n    let p = open_page(\"{url}\")\n    let sd = browser.page_structured_data()\n    print(sd.has_json_ld)\n    let dom = browser.page_capture_dom_snapshot()\n    print(dom.len() > 100)\n}}\n"
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
    let url = fixture_html();
    let program = format!(
        "{PRELUDE}\nfn main() {{\n    let p = open_page(\"{url}\")\n    let pg = browser.page_detect_pagination()\n    print(pg.strategy)\n    print(browser.page_handle_cookie_consent(\"accept\"))\n}}\n"
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
    let url = fixture_html();
    let program = format!(
        "{PRELUDE}\nfn main() {{\n    let p = open_page(\"{url}\")\n    print(p.evaluate(\"typeof document.title\"))\n    print(p.evaluate(\"1 + 41\"))\n    print(p.evaluate(\"document.querySelectorAll('p.x').length\"))\n}}\n"
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
