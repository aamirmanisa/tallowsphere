//! A failing native FFI must be *visible*, not a silent exit.
//!
//! Two earlier attempts at the native `resolve_antibot` lowering were wasted
//! because a Result-tagged failure exits the compiled program before any `print`
//! runs: the run produced no output at all and looked like a crash. The FFI now
//! writes its message to stderr, and every error path returns a report with the
//! `error` field set rather than a null pointer (which the compiled side would
//! dereference for all seven fields).
//!
//! This test drives the empty-URL error path and requires the message to reach
//! the operator.

fn program(url: &str) -> String {
    format!(
        r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "ffi error visibility", personal_data: false)
@persona(id: "ffivis", cover_class: .researcher, compartment: "ffivis", fingerprint_seed: "ffivis-1020")
@burn_plan(persona: "ffivis", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowFfiVis/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    let rep = page.resolve_antibot("{url}")
    print(rep.resolved)
    page.close()
    browser.close()
}}
"#
    )
}

#[test]
fn a_failing_ffi_explains_itself_on_stderr() {
    let path = std::env::temp_dir().join(format!("tallow-ffivis-{}.tl", std::process::id()));
    std::fs::write(&path, program("")).expect("write program");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg("--require-native")
        .arg(&path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let combined = format!("{stdout}{stderr}");

    assert!(!out.status.success(), "an empty URL unexpectedly succeeded:\n{combined}");
    assert!(
        combined.contains("resolve_antibot"),
        "the failure must name the call:\n{combined}"
    );
    assert!(
        combined.contains("url must not be empty"),
        "the failure must explain itself rather than exit silently:\n{combined}"
    );
}
