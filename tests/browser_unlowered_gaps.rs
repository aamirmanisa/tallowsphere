//! The four remaining `Page` methods must fail LOUDLY on the native plane.
//!
//! `docs/browser-native-gaps.md` records them, and `docs/operations/stub-register.md`
//! defines "registered" as *a code path that deliberately refuses*. A silent
//! zero or a missing field would satisfy none of that: the program would print
//! plausible output and the divergence would surface as wrong data later.
//!
//! This test pins the refusal text and, just as importantly, that the program
//! body never runs: `--require-native` must not quietly fall back to the
//! interpreter after the failed build.

use std::path::PathBuf;

/// `(program call, method name as it must appear in the refusal)`.
const GAPS: &[(&str, &str)] = &[
    ("let v = page.get_cookies()", "Page.get_cookies"),
    (r#"let v = page.drain_events("console")"#, "Page.drain_events"),
    (
        r#"let v = page.goto_antibot("http://127.0.0.1:9/")"#,
        "Page.goto_antibot",
    ),
    ("let v = page.resolve_antibot()", "Page.resolve_antibot"),
];

fn program(call: &str) -> String {
    format!(
        r#"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "unlowered method refusal", personal_data: false)
@persona(id: "gap-refusal", cover_class: .researcher, compartment: "gaprefusal", fingerprint_seed: "gap-refusal-1020")
@burn_plan(persona: "gap-refusal", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowGapRefusal/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("http://127.0.0.1:9/")
    {call}
    print("BODY-RAN")
    page.close()
    browser.close()
}}
"#
    )
}

fn run_native(dir: &PathBuf, tag: &str, source: &str) -> (bool, String, String) {
    let path = dir.join(format!("gap-{tag}-{}.tl", std::process::id()));
    std::fs::write(&path, source).expect("write program");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg("--require-native")
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
fn unlowered_page_methods_refuse_by_name_and_never_fall_back() {
    let dir = std::env::temp_dir();
    for (call, method) in GAPS {
        let (ok, stdout, stderr) = run_native(&dir, &method.replace('.', "-"), &program(call));

        assert!(!ok, "{method} unexpectedly succeeded natively:\n{stdout}\n{stderr}");
        assert!(
            stderr.contains(&format!("no lowering for stdlib method '{method}'")),
            "refusal for {method} must name the method:\n{stderr}"
        );
        assert!(
            stderr.contains("--require-native refuses the interpreter fallback"),
            "the refusal must state that fallback is refused:\n{stderr}"
        );
        assert!(
            !stdout.contains("BODY-RAN"),
            "{method} refused the build but the program body still ran — a silent fallback:\n{stdout}"
        );
    }
}
