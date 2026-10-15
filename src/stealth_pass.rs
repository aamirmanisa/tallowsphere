//! @stealth annotation validation pass.
//!
//! This pass enforces Tallow's stealth invariant:
//! **Every function that uses browser navigation SHOULD have a @stealth annotation.**
//!
//! Validates:
//! - Browser navigation functions have @stealth
//! - Profile values are recognized presets
//! - Evasions values are valid
//! - @stealth is always accompanied by @legal
//!
//! Error codes: E0400-E0404

use crate::ast::*;
use crate::error::{Diagnostic, Diagnostics};
use crate::typeck::TypeEnv;

// ── Parsed Stealth Annotation ───────────────────────────────────────────────

#[derive(Debug)]
struct StealthInfo {
    profile: Option<String>,
    evasions: Option<String>,
    fingerprint: Option<String>,
    human_timing: Option<bool>,
    span: crate::lexer::Span,
}

impl StealthInfo {
    fn from_annotation(ann: &Annotation) -> Self {
        let mut info = StealthInfo {
            profile: None,
            evasions: None,
            fingerprint: None,
            human_timing: None,
            span: ann.span,
        };

        for arg in &ann.args {
            match arg.name.as_str() {
                "profile" => {
                    if let ExprKind::DotIdent(ref val) = arg.value.kind {
                        info.profile = Some(val.clone());
                    }
                }
                "evasions" => {
                    if let ExprKind::DotIdent(ref val) = arg.value.kind {
                        info.evasions = Some(val.clone());
                    }
                }
                "fingerprint" => {
                    if let ExprKind::DotIdent(ref val) = arg.value.kind {
                        info.fingerprint = Some(val.clone());
                    }
                }
                "human_timing" => {
                    if let ExprKind::BoolLit(val) = arg.value.kind {
                        info.human_timing = Some(val);
                    }
                }
                _ => {} // ignore unknown args
            }
        }

        info
    }
}

// ── Valid Values ────────────────────────────────────────────────────────────

const VALID_PROFILES: &[&str] = &[
    "chrome_windows",
    "chrome_macos",
    "chrome_linux",
    "mobile_android",
    "mobile_ios",
];

const VALID_EVASIONS: &[&str] = &["all", "minimal", "custom"];

// ── Stealth Pass ────────────────────────────────────────────────────────────

pub struct StealthPass<'a> {
    program: &'a Program,
    env: &'a TypeEnv,
    pub diags: Diagnostics,
}

impl<'a> StealthPass<'a> {
    pub fn new(program: &'a Program, env: &'a TypeEnv) -> Self {
        Self {
            program,
            env,
            diags: Diagnostics::new(),
        }
    }

    /// Run the stealth pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.check_function(f),
                Item::Impl(ib) => {
                    for method in &ib.methods {
                        self.check_function(method);
                    }
                }
                _ => {}
            }
        }
        self.diags
    }

    fn check_function(&mut self, f: &FnDecl) {
        let uses_browser_nav = self.env.browser_nav_functions.contains(&f.name);
        let stealth_ann = f.annotations.iter().find(|a| a.name == "stealth");
        let has_legal = f.annotations.iter().any(|a| a.name == "legal");

        // ── E0400: Browser navigation function missing @stealth ──────────
        if uses_browser_nav && stealth_ann.is_none() {
            self.diags.push(
                Diagnostic::error(
                    "E0400",
                    format!(
                        "function `{}` uses browser navigation but has no @stealth annotation",
                        f.name
                    ),
                    f.span,
                )
                .with_help("add @stealth(profile: .chrome_windows, evasions: .all) to this function"),
            );
            return; // can't validate further without annotation
        }

        // If no stealth annotation, skip
        let Some(ann) = stealth_ann else {
            return;
        };

        let info = StealthInfo::from_annotation(ann);

        // ── E0403: @stealth present without @legal ───────────────────────
        if !has_legal {
            self.diags.push(
                Diagnostic::error(
                    "E0403",
                    format!(
                        "@stealth on `{}` requires a @legal annotation (stealth requires legal basis)",
                        f.name
                    ),
                    info.span,
                )
                .with_help("add @legal(basis: ..., purpose: \"...\") alongside @stealth"),
            );
        }

        // ── E0401: Unknown stealth profile ───────────────────────────────
        if let Some(ref profile) = info.profile {
            if !VALID_PROFILES.contains(&profile.as_str()) {
                self.diags.push(
                    Diagnostic::error(
                        "E0401",
                        format!("unknown stealth profile: .{profile}"),
                        info.span,
                    )
                    .with_help(format!(
                        "valid profiles: {}",
                        VALID_PROFILES
                            .iter()
                            .map(|p| format!(".{p}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                );
            }
        }

        // ── E0402: Invalid evasions value ────────────────────────────────
        if let Some(ref evasions) = info.evasions {
            if !VALID_EVASIONS.contains(&evasions.as_str()) {
                self.diags.push(
                    Diagnostic::error(
                        "E0402",
                        format!("invalid stealth evasions value: .{evasions}"),
                        info.span,
                    )
                    .with_help(format!(
                        "valid values: {}",
                        VALID_EVASIONS
                            .iter()
                            .map(|e| format!(".{e}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                );
            }
        }

        // ── E0404: Inconsistent profile configuration (warning) ──────────
        // A mobile profile (.mobile_android / .mobile_ios) emulates a physical device and
        // depends on the full standard evasion bundle to mask that environment. Selecting
        // `.minimal` or `.custom` evasions on a mobile profile strips the mobile
        // anti-detection the profile relies on, producing an internally inconsistent
        // configuration (the profile claims a mobile device but the evasion set is
        // desktop-oriented). Desktop profiles are exempt.
        if let Some(ref profile) = info.profile {
            if (profile == "mobile_android" || profile == "mobile_ios")
                && matches!(info.evasions.as_deref(), Some("minimal") | Some("custom"))
            {
                let evasions = info.evasions.as_deref().unwrap_or("all");
                self.diags.warning(
                    "E0404",
                    format!(
                        "@stealth on `{}` uses mobile profile `{}` with evasions: .{} — mobile \
                         profiles require the full evasion bundle (.all) to avoid leaking the mobile \
                         environment",
                        f.name, profile, evasions
                    ),
                    info.span,
                );
                if let Some(last) = self.diags.items.last_mut() {
                    last.help = Some(
                        "set evasions: .all on mobile profiles so the standard mobile anti-detection \
                         bundle (UA, touch, viewport, navigator) is applied"
                            .to_string(),
                    );
                }
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;
    use crate::parser::Parser;
    use crate::typeck::TypeChecker;

    fn run_stealth_pass(source: &str) -> Diagnostics {
        let (tokens, _) = lexer::tokenize(source);
        let program = Parser::parse(tokens).unwrap();
        let (env, _) = TypeChecker::new(&program).check();
        StealthPass::new(&program, &env).check()
    }

    #[test]
    fn browser_navigation_without_stealth_emits_e0400() {
        let diags = run_stealth_pass(
            r#"@legal(basis: .public_data, purpose: "scraping")
fn scrape(url: String) { browser.goto(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(
            diags.items.iter().any(|d| d.code == "E0400"),
            "expected E0400, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn stealth_without_legal_emits_e0403() {
        let diags = run_stealth_pass(
            r#"@stealth(profile: .chrome_windows, evasions: .all)
fn scrape(url: String) { browser.goto(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(
            diags.items.iter().any(|d| d.code == "E0403"),
            "expected E0403, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn valid_stealth_with_legal_passes() {
        let diags = run_stealth_pass(
            r#"@stealth(profile: .chrome_windows, evasions: .all)
@legal(basis: .public_data, purpose: "scraping")
fn scrape(url: String) { browser.goto(url) }"#,
        );
        // Should not have stealth errors (may have legal pass warnings, but not stealth)
        let stealth_errors: Vec<_> = diags
            .items
            .iter()
            .filter(|d| d.code.starts_with("E04"))
            .collect();
        assert!(
            stealth_errors.is_empty(),
            "expected no E04xx errors, got: {:?}",
            stealth_errors
        );
    }

    #[test]
    fn unknown_profile_emits_e0401() {
        let diags = run_stealth_pass(
            r#"@stealth(profile: .firefox_linux, evasions: .all)
@legal(basis: .public_data, purpose: "scraping")
fn scrape(url: String) { browser.goto(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(
            diags.items.iter().any(|d| d.code == "E0401"),
            "expected E0401, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn invalid_evasions_emits_e0402() {
        let diags = run_stealth_pass(
            r#"@stealth(profile: .chrome_windows, evasions: .aggressive)
@legal(basis: .public_data, purpose: "scraping")
fn scrape(url: String) { browser.goto(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(
            diags.items.iter().any(|d| d.code == "E0402"),
            "expected E0402, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn pure_element_interaction_without_stealth_no_error() {
        // click, type, select are NOT navigation -- no @stealth needed
        let diags = run_stealth_pass(
            r#"fn interact(el: Element) { el.click() }"#,
        );
        let stealth_errors: Vec<_> = diags
            .items
            .iter()
            .filter(|d| d.code.starts_with("E04"))
            .collect();
        assert!(
            stealth_errors.is_empty(),
            "pure interaction should not require @stealth: {:?}",
            stealth_errors
        );
    }

    #[test]
    fn non_browser_function_without_stealth_no_error() {
        let diags = run_stealth_pass(
            r#"fn add(a: i32, b: i32) -> i32 { a + b }"#,
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn valid_profile_chrome_macos_passes() {
        let diags = run_stealth_pass(
            r#"@stealth(profile: .chrome_macos, evasions: .minimal)
@legal(basis: .public_data, purpose: "scraping")
fn scrape(url: String) { browser.goto(url) }"#,
        );
        let stealth_errors: Vec<_> = diags
            .items
            .iter()
            .filter(|d| d.code.starts_with("E04"))
            .collect();
        assert!(stealth_errors.is_empty());
    }

    #[test]
    fn valid_profile_mobile_android_passes() {
        let diags = run_stealth_pass(
            r#"@stealth(profile: .mobile_android, evasions: .all)
@legal(basis: .research, purpose: "testing")
fn test_mobile(url: String) { page.navigate(url) }"#,
        );
        let stealth_errors: Vec<_> = diags
            .items
            .iter()
            .filter(|d| d.code.starts_with("E04"))
            .collect();
        assert!(stealth_errors.is_empty());
    }

    #[test]
    fn valid_evasions_custom_passes() {
        let diags = run_stealth_pass(
            r#"@stealth(profile: .chrome_linux, evasions: .custom)
@legal(basis: .public_data, purpose: "scraping")
fn scrape(url: String) { browser.goto(url) }"#,
        );
        let stealth_errors: Vec<_> = diags
            .items
            .iter()
            .filter(|d| d.code.starts_with("E04"))
            .collect();
        assert!(stealth_errors.is_empty());
    }

    #[test]
    fn navigate_method_requires_stealth() {
        let diags = run_stealth_pass(
            r#"@legal(basis: .public_data, purpose: "nav")
fn nav(url: String) { page.navigate(url) }"#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "E0400"),
            "page.navigate should require @stealth: {:?}",
            diags.items
        );
    }

    #[test]
    fn new_page_requires_stealth() {
        let diags = run_stealth_pass(
            r#"@legal(basis: .public_data, purpose: "open")
fn open(url: String) { browser.new_page(url) }"#,
        );
        assert!(diags.items.iter().any(|d| d.code == "E0400"));
    }

    #[test]
    fn launch_requires_stealth() {
        let diags = run_stealth_pass(
            r#"@legal(basis: .public_data, purpose: "start")
fn start() { browser.launch() }"#,
        );
        assert!(diags.items.iter().any(|d| d.code == "E0400"));
    }

    #[test]
    fn empty_program_no_errors() {
        let diags = run_stealth_pass("");
        assert!(!diags.has_errors());
    }

    #[test]
    fn stealth_with_human_timing_bool_passes() {
        let diags = run_stealth_pass(
            r#"@stealth(profile: .chrome_windows, evasions: .all, human_timing: true)
@legal(basis: .public_data, purpose: "scraping")
fn scrape(url: String) { browser.goto(url) }"#,
        );
        let stealth_errors: Vec<_> = diags
            .items
            .iter()
            .filter(|d| d.code.starts_with("E04"))
            .collect();
        assert!(stealth_errors.is_empty());
    }

    #[test]
    fn multiple_functions_only_nav_one_gets_e0400() {
        let diags = run_stealth_pass(
            r#"fn pure(x: i32) -> i32 { x + 1 }

@legal(basis: .public_data, purpose: "scraping")
fn scrape(url: String) { browser.goto(url) }"#,
        );
        let e0400_count = diags.items.iter().filter(|d| d.code == "E0400").count();
        assert_eq!(e0400_count, 1, "only the navigation function should get E0400");
    }

    #[test]
    fn stealth_on_non_nav_function_with_legal_no_stealth_errors() {
        // @stealth on a non-navigation function -- allowed (user might be future-proofing)
        let diags = run_stealth_pass(
            r#"@stealth(profile: .chrome_windows, evasions: .all)
@legal(basis: .public_data, purpose: "processing")
fn process(data: String) -> String { data }"#,
        );
        let stealth_errors: Vec<_> = diags
            .items
            .iter()
            .filter(|d| d.code.starts_with("E04"))
            .collect();
        assert!(stealth_errors.is_empty());
    }
}
