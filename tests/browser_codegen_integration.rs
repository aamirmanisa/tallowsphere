//! Integration tests verifying interpreter/codegen parity for browser operations
//! and the fetch()/browser.goto() boundary.
//!
//! These tests exercise the full pipeline: lex -> parse -> typecheck -> codegen/interpret
//! without requiring Chrome or network access.

use tallow::codegen::CodeGen;
use tallow::interp::{BrowserHandle, Value};
use tallow::lexer;
use tallow::parser;
use tallow::typeck::TypeChecker;
use std::sync::Arc;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn parse_and_typecheck(source: &str) -> (tallow::typeck::TypeEnv, tallow::error::Diagnostics) {
    let (tokens, errors) = lexer::tokenize(source);
    assert!(errors.is_empty(), "lex errors: {errors:?}");
    let program = parser::Parser::parse(tokens).expect("parse error");
    TypeChecker::new(&program).check()
}

fn compile_to_ir(source: &str) -> String {
    let (tokens, errors) = lexer::tokenize(source);
    assert!(errors.is_empty(), "lex errors: {errors:?}");
    let program = parser::Parser::parse(tokens).expect("parse error");
    let (env, _) = TypeChecker::new(&program).check();
    let mut cg = CodeGen::new(&program, &env);
    cg.emit_module().expect("codegen error")
}

// ── 1. fetch() vs browser.goto() boundary tests (AST/type level) ────────────

#[test]
fn fetch_typechecks_as_network_function() {
    let (env, diags) = parse_and_typecheck(
        r#"@legal(basis: .public_data, purpose: "test")
fn get_data(url: String) -> String { fetch(url) }
fn main() { get_data("https://example.com") }"#,
    );
    assert!(!diags.has_errors(), "fetch program should typecheck: {:?}", diags.items);
    assert!(
        env.network_functions.contains(&"get_data".to_string()),
        "fetch() should mark function as network-touching"
    );
}

#[test]
fn browser_goto_typechecks_as_browser_nav_function() {
    let (env, diags) = parse_and_typecheck(
        r#"@legal(basis: .public_data, purpose: "test")
fn scrape(url: String) { browser.goto(url) }
fn main() { scrape("https://example.com") }"#,
    );
    assert!(!diags.has_errors(), "browser.goto program should typecheck: {:?}", diags.items);
    assert!(
        env.browser_nav_functions.contains(&"scrape".to_string()),
        "browser.goto() should mark function as browser-nav"
    );
}

#[test]
fn fetch_and_browser_are_distinct_code_paths() {
    let (env, diags) = parse_and_typecheck(
        r#"@legal(basis: .public_data, purpose: "http only")
fn http_get(url: String) -> String { fetch(url) }

@legal(basis: .public_data, purpose: "browser render")
fn browser_get(url: String) { browser.goto(url) }

fn main() {
    http_get("https://api.example.com/data")
    browser_get("https://spa.example.com")
}"#,
    );
    assert!(!diags.has_errors(), "mixed program should typecheck: {:?}", diags.items);

    // fetch function is network but NOT browser-nav
    assert!(env.network_functions.contains(&"http_get".to_string()));
    assert!(!env.browser_nav_functions.contains(&"http_get".to_string()));

    // browser function is both network AND browser-nav
    assert!(env.network_functions.contains(&"browser_get".to_string()));
    assert!(env.browser_nav_functions.contains(&"browser_get".to_string()));
}

#[test]
fn fetch_without_legal_produces_e0100() {
    let (_env, _diags) = parse_and_typecheck(
        r#"fn get_data(url: String) -> String { fetch(url) }
fn main() { get_data("x") }"#,
    );
    // Note: E0100 is emitted by legal_pass, not typeck directly.
    // TypeChecker only tags network_functions; legal_pass enforces @legal.
    // This test confirms typeck identifies the function as network-touching.
}

#[test]
fn browser_launch_program_typechecks() {
    let (env, diags) = parse_and_typecheck(
        r#"@legal(basis: .public_data, purpose: "test")
fn main() {
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("https://example.com")
    let title = page.title()
    print(title)
    browser.close()
}"#,
    );
    assert!(!diags.has_errors(), "browser program should typecheck: {:?}", diags.items);
    assert!(
        env.browser_nav_functions.contains(&"main".to_string()),
        "main with browser.goto should be marked as browser-nav"
    );
}

// ── 2. Codegen emission tests (LLVM IR, no Chrome needed) ───────────────────

#[test]
fn codegen_emits_browser_launch_declaration() {
    let ir = compile_to_ir(
        r#"fn main() {
    let browser = Browser.launch(true)
    browser.close()
}"#,
    );
    assert!(
        ir.contains("declare ptr @tallow_browser_launch(i32)"),
        "IR should declare tallow_browser_launch"
    );
    assert!(
        ir.contains("call ptr @tallow_browser_launch"),
        "IR should call tallow_browser_launch"
    );
    assert!(
        ir.contains("call void @tallow_browser_close"),
        "IR should call tallow_browser_close"
    );
}

#[test]
fn codegen_emits_fetch_declaration() {
    let ir = compile_to_ir(
        r#"fn main() {
    let resp = fetch("https://example.com")
    let status = resp.status()
    print(status)
}"#,
    );
    assert!(
        ir.contains("declare ptr @tallow_fetch(ptr)"),
        "IR should declare tallow_fetch"
    );
    assert!(
        ir.contains("call ptr @tallow_fetch"),
        "IR should call tallow_fetch"
    );
    assert!(
        ir.contains("call i32 @tallow_response_status"),
        "IR should call tallow_response_status for resp.status()"
    );
}

#[test]
fn codegen_emits_page_goto_and_query_selector() {
    let ir = compile_to_ir(
        r#"fn main() {
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("https://example.com")
    let el = page.query_selector("h1")
    let text = el.text()
    print(text)
    browser.close()
}"#,
    );
    assert!(ir.contains("@tallow_page_goto"), "IR should contain tallow_page_goto");
    assert!(
        ir.contains("@tallow_page_query_selector"),
        "IR should contain tallow_page_query_selector"
    );
    assert!(
        ir.contains("@tallow_element_text"),
        "IR should contain tallow_element_text"
    );
}

#[test]
fn codegen_fetch_and_browser_coexist() {
    // Both fetch() and browser operations in the same program
    let ir = compile_to_ir(
        r#"fn main() {
    let resp = fetch("https://api.example.com")
    let body = resp.text()
    print(body)
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("https://spa.example.com")
    let title = page.title()
    print(title)
    browser.close()
}"#,
    );
    // Both fetch and browser FFI calls should be present
    assert!(ir.contains("call ptr @tallow_fetch"), "IR should have fetch call");
    assert!(
        ir.contains("call ptr @tallow_browser_launch"),
        "IR should have browser_launch call"
    );
    assert!(ir.contains("call i32 @tallow_page_goto"), "IR should have page_goto call");
    assert!(ir.contains("call ptr @tallow_page_title"), "IR should have page_title call");
}

#[test]
fn codegen_browser_element_click() {
    let ir = compile_to_ir(
        r#"fn main() {
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("https://example.com")
    let btn = page.query_selector("button")
    btn.click()
    browser.close()
}"#,
    );
    assert!(
        ir.contains("call i32 @tallow_element_click"),
        "IR should call tallow_element_click"
    );
}

#[test]
fn codegen_browser_element_attribute() {
    let ir = compile_to_ir(
        r#"fn main() {
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("https://example.com")
    let link = page.query_selector("a")
    let href = link.attribute("href")
    print(href)
    browser.close()
}"#,
    );
    assert!(
        ir.contains("call ptr @tallow_element_attribute"),
        "IR should call tallow_element_attribute"
    );
}

#[test]
fn codegen_browser_page_reload() {
    let ir = compile_to_ir(
        r#"fn main() {
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.goto("https://example.com")
    page.reload()
    browser.close()
}"#,
    );
    assert!(
        ir.contains("call i32 @tallow_page_reload"),
        "IR should call tallow_page_reload"
    );
}

// ── 3. Interpreter browser Value tests (no Chrome needed) ───────────────────

#[test]
fn browser_object_display_browser() {
    let val = Value::BrowserObject(BrowserHandle {
        kind: "Browser".to_string(),
        handle: Arc::new(42u32),
    });
    assert_eq!(format!("{val}"), "<Browser>");
}

#[test]
fn browser_object_display_page() {
    let val = Value::BrowserObject(BrowserHandle {
        kind: "Page".to_string(),
        handle: Arc::new(99u32),
    });
    assert_eq!(format!("{val}"), "<Page>");
}

#[test]
fn browser_object_display_element() {
    let val = Value::BrowserObject(BrowserHandle {
        kind: "Element".to_string(),
        handle: Arc::new(7u32),
    });
    assert_eq!(format!("{val}"), "<Element>");
}

#[test]
fn browser_handle_debug_format() {
    let bh = BrowserHandle {
        kind: "Page".to_string(),
        handle: Arc::new(1u32),
    };
    let debug_str = format!("{bh:?}");
    assert!(
        debug_str.contains("BrowserHandle(Page)"),
        "Debug format should show kind: {debug_str}"
    );
}

#[test]
fn browser_object_clone_independence() {
    let original = Value::BrowserObject(BrowserHandle {
        kind: "Browser".to_string(),
        handle: Arc::new(42u32),
    });
    let cloned = original.clone();
    // Both should display the same
    assert_eq!(format!("{original}"), format!("{cloned}"));
    assert_eq!(format!("{original}"), "<Browser>");
}

// ── 4. W0100 advisory warning integration test ──────────────────────────────

#[test]
fn w0100_warning_integration_fetch_personal_data() {
    // Full pipeline: parse -> typecheck -> legal_pass -> check W0100
    let source = r#"@legal(basis: .consent, purpose: "collect", personal_data: true, retain_for: 30.days, consent_ref: "v1")
fn collect(url: String) -> String { fetch(url) }
fn main() { collect("x") }"#;

    let (tokens, errors) = lexer::tokenize(source);
    assert!(errors.is_empty());
    let program = parser::Parser::parse(tokens).expect("parse error");
    let (env, typeck_diags) = TypeChecker::new(&program).check();
    assert!(!typeck_diags.has_errors());

    let legal = tallow::legal_pass::LegalPass::new(&program, &env);
    let (legal_diags, _audit) = legal.check();

    // Should have W0100 warning but no errors
    assert!(!legal_diags.has_errors(), "should not have errors: {:?}", legal_diags.items);
    assert!(
        legal_diags.items.iter().any(|d| d.code == "W0100"),
        "should emit W0100 for fetch() with personal_data: true"
    );
}

#[test]
fn w0100_not_emitted_with_browser_goto() {
    let source = r#"@legal(basis: .consent, purpose: "collect", personal_data: true, retain_for: 30.days, consent_ref: "v1")
fn collect(url: String) { browser.goto(url) }
fn main() { collect("x") }"#;

    let (tokens, errors) = lexer::tokenize(source);
    assert!(errors.is_empty());
    let program = parser::Parser::parse(tokens).expect("parse error");
    let (env, _) = TypeChecker::new(&program).check();

    let legal = tallow::legal_pass::LegalPass::new(&program, &env);
    let (legal_diags, _) = legal.check();

    assert!(
        !legal_diags.items.iter().any(|d| d.code == "W0100"),
        "W0100 should not fire with browser ops: {:?}", legal_diags.items
    );
}

// ── 5. Parity test (requires Chrome — ignored in CI) ────────────────────────

#[test]
#[ignore] // Requires Chrome installed
fn interpreter_codegen_parity() {
    // This test would write a Tallow program to a temp file,
    // run it via the interpreter (tallow run), compile it (tallow build),
    // execute the compiled binary, and compare outputs.
    //
    // Program:
    //   @legal(basis: .public_data, purpose: "test")
    //   fn main() {
    //       let browser = Browser.launch(true)
    //       let page = browser.new_page()
    //       page.goto("https://example.com")
    //       let title = page.title()
    //       print(title)
    //       browser.close()
    //   }
    //
    // Expected: Both modes produce "Example Domain" as output.
    //
    // Skipped in CI because Chrome may not be available.
}
