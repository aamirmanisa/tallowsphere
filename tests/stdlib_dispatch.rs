//! Integration tests for stdlib dispatch infrastructure.
//!
//! Tests the full pipeline: lex -> parse -> typecheck -> interpret/privacy-check
//! Verifies:
//! 1. Module-qualified calls route through stdlib dispatch
//! 2. Backward compatibility with existing builtins (db.*, KeyPair.*, fetch, print)
//! 3. Privacy pass catches secret/private data in I/O sinks (fs.write_file, log.info)
//! 4. Typeck detects http.get/http.post as network-touching (requiring @legal)

use tallow::interp::Interpreter;
use tallow::legal_pass::LegalPass;
use tallow::lexer;
use tallow::parser;
use tallow::privacy_pass::PrivacyPass;
use tallow::typeck::TypeChecker;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn run_interp(source: &str) -> Result<tallow::interp::Value, tallow::interp::RuntimeError> {
    let (tokens, lex_errors) = lexer::tokenize(source);
    assert!(lex_errors.is_empty(), "lex errors: {lex_errors:?}");
    let program = parser::Parser::parse(tokens).expect("parse error");
    let mut interp = Interpreter::new();
    interp.run(&program)
}

fn run_interp_output(source: &str) -> (tallow::interp::Value, Vec<String>) {
    let (tokens, lex_errors) = lexer::tokenize(source);
    assert!(lex_errors.is_empty(), "lex errors: {lex_errors:?}");
    let program = parser::Parser::parse(tokens).expect("parse error");
    let mut interp = Interpreter::new();
    let result = interp.run(&program).unwrap();
    (result, interp.output)
}

fn run_privacy_pass(source: &str) -> tallow::error::Diagnostics {
    let (tokens, _) = lexer::tokenize(source);
    let program = parser::Parser::parse(tokens).unwrap();
    let (env, _) = TypeChecker::new(&program).check();
    PrivacyPass::new(&program, &env).check()
}

fn run_legal_pass(source: &str) -> tallow::error::Diagnostics {
    let (tokens, errors) = lexer::tokenize(source);
    assert!(errors.is_empty(), "lex errors: {errors:?}");
    let program = parser::Parser::parse(tokens).expect("parse error");
    let (env, _) = TypeChecker::new(&program).check();
    let (diags, _) = LegalPass::new(&program, &env).check();
    diags
}

// ── 1. Dispatch routing tests ────────────────────────────────────────────────

#[test]
fn stdlib_dispatch_fs_read_file_routes_through_stdlib() {
    // fs.read_file is now implemented in stdlib/fs.rs (Phase 12-05).
    // Reading a nonexistent file should produce fs.read_file error, NOT "undefined function".
    let result = run_interp(
        r#"
        fn main() {
            fs.read_file("__nonexistent_test_file__.txt")
        }
        "#,
    );
    assert!(result.is_err(), "fs.read_file on missing file should error");
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("fs.read_file"),
        "Expected 'fs.read_file' error, got: {err_msg}"
    );
    assert!(
        !err_msg.contains("undefined function"),
        "Should NOT be 'undefined function' error, got: {err_msg}"
    );
}

#[test]
fn stdlib_dispatch_fs_write_file_works() {
    // fs.write_file is now implemented (Phase 12-05). Writing to a valid temp path should work.
    let tmp = std::env::temp_dir().join("tallow_dispatch_test.txt");
    let path_str = tmp.to_string_lossy().replace('\\', "/");
    let result = run_interp(
        &format!(
            r#"
            fn main() {{
                fs.write_file("{path_str}", "dispatch test")
            }}
            "#
        ),
    );
    assert!(result.is_ok(), "fs.write_file should succeed: {:?}", result.err());
    let content = std::fs::read_to_string(&tmp).expect("file should exist");
    assert_eq!(content, "dispatch test");
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn stdlib_dispatch_math_tan_now_works() {
    // math.tan is now implemented in stdlib/math.rs (Phase 12-01).
    let result = run_interp(
        r#"
        fn main() {
            let x = math.tan(0.0)
            print(x)
        }
        "#,
    );
    assert!(result.is_ok(), "math.tan should work: {:?}", result.err());
}

// ── 2. Backward compatibility tests ──────────────────────────────────────────

#[test]
fn backward_compat_db_memory_still_works() {
    // db.memory() is an existing builtin -- NOT a stdlib module function.
    // The dispatch hook should return None for "db" (unknown module),
    // letting it fall through to the existing match arm.
    let (_, output) = run_interp_output(
        r#"
        fn main() {
            let conn = db.memory()
            print("db ok")
        }
        "#,
    );
    assert_eq!(output, vec!["db ok"]);
}

#[test]
fn backward_compat_fs_exists_still_works() {
    // fs.exists is implemented inline in interp.rs. The stdlib stub returns
    // None for it, so it falls through to the inline implementation.
    let (_, output) = run_interp_output(
        r#"
        fn main() {
            print(fs.exists("/nonexistent_path_99999"))
        }
        "#,
    );
    assert_eq!(output, vec!["false"]);
}

#[test]
fn backward_compat_math_sqrt_still_works() {
    let (_, output) = run_interp_output(
        r#"
        fn main() {
            print(math.sqrt(9.0))
        }
        "#,
    );
    assert_eq!(output, vec!["3"]);
}

#[test]
fn backward_compat_log_info_still_works() {
    let (_, output) = run_interp_output(
        r#"
        fn main() {
            log.info("test message")
        }
        "#,
    );
    assert_eq!(output.len(), 1);
    assert!(output[0].starts_with("[INFO] ["), "should have structured format: {}", output[0]);
    assert!(output[0].ends_with("] test message"), "should end with message: {}", output[0]);
}

#[test]
fn backward_compat_time_now_still_works() {
    let result = run_interp(
        r#"
        fn main() {
            let t = time.now()
        }
        "#,
    );
    assert!(result.is_ok(), "time.now() should work: {:?}", result.err());
}

#[test]
fn backward_compat_json_parse_still_works() {
    // Build JSON from a map literal, then parse it back — avoids escape issues
    let (_, output) = run_interp_output(
        r#"fn main() {
            let m = {"x": 42}
            let s = m.to_json()
            let result = json.parse(s)
            if let Ok(data) = result {
                print("json ok")
            }
        }"#,
    );
    assert_eq!(output, vec!["json ok"]);
}

// ── 3. Privacy violation tests (I/O sinks) ───────────────────────────────────

#[test]
fn privacy_fs_write_file_with_secret_is_error() {
    // Writing a secret type to a file should be caught by the privacy pass.
    let diags = run_privacy_pass(
        r#"
        type Password = secret String
        fn leak(pw: Password) {
            fs.write_file("log.txt", pw)
        }
        "#,
    );
    assert!(
        diags.has_errors(),
        "fs.write_file with secret should produce privacy error"
    );
    let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E0201").collect();
    assert!(
        !errors.is_empty(),
        "Expected E0201 (secret type cannot be serialized), got: {:?}",
        diags.items
    );
}

#[test]
fn privacy_fs_write_file_with_private_is_error() {
    let diags = run_privacy_pass(
        r#"
        type Email = private String
        fn leak(email: Email) {
            fs.write_file("log.txt", email)
        }
        "#,
    );
    assert!(
        diags.has_errors(),
        "fs.write_file with private type should produce privacy error"
    );
    let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E0200").collect();
    assert!(
        !errors.is_empty(),
        "Expected E0200 (private type cannot be logged), got: {:?}",
        diags.items
    );
}

#[test]
fn privacy_log_info_with_private_is_error() {
    // Logging a private type without .redact()/.hash() should be caught.
    let diags = run_privacy_pass(
        r#"
        type Email = private String
        fn leak(email: Email) {
            log.info(email)
        }
        "#,
    );
    assert!(
        diags.has_errors(),
        "log.info with private type should produce privacy error"
    );
    let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E0200").collect();
    assert!(
        !errors.is_empty(),
        "Expected E0200 (private type cannot be logged), got: {:?}",
        diags.items
    );
}

#[test]
fn privacy_log_info_with_redacted_is_ok() {
    // Using .redact() on a private type before logging is the SAFE path.
    let diags = run_privacy_pass(
        r#"
        type Email = private String
        fn safe_log(email: Email) {
            log.info(email.redact())
        }
        "#,
    );
    assert!(
        !diags.has_errors(),
        "log.info with .redact() should NOT produce error: {:?}",
        diags.items
    );
}

// ── 4. Network detection tests (typeck) ──────────────────────────────────────

#[test]
fn typeck_http_get_requires_legal_annotation() {
    // A function containing http.get() without @legal should produce a legal error.
    // The typeck pass marks the function as network-touching, then the legal pass
    // produces E0100 for missing @legal.
    let diags = run_legal_pass(
        r#"fn scrape(url: String) -> String {
            http.get(url)
        }"#,
    );
    assert!(
        diags.has_errors(),
        "http.get without @legal should produce error"
    );
    let legal_errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E0100").collect();
    assert!(
        !legal_errors.is_empty(),
        "Expected E0100 (missing @legal), got: {:?}",
        diags.items
    );
}

#[test]
fn typeck_http_post_requires_legal_annotation() {
    let diags = run_legal_pass(
        r#"fn send_data(url: String) {
            http.post(url)
        }"#,
    );
    assert!(
        diags.has_errors(),
        "http.post without @legal should produce error"
    );
    let legal_errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E0100").collect();
    assert!(
        !legal_errors.is_empty(),
        "Expected E0100, got: {:?}",
        diags.items
    );
}

#[test]
fn typeck_http_get_with_legal_is_ok() {
    // Adding @legal annotation should satisfy the requirement.
    let diags = run_legal_pass(
        r#"@legal(basis: .public_data, purpose: "test")
        fn scrape(url: String) -> String {
            http.get(url)
        }"#,
    );
    assert!(
        !diags.has_errors(),
        "http.get with @legal should not produce error: {:?}",
        diags.items
    );
}

#[test]
fn typeck_net_connect_requires_legal_annotation() {
    let diags = run_legal_pass(
        r#"fn connect_to(host: String) {
            net.connect(host)
        }"#,
    );
    assert!(
        diags.has_errors(),
        "net.connect without @legal should produce error"
    );
    let legal_errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E0100").collect();
    assert!(
        !legal_errors.is_empty(),
        "Expected E0100, got: {:?}",
        diags.items
    );
}

// ── FIX12 namespace + contract-parity regression (2026-08-27) ────────────────
//
// The FIX12 triage registered 56 orphaned stdlib modules in the dispatch
// router, but the interp's hardcoded lowercase-namespace list was not
// extended, so bare `csv.read()` / `decimal.decimal_add()` / etc. failed
// with "undefined variable". is_registered_module() now backs the interp
// fallback, and the flat functions declared in stdlib/*.tl dispatch for real.

#[test]
fn fix12_bare_csv_namespace_resolves() {
    // Previously: runtime error "undefined variable: csv".
    let result = run_interp(
        r#"
        fn main() {
            let rows = csv.parse_string("a,b\n1,2\n3,4", true)
            print(rows)
        }"#,
    );
    assert!(result.is_ok(), "csv.parse_string should dispatch: {result:?}");
}

#[test]
fn fix12_bare_decimal_namespace_resolves() {
    let result = run_interp(
        r#"
        fn main() {
            let s = decimal.decimal_add("1.50", "2.25", 4)
            print(s)
        }"#,
    );
    assert!(result.is_ok(), "decimal.decimal_add should dispatch: {result:?}");
}

#[test]
fn fix12_bare_finance_namespace_resolves() {
    let result = run_interp(
        r#"
        fn main() {
            let cr = finance.current_ratio(120.0, 60.0)
            print(cr)
        }"#,
    );
    assert!(result.is_ok(), "finance.current_ratio should dispatch: {result:?}");
}

#[test]
fn fix12_bare_heston_namespace_resolves() {
    let result = run_interp(
        r#"
        fn main() {
            let p = heston.price("call", 100.0, 0.05, 1.0, 0.04, 0.04, 0.02, 1.0, 0.0, 0.5)
            print(p)
        }"#,
    );
    assert!(result.is_ok(), "heston.price should dispatch: {result:?}");
}

#[test]
fn fix12_decimal_flat_api_values() {
    let (value, output) = run_interp_output(
        r#"
        fn main() {
            let s = decimal.decimal_add("1.50", "2.25", 4)
            print(s)
            let c = decimal.decimal_cmp("1.50", "1.50", 4)
            print(c)
            let r = decimal.decimal_round("3.14159", 5, 2)
            print(r)
        }"#,
    );
    assert!(
        output.iter().any(|l| l.contains("3.7500")),
        "decimal_add should produce 3.7500, got: {output:?}"
    );
    assert!(
        output.iter().any(|l| l.trim() == "0"),
        "decimal_cmp(equal) should produce 0, got: {output:?}"
    );
    assert!(
        output.iter().any(|l| l.contains("3.14")),
        "decimal_round(3.14159,5,2) should produce 3.14, got: {output:?}"
    );
}

#[test]
fn fix12_finance_flat_api_values() {
    let (value, output) = run_interp_output(
        r#"
        fn main() {
            let cr = finance.current_ratio(120.0, 60.0)
            print(cr)
            let gm = finance.gross_margin(1000.0, 600.0)
            print(gm)
            let eps = finance.eps(500.0, 100)
            print(eps)
        }"#,
    );
    assert!(
        output.iter().any(|l| l.trim() == "2"),
        "current_ratio(120,60) should be 2, got: {output:?}"
    );
    assert!(
        output.iter().any(|l| l.trim() == "0.4"),
        "gross_margin(1000,600) should be 0.4, got: {output:?}"
    );
    assert!(
        output.iter().any(|l| l.trim() == "5"),
        "eps(500,100) should be 5, got: {output:?}"
    );
}

#[test]
fn fix12_unknown_module_still_undefined_var() {
    // Non-registered names must keep failing as undefined variables
    // (not accidentally resolved as module namespaces).
    let result = run_interp(
        r#"
        fn main() {
            let x = not_a_module.foo()
        }"#,
    );
    assert!(result.is_err(), "unknown module should stay an error");
    let err = format!("{:?}", result.err().unwrap());
    assert!(
        err.to_lowercase().contains("undefinedvar"),
        "expected undefined variable, got: {err}"
    );
}

// ── P1-fix (2026-09-16): single-file stdlib class namespaces ────────────────

#[test]
fn p1_single_file_class_namespaces_resolve() {
    // CookieJar / RateLimiter / TLSProfile / CAPTCHA class-style calls, plus
    // the lowercase module-style surface (cookie_jar.new()). These carried
    // .tl declarations but no sentinel/routing, so every call failed with
    // "undefined variable" before the 2026-09-16 wiring.
    let (result, output) = run_interp_output(
        r#"
        fn main() {
            let j = CookieJar.new()
            let h = j.to_header("example.com")
            let r = RateLimiter.new(1.0)
            let ok = r.try_acquire()
            let ps = TLSProfile.list()
            let blk = CAPTCHA.is_blocked(200, "")
            let m = cookie_jar.new()
            let h2 = m.to_header("example.com")
            print("classes-ok")
        }"#,
    );
    assert!(
        output.iter().any(|l| l.trim() == "classes-ok"),
        "class namespaces should all resolve; output: {output:?}, result: {result:?}"
    );
}

#[test]
fn p1_ws_and_inbox_class_namespaces_resolve() {
    // Network classes resolve without "undefined variable"; the calls fail
    // fast at the transport (dead port / refused), proving resolution.
    let ws = run_interp(
        r#"
        fn main() {
            let w = WS.connect("ws://127.0.0.1:9/nope")
        }"#,
    );
    let msg = format!("{}", ws.expect_err("ws connect to a dead port must error"));
    assert!(!msg.contains("undefined variable"), "WS.connect must resolve: {msg}");

    let imap = run_interp(
        r#"
        fn main() {
            let i = Inbox.connect_imap("127.0.0.1", 9, false)
        }"#,
    );
    let msg = format!("{}", imap.expect_err("imap connect to a dead port must error"));
    assert!(
        !msg.contains("undefined variable"),
        "Inbox.connect_imap must resolve: {msg}"
    );
}

