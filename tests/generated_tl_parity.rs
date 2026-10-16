//! Generated TL compiler/interpreter parity tests.
//!
//! These tests pin the language features emitted by generated legacy request
//! scripts so generated packages cannot rely on untested parser/typechecker/
//! interpreter/codegen behavior.

use tallow::codegen::CodeGen;
use tallow::error::Diagnostics;
use tallow::interp::Interpreter;
use tallow::legal_pass::LegalPass;
use tallow::lexer;
use tallow::parser;
use tallow::typeck::{TypeChecker, TypeEnv};

const GENERATED_HTTP_BATCH_FIXTURE: &str = r#"
import tallow.http

@legal(basis: .public_data, purpose: "generated parity fixture")
@cra_class(.L1)
fn main() {
    let target_urls = ["http://127.0.0.1:9/alpha", "http://127.0.0.1:9/beta"]
    let headers = {"Accept": "text/plain", "User-Agent": "tallow-generated-parity"}
    let l1_concurrency = 2
    let responses = http.batch(target_urls, l1_concurrency, headers)
    print("legacy transport request count=" + responses.len.to_string())
}
"#;

const GENERATED_LOCAL_FEATURE_FIXTURE: &str = r#"
@legal(basis: .public_data, purpose: "generated local parity fixture")
@cra_class(.L1)
fn main() {
    let target_urls = ["https://example.test/alpha", "https://example.test/beta"]
    let headers = {"Accept": "text/plain", "User-Agent": "tallow-generated-parity"}
    let l1_concurrency = 4
    print("generated features=" + target_urls.len.to_string() + ":" + l1_concurrency.to_string())
    print("header keys=" + headers.len.to_string())
}
"#;

fn parse_program(source: &str) -> tallow::ast::Program {
    let (tokens, lex_errors) = lexer::tokenize(source);
    assert!(lex_errors.is_empty(), "lex errors: {lex_errors:?}");
    parser::Parser::parse(tokens).expect("parse error")
}

fn typecheck_and_legal(source: &str) -> (tallow::ast::Program, TypeEnv, Diagnostics) {
    let program = parse_program(source);
    let (env, typeck_diags) = TypeChecker::new(&program).check();
    let (legal_diags, _audit) = LegalPass::new(&program, &env).check();
    let mut all_diags = Diagnostics::new();
    all_diags.items.extend(typeck_diags.items);
    all_diags.items.extend(legal_diags.items);
    (program, env, all_diags)
}

fn run_interpreter_output(program: &tallow::ast::Program) -> Vec<String> {
    let mut interpreter = Interpreter::new();
    interpreter.run(program).expect("interpreter runtime error");
    interpreter.output
}

#[test]
fn generated_legacy_http_batch_fixture_checks_and_interprets() {
    let (program, _env, diags) = typecheck_and_legal(GENERATED_HTTP_BATCH_FIXTURE);
    assert!(
        !diags.has_errors(),
        "generated http.batch fixture should typecheck/legal-pass cleanly: {:?}",
        diags.items
    );
    assert!(
        diags
            .items
            .iter()
            .all(|diag| diag.code != "W-stdlib-import-missing"),
        "canonical import should suppress stdlib import warning: {:?}",
        diags.items
    );

    let output = run_interpreter_output(&program);
    assert_eq!(
        output,
        vec!["legacy transport request count=2".to_string()],
        "interpreter must preserve generated array/map/int/string/method/namespace semantics"
    );
}

#[test]
fn generated_http_batch_without_legal_annotation_fails_legal_pass() {
    let unannotated = GENERATED_HTTP_BATCH_FIXTURE.replace(
        "@legal(basis: .public_data, purpose: \"generated parity fixture\")\n",
        "",
    );
    let (_program, _env, diags) = typecheck_and_legal(&unannotated);
    assert!(
        diags.has_errors(),
        "unannotated network fixture should fail"
    );
    assert!(
        diags.items.iter().any(|diag| diag.code == "E0100"),
        "missing @legal should produce E0100, got: {:?}",
        diags.items
    );
}

#[test]
fn generated_local_feature_matrix_interprets_and_codegen_accepts_supported_syntax() {
    let (program, env, diags) = typecheck_and_legal(GENERATED_LOCAL_FEATURE_FIXTURE);
    assert!(
        !diags.has_errors(),
        "local generated syntax fixture should pass checks: {:?}",
        diags.items
    );

    let output = run_interpreter_output(&program);
    assert_eq!(
        output,
        vec![
            "generated features=2:4".to_string(),
            "header keys=2".to_string(),
        ]
    );

    let mut codegen = CodeGen::new(&program, &env);
    let ir = codegen
        .emit_module()
        .expect("supported generated local syntax should emit LLVM IR");
    assert!(
        ir.contains("generated features="),
        "IR should include generated string literal"
    );
}

#[test]
fn generated_http_batch_codegen_boundary_is_explicit() {
    let (program, env, diags) = typecheck_and_legal(GENERATED_HTTP_BATCH_FIXTURE);
    assert!(
        !diags.has_errors(),
        "fixture should pass before codegen boundary is checked: {:?}",
        diags.items
    );

    let mut codegen = CodeGen::new(&program, &env);
    let err = codegen
        .emit_module()
        .expect_err("http.batch codegen must fail explicitly until compiled parity exists");
    assert!(
        err.contains("http.batch") && err.contains("compiled mode") && err.contains("tallow run"),
        "unsupported codegen diagnostic should identify http.batch and remediation, got: {err}"
    );
}
