//! HackTheCart kinds must be constructible from Tallow source (register #96).
//!
//! `dispatch_hackthecart_static` keys on a dotted call name such as
//! `AdaptiveCrawler.new`. Before the interpreter's method-call path learned to
//! route an unbound, capitalised receiver there, every program that wrote
//! `AdaptiveCrawler.new()` died with `undefined variable: AdaptiveCrawler` and
//! the whole surface — including the method lowerings — was unreachable. These
//! tests pin the reachability, not the dispatch table (which has its own unit
//! tests).

use tallow::interp::{Interpreter, Value};
use tallow::lexer;
use tallow::parser;

fn run(source: &str) -> Result<Value, tallow::interp::RuntimeError> {
    let (tokens, lex_errors) = lexer::tokenize(source);
    assert!(lex_errors.is_empty(), "lex errors: {lex_errors:?}");
    let program = parser::Parser::parse(tokens).expect("parse error");
    let mut interp = Interpreter::new();
    interp.run(&program)
}

/// The value a `Kind.new()` call returns, with the `Ok` wrapper removed.
fn browser_kind(value: &Value) -> (&str, String) {
    let inner = match value {
        Value::Ok(inner) => inner.as_ref(),
        other => other,
    };
    match inner {
        Value::BrowserObject(handle) => (handle.kind.as_str(), format!("{inner:?}")),
        other => panic!("expected a BrowserObject, got {other:?}"),
    }
}

#[test]
fn adaptive_crawler_new_is_reachable_from_source() {
    let value = run(r#"fn main() -> String { let c = AdaptiveCrawler.new() c }"#)
        .expect("AdaptiveCrawler.new() must construct");
    let (kind, _) = browser_kind(&value);
    assert_eq!(kind, "AdaptiveCrawler");
}

#[test]
fn quality_validator_and_product_matcher_are_reachable_from_source() {
    for name in ["QualityValidator", "ProductMatcher", "BasketOptimizer"] {
        let source = format!("fn main() -> String {{ let c = {name}.new() c }}");
        let value = run(&source).unwrap_or_else(|e| panic!("{name}.new() failed: {e}"));
        let (kind, _) = browser_kind(&value);
        assert_eq!(kind, name);
    }
}

#[test]
fn an_unbound_capitalised_receiver_is_still_an_error_when_not_a_kind() {
    // The routing is keyed on the dispatcher's table, not on capitalisation:
    // a name that is not in it must keep failing loudly rather than becoming a
    // silent nil.
    let err = run(r#"fn main() -> String { let c = NotAThing.new() c }"#)
        .expect_err("an unknown kind must not construct");
    let message = format!("{err}");
    assert!(
        message.contains("NotAThing") || message.contains("undefined"),
        "unexpected error: {message}"
    );
}

#[test]
fn a_bound_variable_shadows_the_kind_name() {
    // If a real binding exists, `x.new()` is a method call on that value and
    // must not be diverted into the static dispatcher.
    let err = run(
        r#"fn main() -> String {
            let AdaptiveCrawler = "not-a-kind"
            let c = AdaptiveCrawler.new()
            c
        }"#,
    )
    .expect_err("a bound receiver must not reach the static dispatcher");
    let _ = err;
}
