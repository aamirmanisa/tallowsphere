//! Integration tests for math and env stdlib functions (Phase 12-01).
//!
//! Verifies:
//! 1. New math functions: tan, round, log2, log10, tau, infinity, nan
//! 2. New env functions: set, all
//! 3. Backward compatibility with existing inline implementations

use tallow::interp::Interpreter;
use tallow::lexer;
use tallow::parser;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn run_output(source: &str) -> Vec<String> {
    let (tokens, lex_errors) = lexer::tokenize(source);
    assert!(lex_errors.is_empty(), "lex errors: {lex_errors:?}");
    let program = parser::Parser::parse(tokens).expect("parse error");
    let mut interp = Interpreter::new();
    interp.run(&program).expect("runtime error");
    interp.output
}

fn run_ok(source: &str) {
    let (tokens, lex_errors) = lexer::tokenize(source);
    assert!(lex_errors.is_empty(), "lex errors: {lex_errors:?}");
    let program = parser::Parser::parse(tokens).expect("parse error");
    let mut interp = Interpreter::new();
    interp.run(&program).expect("runtime error");
}

// ── Math tests ───────────────────────────────────────────────────────────────

#[test]
fn test_math_tan_zero() {
    let out = run_output(
        r#"fn main() {
            let x = math.tan(0.0)
            print(x)
        }"#,
    );
    assert_eq!(out, vec!["0"]);
}

#[test]
fn test_math_tan_int_arg() {
    // tan(0) with Int argument should also work (Int -> f64 conversion)
    let out = run_output(
        r#"fn main() {
            let x = math.tan(0)
            print(x)
        }"#,
    );
    assert_eq!(out, vec!["0"]);
}

#[test]
fn test_math_round_up() {
    let out = run_output(
        r#"fn main() {
            let x = math.round(2.7)
            print(x)
        }"#,
    );
    assert_eq!(out, vec!["3"]);
}

#[test]
fn test_math_round_down() {
    let out = run_output(
        r#"fn main() {
            let x = math.round(2.3)
            print(x)
        }"#,
    );
    assert_eq!(out, vec!["2"]);
}

#[test]
fn test_math_round_negative() {
    let out = run_output(
        r#"fn main() {
            let x = math.round(-1.6)
            print(x)
        }"#,
    );
    assert_eq!(out, vec!["-2"]);
}

#[test]
fn test_math_round_int_passthrough() {
    // Rounding an Int should return the same Int
    let out = run_output(
        r#"fn main() {
            let x = math.round(5)
            print(x)
        }"#,
    );
    assert_eq!(out, vec!["5"]);
}

#[test]
fn test_math_log2() {
    let out = run_output(
        r#"fn main() {
            let x = math.log2(8.0)
            print(x)
        }"#,
    );
    assert_eq!(out, vec!["3"]);
}

#[test]
fn test_math_log10() {
    let out = run_output(
        r#"fn main() {
            let x = math.log10(1000.0)
            print(x)
        }"#,
    );
    // log10(1000) = 3.0, which prints as "3"
    assert_eq!(out, vec!["3"]);
}

#[test]
fn test_math_tau() {
    let out = run_output(
        r#"fn main() {
            let x = math.tau()
            print(x)
        }"#,
    );
    assert!(
        out[0].starts_with("6.283"),
        "math.tau should be ~6.283185, got: {}",
        out[0]
    );
}

#[test]
fn test_math_infinity() {
    let out = run_output(
        r#"fn main() {
            let x = math.infinity()
            print(x)
        }"#,
    );
    assert_eq!(out, vec!["inf"]);
}

#[test]
fn test_math_nan() {
    let out = run_output(
        r#"fn main() {
            let x = math.nan()
            print(x)
        }"#,
    );
    assert_eq!(out, vec!["NaN"]);
}

// ── Math backward compatibility ──────────────────────────────────────────────

#[test]
fn test_math_existing_sin_still_works() {
    let out = run_output(
        r#"fn main() {
            let x = math.sin(0.0)
            print(x)
        }"#,
    );
    assert_eq!(out, vec!["0"]);
}

#[test]
fn test_math_existing_pi_still_works() {
    let out = run_output(
        r#"fn main() {
            let x = math.pi()
            print(x)
        }"#,
    );
    assert!(
        out[0].starts_with("3.14"),
        "math.pi should be ~3.14159, got: {}",
        out[0]
    );
}

// ── Env tests ────────────────────────────────────────────────────────────────

#[test]
fn test_env_set_and_get() {
    let out = run_output(
        r#"fn main() {
            env.set("TALLOW_TEST_12_01", "hello_from_tallow")
            let val = env.get("TALLOW_TEST_12_01")
            print(val)
        }"#,
    );
    assert_eq!(out, vec!["hello_from_tallow"]);
}

#[test]
fn test_env_all_returns_map() {
    // env.all() should run without error and return a Map.
    // We can't check exact contents since env varies, but we verify it works.
    run_ok(
        r#"fn main() {
            let m = env.all()
        }"#,
    );
}

// ── Env backward compatibility ───────────────────────────────────────────────

#[test]
fn test_env_cwd_still_works() {
    let out = run_output(
        r#"fn main() {
            let cwd = env.cwd()
            print(cwd)
        }"#,
    );
    assert!(!out[0].is_empty(), "env.cwd() should return non-empty path");
}

#[test]
fn test_env_home_still_works() {
    let out = run_output(
        r#"fn main() {
            let home = env.home()
            print(home)
        }"#,
    );
    assert!(!out[0].is_empty(), "env.home() should return non-empty path");
}

#[test]
fn test_env_args_still_works() {
    run_ok(
        r#"fn main() {
            let a = env.args()
        }"#,
    );
}
