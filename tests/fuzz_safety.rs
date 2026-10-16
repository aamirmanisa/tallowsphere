//! Safety tests: verify lexer, parser, and interpreter never panic on
//! malformed, adversarial, or random-shaped input.
//!
//! These simulate what a fuzzer would do but run as normal tests on all
//! platforms (including Windows where cargo-fuzz / libfuzzer is unavailable).

use std::panic;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Run a closure and assert it does not panic.
fn must_not_panic(label: &str, f: impl FnOnce() + panic::UnwindSafe) {
    let result = panic::catch_unwind(f);
    assert!(
        result.is_ok(),
        "PANIC on input: {label}"
    );
}

// ── Lexer Safety ─────────────────────────────────────────────────────────────

#[test]
fn lexer_does_not_panic_on_empty_and_whitespace() {
    let inputs = ["", " ", "\t", "\n", "\r\n", "   \n\t  \r\n"];
    for input in &inputs {
        must_not_panic(input, || {
            let _ = tallow::lexer::tokenize(input);
        });
    }
}

#[test]
fn lexer_does_not_panic_on_null_bytes_and_control_chars() {
    let inputs = [
        "\0",
        "\x00\x01\x02\x03\x04\x05\x06\x07",
        "\x0B\x0C\x0E\x0F",
        "\x7F",
        "\u{FEFF}", // BOM
        "\u{200B}", // zero-width space
        "\u{FFFD}", // replacement character
    ];
    for input in &inputs {
        must_not_panic(&format!("{:?}", input), || {
            let _ = tallow::lexer::tokenize(input);
        });
    }
}

#[test]
fn lexer_does_not_panic_on_unclosed_delimiters() {
    let inputs = [
        "\"unclosed string",
        "'\\",
        "/* unclosed block comment",
        "/* nested /* still unclosed */",
        "\"hello {world",
        "\"hello {",
        "{{{{{{{{{{{",
        "}}}}}}}}}}}",
        "(((((((((((",
        ")))))))))))",
        "[[[[[[[[[[",
        "]]]]]]]]]]",
    ];
    for input in &inputs {
        must_not_panic(input, || {
            let _ = tallow::lexer::tokenize(input);
        });
    }
}

#[test]
fn lexer_does_not_panic_on_number_edge_cases() {
    let inputs = [
        "0",
        "0x",
        "0b",
        "0o",
        "0x_",
        "0b_",
        "0o_",
        "0xGGGG",
        "0b2222",
        "0o9999",
        "123456789012345678901234567890",
        "99999999999999999999999999999999999999999999999999",
        "1.2.3.4.5",
        "1e999",
        "1e-999",
        "0.0e0",
        "1_000_000",
        "1__2",
        "1.",
        ".1",
        "1e",
        "1e+",
        "1e-",
    ];
    for input in &inputs {
        must_not_panic(input, || {
            let _ = tallow::lexer::tokenize(input);
        });
    }
}

#[test]
fn lexer_does_not_panic_on_keyword_fragments() {
    let inputs = [
        "fn fn fn fn fn",
        "let let let",
        "if if if if",
        "struct enum impl trait",
        "match match match",
        "for while in return",
        "@@@@@",
        "@ @ @ @",
        "let = = = =",
        "fn()()()()",
        "-> -> -> ->",
        "=> => => =>",
    ];
    for input in &inputs {
        must_not_panic(input, || {
            let _ = tallow::lexer::tokenize(input);
        });
    }
}

#[test]
fn lexer_does_not_panic_on_unicode() {
    let inputs = [
        "fn 日本語() {}",
        "let π = 3.14",
        "let 변수 = 42",
        "let 中文 = \"测试\"",
        "// コメント",
        "\"emoji: 🚀🎉💯\"",
        "let café = 1",
        "\u{1F600}\u{1F601}\u{1F602}",
        "\"\\u{FFFFFF}\"",
        "\"\\u{110000}\"",
    ];
    for input in &inputs {
        must_not_panic(input, || {
            let _ = tallow::lexer::tokenize(input);
        });
    }
}

#[test]
fn lexer_does_not_panic_on_long_inputs() {
    let long_ident = "a".repeat(100_000);
    must_not_panic("100K char identifier", || {
        let _ = tallow::lexer::tokenize(&long_ident);
    });

    let long_parens = "(".repeat(10_000);
    must_not_panic("10K open parens", || {
        let _ = tallow::lexer::tokenize(&long_parens);
    });

    let long_close = ")".repeat(10_000);
    must_not_panic("10K close parens", || {
        let _ = tallow::lexer::tokenize(&long_close);
    });

    let deep_interp = "\"".to_string() + &"{\"".repeat(500);
    must_not_panic("deep string interpolation nesting", || {
        let _ = tallow::lexer::tokenize(&deep_interp);
    });

    let long_comment = "// ".to_string() + &"x".repeat(100_000);
    must_not_panic("100K char comment", || {
        let _ = tallow::lexer::tokenize(&long_comment);
    });
}

#[test]
fn lexer_does_not_panic_on_operator_soup() {
    let inputs = [
        "+-*/%&|^~!<>",
        "== != <= >= && || << >>",
        "....",
        "..=..=..=",
        "?????????",
        "::::::::",
        ";;;;;;;;",
        ",,,,,,,,,",
        "++--**//",
        "<<<<>>>>",
    ];
    for input in &inputs {
        must_not_panic(input, || {
            let _ = tallow::lexer::tokenize(input);
        });
    }
}

// ── Parser Safety ────────────────────────────────────────────────────────────

#[test]
fn parser_does_not_panic_on_incomplete_declarations() {
    let inputs = [
        "fn",
        "fn(",
        "fn a(",
        "fn a() {",
        "fn a() -> {",
        "fn a() -> { 42 }",
        "fn a(b:) {}",
        "fn a(,) {}",
        "fn a() ->",
        "struct",
        "struct {",
        "struct Foo",
        "struct Foo {",
        "struct Foo { x: }",
        "enum",
        "enum Foo",
        "enum Foo {",
        "impl",
        "impl {",
        "impl Foo",
        "impl Foo {",
        "trait",
        "trait Foo",
        "trait Foo {",
    ];
    for input in &inputs {
        must_not_panic(input, || {
            let (tokens, _) = tallow::lexer::tokenize(input);
            let _ = tallow::parser::Parser::parse(tokens);
        });
    }
}

#[test]
fn parser_does_not_panic_on_incomplete_statements() {
    let inputs = [
        "fn main() { let }",
        "fn main() { let x }",
        "fn main() { let x = }",
        "fn main() { let x = ; }",
        "fn main() { let x: = 5 }",
        "fn main() { return }",
        "fn main() { return ; }",
        "fn main() { var }",
        "fn main() { var x }",
        "fn main() { var x = }",
    ];
    for input in &inputs {
        must_not_panic(input, || {
            let (tokens, _) = tallow::lexer::tokenize(input);
            let _ = tallow::parser::Parser::parse(tokens);
        });
    }
}

#[test]
fn parser_does_not_panic_on_incomplete_control_flow() {
    let inputs = [
        "fn main() { if }",
        "fn main() { if { }",
        "fn main() { if true }",
        "fn main() { if true { } else }",
        "fn main() { match }",
        "fn main() { match x }",
        "fn main() { match x { }",
        "fn main() { for }",
        "fn main() { for in }",
        "fn main() { for x in }",
        "fn main() { while }",
        "fn main() { while { }",
    ];
    for input in &inputs {
        must_not_panic(input, || {
            let (tokens, _) = tallow::lexer::tokenize(input);
            let _ = tallow::parser::Parser::parse(tokens);
        });
    }
}

#[test]
fn parser_does_not_panic_on_annotation_fragments() {
    let inputs = [
        "@",
        "@legal",
        "@legal(",
        "@legal(basis:",
        "@legal(basis: .public_data",
        "@legal(basis: .public_data,",
        "@legal(basis: .public_data, purpose:",
        "@agent_task",
        "@agent_task(",
        "@agent_task(id:",
    ];
    for input in &inputs {
        must_not_panic(input, || {
            let (tokens, _) = tallow::lexer::tokenize(input);
            let _ = tallow::parser::Parser::parse(tokens);
        });
    }
}

#[test]
fn parser_does_not_panic_on_deeply_nested_expressions() {
    // Deep nesting via parens: ((((((((((1))))))))))
    // Use a larger stack since the recursive descent parser creates one
    // Rust stack frame per nesting level.
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024) // 32 MB
        .name("deep-nest-test".to_string())
        .spawn(|| {
            let depth = 200;
            let nested = "(".repeat(depth) + "1" + &")".repeat(depth);
            let source = format!("fn main() {{ let x = {} }}", nested);
            must_not_panic("200-deep nested parens", || {
                let (tokens, _) = tallow::lexer::tokenize(&source);
                let _ = tallow::parser::Parser::parse(tokens);
            });
        })
        .expect("failed to spawn test thread");
    handle.join().expect("deep nesting test thread panicked");
}

#[test]
fn parser_does_not_panic_on_many_functions() {
    let mut source = String::new();
    for i in 0..500 {
        source.push_str(&format!("fn f{}() {{ let x = {} }}\n", i, i));
    }
    must_not_panic("500 function declarations", || {
        let (tokens, _) = tallow::lexer::tokenize(&source);
        let _ = tallow::parser::Parser::parse(tokens);
    });
}

#[test]
fn parser_does_not_panic_on_garbage_token_sequences() {
    let inputs = [
        "} } } } }",
        "] ] ] ] ]",
        ") ) ) ) )",
        "{ { { { {",
        "[ [ [ [ [",
        "( ( ( ( (",
        "fn fn fn fn fn",
        "let let let let let",
        "if if if if if",
        ". . . . .",
        ", , , , ,",
        ": : : : :",
    ];
    for input in &inputs {
        must_not_panic(input, || {
            let (tokens, _) = tallow::lexer::tokenize(input);
            let _ = tallow::parser::Parser::parse(tokens);
        });
    }
}

// ── Interpreter Safety ───────────────────────────────────────────────────────

#[test]
fn interpreter_does_not_panic_on_type_mismatches() {
    let inputs = [
        r#"fn main() { let x = 1 + "hello" }"#,
        r#"fn main() { let x = true / false }"#,
        r#"fn main() { let x = "a" - "b" }"#,
        r#"fn main() { let x = nil + 1 }"#,
        r#"fn main() { let x = [1,2,3] * 2 }"#,
    ];
    for input in &inputs {
        must_not_panic(input, || {
            let (tokens, lex_errors) = tallow::lexer::tokenize(input);
            if !lex_errors.is_empty() { return; }
            if let Ok(program) = tallow::parser::Parser::parse(tokens) {
                let mut interp = tallow::interp::Interpreter::new();
                let _ = interp.run(&program);
            }
        });
    }
}

#[test]
fn interpreter_does_not_panic_on_undefined_references() {
    let inputs = [
        "fn main() { nonexistent_function() }",
        "fn main() { let x = unknown_variable }",
        "fn main() { let x = 5; x.nonexistent_field }",
        "fn main() { let x = 5; x.nonexistent_method() }",
    ];
    for input in &inputs {
        must_not_panic(input, || {
            let (tokens, lex_errors) = tallow::lexer::tokenize(input);
            if !lex_errors.is_empty() { return; }
            if let Ok(program) = tallow::parser::Parser::parse(tokens) {
                let mut interp = tallow::interp::Interpreter::new();
                let _ = interp.run(&program);
            }
        });
    }
}

#[test]
fn interpreter_does_not_panic_on_index_out_of_bounds() {
    let inputs = [
        "fn main() { let x = [1, 2, 3]; x[999] }",
        "fn main() { let x = [1, 2, 3]; x[-1] }",
        "fn main() { let x = []; x[0] }",
        r#"fn main() { let x = "abc"; x[100] }"#,
    ];
    for input in &inputs {
        must_not_panic(input, || {
            let (tokens, lex_errors) = tallow::lexer::tokenize(input);
            if !lex_errors.is_empty() { return; }
            if let Ok(program) = tallow::parser::Parser::parse(tokens) {
                let mut interp = tallow::interp::Interpreter::new();
                let _ = interp.run(&program);
            }
        });
    }
}

#[test]
fn interpreter_does_not_panic_on_division_by_zero() {
    let inputs = [
        "fn main() { let x = 1 / 0 }",
        "fn main() { let x = 1 % 0 }",
        "fn main() { let x = 1.0 / 0.0 }",
        "fn main() { let x = 0 / 0 }",
    ];
    for input in &inputs {
        must_not_panic(input, || {
            let (tokens, lex_errors) = tallow::lexer::tokenize(input);
            if !lex_errors.is_empty() { return; }
            if let Ok(program) = tallow::parser::Parser::parse(tokens) {
                let mut interp = tallow::interp::Interpreter::new();
                let _ = interp.run(&program);
            }
        });
    }
}

#[test]
fn interpreter_does_not_panic_on_empty_main() {
    let input = "fn main() {}";
    must_not_panic(input, || {
        let (tokens, lex_errors) = tallow::lexer::tokenize(input);
        if !lex_errors.is_empty() { return; }
        if let Ok(program) = tallow::parser::Parser::parse(tokens) {
            let mut interp = tallow::interp::Interpreter::new();
            let _ = interp.run(&program);
        }
    });
}

#[test]
fn interpreter_does_not_panic_on_recursive_calls() {
    // The interpreter's exec_block→eval_expr→call_function cycle creates large
    // Rust stack frames in debug builds. Run in a thread with a generous stack
    // to ensure the interpreter's own MAX_CALL_DEPTH fires before Rust overflows.
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024) // 32 MB
        .name("recursion-test".to_string())
        .spawn(|| {
            let input = r#"
fn recurse(n: i32) -> i32 {
    recurse(n + 1)
}
fn main() { recurse(0) }
"#;
            let (tokens, lex_errors) = tallow::lexer::tokenize(input);
            if !lex_errors.is_empty() { return; }
            if let Ok(program) = tallow::parser::Parser::parse(tokens) {
                let mut interp = tallow::interp::Interpreter::new();
                let result = interp.run(&program);
                // Should be an Err (max recursion depth), not a panic
                assert!(result.is_err(), "Expected error from infinite recursion, got Ok");
                let err_msg = format!("{}", result.unwrap_err());
                assert!(
                    err_msg.contains("recursion depth"),
                    "Expected recursion depth error, got: {err_msg}"
                );
            }
        })
        .expect("failed to spawn test thread");
    handle.join().expect("recursion test thread panicked");
}

#[test]
fn interpreter_does_not_panic_on_string_interpolation_edge_cases() {
    let inputs = [
        r#"fn main() { let x = "{}" }"#,
        r#"fn main() { let x = "{ }" }"#,
        r#"fn main() { let x = 42; let y = "value: {x}" }"#,
        r#"fn main() { let x = "nested: {"{inner}"}" }"#,
    ];
    for input in &inputs {
        must_not_panic(input, || {
            let (tokens, lex_errors) = tallow::lexer::tokenize(input);
            if !lex_errors.is_empty() { return; }
            if let Ok(program) = tallow::parser::Parser::parse(tokens) {
                let mut interp = tallow::interp::Interpreter::new();
                let _ = interp.run(&program);
            }
        });
    }
}

// ── Combined Pipeline Safety ─────────────────────────────────────────────────

#[test]
fn full_pipeline_does_not_panic_on_adversarial_programs() {
    // Run in a thread with a large stack to handle deeply nested inputs
    // that the recursive descent parser processes via deep Rust recursion.
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024) // 32 MB
        .name("adversarial-test".to_string())
        .spawn(|| {
            let inputs: Vec<String> = vec![
                // Mismatched types everywhere
                r#"fn main() { let x: i32 = "not_a_number" }"#.to_string(),
                // Redefinition
                "fn main() { let x = 1; let x = 2 }".to_string(),
                // Very long string literal
                format!(r#"fn main() {{ let x = "{}" }}"#, "A".repeat(10_000)),
                // Many variables
                (0..200).map(|i| format!("fn f{i}() {{ let x{i} = {i} }}")).collect::<Vec<_>>().join("\n"),
                // Deeply nested blocks
                format!("fn main() {{ {} 42 {} }}", "{ ".repeat(50), " }".repeat(50)),
            ];
            for input in &inputs {
                let label = if input.len() > 80 {
                    format!("{}...", &input[..80])
                } else {
                    input.to_string()
                };
                let input_clone = input.clone();
                let result = panic::catch_unwind(move || {
                    let (tokens, lex_errors) = tallow::lexer::tokenize(&input_clone);
                    if !lex_errors.is_empty() { return; }
                    if let Ok(program) = tallow::parser::Parser::parse(tokens) {
                        let mut interp = tallow::interp::Interpreter::new();
                        let _ = interp.run(&program);
                    }
                });
                assert!(result.is_ok(), "PANIC on input: {label}");
            }
        })
        .expect("failed to spawn test thread");
    handle.join().expect("adversarial test thread panicked");
}

// ── Randomized Byte-Level Fuzzing (deterministic seeds) ──────────────────────

#[test]
fn lexer_does_not_panic_on_pseudorandom_bytes() {
    // Generate deterministic "random" byte sequences using a simple LCG
    let mut seed: u64 = 0xDEAD_BEEF_CAFE_BABE;
    for _ in 0..1000 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let len = ((seed >> 32) % 256) as usize;
        let bytes: Vec<u8> = (0..len)
            .map(|_i| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                (seed >> 56) as u8
            })
            .collect();
        if let Ok(s) = std::str::from_utf8(&bytes) {
            let result = panic::catch_unwind(|| {
                let _ = tallow::lexer::tokenize(s);
            });
            assert!(result.is_ok(), "Lexer panicked on pseudorandom input #{}", seed);
        }
    }
}

#[test]
fn parser_does_not_panic_on_pseudorandom_token_streams() {
    // Generate random programs from valid-ish token sequences
    let fragments = [
        "fn", "let", "var", "if", "else", "for", "while", "match", "struct",
        "enum", "impl", "return", "true", "false", "nil", "import", "const",
        "(", ")", "{", "}", "[", "]", ",", ".", ":", ";", "->", "=>",
        "=", "==", "!=", "<", ">", "<=", ">=", "+", "-", "*", "/", "%",
        "&&", "||", "!", "?", "..", "@", "0", "1", "42", "3.14",
        "\"hello\"", "x", "y", "z", "foo", "bar", "main", "i32", "String",
        "\n", " ",
    ];
    let mut seed: u64 = 0x1234_5678_9ABC_DEF0;
    for trial in 0..200 {
        let count = 5 + (trial % 50);
        let mut program = String::new();
        for _ in 0..count {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let idx = ((seed >> 32) as usize) % fragments.len();
            program.push_str(fragments[idx]);
            program.push(' ');
        }
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            let (tokens, _) = tallow::lexer::tokenize(&program);
            let _ = tallow::parser::Parser::parse(tokens);
        }));
        assert!(result.is_ok(), "Parser panicked on trial {}: {:?}",
            trial, if program.len() > 100 { &program[..100] } else { &program });
    }
}
