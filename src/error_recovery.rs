//! Parse-with-recovery: wraps the standard parser to attempt error recovery.
//!
//! Instead of aborting on the first parse error, the parser collects errors
//! and skips to the next top-level synchronisation point (`fn`, `struct`,
//! `enum`, etc.), resuming from there.  All successfully parsed declarations
//! are returned along with the full list of parse diagnostics.

use crate::ast::Item;
use crate::lexer;
use crate::parser::Parser;

/// A collected diagnostic from lex or parse.
#[derive(Debug, Clone)]
pub struct RecoveryDiagnostic {
    pub message: String,
    pub line: usize,
    pub col: usize,
}

impl std::fmt::Display for RecoveryDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.col, self.message)
    }
}

/// Result of parsing with recovery.
pub struct RecoveryResult {
    /// Items that were successfully parsed (may be empty on total failure).
    pub items: Vec<Item>,
    /// All diagnostics collected from lexing and parsing.
    pub diagnostics: Vec<RecoveryDiagnostic>,
}

impl RecoveryResult {
    /// Returns `true` if no errors were encountered.
    pub fn is_ok(&self) -> bool {
        self.diagnostics.is_empty()
    }

    /// Returns `true` if at least one error was encountered.
    pub fn has_errors(&self) -> bool {
        !self.diagnostics.is_empty()
    }
}

/// Parse source code with error recovery.
///
/// Collects lex errors and parse errors into a single diagnostics list.
/// Returns whatever AST items could be parsed.  On parse failure the
/// parser skips to the next top-level synchronisation point and continues,
/// so multiple independent errors are all reported in one pass.
///
/// # Example
/// ```ignore
/// let result = parse_with_recovery(source);
/// for diag in &result.diagnostics {
///     eprintln!("error: {}", diag);
/// }
/// // result.items contains all declarations that parsed successfully
/// ```
pub fn parse_with_recovery(source: &str) -> RecoveryResult {
    let (tokens, lex_errors) = lexer::tokenize(source);

    let mut diagnostics: Vec<RecoveryDiagnostic> = Vec::new();

    // Convert lex errors to diagnostics
    for err in &lex_errors {
        let span = err.span();
        let (line, col) = span.line_col(source);
        diagnostics.push(RecoveryDiagnostic {
            message: err.to_string(),
            line,
            col,
        });
    }

    // Attempt parse with in-parser recovery so we get a partial AST plus
    // all parse errors, even when the source has multiple broken declarations.
    let (program, parse_errors) = Parser::parse_recovering(tokens);

    for parse_err in &parse_errors {
        let (line, col) = parse_err.span.line_col(source);
        diagnostics.push(RecoveryDiagnostic {
            message: parse_err.msg.clone(),
            line,
            col,
        });
    }

    RecoveryResult {
        items: program.items,
        diagnostics,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_on_valid_source() {
        let result = parse_with_recovery("fn main() { let x = 42 }");
        assert!(result.is_ok());
        assert_eq!(result.items.len(), 1);
    }

    #[test]
    fn recovery_collects_lex_errors() {
        let result = parse_with_recovery("fn main() { \"unterminated }");
        assert!(result.has_errors());
        assert!(!result.diagnostics.is_empty());
    }

    #[test]
    fn recovery_collects_parse_errors() {
        let result = parse_with_recovery("fn main( { }");
        assert!(result.has_errors());
        assert!(!result.diagnostics.is_empty());
    }

    #[test]
    fn recovery_returns_empty_items_on_parse_failure() {
        let result = parse_with_recovery("fn {{{");
        assert!(result.has_errors());
        // Items may or may not be empty depending on where the parse fails,
        // but diagnostics must be non-empty.
    }

    #[test]
    fn recovery_handles_empty_input() {
        let result = parse_with_recovery("");
        assert!(result.is_ok());
        assert!(result.items.is_empty());
    }

    #[test]
    fn recovery_multiple_valid_items() {
        let source = r#"
fn foo() { let x = 1 }
fn bar() { let y = 2 }
struct Point { x: i32, y: i32 }
"#;
        let result = parse_with_recovery(source);
        assert!(result.is_ok());
        assert_eq!(result.items.len(), 3);
    }

    // ── New tests for real multi-error recovery ───────────────────────────────

    #[test]
    fn recovery_reports_multiple_errors() {
        // Two broken declarations — parser should report both, not just the first.
        let source = r#"
fn broken_a( { }
fn broken_b( { }
fn good() { let x = 1 }
"#;
        let result = parse_with_recovery(source);
        assert!(result.has_errors());
        // Must have at least 2 diagnostics (one per broken function).
        assert!(
            result.diagnostics.len() >= 2,
            "expected >=2 diagnostics, got {}: {:?}",
            result.diagnostics.len(),
            result.diagnostics
        );
    }

    #[test]
    fn recovery_preserves_good_items_after_bad_one() {
        // A broken declaration in the middle should not prevent later good ones
        // from being parsed and returned.
        let source = r#"
fn before() { let x = 1 }
fn broken( { }
fn after() { let y = 2 }
"#;
        let result = parse_with_recovery(source);
        assert!(result.has_errors());
        // `before` and `after` should still appear in the items list.
        assert!(
            result.items.len() >= 2,
            "expected >=2 successfully parsed items, got {}: {:?}",
            result.items.len(),
            result.items.iter().map(|i| match i {
                crate::ast::Item::Fn(f) => f.name.clone(),
                _ => "?".into(),
            }).collect::<Vec<_>>()
        );
    }

    #[test]
    fn parse_recovering_returns_all_errors_directly() {
        // Smoke-test the Parser::parse_recovering API directly.
        let source = "fn a( { } fn b( { } fn c() { let x = 3 }";
        let (tokens, _) = crate::lexer::tokenize(source);
        let (program, errors) = crate::parser::Parser::parse_recovering(tokens);
        assert!(!errors.is_empty(), "expected parse errors");
        // `fn c` should still be in the AST.
        let fn_names: Vec<_> = program.items.iter().filter_map(|i| {
            if let crate::ast::Item::Fn(f) = i { Some(f.name.as_str()) } else { None }
        }).collect();
        assert!(fn_names.contains(&"c"), "fn c should be parsed; got: {fn_names:?}");
    }
}
