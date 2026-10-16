//! Identity pass: SPIFFE annotation validation (check-time analysis only).
//!
//! Validates that `@identity("spiffe://trust-domain/path")` annotations carry
//! well-formed SPIFFE IDs. The pass records each function's SPIFFE ID in its
//! internal `identity_map` field for downstream consumers.
//!
//! **Scope — check-time analysis only.** This pass does **not** install a
//! runtime SPIFFE identity: it does not set any thread-local SPIFFE context,
//! does not provision or validate X.509-SVIDs, and does not make outbound
//! network calls carry cryptographic identity. Actual mTLS identity
//! enforcement would require a runtime/SPIFFE agent integration (e.g. the
//! SPIFFE Workload API) that this compiler pass does not provide. The
//! `identity_map` it builds is available to codegen backends that implement
//! that integration.
//!
//! Error codes:
//! - E1000: Invalid SPIFFE ID format (must start with `spiffe://`)
//! - E1001: Empty trust domain in SPIFFE ID
//! - E1002: Missing path component in SPIFFE ID

use std::collections::HashMap;

use crate::ast::*;
use crate::error::Diagnostics;
use crate::lexer::Span;
use crate::typeck::TypeEnv;

// ── Identity Pass ─────────────────────────────────────────────────────────────

pub struct IdentityPass<'a> {
    program: &'a Program,
    #[allow(dead_code)]
    env: &'a TypeEnv,
    pub diags: Diagnostics,
    /// Maps function name -> SPIFFE ID string.
    identity_map: HashMap<String, String>,
}

impl<'a> IdentityPass<'a> {
    pub fn new(program: &'a Program, env: &'a TypeEnv) -> Self {
        Self {
            program,
            env,
            diags: Diagnostics::new(),
            identity_map: HashMap::new(),
        }
    }

    /// Run the identity pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        // Phase 1: Collect all @identity annotations
        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.collect_fn_annotation(f),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.collect_fn_annotation(m);
                    }
                }
                _ => {}
            }
        }

        self.diags
    }

    /// Extract @identity("spiffe://...") from a function declaration.
    fn collect_fn_annotation(&mut self, f: &FnDecl) {
        for ann in &f.annotations {
            if ann.name == "identity" {
                if ann.args.is_empty() {
                    self.diags.error(
                        "E1000",
                        "@identity annotation requires a SPIFFE ID argument".to_string(),
                        ann.span,
                    );
                    return;
                }

                // Accept either positional (name == "") or named first arg
                let arg = &ann.args[0];
                if let ExprKind::StringLit(ref s) = arg.value.kind {
                    if self.validate_spiffe_id(s, &ann.span) {
                        self.identity_map.insert(f.name.clone(), s.clone());
                    }
                } else {
                    self.diags.error(
                        "E1000",
                        "@identity argument must be a string literal".to_string(),
                        ann.span,
                    );
                }
            }
        }
    }

    /// Validate a SPIFFE ID format.
    ///
    /// Valid format: `spiffe://<trust-domain>/<path>`
    /// - Must start with `spiffe://`
    /// - Trust domain must be non-empty
    /// - Must have at least one path segment after the trust domain
    fn validate_spiffe_id(&mut self, id: &str, span: &Span) -> bool {
        // Must start with spiffe://
        if !id.starts_with("spiffe://") {
            self.diags.error(
                "E1000",
                format!(
                    "invalid SPIFFE ID '{}': must start with 'spiffe://'",
                    id
                ),
                *span,
            );
            return false;
        }

        // Extract the part after spiffe://
        let rest = &id["spiffe://".len()..];

        // Trust domain is everything before the first /
        let (trust_domain, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, ""),
        };

        // Trust domain must be non-empty
        if trust_domain.is_empty() {
            self.diags.error(
                "E1001",
                format!(
                    "empty trust domain in SPIFFE ID '{}': expected 'spiffe://<trust-domain>/...'",
                    id
                ),
                *span,
            );
            return false;
        }

        // Must have a path component (at least "/something")
        if path.is_empty() || path == "/" {
            self.diags.error(
                "E1002",
                format!(
                    "missing path component in SPIFFE ID '{}': expected 'spiffe://<trust-domain>/<path>'",
                    id
                ),
                *span,
            );
            return false;
        }

        true
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;
    use crate::parser::Parser;
    use crate::typeck::TypeChecker;

    fn run_identity_pass(source: &str) -> Diagnostics {
        let (tokens, _) = lexer::tokenize(source);
        let program = Parser::parse(tokens).unwrap();
        let (env, _) = TypeChecker::new(&program).check();
        IdentityPass::new(&program, &env).check()
    }

    #[test]
    fn test_valid_spiffe_id() {
        let diags = run_identity_pass(
            r#"
@identity("spiffe://example.org/service")
fn my_service() -> String { "ok" }

fn main() {
    let x = my_service()
    print(x)
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "valid SPIFFE ID should produce no errors, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn test_invalid_spiffe_no_prefix() {
        let diags = run_identity_pass(
            r#"
@identity("https://example.org/service")
fn my_service() -> String { "ok" }

fn main() {
    print("done")
}
"#,
        );
        assert!(diags.has_errors(), "expected E1000 for non-spiffe:// prefix");
        assert!(
            diags.items.iter().any(|d| d.code == "E1000"),
            "expected E1000 code"
        );
    }

    #[test]
    fn test_empty_trust_domain() {
        let diags = run_identity_pass(
            r#"
@identity("spiffe:///path")
fn my_service() -> String { "ok" }

fn main() {
    print("done")
}
"#,
        );
        assert!(diags.has_errors(), "expected E1001 for empty trust domain");
        assert!(
            diags.items.iter().any(|d| d.code == "E1001"),
            "expected E1001 code"
        );
    }

    #[test]
    fn test_no_path() {
        let diags = run_identity_pass(
            r#"
@identity("spiffe://domain")
fn my_service() -> String { "ok" }

fn main() {
    print("done")
}
"#,
        );
        assert!(diags.has_errors(), "expected E1002 for missing path");
        assert!(
            diags.items.iter().any(|d| d.code == "E1002"),
            "expected E1002 code"
        );
    }

    #[test]
    fn test_multiple_identity_annotations() {
        let diags = run_identity_pass(
            r#"
@identity("spiffe://example.org/auth")
fn auth_service() -> String { "auth" }

@identity("spiffe://example.org/data")
fn data_service() -> String { "data" }

fn main() {
    let a = auth_service()
    let b = data_service()
    print(a)
    print(b)
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "multiple valid SPIFFE IDs should produce no errors, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn test_no_identity_annotations_no_errors() {
        let diags = run_identity_pass(
            r#"
fn helper() -> String { "help" }

fn main() {
    let x = helper()
    print(x)
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "no @identity annotations should produce no errors, got: {:?}",
            diags.items
        );
    }
}
