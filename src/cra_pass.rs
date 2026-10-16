//! EU Cyber Resilience Act (CRA) annotation validation compiler pass.
//!
//! Validates @cra_class annotations on functions:
//! - E1900: unknown CRA product class
//! - E1901: class_ii/critical missing @legal annotation
//! - E1902: class_ii/critical missing SBOM generation (reserved)
//! - E1903: critical missing third-party assessment flag
//! - W1900: network-touching function without @cra_class classification

use crate::ast::*;
use crate::error::Diagnostics;

// ── CRA-related network keywords ────────────────────────────────────────────

const NETWORK_KEYWORDS: &[&str] = &[
    "fetch", "http", "net", "request", "connect", "socket", "tls",
    "download", "upload", "send", "receive",
];

const VALID_CRA_CLASSES: &[&str] = &[
    "default", "class_i", "class_ii", "critical",
];

// ── Pass ─────────────────────────────────────────────────────────────────────

pub struct CraPass<'a> {
    program: &'a Program,
    pub diags: Diagnostics,
}

impl<'a> CraPass<'a> {
    pub fn new(program: &'a Program) -> Self {
        Self {
            program,
            diags: Diagnostics::new(),
        }
    }

    /// Run the CRA pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.validate_fn(f),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.validate_fn(m);
                    }
                }
                _ => {}
            }
        }
        self.diags
    }

    fn validate_fn(&mut self, f: &FnDecl) {
        let cra_anns: Vec<&Annotation> = f.annotations.iter()
            .filter(|a| a.name == "cra_class")
            .collect();

        if cra_anns.is_empty() {
            // W1900: network-touching function without @cra_class
            self.check_network_warning(f);
            return;
        }

        for ann in &cra_anns {
            self.validate_annotation(ann, f);
        }
    }

    fn validate_annotation(&mut self, ann: &Annotation, f: &FnDecl) {
        // Extract CRA class from first positional DotIdent arg
        let cra_class = ann.args.iter().find_map(|arg| {
            if let ExprKind::DotIdent(name) = &arg.value.kind {
                Some(name.clone())
            } else {
                None
            }
        });

        let level = match cra_class {
            Some(l) => l,
            None => {
                self.diags.error(
                    "E1900",
                    format!(
                        "@cra_class on '{}' has no product class specified",
                        f.name
                    ),
                    ann.span,
                );
                return;
            }
        };

        // E1900: unknown CRA class
        if !VALID_CRA_CLASSES.contains(&level.as_str()) {
            self.diags.error(
                "E1900",
                format!(
                    "@cra_class(.{}) is not a valid CRA product classification (expected: default, class_i, class_ii, critical)",
                    level
                ),
                ann.span,
            );
            return;
        }

        match level.as_str() {
            // .default and .class_i: basic validation -- annotation is well-formed
            "default" | "class_i" => {}

            // .class_ii: must have @legal annotation
            "class_ii" => {
                self.check_class_ii(f, ann);
            }

            // .critical: all class_ii checks + third-party assessment
            "critical" => {
                self.check_class_ii(f, ann);
                self.check_third_party_assessment(f, ann);
            }

            _ => {} // already caught by E1900
        }
    }

    /// Check class_ii requirements: @legal annotation must be present.
    fn check_class_ii(&mut self, f: &FnDecl, ann: &Annotation) {
        let has_legal = f.annotations.iter().any(|a| a.name == "legal");
        if !has_legal {
            self.diags.error(
                "E1901",
                format!(
                    "CRA class II/critical product '{}' requires @legal annotation for compliance traceability",
                    f.name
                ),
                ann.span,
            );
        }
    }

    /// Check critical class requirement: third_party_assessed: true must be present.
    fn check_third_party_assessment(&mut self, f: &FnDecl, ann: &Annotation) {
        let has_assessment = ann.args.iter().any(|arg| {
            arg.name == "third_party_assessed"
                && matches!(&arg.value.kind, ExprKind::BoolLit(true))
        });
        if !has_assessment {
            self.diags.error(
                "E1903",
                format!(
                    "CRA critical product '{}' requires third_party_assessed: true per CRA Annex III",
                    f.name
                ),
                ann.span,
            );
        }
    }

    /// Warn if a function body references network-related keywords but has no @cra_class.
    fn check_network_warning(&mut self, f: &FnDecl) {
        if self.block_has_network_calls(&f.body) {
            self.diags.warning(
                "W1900",
                format!(
                    "function `{}` contains network operations but has no @cra_class classification",
                    f.name
                ),
                f.span,
            );
        }
    }

    /// Walk a block looking for identifiers matching network keywords.
    fn block_has_network_calls(&self, block: &Block) -> bool {
        for stmt in &block.stmts {
            if self.stmt_has_network(stmt) {
                return true;
            }
        }
        false
    }

    fn stmt_has_network(&self, stmt: &Stmt) -> bool {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.expr_has_network(value)
            }
            StmtKind::Expr { expr } => {
                self.expr_has_network(expr)
            }
            StmtKind::Return(Some(expr)) => {
                self.expr_has_network(expr)
            }
            StmtKind::Return(None) => false,
            _ => false,
        }
    }

    fn expr_has_network(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Call { callee, args, .. } => {
                if self.expr_has_network(callee) {
                    return true;
                }
                args.iter().any(|a| self.expr_has_network(&a.value))
            }
            ExprKind::Ident(name) => {
                let lower = name.to_lowercase();
                NETWORK_KEYWORDS.iter().any(|kw| lower.contains(kw))
            }
            ExprKind::FieldAccess { object, field, .. } => {
                let lower = field.to_lowercase();
                if NETWORK_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
                    return true;
                }
                self.expr_has_network(object)
            }
            ExprKind::MethodCall { object, method, args, .. } => {
                let lower = method.to_lowercase();
                if NETWORK_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
                    return true;
                }
                if self.expr_has_network(object) {
                    return true;
                }
                args.iter().any(|a| self.expr_has_network(&a.value))
            }
            ExprKind::Binary { left, right, .. } => {
                self.expr_has_network(left) || self.expr_has_network(right)
            }
            ExprKind::Block(block) => self.block_has_network_calls(block),
            _ => false,
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_and_check(src: &str) -> Diagnostics {
        let (tokens, _) = crate::lexer::tokenize(src);
        let program = crate::parser::Parser::parse(tokens).expect("parse failed");
        CraPass::new(&program).check()
    }

    #[test]
    fn test_cra_default_no_errors() {
        let src = r#"
@cra_class(.default)
fn simple_handler(x: i32) -> i32 {
    x
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "default should have no errors");
        assert_eq!(diags.warning_count(), 0, "default should have no warnings");
    }

    #[test]
    fn test_cra_class_ii_missing_legal_e1901() {
        let src = r#"
@cra_class(.class_ii)
fn process_data(data: String) -> String {
    data
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 1);
        let err = &diags.items[0];
        assert_eq!(err.code, "E1901");
        assert!(err.msg.contains("@legal"));
    }

    #[test]
    fn test_cra_critical_missing_assessment_e1903() {
        let src = r#"
@cra_class(.critical)
@legal(basis: .public_data, purpose: "testing")
fn critical_system(data: String) -> String {
    data
}
"#;
        let diags = parse_and_check(src);
        let e1903: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E1903")
            .collect();
        assert_eq!(e1903.len(), 1, "should have E1903 for missing third_party_assessed");
        assert!(e1903[0].msg.contains("third_party_assessed"));
    }

    #[test]
    fn test_cra_unknown_class_e1900() {
        let src = r#"
@cra_class(.unknown)
fn some_fn(x: i32) -> i32 {
    x
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 1);
        let err = &diags.items[0];
        assert_eq!(err.code, "E1900");
        assert!(err.msg.contains("unknown"));
    }

    #[test]
    fn test_cra_network_fn_without_classification_w1900() {
        let src = r#"
fn fetch_data(url: String) -> String {
    let resp = fetch(url)
    resp
}
"#;
        let diags = parse_and_check(src);
        let w1900: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W1900")
            .collect();
        assert_eq!(w1900.len(), 1, "should have W1900 for network fn without @cra_class");
        assert!(w1900[0].msg.contains("network operations"));
    }

    #[test]
    fn test_cra_class_ii_with_legal_no_errors() {
        let src = r#"
@cra_class(.class_ii)
@legal(basis: .public_data, purpose: "testing")
fn compliant_fn(data: String) -> String {
    data
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "class_ii with @legal should pass");
    }

    #[test]
    fn test_cra_critical_fully_compliant() {
        let src = r#"
@cra_class(.critical, third_party_assessed: true)
@legal(basis: .public_data, purpose: "testing")
fn fully_compliant(data: String) -> String {
    data
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "critical with all requirements should pass");
    }

    #[test]
    fn test_cra_class_i_no_errors() {
        let src = r#"
@cra_class(.class_i)
fn class_i_fn(data: String) -> String {
    data
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "class_i should have no errors");
    }
}
