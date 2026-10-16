//! Data lineage compiler pass — validates provenance propagation for @legal functions.
//!
//! When a function declares `@legal(personal_data: true)`, it handles GDPR personal data.
//! This pass warns if such functions don't have provenance tracking context, enabling
//! data governance audit trails.
//!
//! Warning codes: W1200

use crate::ast::*;
use crate::error::{Diagnostic, Diagnostics};
use crate::typeck::TypeEnv;

/// Data lineage compiler pass.
pub struct LineagePass<'a> {
    program: &'a Program,
    #[allow(dead_code)]
    env: &'a TypeEnv,
}

impl<'a> LineagePass<'a> {
    pub fn new(program: &'a Program, env: &'a TypeEnv) -> Self {
        LineagePass { program, env }
    }

    /// Run the lineage pass, returning diagnostics (warnings).
    pub fn check(&self) -> Diagnostics {
        let mut diags = Diagnostics::new();

        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.check_fn(f, &mut diags),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.check_fn(m, &mut diags);
                    }
                }
                _ => {}
            }
        }

        diags
    }

    fn check_fn(&self, f: &FnDecl, diags: &mut Diagnostics) {
        // Check if this function has @legal(personal_data: true)
        let legal_ann = f.annotations.iter().find(|a| a.name == "legal");
        if let Some(ann) = legal_ann {
            let has_personal_data = Self::has_personal_data_true(ann);
            if has_personal_data {
                let has_provenance_context = Self::body_has_provenance_context(&f.body);
                let has_return = f.return_type.is_some();

                if has_return && !has_provenance_context {
                    diags.push(Diagnostic::warning(
                        "W1200",
                        format!(
                            "@legal function `{}` with personal_data: true returns a value but has no provenance tracking context (fetch/read_file/provenance)",
                            f.name
                        ),
                        f.span,
                    ));
                }
            }
        }
    }

    /// Check if an @legal annotation has personal_data: true.
    fn has_personal_data_true(ann: &Annotation) -> bool {
        for arg in &ann.args {
            if arg.name == "personal_data" {
                if let ExprKind::BoolLit(true) = arg.value.kind {
                    return true;
                }
            }
        }
        false
    }

    /// Best-effort check: does the function body contain provenance-related patterns?
    fn body_has_provenance_context(body: &Block) -> bool {
        for stmt in &body.stmts {
            if Self::stmt_has_provenance(stmt) {
                return true;
            }
        }
        false
    }

    fn stmt_has_provenance(stmt: &Stmt) -> bool {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                Self::expr_has_provenance(value)
            }
            StmtKind::LetDestructure { value, .. } => Self::expr_has_provenance(value),
            StmtKind::Expr { expr } => Self::expr_has_provenance(expr),
            StmtKind::Return(Some(expr)) => Self::expr_has_provenance(expr),
            _ => false,
        }
    }

    fn expr_has_provenance(expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Call { callee, args, .. } => {
                // Check if calling fetch or read_file
                if let ExprKind::Ident(name) = &callee.kind {
                    if name == "fetch" || name == "read_file" {
                        return true;
                    }
                }
                if Self::expr_has_provenance(callee) {
                    return true;
                }
                for arg in args {
                    if Self::expr_has_provenance(&arg.value) {
                        return true;
                    }
                }
                false
            }
            ExprKind::MethodCall { object, method, args, .. } => {
                if method == "provenance" || method == "fetch" || method == "read_file" {
                    return true;
                }
                if Self::expr_has_provenance(object) {
                    return true;
                }
                for arg in args {
                    if Self::expr_has_provenance(&arg.value) {
                        return true;
                    }
                }
                false
            }
            ExprKind::FieldAccess { object, field } => {
                if field == "provenance" {
                    return true;
                }
                Self::expr_has_provenance(object)
            }
            ExprKind::Ident(name) => name == "provenance",
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_source(src: &str) -> Diagnostics {
        let (tokens, _) = crate::lexer::tokenize(src);
        let program = crate::parser::Parser::parse(tokens).expect("parse failed");
        let (env, _) = crate::typeck::TypeChecker::new(&program).check();
        LineagePass::new(&program, &env).check()
    }

    #[test]
    fn test_lineage_warns_personal_data_no_provenance() {
        let diags = check_source(r#"
@legal(basis: .consent, personal_data: true, retain_for: 30.days, purpose: "test", consent_ref: "c1")
fn collect_emails(url: String) -> String {
    let x = "static"
    x
}
"#);
        assert!(
            diags.items.iter().any(|d| d.code == "W1200"),
            "expected W1200 warning for personal_data without provenance, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn test_lineage_no_warn_with_fetch() {
        let diags = check_source(r#"
@legal(basis: .consent, personal_data: true, retain_for: 30.days, purpose: "test", consent_ref: "c1")
fn collect_data(url: String) -> String {
    let resp = fetch(url)
    resp
}
"#);
        assert!(
            !diags.items.iter().any(|d| d.code == "W1200"),
            "should not warn when fetch is used: {:?}",
            diags.items
        );
    }

    #[test]
    fn test_lineage_no_warn_without_personal_data() {
        let diags = check_source(r#"
@legal(basis: .public_data, purpose: "test")
fn scrape(url: String) -> String {
    let x = "data"
    x
}
"#);
        assert!(
            !diags.items.iter().any(|d| d.code == "W1200"),
            "should not warn without personal_data: true: {:?}",
            diags.items
        );
    }

    #[test]
    fn test_lineage_no_warn_with_provenance_method() {
        let diags = check_source(r#"
@legal(basis: .consent, personal_data: true, retain_for: 30.days, purpose: "test", consent_ref: "c1")
fn collect_data(data: String) -> String {
    let p = data.provenance()
    data
}
"#);
        assert!(
            !diags.items.iter().any(|d| d.code == "W1200"),
            "should not warn when .provenance() is used: {:?}",
            diags.items
        );
    }

    #[test]
    fn test_lineage_no_warn_no_return_type() {
        let diags = check_source(r#"
@legal(basis: .consent, personal_data: true, retain_for: 30.days, purpose: "test", consent_ref: "c1")
fn process(data: String) {
    let x = "hello"
}
"#);
        assert!(
            !diags.items.iter().any(|d| d.code == "W1200"),
            "should not warn for void function: {:?}",
            diags.items
        );
    }
}
