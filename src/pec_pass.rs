//! Privacy-Enhancing Computation (PEC) compiler pass (Phase 46).
//!
//! Validates MetaPrivate<T> usage and PEC context requirements:
//! - E2800: MetaPrivate value used in non-PEC context (print, log, network send)
//! - W2800: Missing PEC wrapper on sensitive computation involving private data
//!
//! MetaPrivate<T> is a higher-order privacy type that requires all computations
//! to go through PEC primitives (ZK, MPC, FHE, DP) rather than plaintext.
//! It delegates to existing ZkCircuit/MpcSession/FheKey subsystems.

use std::collections::HashSet;

use crate::ast::*;
#[allow(unused_imports)]
use crate::ast::TypeExprKind;
use crate::error::Diagnostics;

// ── Known PEC functions ─────────────────────────────────────────────────────

/// Functions that ARE valid PEC contexts (can receive MetaPrivate values).
const PEC_FUNCTIONS: &[&str] = &[
    "ZkCircuit.prove",
    "ZkCircuit.verify",
    "MpcSession.contribute",
    "MpcSession.compute",
    "FheKey.encrypt",
    "FheKey.decrypt",
    "MixChannel.send",
    "MixChannel.receive",
    "SealedData.seal",
    "HarvestGuard.protect",
    "dp_query",
    "dp_add_noise",
];

/// Functions that MUST NOT receive MetaPrivate values.
const NON_PEC_SINKS: &[&str] = &[
    "print",
    "println",
    "log.info",
    "log.debug",
    "log.warn",
    "log.error",
    "log.fatal",
    "fetch",
    "db.insert",
    "db.update",
    "write_file",
];

// ── Pass ─────────────────────────────────────────────────────────────────────

pub struct PecPass<'a> {
    program: &'a Program,
    pub diags: Diagnostics,
    /// Variables known to hold MetaPrivate values.
    meta_private_vars: HashSet<String>,
}

impl<'a> PecPass<'a> {
    pub fn new(program: &'a Program) -> Self {
        Self {
            program,
            diags: Diagnostics::new(),
            meta_private_vars: HashSet::new(),
        }
    }

    /// Run the PEC pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.check_fn(f),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.check_fn(m);
                    }
                }
                _ => {}
            }
        }

        self.diags
    }

    fn check_fn(&mut self, f: &FnDecl) {
        // Collect params with MetaPrivate type
        let mut fn_meta_private = HashSet::new();
        for param in &f.params {
            if self.is_meta_private_type(&param.ty) {
                fn_meta_private.insert(param.name.clone());
            }
        }

        let prev = std::mem::replace(&mut self.meta_private_vars, fn_meta_private);
        for stmt in &f.body.stmts {
            self.check_stmt(stmt);
        }
        self.meta_private_vars = prev;
    }

    fn check_stmt(&mut self, stmt: &Stmt) {
        match &stmt.kind {
            StmtKind::Let { name, ty, value, .. } | StmtKind::Var { name, ty, value, .. } => {
                // Check if the type annotation is MetaPrivate<T>
                if let Some(t) = ty {
                    if self.is_meta_private_type(t) {
                        self.meta_private_vars.insert(name.clone());
                    }
                }
                // Check if value is from MetaPrivate source
                if self.expr_is_meta_private(value) {
                    self.meta_private_vars.insert(name.clone());
                }
                self.check_expr(value);
            }
            StmtKind::Expr { expr } => {
                self.check_expr(expr);
            }
            StmtKind::Return(Some(expr)) => {
                self.check_expr(expr);
            }
            StmtKind::For { iter, body, .. } => {
                self.check_expr(iter);
                for s in &body.stmts {
                    self.check_stmt(s);
                }
            }
            StmtKind::While { condition, body } => {
                self.check_expr(condition);
                for s in &body.stmts {
                    self.check_stmt(s);
                }
            }
            _ => {}
        }
    }

    fn check_expr(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                let fn_name = self.extract_call_name(callee);
                // Check if any MetaPrivate var is passed to a non-PEC sink
                if let Some(ref name) = fn_name {
                    let is_non_pec = NON_PEC_SINKS.iter().any(|s| name.contains(s));
                    let is_pec_context = PEC_FUNCTIONS.iter().any(|p| name.contains(p));
                    let meta_private_args: Vec<_> = args
                        .iter()
                        .filter(|a| self.expr_is_meta_private(&a.value))
                        .collect();
                    if is_non_pec {
                        if !meta_private_args.is_empty() {
                            self.diags.error(
                                "E2800",
                                format!(
                                    "MetaPrivate value passed to non-PEC sink `{name}` — use ZkCircuit, MpcSession, or FheKey instead"
                                ),
                                expr.span,
                            );
                        }
                    } else if !is_pec_context && !meta_private_args.is_empty() {
                        // W2800: MetaPrivate flows into a callee that is
                        // neither a documented PEC primitive nor a known
                        // non-PEC sink — the computation happens outside a
                        // declared PEC context.
                        self.diags.warning(
                            "W2800",
                            format!(
                                "MetaPrivate value passed to `{name}` outside a documented PEC context — wrap the computation in ZkCircuit, MpcSession, or FheKey"
                            ),
                            expr.span,
                        );
                    }
                }
                for arg in args {
                    self.check_expr(&arg.value);
                }
            }
            ExprKind::MethodCall { object, method, args } => {
                // Check print-like methods
                let full_name = format!("{}.{method}", self.expr_name(object));
                let is_non_pec = NON_PEC_SINKS.iter().any(|s| full_name.contains(s))
                    || method == "to_string";
                let is_pec_context = PEC_FUNCTIONS.iter().any(|p| full_name.contains(p));
                if is_non_pec {
                    // Check if the receiver is MetaPrivate (e.g., data.to_string())
                    if self.expr_is_meta_private(object) {
                        self.diags.error(
                            "E2800",
                            format!(
                                "MetaPrivate value used in non-PEC context `.{method}()` — use PEC primitives for computation"
                            ),
                            expr.span,
                        );
                    }
                    // Check if any arg is MetaPrivate (e.g., log.info(data))
                    for arg in args {
                        if self.expr_is_meta_private(&arg.value) {
                            self.diags.error(
                                "E2800",
                                format!(
                                    "MetaPrivate value passed to non-PEC sink `{full_name}` — use ZkCircuit, MpcSession, or FheKey instead"
                                ),
                                expr.span,
                            );
                        }
                    }
                } else if !is_pec_context
                    && (self.expr_is_meta_private(object)
                        || args.iter().any(|a| self.expr_is_meta_private(&a.value)))
                {
                    // W2800: method call on/with MetaPrivate outside a
                    // documented PEC context.
                    self.diags.warning(
                        "W2800",
                        format!(
                            "MetaPrivate value used in `{full_name}` outside a documented PEC context — use ZkCircuit, MpcSession, or FheKey instead"
                        ),
                        expr.span,
                    );
                }
                self.check_expr(object);
                for arg in args {
                    self.check_expr(&arg.value);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.check_expr(left);
                self.check_expr(right);
            }
            ExprKind::Block(block) => {
                for s in &block.stmts {
                    self.check_stmt(s);
                }
            }
            _ => {}
        }
    }

    /// Check if a type expression is MetaPrivate<T>.
    fn is_meta_private_type(&self, ty: &TypeExpr) -> bool {
        match &ty.kind {
            TypeExprKind::Named(name) => name == "MetaPrivate",
            TypeExprKind::Generic { name, .. } => name == "MetaPrivate",
            _ => false,
        }
    }

    /// Check if an expression evaluates to a MetaPrivate value.
    fn expr_is_meta_private(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Ident(name) => self.meta_private_vars.contains(name),
            _ => false,
        }
    }

    /// Extract the call name from a function expression.
    fn extract_call_name(&self, expr: &Expr) -> Option<String> {
        match &expr.kind {
            ExprKind::Ident(name) => Some(name.clone()),
            ExprKind::FieldAccess { object, field } => {
                if let ExprKind::Ident(module) = &object.kind {
                    Some(format!("{module}.{field}"))
                } else {
                    Some(field.clone())
                }
            }
            _ => None,
        }
    }

    fn expr_name(&self, expr: &Expr) -> String {
        match &expr.kind {
            ExprKind::Ident(name) => name.clone(),
            _ => "<expr>".to_string(),
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pec_pass_meta_private_in_print() {
        use crate::lexer;
        use crate::parser::Parser;

        let source = r#"
fn process(data: MetaPrivate) {
    print(data)
}
fn main() {}
"#;
        let (tokens, lex_errors) = lexer::tokenize(source);
        assert!(lex_errors.is_empty());
        let program = Parser::parse(tokens).unwrap();

        let pass = PecPass::new(&program);
        let diags = pass.check();
        let errors: Vec<_> = diags
            .items
            .iter()
            .filter(|d| d.code == "E2800")
            .collect();
        assert!(
            !errors.is_empty(),
            "expected E2800 error for MetaPrivate passed to print()"
        );
    }

    #[test]
    fn test_pec_pass_meta_private_in_log() {
        use crate::lexer;
        use crate::parser::Parser;

        let source = r#"
fn handle(data: MetaPrivate) {
    log.info(data)
}
fn main() {}
"#;
        let (tokens, lex_errors) = lexer::tokenize(source);
        assert!(lex_errors.is_empty());
        let program = Parser::parse(tokens).unwrap();

        let pass = PecPass::new(&program);
        let diags = pass.check();
        let errors: Vec<_> = diags
            .items
            .iter()
            .filter(|d| d.code == "E2800")
            .collect();
        assert!(
            !errors.is_empty(),
            "expected E2800 error for MetaPrivate passed to log.info()"
        );
    }

    #[test]
    fn test_pec_pass_no_error_for_regular_types() {
        use crate::lexer;
        use crate::parser::Parser;

        let source = r#"
fn process(data: String) {
    print(data)
}
fn main() {}
"#;
        let (tokens, lex_errors) = lexer::tokenize(source);
        assert!(lex_errors.is_empty());
        let program = Parser::parse(tokens).unwrap();

        let pass = PecPass::new(&program);
        let diags = pass.check();
        assert!(
            diags.items.is_empty(),
            "no PEC errors expected for non-MetaPrivate types"
        );
    }

    #[test]
    fn test_pec_pass_w2800_outside_pec_context() {
        use crate::lexer;
        use crate::parser::Parser;

        // `transform` is neither a documented PEC primitive nor a non-PEC
        // sink — MetaPrivate flowing into it should produce the W2800
        // advisory ("computation outside a documented PEC context").
        let source = r#"
fn process(data: MetaPrivate) {
    transform(data)
}
fn transform(x: MetaPrivate) -> MetaPrivate { x }
fn main() {}
"#;
        let (tokens, lex_errors) = lexer::tokenize(source);
        assert!(lex_errors.is_empty());
        let program = Parser::parse(tokens).unwrap();

        let pass = PecPass::new(&program);
        let diags = pass.check();
        let warnings: Vec<_> = diags
            .items
            .iter()
            .filter(|d| d.code == "W2800")
            .collect();
        assert!(
            !warnings.is_empty(),
            "expected W2800 for MetaPrivate passed outside a PEC context, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn test_pec_pass_no_warning_for_pec_context() {
        use crate::lexer;
        use crate::parser::Parser;

        // ZkCircuit.prove IS a valid PEC context — no diagnostics expected.
        let source = r#"
fn prove_secret(data: MetaPrivate) {
    ZkCircuit.prove(data)
}
fn main() {}
"#;
        let (tokens, lex_errors) = lexer::tokenize(source);
        assert!(lex_errors.is_empty());
        let program = Parser::parse(tokens).unwrap();

        let pass = PecPass::new(&program);
        let diags = pass.check();
        assert!(
            diags.items.is_empty(),
            "no PEC diagnostics expected inside ZkCircuit.prove, got: {:?}",
            diags.items
        );
    }
}
