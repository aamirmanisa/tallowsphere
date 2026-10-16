//! @mpc annotation validation compiler pass.
//!
//! Validates @mpc annotations on functions for secure multi-party computation:
//! - E1800: threshold > parties in @mpc annotation
//! - E1801: (reserved) Non-encrypted argument in @mpc function — not yet
//!   emitted; parameter encryption checking is not implemented
//! - E1802: Invalid MPC protocol (not .shamir, .garbled_circuit, .bgw)
//! - E1803: @mpc function with side effects (print, fetch, fs operations)
//! - W1800: @mpc with threshold == 1 (no security benefit)
//!
//! @mpc annotated functions must be pure: no I/O, no side effects.
//!
//! **Scope — check-time analysis only.** This pass validates `@mpc` annotations
//! and enforces purity at compile time; it does **not** generate secret-sharing
//! or garbled-circuit code. There is no MPC codegen backend in this compiler,
//! so an `@mpc` function is *not* automatically compiled to a multi-party
//! protocol — it is simply a statically-checked, side-effect-free function
//! carrying an MPC policy annotation. Actual secret sharing / garbled circuit
//! execution would require a separate MPC runtime/backend that this pass does
//! not provide.

use std::collections::HashSet;

use crate::ast::*;
use crate::error::Diagnostics;

// ── Constants ────────────────────────────────────────────────────────────────

const VALID_PROTOCOLS: &[&str] = &["shamir", "garbled_circuit", "bgw"];

const IO_FUNCTIONS: &[&str] = &[
    "print", "println", "fetch", "read_file", "write_file",
    "log.info", "log.debug", "log.warn", "log.error", "log.fatal",
];

// ── Pass ─────────────────────────────────────────────────────────────────────

pub struct MpcPass<'a> {
    program: &'a Program,
    pub diags: Diagnostics,
    /// Functions that have @mpc annotation.
    mpc_fns: HashSet<String>,
}

impl<'a> MpcPass<'a> {
    pub fn new(program: &'a Program) -> Self {
        Self {
            program,
            diags: Diagnostics::new(),
            mpc_fns: HashSet::new(),
        }
    }

    /// Run the MPC pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        // Phase 1: Collect all @mpc annotations and validate them
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

        // Phase 2: Walk each @mpc function body for side effects
        let mpc_fns = self.mpc_fns.clone();
        for item in &self.program.items {
            match item {
                Item::Fn(f) => {
                    if mpc_fns.contains(&f.name) {
                        self.check_mpc_body(f);
                    }
                }
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        if mpc_fns.contains(&m.name) {
                            self.check_mpc_body(m);
                        }
                    }
                }
                _ => {}
            }
        }

        self.diags
    }

    fn validate_fn(&mut self, f: &FnDecl) {
        let mpc_anns: Vec<&Annotation> = f.annotations.iter()
            .filter(|a| a.name == "mpc")
            .collect();

        if mpc_anns.is_empty() {
            return;
        }

        self.mpc_fns.insert(f.name.clone());

        for ann in &mpc_anns {
            let mut parties: Option<i128> = None;
            let mut threshold: Option<i128> = None;

            for arg in &ann.args {
                match arg.name.as_str() {
                    "parties" => {
                        if let ExprKind::IntLit(n) = &arg.value.kind {
                            parties = Some(*n);
                            if *n < 2 {
                                self.diags.error(
                                    "E1800",
                                    format!(
                                        "@mpc annotation on '{}' requires parties >= 2, got {}",
                                        f.name, n
                                    ),
                                    arg.value.span,
                                );
                            }
                        }
                    }
                    "threshold" => {
                        if let ExprKind::IntLit(n) = &arg.value.kind {
                            threshold = Some(*n);
                            if *n < 1 {
                                self.diags.error(
                                    "E1800",
                                    format!(
                                        "@mpc annotation on '{}' requires threshold >= 1, got {}",
                                        f.name, n
                                    ),
                                    arg.value.span,
                                );
                            }
                            // W1800: threshold == 1 offers no security
                            if *n == 1 {
                                self.diags.warning(
                                    "W1800",
                                    format!(
                                        "@mpc annotation on '{}' has threshold: 1 \
                                         -- this offers no security benefit (any single party can reconstruct)",
                                        f.name
                                    ),
                                    arg.value.span,
                                );
                            }
                        }
                    }
                    "protocol" => {
                        if let ExprKind::DotIdent(proto) = &arg.value.kind {
                            if !VALID_PROTOCOLS.contains(&proto.as_str()) {
                                self.diags.error(
                                    "E1802",
                                    format!(
                                        "invalid MPC protocol '.{proto}' on @mpc function '{}' \
                                         (valid: .shamir, .garbled_circuit, .bgw)",
                                        f.name
                                    ),
                                    arg.value.span,
                                );
                            }
                        }
                    }
                    "" => {
                        // Positional args: check if protocol
                        if let ExprKind::DotIdent(val) = &arg.value.kind {
                            if !VALID_PROTOCOLS.contains(&val.as_str()) {
                                self.diags.error(
                                    "E1802",
                                    format!(
                                        "invalid MPC protocol '.{val}' on @mpc function '{}' \
                                         (valid: .shamir, .garbled_circuit, .bgw)",
                                        f.name
                                    ),
                                    arg.value.span,
                                );
                            }
                        }
                        // Positional integers: first is parties, second threshold
                        if let ExprKind::IntLit(n) = &arg.value.kind {
                            if parties.is_none() {
                                parties = Some(*n);
                            } else if threshold.is_none() {
                                threshold = Some(*n);
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Validate threshold <= parties
            if let (Some(p), Some(t)) = (parties, threshold) {
                if t > p {
                    self.diags.error(
                        "E1800",
                        format!(
                            "@mpc annotation on '{}': threshold ({}) exceeds parties ({})",
                            f.name, t, p
                        ),
                        ann.span,
                    );
                }
            }
        }
    }

    fn check_mpc_body(&mut self, f: &FnDecl) {
        for stmt in &f.body.stmts {
            self.check_stmt_purity(stmt, &f.name);
        }
    }

    fn check_stmt_purity(&mut self, stmt: &Stmt, fn_name: &str) {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.walk_expr_purity(value, fn_name);
            }
            StmtKind::LetDestructure { value, .. } => {
                self.walk_expr_purity(value, fn_name);
            }
            StmtKind::Expr { expr } => {
                self.walk_expr_purity(expr, fn_name);
            }
            StmtKind::Return(Some(expr)) => {
                self.walk_expr_purity(expr, fn_name);
            }
            StmtKind::While { condition, body } => {
                self.walk_expr_purity(condition, fn_name);
                for s in &body.stmts {
                    self.check_stmt_purity(s, fn_name);
                }
            }
            StmtKind::For { iter, body, .. } => {
                self.walk_expr_purity(iter, fn_name);
                for s in &body.stmts {
                    self.check_stmt_purity(s, fn_name);
                }
            }
            _ => {}
        }
    }

    fn walk_expr_purity(&mut self, expr: &Expr, fn_name: &str) {
        match &expr.kind {
            ExprKind::Call { callee, args, .. } => {
                let callee_name = self.extract_call_name(callee);
                if let Some(ref name) = callee_name {
                    if IO_FUNCTIONS.contains(&name.as_str()) {
                        self.diags.error(
                            "E1803",
                            format!(
                                "side effect '{name}' in @mpc function '{fn_name}' \
                                 -- @mpc functions must be pure (no I/O or side effects)"
                            ),
                            expr.span,
                        );
                    }
                }
                for arg in args {
                    self.walk_expr_purity(&arg.value, fn_name);
                }
            }
            ExprKind::MethodCall { object, method, args, .. } => {
                if let ExprKind::Ident(ref obj_name) = object.kind {
                    let full_name = format!("{obj_name}.{method}");
                    if IO_FUNCTIONS.contains(&full_name.as_str()) {
                        self.diags.error(
                            "E1803",
                            format!(
                                "side effect '{full_name}' in @mpc function '{fn_name}' \
                                 -- @mpc functions must be pure (no I/O or side effects)"
                            ),
                            expr.span,
                        );
                    }
                    if obj_name == "tallow" {
                        let io_methods = ["fetch", "read_file", "write_file", "connect", "send"];
                        if io_methods.contains(&method.as_str()) {
                            self.diags.error(
                                "E1803",
                                format!(
                                    "side effect 'tallow.{method}' in @mpc function '{fn_name}' \
                                     -- @mpc functions must be pure"
                                ),
                                expr.span,
                            );
                        }
                    }
                }
                self.walk_expr_purity(object, fn_name);
                for arg in args {
                    self.walk_expr_purity(&arg.value, fn_name);
                }
            }
            ExprKind::Block(block) => {
                for stmt in &block.stmts {
                    self.check_stmt_purity(stmt, fn_name);
                }
            }
            ExprKind::If { condition, then_block, else_branch, .. } => {
                self.walk_expr_purity(condition, fn_name);
                for stmt in &then_block.stmts {
                    self.check_stmt_purity(stmt, fn_name);
                }
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(block) => {
                            for stmt in &block.stmts {
                                self.check_stmt_purity(stmt, fn_name);
                            }
                        }
                        ElseBranch::ElseIf(expr) => {
                            self.walk_expr_purity(expr, fn_name);
                        }
                    }
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.walk_expr_purity(left, fn_name);
                self.walk_expr_purity(right, fn_name);
            }
            ExprKind::Unary { operand, .. } => {
                self.walk_expr_purity(operand, fn_name);
            }
            _ => {}
        }
    }

    fn extract_call_name(&self, expr: &Expr) -> Option<String> {
        match &expr.kind {
            ExprKind::Ident(name) => Some(name.clone()),
            ExprKind::FieldAccess { object, field } => {
                if let ExprKind::Ident(obj) = &object.kind {
                    Some(format!("{obj}.{field}"))
                } else {
                    None
                }
            }
            _ => None,
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
        MpcPass::new(&program).check()
    }

    #[test]
    fn test_mpc_valid_annotation() {
        let src = r#"
@mpc(parties: 3, threshold: 2, protocol: .shamir)
fn secret_sum(a: i32, b: i32, c: i32) -> i32 {
    a + b + c
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "valid @mpc should have no errors");
    }

    #[test]
    fn test_mpc_threshold_exceeds_parties() {
        let src = r#"
@mpc(parties: 3, threshold: 5)
fn bad_threshold(a: i32, b: i32) -> i32 {
    a + b
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 1, "should have 1 E1800 error");
        let err = &diags.items[0];
        assert_eq!(err.code, "E1800");
        assert!(err.msg.contains("threshold") && err.msg.contains("exceeds"), "error: {}", err.msg);
    }

    #[test]
    fn test_mpc_invalid_protocol() {
        let src = r#"
@mpc(parties: 3, threshold: 2, protocol: .invalid)
fn bad_proto(a: i32, b: i32) -> i32 {
    a + b
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 1, "should have 1 E1802 error");
        let err = &diags.items[0];
        assert_eq!(err.code, "E1802");
        assert!(err.msg.contains("invalid"), "error: {}", err.msg);
    }

    #[test]
    fn test_mpc_rejects_side_effects() {
        let src = r#"
@mpc(parties: 3, threshold: 2)
fn bad_mpc(a: i32, b: i32) -> i32 {
    print("leaking secret!")
    a + b
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 1, "should have 1 E1803 error");
        let err = &diags.items[0];
        assert_eq!(err.code, "E1803");
        assert!(err.msg.contains("print"), "error: {}", err.msg);
    }

    #[test]
    fn test_mpc_warns_threshold_one() {
        let src = r#"
@mpc(parties: 3, threshold: 1)
fn low_threshold(a: i32, b: i32, c: i32) -> i32 {
    a + b + c
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "threshold 1 is valid but warned");
        let warnings: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W1800")
            .collect();
        assert_eq!(warnings.len(), 1, "should have 1 W1800 warning");
        assert!(warnings[0].msg.contains("threshold: 1"), "warning: {}", warnings[0].msg);
    }

    #[test]
    fn test_mpc_valid_protocols() {
        for proto in &["shamir", "garbled_circuit", "bgw"] {
            let src = format!(
                r#"
@mpc(parties: 2, threshold: 2, protocol: .{proto})
fn compute(a: i32, b: i32) -> i32 {{
    a + b
}}
"#
            );
            let diags = parse_and_check(&src);
            assert_eq!(diags.error_count(), 0, "protocol .{proto} should be valid");
        }
    }
}
