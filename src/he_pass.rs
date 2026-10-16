//! Homomorphic encryption type flow validation pass.
//!
//! Validates usage of `encrypted<T>` typed values:
//! - W1510: Encrypted value used in if/match/while condition (FHE comparison produces encrypted<bool>, not usable as branch condition)
//! - W1511: Encrypted value passed to print/log (information leakage risk)
//!
//! The `encrypted<T>` type enables arithmetic on ciphertext values. Binary operations
//! on two encrypted values produce encrypted results. Mixing encrypted and plaintext
//! values in arithmetic is a type error (caught by typeck, not here).

use std::collections::HashSet;

use crate::ast::*;
use crate::error::Diagnostics;

// ── I/O sinks that leak encrypted values ────────────────────────────────────

const PRINT_FUNCTIONS: &[&str] = &[
    "print", "println",
    "log.info", "log.debug", "log.warn", "log.error", "log.fatal",
];

// ── Pass ─────────────────────────────────────────────────────────────────────

pub struct HePass<'a> {
    program: &'a Program,
    pub diags: Diagnostics,
    /// Variable names known to hold encrypted<T> values.
    encrypted_vars: HashSet<String>,
}

impl<'a> HePass<'a> {
    pub fn new(program: &'a Program) -> Self {
        Self {
            program,
            diags: Diagnostics::new(),
            encrypted_vars: HashSet::new(),
        }
    }

    /// Run the HE pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        // Walk all items looking for encrypted<T> usage
        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.check_fn_body(f),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.check_fn_body(m);
                    }
                }
                _ => {}
            }
        }

        self.diags
    }

    fn check_fn_body(&mut self, f: &FnDecl) {
        // Collect params that are encrypted<T>
        let mut fn_encrypted = HashSet::new();
        for param in &f.params {
            if self.is_encrypted_type(&param.ty) {
                fn_encrypted.insert(param.name.clone());
            }
        }
        // Also check return type


        // Save and restore per-function
        let prev = std::mem::replace(&mut self.encrypted_vars, fn_encrypted);
        for stmt in &f.body.stmts {
            self.check_stmt(stmt);
        }
        self.encrypted_vars = prev;
    }

    fn check_stmt(&mut self, stmt: &Stmt) {
        match &stmt.kind {
            StmtKind::Let { name, ty, value, .. } | StmtKind::Var { name, ty, value, .. } => {
                // Track if bound to encrypted type or encrypted value
                if ty.as_ref().map_or(false, |t| self.is_encrypted_type(t)) {
                    self.encrypted_vars.insert(name.clone());
                } else if self.expr_is_encrypted(value) {
                    self.encrypted_vars.insert(name.clone());
                }
                self.check_expr(value);
            }
            StmtKind::LetDestructure { value, .. } => {
                self.check_expr(value);
            }
            StmtKind::Expr { expr } => {
                self.check_expr(expr);
            }
            StmtKind::Return(Some(expr)) => {
                self.check_expr(expr);
            }
            StmtKind::While { condition, body } => {
                if self.expr_is_encrypted(condition) {
                    self.diags.warning(
                        "W1510",
                        "encrypted value used as loop condition \
                         -- FHE comparison produces encrypted<bool>, not a usable condition"
                            .to_string(),
                        condition.span,
                    );
                }
                self.check_expr(condition);
                for stmt in &body.stmts {
                    self.check_stmt(stmt);
                }
            }
            StmtKind::For { body, iter, .. } => {
                self.check_expr(iter);
                for stmt in &body.stmts {
                    self.check_stmt(stmt);
                }
            }
            _ => {}
        }
    }

    fn check_expr(&mut self, expr: &Expr) {
        match &expr.kind {
            // W1510: encrypted value as branch condition
            ExprKind::If { condition, then_block, else_branch, .. } => {
                if self.expr_is_encrypted(condition) {
                    self.diags.warning(
                        "W1510",
                        "encrypted value used as branch condition \
                         -- FHE comparison produces encrypted<bool>, not a usable condition"
                            .to_string(),
                        condition.span,
                    );
                }
                self.check_expr(condition);
                for stmt in &then_block.stmts {
                    self.check_stmt(stmt);
                }
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(block) => {
                            for stmt in &block.stmts {
                                self.check_stmt(stmt);
                            }
                        }
                        ElseBranch::ElseIf(expr) => {
                            self.check_expr(expr);
                        }
                    }
                }
            }
            // W1511: encrypted value passed to print/log
            ExprKind::Call { callee, args, .. } => {
                let callee_name = self.extract_call_name(callee);
                if let Some(ref name) = callee_name {
                    if PRINT_FUNCTIONS.contains(&name.as_str()) {
                        for arg in args {
                            if self.expr_is_encrypted(&arg.value) {
                                self.diags.warning(
                                    "W1511",
                                    format!(
                                        "encrypted value passed to '{name}' \
                                         -- information leakage risk"
                                    ),
                                    arg.value.span,
                                );
                            }
                        }
                    }
                }
                for arg in args {
                    self.check_expr(&arg.value);
                }
            }
            ExprKind::MethodCall { object, method, args, .. } => {
                // Check for log.* calls
                if let ExprKind::Ident(ref obj_name) = object.kind {
                    let full_name = format!("{obj_name}.{method}");
                    if PRINT_FUNCTIONS.contains(&full_name.as_str()) {
                        for arg in args {
                            if self.expr_is_encrypted(&arg.value) {
                                self.diags.warning(
                                    "W1511",
                                    format!(
                                        "encrypted value passed to '{full_name}' \
                                         -- information leakage risk"
                                    ),
                                    arg.value.span,
                                );
                            }
                        }
                    }
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
            ExprKind::Unary { operand, .. } => {
                self.check_expr(operand);
            }
            ExprKind::Block(block) => {
                for stmt in &block.stmts {
                    self.check_stmt(stmt);
                }
            }
            ExprKind::Match { subject, arms } => {
                if self.expr_is_encrypted(subject) {
                    self.diags.warning(
                        "W1510",
                        "encrypted value used as match subject \
                         -- encrypted values cannot be pattern-matched"
                            .to_string(),
                        subject.span,
                    );
                }
                self.check_expr(subject);
                for arm in arms {
                    self.check_expr(&arm.body);
                }
            }
            _ => {}
        }
    }

    /// Check if an expression likely evaluates to an encrypted value.
    fn expr_is_encrypted(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Ident(name) => self.encrypted_vars.contains(name),
            // Method call: .encrypt() returns encrypted
            ExprKind::MethodCall { method, .. } if method == "encrypt" => true,
            // Binary op on two encrypted operands produces encrypted
            ExprKind::Binary { left, right, .. } => {
                self.expr_is_encrypted(left) && self.expr_is_encrypted(right)
            }
            _ => false,
        }
    }

    /// Check if a type annotation refers to encrypted<T>.
    fn is_encrypted_type(&self, ty: &TypeExpr) -> bool {
        if let TypeExprKind::Named(name) = &ty.kind {
            if name == "encrypted" {
                return true;
            }
        }
        if let TypeExprKind::Generic { name, .. } = &ty.kind {
            if name == "encrypted" {
                return true;
            }
        }
        false
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
        HePass::new(&program).check()
    }

    #[test]
    fn test_he_pass_warns_encrypted_in_condition() {
        let src = r#"
fn test_branch(enc_val: encrypted<i32>) {
    if enc_val {
        print("yes")
    }
}
"#;
        let diags = parse_and_check(src);
        let w1510: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W1510")
            .collect();
        assert!(!w1510.is_empty(), "should have W1510 warning for encrypted in condition");
    }

    #[test]
    fn test_he_pass_warns_encrypted_in_print() {
        let src = r#"
fn test_leak(enc_val: encrypted<i32>) {
    print(enc_val)
}
"#;
        let diags = parse_and_check(src);
        let w1511: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W1511")
            .collect();
        assert!(!w1511.is_empty(), "should have W1511 warning for encrypted in print");
    }

    #[test]
    fn test_he_pass_no_warnings_for_normal_values() {
        let src = r#"
fn test_normal(x: i32) {
    if x > 0 {
        print(x)
    }
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.items.len(), 0, "no warnings for non-encrypted values");
    }

    #[test]
    fn test_he_pass_tracks_encrypted_through_let() {
        let src = r#"
fn test_track(enc_val: encrypted<i32>) {
    let x = enc_val
    print(x)
}
"#;
        let diags = parse_and_check(src);
        let w1511: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W1511")
            .collect();
        assert!(!w1511.is_empty(), "should track encrypted through let binding");
    }

    #[test]
    fn test_he_pass_warns_encrypted_in_while() {
        let src = r#"
fn test_while(enc_val: encrypted<bool>) {
    while enc_val {
        let x = 1
    }
}
"#;
        let diags = parse_and_check(src);
        let w1510: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W1510")
            .collect();
        assert!(!w1510.is_empty(), "should have W1510 warning for encrypted in while condition");
    }
}
