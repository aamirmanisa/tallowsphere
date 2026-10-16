//! Differential privacy budget tracking pass.
//!
//! Enforces privacy budget accounting at compile time:
//!
//! - `@epsilon(value)` declares a function's differential privacy budget
//! - Functions calling `add_noise` must have an `@epsilon` annotation (E0500)
//! - Epsilon values must be positive (E0501)
//! - Cumulative epsilon across composed calls warns when > threshold (W0500)
//! - `@purpose("...")` annotations enforce data minimization (E0506)

use std::collections::HashMap;

use crate::ast::*;
use crate::error::{Diagnostic, Diagnostics};
use crate::typeck::TypeEnv;

// ── DP Budget Pass ──────────────────────────────────────────────────────────

pub struct DPBudgetPass<'a> {
    program: &'a Program,
    #[allow(dead_code)]
    env: &'a TypeEnv,
    pub diags: Diagnostics,
    /// Per-function epsilon values from @epsilon annotations.
    epsilon_map: HashMap<String, f64>,
    /// Per-function purpose strings from @purpose annotations.
    purpose_map: HashMap<String, String>,
    /// Default budget threshold (cumulative epsilon above this warns).
    budget_threshold: f64,
}

impl<'a> DPBudgetPass<'a> {
    pub fn new(program: &'a Program, env: &'a TypeEnv) -> Self {
        Self {
            program,
            env,
            diags: Diagnostics::new(),
            epsilon_map: HashMap::new(),
            purpose_map: HashMap::new(),
            budget_threshold: 1.0,
        }
    }

    /// Run the DP budget pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        // Phase 1: Collect all @epsilon and @purpose annotations
        for item in &self.program.items {
            if let Item::Fn(f) = item {
                self.collect_annotations(f);
            }
        }

        // Phase 2: Check function bodies for add_noise usage without @epsilon,
        // purpose violations at call sites, and budget composition.
        let epsilon_map = self.epsilon_map.clone();
        let purpose_map = self.purpose_map.clone();
        for item in &self.program.items {
            if let Item::Fn(f) = item {
                self.check_function(f, &epsilon_map, &purpose_map);
            }
        }

        self.diags
    }

    /// Extract @epsilon and @purpose annotations from a function declaration.
    fn collect_annotations(&mut self, f: &FnDecl) {
        for ann in &f.annotations {
            match ann.name.as_str() {
                "epsilon" => {
                    if let Some(val) = self.extract_epsilon_value(ann) {
                        if val <= 0.0 {
                            self.diags.push(Diagnostic::error(
                                "E0501",
                                format!(
                                    "invalid epsilon value {val} on function `{}`: must be positive",
                                    f.name
                                ),
                                ann.span,
                            ));
                        } else {
                            self.epsilon_map.insert(f.name.clone(), val);
                        }

                        // Check for custom budget threshold
                        for arg in &ann.args {
                            if arg.name == "budget" {
                                if let Some(b) = self.expr_to_f64(&arg.value) {
                                    self.budget_threshold = b;
                                }
                            }
                        }
                    }
                }
                "purpose" => {
                    if let Some(arg) = ann.args.first() {
                        if let ExprKind::StringLit(ref s) = arg.value.kind {
                            self.purpose_map.insert(f.name.clone(), s.clone());
                        } else if arg.name.is_empty() {
                            // Positional: @purpose("analytics")
                            if let ExprKind::StringLit(ref s) = arg.value.kind {
                                self.purpose_map.insert(f.name.clone(), s.clone());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Extract the epsilon value from an @epsilon annotation.
    /// Supports @epsilon(0.1) or @epsilon(value: 0.1).
    fn extract_epsilon_value(&self, ann: &Annotation) -> Option<f64> {
        // First positional arg or named "value"
        for arg in &ann.args {
            if arg.name.is_empty() || arg.name == "value" {
                return self.expr_to_f64(&arg.value);
            }
        }
        None
    }

    /// Convert an expression to f64 (IntLit or FloatLit).
    fn expr_to_f64(&self, expr: &Expr) -> Option<f64> {
        match &expr.kind {
            ExprKind::FloatLit(f) => Some(*f),
            ExprKind::IntLit(i) => Some(*i as f64),
            ExprKind::Unary { op: UnOp::Neg, operand } => {
                self.expr_to_f64(operand).map(|v| -v)
            }
            _ => None,
        }
    }

    /// Check a function body for:
    /// 1. add_noise usage without @epsilon (E0500)
    /// 2. Purpose violations at call sites (E0506)
    /// 3. Budget composition (W0500)
    fn check_function(
        &mut self,
        f: &FnDecl,
        epsilon_map: &HashMap<String, f64>,
        purpose_map: &HashMap<String, String>,
    ) {
        let has_epsilon = epsilon_map.contains_key(&f.name);
        let caller_purpose = purpose_map.get(&f.name);

        // Check for add_noise usage
        let uses_add_noise = self.body_uses_add_noise(&f.body);
        if uses_add_noise && !has_epsilon {
            self.diags.push(Diagnostic::error(
                "E0500",
                format!(
                    "function `{}` uses `add_noise` but has no @epsilon annotation",
                    f.name
                ),
                f.span,
            ));
        }

        // Check call graph for budget composition and purpose violations
        let mut cumulative_epsilon = epsilon_map.get(&f.name).copied().unwrap_or(0.0);
        let callees = self.collect_callees(&f.body);

        for callee_name in &callees {
            // Budget composition: sum epsilon of called functions
            if let Some(&callee_eps) = epsilon_map.get(callee_name.as_str()) {
                cumulative_epsilon += callee_eps;
            }

            // Purpose violation check
            if let Some(caller_p) = caller_purpose {
                if let Some(callee_p) = purpose_map.get(callee_name.as_str()) {
                    if caller_p != callee_p {
                        self.diags.push(Diagnostic::error(
                            "E0506",
                            format!(
                                "purpose mismatch: `{}` has @purpose(\"{}\") but calls `{}` with @purpose(\"{}\")",
                                f.name, caller_p, callee_name, callee_p
                            ),
                            f.span,
                        ));
                    }
                }
            }
        }

        // Budget threshold warning
        if cumulative_epsilon > self.budget_threshold && has_epsilon {
            self.diags.push(Diagnostic::warning(
                "W0500",
                format!(
                    "cumulative epsilon {cumulative_epsilon:.2} exceeds budget threshold {:.2} in function `{}`",
                    self.budget_threshold, f.name
                ),
                f.span,
            ));
        }
    }

    /// Check if a block contains any `add_noise` method call.
    fn body_uses_add_noise(&self, block: &Block) -> bool {
        for stmt in &block.stmts {
            if self.stmt_uses_add_noise(stmt) {
                return true;
            }
        }
        false
    }

    fn stmt_uses_add_noise(&self, stmt: &Stmt) -> bool {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.expr_uses_add_noise(value)
            }
            StmtKind::Expr { expr } => self.expr_uses_add_noise(expr),
            StmtKind::Return(Some(e)) => self.expr_uses_add_noise(e),
            StmtKind::While { condition, body } => {
                self.expr_uses_add_noise(condition) || self.body_uses_add_noise(body)
            }
            StmtKind::For { iter, body, .. } => {
                self.expr_uses_add_noise(iter) || self.body_uses_add_noise(body)
            }
            _ => false,
        }
    }

    fn expr_uses_add_noise(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::MethodCall {
                object,
                method,
                args,
            } => {
                if method == "add_noise" {
                    return true;
                }
                self.expr_uses_add_noise(object)
                    || args.iter().any(|a| self.expr_uses_add_noise(&a.value))
            }
            ExprKind::Call { callee, args } => {
                self.expr_uses_add_noise(callee)
                    || args.iter().any(|a| self.expr_uses_add_noise(&a.value))
            }
            ExprKind::Binary { left, right, .. } => {
                self.expr_uses_add_noise(left) || self.expr_uses_add_noise(right)
            }
            ExprKind::Unary { operand, .. } => self.expr_uses_add_noise(operand),
            ExprKind::Block(block) => self.body_uses_add_noise(block),
            ExprKind::If { condition, then_block, else_branch, .. } => {
                self.expr_uses_add_noise(condition)
                    || self.body_uses_add_noise(then_block)
                    || else_branch.as_ref().map(|eb| match eb {
                        ElseBranch::ElseIf(e) => self.expr_uses_add_noise(e),
                        ElseBranch::Block(b) => self.body_uses_add_noise(b),
                    }).unwrap_or(false)
            }
            ExprKind::Assign { value, .. } => self.expr_uses_add_noise(value),
            _ => false,
        }
    }

    /// Collect all function names called from a block.
    fn collect_callees(&self, block: &Block) -> Vec<String> {
        let mut callees = Vec::new();
        for stmt in &block.stmts {
            self.collect_callees_from_stmt(stmt, &mut callees);
        }
        callees
    }

    fn collect_callees_from_stmt(&self, stmt: &Stmt, callees: &mut Vec<String>) {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.collect_callees_from_expr(value, callees);
            }
            StmtKind::Expr { expr } => {
                self.collect_callees_from_expr(expr, callees);
            }
            StmtKind::Return(Some(e)) => {
                self.collect_callees_from_expr(e, callees);
            }
            StmtKind::While { condition, body } => {
                self.collect_callees_from_expr(condition, callees);
                for s in &body.stmts {
                    self.collect_callees_from_stmt(s, callees);
                }
            }
            StmtKind::For { iter, body, .. } => {
                self.collect_callees_from_expr(iter, callees);
                for s in &body.stmts {
                    self.collect_callees_from_stmt(s, callees);
                }
            }
            _ => {}
        }
    }

    fn collect_callees_from_expr(&self, expr: &Expr, callees: &mut Vec<String>) {
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                if let ExprKind::Ident(name) = &callee.kind {
                    callees.push(name.clone());
                }
                self.collect_callees_from_expr(callee, callees);
                for a in args {
                    self.collect_callees_from_expr(&a.value, callees);
                }
            }
            ExprKind::MethodCall {
                object, args, ..
            } => {
                self.collect_callees_from_expr(object, callees);
                for a in args {
                    self.collect_callees_from_expr(&a.value, callees);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.collect_callees_from_expr(left, callees);
                self.collect_callees_from_expr(right, callees);
            }
            ExprKind::Unary { operand, .. } => {
                self.collect_callees_from_expr(operand, callees);
            }
            ExprKind::Block(block) => {
                for s in &block.stmts {
                    self.collect_callees_from_stmt(s, callees);
                }
            }
            ExprKind::Assign { value, .. } => {
                self.collect_callees_from_expr(value, callees);
            }
            ExprKind::If { condition, then_block, else_branch, .. } => {
                self.collect_callees_from_expr(condition, callees);
                for s in &then_block.stmts {
                    self.collect_callees_from_stmt(s, callees);
                }
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::ElseIf(e) => self.collect_callees_from_expr(e, callees),
                        ElseBranch::Block(b) => {
                            for s in &b.stmts {
                                self.collect_callees_from_stmt(s, callees);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;
    use crate::parser::Parser;
    use crate::typeck::TypeChecker;

    fn run_dp_pass(source: &str) -> Diagnostics {
        let (tokens, _) = lexer::tokenize(source);
        let program = Parser::parse(tokens).unwrap();
        let (env, _) = TypeChecker::new(&program).check();
        DPBudgetPass::new(&program, &env).check()
    }

    #[test]
    fn dp_valid_epsilon_annotation() {
        let diags = run_dp_pass(
            r#"
@epsilon(0.1)
fn private_query(data: i32) -> i32 {
    data.add_noise(epsilon: 0.1)
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "expected no errors, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn dp_missing_epsilon_on_add_noise() {
        let diags = run_dp_pass(
            r#"
fn bad_query(data: i32) -> i32 {
    data.add_noise(epsilon: 0.1)
}
"#,
        );
        assert!(diags.has_errors());
        assert!(
            diags.items.iter().any(|d| d.code == "E0500"),
            "expected E0500, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn dp_negative_epsilon() {
        let diags = run_dp_pass(
            r#"
@epsilon(-0.5)
fn bad_query(data: i32) -> i32 {
    data
}
"#,
        );
        assert!(diags.has_errors());
        assert!(
            diags.items.iter().any(|d| d.code == "E0501"),
            "expected E0501, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn dp_budget_exceeded_warning() {
        // Two functions each with 0.6 epsilon. Caller calls both => cumulative 1.8 > 1.0
        let diags = run_dp_pass(
            r#"
@epsilon(0.6)
fn query_a(x: i32) -> i32 {
    x.add_noise(epsilon: 0.6)
}

@epsilon(0.6)
fn query_b(x: i32) -> i32 {
    x.add_noise(epsilon: 0.6)
}

@epsilon(0.6)
fn combined(x: i32) -> i32 {
    let a = query_a(x)
    query_b(a)
}
"#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "W0500"),
            "expected W0500 budget warning, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn dp_purpose_violation() {
        let diags = run_dp_pass(
            r#"
@purpose("analytics")
fn analyze(x: i32) -> i32 { x }

@purpose("marketing")
fn market(x: i32) -> i32 {
    analyze(x)
}
"#,
        );
        assert!(diags.has_errors());
        assert!(
            diags.items.iter().any(|d| d.code == "E0506"),
            "expected E0506, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn dp_valid_same_purpose() {
        let diags = run_dp_pass(
            r#"
@purpose("analytics")
fn analyze(x: i32) -> i32 { x }

@purpose("analytics")
fn report(x: i32) -> i32 {
    analyze(x)
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "expected no errors for matching purpose, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn dp_no_annotations_no_noise_is_fine() {
        let diags = run_dp_pass(
            r#"
fn normal_fn(x: i32) -> i32 { x }
"#,
        );
        assert!(
            !diags.has_errors(),
            "expected no errors, got: {:?}",
            diags.items
        );
    }
}
