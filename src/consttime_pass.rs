//! Constant-time verification pass.
//!
//! Rejects cryptographic functions containing secret-dependent branches
//! or variable-time memory access patterns, ensuring constant-time
//! execution for all code handling `secret` types.
//!
//! - E1200: secret-dependent branch (if/if-let on tainted value)
//! - E1201: secret-dependent match on tainted value
//! - E1202: secret-dependent loop bound (while/for on tainted value)
//! - E1203: secret-dependent memory access (index by tainted value)
//! - E1204: secret-dependent division/modulo (KyberSlash-class timing)
//! - W1200: function has secret params but no @constant_time annotation

use std::collections::{HashMap, HashSet};

use crate::ast::*;
use crate::error::{Diagnostic, Diagnostics};
use crate::typeck::TypeEnv;

/// Methods that are safe to call on secret/tainted values (constant-time by design).
const ALLOWLISTED_METHODS: &[&str] = &[
    "verify",
    "hash",
    "encrypt",
    "decrypt",
    "sign",
    "compare_constant_time",
    "redact",
    "mask",
    "wipe",
];

// ── Constant-Time Pass ──────────────────────────────────────────────────────

pub struct ConstTimePass<'a> {
    program: &'a Program,
    env: &'a TypeEnv,
    pub diags: Diagnostics,
    /// fn name -> set of secret-typed param names
    secret_params: HashMap<String, HashSet<String>>,
}

impl<'a> ConstTimePass<'a> {
    pub fn new(program: &'a Program, env: &'a TypeEnv) -> Self {
        Self {
            program,
            env,
            diags: Diagnostics::new(),
            secret_params: HashMap::new(),
        }
    }

    /// Run the constant-time pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        // Phase 1: Collect secret params for all functions
        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.collect_secret_params(f),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.collect_secret_params(m);
                    }
                }
                _ => {}
            }
        }

        // Phase 2: Validate functions with secret params or @constant_time
        let secret_params = self.secret_params.clone();
        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.validate_function(f, &secret_params),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.validate_function(m, &secret_params);
                    }
                }
                _ => {}
            }
        }

        self.diags
    }

    /// Inspect function params and determine which are secret-typed.
    fn collect_secret_params(&mut self, f: &FnDecl) {
        let mut secrets = HashSet::new();

        if let Some(sig) = self.env.functions.get(&f.name) {
            for (name, ty) in &sig.params {
                if ty.is_secret() {
                    secrets.insert(name.clone());
                }
            }
        }

        if !secrets.is_empty() {
            self.secret_params.insert(f.name.clone(), secrets);
        }
    }

    /// Check if function has @constant_time annotation.
    fn has_constant_time_annotation(f: &FnDecl) -> bool {
        f.annotations.iter().any(|a| a.name == "constant_time")
    }

    /// Validate a function body for constant-time violations.
    fn validate_function(
        &mut self,
        f: &FnDecl,
        secret_params: &HashMap<String, HashSet<String>>,
    ) {
        let has_secrets = secret_params.contains_key(&f.name);
        let has_annotation = Self::has_constant_time_annotation(f);

        // W1200: has secret params but no @constant_time
        if has_secrets && !has_annotation {
            self.diags.push(Diagnostic::warning(
                "W1200",
                format!(
                    "function `{}` has secret parameters but is not marked @constant_time",
                    f.name
                ),
                f.span,
            ));
        }

        // Only validate body if function has secret params or @constant_time
        if !has_secrets && !has_annotation {
            return;
        }

        // Build initial tainted set from secret params
        let mut tainted = if let Some(sp) = secret_params.get(&f.name) {
            sp.clone()
        } else {
            HashSet::new()
        };

        // Walk body: propagate taint and check for violations
        self.check_block(&f.body, &mut tainted, &f.name);
    }

    /// Walk a block, propagating taint and checking for violations.
    fn check_block(&mut self, block: &Block, tainted: &mut HashSet<String>, fn_name: &str) {
        for stmt in &block.stmts {
            self.check_stmt(stmt, tainted, fn_name);
        }
    }

    /// Check a statement for taint propagation and violations.
    fn check_stmt(&mut self, stmt: &Stmt, tainted: &mut HashSet<String>, fn_name: &str) {
        match &stmt.kind {
            StmtKind::Let { name, value, .. } | StmtKind::Var { name, value, .. } => {
                // Taint propagation: if RHS references tainted var, taint LHS
                if Self::expr_references_tainted(value, tainted) {
                    tainted.insert(name.clone());
                }
                // Also check the value expression itself for violations
                self.check_expr(value, tainted, fn_name);
            }
            StmtKind::LetDestructure { names, value } => {
                if Self::expr_references_tainted(value, tainted) {
                    for name in names {
                        tainted.insert(name.clone());
                    }
                }
                self.check_expr(value, tainted, fn_name);
            }
            StmtKind::Expr { expr } => {
                self.check_expr(expr, tainted, fn_name);
            }
            StmtKind::Return(Some(expr)) => {
                self.check_expr(expr, tainted, fn_name);
            }
            StmtKind::While { condition, body } => {
                // E1202: secret-dependent loop bound
                if Self::expr_references_tainted(condition, tainted) {
                    self.diags.push(Diagnostic::error(
                        "E1202",
                        format!("secret-dependent loop bound in function `{fn_name}`"),
                        stmt.span,
                    ));
                }
                self.check_expr(condition, tainted, fn_name);
                self.check_block(body, tainted, fn_name);
            }
            StmtKind::For { iter, body, .. } => {
                // E1202: secret-dependent loop iteration
                if Self::expr_references_tainted(iter, tainted) {
                    self.diags.push(Diagnostic::error(
                        "E1202",
                        format!("secret-dependent loop bound in function `{fn_name}`"),
                        stmt.span,
                    ));
                }
                self.check_expr(iter, tainted, fn_name);
                self.check_block(body, tainted, fn_name);
            }
            StmtKind::WhileLet { expr, body, .. } => {
                if Self::expr_references_tainted(expr, tainted) {
                    self.diags.push(Diagnostic::error(
                        "E1202",
                        format!("secret-dependent loop bound in function `{fn_name}`"),
                        stmt.span,
                    ));
                }
                self.check_expr(expr, tainted, fn_name);
                self.check_block(body, tainted, fn_name);
            }
            StmtKind::Loop { body } => {
                self.check_block(body, tainted, fn_name);
            }
            StmtKind::Bail(expr) => {
                self.check_expr(expr, tainted, fn_name);
            }
            _ => {}
        }
    }

    /// Check an expression for constant-time violations.
    fn check_expr(&mut self, expr: &Expr, tainted: &mut HashSet<String>, fn_name: &str) {
        match &expr.kind {
            ExprKind::If {
                condition,
                then_block,
                else_branch,
            } => {
                // E1200: secret-dependent branch
                if Self::expr_references_tainted(condition, tainted) {
                    self.diags.push(Diagnostic::error(
                        "E1200",
                        format!("secret-dependent branch in function `{fn_name}`"),
                        expr.span,
                    ));
                }
                self.check_expr(condition, tainted, fn_name);
                self.check_block(then_block, tainted, fn_name);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::ElseIf(e) => self.check_expr(e, tainted, fn_name),
                        ElseBranch::Block(b) => self.check_block(b, tainted, fn_name),
                    }
                }
            }
            ExprKind::IfLet {
                expr: subject,
                then_block,
                else_branch,
                ..
            } => {
                // E1200: secret-dependent branch (if-let)
                if Self::expr_references_tainted(subject, tainted) {
                    self.diags.push(Diagnostic::error(
                        "E1200",
                        format!("secret-dependent branch in function `{fn_name}`"),
                        expr.span,
                    ));
                }
                self.check_expr(subject, tainted, fn_name);
                self.check_block(then_block, tainted, fn_name);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::ElseIf(e) => self.check_expr(e, tainted, fn_name),
                        ElseBranch::Block(b) => self.check_block(b, tainted, fn_name),
                    }
                }
            }
            ExprKind::Match { subject, arms } => {
                // E1201: secret-dependent match
                if Self::expr_references_tainted(subject, tainted) {
                    self.diags.push(Diagnostic::error(
                        "E1201",
                        format!("secret-dependent match in function `{fn_name}`"),
                        expr.span,
                    ));
                }
                self.check_expr(subject, tainted, fn_name);
                for arm in arms {
                    self.check_expr(&arm.body, tainted, fn_name);
                }
            }
            ExprKind::Index { object, index } => {
                // E1203: secret-dependent memory access
                if Self::expr_references_tainted(index, tainted) {
                    self.diags.push(Diagnostic::error(
                        "E1203",
                        format!("secret-dependent memory access in function `{fn_name}`"),
                        expr.span,
                    ));
                }
                self.check_expr(object, tainted, fn_name);
                self.check_expr(index, tainted, fn_name);
            }
            ExprKind::Binary { op, left, right } => {
                // E1204: secret-dependent division/modulo (KyberSlash-class)
                if matches!(op, BinOp::Div | BinOp::Mod) {
                    if Self::expr_references_tainted(left, tainted)
                        || Self::expr_references_tainted(right, tainted)
                    {
                        self.diags.push(Diagnostic::error(
                            "E1204",
                            format!("secret-dependent division/modulo in function `{fn_name}` (KyberSlash-class timing vulnerability)"),
                            expr.span,
                        ));
                    }
                }
                self.check_expr(left, tainted, fn_name);
                self.check_expr(right, tainted, fn_name);
            }
            ExprKind::Unary { operand, .. } => {
                self.check_expr(operand, tainted, fn_name);
            }
            ExprKind::Call { callee, args } => {
                self.check_expr(callee, tainted, fn_name);
                for a in args {
                    self.check_expr(&a.value, tainted, fn_name);
                }
            }
            ExprKind::MethodCall {
                object, args, ..
            } => {
                // Don't recurse into allowlisted method calls on tainted objects
                // (they are safe by design)
                self.check_expr(object, tainted, fn_name);
                for a in args {
                    self.check_expr(&a.value, tainted, fn_name);
                }
            }
            ExprKind::FieldAccess { object, .. } => {
                self.check_expr(object, tainted, fn_name);
            }
            ExprKind::Block(block) => {
                self.check_block(block, tainted, fn_name);
            }
            ExprKind::Assign { target, value } => {
                self.check_expr(target, tainted, fn_name);
                self.check_expr(value, tainted, fn_name);
            }
            ExprKind::Try(inner) => {
                self.check_expr(inner, tainted, fn_name);
            }
            ExprKind::Await(inner) => {
                self.check_expr(inner, tainted, fn_name);
            }
            ExprKind::Cast { expr: inner, .. } => {
                self.check_expr(inner, tainted, fn_name);
            }
            ExprKind::Array(elems) => {
                for e in elems {
                    self.check_expr(e, tainted, fn_name);
                }
            }
            ExprKind::Closure { body, .. } => {
                for s in body {
                    self.check_stmt(s, tainted, fn_name);
                }
            }
            ExprKind::Interpolation(parts) => {
                for part in parts {
                    if let StringPart::Expr(e) = part {
                        self.check_expr(e, tainted, fn_name);
                    }
                }
            }
            _ => {}
        }
    }

    /// Recursively check if an expression references any tainted variable.
    /// Handles allowlisted methods: a method call like `secret.verify(...)` does
    /// NOT count as referencing a tainted value for branch/index purposes.
    fn expr_references_tainted(expr: &Expr, tainted: &HashSet<String>) -> bool {
        match &expr.kind {
            ExprKind::Ident(name) => tainted.contains(name),
            ExprKind::Binary { left, right, .. } => {
                Self::expr_references_tainted(left, tainted)
                    || Self::expr_references_tainted(right, tainted)
            }
            ExprKind::Unary { operand, .. } => {
                Self::expr_references_tainted(operand, tainted)
            }
            ExprKind::Call { callee, args } => {
                Self::expr_references_tainted(callee, tainted)
                    || args
                        .iter()
                        .any(|a| Self::expr_references_tainted(&a.value, tainted))
            }
            ExprKind::MethodCall {
                object,
                method,
                args,
            } => {
                // Allowlisted methods on tainted objects are safe
                if ALLOWLISTED_METHODS.contains(&method.as_str()) {
                    // The object can be tainted; that's fine for allowlisted methods.
                    // But still check the args (non-object) for taint.
                    return args
                        .iter()
                        .any(|a| Self::expr_references_tainted(&a.value, tainted));
                }
                Self::expr_references_tainted(object, tainted)
                    || args
                        .iter()
                        .any(|a| Self::expr_references_tainted(&a.value, tainted))
            }
            ExprKind::FieldAccess { object, .. } => {
                Self::expr_references_tainted(object, tainted)
            }
            ExprKind::Index { object, index } => {
                Self::expr_references_tainted(object, tainted)
                    || Self::expr_references_tainted(index, tainted)
            }
            ExprKind::Try(inner) => Self::expr_references_tainted(inner, tainted),
            ExprKind::Await(inner) => Self::expr_references_tainted(inner, tainted),
            ExprKind::Cast { expr: inner, .. } => {
                Self::expr_references_tainted(inner, tainted)
            }
            _ => false,
        }
    }
}

// ── IR Verification Helper ───────────────────────────────────────────────────

/// Scan LLVM IR text for non-constant-time branches (`br i1`) inside a named
/// function.  Returns a list of warning strings for each branch found.
/// Matches both quoted (`@"tallow.fn_name"`) and unquoted (`@tallow.fn_name`) forms.
pub fn ir_verify_constant_time(ir_text: &str, fn_name: &str) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut in_function = false;
    let quoted_pattern = format!("@\"tallow.{fn_name}\"");
    let unquoted_pattern = format!("@tallow.{fn_name}(");
    for (i, line) in ir_text.lines().enumerate() {
        if line.starts_with("define")
            && (line.contains(&quoted_pattern) || line.contains(&unquoted_pattern))
        {
            in_function = true;
            continue;
        }
        if in_function && line.starts_with('}') {
            break;
        }
        if in_function && line.trim_start().starts_with("br i1") {
            warnings.push(format!(
                "W1201: non-constant-time branch at IR line {} in function `{fn_name}`",
                i + 1
            ));
        }
    }
    warnings
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;
    use crate::parser::Parser;
    use crate::typeck::TypeChecker;

    fn run_consttime_pass(source: &str) -> Diagnostics {
        let (tokens, _) = lexer::tokenize(source);
        let program = Parser::parse(tokens).unwrap();
        let (env, _) = TypeChecker::new(&program).check();
        ConstTimePass::new(&program, &env).check()
    }

    #[test]
    fn secret_param_if_branch_e1200() {
        let diags = run_consttime_pass(
            r#"
type Password = secret String

fn bad_compare(pw: Password, input: String) -> bool {
    if pw == input {
        true
    } else {
        false
    }
}
"#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "E1200"),
            "expected E1200, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn secret_param_match_e1201() {
        let diags = run_consttime_pass(
            r#"
type Token = secret String

fn bad_match(tok: Token) -> i32 {
    tok match {
        _ -> 0
    }
}
"#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "E1201"),
            "expected E1201, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn secret_param_while_condition_e1202() {
        let diags = run_consttime_pass(
            r#"
type Password = secret String

fn bad_loop(pw: Password) -> i32 {
    var count = 0
    while pw == "test" {
        count = count + 1
    }
    count
}
"#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "E1202"),
            "expected E1202, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn secret_param_index_e1203() {
        let diags = run_consttime_pass(
            r#"
type Token = secret String

fn bad_index(key: Token, data: []i32) -> i32 {
    let idx = key.len()
    data[idx]
}
"#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "E1203"),
            "expected E1203, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn allowlisted_verify_no_error() {
        let diags = run_consttime_pass(
            r#"
type Password = secret String

fn good_verify(pw: Password, hash: String) -> bool {
    pw.verify(hash)
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "expected no errors for allowlisted .verify(), got: {:?}",
            diags.items
        );
    }

    #[test]
    fn allowlisted_hash_no_error() {
        let diags = run_consttime_pass(
            r#"
type Password = secret String

fn good_hash(pw: Password) -> String {
    pw.hash()
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "expected no errors for allowlisted .hash(), got: {:?}",
            diags.items
        );
    }

    #[test]
    fn no_secret_params_no_errors() {
        let diags = run_consttime_pass(
            r#"
fn normal_fn(x: i32) -> i32 {
    if x > 0 {
        x
    } else {
        0
    }
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "expected no errors, got: {:?}",
            diags.items
        );
        assert!(
            !diags.items.iter().any(|d| d.code == "W1200"),
            "expected no W1200 warning for non-secret function"
        );
    }

    #[test]
    fn taint_propagation_e1200() {
        let diags = run_consttime_pass(
            r#"
type Password = secret String

fn bad_propagate(pw: Password) -> bool {
    let x = pw
    if x == "test" {
        true
    } else {
        false
    }
}
"#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "E1200"),
            "expected E1200 via taint propagation, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn constant_time_annotation_validates_body() {
        let diags = run_consttime_pass(
            r#"
@constant_time
fn timing_safe(a: String, b: String) -> bool {
    if a == b {
        true
    } else {
        false
    }
}
"#,
        );
        // @constant_time with non-secret params: no tainted vars, so no E1200
        // (the annotation marks the function for checking, but there's nothing tainted)
        assert!(
            !diags.has_errors(),
            "expected no errors when no tainted values, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn w1200_missing_constant_time_annotation() {
        let diags = run_consttime_pass(
            r#"
type Password = secret String

fn missing_annotation(pw: Password) -> String {
    pw.hash()
}
"#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "W1200"),
            "expected W1200 warning, got: {:?}",
            diags.items
        );
    }

    // ── E1204 KyberSlash tests ───────────────────────────────────────────

    #[test]
    fn test_e1204_division_on_secret() {
        let diags = run_consttime_pass(
            r#"
type SecretI32 = secret i32

@constant_time
fn f(x: SecretI32) -> i32 {
    x / 3329
}
"#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "E1204"),
            "expected E1204 for secret-dependent division, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn test_e1204_modulo_on_secret() {
        let diags = run_consttime_pass(
            r#"
type SecretI32 = secret i32

@constant_time
fn f(x: SecretI32) -> i32 {
    x % 256
}
"#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "E1204"),
            "expected E1204 for secret-dependent modulo, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn test_e1204_no_error_on_non_secret_div() {
        let diags = run_consttime_pass(
            r#"
@constant_time
fn f(x: i32) -> i32 {
    x / 2
}
"#,
        );
        assert!(
            !diags.items.iter().any(|d| d.code == "E1204"),
            "expected no E1204 for non-secret division, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn test_e1204_taint_through_division() {
        let diags = run_consttime_pass(
            r#"
type SecretI32 = secret i32

@constant_time
fn f(x: SecretI32) -> i32 {
    let y = x + 1
    y / 3
}
"#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "E1204"),
            "expected E1204 via taint propagation through division, got: {:?}",
            diags.items
        );
    }

    // ── IR verification tests ────────────────────────────────────────────

    #[test]
    fn test_ir_verify_detects_branch() {
        let ir = r#"
define i32 @"tallow.check_key"() {
entry:
  %cmp = icmp eq i32 %0, %1
  br i1 %cmp, label %then, label %else
then:
  ret i32 1
else:
  ret i32 0
}
"#;
        let warnings = super::ir_verify_constant_time(ir, "check_key");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("W1201"));
        assert!(warnings[0].contains("check_key"));
    }

    #[test]
    fn test_ir_verify_clean_function() {
        let ir = r#"
define i32 @"tallow.safe_add"() {
entry:
  %sum = add i32 %0, %1
  ret i32 %sum
}
"#;
        let warnings = super::ir_verify_constant_time(ir, "safe_add");
        assert!(
            warnings.is_empty(),
            "expected no warnings for branch-free function, got: {:?}",
            warnings
        );
    }
}
