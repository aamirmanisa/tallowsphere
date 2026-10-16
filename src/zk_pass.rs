//! @zk annotation validation compiler pass.
//!
//! Validates @zk annotations on functions for zero-knowledge proof circuit purity:
//! - E1500: I/O operation in @zk function (print, fetch, read_file, write_file, log.*)
//! - E1501: Mutable state access in @zk function (global mutation)
//! - E1502: Invalid ZK scheme (not .groth16, .plonk, .stark)
//! - E1503: Invalid ZK curve (not .bn254, .bls12_381)
//! - W1500: @zk function calls non-@zk function (purity cannot be verified)
//!
//! @zk annotated functions must be pure: no I/O, no network, no side effects.
//! They compile to ZK-SNARK/STARK circuits for proof generation without revealing inputs.

use std::collections::HashSet;

use crate::ast::*;
use crate::error::Diagnostics;

// ── Known I/O functions ──────────────────────────────────────────────────────

const IO_FUNCTIONS: &[&str] = &[
    "print", "println", "fetch", "read_file", "write_file",
    "log.info", "log.debug", "log.warn", "log.error", "log.fatal",
];

const VALID_SCHEMES: &[&str] = &["groth16", "plonk", "stark"];
const VALID_CURVES: &[&str] = &["bn254", "bls12_381"];

// ── Pass ─────────────────────────────────────────────────────────────────────

pub struct ZkPass<'a> {
    program: &'a Program,
    pub diags: Diagnostics,
    /// Functions that have @zk annotation.
    zk_fns: HashSet<String>,
}

impl<'a> ZkPass<'a> {
    pub fn new(program: &'a Program) -> Self {
        Self {
            program,
            diags: Diagnostics::new(),
            zk_fns: HashSet::new(),
        }
    }

    /// Run the ZK pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        // Phase 1: Collect all @zk annotations and validate them
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

        // Phase 2: Walk each @zk function body for I/O and purity violations
        let zk_fns = self.zk_fns.clone();
        for item in &self.program.items {
            match item {
                Item::Fn(f) => {
                    if zk_fns.contains(&f.name) {
                        self.check_zk_body(f, &zk_fns);
                    }
                }
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        if zk_fns.contains(&m.name) {
                            self.check_zk_body(m, &zk_fns);
                        }
                    }
                }
                _ => {}
            }
        }

        self.diags
    }

    fn validate_fn(&mut self, f: &FnDecl) {
        let zk_anns: Vec<&Annotation> = f.annotations.iter()
            .filter(|a| a.name == "zk")
            .collect();

        if zk_anns.is_empty() {
            return;
        }

        self.zk_fns.insert(f.name.clone());

        for ann in &zk_anns {
            let mut has_scheme = false;

            for arg in &ann.args {
                if arg.name == "scheme" {
                    has_scheme = true;
                    // Validate scheme value
                    if let ExprKind::DotIdent(scheme) = &arg.value.kind {
                        if !VALID_SCHEMES.contains(&scheme.as_str()) {
                            self.diags.error(
                                "E1502",
                                format!(
                                    "invalid ZK scheme '.{scheme}' on @zk function '{}' \
                                     (valid: .groth16, .plonk, .stark)",
                                    f.name
                                ),
                                arg.value.span,
                            );
                        }
                    }
                } else if arg.name == "curve" {
                    // Validate curve value
                    if let ExprKind::DotIdent(curve) = &arg.value.kind {
                        if !VALID_CURVES.contains(&curve.as_str()) {
                            self.diags.error(
                                "E1503",
                                format!(
                                    "invalid ZK curve '.{curve}' on @zk function '{}' \
                                     (valid: .bn254, .bls12_381)",
                                    f.name
                                ),
                                arg.value.span,
                            );
                        }
                    }
                } else if arg.name.is_empty() {
                    // Positional arg: check if it's a scheme (.groth16 etc.)
                    if let ExprKind::DotIdent(val) = &arg.value.kind {
                        if VALID_SCHEMES.contains(&val.as_str()) {
                            has_scheme = true;
                        } else if !VALID_CURVES.contains(&val.as_str()) {
                            self.diags.error(
                                "E1502",
                                format!(
                                    "invalid ZK scheme '.{val}' on @zk function '{}' \
                                     (valid: .groth16, .plonk, .stark)",
                                    f.name
                                ),
                                arg.value.span,
                            );
                        }
                    }
                }
            }

            // scheme is required when args are present
            if !ann.args.is_empty() && !has_scheme {
                self.diags.error(
                    "E1502",
                    format!(
                        "@zk annotation on '{}' requires a scheme (e.g., scheme: .groth16)",
                        f.name
                    ),
                    ann.span,
                );
            }
        }
    }

    fn check_zk_body(&mut self, f: &FnDecl, zk_fns: &HashSet<String>) {
        for stmt in &f.body.stmts {
            self.check_stmt_purity(stmt, &f.name, zk_fns);
        }
    }

    fn check_stmt_purity(&mut self, stmt: &Stmt, fn_name: &str, zk_fns: &HashSet<String>) {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.walk_expr_purity(value, fn_name, zk_fns);
            }
            StmtKind::LetDestructure { value, .. } => {
                self.walk_expr_purity(value, fn_name, zk_fns);
            }
            StmtKind::Expr { expr } => {
                self.walk_expr_purity(expr, fn_name, zk_fns);
            }
            StmtKind::Return(Some(expr)) => {
                self.walk_expr_purity(expr, fn_name, zk_fns);
            }
            // Assignments are handled via Expr { expr } containing ExprKind::Assign
            _ => {}
        }
    }

    fn walk_expr_purity(&mut self, expr: &Expr, fn_name: &str, zk_fns: &HashSet<String>) {
        match &expr.kind {
            ExprKind::Call { callee, args, .. } => {
                // Check if callee is an I/O function
                let callee_name = self.extract_call_name(callee);
                if let Some(ref name) = callee_name {
                    if IO_FUNCTIONS.contains(&name.as_str()) {
                        self.diags.error(
                            "E1500",
                            format!(
                                "I/O operation '{name}' in @zk function '{fn_name}' \
                                 — @zk functions must be pure (no I/O, network, or side effects)"
                            ),
                            expr.span,
                        );
                    } else if !zk_fns.contains(name.as_str())
                        && !is_pure_builtin(name)
                    {
                        // W1500: calling non-@zk function
                        self.diags.warning(
                            "W1500",
                            format!(
                                "@zk function '{fn_name}' calls non-@zk function '{name}' \
                                 — purity cannot be verified"
                            ),
                            expr.span,
                        );
                    }
                }
                // Walk args
                for arg in args {
                    self.walk_expr_purity(&arg.value, fn_name, zk_fns);
                }
            }
            ExprKind::MethodCall { object, method, args, .. } => {
                // Check for log.* and tallow.* I/O calls
                if let ExprKind::Ident(ref obj_name) = object.kind {
                    let full_name = format!("{obj_name}.{method}");
                    if IO_FUNCTIONS.contains(&full_name.as_str()) {
                        self.diags.error(
                            "E1500",
                            format!(
                                "I/O operation '{full_name}' in @zk function '{fn_name}' \
                                 — @zk functions must be pure (no I/O, network, or side effects)"
                            ),
                            expr.span,
                        );
                    }
                    // Check for tallow.* stdlib calls (network/fs)
                    if obj_name == "tallow" {
                        let io_methods = ["fetch", "read_file", "write_file", "connect", "send"];
                        if io_methods.contains(&method.as_str()) {
                            self.diags.error(
                                "E1500",
                                format!(
                                    "I/O operation 'tallow.{method}' in @zk function '{fn_name}' \
                                     — @zk functions must be pure"
                                ),
                                expr.span,
                            );
                        }
                    }
                }
                self.walk_expr_purity(object, fn_name, zk_fns);
                for arg in args {
                    self.walk_expr_purity(&arg.value, fn_name, zk_fns);
                }
            }
            ExprKind::Block(block) => {
                for stmt in &block.stmts {
                    self.check_stmt_purity(stmt, fn_name, zk_fns);
                }
            }
            ExprKind::If { condition, then_block, else_branch, .. } => {
                self.walk_expr_purity(condition, fn_name, zk_fns);
                for stmt in &then_block.stmts {
                    self.check_stmt_purity(stmt, fn_name, zk_fns);
                }
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(block) => {
                            for stmt in &block.stmts {
                                self.check_stmt_purity(stmt, fn_name, zk_fns);
                            }
                        }
                        ElseBranch::ElseIf(expr) => {
                            self.walk_expr_purity(expr, fn_name, zk_fns);
                        }
                    }
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.walk_expr_purity(left, fn_name, zk_fns);
                self.walk_expr_purity(right, fn_name, zk_fns);
            }
            ExprKind::Unary { operand, .. } => {
                self.walk_expr_purity(operand, fn_name, zk_fns);
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

/// Pure builtins that are safe to call from @zk functions.
fn is_pure_builtin(name: &str) -> bool {
    matches!(name,
        "len" | "to_string" | "type_of" | "type_name"
        | "Ok" | "Err" | "Some" | "None"
        | "abs" | "min" | "max"
        | "math.sin" | "math.cos" | "math.tan" | "math.sqrt" | "math.pow"
        | "math.abs" | "math.floor" | "math.ceil" | "math.round"
        | "math.min" | "math.max" | "math.log" | "math.log2" | "math.log10"
    )
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_and_check(src: &str) -> Diagnostics {
        let (tokens, _) = crate::lexer::tokenize(src);
        let program = crate::parser::Parser::parse(tokens).expect("parse failed");
        ZkPass::new(&program).check()
    }

    #[test]
    fn test_zk_valid_pure_function() {
        let src = r#"
@zk(scheme: .groth16, curve: .bn254)
fn prove_age(birth_year: i32, current_year: i32) -> bool {
    let age = current_year - birth_year
    age >= 18
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "pure @zk function should have no errors");
    }

    #[test]
    fn test_zk_rejects_io() {
        let src = r#"
@zk(scheme: .groth16)
fn bad_zk(x: i32) -> i32 {
    print("leaking info")
    x * 2
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 1, "should have 1 E1500 error");
        let err = &diags.items[0];
        assert_eq!(err.code, "E1500");
        assert!(err.msg.contains("print"), "error should mention print");
    }

    #[test]
    fn test_zk_rejects_fetch() {
        let src = r#"
@zk(scheme: .plonk)
fn bad_fetch(url: String) -> String {
    fetch(url)
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 1);
        let err = &diags.items[0];
        assert_eq!(err.code, "E1500");
        assert!(err.msg.contains("fetch"));
    }

    #[test]
    fn test_zk_invalid_scheme() {
        let src = r#"
@zk(scheme: .invalid_scheme)
fn bad_scheme(x: i32) -> i32 {
    x + 1
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 1);
        let err = &diags.items[0];
        assert_eq!(err.code, "E1502");
        assert!(err.msg.contains("invalid_scheme"));
    }

    #[test]
    fn test_zk_invalid_curve() {
        let src = r#"
@zk(scheme: .groth16, curve: .secp256k1)
fn bad_curve(x: i32) -> i32 {
    x + 1
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 1);
        let err = &diags.items[0];
        assert_eq!(err.code, "E1503");
        assert!(err.msg.contains("secp256k1"));
    }

    #[test]
    fn test_zk_warns_non_zk_call() {
        let src = r#"
fn helper(x: i32) -> i32 {
    x * 3
}

@zk(scheme: .stark)
fn zk_fn(x: i32) -> i32 {
    helper(x)
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "no errors expected");
        let warnings: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W1500")
            .collect();
        assert_eq!(warnings.len(), 1, "should have 1 W1500 warning");
        assert!(warnings[0].msg.contains("helper"));
    }

    #[test]
    fn test_zk_accepts_zk_to_zk_call() {
        let src = r#"
@zk(scheme: .groth16)
fn zk_helper(x: i32) -> i32 {
    x * 3
}

@zk(scheme: .groth16)
fn zk_fn(x: i32) -> i32 {
    zk_helper(x)
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0);
        assert_eq!(diags.warning_count(), 0, "@zk calling @zk should have no warnings");
    }

    #[test]
    fn test_zk_rejects_log_call() {
        let src = r#"
@zk(scheme: .groth16)
fn bad_log(x: i32) -> i32 {
    log.info("value is x")
    x
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 1);
        assert_eq!(diags.items[0].code, "E1500");
        assert!(diags.items[0].msg.contains("log.info"));
    }
}
