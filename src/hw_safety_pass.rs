//! ARM MTE and CHERI hardware safety compiler pass.
//!
//! Validates hardware memory safety annotations and type qualifiers:
//! - E1700: Unsafe allocation pattern in @mte_tagged function
//! - E1701: Capability pointer violation (pointer arithmetic on capability type)
//! - E1702: Capability forge attempt (casting integer to capability pointer)
//! - W1700: @mte_tagged function without tagged allocator usage

use std::collections::HashSet;

use crate::ast::*;
use crate::error::Diagnostics;

// ── Unsafe allocation patterns ──────────────────────────────────────────────

/// Call names that indicate unsafe/raw pointer operations.
const UNSAFE_ALLOC_PATTERNS: &[&str] = &[
    "malloc", "free", "realloc", "calloc",
    "ptr_add", "ptr_sub", "ptr_offset",
    "raw_dealloc", "manual_free", "dealloc",
];

/// Call names that indicate proper tagged allocation.
const TAGGED_ALLOC_PATTERNS: &[&str] = &[
    "alloc", "new", "create", "push", "insert",
    "mte_alloc", "tagged_alloc",
];

// ── Pass ────────────────────────────────────────────────────────────────────

pub struct HwSafetyPass<'a> {
    program: &'a Program,
    pub diags: Diagnostics,
}

impl<'a> HwSafetyPass<'a> {
    pub fn new(program: &'a Program) -> Self {
        Self {
            program,
            diags: Diagnostics::new(),
        }
    }

    /// Run the hardware safety pass. Returns diagnostics.
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

        // Check capability type qualifiers across all functions
        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.check_capability_usage(f),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.check_capability_usage(m);
                    }
                }
                _ => {}
            }
        }

        self.diags
    }

    /// Check @mte_tagged annotated functions.
    fn check_fn(&mut self, f: &FnDecl) {
        let is_mte = f.annotations.iter().any(|a| a.name == "mte_tagged");
        if !is_mte {
            return;
        }

        let mut has_unsafe_pattern = false;
        let mut has_alloc = false;

        self.scan_body_for_patterns(
            &f.body.stmts,
            &mut has_unsafe_pattern,
            &mut has_alloc,
            &f.name,
            f.span,
        );

        // W1700: @mte_tagged without any allocation usage
        if !has_alloc && !has_unsafe_pattern {
            self.diags.warning(
                "W1700",
                format!(
                    "@mte_tagged function '{}' does not use any allocator; \
                     MTE tagging has no effect without allocations",
                    f.name
                ),
                f.span,
            );
        }
    }

    fn scan_body_for_patterns(
        &mut self,
        stmts: &[Stmt],
        has_unsafe: &mut bool,
        has_alloc: &mut bool,
        fn_name: &str,
        fn_span: crate::lexer::Span,
    ) {
        for stmt in stmts {
            self.scan_stmt(stmt, has_unsafe, has_alloc, fn_name, fn_span);
        }
    }

    fn scan_stmt(
        &mut self,
        stmt: &Stmt,
        has_unsafe: &mut bool,
        has_alloc: &mut bool,
        fn_name: &str,
        fn_span: crate::lexer::Span,
    ) {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.scan_expr(value, has_unsafe, has_alloc, fn_name, fn_span);
            }
            StmtKind::LetDestructure { value, .. } => {
                self.scan_expr(value, has_unsafe, has_alloc, fn_name, fn_span);
            }
            StmtKind::Expr { expr } => {
                self.scan_expr(expr, has_unsafe, has_alloc, fn_name, fn_span);
            }
            StmtKind::Return(Some(expr)) => {
                self.scan_expr(expr, has_unsafe, has_alloc, fn_name, fn_span);
            }
            _ => {}
        }
    }

    fn scan_expr(
        &mut self,
        expr: &Expr,
        has_unsafe: &mut bool,
        has_alloc: &mut bool,
        fn_name: &str,
        _fn_span: crate::lexer::Span,
    ) {
        match &expr.kind {
            ExprKind::Call { callee, args, .. } => {
                if let Some(name) = self.extract_name(callee) {
                    if UNSAFE_ALLOC_PATTERNS.iter().any(|p| name == *p || name.ends_with(p)) {
                        *has_unsafe = true;
                        self.diags.error(
                            "E1700",
                            format!(
                                "unsafe allocation pattern '{name}' in @mte_tagged function '{fn_name}'; \
                                 use tagged allocator instead of raw pointer operations"
                            ),
                            expr.span,
                        );
                    }
                    if TAGGED_ALLOC_PATTERNS.iter().any(|p| name == *p || name.ends_with(p)) {
                        *has_alloc = true;
                    }
                }
                for arg in args {
                    self.scan_expr(&arg.value, has_unsafe, has_alloc, fn_name, _fn_span);
                }
            }
            ExprKind::MethodCall { object, method, args, .. } => {
                if UNSAFE_ALLOC_PATTERNS.iter().any(|p| method == p) {
                    *has_unsafe = true;
                    self.diags.error(
                        "E1700",
                        format!(
                            "unsafe allocation pattern '.{method}()' in @mte_tagged function '{fn_name}'; \
                             use tagged allocator instead of raw pointer operations"
                        ),
                        expr.span,
                    );
                }
                if TAGGED_ALLOC_PATTERNS.iter().any(|p| method == p) {
                    *has_alloc = true;
                }
                self.scan_expr(object, has_unsafe, has_alloc, fn_name, _fn_span);
                for arg in args {
                    self.scan_expr(&arg.value, has_unsafe, has_alloc, fn_name, _fn_span);
                }
            }
            ExprKind::Block(block) => {
                for stmt in &block.stmts {
                    self.scan_stmt(stmt, has_unsafe, has_alloc, fn_name, _fn_span);
                }
            }
            _ => {}
        }
    }

    /// Check for capability type qualifier violations across all functions.
    fn check_capability_usage(&mut self, f: &FnDecl) {
        // Collect variables declared with capability type
        let mut cap_vars = HashSet::new();

        for stmt in &f.body.stmts {
            self.collect_capability_vars(stmt, &mut cap_vars);
        }

        // Always scan for forge attempts (E1702) even without capability vars
        // Only skip arithmetic checks (E1701) if no capability vars
        for stmt in &f.body.stmts {
            self.check_capability_violations(stmt, &cap_vars, &f.name);
        }
    }

    fn collect_capability_vars(&self, stmt: &Stmt, cap_vars: &mut HashSet<String>) {
        match &stmt.kind {
            StmtKind::Let { name, ty, .. } | StmtKind::Var { name, ty, .. } => {
                if let Some(type_expr) = ty {
                    if self.is_capability_type(type_expr) {
                        cap_vars.insert(name.clone());
                    }
                }
            }
            _ => {}
        }
    }

    fn is_capability_type(&self, ty: &TypeExpr) -> bool {
        match &ty.kind {
            TypeExprKind::Named(name) => {
                name.starts_with("capability") || name.starts_with("Capability")
                    || name == "cap_ptr" || name == "CapPtr"
            }
            _ => false,
        }
    }

    fn check_capability_violations(
        &mut self,
        stmt: &Stmt,
        cap_vars: &HashSet<String>,
        fn_name: &str,
    ) {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.check_expr_capability(value, cap_vars, fn_name);
            }
            StmtKind::Expr { expr } => {
                self.check_expr_capability(expr, cap_vars, fn_name);
            }
            StmtKind::Return(Some(expr)) => {
                self.check_expr_capability(expr, cap_vars, fn_name);
            }
            _ => {}
        }
    }

    fn check_expr_capability(
        &mut self,
        expr: &Expr,
        cap_vars: &HashSet<String>,
        fn_name: &str,
    ) {
        match &expr.kind {
            // E1701: Pointer arithmetic on capability variable
            ExprKind::Binary { left, op, right, .. } => {
                let left_is_cap = self.expr_is_capability(left, cap_vars);
                let right_is_cap = self.expr_is_capability(right, cap_vars);

                if (left_is_cap || right_is_cap)
                    && matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod)
                {
                    self.diags.error(
                        "E1701",
                        format!(
                            "pointer arithmetic on capability type in function '{fn_name}'; \
                             capability pointers cannot be used in arithmetic operations"
                        ),
                        expr.span,
                    );
                }

                self.check_expr_capability(left, cap_vars, fn_name);
                self.check_expr_capability(right, cap_vars, fn_name);
            }
            // E1702: Casting integer to capability (via `as` or explicit cast call)
            ExprKind::Cast { expr: inner, ty, .. } => {
                if self.is_capability_type(ty) {
                    // Casting TO capability type -- check if source is integer
                    if self.expr_could_be_integer(inner) {
                        self.diags.error(
                            "E1702",
                            format!(
                                "capability forge attempt in function '{fn_name}'; \
                                 cannot cast integer to capability pointer type"
                            ),
                            expr.span,
                        );
                    }
                }
                self.check_expr_capability(inner, cap_vars, fn_name);
            }
            ExprKind::Call { callee, args, .. } => {
                // Check for explicit forge patterns like cap_from_int()
                if let Some(name) = self.extract_name(callee) {
                    if name == "cap_from_int" || name == "forge_capability"
                        || name == "int_to_cap" || name == "ptr_from_int"
                    {
                        self.diags.error(
                            "E1702",
                            format!(
                                "capability forge attempt '{name}' in function '{fn_name}'; \
                                 cannot forge capability pointers from integers"
                            ),
                            expr.span,
                        );
                    }
                }
                for arg in args {
                    self.check_expr_capability(&arg.value, cap_vars, fn_name);
                }
            }
            ExprKind::Block(block) => {
                for stmt in &block.stmts {
                    self.check_capability_violations(stmt, cap_vars, fn_name);
                }
            }
            _ => {}
        }
    }

    fn expr_is_capability(&self, expr: &Expr, cap_vars: &HashSet<String>) -> bool {
        if let ExprKind::Ident(name) = &expr.kind {
            cap_vars.contains(name)
        } else {
            false
        }
    }

    fn expr_could_be_integer(&self, expr: &Expr) -> bool {
        matches!(&expr.kind, ExprKind::IntLit(_) | ExprKind::Ident(_))
    }

    fn extract_name(&self, expr: &Expr) -> Option<String> {
        match &expr.kind {
            ExprKind::Ident(name) => Some(name.clone()),
            ExprKind::FieldAccess { object, field, .. } => {
                if let ExprKind::Ident(module) = &object.kind {
                    Some(format!("{module}.{field}"))
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_and_check(src: &str) -> Diagnostics {
        let (tokens, _) = crate::lexer::tokenize(src);
        let program = crate::parser::Parser::parse(tokens).expect("parse failed");
        HwSafetyPass::new(&program).check()
    }

    #[test]
    fn test_mte_valid_function() {
        let src = r#"
@mte_tagged
fn safe_alloc() {
    let data = alloc(1024)
    let x = 42
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "valid @mte_tagged function should have no errors");
    }

    #[test]
    fn test_mte_rejects_unsafe_pattern() {
        let src = r#"
@mte_tagged
fn bad_alloc() {
    let ptr = malloc(1024)
    free(ptr)
}
"#;
        let diags = parse_and_check(src);
        assert!(diags.error_count() >= 1, "should reject malloc in @mte_tagged");
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E1700")
            .collect();
        assert!(errors.len() >= 1, "should have E1700 error");
        assert!(errors[0].msg.contains("malloc") || errors[0].msg.contains("free"));
    }

    #[test]
    fn test_mte_warns_no_allocation() {
        let src = r#"
@mte_tagged
fn no_alloc() {
    let x = 42
}
"#;
        let diags = parse_and_check(src);
        let warnings: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W1700")
            .collect();
        assert_eq!(warnings.len(), 1, "should warn about @mte_tagged without allocations");
    }

    #[test]
    fn test_cheri_rejects_pointer_arithmetic() {
        let src = r#"
fn use_cap() {
    let ptr: Capability = alloc(4)
    let next = ptr + 1
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E1701")
            .collect();
        assert_eq!(errors.len(), 1, "should reject arithmetic on capability");
        assert!(errors[0].msg.contains("capability"));
    }

    #[test]
    fn test_cheri_rejects_cast() {
        let src = r#"
fn forge_cap() {
    let addr = 0xDEADBEEF
    let ptr = cap_from_int(addr)
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E1702")
            .collect();
        assert_eq!(errors.len(), 1, "should reject forging capability from int");
        assert!(errors[0].msg.contains("forge"));
    }
}
