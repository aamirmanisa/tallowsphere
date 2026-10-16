//! Erasure pass: @erasable copy tracking and purge verification.
//!
//! Enforces:
//! - `@erasable` type aliases have all copies tracked through assignments
//! - External storage of @erasable data without purge path emits E0505
//! - Serialization of @erasable data emits W0502
//! - No purge handler for @erasable type emits W0503

use std::collections::{HashMap, HashSet};

use crate::ast::*;
use crate::error::{Diagnostic, Diagnostics};
use crate::lexer::Span;
use crate::typeck::TypeEnv;

/// I/O sink functions that represent external storage.
const IO_SINKS: &[&str] = &[
    "write_file", "insert", "post", "put", "send", "store", "save",
];

/// Serialization functions that convert data to external format.
const SERIALIZATION_FNS: &[&str] = &[
    "to_string", "to_json", "serialize", "encode", "marshal",
];

/// Purge/delete related function or method names.
const PURGE_PATTERNS: &[&str] = &[
    "purge", "delete", "remove", "erase", "destroy", "wipe",
];

// ── Erasure Pass ────────────────────────────────────────────────────────────

pub struct ErasurePass<'a> {
    program: &'a Program,
    #[allow(dead_code)]
    env: &'a TypeEnv,
    pub diags: Diagnostics,
    /// Set of type names annotated with @erasable.
    erasable_types: HashSet<String>,
    /// Map of function name -> set of erasable parameter names.
    fn_erasable_params: HashMap<String, HashSet<String>>,
}

impl<'a> ErasurePass<'a> {
    pub fn new(program: &'a Program, env: &'a TypeEnv) -> Self {
        Self {
            program,
            env,
            diags: Diagnostics::new(),
            erasable_types: HashSet::new(),
            fn_erasable_params: HashMap::new(),
        }
    }

    /// Run the erasure pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        // Phase 1: Collect @erasable annotations from TypeAlias items
        self.collect_erasable_types();

        if self.erasable_types.is_empty() {
            return self.diags;
        }

        // Phase 2: Build map of function -> erasable params
        self.collect_fn_erasable_params();

        // Phase 3: Check each function for storage sinks, serialization, and purge paths
        let erasable_types = self.erasable_types.clone();
        let fn_erasable_params = self.fn_erasable_params.clone();
        for item in &self.program.items {
            if let Item::Fn(f) = item {
                if let Some(params) = fn_erasable_params.get(&f.name) {
                    if !params.is_empty() {
                        self.check_function(f, params, &erasable_types);
                    }
                }
            }
        }

        // Phase 4: Check for missing purge handlers (W0503)
        self.check_missing_purge_handlers(&erasable_types);

        self.diags
    }

    /// Collect @erasable annotations from type aliases.
    fn collect_erasable_types(&mut self) {
        for item in &self.program.items {
            if let Item::TypeAlias(ta) = item {
                for ann in &ta.annotations {
                    if ann.name == "erasable" {
                        self.erasable_types.insert(ta.name.clone());
                    }
                }
            }
        }
    }

    /// Build a map of function name -> set of parameter names that are erasable-typed.
    fn collect_fn_erasable_params(&mut self) {
        for item in &self.program.items {
            if let Item::Fn(f) = item {
                let mut erasable_params = HashSet::new();
                for param in &f.params {
                    if self.is_erasable_type_expr(&param.ty) {
                        erasable_params.insert(param.name.clone());
                    }
                }
                if !erasable_params.is_empty() {
                    self.fn_erasable_params.insert(f.name.clone(), erasable_params);
                }
            }
        }
    }

    /// Check if a TypeExpr refers to an @erasable type.
    fn is_erasable_type_expr(&self, ty: &TypeExpr) -> bool {
        match &ty.kind {
            TypeExprKind::Named(name) => self.erasable_types.contains(name),
            TypeExprKind::Generic { name, .. } => self.erasable_types.contains(name),
            _ => false,
        }
    }

    /// Check a function for E0505 (storage without purge) and W0502 (serialization).
    fn check_function(
        &mut self,
        f: &FnDecl,
        erasable_params: &HashSet<String>,
        _erasable_types: &HashSet<String>,
    ) {
        let mut has_io_sink = false;
        let mut has_serialization = false;
        let mut has_purge = false;

        self.scan_block(&f.body, erasable_params, &mut has_io_sink, &mut has_serialization, &mut has_purge);

        // E0505: erasable stored externally without purge path
        if has_io_sink && !has_purge {
            self.diags.push(Diagnostic::error(
                "E0505",
                format!(
                    "function `{}` stores @erasable data to external sink without purge path — add a purge/delete handler",
                    f.name
                ),
                f.span,
            ));
        }

        // W0502: serialization warning
        if has_serialization {
            self.diags.push(Diagnostic::warning(
                "W0502",
                format!(
                    "function `{}` serializes @erasable data — ensure external recipients can fulfill erasure requests",
                    f.name
                ),
                f.span,
            ));
        }
    }

    /// Scan a block for IO sinks, serialization, and purge patterns involving erasable params.
    fn scan_block(
        &self,
        block: &Block,
        erasable_params: &HashSet<String>,
        has_io_sink: &mut bool,
        has_serialization: &mut bool,
        has_purge: &mut bool,
    ) {
        for stmt in &block.stmts {
            self.scan_stmt(stmt, erasable_params, has_io_sink, has_serialization, has_purge);
        }
    }

    fn scan_stmt(
        &self,
        stmt: &Stmt,
        erasable_params: &HashSet<String>,
        has_io_sink: &mut bool,
        has_serialization: &mut bool,
        has_purge: &mut bool,
    ) {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.scan_expr(value, erasable_params, has_io_sink, has_serialization, has_purge);
            }
            StmtKind::Expr { expr } => {
                self.scan_expr(expr, erasable_params, has_io_sink, has_serialization, has_purge);
            }
            StmtKind::Return(Some(e)) => {
                self.scan_expr(e, erasable_params, has_io_sink, has_serialization, has_purge);
            }
            StmtKind::While { condition, body } => {
                self.scan_expr(condition, erasable_params, has_io_sink, has_serialization, has_purge);
                self.scan_block(body, erasable_params, has_io_sink, has_serialization, has_purge);
            }
            StmtKind::For { iter, body, .. } => {
                self.scan_expr(iter, erasable_params, has_io_sink, has_serialization, has_purge);
                self.scan_block(body, erasable_params, has_io_sink, has_serialization, has_purge);
            }
            _ => {}
        }
    }

    fn scan_expr(
        &self,
        expr: &Expr,
        erasable_params: &HashSet<String>,
        has_io_sink: &mut bool,
        has_serialization: &mut bool,
        has_purge: &mut bool,
    ) {
        match &expr.kind {
            ExprKind::MethodCall { object, method, args } => {
                // Check if the method is a purge pattern
                if PURGE_PATTERNS.iter().any(|p| method.contains(p)) {
                    *has_purge = true;
                }

                // Check if erasable data flows to IO sink
                if IO_SINKS.iter().any(|s| method.contains(s)) {
                    if self.expr_involves_erasable(object, erasable_params)
                        || args.iter().any(|a| self.expr_involves_erasable(&a.value, erasable_params))
                    {
                        *has_io_sink = true;
                    }
                }

                // Check serialization
                if SERIALIZATION_FNS.iter().any(|s| method.contains(s)) {
                    if self.expr_involves_erasable(object, erasable_params)
                        || args.iter().any(|a| self.expr_involves_erasable(&a.value, erasable_params))
                    {
                        *has_serialization = true;
                    }
                }

                self.scan_expr(object, erasable_params, has_io_sink, has_serialization, has_purge);
                for a in args {
                    self.scan_expr(&a.value, erasable_params, has_io_sink, has_serialization, has_purge);
                }
            }
            ExprKind::Call { callee, args } => {
                // Check function name for purge/sink/serialization patterns
                if let ExprKind::Ident(fn_name) = &callee.kind {
                    if PURGE_PATTERNS.iter().any(|p| fn_name.contains(p)) {
                        *has_purge = true;
                    }
                    if IO_SINKS.iter().any(|s| fn_name.contains(s)) {
                        if args.iter().any(|a| self.expr_involves_erasable(&a.value, erasable_params)) {
                            *has_io_sink = true;
                        }
                    }
                    if SERIALIZATION_FNS.iter().any(|s| fn_name.contains(s)) {
                        if args.iter().any(|a| self.expr_involves_erasable(&a.value, erasable_params)) {
                            *has_serialization = true;
                        }
                    }
                }
                // Also check module-qualified calls like fs.write_file
                if let ExprKind::FieldAccess { object: obj, field } = &callee.kind {
                    if let ExprKind::Ident(_) = &obj.kind {
                        if PURGE_PATTERNS.iter().any(|p| field.contains(p)) {
                            *has_purge = true;
                        }
                        if IO_SINKS.iter().any(|s| field.contains(s)) {
                            if args.iter().any(|a| self.expr_involves_erasable(&a.value, erasable_params)) {
                                *has_io_sink = true;
                            }
                        }
                        if SERIALIZATION_FNS.iter().any(|s| field.contains(s)) {
                            if args.iter().any(|a| self.expr_involves_erasable(&a.value, erasable_params)) {
                                *has_serialization = true;
                            }
                        }
                    }
                }
                self.scan_expr(callee, erasable_params, has_io_sink, has_serialization, has_purge);
                for a in args {
                    self.scan_expr(&a.value, erasable_params, has_io_sink, has_serialization, has_purge);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.scan_expr(left, erasable_params, has_io_sink, has_serialization, has_purge);
                self.scan_expr(right, erasable_params, has_io_sink, has_serialization, has_purge);
            }
            ExprKind::Unary { operand, .. } => {
                self.scan_expr(operand, erasable_params, has_io_sink, has_serialization, has_purge);
            }
            ExprKind::Block(block) => {
                self.scan_block(block, erasable_params, has_io_sink, has_serialization, has_purge);
            }
            ExprKind::If { condition, then_block, else_branch, .. } => {
                self.scan_expr(condition, erasable_params, has_io_sink, has_serialization, has_purge);
                self.scan_block(then_block, erasable_params, has_io_sink, has_serialization, has_purge);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::ElseIf(e) => self.scan_expr(e, erasable_params, has_io_sink, has_serialization, has_purge),
                        ElseBranch::Block(b) => self.scan_block(b, erasable_params, has_io_sink, has_serialization, has_purge),
                    }
                }
            }
            ExprKind::Assign { value, .. } => {
                self.scan_expr(value, erasable_params, has_io_sink, has_serialization, has_purge);
            }
            _ => {}
        }
    }

    /// Check if an expression involves an erasable parameter.
    fn expr_involves_erasable(&self, expr: &Expr, erasable_params: &HashSet<String>) -> bool {
        match &expr.kind {
            ExprKind::Ident(name) => erasable_params.contains(name),
            ExprKind::FieldAccess { object, .. } => self.expr_involves_erasable(object, erasable_params),
            ExprKind::MethodCall { object, args, .. } => {
                self.expr_involves_erasable(object, erasable_params)
                    || args.iter().any(|a| self.expr_involves_erasable(&a.value, erasable_params))
            }
            ExprKind::Call { callee, args } => {
                self.expr_involves_erasable(callee, erasable_params)
                    || args.iter().any(|a| self.expr_involves_erasable(&a.value, erasable_params))
            }
            _ => false,
        }
    }

    /// W0503: Check that each @erasable type has its OWN purge handler.
    ///
    /// A purge handler for type T is a function (or impl method) that either
    /// (a) has a purge-pattern name and takes a parameter of type T, or
    /// (b) contains a purge-pattern call/method whose arguments involve a
    /// parameter of type T. This is per-type: a purge handler for one
    /// @erasable type does NOT satisfy the erasure obligation of another.
    fn check_missing_purge_handlers(&mut self, erasable_types: &HashSet<String>) {
        // type name -> has a purge handler somewhere in the program
        let mut purge_handlers: HashMap<String, bool> = erasable_types
            .iter()
            .map(|t| (t.clone(), false))
            .collect();

        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.note_purge_handler(f, &mut purge_handlers),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.note_purge_handler(m, &mut purge_handlers);
                    }
                }
                _ => {}
            }
        }

        for type_name in erasable_types {
            if !purge_handlers.get(type_name).copied().unwrap_or(false) {
                // Find the TypeAlias span for reporting
                let span = self.find_type_alias_span(type_name);
                self.diags.push(Diagnostic::warning(
                    "W0503",
                    format!(
                        "no purge handler found for @erasable type `{type_name}` — add a purge/delete function that takes a `{type_name}` to support right-to-erasure",
                    ),
                    span,
                ));
            }
        }
    }

    /// Record whether a function is a purge handler for any @erasable type it
    /// touches. A function is a purge handler for type T when its name matches
    /// a purge pattern and it takes a T-typed parameter, OR its body contains a
    /// purge-pattern call whose arguments involve a T-typed parameter.
    fn note_purge_handler(&self, f: &FnDecl, purge_handlers: &mut HashMap<String, bool>) {
        let name_matches = PURGE_PATTERNS.iter().any(|p| f.name.contains(p));

        // Collect (param_name, erasable_type) pairs for this function.
        let mut param_types: Vec<(String, String)> = Vec::new();
        for param in &f.params {
            if let Some(tname) = self.type_expr_name(&param.ty) {
                if purge_handlers.contains_key(&tname) {
                    param_types.push((param.name.clone(), tname));
                }
            }
        }

        // (a) Purge-pattern function name + erasable-typed parameter.
        if name_matches {
            for (_, tname) in &param_types {
                if let Some(flag) = purge_handlers.get_mut(tname) {
                    *flag = true;
                }
            }
        }

        // (b) Purge-pattern call/method in the body involving the parameter.
        for (param, tname) in &param_types {
            if self.body_purges_param(&f.body, param) {
                if let Some(flag) = purge_handlers.get_mut(tname) {
                    *flag = true;
                }
            }
        }
    }

    /// Extract the plain type name from a TypeExpr, if it is a named/generic type.
    fn type_expr_name(&self, ty: &TypeExpr) -> Option<String> {
        match &ty.kind {
            TypeExprKind::Named(name) => Some(name.clone()),
            TypeExprKind::Generic { name, .. } => Some(name.clone()),
            _ => None,
        }
    }

    /// True if the block contains a purge-pattern call/method whose arguments
    /// (or receiver) involve the given parameter.
    fn body_purges_param(&self, block: &Block, param: &str) -> bool {
        let mut found = false;
        self.scan_purge_block(block, param, &mut found);
        found
    }

    fn scan_purge_block(&self, block: &Block, param: &str, found: &mut bool) {
        if *found { return; }
        for stmt in &block.stmts {
            self.scan_purge_stmt(stmt, param, found);
            if *found { return; }
        }
    }

    fn scan_purge_stmt(&self, stmt: &Stmt, param: &str, found: &mut bool) {
        if *found { return; }
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.scan_purge_expr(value, param, found);
            }
            StmtKind::Expr { expr } => {
                self.scan_purge_expr(expr, param, found);
            }
            StmtKind::Return(Some(e)) => {
                self.scan_purge_expr(e, param, found);
            }
            StmtKind::While { condition, body } => {
                self.scan_purge_expr(condition, param, found);
                self.scan_purge_block(body, param, found);
            }
            StmtKind::For { iter, body, .. } => {
                self.scan_purge_expr(iter, param, found);
                self.scan_purge_block(body, param, found);
            }
            _ => {}
        }
    }

    fn scan_purge_expr(&self, expr: &Expr, param: &str, found: &mut bool) {
        if *found { return; }
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                let callee_name = match &callee.kind {
                    ExprKind::Ident(name) => Some(name.clone()),
                    ExprKind::FieldAccess { field, .. } => Some(field.clone()),
                    _ => None,
                };
                if let Some(name) = callee_name {
                    if PURGE_PATTERNS.iter().any(|p| name.contains(p))
                        && args
                            .iter()
                            .any(|a| self.expr_involves_param(&a.value, param))
                    {
                        *found = true;
                        return;
                    }
                }
                self.scan_purge_expr(callee, param, found);
                for a in args {
                    self.scan_purge_expr(&a.value, param, found);
                }
            }
            ExprKind::MethodCall { object, method, args } => {
                if PURGE_PATTERNS.iter().any(|p| method.contains(p))
                    && (self.expr_involves_param(object, param)
                        || args
                            .iter()
                            .any(|a| self.expr_involves_param(&a.value, param)))
                {
                    *found = true;
                    return;
                }
                self.scan_purge_expr(object, param, found);
                for a in args {
                    self.scan_purge_expr(&a.value, param, found);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.scan_purge_expr(left, param, found);
                self.scan_purge_expr(right, param, found);
            }
            ExprKind::Block(block) => {
                self.scan_purge_block(block, param, found);
            }
            ExprKind::If { condition, then_block, else_branch, .. } => {
                self.scan_purge_expr(condition, param, found);
                self.scan_purge_block(then_block, param, found);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::ElseIf(e) => self.scan_purge_expr(e, param, found),
                        ElseBranch::Block(b) => self.scan_purge_block(b, param, found),
                    }
                }
            }
            _ => {}
        }
    }

    /// True if the expression references the named parameter (transitively).
    fn expr_involves_param(&self, expr: &Expr, param: &str) -> bool {
        match &expr.kind {
            ExprKind::Ident(name) => name == param,
            ExprKind::FieldAccess { object, .. } => self.expr_involves_param(object, param),
            ExprKind::MethodCall { object, args, .. } => {
                self.expr_involves_param(object, param)
                    || args.iter().any(|a| self.expr_involves_param(&a.value, param))
            }
            ExprKind::Call { callee, args } => {
                self.expr_involves_param(callee, param)
                    || args.iter().any(|a| self.expr_involves_param(&a.value, param))
            }
            ExprKind::Binary { left, right, .. } => {
                self.expr_involves_param(left, param) || self.expr_involves_param(right, param)
            }
            _ => false,
        }
    }

    /// Find the span of a TypeAlias by name.
    fn find_type_alias_span(&self, name: &str) -> Span {
        for item in &self.program.items {
            if let Item::TypeAlias(ta) = item {
                if ta.name == name {
                    return ta.span;
                }
            }
        }
        Span::new(0, 0)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;
    use crate::parser::Parser;
    use crate::typeck::TypeChecker;

    fn run_erasure_pass(source: &str) -> Diagnostics {
        let (tokens, _) = lexer::tokenize(source);
        let program = Parser::parse(tokens).unwrap();
        let (env, _) = TypeChecker::new(&program).check();
        ErasurePass::new(&program, &env).check()
    }

    // ── E0505: External storage without purge path ──

    #[test]
    fn erasure_pass_e0505_storage_without_purge() {
        let diags = run_erasure_pass(
            r#"
@erasable
type UserProfile = private String

fn store_user(profile: UserProfile) {
    fs.write_file("users.json", profile)
}
"#,
        );
        assert!(diags.has_errors(), "expected E0505 error, got: {:?}", diags.items);
        assert!(
            diags.items.iter().any(|d| d.code == "E0505"),
            "expected E0505, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn erasure_pass_valid_storage_with_purge() {
        let diags = run_erasure_pass(
            r#"
@erasable
type UserProfile = private String

fn store_user(profile: UserProfile) {
    fs.write_file("users.json", profile)
    purge("user-123")
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "expected no errors when purge handler present, got: {:?}",
            diags.items
        );
    }

    // ── W0502: Serialization warning ──

    #[test]
    fn erasure_pass_w0502_serialization() {
        let diags = run_erasure_pass(
            r#"
@erasable
type UserProfile = private String

fn export_user(profile: UserProfile) -> String {
    profile.to_json()
}
"#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "W0502"),
            "expected W0502 serialization warning, got: {:?}",
            diags.items
        );
    }

    // ── W0503: Missing purge handler ──

    #[test]
    fn erasure_pass_w0503_no_purge_handler() {
        let diags = run_erasure_pass(
            r#"
@erasable
type UserProfile = private String

fn process_user(profile: UserProfile) -> String {
    profile
}
"#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "W0503"),
            "expected W0503 missing purge warning, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn erasure_pass_no_warnings_with_purge_handler() {
        let diags = run_erasure_pass(
            r#"
@erasable
type UserProfile = private String

fn delete_user(profile: UserProfile) {
    purge("user-123")
}
"#,
        );
        assert!(
            !diags.items.iter().any(|d| d.code == "W0503"),
            "expected no W0503 when purge handler exists, got: {:?}",
            diags.items
        );
    }

    // ── Type::Erasable ──

    #[test]
    fn erasure_pass_type_erasable_in_type_system() {
        let source = r#"
@erasable
type UserProfile = private String
"#;
        let (tokens, _) = lexer::tokenize(source);
        let program = Parser::parse(tokens).unwrap();
        let (env, _) = TypeChecker::new(&program).check();
        let ty = env.type_aliases.get("UserProfile").unwrap();
        assert!(ty.is_erasable(), "expected UserProfile to be Erasable, got: {:?}", ty);
    }

    // ── No erasable types = no errors ──

    #[test]
    fn erasure_pass_no_erasable_types_no_errors() {
        let diags = run_erasure_pass(
            r#"
type Email = private String

fn process(email: Email) -> String {
    email
}
"#,
        );
        assert!(
            diags.items.is_empty(),
            "expected no diagnostics when no @erasable types, got: {:?}",
            diags.items
        );
    }

    // ── Erasable with delete method ──

    #[test]
    fn erasure_pass_delete_method_counts_as_purge() {
        let diags = run_erasure_pass(
            r#"
@erasable
type UserProfile = private String

fn cleanup_user(profile: UserProfile) {
    fs.write_file("users.json", profile)
    db.delete("users", profile)
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "expected no errors when delete handler present, got: {:?}",
            diags.items
        );
    }

    // ── W0503 is per-type: a purge handler for one @erasable type does not
    // satisfy the erasure obligation of another ──

    #[test]
    fn erasure_pass_w0503_is_per_type() {
        let diags = run_erasure_pass(
            r#"
@erasable
type UserProfile = private String

@erasable
type PaymentRecord = private String

fn delete_user(profile: UserProfile) {
    db.delete("users", profile)
}
"#,
        );
        let w0503: Vec<_> = diags
            .items
            .iter()
            .filter(|d| d.code == "W0503")
            .collect();
        assert_eq!(
            w0503.len(),
            1,
            "expected exactly one W0503 (for PaymentRecord only), got: {:?}",
            diags.items
        );
        assert!(
            w0503[0].msg.contains("PaymentRecord"),
            "W0503 should name the unhandled type PaymentRecord, got: {}",
            w0503[0].msg
        );
        assert!(
            !w0503[0].msg.contains("UserProfile"),
            "W0503 must not fire for UserProfile (delete_user handles it), got: {}",
            w0503[0].msg
        );
    }
}
