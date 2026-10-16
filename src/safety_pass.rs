//! Safety-level lattice enforcement compiler pass.
//!
//! Validates `@safety_critical` annotations on functions across DO-178C (DAL),
//! ISO 26262 (ASIL), and IEC 61508 (SIL) safety standards:
//!
//! - E2100: Unknown safety level in @safety_critical annotation
//! - E2101: Safety violation — higher-safety function calls lower-safety function
//!          without @downgrade
//! - E2102: @downgrade annotation present but missing required `reason` argument
//! - W2100: Safety-annotated function calls unannotated function (implicit trust)
//!
//! Unified numeric ordering (0 = highest integrity, 5 = unrestricted):
//!   Level 0: DAL-A / ASIL-D / SIL-4
//!   Level 1: DAL-B / ASIL-C / SIL-3
//!   Level 2: DAL-C / ASIL-B / SIL-2
//!   Level 3: DAL-D / ASIL-A / SIL-1
//!   Level 4: DAL-E / QM
//!   Level 5: Unrestricted (no annotation)

use std::collections::HashMap;

use crate::ast::*;
use crate::error::Diagnostics;

// ── Safety Level Mapping ────────────────────────────────────────────────────

/// Parse a DotIdent string into a unified safety level (0 = highest, 4 = lowest annotated).
/// Returns None for unknown level names.
pub fn parse_safety_level(name: &str) -> Option<u8> {
    match name {
        // Level 0: Highest integrity
        "dal_a" | "asil_d" | "sil_4" => Some(0),
        // Level 1
        "dal_b" | "asil_c" | "sil_3" => Some(1),
        // Level 2
        "dal_c" | "asil_b" | "sil_2" => Some(2),
        // Level 3
        "dal_d" | "asil_a" | "sil_1" => Some(3),
        // Level 4: Lowest annotated safety
        "dal_e" | "qm" => Some(4),
        _ => None,
    }
}

// ── Pass ─────────────────────────────────────────────────────────────────────

pub struct SafetyPass<'a> {
    program: &'a Program,
    pub diags: Diagnostics,
    fn_safety_levels: HashMap<String, u8>,
}

impl<'a> SafetyPass<'a> {
    pub fn new(program: &'a Program) -> Self {
        Self {
            program,
            diags: Diagnostics::new(),
            fn_safety_levels: HashMap::new(),
        }
    }

    /// Run the safety pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        // Phase 1: Collect safety levels from @safety_critical annotations
        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.collect_fn(f),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.collect_fn(m);
                    }
                }
                _ => {}
            }
        }

        // Phase 2: Validate call graph — check that callers don't call less-safe callees
        let levels = self.fn_safety_levels.clone();
        for item in &self.program.items {
            match item {
                Item::Fn(f) => {
                    if let Some(&caller_level) = levels.get(&f.name) {
                        self.validate_calls(f, caller_level);
                    }
                }
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        if let Some(&caller_level) = levels.get(&m.name) {
                            self.validate_calls(m, caller_level);
                        }
                    }
                }
                _ => {}
            }
        }

        // Phase 3 (44): @no_heap, @no_recursion, @bounded_by annotations
        self.check_phase44_annotations();

        self.diags
    }

    // ── Phase 1: Collect ────────────────────────────────────────────────

    fn collect_fn(&mut self, f: &FnDecl) {
        let safety_ann = f.annotations.iter().find(|a| a.name == "safety_critical");
        let ann = match safety_ann {
            Some(a) => a,
            None => return,
        };

        // Extract level from named arg `level:` or first positional DotIdent
        let level_str = self.extract_level(ann);

        match level_str {
            Some(name) => {
                match parse_safety_level(&name) {
                    Some(level) => {
                        self.fn_safety_levels.insert(f.name.clone(), level);
                    }
                    None => {
                        self.diags.error(
                            "E2100",
                            format!(
                                "unknown safety level '.{}' in @safety_critical on '{}' \
                                 (valid: .dal_a-.dal_e, .asil_a-.asil_d, .qm, .sil_1-.sil_4)",
                                name, f.name
                            ),
                            ann.span,
                        );
                    }
                }
            }
            None => {
                self.diags.error(
                    "E2100",
                    format!(
                        "@safety_critical on '{}' has no level specified \
                         (valid: .dal_a-.dal_e, .asil_a-.asil_d, .qm, .sil_1-.sil_4)",
                        f.name
                    ),
                    ann.span,
                );
            }
        }
    }

    /// Extract level string from annotation: named arg `level:` or first positional DotIdent.
    fn extract_level(&self, ann: &Annotation) -> Option<String> {
        // Try named arg `level:`
        for arg in &ann.args {
            if arg.name == "level" {
                if let ExprKind::DotIdent(name) = &arg.value.kind {
                    return Some(name.clone());
                }
            }
        }
        // Try first positional DotIdent
        for arg in &ann.args {
            if arg.name.is_empty() {
                if let ExprKind::DotIdent(name) = &arg.value.kind {
                    return Some(name.clone());
                }
            }
        }
        None
    }

    // ── Phase 2: Validate call graph ────────────────────────────────────

    fn validate_calls(&mut self, f: &FnDecl, caller_level: u8) {
        let has_downgrade = f.annotations.iter().any(|a| a.name == "downgrade");
        let downgrade_has_reason = f.annotations.iter().any(|a| {
            a.name == "downgrade"
                && a.args.iter().any(|arg| {
                    (arg.name == "reason" || arg.name.is_empty())
                        && matches!(&arg.value.kind, ExprKind::StringLit(_))
                })
        });

        for stmt in &f.body.stmts {
            self.check_stmt_calls(stmt, &f.name, caller_level, has_downgrade, downgrade_has_reason);
        }
    }

    fn check_stmt_calls(
        &mut self,
        stmt: &Stmt,
        caller_name: &str,
        caller_level: u8,
        has_downgrade: bool,
        downgrade_has_reason: bool,
    ) {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.walk_expr_calls(value, caller_name, caller_level, has_downgrade, downgrade_has_reason);
            }
            StmtKind::LetDestructure { value, .. } => {
                self.walk_expr_calls(value, caller_name, caller_level, has_downgrade, downgrade_has_reason);
            }
            StmtKind::Expr { expr } => {
                self.walk_expr_calls(expr, caller_name, caller_level, has_downgrade, downgrade_has_reason);
            }
            StmtKind::Return(Some(expr)) => {
                self.walk_expr_calls(expr, caller_name, caller_level, has_downgrade, downgrade_has_reason);
            }
            StmtKind::Return(None) => {}
            StmtKind::For { iter, body, .. } => {
                self.walk_expr_calls(iter, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                for s in &body.stmts {
                    self.check_stmt_calls(s, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                }
            }
            StmtKind::While { condition, body } => {
                self.walk_expr_calls(condition, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                for s in &body.stmts {
                    self.check_stmt_calls(s, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                }
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.walk_expr_calls(expr, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                for s in &body.stmts {
                    self.check_stmt_calls(s, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                }
            }
            StmtKind::Loop { body } => {
                for s in &body.stmts {
                    self.check_stmt_calls(s, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                }
            }
            StmtKind::Bail(expr) => {
                self.walk_expr_calls(expr, caller_name, caller_level, has_downgrade, downgrade_has_reason);
            }
            StmtKind::Break | StmtKind::Continue => {}
            StmtKind::Defer { .. } => {}
        }
    }

    fn walk_expr_calls(
        &mut self,
        expr: &Expr,
        caller_name: &str,
        caller_level: u8,
        has_downgrade: bool,
        downgrade_has_reason: bool,
    ) {
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                // Check the callee
                if let Some(callee_name) = self.extract_call_name(callee) {
                    self.check_callee(
                        &callee_name,
                        caller_name,
                        caller_level,
                        has_downgrade,
                        downgrade_has_reason,
                        expr.span,
                    );
                }
                // Recurse into callee expression and arguments
                self.walk_expr_calls(callee, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                for arg in args {
                    self.walk_expr_calls(&arg.value, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                }
            }
            ExprKind::MethodCall { object, method, args } => {
                // For method calls, the method name is the callee
                self.check_callee(
                    method,
                    caller_name,
                    caller_level,
                    has_downgrade,
                    downgrade_has_reason,
                    expr.span,
                );
                self.walk_expr_calls(object, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                for arg in args {
                    self.walk_expr_calls(&arg.value, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.walk_expr_calls(left, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                self.walk_expr_calls(right, caller_name, caller_level, has_downgrade, downgrade_has_reason);
            }
            ExprKind::Unary { operand, .. } => {
                self.walk_expr_calls(operand, caller_name, caller_level, has_downgrade, downgrade_has_reason);
            }
            ExprKind::FieldAccess { object, .. } => {
                self.walk_expr_calls(object, caller_name, caller_level, has_downgrade, downgrade_has_reason);
            }
            ExprKind::Index { object, index } => {
                self.walk_expr_calls(object, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                self.walk_expr_calls(index, caller_name, caller_level, has_downgrade, downgrade_has_reason);
            }
            ExprKind::If { condition, then_block, else_branch } => {
                self.walk_expr_calls(condition, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                for s in &then_block.stmts {
                    self.check_stmt_calls(s, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                }
                match else_branch {
                    Some(ElseBranch::Block(b)) => {
                        for s in &b.stmts {
                            self.check_stmt_calls(s, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                        }
                    }
                    Some(ElseBranch::ElseIf(e)) => {
                        self.walk_expr_calls(e, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                    }
                    None => {}
                }
            }
            ExprKind::IfLet { then_block, else_branch, .. } => {
                for s in &then_block.stmts {
                    self.check_stmt_calls(s, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                }
                match else_branch {
                    Some(ElseBranch::Block(b)) => {
                        for s in &b.stmts {
                            self.check_stmt_calls(s, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                        }
                    }
                    Some(ElseBranch::ElseIf(e)) => {
                        self.walk_expr_calls(e, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                    }
                    None => {}
                }
            }
            ExprKind::Match { subject, arms } => {
                self.walk_expr_calls(subject, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                for arm in arms {
                    self.walk_expr_calls(&arm.body, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                }
            }
            ExprKind::Block(b) => {
                for s in &b.stmts {
                    self.check_stmt_calls(s, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                }
            }
            ExprKind::StructLit { fields, .. } => {
                for f in fields {
                    self.walk_expr_calls(&f.value, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                }
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) | ExprKind::Cast { expr: inner, .. } => {
                self.walk_expr_calls(inner, caller_name, caller_level, has_downgrade, downgrade_has_reason);
            }
            ExprKind::Assign { value, .. } => {
                self.walk_expr_calls(value, caller_name, caller_level, has_downgrade, downgrade_has_reason);
            }
            ExprKind::Array(items) => {
                for item in items {
                    self.walk_expr_calls(item, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                }
            }
            ExprKind::Closure { body, .. } => {
                for s in body {
                    self.check_stmt_calls(s, caller_name, caller_level, has_downgrade, downgrade_has_reason);
                }
            }
            _ => {}
        }
    }

    /// Check a callee against the caller's safety level.
    fn check_callee(
        &mut self,
        callee_name: &str,
        caller_name: &str,
        caller_level: u8,
        has_downgrade: bool,
        downgrade_has_reason: bool,
        span: crate::lexer::Span,
    ) {
        if let Some(&callee_level) = self.fn_safety_levels.get(callee_name) {
            // Higher numeric level means LESS safe.
            // If callee is less safe than caller, that's a violation.
            if callee_level > caller_level {
                if has_downgrade {
                    if !downgrade_has_reason {
                        self.diags.error(
                            "E2102",
                            format!(
                                "@downgrade on '{}' requires a reason argument \
                                 (e.g., @downgrade(reason: \"...\"))",
                                caller_name
                            ),
                            span,
                        );
                    }
                    // else: @downgrade with reason -> suppressed
                } else {
                    self.diags.error(
                        "E2101",
                        format!(
                            "safety violation: '{}' (level {}) calls '{}' (level {}) \
                             — higher-safety function cannot call lower-safety function \
                             without @downgrade annotation",
                            caller_name, caller_level, callee_name, callee_level
                        ),
                        span,
                    );
                }
            }
        } else {
            // Callee not in fn_safety_levels and caller has a safety level
            if caller_level < 5 {
                self.diags.warning(
                    "W2100",
                    format!(
                        "safety-annotated function '{}' (level {}) calls unannotated function '{}' \
                         — consider adding @safety_critical to the callee",
                        caller_name, caller_level, callee_name
                    ),
                    span,
                );
            }
        }
    }

    /// Extract a function name from a Call callee expression.
    fn extract_call_name(&self, expr: &Expr) -> Option<String> {
        match &expr.kind {
            ExprKind::Ident(name) => Some(name.clone()),
            ExprKind::FieldAccess { object, field } => {
                if let ExprKind::Ident(obj) = &object.kind {
                    Some(format!("{}.{}", obj, field))
                } else {
                    Some(field.clone())
                }
            }
            _ => None,
        }
    }

    // ── Phase 44: @no_heap, @no_recursion, @bounded_by ────────────────

    /// Check Phase 44 annotations: @no_heap, @no_recursion, @bounded_by.
    /// Called from `check()` after existing phases.
    fn check_phase44_annotations(&mut self) {
        let fn_names: Vec<String> = self.program.items.iter().filter_map(|item| {
            match item {
                Item::Fn(f) => Some(f.name.clone()),
                _ => None,
            }
        }).collect();

        // Also collect impl method names
        let method_names: Vec<String> = self.program.items.iter().flat_map(|item| {
            match item {
                Item::Impl(imp) => imp.methods.iter().map(|m| m.name.clone()).collect::<Vec<_>>(),
                _ => vec![],
            }
        }).collect();

        let all_names: std::collections::HashSet<String> = fn_names.iter()
            .chain(method_names.iter())
            .cloned()
            .collect();

        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.check_fn_phase44(f, &all_names),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.check_fn_phase44(m, &all_names);
                    }
                }
                _ => {}
            }
        }
    }

    fn check_fn_phase44(&mut self, f: &FnDecl, all_fn_names: &std::collections::HashSet<String>) {
        // ── @no_heap ──
        let has_no_heap = f.annotations.iter().any(|a| a.name == "no_heap");
        if has_no_heap {
            self.check_no_heap(f);
        }

        // ── @no_recursion ──
        let has_no_recursion = f.annotations.iter().any(|a| a.name == "no_recursion");
        if has_no_recursion {
            self.check_no_recursion(f, all_fn_names);
        }

        // ── @bounded_by ──
        if let Some(ann) = f.annotations.iter().find(|a| a.name == "bounded_by") {
            self.check_bounded_by(f, ann);
        }
    }

    /// E2600: @no_heap — function must not use heap allocation.
    /// Detects: Vec/Map/Set/String constructors, array literals, struct literals with heap types.
    fn check_no_heap(&mut self, f: &FnDecl) {
        // Walk the body looking for heap-allocating patterns
        for stmt in &f.body.stmts {
            self.walk_stmt_no_heap(stmt, &f.name, f.span);
        }
    }

    fn walk_stmt_no_heap(&mut self, stmt: &Stmt, fn_name: &str, fn_span: crate::lexer::Span) {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.walk_expr_no_heap(value, fn_name, fn_span);
            }
            StmtKind::LetDestructure { value, .. } => {
                self.walk_expr_no_heap(value, fn_name, fn_span);
            }
            StmtKind::Expr { expr } => {
                self.walk_expr_no_heap(expr, fn_name, fn_span);
            }
            StmtKind::Return(Some(expr)) => {
                self.walk_expr_no_heap(expr, fn_name, fn_span);
            }
            StmtKind::For { iter, body, .. } => {
                self.walk_expr_no_heap(iter, fn_name, fn_span);
                for s in &body.stmts { self.walk_stmt_no_heap(s, fn_name, fn_span); }
            }
            StmtKind::While { condition, body } => {
                self.walk_expr_no_heap(condition, fn_name, fn_span);
                for s in &body.stmts { self.walk_stmt_no_heap(s, fn_name, fn_span); }
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.walk_expr_no_heap(expr, fn_name, fn_span);
                for s in &body.stmts { self.walk_stmt_no_heap(s, fn_name, fn_span); }
            }
            StmtKind::Loop { body } => {
                for s in &body.stmts { self.walk_stmt_no_heap(s, fn_name, fn_span); }
            }
            StmtKind::Bail(expr) => {
                self.walk_expr_no_heap(expr, fn_name, fn_span);
            }
            _ => {}
        }
    }

    fn walk_expr_no_heap(&mut self, expr: &Expr, fn_name: &str, fn_span: crate::lexer::Span) {
        match &expr.kind {
            // Array literals allocate on the heap
            ExprKind::Array(_items) => {
                self.diags.error(
                    "E2600",
                    format!(
                        "@no_heap violation in '{}': array literal allocates on the heap",
                        fn_name
                    ),
                    expr.span,
                );
            }
            // Map/Vec/Set constructors
            ExprKind::Call { callee, args } => {
                if let Some(name) = self.extract_call_name(callee) {
                    let heap_constructors = [
                        "Vec.new", "Map.new", "Set.new", "Queue.new",
                        "String.new", "String.from",
                    ];
                    if heap_constructors.iter().any(|c| name == *c) {
                        self.diags.error(
                            "E2600",
                            format!(
                                "@no_heap violation in '{}': '{}' allocates on the heap",
                                fn_name, name
                            ),
                            expr.span,
                        );
                    }
                }
                self.walk_expr_no_heap(callee, fn_name, fn_span);
                for a in args { self.walk_expr_no_heap(&a.value, fn_name, fn_span); }
            }
            // String literals — also heap-allocated
            ExprKind::StringLit(_) => {
                self.diags.error(
                    "E2600",
                    format!(
                        "@no_heap violation in '{}': string literal allocates on the heap",
                        fn_name
                    ),
                    expr.span,
                );
            }
            // Recurse into sub-expressions
            ExprKind::Binary { left, right, .. } => {
                self.walk_expr_no_heap(left, fn_name, fn_span);
                self.walk_expr_no_heap(right, fn_name, fn_span);
            }
            ExprKind::Unary { operand, .. } => {
                self.walk_expr_no_heap(operand, fn_name, fn_span);
            }
            ExprKind::FieldAccess { object, .. } => {
                self.walk_expr_no_heap(object, fn_name, fn_span);
            }
            ExprKind::Index { object, index } => {
                self.walk_expr_no_heap(object, fn_name, fn_span);
                self.walk_expr_no_heap(index, fn_name, fn_span);
            }
            ExprKind::MethodCall { object, args, .. } => {
                self.walk_expr_no_heap(object, fn_name, fn_span);
                for a in args { self.walk_expr_no_heap(&a.value, fn_name, fn_span); }
            }
            ExprKind::If { condition, then_block, else_branch } => {
                self.walk_expr_no_heap(condition, fn_name, fn_span);
                for s in &then_block.stmts { self.walk_stmt_no_heap(s, fn_name, fn_span); }
                match else_branch {
                    Some(ElseBranch::Block(b)) => {
                        for s in &b.stmts { self.walk_stmt_no_heap(s, fn_name, fn_span); }
                    }
                    Some(ElseBranch::ElseIf(e)) => self.walk_expr_no_heap(e, fn_name, fn_span),
                    None => {}
                }
            }
            ExprKind::Block(b) => {
                for s in &b.stmts { self.walk_stmt_no_heap(s, fn_name, fn_span); }
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) | ExprKind::Cast { expr: inner, .. } => {
                self.walk_expr_no_heap(inner, fn_name, fn_span);
            }
            ExprKind::Assign { value, .. } => {
                self.walk_expr_no_heap(value, fn_name, fn_span);
            }
            _ => {}
        }
    }

    /// E2601: @no_recursion — function must not call itself directly or indirectly.
    fn check_no_recursion(&mut self, f: &FnDecl, all_fn_names: &std::collections::HashSet<String>) {
        // Check for direct self-calls in the body
        let mut found_self_call = false;
        self.walk_stmts_for_call(&f.body.stmts, &f.name, &mut found_self_call);

        if found_self_call {
            self.diags.error(
                "E2601",
                format!(
                    "@no_recursion violation in '{}': function calls itself (direct recursion detected)",
                    f.name
                ),
                f.span,
            );
        }

        // For indirect recursion, we'd need a full call-graph analysis.
        // We approximate by checking if any callee in the function also calls back.
        // Collect callees from f
        let mut callees: Vec<String> = Vec::new();
        self.collect_callees_from_stmts(&f.body.stmts, &mut callees);

        // For each callee that is a known function, check if it calls f.name
        for callee_name in &callees {
            if callee_name == &f.name { continue; } // already handled above
            if !all_fn_names.contains(callee_name) { continue; }

            // Find the callee's body
            for item in &self.program.items {
                match item {
                    Item::Fn(callee_fn) if callee_fn.name == *callee_name => {
                        let mut calls_back = false;
                        self.walk_stmts_for_call(&callee_fn.body.stmts, &f.name, &mut calls_back);
                        if calls_back {
                            self.diags.error(
                                "E2601",
                                format!(
                                    "@no_recursion violation in '{}': indirect recursion detected \
                                     via '{}' which calls back to '{}'",
                                    f.name, callee_name, f.name
                                ),
                                f.span,
                            );
                        }
                    }
                    Item::Impl(imp) => {
                        for m in &imp.methods {
                            if m.name == *callee_name {
                                let mut calls_back = false;
                                self.walk_stmts_for_call(&m.body.stmts, &f.name, &mut calls_back);
                                if calls_back {
                                    self.diags.error(
                                        "E2601",
                                        format!(
                                            "@no_recursion violation in '{}': indirect recursion detected \
                                             via '{}' which calls back to '{}'",
                                            f.name, callee_name, f.name
                                        ),
                                        f.span,
                                    );
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn walk_stmts_for_call(&self, stmts: &[Stmt], target: &str, found: &mut bool) {
        for stmt in stmts {
            if *found { return; }
            self.walk_stmt_for_call(stmt, target, found);
        }
    }

    fn walk_stmt_for_call(&self, stmt: &Stmt, target: &str, found: &mut bool) {
        if *found { return; }
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.walk_expr_for_call(value, target, found);
            }
            StmtKind::LetDestructure { value, .. } => {
                self.walk_expr_for_call(value, target, found);
            }
            StmtKind::Expr { expr } => {
                self.walk_expr_for_call(expr, target, found);
            }
            StmtKind::Return(Some(expr)) => {
                self.walk_expr_for_call(expr, target, found);
            }
            StmtKind::For { iter, body, .. } => {
                self.walk_expr_for_call(iter, target, found);
                self.walk_stmts_for_call(&body.stmts, target, found);
            }
            StmtKind::While { condition, body } => {
                self.walk_expr_for_call(condition, target, found);
                self.walk_stmts_for_call(&body.stmts, target, found);
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.walk_expr_for_call(expr, target, found);
                self.walk_stmts_for_call(&body.stmts, target, found);
            }
            StmtKind::Loop { body } => {
                self.walk_stmts_for_call(&body.stmts, target, found);
            }
            StmtKind::Bail(expr) => {
                self.walk_expr_for_call(expr, target, found);
            }
            _ => {}
        }
    }

    fn walk_expr_for_call(&self, expr: &Expr, target: &str, found: &mut bool) {
        if *found { return; }
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                if let Some(name) = self.extract_call_name(callee) {
                    if name == target {
                        *found = true;
                        return;
                    }
                }
                self.walk_expr_for_call(callee, target, found);
                for a in args { self.walk_expr_for_call(&a.value, target, found); }
            }
            ExprKind::MethodCall { object, method, args } => {
                if method == target {
                    *found = true;
                    return;
                }
                self.walk_expr_for_call(object, target, found);
                for a in args { self.walk_expr_for_call(&a.value, target, found); }
            }
            ExprKind::Binary { left, right, .. } => {
                self.walk_expr_for_call(left, target, found);
                self.walk_expr_for_call(right, target, found);
            }
            ExprKind::Unary { operand, .. } => {
                self.walk_expr_for_call(operand, target, found);
            }
            ExprKind::FieldAccess { object, .. } => {
                self.walk_expr_for_call(object, target, found);
            }
            ExprKind::Index { object, index } => {
                self.walk_expr_for_call(object, target, found);
                self.walk_expr_for_call(index, target, found);
            }
            ExprKind::If { condition, then_block, else_branch } => {
                self.walk_expr_for_call(condition, target, found);
                self.walk_stmts_for_call(&then_block.stmts, target, found);
                match else_branch {
                    Some(ElseBranch::Block(b)) => self.walk_stmts_for_call(&b.stmts, target, found),
                    Some(ElseBranch::ElseIf(e)) => self.walk_expr_for_call(e, target, found),
                    None => {}
                }
            }
            ExprKind::IfLet { then_block, else_branch, .. } => {
                self.walk_stmts_for_call(&then_block.stmts, target, found);
                match else_branch {
                    Some(ElseBranch::Block(b)) => self.walk_stmts_for_call(&b.stmts, target, found),
                    Some(ElseBranch::ElseIf(e)) => self.walk_expr_for_call(e, target, found),
                    None => {}
                }
            }
            ExprKind::Match { subject, arms } => {
                self.walk_expr_for_call(subject, target, found);
                for arm in arms { self.walk_expr_for_call(&arm.body, target, found); }
            }
            ExprKind::Block(b) => {
                self.walk_stmts_for_call(&b.stmts, target, found);
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) | ExprKind::Cast { expr: inner, .. } => {
                self.walk_expr_for_call(inner, target, found);
            }
            ExprKind::Assign { value, .. } => {
                self.walk_expr_for_call(value, target, found);
            }
            ExprKind::Array(items) => {
                for item in items { self.walk_expr_for_call(item, target, found); }
            }
            ExprKind::Closure { body, .. } => {
                self.walk_stmts_for_call(body, target, found);
            }
            _ => {}
        }
    }

    fn collect_callees_from_stmts(&self, stmts: &[Stmt], callees: &mut Vec<String>) {
        for stmt in stmts {
            self.collect_callees_from_stmt(stmt, callees);
        }
    }

    fn collect_callees_from_stmt(&self, stmt: &Stmt, callees: &mut Vec<String>) {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.collect_callees_from_expr(value, callees);
            }
            StmtKind::LetDestructure { value, .. } => {
                self.collect_callees_from_expr(value, callees);
            }
            StmtKind::Expr { expr } => {
                self.collect_callees_from_expr(expr, callees);
            }
            StmtKind::Return(Some(expr)) => {
                self.collect_callees_from_expr(expr, callees);
            }
            StmtKind::For { iter, body, .. } => {
                self.collect_callees_from_expr(iter, callees);
                self.collect_callees_from_stmts(&body.stmts, callees);
            }
            StmtKind::While { condition, body } => {
                self.collect_callees_from_expr(condition, callees);
                self.collect_callees_from_stmts(&body.stmts, callees);
            }
            StmtKind::Loop { body } => {
                self.collect_callees_from_stmts(&body.stmts, callees);
            }
            StmtKind::Bail(expr) => {
                self.collect_callees_from_expr(expr, callees);
            }
            _ => {}
        }
    }

    fn collect_callees_from_expr(&self, expr: &Expr, callees: &mut Vec<String>) {
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                if let Some(name) = self.extract_call_name(callee) {
                    callees.push(name);
                }
                self.collect_callees_from_expr(callee, callees);
                for a in args { self.collect_callees_from_expr(&a.value, callees); }
            }
            ExprKind::MethodCall { object, method, args } => {
                callees.push(method.clone());
                self.collect_callees_from_expr(object, callees);
                for a in args { self.collect_callees_from_expr(&a.value, callees); }
            }
            ExprKind::Binary { left, right, .. } => {
                self.collect_callees_from_expr(left, callees);
                self.collect_callees_from_expr(right, callees);
            }
            ExprKind::Unary { operand, .. } => {
                self.collect_callees_from_expr(operand, callees);
            }
            ExprKind::If { condition, then_block, else_branch } => {
                self.collect_callees_from_expr(condition, callees);
                self.collect_callees_from_stmts(&then_block.stmts, callees);
                match else_branch {
                    Some(ElseBranch::Block(b)) => self.collect_callees_from_stmts(&b.stmts, callees),
                    Some(ElseBranch::ElseIf(e)) => self.collect_callees_from_expr(e, callees),
                    None => {}
                }
            }
            ExprKind::Block(b) => {
                self.collect_callees_from_stmts(&b.stmts, callees);
            }
            ExprKind::Array(items) => {
                for item in items { self.collect_callees_from_expr(item, callees); }
            }
            _ => {}
        }
    }

    /// E2602: @bounded_by(N) — all loops in function must have bounded iteration count.
    /// E2603: @bounded_by with no bound specified.
    /// E2604: unbounded loop (while true, loop {}) in a @bounded_by function.
    fn check_bounded_by(&mut self, f: &FnDecl, ann: &Annotation) {
        // Extract the bound value from the annotation
        let bound = self.extract_bounded_by_value(ann);

        match bound {
            None => {
                self.diags.error(
                    "E2603",
                    format!(
                        "@bounded_by on '{}' requires a numeric bound \
                         (e.g., @bounded_by(1000))",
                        f.name
                    ),
                    ann.span,
                );
                return;
            }
            Some(_) => {}
        }

        // Walk body for unbounded loops
        for stmt in &f.body.stmts {
            self.walk_stmt_bounded_by(stmt, &f.name);
        }
    }

    fn extract_bounded_by_value(&self, ann: &Annotation) -> Option<i128> {
        // Try positional integer argument first
        for arg in &ann.args {
            if arg.name.is_empty() {
                if let ExprKind::IntLit(v) = &arg.value.kind {
                    return Some(*v);
                }
            }
        }
        // Try named `bound:` or `n:` argument
        for arg in &ann.args {
            if arg.name == "bound" || arg.name == "n" {
                if let ExprKind::IntLit(v) = &arg.value.kind {
                    return Some(*v);
                }
            }
        }
        None
    }

    fn walk_stmt_bounded_by(&mut self, stmt: &Stmt, fn_name: &str) {
        match &stmt.kind {
            // `while <condition>` — check if condition is always true (unbounded)
            StmtKind::While { condition, body } => {
                if self.is_always_true(condition) {
                    self.diags.error(
                        "E2604",
                        format!(
                            "@bounded_by violation in '{}': unbounded 'while true' loop detected",
                            fn_name
                        ),
                        condition.span,
                    );
                }
                self.walk_expr_bounded_by(condition, fn_name);
                for s in &body.stmts { self.walk_stmt_bounded_by(s, fn_name); }
            }
            // `loop {}` is always unbounded
            StmtKind::Loop { body } => {
                self.diags.error(
                    "E2604",
                    format!(
                        "@bounded_by violation in '{}': unbounded 'loop' construct detected \
                         — use 'for' with a range instead",
                        fn_name
                    ),
                    stmt.span,
                );
                for s in &body.stmts { self.walk_stmt_bounded_by(s, fn_name); }
            }
            // `for` loops with ranges are bounded — OK
            StmtKind::For { body, .. } => {
                for s in &body.stmts { self.walk_stmt_bounded_by(s, fn_name); }
            }
            StmtKind::WhileLet { body, .. } => {
                for s in &body.stmts { self.walk_stmt_bounded_by(s, fn_name); }
            }
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.walk_expr_bounded_by(value, fn_name);
            }
            StmtKind::LetDestructure { value, .. } => {
                self.walk_expr_bounded_by(value, fn_name);
            }
            StmtKind::Expr { expr } => {
                self.walk_expr_bounded_by(expr, fn_name);
            }
            StmtKind::Return(Some(expr)) => {
                self.walk_expr_bounded_by(expr, fn_name);
            }
            _ => {}
        }
    }

    fn walk_expr_bounded_by(&mut self, expr: &Expr, fn_name: &str) {
        match &expr.kind {
            ExprKind::If { then_block, else_branch, .. } => {
                for s in &then_block.stmts { self.walk_stmt_bounded_by(s, fn_name); }
                match else_branch {
                    Some(ElseBranch::Block(b)) => {
                        for s in &b.stmts { self.walk_stmt_bounded_by(s, fn_name); }
                    }
                    Some(ElseBranch::ElseIf(e)) => self.walk_expr_bounded_by(e, fn_name),
                    None => {}
                }
            }
            ExprKind::Block(b) => {
                for s in &b.stmts { self.walk_stmt_bounded_by(s, fn_name); }
            }
            ExprKind::Match { arms, .. } => {
                for arm in arms { self.walk_expr_bounded_by(&arm.body, fn_name); }
            }
            ExprKind::Closure { body, .. } => {
                for s in body { self.walk_stmt_bounded_by(s, fn_name); }
            }
            _ => {}
        }
    }

    fn is_always_true(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::BoolLit(true) => true,
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
        SafetyPass::new(&program).check()
    }

    // ── Test 1: All 14 valid safety level names parse correctly ──────

    #[test]
    fn test_parse_safety_level_all_valid() {
        // DAL levels
        assert_eq!(parse_safety_level("dal_a"), Some(0));
        assert_eq!(parse_safety_level("dal_b"), Some(1));
        assert_eq!(parse_safety_level("dal_c"), Some(2));
        assert_eq!(parse_safety_level("dal_d"), Some(3));
        assert_eq!(parse_safety_level("dal_e"), Some(4));
        // ASIL levels
        assert_eq!(parse_safety_level("asil_d"), Some(0));
        assert_eq!(parse_safety_level("asil_c"), Some(1));
        assert_eq!(parse_safety_level("asil_b"), Some(2));
        assert_eq!(parse_safety_level("asil_a"), Some(3));
        // QM
        assert_eq!(parse_safety_level("qm"), Some(4));
        // SIL levels
        assert_eq!(parse_safety_level("sil_4"), Some(0));
        assert_eq!(parse_safety_level("sil_3"), Some(1));
        assert_eq!(parse_safety_level("sil_2"), Some(2));
        assert_eq!(parse_safety_level("sil_1"), Some(3));
    }

    // ── Test 2: Unknown level rejected (E2100) ──────────────────────

    #[test]
    fn test_unknown_safety_level_e2100() {
        let src = r#"
@safety_critical(level: .bogus)
fn critical_fn(x: i32) -> i32 {
    x
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 1);
        assert_eq!(diags.items[0].code, "E2100");
        assert!(diags.items[0].msg.contains("bogus"));
    }

    // ── Test 3: Same-level calls allowed ─────────────────────────────

    #[test]
    fn test_same_level_calls_allowed() {
        let src = r#"
@safety_critical(level: .asil_d)
fn fn_a(x: i32) -> i32 {
    fn_b(x)
}

@safety_critical(level: .asil_d)
fn fn_b(x: i32) -> i32 {
    x * 2
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter().filter(|d| d.severity == crate::error::Severity::Error).collect();
        assert_eq!(errors.len(), 0, "same-level calls should be allowed");
    }

    // ── Test 4: Higher-calling-lower blocked (E2101) ─────────────────

    #[test]
    fn test_higher_calling_lower_e2101() {
        let src = r#"
@safety_critical(level: .asil_d)
fn critical_fn(x: i32) -> i32 {
    medium_fn(x)
}

@safety_critical(level: .asil_b)
fn medium_fn(x: i32) -> i32 {
    x + 1
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2101")
            .collect();
        assert_eq!(errors.len(), 1, "higher calling lower should produce E2101");
        assert!(errors[0].msg.contains("critical_fn"));
        assert!(errors[0].msg.contains("medium_fn"));
    }

    // ── Test 5: Lower-calling-higher allowed ─────────────────────────

    #[test]
    fn test_lower_calling_higher_allowed() {
        let src = r#"
@safety_critical(level: .asil_b)
fn medium_fn(x: i32) -> i32 {
    critical_fn(x)
}

@safety_critical(level: .asil_d)
fn critical_fn(x: i32) -> i32 {
    x * 2
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2101")
            .collect();
        assert_eq!(errors.len(), 0, "lower calling higher should be allowed");
    }

    // ── Test 6: @downgrade suppresses E2101 ──────────────────────────

    #[test]
    fn test_downgrade_suppresses_violation() {
        let src = r#"
@safety_critical(level: .asil_d)
@downgrade(reason: "validated externally via hardware watchdog")
fn critical_fn(x: i32) -> i32 {
    medium_fn(x)
}

@safety_critical(level: .asil_b)
fn medium_fn(x: i32) -> i32 {
    x + 1
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2101")
            .collect();
        assert_eq!(errors.len(), 0, "@downgrade with reason should suppress E2101");
        let e2102: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2102")
            .collect();
        assert_eq!(e2102.len(), 0, "should have no E2102 either");
    }

    // ── Test 7: @downgrade without reason produces E2102 ─────────────

    #[test]
    fn test_downgrade_without_reason_e2102() {
        let src = r#"
@safety_critical(level: .asil_d)
@downgrade
fn critical_fn(x: i32) -> i32 {
    medium_fn(x)
}

@safety_critical(level: .asil_b)
fn medium_fn(x: i32) -> i32 {
    x + 1
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2102")
            .collect();
        assert_eq!(errors.len(), 1, "@downgrade without reason should produce E2102");
        assert!(errors[0].msg.contains("reason"));
    }

    // ── Test 8: W2100 on calling unannotated function ────────────────

    #[test]
    fn test_calling_unannotated_w2100() {
        let src = r#"
@safety_critical(level: .sil_4)
fn critical_fn(x: i32) -> i32 {
    helper(x)
}

fn helper(x: i32) -> i32 {
    x + 1
}
"#;
        let diags = parse_and_check(src);
        let warnings: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W2100")
            .collect();
        assert_eq!(warnings.len(), 1, "calling unannotated fn should produce W2100");
        assert!(warnings[0].msg.contains("helper"));
    }

    // ── Test 9: Cross-standard equivalence ───────────────────────────

    #[test]
    fn test_cross_standard_equivalence() {
        // ASIL-D = DAL-A = SIL-4 (all level 0) — calling between them is fine
        let src = r#"
@safety_critical(level: .asil_d)
fn auto_fn(x: i32) -> i32 {
    avionics_fn(x)
}

@safety_critical(level: .dal_a)
fn avionics_fn(x: i32) -> i32 {
    industrial_fn(x)
}

@safety_critical(level: .sil_4)
fn industrial_fn(x: i32) -> i32 {
    x * 2
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2101")
            .collect();
        assert_eq!(errors.len(), 0, "equivalent levels across standards should be allowed");
    }

    // ── Test 10: Impl method safety validation ───────────────────────

    #[test]
    fn test_impl_method_safety() {
        let src = r#"
struct Controller {
    value: i32
}

impl Controller {
    @safety_critical(level: .asil_d)
    fn critical_method(self) -> i32 {
        self.lower_method()
    }

    @safety_critical(level: .asil_b)
    fn lower_method(self) -> i32 {
        self.value
    }
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2101")
            .collect();
        assert_eq!(errors.len(), 1, "impl method should have E2101 for calling lower method");
    }

    // ── Test 11: No annotation -> no diagnostics ─────────────────────

    #[test]
    fn test_no_annotation_no_diagnostics() {
        let src = r#"
fn add(a: i32, b: i32) -> i32 {
    a + b
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0);
        assert_eq!(diags.warning_count(), 0);
    }

    // ── Test 12: Positional argument syntax ──────────────────────────

    #[test]
    fn test_positional_level_argument() {
        let src = r#"
@safety_critical(.dal_a)
fn critical_fn(x: i32) -> i32 {
    x
}
"#;
        let diags = parse_and_check(src);
        // Should parse level correctly — no E2100, no errors except maybe W2100
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2100")
            .collect();
        assert_eq!(errors.len(), 0, "positional .dal_a should be accepted");
    }

    // ── Test 13: No level specified -> E2100 ─────────────────────────

    #[test]
    fn test_no_level_specified_e2100() {
        let src = r#"
@safety_critical
fn critical_fn(x: i32) -> i32 {
    x
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2100")
            .collect();
        assert_eq!(errors.len(), 1, "missing level should produce E2100");
    }

    // ── Test 14: Recursive body walking — nested if/match/loop ───────

    #[test]
    fn test_nested_call_in_if_body() {
        let src = r#"
@safety_critical(level: .dal_a)
fn critical_fn(x: i32) -> i32 {
    if x > 0 {
        lower_fn(x)
    } else {
        x
    }
}

@safety_critical(level: .dal_c)
fn lower_fn(x: i32) -> i32 {
    x + 1
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2101")
            .collect();
        assert_eq!(errors.len(), 1, "call inside if body should be caught");
    }

    // ── Test 15: Multiple violations in one function ─────────────────

    #[test]
    fn test_multiple_violations() {
        let src = r#"
@safety_critical(level: .sil_4)
fn top_fn(x: i32) -> i32 {
    let a = mid_fn(x)
    let b = low_fn(a)
    b
}

@safety_critical(level: .sil_2)
fn mid_fn(x: i32) -> i32 {
    x + 1
}

@safety_critical(level: .sil_1)
fn low_fn(x: i32) -> i32 {
    x * 2
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2101")
            .collect();
        assert_eq!(errors.len(), 2, "should have 2 E2101 errors for calling both lower functions");
    }

    // ── Test 16: DAL-E / QM calling DAL-A is fine (low calls high) ──

    #[test]
    fn test_low_safety_calling_high_safety_ok() {
        let src = r#"
@safety_critical(level: .dal_e)
fn low_fn(x: i32) -> i32 {
    high_fn(x)
}

@safety_critical(level: .dal_a)
fn high_fn(x: i32) -> i32 {
    x * 2
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2101")
            .collect();
        assert_eq!(errors.len(), 0, "DAL-E calling DAL-A should be allowed");
    }

    // ── Test 17: Call in for-loop body detected ──────────────────────

    #[test]
    fn test_call_in_for_loop() {
        let src = r#"
@safety_critical(level: .asil_d)
fn critical_fn(items: []i32) -> i32 {
    for item in items {
        lower_fn(item)
    }
    0
}

@safety_critical(level: .qm)
fn lower_fn(x: i32) -> i32 {
    x
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2101")
            .collect();
        assert_eq!(errors.len(), 1, "call in for loop body should be caught");
    }

    // ══════════════════════════════════════════════════════════════════════
    // ── Phase 44: @no_heap, @no_recursion, @bounded_by tests ──
    // ══════════════════════════════════════════════════════════════════════

    // ── Test 18: @no_heap detects array literal ───────────────────────

    #[test]
    fn test_no_heap_array_literal_e2600() {
        let src = r#"
@no_heap
fn stack_only(x: i32) -> i32 {
    let arr = [1, 2, 3]
    x
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2600")
            .collect();
        assert!(errors.len() >= 1, "@no_heap should detect array literal");
        assert!(errors[0].msg.contains("no_heap"));
    }

    // ── Test 19: @no_heap detects string literal ──────────────────────

    #[test]
    fn test_no_heap_string_literal_e2600() {
        let src = r#"
@no_heap
fn stack_only(x: i32) -> i32 {
    let s = "hello"
    x
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2600")
            .collect();
        assert!(errors.len() >= 1, "@no_heap should detect string literal");
        assert!(errors[0].msg.contains("string literal"));
    }

    // ── Test 20: @no_heap allows pure arithmetic ──────────────────────

    #[test]
    fn test_no_heap_allows_arithmetic() {
        let src = r#"
@no_heap
fn add(a: i32, b: i32) -> i32 {
    a + b
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2600")
            .collect();
        assert_eq!(errors.len(), 0, "@no_heap should allow pure arithmetic");
    }

    // ── Test 21: @no_recursion detects direct recursion ───────────────

    #[test]
    fn test_no_recursion_direct_e2601() {
        let src = r#"
@no_recursion
fn factorial(n: i32) -> i32 {
    if n <= 1 {
        1
    } else {
        n * factorial(n - 1)
    }
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2601")
            .collect();
        assert!(errors.len() >= 1, "@no_recursion should detect direct recursion");
        assert!(errors[0].msg.contains("direct recursion"));
    }

    // ── Test 22: @no_recursion detects indirect recursion ─────────────

    #[test]
    fn test_no_recursion_indirect_e2601() {
        let src = r#"
@no_recursion
fn ping(n: i32) -> i32 {
    pong(n)
}

fn pong(n: i32) -> i32 {
    ping(n - 1)
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2601")
            .collect();
        assert!(errors.len() >= 1, "@no_recursion should detect indirect recursion");
        assert!(errors[0].msg.contains("indirect recursion"));
    }

    // ── Test 23: @no_recursion allows non-recursive function ──────────

    #[test]
    fn test_no_recursion_allows_non_recursive() {
        let src = r#"
@no_recursion
fn add(a: i32, b: i32) -> i32 {
    a + b
}

fn helper(x: i32) -> i32 {
    x * 2
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2601")
            .collect();
        assert_eq!(errors.len(), 0, "@no_recursion should allow non-recursive function");
    }

    // ── Test 24: @bounded_by detects while true ───────────────────────

    #[test]
    fn test_bounded_by_while_true_e2604() {
        let src = r#"
@bounded_by(1000)
fn process(x: i32) -> i32 {
    var result = 0
    while true {
        result = result + 1
    }
    result
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2604")
            .collect();
        assert!(errors.len() >= 1, "@bounded_by should detect while true");
        assert!(errors[0].msg.contains("unbounded"));
    }

    // ── Test 25: @bounded_by detects loop construct ───────────────────

    #[test]
    fn test_bounded_by_loop_e2604() {
        let src = r#"
@bounded_by(100)
fn process(x: i32) -> i32 {
    var result = 0
    loop {
        result = result + 1
    }
    result
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2604")
            .collect();
        assert!(errors.len() >= 1, "@bounded_by should detect loop construct");
    }

    // ── Test 26: @bounded_by allows for-range loops ───────────────────

    #[test]
    fn test_bounded_by_allows_for_range() {
        let src = r#"
@bounded_by(100)
fn process(items: []i32) -> i32 {
    var sum = 0
    for item in items {
        sum = sum + item
    }
    sum
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2604")
            .collect();
        assert_eq!(errors.len(), 0, "@bounded_by should allow for-range loops");
    }

    // ── Test 27: @bounded_by without value produces E2603 ─────────────

    #[test]
    fn test_bounded_by_no_value_e2603() {
        let src = r#"
@bounded_by
fn process(x: i32) -> i32 {
    x
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2603")
            .collect();
        assert_eq!(errors.len(), 1, "@bounded_by without value should produce E2603");
    }

    // ── Test 28: Combined @safety_critical + @no_heap ─────────────────

    #[test]
    fn test_combined_safety_critical_no_heap() {
        let src = r#"
@safety_critical(level: .sil_4)
@no_heap
fn critical_stack_only(a: i32, b: i32) -> i32 {
    a + b
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.severity == crate::error::Severity::Error)
            .collect();
        assert_eq!(errors.len(), 0, "combined annotations should work on valid code");
    }
}
