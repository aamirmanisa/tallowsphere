//! Contract programming and property-based testing compiler pass.
//!
//! Validates `@requires`, `@ensures`, `@invariant`, and `@property` annotations:
//!
//! - E1300: `@requires` references unknown identifier (not in function params)
//! - E1301: `@ensures` references unknown identifier (not in params or `result`)
//! - E1302: `@invariant` used outside of impl method
//! - E1303: `@invariant` references unknown field on struct
//! - E1304: Duplicate contract annotation of same type on same function (warning)
//! - E1305: `@property` on function with untyped params
//! - E1306: `@property` on function with unsupported param type for random generation
//! - W1300: `@property` function body has no assertions

use std::collections::{HashMap, HashSet};

use crate::ast::*;
use crate::error::{Diagnostic, Diagnostics};
use crate::typeck::TypeEnv;

// ── Contract Pass ──────────────────────────────────────────────────────────

pub struct ContractPass<'a> {
    program: &'a Program,
    #[allow(dead_code)]
    env: &'a TypeEnv,
    pub diags: Diagnostics,
    /// Map struct name -> field names (for @invariant validation).
    struct_fields: HashMap<String, Vec<String>>,
}

/// Types supported for random generation in property-based testing.
const PROPERTY_SUPPORTED_TYPES: &[&str] = &[
    "i32", "i64", "u32", "u64", "f64", "bool", "String",
];

impl<'a> ContractPass<'a> {
    pub fn new(program: &'a Program, env: &'a TypeEnv) -> Self {
        Self {
            program,
            env,
            diags: Diagnostics::new(),
            struct_fields: HashMap::new(),
        }
    }

    /// Run the contract pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        // Phase 0: Collect struct field names for @invariant validation
        for item in &self.program.items {
            if let Item::Struct(s) = item {
                let fields: Vec<String> = s.fields.iter().map(|f| f.name.clone()).collect();
                self.struct_fields.insert(s.name.clone(), fields);
            }
        }

        // Phase 1: Validate contract annotations on functions
        for item in &self.program.items {
            match item {
                Item::Fn(f) => {
                    self.validate_contracts(f, None);
                    self.validate_property(f);
                }
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.validate_contracts(m, Some(&imp.target));
                        self.validate_property(m);
                    }
                }
                _ => {}
            }
        }

        self.diags
    }

    /// Validate @requires, @ensures, @invariant annotations on a function.
    /// `impl_target` is Some(struct_name) if the function is an impl method.
    fn validate_contracts(&mut self, f: &FnDecl, impl_target: Option<&str>) {
        let param_names: HashSet<String> = f.params.iter().map(|p| p.name.clone()).collect();

        let mut requires_count = 0u32;
        let mut ensures_count = 0u32;
        let mut invariant_count = 0u32;

        for ann in &f.annotations {
            match ann.name.as_str() {
                "requires" => {
                    requires_count += 1;
                    if requires_count > 1 {
                        self.diags.push(Diagnostic::warning(
                            "E1304",
                            format!(
                                "duplicate @requires annotation on function `{}`",
                                f.name
                            ),
                            ann.span,
                        ));
                    }
                    // Extract condition expression from first unnamed arg
                    if let Some(condition_arg) = ann.args.first() {
                        if condition_arg.name.is_empty() || condition_arg.name == "" {
                            let idents = collect_idents_from_expr(&condition_arg.value);
                            for ident in &idents {
                                if !param_names.contains(ident) {
                                    self.diags.push(Diagnostic::error(
                                        "E1300",
                                        format!(
                                            "contract error: `@requires` references unknown identifier `{}` in function `{}`",
                                            ident, f.name
                                        ),
                                        ann.span,
                                    ));
                                }
                            }
                        }
                    }
                }
                "ensures" => {
                    ensures_count += 1;
                    if ensures_count > 1 {
                        self.diags.push(Diagnostic::warning(
                            "E1304",
                            format!(
                                "duplicate @ensures annotation on function `{}`",
                                f.name
                            ),
                            ann.span,
                        ));
                    }
                    if let Some(condition_arg) = ann.args.first() {
                        if condition_arg.name.is_empty() || condition_arg.name == "" {
                            let idents = collect_idents_from_expr(&condition_arg.value);
                            for ident in &idents {
                                // @ensures allows `result` in addition to param names
                                if ident != "result" && !param_names.contains(ident) {
                                    self.diags.push(Diagnostic::error(
                                        "E1301",
                                        format!(
                                            "contract error: `@ensures` references unknown identifier `{}` in function `{}`",
                                            ident, f.name
                                        ),
                                        ann.span,
                                    ));
                                }
                            }
                        }
                    }
                }
                "invariant" => {
                    invariant_count += 1;
                    if invariant_count > 1 {
                        self.diags.push(Diagnostic::warning(
                            "E1304",
                            format!(
                                "duplicate @invariant annotation on function `{}`",
                                f.name
                            ),
                            ann.span,
                        ));
                    }
                    if let Some(struct_name) = impl_target {
                        // Validate field references
                        if let Some(condition_arg) = ann.args.first() {
                            if condition_arg.name.is_empty() || condition_arg.name == "" {
                                let field_refs = collect_self_field_refs(&condition_arg.value);
                                if let Some(fields) = self.struct_fields.get(struct_name) {
                                    for field_ref in &field_refs {
                                        if !fields.contains(field_ref) {
                                            self.diags.push(Diagnostic::error(
                                                "E1303",
                                                format!(
                                                    "`@invariant` references unknown field `{}` on struct `{}`",
                                                    field_ref, struct_name
                                                ),
                                                ann.span,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        // @invariant on standalone function
                        self.diags.push(Diagnostic::error(
                            "E1302",
                            format!(
                                "`@invariant` used on standalone function `{}` — only valid on impl methods",
                                f.name
                            ),
                            ann.span,
                        ));
                    }
                }
                _ => {}
            }
        }
    }

    /// Validate @property annotations on a function.
    fn validate_property(&mut self, f: &FnDecl) {
        let has_property = f.annotations.iter().any(|a| a.name == "property");
        if !has_property {
            return;
        }

        // Check all params have types that support random generation
        for param in &f.params {
            match &param.ty.kind {
                TypeExprKind::Named(name) => {
                    if name == "_" || name.is_empty() {
                        self.diags.push(Diagnostic::error(
                            "E1305",
                            format!(
                                "property test function `{}` requires typed parameters for random generation",
                                f.name
                            ),
                            param.span,
                        ));
                    } else if !PROPERTY_SUPPORTED_TYPES.contains(&name.as_str()) {
                        self.diags.push(Diagnostic::error(
                            "E1306",
                            format!(
                                "property test function `{}`: parameter `{}` has unsupported type `{}` for random generation (supported: {})",
                                f.name, param.name, name,
                                PROPERTY_SUPPORTED_TYPES.join(", ")
                            ),
                            param.span,
                        ));
                    }
                }
                _ => {
                    // Generic, Slice, Optional, Tuple, Function types are not supported
                    self.diags.push(Diagnostic::error(
                        "E1306",
                        format!(
                            "property test function `{}`: parameter `{}` has unsupported type for random generation (supported: {})",
                            f.name, param.name,
                            PROPERTY_SUPPORTED_TYPES.join(", ")
                        ),
                        param.span,
                    ));
                }
            }
        }

        // Check that body contains assert calls (warning)
        if !block_contains_assert(&f.body) {
            self.diags.push(Diagnostic::warning(
                "W1300",
                format!(
                    "property function `{}` has no assertions",
                    f.name
                ),
                f.span,
            ));
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Recursively collect all identifier names from an expression tree.
/// For `self.field` patterns (FieldAccess on Ident("self")), skips `self`
/// and does NOT add the field name (use `collect_self_field_refs` for that).
fn collect_idents_from_expr(expr: &Expr) -> Vec<String> {
    let mut idents = Vec::new();
    collect_idents_inner(expr, &mut idents);
    idents
}

fn collect_idents_inner(expr: &Expr, idents: &mut Vec<String>) {
    match &expr.kind {
        ExprKind::Ident(name) => {
            if name != "self" {
                idents.push(name.clone());
            }
        }
        ExprKind::Binary { left, right, .. } => {
            collect_idents_inner(left, idents);
            collect_idents_inner(right, idents);
        }
        ExprKind::Unary { operand, .. } => {
            collect_idents_inner(operand, idents);
        }
        ExprKind::Call { callee, args } => {
            collect_idents_inner(callee, idents);
            for arg in args {
                collect_idents_inner(&arg.value, idents);
            }
        }
        ExprKind::MethodCall { object, args, .. } => {
            collect_idents_inner(object, idents);
            for arg in args {
                collect_idents_inner(&arg.value, idents);
            }
        }
        ExprKind::FieldAccess { object, field: _ } => {
            // For self.field, don't add self or field to idents
            // (field refs are handled separately by collect_self_field_refs)
            if let ExprKind::Ident(name) = &object.kind {
                if name == "self" {
                    return; // skip self.field entirely for ident collection
                }
            }
            collect_idents_inner(object, idents);
            // field name is not an identifier reference
        }
        ExprKind::Index { object, index } => {
            collect_idents_inner(object, idents);
            collect_idents_inner(index, idents);
        }
        ExprKind::IntLit(_) | ExprKind::FloatLit(_) | ExprKind::StringLit(_)
        | ExprKind::BoolLit(_) | ExprKind::Nil | ExprKind::DotIdent(_) => {}
        ExprKind::If { condition, then_block, else_branch } => {
            collect_idents_inner(condition, idents);
            for stmt in &then_block.stmts {
                if let StmtKind::Expr { expr } = &stmt.kind {
                    collect_idents_inner(expr, idents);
                }
            }
            if let Some(eb) = else_branch {
                match eb {
                    ElseBranch::ElseIf(e) => collect_idents_inner(e, idents),
                    ElseBranch::Block(block) => {
                        for stmt in &block.stmts {
                            if let StmtKind::Expr { expr } = &stmt.kind {
                                collect_idents_inner(expr, idents);
                            }
                        }
                    }
                }
            }
        }
        ExprKind::Block(block) => {
            for stmt in &block.stmts {
                if let StmtKind::Expr { expr } = &stmt.kind {
                    collect_idents_inner(expr, idents);
                }
            }
        }
        _ => {}
    }
}

/// Collect `self.field` references from an expression.
/// Returns the field names referenced (e.g., `self.count` -> "count").
fn collect_self_field_refs(expr: &Expr) -> Vec<String> {
    let mut refs = Vec::new();
    collect_self_field_refs_inner(expr, &mut refs);
    refs
}

fn collect_self_field_refs_inner(expr: &Expr, refs: &mut Vec<String>) {
    match &expr.kind {
        ExprKind::FieldAccess { object, field } => {
            if let ExprKind::Ident(name) = &object.kind {
                if name == "self" {
                    refs.push(field.clone());
                    return;
                }
            }
            collect_self_field_refs_inner(object, refs);
        }
        ExprKind::Binary { left, right, .. } => {
            collect_self_field_refs_inner(left, refs);
            collect_self_field_refs_inner(right, refs);
        }
        ExprKind::Unary { operand, .. } => {
            collect_self_field_refs_inner(operand, refs);
        }
        ExprKind::Call { callee, args } => {
            collect_self_field_refs_inner(callee, refs);
            for arg in args {
                collect_self_field_refs_inner(&arg.value, refs);
            }
        }
        ExprKind::MethodCall { object, args, .. } => {
            collect_self_field_refs_inner(object, refs);
            for arg in args {
                collect_self_field_refs_inner(&arg.value, refs);
            }
        }
        ExprKind::Index { object, index } => {
            collect_self_field_refs_inner(object, refs);
            collect_self_field_refs_inner(index, refs);
        }
        _ => {}
    }
}

/// Check if a block contains any call to `assert` (directly or nested).
fn block_contains_assert(block: &Block) -> bool {
    for stmt in &block.stmts {
        if stmt_contains_assert(stmt) {
            return true;
        }
    }
    false
}

fn stmt_contains_assert(stmt: &Stmt) -> bool {
    match &stmt.kind {
        StmtKind::Expr { expr } => expr_contains_assert(expr),
        StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
            expr_contains_assert(value)
        }
        StmtKind::Return(Some(e)) => expr_contains_assert(e),
        StmtKind::Return(None) => false,
        StmtKind::For { body, .. } | StmtKind::While { body, .. } => block_contains_assert(body),
        _ => false,
    }
}

fn expr_contains_assert(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::Call { callee, args } => {
            if let ExprKind::Ident(name) = &callee.kind {
                if name == "assert" || name == "assert_eq" || name == "assert_ne" {
                    return true;
                }
            }
            // Check args recursively
            for arg in args {
                if expr_contains_assert(&arg.value) {
                    return true;
                }
            }
            false
        }
        ExprKind::Block(block) => block_contains_assert(block),
        ExprKind::If { condition, then_block, else_branch } => {
            expr_contains_assert(condition)
                || block_contains_assert(then_block)
                || else_branch.as_ref().map_or(false, |eb| match eb {
                    ElseBranch::ElseIf(e) => expr_contains_assert(e),
                    ElseBranch::Block(b) => block_contains_assert(b),
                })
        }
        ExprKind::Binary { left, right, .. } => {
            expr_contains_assert(left) || expr_contains_assert(right)
        }
        _ => false,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Span;

    fn dummy_span() -> Span {
        Span { start: 0, end: 0 }
    }

    fn make_ident_expr(name: &str) -> Expr {
        Expr {
            kind: ExprKind::Ident(name.to_string()),
            span: dummy_span(),
        }
    }

    fn make_int_expr(n: i128) -> Expr {
        Expr {
            kind: ExprKind::IntLit(n),
            span: dummy_span(),
        }
    }

    fn make_binary(left: Expr, op: BinOp, right: Expr) -> Expr {
        Expr {
            kind: ExprKind::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            },
            span: dummy_span(),
        }
    }

    fn make_field_access(object: Expr, field: &str) -> Expr {
        Expr {
            kind: ExprKind::FieldAccess {
                object: Box::new(object),
                field: field.to_string(),
            },
            span: dummy_span(),
        }
    }

    fn make_param(name: &str, ty: &str) -> Param {
        Param {
            name: name.to_string(),
            ty: TypeExpr::new(TypeExprKind::Named(ty.to_string()), dummy_span()),
            default: None,
            span: dummy_span(),
        }
    }

    fn make_annotation(name: &str, condition: Expr) -> Annotation {
        Annotation {
            name: name.to_string(),
            args: vec![AnnotationArg {
                name: String::new(),
                value: condition,
                span: dummy_span(),
            }],
            span: dummy_span(),
        }
    }

    fn make_fn(name: &str, params: Vec<Param>, annotations: Vec<Annotation>, body: Vec<Stmt>) -> FnDecl {
        FnDecl {
            annotations,
            is_async: false,
            name: name.to_string(),
            type_params: vec![],
            params,
            return_type: None,
            body: Block {
                stmts: body,
                span: dummy_span(),
            },
            span: dummy_span(),
        }
    }

    fn make_program(items: Vec<Item>) -> Program {
        Program {
            items,
            span: dummy_span(),
        }
    }

    fn run_pass(program: &Program) -> Diagnostics {
        let env = TypeEnv::default();
        ContractPass::new(program, &env).check()
    }

    // ── @requires tests ──────────────────────────────────────────────────

    #[test]
    fn requires_valid_param_reference() {
        // @requires(n > 0) on fn foo(n: i32) -> no error
        let cond = make_binary(make_ident_expr("n"), BinOp::Gt, make_int_expr(0));
        let f = make_fn("foo", vec![make_param("n", "i32")], vec![make_annotation("requires", cond)], vec![]);
        let program = make_program(vec![Item::Fn(f)]);
        let diags = run_pass(&program);
        assert_eq!(diags.error_count(), 0, "expected no errors: {:?}", diags.items);
    }

    #[test]
    fn requires_unknown_identifier() {
        // @requires(x > 0) on fn foo(n: i32) -> E1300
        let cond = make_binary(make_ident_expr("x"), BinOp::Gt, make_int_expr(0));
        let f = make_fn("foo", vec![make_param("n", "i32")], vec![make_annotation("requires", cond)], vec![]);
        let program = make_program(vec![Item::Fn(f)]);
        let diags = run_pass(&program);
        assert_eq!(diags.error_count(), 1);
        assert!(diags.items[0].code == "E1300", "expected E1300, got {}", diags.items[0].code);
    }

    // ── @ensures tests ───────────────────────────────────────────────────

    #[test]
    fn ensures_result_reference_valid() {
        // @ensures(result > 0) on fn foo(n: i32) -> i32 -> no error
        let cond = make_binary(make_ident_expr("result"), BinOp::Gt, make_int_expr(0));
        let f = make_fn("foo", vec![make_param("n", "i32")], vec![make_annotation("ensures", cond)], vec![]);
        let program = make_program(vec![Item::Fn(f)]);
        let diags = run_pass(&program);
        assert_eq!(diags.error_count(), 0, "expected no errors: {:?}", diags.items);
    }

    #[test]
    fn ensures_unknown_identifier() {
        // @ensures(bogus > 0) -> E1301
        let cond = make_binary(make_ident_expr("bogus"), BinOp::Gt, make_int_expr(0));
        let f = make_fn("foo", vec![make_param("n", "i32")], vec![make_annotation("ensures", cond)], vec![]);
        let program = make_program(vec![Item::Fn(f)]);
        let diags = run_pass(&program);
        assert_eq!(diags.error_count(), 1);
        assert!(diags.items[0].code == "E1301", "expected E1301, got {}", diags.items[0].code);
    }

    // ── @invariant tests ─────────────────────────────────────────────────

    #[test]
    fn invariant_in_impl_method_valid() {
        // @invariant(self.count >= 0) inside impl method -> no error
        let cond = make_binary(
            make_field_access(make_ident_expr("self"), "count"),
            BinOp::Gte,
            make_int_expr(0),
        );
        let method = make_fn("increment", vec![], vec![make_annotation("invariant", cond)], vec![]);
        let struct_decl = StructDecl {
            name: "Counter".to_string(),
            type_params: vec![],
            fields: vec![FieldDecl {
                name: "count".to_string(),
                ty: TypeExpr::new(TypeExprKind::Named("i32".to_string()), dummy_span()),
                default: None,
                span: dummy_span(),
            }],
            span: dummy_span(),
        };
        let impl_block = ImplBlock {
            trait_name: None,
            type_params: vec![],
            target: "Counter".to_string(),
            methods: vec![method],
            span: dummy_span(),
        };
        let program = make_program(vec![Item::Struct(struct_decl), Item::Impl(impl_block)]);
        let diags = run_pass(&program);
        assert_eq!(diags.error_count(), 0, "expected no errors: {:?}", diags.items);
    }

    #[test]
    fn invariant_on_standalone_function() {
        // @invariant(...) on standalone function -> E1302
        let cond = make_binary(make_ident_expr("x"), BinOp::Gt, make_int_expr(0));
        let f = make_fn("foo", vec![], vec![make_annotation("invariant", cond)], vec![]);
        let program = make_program(vec![Item::Fn(f)]);
        let diags = run_pass(&program);
        assert_eq!(diags.error_count(), 1);
        assert!(diags.items[0].code == "E1302", "expected E1302, got {}", diags.items[0].code);
    }

    #[test]
    fn invariant_unknown_field() {
        // @invariant(self.bogus >= 0) -> E1303
        let cond = make_binary(
            make_field_access(make_ident_expr("self"), "bogus"),
            BinOp::Gte,
            make_int_expr(0),
        );
        let method = make_fn("increment", vec![], vec![make_annotation("invariant", cond)], vec![]);
        let struct_decl = StructDecl {
            name: "Counter".to_string(),
            type_params: vec![],
            fields: vec![FieldDecl {
                name: "count".to_string(),
                ty: TypeExpr::new(TypeExprKind::Named("i32".to_string()), dummy_span()),
                default: None,
                span: dummy_span(),
            }],
            span: dummy_span(),
        };
        let impl_block = ImplBlock {
            trait_name: None,
            type_params: vec![],
            target: "Counter".to_string(),
            methods: vec![method],
            span: dummy_span(),
        };
        let program = make_program(vec![Item::Struct(struct_decl), Item::Impl(impl_block)]);
        let diags = run_pass(&program);
        assert_eq!(diags.error_count(), 1);
        assert!(diags.items[0].code == "E1303", "expected E1303, got {}", diags.items[0].code);
    }

    // ── @property tests ──────────────────────────────────────────────────

    #[test]
    fn property_with_i32_param_valid() {
        // @property on fn with i32 param -> no error (if body has assert)
        let assert_call = Expr {
            kind: ExprKind::Call {
                callee: Box::new(make_ident_expr("assert")),
                args: vec![CallArg {
                    name: None,
                    value: make_binary(make_ident_expr("x"), BinOp::Gte, make_int_expr(0)),
                    span: dummy_span(),
                }],
            },
            span: dummy_span(),
        };
        let body = vec![Stmt {
            kind: StmtKind::Expr { expr: assert_call },
            span: dummy_span(),
        }];
        let ann = Annotation {
            name: "property".to_string(),
            args: vec![],
            span: dummy_span(),
        };
        let f = make_fn("prop_test", vec![make_param("x", "i32")], vec![ann], body);
        let program = make_program(vec![Item::Fn(f)]);
        let diags = run_pass(&program);
        assert_eq!(diags.error_count(), 0, "expected no errors: {:?}", diags.items);
    }

    #[test]
    fn property_with_unsupported_type() {
        // @property on fn with Map<K,V> param -> E1306
        let ann = Annotation {
            name: "property".to_string(),
            args: vec![],
            span: dummy_span(),
        };
        let param = Param {
            name: "m".to_string(),
            default: None,
            ty: TypeExpr::new(
                TypeExprKind::Generic {
                    name: "Map".to_string(),
                    args: vec![
                        TypeExpr::new(TypeExprKind::Named("String".to_string()), dummy_span()),
                        TypeExpr::new(TypeExprKind::Named("i32".to_string()), dummy_span()),
                    ],
                },
                dummy_span(),
            ),
            span: dummy_span(),
        };
        let f = make_fn("prop_test", vec![param], vec![ann], vec![]);
        let program = make_program(vec![Item::Fn(f)]);
        let diags = run_pass(&program);
        // E1306 for unsupported type + W1300 for no assertions
        let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E1306").collect();
        assert_eq!(errors.len(), 1, "expected 1 E1306 error");
    }

    #[test]
    fn property_without_assertions_warning() {
        // @property fn with no assert -> W1300
        let ann = Annotation {
            name: "property".to_string(),
            args: vec![],
            span: dummy_span(),
        };
        let body = vec![Stmt {
            kind: StmtKind::Expr { expr: make_int_expr(42) },
            span: dummy_span(),
        }];
        let f = make_fn("prop_test", vec![make_param("x", "i32")], vec![ann], body);
        let program = make_program(vec![Item::Fn(f)]);
        let diags = run_pass(&program);
        assert_eq!(diags.error_count(), 0);
        let warnings: Vec<_> = diags.items.iter().filter(|d| d.code == "W1300").collect();
        assert_eq!(warnings.len(), 1, "expected W1300 warning");
    }
}
