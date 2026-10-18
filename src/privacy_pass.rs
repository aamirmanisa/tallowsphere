//! Privacy type flow analysis pass.
//!
//! Enforces Tallow's privacy invariants:
//!
//! **private types:**
//! - Cannot be passed to print/log without .redact() or .hash()
//! - Cannot be sent unencrypted
//! - Cannot be stored without retention limits
//!
//! **secret types:**
//! - All of the above, PLUS:
//! - Cannot be serialized (to disk, network, or database)
//! - Cannot appear in string interpolation
//! - Cannot be returned from public functions
//! - Zero-wiped from memory on scope exit (enforced at codegen)

use std::collections::HashMap;

use crate::ast::*;
use crate::error::{Diagnostic, Diagnostics};
use crate::typeck::{Type, TypeEnv};

// ── Privacy Pass ─────────────────────────────────────────────────────────────

pub struct PrivacyPass<'a> {
    program: &'a Program,
    env: &'a TypeEnv,
    pub diags: Diagnostics,
}

impl<'a> PrivacyPass<'a> {
    pub fn new(program: &'a Program, env: &'a TypeEnv) -> Self {
        Self {
            program,
            env,
            diags: Diagnostics::new(),
        }
    }

    /// Run the privacy pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        for item in &self.program.items {
            if let Item::Fn(f) = item {
                self.check_function(f);
            }
        }
        self.diags
    }

    fn check_function(&mut self, f: &FnDecl) {
        // Build local type environment from params
        let mut locals = HashMap::new();
        if let Some(sig) = self.env.functions.get(&f.name) {
            for (name, ty) in &sig.params {
                locals.insert(name.clone(), ty.clone());
            }
        }

        // Check each statement
        for stmt in &f.body.stmts {
            self.check_stmt(stmt, &mut locals);
        }

        // Cross-reference: if this is an @agent_task function returning a private type,
        // add a note pointing to agent_safety_pass for full info flow validation (E0618).
        if self.env.agent_functions.contains_key(&f.name) {
            if let Some(sig) = self.env.functions.get(&f.name) {
                if sig.return_type.is_private() || self.type_contains_private(&sig.return_type) {
                    self.diags.push(
                        Diagnostic::warning(
                            "W0210",
                            format!(
                                "agent function `{}` returns a private type -- see agent safety pass (E0618) for boundary validation",
                                f.name
                            ),
                            f.span,
                        ),
                    );
                }
            }
        }
    }

    /// Check if a type transitively contains a private type.
    fn type_contains_private(&self, ty: &Type) -> bool {
        match ty {
            Type::Private(_) => true,
            Type::Result(inner) | Type::Optional(inner) | Type::Array(inner) => {
                self.type_contains_private(inner)
            }
            Type::Tuple(types) => types.iter().any(|t| self.type_contains_private(t)),
            _ => false,
        }
    }

    fn check_stmt(&mut self, stmt: &Stmt, locals: &mut HashMap<String, Type>) {
        match &stmt.kind {
            StmtKind::Let { name, value, .. } | StmtKind::Var { name, value, .. } => {
                self.check_expr_privacy(value, locals);
                // Track the type of the new binding
                let ty = self.infer_type(value, locals);
                locals.insert(name.clone(), ty);
            }
            StmtKind::LetDestructure { names, value } => {
                self.check_expr_privacy(value, locals);
                for name in names {
                    locals.insert(name.clone(), Type::Unknown);
                }
            }
            StmtKind::Expr { expr } => {
                self.check_expr_privacy(expr, locals);
            }
            StmtKind::Return(Some(expr)) => {
                self.check_expr_privacy(expr, locals);
            }
            StmtKind::Return(None) => {}
            StmtKind::For {
                binding,
                iter,
                body,
            } => {
                self.check_expr_privacy(iter, locals);
                let mut inner = locals.clone();
                inner.insert(binding.clone(), Type::Unknown);
                for s in &body.stmts {
                    self.check_stmt(s, &mut inner);
                }
            }
            StmtKind::While { condition, body } => {
                self.check_expr_privacy(condition, locals);
                let mut inner = locals.clone();
                for s in &body.stmts {
                    self.check_stmt(s, &mut inner);
                }
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.check_expr_privacy(expr, locals);
                let mut inner = locals.clone();
                for s in &body.stmts {
                    self.check_stmt(s, &mut inner);
                }
            }
            StmtKind::Bail(expr) => {
                self.check_expr_privacy(expr, locals);
            }
            StmtKind::Loop { body } => {
                let mut inner = locals.clone();
                for s in &body.stmts {
                    self.check_stmt(s, &mut inner);
                }
            }
            StmtKind::Break | StmtKind::Continue => {}
            // `defer` runs its block on scope exit, so it is a sink site like
            // any other: a `print(secret)` in a deferred block still prints.
            StmtKind::Defer { body } => {
                let mut inner = locals.clone();
                for s in &body.stmts {
                    self.check_stmt(s, &mut inner);
                }
            }
        }
    }

    fn check_expr_privacy(&mut self, expr: &Expr, locals: &HashMap<String, Type>) {
        match &expr.kind {
            // ── Rule 1: print(private_value) without .redact()/.hash() ───
            ExprKind::Call { callee, args, .. } => {
                if let ExprKind::Ident(name) = &callee.kind {
                    if is_logging_function(name) {
                        for arg in args {
                            self.check_not_sensitive_raw(&arg.value, locals);
                        }
                    }
                }
                // Recurse
                for arg in args {
                    self.check_expr_privacy(&arg.value, locals);
                }
            }

            // Method calls — check for I/O sinks and logging, then recurse
            ExprKind::MethodCall {
                object,
                method,
                args,
                ..
            } => {
                // Don't flag the object of .redact()/.hash()/.mask() — that's the SAFE path
                // But DO check if this is a module-qualified I/O sink or logging function
                if let ExprKind::Ident(obj_name) = &object.kind {
                    // I/O sink check: secret/private data cannot be written to fs/http
                    if is_module_io_sink(obj_name, method) {
                        for arg in args {
                            self.check_not_sensitive_raw(&arg.value, locals);
                        }
                    }
                    // Module-qualified logging check (log.info, log.warn, etc.)
                    if is_module_logging(obj_name, method) {
                        for arg in args {
                            self.check_not_sensitive_raw(&arg.value, locals);
                        }
                    }
                }

                // Existing: recurse into object and args
                self.check_expr_privacy(object, locals);
                for arg in args {
                    self.check_expr_privacy(&arg.value, locals);
                }
            }

            // ── Rule 2: secret types cannot be in string interpolation ───
            // Enforced in the `ExprKind::Interpolation` arm below: each embedded
            // `{expr}` is checked like a print argument (E0200/E0201).

            // Recurse into sub-expressions
            ExprKind::Binary { left, right, .. } => {
                self.check_expr_privacy(left, locals);
                self.check_expr_privacy(right, locals);
            }
            ExprKind::Unary { operand, .. } => {
                self.check_expr_privacy(operand, locals);
            }
            ExprKind::If {
                condition,
                then_block,
                else_branch,
            } => {
                self.check_expr_privacy(condition, locals);
                let mut inner = locals.clone();
                for s in &then_block.stmts {
                    self.check_stmt(s, &mut inner);
                }
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(block) => {
                            let mut inner = locals.clone();
                            for s in &block.stmts {
                                self.check_stmt(s, &mut inner);
                            }
                        }
                        ElseBranch::ElseIf(expr) => {
                            self.check_expr_privacy(expr, locals);
                        }
                    }
                }
            }
            ExprKind::IfLet {
                expr,
                then_block,
                else_branch,
                ..
            } => {
                self.check_expr_privacy(expr, locals);
                let mut inner = locals.clone();
                for s in &then_block.stmts {
                    self.check_stmt(s, &mut inner);
                }
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(block) => {
                            let mut inner = locals.clone();
                            for s in &block.stmts {
                                self.check_stmt(s, &mut inner);
                            }
                        }
                        ElseBranch::ElseIf(expr) => {
                            self.check_expr_privacy(expr, locals);
                        }
                    }
                }
            }
            ExprKind::Match { subject, arms } => {
                self.check_expr_privacy(subject, locals);
                for arm in arms {
                    self.check_expr_privacy(&arm.body, locals);
                }
            }
            ExprKind::Block(block) => {
                let mut inner = locals.clone();
                for s in &block.stmts {
                    self.check_stmt(s, &mut inner);
                }
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) => {
                self.check_expr_privacy(inner, locals);
            }
            ExprKind::FieldAccess { object, .. } => {
                self.check_expr_privacy(object, locals);
            }
            ExprKind::Index { object, index } => {
                self.check_expr_privacy(object, locals);
                self.check_expr_privacy(index, locals);
            }
            ExprKind::Array(elements) => {
                for e in elements {
                    self.check_expr_privacy(e, locals);
                }
            }
            ExprKind::MapLit(entries) => {
                for (k, v) in entries {
                    self.check_expr_privacy(k, locals);
                    self.check_expr_privacy(v, locals);
                }
            }
            ExprKind::Assign { target, value } => {
                self.check_expr_privacy(target, locals);
                self.check_expr_privacy(value, locals);
            }
            ExprKind::Cast { expr, .. } => {
                self.check_expr_privacy(expr, locals);
            }
            ExprKind::StructLit { fields, spread, .. } => {
                for f in fields {
                    self.check_expr_privacy(&f.value, locals);
                }
                if let Some(s) = spread {
                    self.check_expr_privacy(s, locals);
                }
            }
            ExprKind::Interpolation(parts) => {
                for part in parts {
                    if let StringPart::Expr(e) = part {
                        // Interpolated expressions in strings are like print arguments —
                        // sensitive values must be redacted
                        self.check_not_sensitive_raw(e, locals);
                        self.check_expr_privacy(e, locals);
                    }
                }
            }
            ExprKind::Closure { body, .. } => {
                let mut inner = locals.clone();
                for s in body {
                    self.check_stmt(s, &mut inner);
                }
            }
            ExprKind::Bail(e) => {
                self.check_expr_privacy(e, locals);
            }
            // ── Concurrency (Phase 1) ────────────────────────────────────
            // A spawn evaluates its arguments on the spawning thread and then
            // runs them on another one — same data, so the scan must see both
            // the arguments (a spawned `print(secret)` prints) and any closure
            // body reached through `func`.
            ExprKind::Spawn { func, args } => {
                if let ExprKind::Ident(name) = &func.kind {
                    if is_logging_function(name) {
                        for arg in args {
                            self.check_not_sensitive_raw(arg, locals);
                        }
                    }
                }
                self.check_expr_privacy(func, locals);
                for arg in args {
                    self.check_expr_privacy(arg, locals);
                }
            }
            // `select` arm bodies and their channel operations are ordinary
            // code: an arm that prints a secret is the same violation it would
            // be outside the select.
            ExprKind::Select { cases, default } => {
                for case in cases {
                    match &case.op {
                        SelectOp::Recv(ch) => self.check_expr_privacy(ch, locals),
                        SelectOp::Send { ch, val } => {
                            self.check_expr_privacy(ch, locals);
                            self.check_expr_privacy(val, locals);
                        }
                    }
                    match &case.variable {
                        Some(variable) => {
                            let mut inner = locals.clone();
                            inner.insert(variable.clone(), Type::Unknown);
                            self.check_expr_privacy(&case.body, &inner);
                        }
                        None => self.check_expr_privacy(&case.body, locals),
                    }
                }
                if let Some(default) = default {
                    self.check_expr_privacy(default, locals);
                }
            }
            // Leaf nodes
            ExprKind::IntLit(_)
            | ExprKind::FloatLit(_)
            | ExprKind::StringLit(_)
            | ExprKind::BoolLit(_)
            | ExprKind::Nil
            | ExprKind::Ident(_)
            | ExprKind::DotIdent(_) => {}
        }
    }

    /// Check that an expression is not a raw sensitive value.
    /// It's OK if it's been transformed through .redact(), .hash(), or .mask().
    fn check_not_sensitive_raw(&mut self, expr: &Expr, locals: &HashMap<String, Type>) {
        match &expr.kind {
            // Direct identifier — check its type
            ExprKind::Ident(name) => {
                if let Some(ty) = locals.get(name) {
                    if ty.is_private() {
                        self.diags.push(
                            Diagnostic::error(
                                "E0200",
                                format!(
                                    "`{name}` is a private type and cannot be logged or printed directly"
                                ),
                                expr.span,
                            )
                            .with_help(
                                format!("use {name}.redact(), {name}.hash(), or {name}.mask() instead"),
                            ),
                        );
                    }
                    if ty.is_secret() {
                        self.diags.push(
                            Diagnostic::error(
                                "E0201",
                                format!(
                                    "`{name}` is a secret type and can NEVER be logged, printed, or serialized"
                                ),
                                expr.span,
                            )
                            .with_help(
                                "secret types cannot be exposed in any form — use .verify() for comparison",
                            ),
                        );
                    } else if !ty.is_private() {
                        // A container is not itself private/secret, but
                        // printing it prints what is inside (#49).
                        self.flag_sensitive_value(expr.span, ty, &format!("`{name}`"));
                    }
                }
            }
            // Method call — if it's .redact()/.hash()/.mask(), that's fine
            ExprKind::MethodCall { object, method, .. } => {
                if is_safe_transform(method) {
                    // This is the SAFE path — .redact(), .hash(), .mask() on a private type
                    // No violation.
                    return;
                }
                // Otherwise, check if the method returns a sensitive type
                let obj_ty = self.infer_type(object, locals);
                if obj_ty.is_secret() {
                    self.diags.push(
                        Diagnostic::error(
                            "E0201",
                            "secret type value cannot be logged or printed".to_string(),
                            expr.span,
                        )
                        .with_help("secret types cannot be exposed in any form"),
                    );
                } else if obj_ty.is_private() && !is_safe_transform(method) {
                    self.diags.push(
                        Diagnostic::error(
                            "E0200",
                            "private type value cannot be logged without redaction".to_string(),
                            expr.span,
                        )
                        .with_help("use .redact(), .hash(), or .mask()"),
                    );
                }
            }
            // Field access — the *field's* type is what gets printed, not the
            // receiver's. `print(session.token)` was previously judged by the
            // Session type (plain), so a secret field passed clean (#49).
            ExprKind::FieldAccess { field, .. } => {
                let field_ty = self.infer_type(expr, locals);
                self.flag_sensitive_value(
                    expr.span,
                    &field_ty,
                    &format!("`{field}`"),
                );
            }
            // Call as the printed value — the *result* carries the callee's
            // return type, so `print(fetch_email())` must be as illegal as
            // printing the Email it returns. Wrappers (`Result`, `Optional`,
            // arrays) are unwrapped: `print(find()?)` exposes the inner value.
            ExprKind::Call { callee, args, .. } => {
                let mut ret = self.infer_type(expr, locals);
                while let Type::Result(inner) | Type::Optional(inner) | Type::Array(inner) = ret {
                    ret = *inner;
                }
                let callee_name = match &callee.kind {
                    ExprKind::Ident(name) => format!("`{name}()`"),
                    _ => "this call".to_string(),
                };
                if ret.is_secret() {
                    self.diags.push(
                        Diagnostic::error(
                            "E0201",
                            format!(
                                "{callee_name} returns a secret type and can NEVER be logged, printed, or serialized"
                            ),
                            expr.span,
                        )
                        .with_help("secret types cannot be exposed in any form — use .verify() for comparison"),
                    );
                } else if ret.is_private() {
                    self.diags.push(
                        Diagnostic::error(
                            "E0200",
                            format!(
                                "{callee_name} returns a private type and cannot be logged or printed directly"
                            ),
                            expr.span,
                        )
                        .with_help("use .redact(), .hash(), or .mask() on the result"),
                    );
                }
                for arg in args {
                    self.check_not_sensitive_raw(&arg.value, locals);
                }
            }
            // `print(x?)` / `print(await x)` expose whatever the inner
            // expression evaluates to.
            ExprKind::Try(inner) | ExprKind::Await(inner) => {
                self.check_not_sensitive_raw(inner, locals);
            }
            // Projections and aggregates (register #49). The arms above cover
            // the shapes the pass could already type; these are the ones it now
            // can — an index into a collection, an array/map literal, a struct
            // literal — and computing their type is only useful if the sink
            // consults it. Containers are checked for *contained* secrets too:
            // `print(tokens)` prints every token in the list.
            ExprKind::Index { .. }
            | ExprKind::Array(_)
            | ExprKind::MapLit(_)
            | ExprKind::StructLit { .. } => {
                let ty = self.infer_type(expr, locals);
                self.flag_sensitive_value(expr.span, &ty, "this value");
            }
            // Everything else — not flagged at this level
            _ => {}
        }
    }

    /// Push E0200/E0201 for an expression whose inferred type is sensitive,
    /// including a container that merely holds one.
    fn flag_sensitive_value(&mut self, span: crate::lexer::Span, ty: &Type, what: &str) {
        let secret = matches!(ty, Type::Secret(_)) || type_contains(ty, true);
        let private = matches!(ty, Type::Private(_)) || type_contains(ty, false);
        if secret {
            self.diags.push(
                Diagnostic::error(
                    "E0201",
                    format!("{what} is (or contains) a secret type and can NEVER be logged, printed, or serialized"),
                    span,
                )
                .with_help("secret types cannot be exposed in any form — use .verify() for comparison"),
            );
        } else if private {
            self.diags.push(
                Diagnostic::error(
                    "E0200",
                    format!("{what} is (or contains) a private type and cannot be logged or printed directly"),
                    span,
                )
                .with_help("use .redact(), .hash(), or .mask() instead"),
            );
        }
    }

    /// Type inference for privacy checking.
    ///
    /// Register #49: this used to answer only for identifiers, calls and
    /// method calls, so a value arriving through a **field**, a **collection
    /// element** or an **alias of either** inferred as `Unknown` and reached a
    /// sink unflagged — a false negative in a security rule, the direction that
    /// matters. The arms below project the declared type through those shapes.
    ///
    /// Deliberately conservative where the answer is unknown: an unresolved
    /// receiver keeps its own sensitivity rather than decaying to `Unknown`,
    /// because losing taint is the failure mode that hides a leak.
    fn infer_type(&self, expr: &Expr, locals: &HashMap<String, Type>) -> Type {
        match &expr.kind {
            ExprKind::Ident(name) => locals.get(name).cloned().unwrap_or(Type::Unknown),
            ExprKind::MethodCall { object, method, .. } => {
                let obj_ty = self.infer_type(object, locals);
                if obj_ty.is_sensitive() && is_safe_transform(method) {
                    // .redact()/.hash()/.mask() returns a safe String
                    Type::String
                } else {
                    obj_ty
                }
            }
            // `user.token` — a projection, not an escape: the field's own
            // declared type is the answer, so a safe field of a struct that
            // also holds a secret stays safe, and a secret field stays flagged
            // wherever it is selected from.
            ExprKind::FieldAccess { object, field } => {
                let obj_ty = self.infer_type(object, locals);
                if let Type::Named(name) = strip_sensitivity(&obj_ty) {
                    if let Some(info) = self.env.structs.get(name) {
                        if let Some((_, field_ty)) =
                            info.fields.iter().find(|(f, _)| f == field)
                        {
                            return field_ty.clone();
                        }
                    }
                }
                if obj_ty.is_sensitive() {
                    obj_ty
                } else {
                    Type::Unknown
                }
            }
            // `tokens[0]` — element type of the container, re-wrapped when the
            // container itself is sensitive so `[secret]` cannot launder one
            // through an index.
            ExprKind::Index { object, .. } => {
                index_element_type(&self.infer_type(object, locals))
            }
            // `[a, b]` / `{k: v}` literals: the widest element sensitivity wins,
            // so `[token]` is an array of secrets and `[name]` stays plain.
            ExprKind::Array(items) => {
                let elem = widest_type(
                    items.iter().map(|item| self.infer_type(item, locals)),
                );
                Type::Array(Box::new(elem))
            }
            ExprKind::MapLit(entries) => {
                let key = widest_type(entries.iter().map(|(k, _)| self.infer_type(k, locals)));
                let value =
                    widest_type(entries.iter().map(|(_, v)| self.infer_type(v, locals)));
                Type::Map(Box::new(key), Box::new(value))
            }
            // `User { token: t }` — the literal's type is the struct name, and
            // the struct itself is as sensitive as its most sensitive field:
            // printing the aggregate prints the secret inside it.
            ExprKind::StructLit { name, fields, .. } => {
                let worst = widest_sensitivity(
                    fields.iter().map(|f| self.infer_type(&f.value, locals)),
                );
                wrap_sensitivity(Type::Named(name.clone()), worst)
            }
            ExprKind::Call { callee, .. } => {
                if let ExprKind::Ident(name) = &callee.kind {
                    if let Some(sig) = self.env.functions.get(name) {
                        return sig.return_type.clone();
                    }
                }
                Type::Unknown
            }
            ExprKind::Try(inner) => match self.infer_type(inner, locals) {
                Type::Result(t) => *t,
                other => other,
            },
            ExprKind::Await(inner) => self.infer_type(inner, locals),
            _ => Type::Unknown,
        }
    }
}

// ── Type projection helpers (#49) ────────────────────────────────────────────

/// Does this type wrap, or contain in a collection, a secret (when
/// `want_secret`) / private (otherwise) value?
fn type_contains(ty: &Type, want_secret: bool) -> bool {
    let hit = |t: &Type| {
        if want_secret {
            matches!(t, Type::Secret(_))
        } else {
            matches!(t, Type::Private(_))
        }
    };
    match ty {
        Type::Secret(inner) | Type::Private(inner) => {
            hit(ty) || type_contains(inner, want_secret)
        }
        Type::Array(inner) | Type::Set(inner) | Type::Chan(inner) | Type::Optional(inner)
        | Type::Result(inner) | Type::Consent(inner) | Type::Erasable(inner)
        | Type::Trusted(inner) | Type::Unverified(inner) | Type::Boxed(inner)
        | Type::Fresh(inner, _) => type_contains(inner, want_secret),
        Type::Map(key, value) => {
            type_contains(key, want_secret) || type_contains(value, want_secret)
        }
        Type::Tuple(items) => items.iter().any(|t| type_contains(t, want_secret)),
        _ => false,
    }
}

/// Strip `private`/`secret` so a projection can look at the shape underneath
/// without losing the wrapper for the caller.
fn strip_sensitivity(ty: &Type) -> &Type {
    match ty {
        Type::Private(inner) | Type::Secret(inner) => strip_sensitivity(inner),
        other => other,
    }
}

/// Sensitivity rank: 0 plain, 1 private, 2 secret (secret dominates).
fn sensitivity_rank(ty: &Type) -> u8 {
    match ty {
        Type::Secret(_) => 2,
        Type::Private(_) => 1,
        _ => 0,
    }
}

fn wrap_sensitivity(ty: Type, rank: u8) -> Type {
    match rank {
        2 => Type::Secret(Box::new(ty)),
        1 => Type::Private(Box::new(ty)),
        _ => ty,
    }
}

/// The most sensitive of the given types, keeping that type's shape.
fn widest_type(types: impl Iterator<Item = Type>) -> Type {
    let mut best = Type::Unknown;
    let mut best_rank = 0u8;
    for ty in types {
        let rank = sensitivity_rank(&ty);
        if rank >= best_rank && !matches!(ty, Type::Unknown) {
            best_rank = rank;
            best = ty;
        }
    }
    best
}

/// Only the rank of the most sensitive value, for struct literals where the
/// shape is the struct name and only the taint matters.
fn widest_sensitivity(types: impl Iterator<Item = Type>) -> u8 {
    types.map(|t| sensitivity_rank(&t)).max().unwrap_or(0)
}

/// Element type of a container, preserving the container's own sensitivity.
fn index_element_type(container: &Type) -> Type {
    let rank = sensitivity_rank(container);
    let element = match strip_sensitivity(container) {
        Type::Array(inner) | Type::Set(inner) | Type::Chan(inner) => (**inner).clone(),
        Type::Map(_, value) => (**value).clone(),
        Type::String => Type::Char,
        // Not a container we model: if it was sensitive, keep it sensitive
        // rather than answer `Unknown` and lose the taint.
        other => other.clone(),
    };
    if element.is_sensitive() {
        element
    } else {
        wrap_sensitivity(element, rank)
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Module-qualified functions that write data to external sinks.
/// Secret and private types must not be passed as arguments to these.
fn is_module_io_sink(module: &str, method: &str) -> bool {
    matches!(
        (module, method),
        ("fs", "write_file")
            | ("fs", "write")
            | ("fs", "append")
            | ("fs", "copy")
            | ("fs", "rename")
            | ("http", "post")
            | ("http", "put")
            | ("http", "delete")
            | ("net", "connect")
    )
}

/// Module-qualified logging functions.
/// Private types must use .redact()/.hash() before being passed here.
fn is_module_logging(module: &str, method: &str) -> bool {
    matches!(
        (module, method),
        ("log", "info") | ("log", "warn") | ("log", "error") | ("log", "debug") | ("log", "fatal")
    )
}

/// Functions that log/print output (where sensitive data must not appear raw).
fn is_logging_function(name: &str) -> bool {
    matches!(
        name,
        "print" | "println" | "log" | "debug" | "info" | "warn" | "error" | "fatal"
    )
}

/// Methods that safely transform sensitive data for output.
fn is_safe_transform(method: &str) -> bool {
    matches!(method, "redact" | "hash" | "mask" | "verify")
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;
    use crate::parser::Parser;
    use crate::typeck::TypeChecker;

    fn run_privacy_pass(source: &str) -> Diagnostics {
        let (tokens, _) = lexer::tokenize(source);
        let program = Parser::parse(tokens).unwrap();
        let (env, _) = TypeChecker::new(&program).check();
        PrivacyPass::new(&program, &env).check()
    }

    #[test]
    fn privacy_valid_redact() {
        let diags = run_privacy_pass("fn log_user(email: Email) { print(email.redact()) }");
        assert!(
            !diags.has_errors(),
            "expected no errors, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn privacy_valid_hash() {
        let diags = run_privacy_pass("fn log_user(email: Email) { print(email.hash()) }");
        assert!(!diags.has_errors());
    }

    #[test]
    fn privacy_valid_mask() {
        let diags = run_privacy_pass("fn log_user(email: Email) { print(email.mask()) }");
        assert!(!diags.has_errors());
    }

    #[test]
    fn privacy_invalid_raw_print() {
        let diags = run_privacy_pass("fn log_user(email: Email) { print(email) }");
        assert!(diags.has_errors());
        assert!(diags.items[0].code == "E0200");
    }

    #[test]
    fn secret_cannot_be_printed_at_all() {
        let diags = run_privacy_pass("fn show_password(password: Password) { print(password) }");
        assert!(diags.has_errors());
        assert!(diags.items[0].code == "E0201");
    }

    #[test]
    fn secret_cannot_use_redact() {
        // Even .redact() on a secret should still be blocked
        // (secrets can NEVER be exposed, even redacted)
        // Actually, this is a design choice. In the spec, .redact() IS allowed on private
        // but for secrets, even .verify() is the only safe operation.
        // For now, we allow .redact() on secrets as a safe transform.
        let diags = run_privacy_pass("fn log_secret(token: Token) { print(token.redact()) }");
        // This should pass because .redact() is a safe transform
        assert!(!diags.has_errors());
    }

    #[test]
    fn non_sensitive_type_ok() {
        let diags = run_privacy_pass("fn log_data(name: String) { print(name) }");
        assert!(!diags.has_errors());
    }

    // ── Call-result sensitivity (#49) ───────────────────────────────────────

    #[test]
    fn private_return_value_printed_directly_is_flagged() {
        let diags = run_privacy_pass(
            r#"
            fn fetch_email() -> Email { "a@b.c" }
            fn leak() { print(fetch_email()) }
        "#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "E0200"),
            "a call returning a private type must be flagged at the sink, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn secret_return_value_printed_directly_is_flagged() {
        let diags = run_privacy_pass(
            r#"
            fn fetch_token() -> Token { "tok" }
            fn leak() { print(fetch_token()) }
        "#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "E0201"),
            "a call returning a secret type must be flagged at the sink, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn redacted_call_result_is_allowed() {
        let diags = run_privacy_pass(
            r#"
            fn fetch_email() -> Email { "a@b.c" }
            fn ok() { print(fetch_email().redact()) }
        "#,
        );
        assert!(
            !diags.has_errors(),
            "redacting the result is the safe path, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn private_result_unwrapped_by_try_is_flagged() {
        let diags = run_privacy_pass(
            r#"
            fn find_email() -> Result<Email, String> { Ok("a@b.c") }
            fn leak() -> Result<Int, String> { print(find_email()?) 0 }
        "#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "E0200"),
            "the inner private value of a `?`-unwrapped call must be flagged, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn plain_return_value_printed_directly_is_allowed() {
        let diags = run_privacy_pass(
            r#"
            fn greeting() -> String { "hi" }
            fn ok() { print(greeting()) }
        "#,
        );
        assert!(
            !diags.has_errors(),
            "a plain return type must not be flagged, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn fixtures_privacy_valid() {
        let source = include_str!("../tests/fixtures/privacy_valid.tl");
        let diags = run_privacy_pass(source);
        assert!(
            !diags.has_errors(),
            "privacy_valid.tl should pass: {:?}",
            diags.items
        );
    }

    #[test]
    fn fixtures_privacy_invalid() {
        let source = include_str!("../tests/fixtures/privacy_invalid.tl");
        let diags = run_privacy_pass(source);
        assert!(diags.has_errors(), "privacy_invalid.tl should fail");
        assert!(diags.items[0].code == "E0200");
    }

    #[test]
    fn multiple_args_catches_sensitive() {
        let diags =
            run_privacy_pass(r#"fn log_stuff(email: Email, name: String) { print(name, email) }"#);
        assert!(diags.has_errors());
        // Should flag `email` but not `name`
        assert_eq!(diags.error_count(), 1);
    }

    // ── Additional privacy pass tests ─────────────────────────────────────

    #[test]
    fn privacy_verify_is_safe() {
        let diags =
            run_privacy_pass("fn check(password: Password) -> bool { password.verify(\"hash\") }");
        assert!(!diags.has_errors());
    }

    #[test]
    fn secret_raw_in_debug_blocked() {
        let diags = run_privacy_pass("fn log_key(key: APIKey) { debug(key) }");
        assert!(diags.has_errors());
        assert!(diags.items[0].code == "E0201");
    }

    #[test]
    fn secret_raw_in_warn_blocked() {
        let diags = run_privacy_pass("fn log_key(key: PrivateKey) { warn(key) }");
        assert!(diags.has_errors());
    }

    #[test]
    fn private_in_info_blocked() {
        let diags = run_privacy_pass("fn log_ip(ip: IPAddress) { info(ip) }");
        assert!(diags.has_errors());
        assert!(diags.items[0].code == "E0200");
    }

    #[test]
    fn private_in_error_log_blocked() {
        let diags = run_privacy_pass("fn log_phone(phone: Phone) { error(phone) }");
        assert!(diags.has_errors());
    }

    #[test]
    fn private_in_fatal_blocked() {
        let diags = run_privacy_pass("fn log_loc(loc: Location) { fatal(loc) }");
        assert!(diags.has_errors());
    }

    #[test]
    fn ssn_is_private() {
        let diags = run_privacy_pass("fn log_ssn(ssn: SSN) { print(ssn) }");
        assert!(diags.has_errors());
        assert!(diags.items[0].code == "E0200");
    }

    #[test]
    fn name_is_private() {
        let diags = run_privacy_pass("fn log_name(n: Name) { print(n) }");
        assert!(diags.has_errors());
    }

    #[test]
    fn multiple_private_args_multiple_errors() {
        let diags =
            run_privacy_pass(r#"fn log_all(email: Email, phone: Phone) { print(email, phone) }"#);
        assert!(diags.has_errors());
        assert_eq!(diags.error_count(), 2);
    }

    #[test]
    fn hash_on_all_private_types_ok() {
        let diags = run_privacy_pass(r#"fn log_hash(email: Email) { print(email.hash()) }"#);
        assert!(!diags.has_errors());
    }

    #[test]
    fn non_logging_function_with_private_ok() {
        // Calling a non-logging function with a private param should be fine
        let diags = run_privacy_pass(r#"fn process(email: Email) { do_something(email) }"#);
        assert!(!diags.has_errors());
    }

    // ── Edge case tests ─────────────────────────────────────────────────

    #[test]
    fn empty_program_no_errors() {
        let diags = run_privacy_pass("");
        assert!(!diags.has_errors());
    }

    #[test]
    fn non_private_params_in_print_ok() {
        let diags = run_privacy_pass(
            r#"fn display(count: i32, name: String) { print(count); print(name) }"#,
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn multiple_private_params_all_redacted_ok() {
        let diags = run_privacy_pass(
            r#"fn audit(email: Email, phone: Phone) { print(email.redact()); print(phone.redact()) }"#,
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn private_in_interpolation_blocked() {
        let diags = run_privacy_pass(r#"fn bad(email: Email) { let msg = "user: {email}" }"#);
        assert!(diags.has_errors());
    }

    #[test]
    fn secret_in_interpolation_blocked() {
        let diags = run_privacy_pass(r#"fn bad(token: Token) { let msg = "token: {token}" }"#);
        assert!(diags.has_errors());
    }

    #[test]
    fn rule2_interpolation_enforced_with_codes() {
        // Rule 2: secret in interpolation -> E0201 (never exposable).
        let diags = run_privacy_pass(r#"fn bad(pw: Password) { print("password is {pw}") }"#);
        assert!(diags.has_errors());
        assert_eq!(diags.items[0].code, "E0201");

        // Private in interpolation -> E0200.
        let diags = run_privacy_pass(r#"fn bad(email: Email) { print("email: {email}") }"#);
        assert!(diags.has_errors());
        assert_eq!(diags.items[0].code, "E0200");

        // .redact() on a private type restores the safe path.
        let diags = run_privacy_pass(r#"fn ok(email: Email) { print("email: {email.redact()}") }"#);
        assert!(
            !diags.has_errors(),
            "redacted interpolation should be safe: {:?}",
            diags.items
        );
    }

    #[test]
    fn secret_hash_is_allowed() {
        let diags = run_privacy_pass(r#"fn log_hash(apikey: APIKey) { print(apikey.hash()) }"#);
        assert!(!diags.has_errors());
    }

    #[test]
    fn location_is_private() {
        let diags = run_privacy_pass(r#"fn bad_log(loc: Location) { print(loc) }"#);
        assert!(diags.has_errors());
    }

    #[test]
    fn ip_address_is_private() {
        let diags = run_privacy_pass(r#"fn bad_log(ip: IPAddress) { print(ip) }"#);
        assert!(diags.has_errors());
    }

    #[test]
    fn password_is_secret() {
        let diags = run_privacy_pass(r#"fn bad_log(pw: Password) { print(pw) }"#);
        assert!(diags.has_errors());
    }

    #[test]
    fn private_key_is_secret() {
        let diags = run_privacy_pass(r#"fn bad_log(key: PrivateKey) { print(key) }"#);
        assert!(diags.has_errors());
    }

    #[test]
    fn multiple_functions_only_first_errors() {
        let diags = run_privacy_pass(
            r#"fn good(email: Email) { print(email.redact()) }
fn bad(email: Email) { print(email) }"#,
        );
        assert!(diags.has_errors());
        // Should have exactly 1 error (from the bad function)
        let error_count = diags
            .items
            .iter()
            .filter(|d| d.code.starts_with("E"))
            .count();
        assert!(error_count >= 1);
    }

    // ── Batch: additional privacy pass coverage ───────────────────────

    #[test]
    fn private_in_info_call_blocked() {
        let diags = run_privacy_pass(r#"fn bad(email: Email) { info(email) }"#);
        assert!(diags.has_errors());
    }

    #[test]
    fn private_in_warn_call_blocked() {
        let diags = run_privacy_pass(r#"fn bad(email: Email) { warn(email) }"#);
        assert!(diags.has_errors());
    }

    #[test]
    fn private_in_error_call_blocked() {
        let diags = run_privacy_pass(r#"fn bad(email: Email) { error(email) }"#);
        assert!(diags.has_errors());
    }

    #[test]
    fn private_in_debug_call_blocked() {
        let diags = run_privacy_pass(r#"fn bad(email: Email) { debug(email) }"#);
        assert!(diags.has_errors());
    }

    #[test]
    fn secret_in_fatal_call_blocked() {
        let diags = run_privacy_pass(r#"fn bad(token: Token) { fatal(token) }"#);
        assert!(diags.has_errors());
    }

    #[test]
    fn mask_on_private_type_ok() {
        let diags = run_privacy_pass(r#"fn log_masked(email: Email) { print(email.mask()) }"#);
        assert!(!diags.has_errors());
    }

    #[test]
    fn verify_on_secret_type_ok() {
        let diags = run_privacy_pass(r#"fn check(pw: Password) { pw.verify("stored_hash") }"#);
        assert!(!diags.has_errors());
    }

    #[test]
    fn private_in_println_blocked() {
        let diags = run_privacy_pass(r#"fn bad(name: Name) { println(name) }"#);
        assert!(diags.has_errors());
    }

    #[test]
    fn ssn_is_private_type() {
        let diags = run_privacy_pass(r#"fn bad(ssn: SSN) { print(ssn) }"#);
        assert!(diags.has_errors());
    }

    #[test]
    fn custom_private_alias_blocked() {
        let diags = run_privacy_pass(
            r#"type UserID = private String
fn bad(uid: UserID) { print(uid) }"#,
        );
        assert!(diags.has_errors());
    }

    // ── New coverage tests ──────────────────────────────────────────

    #[test]
    fn private_unsafe_method_in_print() {
        let diags = run_privacy_pass(r#"fn bad(email: Email) { print(email.to_upper()) }"#);
        assert!(
            diags.has_errors(),
            "unsafe method on private type should be blocked: {:?}",
            diags.items
        );
    }

    #[test]
    fn secret_unsafe_method_in_print() {
        let diags = run_privacy_pass(r#"fn bad(token: Token) { print(token.to_string()) }"#);
        assert!(
            diags.has_errors(),
            "unsafe method on secret type should be blocked: {:?}",
            diags.items
        );
    }

    #[test]
    fn private_redact_in_print_ok() {
        let diags = run_privacy_pass(r#"fn ok(email: Email) { print(email.redact()) }"#);
        assert!(
            !diags.has_errors(),
            "redact on private should be safe: {:?}",
            diags.items
        );
    }

    #[test]
    fn secret_hash_in_print_ok() {
        let diags = run_privacy_pass(r#"fn ok(token: Token) { print(token.hash()) }"#);
        assert!(
            !diags.has_errors(),
            "hash on secret should be safe: {:?}",
            diags.items
        );
    }

    #[test]
    fn private_mask_in_print_ok() {
        let diags = run_privacy_pass(r#"fn ok(email: Email) { print(email.mask()) }"#);
        assert!(
            !diags.has_errors(),
            "mask on private should be safe: {:?}",
            diags.items
        );
    }

    #[test]
    fn private_in_log_info_blocked() {
        let diags = run_privacy_pass(r#"fn bad(email: Email) { info(email) }"#);
        assert!(diags.has_errors());
    }

    #[test]
    fn private_in_log_warn_blocked() {
        let diags = run_privacy_pass(r#"fn bad(name: Name) { warn(name) }"#);
        assert!(diags.has_errors());
    }

    #[test]
    fn private_in_log_error_blocked() {
        let diags = run_privacy_pass(r#"fn bad(phone: Phone) { error(phone) }"#);
        assert!(diags.has_errors());
    }

    #[test]
    fn private_in_log_debug_blocked() {
        let diags = run_privacy_pass(r#"fn bad(email: Email) { debug(email) }"#);
        assert!(diags.has_errors());
    }

    #[test]
    fn non_private_string_in_print_ok() {
        let diags = run_privacy_pass(r#"fn ok(name: String) { print(name) }"#);
        assert!(
            !diags.has_errors(),
            "plain String should be fine: {:?}",
            diags.items
        );
    }

    #[test]
    fn multiple_private_args_all_blocked() {
        let diags = run_privacy_pass(r#"fn bad(a: Email, b: Name) { print(a) print(b) }"#);
        assert!(diags.error_count() >= 2, "both should be blocked");
    }

    #[test]
    fn secret_in_string_interpolation_caught() {
        let diags = run_privacy_pass(r#"fn bad(pw: Password) { print("password is {pw}") }"#);
        assert!(
            diags.has_errors(),
            "secret in interpolation should be blocked"
        );
    }

    #[test]
    fn private_in_string_interpolation_caught() {
        let diags = run_privacy_pass(r#"fn bad(email: Email) { print("email: {email}") }"#);
        assert!(
            diags.has_errors(),
            "private in interpolation should be blocked"
        );
    }

    #[test]
    fn deferred_print_of_a_secret_is_flagged() {
        let diags = run_privacy_pass(
            r#"
            fn f(password: Password) {
                defer {
                    print(password)
                }
            }
        "#,
        );
        assert!(
            diags.has_errors(),
            "a deferred print(secret) is still a print: {diags:?}"
        );
    }

    #[test]
    fn select_arm_print_of_a_secret_is_flagged() {
        let diags = run_privacy_pass(
            r#"
            fn f(password: Password) {
                let ch = sync.channel(10)
                select {
                    recv(ch) -> val {
                        print(password)
                    }
                }
            }
        "#,
        );
        assert!(
            diags.has_errors(),
            "a select arm that prints a secret must be flagged: {diags:?}"
        );
    }

    #[test]
    fn spawned_print_of_a_secret_is_flagged() {
        let diags = run_privacy_pass(
            r#"
            fn f(password: Password) {
                spawn print(password)
            }
        "#,
        );
        assert!(
            diags.has_errors(),
            "spawn print(secret) is the same sink on another thread: {diags:?}"
        );
    }
    // ── Fields, collections and aliases (#49) ──────────────────────────────

    #[test]
    fn secret_field_of_a_struct_is_flagged_at_the_sink() {
        let diags = run_privacy_pass(
            r#"
            struct Session { name: String, token: Token }
            fn leak(s: Session) { print(s.token) }
        "#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "E0201"),
            "a secret field must be flagged where it is printed, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn safe_field_of_a_struct_that_holds_a_secret_is_not_flagged() {
        // A projection is not an escape, but neither is the struct infectious:
        // reading `name` out of a Session does not print the token.
        let diags = run_privacy_pass(
            r#"
            struct Session { name: String, token: Token }
            fn ok(s: Session) { print(s.name) }
        "#,
        );
        assert!(
            !diags.has_errors(),
            "a declared-safe field must stay clean, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn struct_literal_holding_a_secret_is_flagged_when_printed_whole() {
        let diags = run_privacy_pass(
            r#"
            struct Session { name: String, token: Token }
            fn leak(t: Token) { let s = Session { name: "n", token: t }; print(s) }
        "#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "E0201"),
            "printing the aggregate prints the secret inside it, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn secret_element_of_an_array_is_flagged_through_the_index() {
        let diags = run_privacy_pass(
            r#"
            fn leak(t: Token) { let xs = [t]; print(xs[0]) }
        "#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "E0201"),
            "an indexed secret must not launder through a collection, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn printing_a_list_of_secrets_is_flagged() {
        let diags = run_privacy_pass(
            r#"
            fn leak(t: Token) { let xs = [t]; print(xs) }
        "#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "E0201"),
            "printing the list prints every secret in it, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn alias_of_a_secret_field_is_flagged() {
        let diags = run_privacy_pass(
            r#"
            struct Session { token: Token }
            fn leak(s: Session) { let t = s.token; print(t) }
        "#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "E0201"),
            "an alias must carry the field's sensitivity, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn plain_collection_and_field_stay_clean() {
        let diags = run_privacy_pass(
            r#"
            struct Session { name: String }
            fn ok(n: String, s: Session) { let xs = [n]; print(xs[0]); print(s.name) }
        "#,
        );
        assert!(
            !diags.has_errors(),
            "no secret involved, nothing may be flagged, got: {:?}",
            diags.items
        );
    }

}
