//! Module visibility (G09) — `docs/spec/MODULE-VISIBILITY.md`.
//!
//! Tallow has one flat namespace per program: an import merges the imported
//! file's items into the importing program, and nothing afterwards remembers
//! which file a name came from. Visibility therefore has to be decided *at the
//! merge* — in import resolution — because it is the only phase that still
//! knows both files.
//!
//! Three rules, and nothing beyond them:
//!
//! | Marker | Visible to |
//! |---|---|
//! | none | only items declared in the same file |
//! | `pub` | every file that imports the module |
//! | `pub(crate)` | every file in the same package |
//!
//! A package is the directory tree rooted at the entry-point file's directory;
//! two files are in the same package when their canonical paths share that
//! root.
//!
//! ## What a merge keeps
//!
//! An item that is not visible to the importer is not merged **for the
//! importer**. It is still merged when the imported module's own visible items
//! use it — a `pub fn api()` must be able to call the private `helper()` beside
//! it, and after a flat merge there is no other way for that call to bind. So
//! the merged set is the visible items plus the transitive closure of the
//! invisible items *they* reference. Nothing outside that closure crosses the
//! boundary, and a reference to an invisible item from the importing file is
//! refused with E0153 before type checking ever runs.

use crate::ast::*;
use crate::lexer::Span;
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

/// Canonical directory the package is rooted at: the entry file's directory.
pub fn package_root(entry_file: &Path) -> PathBuf {
    let canon = entry_file
        .canonicalize()
        .unwrap_or_else(|_| entry_file.to_path_buf());
    canon
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn canonical(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// Is `file` inside the package rooted at `package_root`?
pub fn in_package(file: &Path, package_root: &Path) -> bool {
    canonical(file).starts_with(package_root)
}

/// Does a marker written on an item declared in `defined_in` reach `importer`?
///
/// `Private` reaches only the declaring file, which is never the importer (a
/// file does not import itself), so a private item never crosses a boundary.
pub fn reaches(
    visibility: Visibility,
    defined_in: &Path,
    importer: &Path,
    package_root: &Path,
) -> bool {
    match visibility {
        Visibility::Pub => true,
        // Both ends must be in the package: the marker says "every file in the
        // same package", and the package is the tree rooted at the entry
        // file's directory. The importer is normally inside it by
        // construction, but a file reached *from* outside is not — and a
        // `pub(crate)` item declared outside the package reaches nothing.
        Visibility::PubCrate => {
            in_package(defined_in, package_root) && in_package(importer, package_root)
        }
        Visibility::Private => canonical(defined_in) == canonical(importer),
    }
}

/// A path as a diagnostic should spell it: relative to `base` when it lives
/// under it, absolute otherwise. The spec's message is `` `helper` is private to
/// src/net.tl `` — a path a reader can open from the project root.
pub fn display_relative(path: &Path, base: &Path) -> String {
    let stripped = path.canonicalize().ok().and_then(|p| {
        base.canonicalize()
            .ok()
            .and_then(|b| p.strip_prefix(b).map(|r| r.to_path_buf()).ok())
    });
    match stripped {
        Some(relative) => relative.display().to_string(),
        None => path.display().to_string(),
    }
}

// ── References ───────────────────────────────────────────────────────────────

/// One identifier occurrence inside an item's body or signatures.
#[derive(Debug, Clone)]
pub struct IdentRef {
    pub name: String,
    pub span: Span,
}

/// Every identifier an item *mentions*: call targets, value names, type names,
/// struct-literal type names. Bound names (parameters, `let` bindings, pattern
/// names) are not references and are not returned.
///
/// The walk is deliberately over-approximate: an extra name only keeps an item
/// in the merge closure, while a missed one would let an invisible item bind by
/// accident — so every position that can spell a name is visited.
pub fn item_refs(item: &Item) -> Vec<IdentRef> {
    let mut out = Vec::new();
    match item {
        Item::Fn(f) => {
            for p in &f.params {
                type_refs(&p.ty, &mut out);
                if let Some(default) = &p.default {
                    expr_refs(default, &mut out);
                }
            }
            if let Some(ret) = &f.return_type {
                type_refs(ret, &mut out);
            }
            block_refs(&f.body, &mut out);
        }
        Item::Struct(s) => {
            for field in &s.fields {
                type_refs(&field.ty, &mut out);
                if let Some(default) = &field.default {
                    expr_refs(default, &mut out);
                }
            }
        }
        Item::Enum(e) => {
            for variant in &e.variants {
                for field in &variant.fields {
                    type_refs(&field.ty, &mut out);
                }
            }
        }
        Item::Impl(i) => {
            // The target type is a name this impl block leans on.
            out.push(IdentRef {
                name: i.target.clone(),
                span: i.span,
            });
            if let Some(trait_name) = &i.trait_name {
                out.push(IdentRef {
                    name: trait_name.clone(),
                    span: i.span,
                });
            }
            for method in &i.methods {
                for p in &method.params {
                    type_refs(&p.ty, &mut out);
                }
                if let Some(ret) = &method.return_type {
                    type_refs(ret, &mut out);
                }
                block_refs(&method.body, &mut out);
            }
        }
        Item::Trait(t) => {
            for method in &t.methods {
                for p in &method.params {
                    type_refs(&p.ty, &mut out);
                }
                if let Some(ret) = &method.return_type {
                    type_refs(ret, &mut out);
                }
                if let Some(body) = &method.body {
                    block_refs(body, &mut out);
                }
            }
        }
        Item::Const(c) => {
            if let Some(ty) = &c.ty {
                type_refs(ty, &mut out);
            }
            expr_refs(&c.value, &mut out);
        }
        Item::TypeAlias(t) => type_refs(&t.ty, &mut out),
        Item::Import(_) => {}
    }
    out
}

fn type_refs(ty: &TypeExpr, out: &mut Vec<IdentRef>) {
    match &ty.kind {
        TypeExprKind::Named(name) => out.push(IdentRef {
            name: name.clone(),
            span: ty.span,
        }),
        TypeExprKind::Generic { name, args } => {
            out.push(IdentRef {
                name: name.clone(),
                span: ty.span,
            });
            for arg in args {
                type_refs(arg, out);
            }
        }
        TypeExprKind::Slice(inner) | TypeExprKind::Optional(inner) => type_refs(inner, out),
        TypeExprKind::Boxed(inner) => type_refs(inner, out),
        TypeExprKind::Tuple(elems) => {
            for e in elems {
                type_refs(e, out);
            }
        }
        TypeExprKind::Function {
            params,
            return_type,
            ..
        } => {
            for p in params {
                type_refs(p, out);
            }
            type_refs(return_type, out);
        }
        TypeExprKind::ImplTrait(name) | TypeExprKind::DynTrait(name) => out.push(IdentRef {
            name: name.clone(),
            span: ty.span,
        }),
    }
}

fn block_refs(block: &Block, out: &mut Vec<IdentRef>) {
    stmts_refs(&block.stmts, out);
}

fn stmts_refs(stmts: &[Stmt], out: &mut Vec<IdentRef>) {
    for stmt in stmts {
        match &stmt.kind {
            StmtKind::Let { ty, value, .. } | StmtKind::Var { ty, value, .. } => {
                if let Some(ty) = ty {
                    type_refs(ty, out);
                }
                expr_refs(value, out);
            }
            StmtKind::LetDestructure { pattern, value } => {
                pattern_refs(pattern, out);
                expr_refs(value, out);
            }
            StmtKind::Expr { expr } => expr_refs(expr, out),
            StmtKind::Return(value) => {
                if let Some(v) = value {
                    expr_refs(v, out);
                }
            }
            StmtKind::For {
                pattern,
                iter,
                body,
                ..
            } => {
                pattern_refs(pattern, out);
                expr_refs(iter, out);
                block_refs(body, out);
            }
            StmtKind::While {
                condition, body, ..
            } => {
                expr_refs(condition, out);
                block_refs(body, out);
            }
            StmtKind::WhileLet {
                pattern,
                expr,
                body,
                ..
            } => {
                pattern_refs(pattern, out);
                expr_refs(expr, out);
                block_refs(body, out);
            }
            StmtKind::Bail(expr) => expr_refs(expr, out),
            StmtKind::Break { value, .. } => {
                if let Some(v) = value {
                    expr_refs(v, out);
                }
            }
            StmtKind::Continue { .. } => {}
            StmtKind::Loop { body, .. } => block_refs(body, out),
            StmtKind::Defer { body } => block_refs(body, out),
        }
    }
}

fn pattern_refs(pattern: &Pattern, out: &mut Vec<IdentRef>) {
    match pattern {
        Pattern::Literal(expr) => expr_refs(expr, out),
        // A bare name is a binding, not a reference.
        Pattern::Ident(_) | Pattern::Wildcard => {}
        Pattern::Variant { fields, .. } => {
            for field in fields {
                pattern_refs(&field.pattern, out);
            }
        }
        Pattern::Tuple(pats) => {
            for p in pats {
                pattern_refs(p, out);
            }
        }
        Pattern::Array { elems, rest } => {
            for p in elems {
                pattern_refs(p, out);
            }
            if let Some(rest) = rest {
                pattern_refs(rest, out);
            }
        }
    }
}

fn expr_refs(expr: &Expr, out: &mut Vec<IdentRef>) {
    match &expr.kind {
        ExprKind::IntLit(_)
        | ExprKind::FloatLit(_)
        | ExprKind::StringLit(_)
        | ExprKind::BoolLit(_)
        | ExprKind::Nil => {}
        ExprKind::Ident(name) => out.push(IdentRef {
            name: name.clone(),
            span: expr.span,
        }),
        ExprKind::DotIdent(name) => out.push(IdentRef {
            name: name.clone(),
            span: expr.span,
        }),
        ExprKind::Binary { left, right, .. } => {
            expr_refs(left, out);
            expr_refs(right, out);
        }
        ExprKind::Unary { operand, .. } => expr_refs(operand, out),
        ExprKind::Call { callee, args } => {
            expr_refs(callee, out);
            for arg in args {
                expr_refs(&arg.value, out);
            }
        }
        ExprKind::MethodCall { object, args, .. } => {
            expr_refs(object, out);
            for arg in args {
                expr_refs(&arg.value, out);
            }
        }
        ExprKind::FieldAccess { object, .. } => expr_refs(object, out),
        ExprKind::Index { object, index } => {
            expr_refs(object, out);
            expr_refs(index, out);
        }
        ExprKind::If {
            condition,
            then_block,
            else_branch,
        } => {
            expr_refs(condition, out);
            block_refs(then_block, out);
            if let Some(else_branch) = else_branch {
                match else_branch {
                    ElseBranch::Block(block) => block_refs(block, out),
                    ElseBranch::ElseIf(e) => expr_refs(e, out),
                }
            }
        }
        ExprKind::IfLet {
            pattern,
            expr,
            then_block,
            else_branch,
        } => {
            pattern_refs(pattern, out);
            expr_refs(expr, out);
            block_refs(then_block, out);
            if let Some(else_branch) = else_branch {
                match else_branch {
                    ElseBranch::Block(block) => block_refs(block, out),
                    ElseBranch::ElseIf(e) => expr_refs(e, out),
                }
            }
        }
        ExprKind::Match { subject, arms } => {
            expr_refs(subject, out);
            for arm in arms {
                pattern_refs(&arm.pattern, out);
                expr_refs(&arm.body, out);
            }
        }
        ExprKind::Block(block) => block_refs(block, out),
        ExprKind::Loop { body, .. } => block_refs(body, out),
        ExprKind::Array(elems) => {
            for e in elems {
                expr_refs(e, out);
            }
        }
        ExprKind::MapLit(entries) => {
            for (k, v) in entries {
                expr_refs(k, out);
                expr_refs(v, out);
            }
        }
        ExprKind::Try(inner) | ExprKind::Await(inner) => expr_refs(inner, out),
        ExprKind::Assign { target, value } => {
            expr_refs(target, out);
            expr_refs(value, out);
        }
        ExprKind::StructLit {
            name,
            fields,
            spread,
        } => {
            out.push(IdentRef {
                name: name.clone(),
                span: expr.span,
            });
            for field in fields {
                expr_refs(&field.value, out);
            }
            if let Some(spread) = spread {
                expr_refs(spread, out);
            }
        }
        ExprKind::Cast { expr, ty } => {
            expr_refs(expr, out);
            type_refs(ty, out);
        }
        ExprKind::Interpolation(parts) => {
            for part in parts {
                if let StringPart::Expr(e) = part {
                    expr_refs(e, out);
                }
            }
        }
        ExprKind::Closure { params, body } => {
            for p in params {
                if let Some(ty) = &p.ty {
                    type_refs(ty, out);
                }
            }
            // A closure body is a statement list, not a Block.
            stmts_refs(body, out);
        }
        ExprKind::Bail(inner) => expr_refs(inner, out),
        ExprKind::Spawn { func, args } => {
            expr_refs(func, out);
            for arg in args {
                expr_refs(arg, out);
            }
        }
        ExprKind::Select { cases, default } => {
            for case in cases {
                match &case.op {
                    SelectOp::Recv(e) => expr_refs(e, out),
                    SelectOp::Send { ch, val } => {
                        expr_refs(ch, out);
                        expr_refs(val, out);
                    }
                }
                expr_refs(&case.body, out);
            }
            if let Some(default) = default {
                expr_refs(default, out);
            }
        }
    }
}

// ── Selecting what an import merges ──────────────────────────────────────────

/// The items an import contributes, split by whether they reach the importer.
pub struct ImportSelection {
    /// Items to merge into the importing program: the visible ones, plus the
    /// invisible ones the visible ones use.
    pub merge: Vec<Item>,
    /// Names visible to the importer — a use of one of these is satisfied.
    pub visible_names: BTreeSet<String>,
    /// Names that did **not** cross the boundary, with the marker that stopped
    /// them. A reference to one of these from the importing file is E0153.
    pub hidden: Vec<(String, Visibility)>,
}

/// Split one imported file's items into what crosses the boundary and what does
/// not (see the module docs).
pub fn select_imported_items(
    items: Vec<Item>,
    importer: &Path,
    defined_in: &Path,
    package_root: &Path,
) -> ImportSelection {
    let mut visible: Vec<Item> = Vec::new();
    let mut hidden_items: Vec<Item> = Vec::new();
    let mut hidden: Vec<(String, Visibility)> = Vec::new();

    for item in items {
        // Import statements are resolved by the caller, which knows how to
        // follow them; they are not merged.
        if matches!(item, Item::Import(_)) {
            continue;
        }
        let visibility = item.visibility();
        // An impl block contributes no name of its own; it only adds methods to
        // a type. Dropping it would break the module's own methods, and keeping
        // it cannot leak a name, so it always travels with its file.
        let is_impl = matches!(item, Item::Impl(_));
        // `main` always travels: a `main` in an imported file is refused by
        // E0147 whether or not it is `pub`, and the refusal is emitted by a
        // later phase that has to see the item. Visibility does not change that
        // rule (`docs/spec/MODULE-VISIBILITY.md`).
        let is_imported_main = matches!(item, Item::Fn(_)) && item.name() == Some("main");
        if is_impl || is_imported_main || reaches(visibility, defined_in, importer, package_root) {
            visible.push(item);
        } else {
            if let Some(name) = item.name() {
                hidden.push((name.to_string(), visibility));
            }
            hidden_items.push(item);
        }
    }

    // Closure: an invisible item travels when a visible item of the same file
    // uses it, and so on transitively.
    let mut wanted: HashSet<String> = HashSet::new();
    for item in &visible {
        for r in item_refs(item) {
            wanted.insert(r.name);
        }
    }
    let mut progressed = true;
    while progressed {
        progressed = false;
        let mut still_hidden = Vec::new();
        for item in hidden_items {
            let travels = item
                .name()
                .map(|n| wanted.contains(n))
                .unwrap_or(false);
            if travels {
                for r in item_refs(&item) {
                    wanted.insert(r.name);
                }
                visible.push(item);
                progressed = true;
            } else {
                still_hidden.push(item);
            }
        }
        hidden_items = still_hidden;
    }

    let visible_names = visible.iter().filter_map(|i| i.name().map(str::to_string)).collect();
    ImportSelection {
        merge: visible,
        visible_names,
        hidden,
    }
}
