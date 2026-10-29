//! G10 — newtype erasure.
//!
//! A newtype is a *nominal* type: `newtype UserId = String` is not `String`, and
//! nothing converts between the two except the two spellings that are meant to
//! be explicit — the constructor `UserId(..)` and the unwrap `.inner`.
//!
//! That distinction is a compile-time one. At run time the value simply *is* the
//! wrapped value, which is what lets one lowering serve both execution planes
//! unchanged: this pass rewrites
//!
//! * `UserId(<expr>)` → `<expr>`, and
//! * `<newtype value>.inner` → `<newtype value>`
//!
//! before the program reaches the interpreter or the native backend. Doing it
//! once, in the front end, is the reason the two planes agree by construction
//! rather than by two engines happening to implement the same identity.
//!
//! It runs **after** type checking on purpose. The checker is what sees the
//! nominal type and refuses the implicit conversions; erasing first would erase
//! the evidence, and `UserId("x")` assigned to a `String` slot would type as
//! `String` and pass.
//!
//! What this pass will *not* do is guess. A `.inner` is erased only when the
//! receiver is statically known to be a newtype — a declared parameter, a
//! binding initialised from a constructor or annotated with a newtype, or a call
//! to a function whose return type is one. Anything else is left alone, which
//! fails loudly (`call to unknown function`) instead of silently changing
//! meaning.

use std::collections::HashMap;

use crate::ast::*;
use crate::typeck::{Type, TypeEnv};

/// Rewrite every newtype constructor call and `.inner` unwrap in `program`.
///
/// `env` is the type checker's environment: the newtype declarations and the
/// resolved function signatures are what make the rewrite type-directed without
/// re-implementing inference here.
pub fn lower(program: &mut Program, env: &TypeEnv) {
    let mut lowerer = Lowerer {
        env,
        known: HashMap::new(),
    };
    for item in &mut program.items {
        match item {
            Item::Fn(f) => lowerer.fn_decl(f),
            Item::Impl(block) => {
                for method in &mut block.methods {
                    lowerer.fn_decl(method);
                }
            }
            Item::Const(c) => lowerer.expr(&mut c.value),
            _ => {}
        }
    }
}

struct Lowerer<'a> {
    env: &'a TypeEnv,
    /// Local name → "holds a newtype value" for the function being walked.
    ///
    /// Only ever set from something the program states: a declared type or an
    /// initialiser that is itself unambiguous. An unknown local stays `false`,
    /// so `.inner` on it is not rewritten.
    known: HashMap<String, bool>,
}

impl Lowerer<'_> {
    fn is_newtype_name(&self, name: &str) -> bool {
        self.env.newtypes.contains_key(name)
    }

    /// Does this annotation name a newtype (directly or through an alias)?
    fn annotation_is_newtype(&self, ty: &TypeExpr) -> bool {
        let TypeExprKind::Named(name) = &ty.kind else {
            return false;
        };
        if self.is_newtype_name(name) {
            return true;
        }
        // `type Id = UserId` is transparent, and the alias table resolves to the
        // nominal type because name resolution consults newtypes first.
        matches!(self.env.type_aliases.get(name), Some(Type::Newtype { .. }))
    }

    /// Is this expression statically a newtype value?
    fn expr_is_newtype(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Ident(name) => self.known.get(name).copied().unwrap_or(false),
            ExprKind::Call { callee, .. } => match &callee.kind {
                ExprKind::Ident(name) => {
                    self.is_newtype_name(name)
                        || self
                            .env
                            .functions
                            .get(name)
                            .map(|sig| matches!(sig.return_type, Type::Newtype { .. }))
                            .unwrap_or(false)
                }
                _ => false,
            },
            _ => false,
        }
    }

    fn fn_decl(&mut self, f: &mut FnDecl) {
        self.known.clear();
        for param in &f.params {
            let is_newtype = self.annotation_is_newtype(&param.ty);
            self.known.insert(param.name.clone(), is_newtype);
        }
        self.block(&mut f.body);
    }

    fn block(&mut self, block: &mut Block) {
        for stmt in &mut block.stmts {
            self.stmt(stmt);
        }
    }

    /// Walk a block in a nested scope: bindings it introduces do not leak into
    /// the surrounding statements.
    fn scoped_block(&mut self, block: &mut Block) {
        let saved = self.known.clone();
        self.block(block);
        self.known = saved;
    }

    fn stmt(&mut self, stmt: &mut Stmt) {
        match &mut stmt.kind {
            StmtKind::Let { name, ty, value } | StmtKind::Var { name, ty, value } => {
                // Decide what the binding holds *before* the initialiser is
                // rewritten: `let id = UserId("x")` is a newtype, even though
                // the initialiser becomes `"x"` a moment later.
                let is_newtype = match ty {
                    Some(annotation) => self.annotation_is_newtype(annotation),
                    None => self.expr_is_newtype(value),
                };
                self.known.insert(name.clone(), is_newtype);
                self.expr(value);
            }
            StmtKind::LetDestructure { pattern, value } => {
                for name in pattern.bound_names() {
                    self.known.insert(name, false);
                }
                self.expr(value);
            }
            StmtKind::Expr { expr } => self.expr(expr),
            StmtKind::Return(Some(expr)) => self.expr(expr),
            StmtKind::Return(None) | StmtKind::Continue { .. } => {}
            StmtKind::For {
                pattern,
                iter,
                body,
                ..
            } => {
                self.expr(iter);
                let saved = self.known.clone();
                for name in pattern.bound_names() {
                    self.known.insert(name, false);
                }
                self.block(body);
                self.known = saved;
            }
            StmtKind::While {
                condition, body, ..
            } => {
                self.expr(condition);
                self.scoped_block(body);
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.expr(expr);
                self.scoped_block(body);
            }
            StmtKind::Bail(expr) => self.expr(expr),
            StmtKind::Break { value, .. } => {
                if let Some(value) = value {
                    self.expr(value);
                }
            }
            StmtKind::Loop { body, .. } | StmtKind::Defer { body } => self.scoped_block(body),
        }
    }

    fn expr(&mut self, expr: &mut Expr) {
        match &mut expr.kind {
            ExprKind::Call { callee, args } => {
                let is_constructor =
                    matches!(&callee.kind, ExprKind::Ident(name) if self.is_newtype_name(name));
                if is_constructor && args.len() == 1 {
                    // The constructor is the identity: the checker has already
                    // required exactly one target-typed argument, so the run-time
                    // value is that argument.
                    let arg = args.remove(0);
                    let mut inner = arg.value;
                    self.expr(&mut inner);
                    *expr = inner;
                    return;
                }
                for arg in args.iter_mut() {
                    self.expr(&mut arg.value);
                }
                self.expr(callee);
            }
            ExprKind::MethodCall { object, args, .. } => {
                self.expr(object);
                for arg in args.iter_mut() {
                    self.expr(&mut arg.value);
                }
            }
            ExprKind::FieldAccess { object, field } => {
                // Decide from the *unrewritten* receiver: `UserId("x").inner`
                // is a newtype value before the constructor below collapses.
                let unwrap = field == "inner" && self.expr_is_newtype(object);
                self.expr(object);
                if unwrap {
                    let receiver = std::mem::replace(
                        &mut **object,
                        Expr {
                            kind: ExprKind::Nil,
                            span: expr.span,
                        },
                    );
                    *expr = receiver;
                }
            }
            ExprKind::Index { object, index } => {
                self.expr(object);
                self.expr(index);
            }
            ExprKind::Binary { left, right, .. } => {
                self.expr(left);
                self.expr(right);
            }
            ExprKind::Unary { operand, .. } => self.expr(operand),
            ExprKind::If {
                condition,
                then_block,
                else_branch,
            } => {
                self.expr(condition);
                self.scoped_block(then_block);
                if let Some(branch) = else_branch {
                    self.else_branch(branch);
                }
            }
            ExprKind::IfLet {
                expr: scrutinee,
                then_block,
                else_branch,
                ..
            } => {
                self.expr(scrutinee);
                self.scoped_block(then_block);
                if let Some(branch) = else_branch {
                    self.else_branch(branch);
                }
            }
            ExprKind::Match { subject, arms } => {
                self.expr(subject);
                for arm in arms.iter_mut() {
                    let saved = self.known.clone();
                    self.expr(&mut arm.body);
                    self.known = saved;
                }
            }
            ExprKind::Block(block) => self.scoped_block(block),
            ExprKind::Loop { body, .. } => self.scoped_block(body),
            ExprKind::Array(elements) => {
                for element in elements {
                    self.expr(element);
                }
            }
            ExprKind::MapLit(entries) => {
                for (key, value) in entries {
                    self.expr(key);
                    self.expr(value);
                }
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) | ExprKind::Bail(inner) => {
                self.expr(inner)
            }
            ExprKind::Assign { target, value } => {
                // A reassignment can change what a local holds; follow it so a
                // later `.inner` is judged on the value actually stored.
                if let ExprKind::Ident(name) = &target.kind {
                    let is_newtype = self.expr_is_newtype(value);
                    self.known.insert(name.clone(), is_newtype);
                }
                self.expr(target);
                self.expr(value);
            }
            ExprKind::StructLit { fields, spread, .. } => {
                for field in fields.iter_mut() {
                    self.expr(&mut field.value);
                }
                if let Some(spread) = spread {
                    self.expr(spread);
                }
            }
            ExprKind::Cast { expr: inner, .. } => self.expr(inner),
            ExprKind::Interpolation(parts) => {
                for part in parts {
                    if let StringPart::Expr(inner) = part {
                        self.expr(inner);
                    }
                }
            }
            ExprKind::Closure { params, body } => {
                let saved = self.known.clone();
                for param in params.iter_mut() {
                    let is_newtype = param
                        .ty
                        .as_ref()
                        .map(|ty| self.annotation_is_newtype(ty))
                        .unwrap_or(false);
                    self.known.insert(param.name.clone(), is_newtype);
                }
                for stmt in body.iter_mut() {
                    self.stmt(stmt);
                }
                self.known = saved;
            }
            ExprKind::Spawn { func, args } => {
                self.expr(func);
                for arg in args.iter_mut() {
                    self.expr(arg);
                }
            }
            ExprKind::Select { cases, default } => {
                for case in cases.iter_mut() {
                    match &mut case.op {
                        SelectOp::Recv(ch) => self.expr(ch),
                        SelectOp::Send { ch, val } => {
                            self.expr(ch);
                            self.expr(val);
                        }
                    }
                    if let Some(variable) = &case.variable {
                        self.known.insert(variable.clone(), false);
                    }
                    self.expr(&mut case.body);
                }
                if let Some(default) = default {
                    self.expr(default);
                }
            }
            // Leaves and names: nothing to rewrite.
            ExprKind::IntLit(_)
            | ExprKind::FloatLit(_)
            | ExprKind::StringLit(_)
            | ExprKind::BoolLit(_)
            | ExprKind::Nil
            | ExprKind::Ident(_)
            | ExprKind::DotIdent(_) => {}
        }
    }

    fn else_branch(&mut self, branch: &mut ElseBranch) {
        match branch {
            ElseBranch::Block(block) => self.scoped_block(block),
            ElseBranch::ElseIf(expr) => self.expr(expr),
        }
    }
}
