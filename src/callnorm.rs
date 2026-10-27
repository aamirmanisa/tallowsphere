//! G03 — named and default arguments, resolved at the front end.
//!
//! `fn connect(host: String, port: Int = 443, tls: Bool = true)` may be called
//! as `connect("example.test")`, `connect("example.test", tls: false)` or
//! `connect(host: "example.test", port: 8443)`. Both planes of the compiler
//! have to agree on what that means, and there is only one place where they
//! can: the AST they share.
//!
//! So this pass rewrites every *statically resolvable* call into a fully
//! positional one — named arguments reordered into declaration order, omitted
//! trailing defaults spliced in as the declared default expression. After it
//! runs, the interpreter and the compiled backend see an ordinary positional
//! call with exactly `params.len()` arguments, and neither needs a new rule.
//! That is deliberate: the parity requirement is satisfied by construction
//! rather than by two independent implementations that must be kept in step.
//!
//! # The default-evaluation rule (chosen, and relied on below)
//!
//! **A default is evaluated at call time, at the call site, in the caller's
//! scope, and a default expression may not reference any parameter of its own
//! function (E0124, reported at the declaration).**
//!
//! The second half is what makes the first half sound. Splicing a clone of the
//! default expression into the call site is only equivalent to "evaluate it in
//! the callee's scope" if the expression cannot read anything that exists in
//! the callee and not in the caller. A parameter of the same call is exactly
//! such a name — `fn f(a: Int, b: Int = a)` would mean two different things —
//! so that shape is refused at the declaration rather than given a meaning.
//! What remains is an expression over globals, constants and calls, all of
//! which denote the same thing at both sites, and which is re-evaluated on
//! every call because the cloned node sits inside the call expression.
//!
//! A caller local that shadows a global the default names is the one residual
//! difference, and it is stated rather than hidden: the rule above says the
//! caller's scope, so a shadowing local is picked up, by definition.
//!
//! # What is *not* normalised, and why
//!
//! * **Calls to `native` functions.** Their defaults are applied by the
//!   runtime dispatcher (see the R2-3 note on `ast::Param::default`), and their
//!   argument lists are dispatched by name in the interpreter
//!   (`interp.rs` matches `arg.name == "scheme"` for `crypto.*`, for one).
//!   Re-splicing a default there would move a rule the runtime already owns.
//!   The *shape* is still validated (unknown name, duplicate, named-then-
//!   positional), because those refusals are the same whichever side binds.
//! * **Method calls** (`obj.m(x: 1)`). A method's signature comes from an impl
//!   block or a native table, not from a free function, and the same native
//!   dispatch argument applies. Named arguments were already accepted there and
//!   still bind by name in the dispatcher that owns them.
//! * **Calls through a value** (`let g = connect; g(port: 1)`). The callee's
//!   signature is not statically known, so binding cannot be decided here. The
//!   call is left exactly as written — this pass never guesses an order.
//!
//! # Refusal codes
//!
//! | code | meaning |
//! |------|---------|
//! | E0121 | positional argument after a named one |
//! | E0122 | unknown argument name — the message lists the parameter names |
//! | E0123 | duplicate binding (positional and named, or named twice) |
//! | E0124 | a required parameter is unbound, or a default reads a parameter |

use crate::ast::*;
use crate::error::{Diagnostic, Diagnostics};
use std::collections::HashMap;

/// A declared function's parameter list, in the shape this pass needs.
#[derive(Debug, Clone)]
struct Shape {
    /// Parameter names, in declaration order.
    params: Vec<String>,
    /// Declared default for each parameter, `None` when it is required.
    defaults: Vec<Option<Expr>>,
    /// `native fn` — shape is validated, defaults are not spliced.
    native: bool,
}

/// Rewrite `program` in place and return the refusals.
///
/// Call it once, after imports are resolved (so an imported function's
/// defaults are known) and before type checking (so the checker, both passes
/// and both backends only ever see positional calls).
pub fn normalize(program: &mut Program) -> Diagnostics {
    let sigs = collect_shapes(program);
    let mut pass = Normalizer {
        sigs,
        diags: Diagnostics::new(),
    };
    pass.check_defaults(program);
    for item in &mut program.items {
        if let Item::Fn(f) = item {
            // A default expression is spliced at call sites, so it is normal
            // there too: `fn f(x: Int, y: Int = g(tls: false))`.
            pass.walk_block(&mut f.body);
        }
    }
    pass.diags
}

fn collect_shapes(program: &Program) -> HashMap<String, Shape> {
    let mut sigs = HashMap::new();
    for item in &program.items {
        if let Item::Fn(f) = item {
            // Two declarations of one name are a different rule's problem;
            // the first wins here and nothing downstream is made worse.
            sigs.entry(f.name.clone()).or_insert_with(|| Shape {
                params: f.params.iter().map(|p| p.name.clone()).collect(),
                defaults: f.params.iter().map(|p| p.default.clone()).collect(),
                native: f.is_native,
            });
        }
    }
    sigs
}

struct Normalizer {
    sigs: HashMap<String, Shape>,
    diags: Diagnostics,
}

impl Normalizer {
    /// Declaration-time rules about defaults.
    ///
    /// A default may not read a parameter of the same call, because the
    /// default is evaluated where the call is written and those names do not
    /// exist there (see the module docs). This is the rule that makes the
    /// splice sound, so it is checked once per declaration rather than left to
    /// surface as a confusing "undefined variable" at each call site.
    fn check_defaults(&mut self, program: &Program) {
        for item in &program.items {
            let Item::Fn(f) = item else { continue };
            let params: Vec<&str> = f.params.iter().map(|p| p.name.as_str()).collect();
            for param in &f.params {
                let Some(default) = &param.default else {
                    continue;
                };
                let mut idents = Vec::new();
                collect_idents(default, &mut idents);
                for (name, span) in idents {
                    if params.contains(&name.as_str()) {
                        self.diags.push(
                            Diagnostic::error(
                                "E0124",
                                format!(
                                    "the default for parameter `{}` of `{}` reads parameter `{name}`, which does not exist where the default is evaluated",
                                    param.name, f.name
                                ),
                                span,
                            )
                            .with_help(
                                "a default is evaluated at the call site, so it may only read globals, constants and calls; make the parameter required and pass it at each call instead",
                            ),
                        );
                        break;
                    }
                }
            }
        }
    }

    // ── The walk ──────────────────────────────────────────────────────────

    fn walk_block(&mut self, block: &mut Block) {
        for stmt in &mut block.stmts {
            self.walk_stmt(stmt);
        }
    }

    fn walk_stmt(&mut self, stmt: &mut Stmt) {
        match &mut stmt.kind {
            StmtKind::Let { value, .. }
            | StmtKind::Var { value, .. }
            | StmtKind::LetDestructure { value, .. }
            | StmtKind::Expr { expr: value }
            | StmtKind::Bail(value) => self.walk_expr(value),
            StmtKind::Return(Some(value)) => self.walk_expr(value),
            StmtKind::Return(None) => {}
            StmtKind::For { iter, body, .. } => {
                self.walk_expr(iter);
                self.walk_block(body);
            }
            StmtKind::While {
                condition, body, ..
            } => {
                self.walk_expr(condition);
                self.walk_block(body);
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.walk_expr(expr);
                self.walk_block(body);
            }
            StmtKind::Break { value, .. } => {
                if let Some(v) = value {
                    self.walk_expr(v);
                }
            }
            StmtKind::Continue { .. } => {}
            StmtKind::Loop { body, .. } | StmtKind::Defer { body } => self.walk_block(body),
        }
    }

    fn walk_expr(&mut self, expr: &mut Expr) {
        match &mut expr.kind {
            ExprKind::IntLit(_)
            | ExprKind::FloatLit(_)
            | ExprKind::StringLit(_)
            | ExprKind::BoolLit(_)
            | ExprKind::Nil
            | ExprKind::Ident(_)
            | ExprKind::DotIdent(_) => {}

            ExprKind::Binary { left, right, .. } => {
                self.walk_expr(left);
                self.walk_expr(right);
            }
            ExprKind::Unary { operand, .. } => self.walk_expr(operand),

            ExprKind::Call { callee, args } => {
                // Resolve the callee before rewriting: `ExprKind::Ident` is the
                // only shape carrying a statically known signature here.
                if let ExprKind::Ident(name) = &callee.kind {
                    let name = name.clone();
                    let span = expr.span;
                    if let Some(shape) = self.sigs.get(&name).cloned() {
                        self.rewrite(&name, &shape, args, span);
                    }
                }
                self.walk_expr(callee);
                for arg in args.iter_mut() {
                    self.walk_expr(&mut arg.value);
                }
            }
            ExprKind::MethodCall { object, args, .. } => {
                self.walk_expr(object);
                for arg in args.iter_mut() {
                    self.walk_expr(&mut arg.value);
                }
            }
            ExprKind::FieldAccess { object, .. } => self.walk_expr(object),
            ExprKind::Index { object, index } => {
                self.walk_expr(object);
                self.walk_expr(index);
            }
            ExprKind::If {
                condition,
                then_block,
                else_branch,
            } => {
                self.walk_expr(condition);
                self.walk_block(then_block);
                if let Some(else_branch) = else_branch {
                    match else_branch {
                        ElseBranch::Block(b) => self.walk_block(b),
                        ElseBranch::ElseIf(e) => self.walk_expr(e),
                    }
                }
            }
            ExprKind::IfLet {
                expr: scrutinee,
                then_block,
                else_branch,
                ..
            } => {
                self.walk_expr(scrutinee);
                self.walk_block(then_block);
                if let Some(else_branch) = else_branch {
                    match else_branch {
                        ElseBranch::Block(b) => self.walk_block(b),
                        ElseBranch::ElseIf(e) => self.walk_expr(e),
                    }
                }
            }
            ExprKind::Match { subject, arms } => {
                self.walk_expr(subject);
                for arm in arms {
                    // A pattern literal is an expression node too, but it holds
                    // no call: literals are the only pattern payload.
                    self.walk_expr(&mut arm.body);
                }
            }
            ExprKind::Block(b) => self.walk_block(b),
            ExprKind::Loop { body, .. } => self.walk_block(body),
            ExprKind::Array(elements) => {
                for element in elements {
                    self.walk_expr(element);
                }
            }
            ExprKind::MapLit(entries) => {
                for (key, value) in entries {
                    self.walk_expr(key);
                    self.walk_expr(value);
                }
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) | ExprKind::Bail(inner) => {
                self.walk_expr(inner)
            }
            ExprKind::Assign { target, value } => {
                self.walk_expr(target);
                self.walk_expr(value);
            }
            ExprKind::StructLit { fields, spread, .. } => {
                for field in fields {
                    self.walk_expr(&mut field.value);
                }
                if let Some(spread) = spread {
                    self.walk_expr(spread);
                }
            }
            ExprKind::Cast { expr: inner, .. } => self.walk_expr(inner),
            ExprKind::Interpolation(parts) => {
                for part in parts {
                    if let StringPart::Expr(e) = part {
                        self.walk_expr(e);
                    }
                }
            }
            ExprKind::Closure { body, .. } => {
                for stmt in body {
                    self.walk_stmt(stmt);
                }
            }
            ExprKind::Spawn { func, args } => {
                self.walk_expr(func);
                for arg in args {
                    self.walk_expr(arg);
                }
            }
            ExprKind::Select { cases, default } => {
                for case in cases {
                    match &mut case.op {
                        SelectOp::Recv(ch) => self.walk_expr(ch),
                        SelectOp::Send { ch, val } => {
                            self.walk_expr(ch);
                            self.walk_expr(val);
                        }
                    }
                    self.walk_expr(&mut case.body);
                }
                if let Some(default) = default {
                    self.walk_expr(default);
                }
            }
        }
    }

    /// Bind one call's arguments to its declared parameters.
    ///
    /// On any refusal the call is left exactly as written: a half-rewritten
    /// call would be a second, wrong program.
    fn rewrite(&mut self, name: &str, shape: &Shape, args: &mut Vec<CallArg>, span: Span) {
        if args.is_empty() && shape.defaults.iter().all(|d| d.is_none()) {
            return;
        }
        let mut failed = false;

        // Rule 1: positional arguments may precede named ones, never follow
        // them. Reported against the offending argument, not the call.
        let mut named_seen = false;
        for arg in args.iter() {
            match (&arg.name, named_seen) {
                (Some(_), _) => named_seen = true,
                (None, true) => {
                    failed = true;
                    self.diags.push(
                        Diagnostic::error(
                            "E0121",
                            format!(
                                "positional argument after a named argument in call to `{name}`"
                            ),
                            arg.span,
                        )
                        .with_help(
                            "named arguments close the list: name this one too, or move the positional arguments before the named ones",
                        ),
                    );
                }
                (None, false) => {}
            }
        }

        // Rule 2 and 3: bind every argument to exactly one parameter.
        let mut slots: Vec<Option<Expr>> = vec![None; shape.params.len()];
        let mut bound_by: Vec<Option<String>> = vec![None; shape.params.len()];
        for (index, arg) in args.iter().enumerate() {
            let slot = match &arg.name {
                Some(arg_name) => match shape.params.iter().position(|p| p == arg_name) {
                    Some(slot) => slot,
                    None => {
                        failed = true;
                        self.diags.push(
                            Diagnostic::error(
                                "E0122",
                                format!(
                                    "unknown argument name `{arg_name}` in call to `{name}`; parameters are {}",
                                    param_list(&shape.params)
                                ),
                                arg.span,
                            )
                            .with_help(if shape.params.is_empty() {
                                format!("`{name}` takes no arguments")
                            } else {
                                format!("spell one of: {}", shape.params.join(", "))
                            }),
                        );
                        continue;
                    }
                },
                None => index,
            };
            if slot >= shape.params.len() {
                // Too many positional arguments: the type checker's arity
                // rule (E0103) owns that message, and it has the declaration.
                failed = true;
                continue;
            }
            if slots[slot].is_some() {
                failed = true;
                let how = match &arg.name {
                    Some(arg_name) => format!("named `{arg_name}`"),
                    None => format!("positional argument #{}", index + 1),
                };
                self.diags.push(
                    Diagnostic::error(
                        "E0123",
                        format!(
                            "parameter `{}` of `{name}` is bound twice: {} and {}",
                            shape.params[slot],
                            bound_by[slot].as_deref().unwrap_or("an earlier argument"),
                            how
                        ),
                        arg.span,
                    )
                    .with_help("each parameter takes exactly one argument; drop one of the two"),
                );
                continue;
            }
            slots[slot] = Some(arg.value.clone());
            bound_by[slot] = Some(match &arg.name {
                Some(arg_name) => format!("named `{arg_name}`"),
                None => format!("positional argument #{}", index + 1),
            });
        }

        // Rule 4, second half: fill the holes a call is allowed to leave.
        // Splicing is skipped for `native fn` — the runtime owns that rule.
        let mut missing = Vec::new();
        for (slot, param) in shape.params.iter().enumerate() {
            if slots[slot].is_some() {
                continue;
            }
            match &shape.defaults[slot] {
                Some(default) if !shape.native => {
                    slots[slot] = Some(default.clone());
                    bound_by[slot] = Some("its declared default".to_string());
                }
                Some(_) => {
                    // Native default: leave the hole for the dispatcher.
                    return;
                }
                None => missing.push(param.clone()),
            }
        }
        if !missing.is_empty() {
            failed = true;
            // Only worth its own message when the call named something: a
            // plain short call is E0103's shape, and it says more.
            if args.iter().any(|a| a.name.is_some()) {
                self.diags.push(
                    Diagnostic::error(
                        "E0124",
                        format!(
                            "call to `{name}` leaves required parameter{} {} unbound",
                            if missing.len() == 1 { "" } else { "s" },
                            missing
                                .iter()
                                .map(|m| format!("`{m}`"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        span,
                    )
                    .with_help(format!(
                        "`{name}` takes {}{}",
                        param_list(&shape.params),
                        default_note(&shape)
                    )),
                );
            }
        }

        if failed {
            return;
        }

        // Rebuild in declaration order. Spans are kept from whatever supplied
        // the value, so a diagnostic about an argument still points at the
        // text the programmer wrote (or at the default, for a default).
        let rebuilt: Vec<CallArg> = slots
            .into_iter()
            .enumerate()
            .map(|(slot, value)| {
                let value = value.expect("every slot is bound when no rule failed");
                let span = value.span;
                CallArg {
                    name: None,
                    value,
                    span,
                }
            })
            .collect();
        *args = rebuilt;
    }
}

/// `a`, `a,b`, `a, b and c` — the parameter names as the source spells them.
fn param_list(params: &[String]) -> String {
    match params {
        [] => "none".to_string(),
        [one] => format!("`{one}`"),
        _ => params
            .iter()
            .map(|p| format!("`{p}`"))
            .collect::<Vec<_>>()
            .join(", "),
    }
}

fn default_note(shape: &Shape) -> String {
    let defaulted: Vec<&String> = shape
        .params
        .iter()
        .zip(shape.defaults.iter())
        .filter(|(_, d)| d.is_some())
        .map(|(p, _)| p)
        .collect();
    if defaulted.is_empty() {
        String::new()
    } else {
        format!(
            "; {} {} a default",
            defaulted
                .iter()
                .map(|p| format!("`{p}`"))
                .collect::<Vec<_>>()
                .join(", "),
            if defaulted.len() == 1 { "has" } else { "have" }
        )
    }
}

/// Every identifier mentioned in an expression, with the span it was written at.
///
/// Deliberately syntactic: the point is "does this text name a parameter?", and
/// that question is answered by the text.
fn collect_idents(expr: &Expr, out: &mut Vec<(String, Span)>) {
    match &expr.kind {
        ExprKind::Ident(name) => out.push((name.clone(), expr.span)),
        ExprKind::Binary { left, right, .. } => {
            collect_idents(left, out);
            collect_idents(right, out);
        }
        ExprKind::Unary { operand, .. } => collect_idents(operand, out),
        ExprKind::Call { callee, args } => {
            collect_idents(callee, out);
            for arg in args {
                collect_idents(&arg.value, out);
            }
        }
        ExprKind::MethodCall { object, args, .. } => {
            collect_idents(object, out);
            for arg in args {
                collect_idents(&arg.value, out);
            }
        }
        ExprKind::FieldAccess { object, .. } => collect_idents(object, out),
        ExprKind::Index { object, index } => {
            collect_idents(object, out);
            collect_idents(index, out);
        }
        ExprKind::If {
            condition,
            then_block,
            else_branch,
        } => {
            collect_idents(condition, out);
            collect_idents_in_block(then_block, out);
            if let Some(ElseBranch::ElseIf(e)) = else_branch {
                collect_idents(e, out);
            } else if let Some(ElseBranch::Block(b)) = else_branch {
                collect_idents_in_block(b, out);
            }
        }
        ExprKind::Block(b) => collect_idents_in_block(b, out),
        ExprKind::Array(elements) => {
            for e in elements {
                collect_idents(e, out);
            }
        }
        ExprKind::MapLit(entries) => {
            for (k, v) in entries {
                collect_idents(k, out);
                collect_idents(v, out);
            }
        }
        ExprKind::Try(inner) | ExprKind::Await(inner) | ExprKind::Bail(inner) => {
            collect_idents(inner, out)
        }
        ExprKind::Assign { target, value } => {
            collect_idents(target, out);
            collect_idents(value, out);
        }
        ExprKind::StructLit { fields, spread, .. } => {
            for f in fields {
                collect_idents(&f.value, out);
            }
            if let Some(s) = spread {
                collect_idents(s, out);
            }
        }
        ExprKind::Cast { expr, .. } => collect_idents(expr, out),
        ExprKind::Interpolation(parts) => {
            for part in parts {
                if let StringPart::Expr(e) = part {
                    collect_idents(e, out);
                }
            }
        }
        ExprKind::Match { subject, arms } => {
            collect_idents(subject, out);
            for arm in arms {
                collect_idents(&arm.body, out);
            }
        }
        ExprKind::Closure { body, .. } => {
            for stmt in body {
                collect_idents_in_stmt(stmt, out);
            }
        }
        ExprKind::Loop { body, .. } => collect_idents_in_block(body, out),
        ExprKind::IfLet {
            expr, then_block, ..
        } => {
            collect_idents(expr, out);
            collect_idents_in_block(then_block, out);
        }
        ExprKind::Spawn { func, args } => {
            collect_idents(func, out);
            for a in args {
                collect_idents(a, out);
            }
        }
        ExprKind::Select { cases, .. } => {
            for case in cases {
                collect_idents(&case.body, out);
            }
        }
        _ => {}
    }
}

fn collect_idents_in_block(block: &Block, out: &mut Vec<(String, Span)>) {
    for stmt in &block.stmts {
        collect_idents_in_stmt(stmt, out);
    }
}

fn collect_idents_in_stmt(stmt: &Stmt, out: &mut Vec<(String, Span)>) {
    match &stmt.kind {
        StmtKind::Let { value, .. }
        | StmtKind::Var { value, .. }
        | StmtKind::LetDestructure { value, .. }
        | StmtKind::Expr { expr: value }
        | StmtKind::Bail(value) => collect_idents(value, out),
        StmtKind::Return(Some(v)) => collect_idents(v, out),
        StmtKind::For { iter, body, .. } => {
            collect_idents(iter, out);
            collect_idents_in_block(body, out);
        }
        StmtKind::While {
            condition, body, ..
        } => {
            collect_idents(condition, out);
            collect_idents_in_block(body, out);
        }
        StmtKind::WhileLet { expr, body, .. } => {
            collect_idents(expr, out);
            collect_idents_in_block(body, out);
        }
        StmtKind::Loop { body, .. } | StmtKind::Defer { body } => {
            collect_idents_in_block(body, out)
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;
    use crate::parser::Parser;

    fn parse(source: &str) -> Program {
        let (tokens, lex_errors) = lexer::tokenize(source);
        assert!(lex_errors.is_empty(), "lex errors: {lex_errors:?}");
        Parser::parse(tokens).expect("parse")
    }

    fn normalize_src(source: &str) -> (Program, Diagnostics) {
        let mut program = parse(source);
        let diags = normalize(&mut program);
        (program, diags)
    }

    fn fn_body<'a>(program: &'a Program, name: &str) -> &'a Block {
        for item in &program.items {
            if let Item::Fn(f) = item {
                if f.name == name {
                    return &f.body;
                }
            }
        }
        panic!("no function `{name}`");
    }

    /// The first `Call` reachable from an expression, in evaluation order.
    fn first_call(expr: &Expr) -> Option<&Vec<CallArg>> {
        if let ExprKind::Call { args, .. } = &expr.kind {
            Some(args)
        } else {
            None
        }
    }

    fn call_args_of(program: &Program, name: &str) -> Vec<CallArg> {
        let body = fn_body(program, name);
        for stmt in &body.stmts {
            let value = match &stmt.kind {
                StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => value,
                StmtKind::Expr { expr } => expr,
                StmtKind::Return(Some(value)) => value,
                _ => continue,
            };
            if let Some(args) = first_call(value) {
                return args.clone();
            }
            // `connect("x")` written as a direct call statement lands here.
            if let ExprKind::Call { args, .. } = &value.kind {
                return args.clone();
            }
        }
        panic!("no call in `{name}`");
    }

    fn codes(diags: &Diagnostics) -> Vec<&'static str> {
        diags.items.iter().map(|d| d.code).collect()
    }

    const CONNECT: &str = "fn connect(host: String, port: Int = 443, tls: Bool = true) -> Int {
        return port;
    }
    ";

    #[test]
    fn defaults_are_spliced_at_the_call_site() {
        let (program, diags) = normalize_src(&format!(
            "{CONNECT}\nfn main() {{ let p = connect(\"example.test\"); }}"
        ));
        assert!(diags.items.is_empty(), "{:?}", diags.items);
        let args = call_args_of(&program, "main");
        assert_eq!(
            args.len(),
            3,
            "every parameter is bound after normalisation"
        );
        assert!(args.iter().all(|a| a.name.is_none()), "no names survive");
        assert!(matches!(args[0].value.kind, ExprKind::StringLit(_)));
        assert!(matches!(args[1].value.kind, ExprKind::IntLit(443)));
        assert!(matches!(args[2].value.kind, ExprKind::BoolLit(true)));
    }

    #[test]
    fn named_argument_binds_by_name_not_position() {
        // `tls: false` is the third parameter; it must land in slot 3, with the
        // defaulted `port` in slot 2.
        let (program, diags) = normalize_src(&format!(
            "{CONNECT}\nfn main() {{ let p = connect(\"example.test\", tls: false); }}"
        ));
        assert!(diags.items.is_empty(), "{:?}", diags.items);
        let args = call_args_of(&program, "main");
        assert_eq!(args.len(), 3);
        assert!(matches!(args[1].value.kind, ExprKind::IntLit(443)));
        assert!(matches!(args[2].value.kind, ExprKind::BoolLit(false)));
    }

    #[test]
    fn named_arguments_may_be_written_out_of_order() {
        let (program, diags) = normalize_src(&format!(
            "{CONNECT}\nfn main() {{ let p = connect(tls: false, host: \"h\"); }}"
        ));
        assert!(diags.items.is_empty(), "{:?}", diags.items);
        let args = call_args_of(&program, "main");
        assert!(matches!(args[0].value.kind, ExprKind::StringLit(_)));
        assert!(matches!(args[1].value.kind, ExprKind::IntLit(443)));
        assert!(matches!(args[2].value.kind, ExprKind::BoolLit(false)));
    }

    #[test]
    fn positional_after_named_is_refused() {
        let (_program, diags) = normalize_src(&format!(
            "{CONNECT}\nfn main() {{ let p = connect(tls: false, \"example.test\"); }}"
        ));
        let refusal = diags
            .items
            .iter()
            .find(|d| d.code == "E0121")
            .unwrap_or_else(|| panic!("expected E0121, got {:?}", codes(&diags)));
        assert!(refusal.msg.contains("connect"), "{}", refusal.msg);
    }

    #[test]
    fn unknown_argument_name_lists_the_parameters() {
        let (_program, diags) = normalize_src(&format!(
            "{CONNECT}\nfn main() {{ let p = connect(\"h\", prot: 1); }}"
        ));
        let refusal = diags
            .items
            .iter()
            .find(|d| d.code == "E0122")
            .unwrap_or_else(|| panic!("expected E0122, got {:?}", codes(&diags)));
        for name in ["host", "port", "tls"] {
            assert!(
                refusal.msg.contains(name),
                "the refusal must list parameter `{name}`: {}",
                refusal.msg
            );
        }
        assert!(
            !refusal.msg.trim_end().ends_with("unknown argument"),
            "the refusal must not be bare: {}",
            refusal.msg
        );
    }

    #[test]
    fn duplicate_binding_names_both_sites() {
        let (_program, diags) = normalize_src(&format!(
            "{CONNECT}\nfn main() {{ let p = connect(\"h\", host: \"other\"); }}"
        ));
        let refusal = diags
            .items
            .iter()
            .find(|d| d.code == "E0123")
            .unwrap_or_else(|| panic!("expected E0123, got {:?}", codes(&diags)));
        assert!(refusal.msg.contains("`host`"), "{}", refusal.msg);
        assert!(
            refusal.msg.contains("positional argument #1") && refusal.msg.contains("named `host`"),
            "both sites must be named: {}",
            refusal.msg
        );
    }

    #[test]
    fn a_default_may_not_read_a_parameter() {
        let (_program, diags) =
            normalize_src("fn f(a: Int, b: Int = a) -> Int { return b; }\nfn main() {}");
        let refusal = diags
            .items
            .iter()
            .find(|d| d.code == "E0124")
            .unwrap_or_else(|| panic!("expected E0124, got {:?}", codes(&diags)));
        assert!(
            refusal.msg.contains("`b`") && refusal.msg.contains("`a`"),
            "{}",
            refusal.msg
        );
    }

    #[test]
    fn a_named_call_leaving_a_required_parameter_unbound_is_refused() {
        let (_program, diags) = normalize_src(&format!(
            "{CONNECT}\nfn main() {{ let p = connect(port: 8443); }}"
        ));
        let refusal = diags
            .items
            .iter()
            .find(|d| d.code == "E0124")
            .unwrap_or_else(|| panic!("expected E0124, got {:?}", codes(&diags)));
        assert!(refusal.msg.contains("`host`"), "{}", refusal.msg);
    }

    #[test]
    fn native_defaults_are_left_to_the_dispatcher() {
        // A `native fn`'s defaults are the runtime's rule; the call keeps its
        // shape so the dispatcher still sees a short argument list.
        let (program, diags) =
            normalize_src("native fn go(a: Int = 1) -> Int\nfn main() { let x = go(); }");
        assert!(diags.items.is_empty(), "{:?}", diags.items);
        let args = call_args_of(&program, "main");
        assert!(args.is_empty(), "no default was spliced: {args:?}");
    }

    #[test]
    fn a_default_that_calls_a_named_call_is_itself_normalised() {
        let (program, diags) = normalize_src(
            "fn port() -> Int { return 1; }
             fn f(a: Int = port()) -> Int { return a; }
             fn main() { let x = f(); }",
        );
        assert!(diags.items.is_empty(), "{:?}", diags.items);
        let args = call_args_of(&program, "main");
        assert_eq!(args.len(), 1);
        assert!(matches!(args[0].value.kind, ExprKind::Call { .. }));
    }

    #[test]
    fn method_calls_are_left_alone() {
        let (program, diags) = normalize_src(
            "fn connect(host: String) -> Int { return 1; }
             struct S { v: Int }
             fn main() { let s = S { v: 1 }; let x = s.m(port: 1); }",
        );
        assert!(diags.items.is_empty(), "{:?}", diags.items);
        // The struct literal and method call survive untouched.
        let body = fn_body(&program, "main");
        assert_eq!(body.stmts.len(), 2);
    }
}
