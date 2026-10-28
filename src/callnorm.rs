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
//! * **Calls through a value whose signature is not decidable.** `let g =
//!   connect; g("h")` *is* ordered here, because the binding names a top-level
//!   function and nothing rebinds it (see "Calls through a function value"
//!   below). Everything else — a parameter, a `var`, a shadowed or re-bound
//!   name, a field, an element, a function returned from a call — is left
//!   exactly as written; this pass never guesses an order.
//!
//! # Termination: a default may not close a cycle
//!
//! Rewriting a call splices a clone of the callee's default and then walks the
//! arguments it has just spliced, so the spliced default is normalised too.
//! That is by design — `fn outer(a: Int = inner("h"))` needs `inner`'s own
//! default filled in — but it terminates only if the "default of" relation is
//! acyclic. `fn f(a: Int, b: Int = f(1))` closes it: the splice inserts `f(1)`,
//! which is rewritten, which splices `f(1)` again. Before the rule below, that
//! input aborted the compiler with a stack overflow (exit 134) and no
//! diagnostic at all.
//!
//! So the relation is checked once, at declaration time, before any call is
//! walked. The graph has a node per function and an edge `F -> G` when some
//! default of `F` calls `G` in a way this pass will splice (a bare-name call
//! to a non-`native` function that leaves at least one of `G`'s defaulted
//! parameters unbound — the only shape that re-enters `rewrite`). A cycle in
//! that graph is refused as **E0125**, naming the path:
//!
//! ```text
//! error[E0125]: default parameter cycle: f -> g -> f
//! ```
//!
//! A depth limit was the alternative and is not what is implemented: it turns
//! an abort into a refusal at an arbitrary depth, on inputs whose expansion is
//! unbounded, so the same declaration would be legal or illegal depending on
//! how many other defaults happened to sit between the call site and the cycle.
//! The graph rule is a property of the declarations alone.
//!
//! The walk carries a second, redundant guard: the names of the functions
//! whose defaults are being expanded right now (`Normalizer::expanding`). A
//! call to a name already on that stack does not splice. With the declaration
//! check in place this can never fire; it exists so that a future shape the
//! graph fails to model still terminates instead of aborting, and if it ever
//! does fire it reports E0125 rather than silently dropping a default.
//!
//! # Calls through a function value
//!
//! `let g = connect; g("h")` used to be left exactly as written, on the theory
//! that the callee's signature is not statically known. It is statically known
//! whenever the binding is: a `let` whose initialiser is the bare name of a
//! top-level `fn`, in a scope where that name is neither re-bound, shadowed nor
//! assigned. Such a call is bound against that function's shape like a direct
//! call, which is what makes the planes agree — measured before the rule:
//! interpreted `443`, native `0`, both exit 0, for one program.
//!
//! What is *not* rewritten is everything whose callee cannot be pinned to a
//! declaration: a parameter, a `var`, a name that is shadowed or assigned in
//! the scope the call is written in, a field, an element, and a function
//! returned by a call. Those stay as written, and a default omitted there is
//! still the caller's problem — the pass never invents a signature.
//!
//! # Refusal codes
//!
//! | code | meaning |
//! |------|---------|
//! | E0121 | positional argument after a named one |
//! | E0122 | unknown argument name — the message lists the parameter names |
//! | E0123 | duplicate binding (positional and named, or named twice) |
//! | E0124 | a required parameter is unbound, or a default reads a parameter |
//! | E0125 | a cycle of defaults (`f -> g -> f`) — refused at the declaration |

use crate::ast::*;
use crate::error::{Diagnostic, Diagnostics};
use std::collections::{HashMap, HashSet};

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
        scopes: Vec::new(),
        expanding: Vec::new(),
    };
    pass.check_defaults(program);
    pass.check_default_cycles(program);
    for item in &mut program.items {
        if let Item::Fn(f) = item {
            // A parameter shadows a top-level function of the same name, so it
            // has to be bound before the body is walked: `fn go(conn: Int)`
            // must not make `conn(...)` inside `go` look like a direct call.
            let params: Vec<String> = f.params.iter().map(|p| p.name.clone()).collect();
            pass.push_scope();
            for name in &params {
                pass.bind(name, None);
            }
            // A default expression is spliced at call sites, so it is normal
            // there too: `fn f(x: Int, y: Int = g(tls: false))`.
            pass.walk_block(&mut f.body);
            pass.pop_scope();
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
    /// Innermost-last stack of local bindings, one map per block.
    ///
    /// `Some(f)` means the name holds the top-level function `f` and a call
    /// through it can be bound against `f`'s shape. `None` means the name holds
    /// anything else — or has been assigned to — so a call through it is left
    /// alone. The entry is only written by the statements that introduce the
    /// binding, so a lookup answers for the scope the call is written in.
    scopes: Vec<HashMap<String, Option<String>>>,
    /// Names of the functions whose defaults are being spliced right now.
    ///
    /// The redundant termination guard described in the module docs: a call to
    /// a name already on this stack does not splice, so the walk cannot outlive
    /// the declaration-time cycle check even if a shape slips past it.
    expanding: Vec<String>,
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

    // ── Termination ───────────────────────────────────────────────────────

    /// Refuse a cycle of defaults at the declaration, before any call is
    /// walked.
    ///
    /// Building the graph is the whole rule; see the module docs for why a
    /// depth limit is not the answer. Edges are only the calls that actually
    /// re-enter `rewrite` — a default that calls another function with every
    /// argument supplied splices nothing, so `fn f(a: Int, b: Int = f(1, 2))`
    /// is legal and is not an edge.
    fn check_default_cycles(&mut self, program: &Program) {
        let mut graph: HashMap<String, Vec<(String, Span)>> = HashMap::new();
        for item in &program.items {
            let Item::Fn(f) = item else { continue };
            // A `native fn`'s defaults are the dispatcher's rule: this pass
            // never splices them, so its edges cannot recurse here.
            if f.is_native {
                continue;
            }
            let mut edges = Vec::new();
            for param in &f.params {
                if let Some(default) = &param.default {
                    collect_splicing_calls(default, &self.sigs, &mut edges);
                }
            }
            if !edges.is_empty() {
                graph.entry(f.name.clone()).or_default().extend(edges);
            }
        }

        // Iterative depth-first search: an explicit stack so that a long chain
        // of defaulted declarations cannot overflow this one.
        let mut completed: HashSet<String> = HashSet::new();
        let mut reported: HashSet<String> = HashSet::new();
        // Sorted, so the order the search happens to reach a cycle in is not
        // visible to the user (the message is rotated to a fixed start anyway).
        let mut starts: Vec<String> = graph.keys().cloned().collect();
        starts.sort();
        for start in starts {
            if completed.contains(&start) {
                continue;
            }
            let mut stack: Vec<(String, usize)> = vec![(start.clone(), 0)];
            let mut on_stack: HashSet<String> = HashSet::from([start]);
            while let Some((node, index)) = stack.last().cloned() {
                let edges = graph.get(&node).cloned().unwrap_or_default();
                if index >= edges.len() {
                    completed.insert(node.clone());
                    on_stack.remove(&node);
                    stack.pop();
                    continue;
                }
                stack.last_mut().expect("frame was just read").1 = index + 1;
                let (target, span) = edges[index].clone();
                if on_stack.contains(&target) {
                    let from = stack
                        .iter()
                        .position(|(name, _)| *name == target)
                        .expect("an on-stack name has a frame");
                    let path: Vec<String> =
                        stack[from..].iter().map(|(name, _)| name.clone()).collect();
                    let cycle = closed_cycle(&path);
                    if reported.insert(canonical_cycle(&cycle)) {
                        self.diags.push(
                            Diagnostic::error("E0125", cycle_message(&cycle), span).with_help(
                                "a default is spliced at the call site, so these defaults would \
                                 expand without end; give one of them a value that does not call \
                                 into the cycle, or make the parameter required and pass it at \
                                 each call instead",
                            ),
                        );
                    }
                } else if !completed.contains(&target) {
                    on_stack.insert(target.clone());
                    stack.push((target, 0));
                }
            }
        }
    }

    // ── Local bindings ────────────────────────────────────────────────────

    fn push_scope(&mut self) {
        self.scopes.push(HashMap::new());
    }

    fn pop_scope(&mut self) {
        self.scopes.pop();
    }

    /// Record what `name` holds from here on: `Some(f)` for an alias of the
    /// top-level function `f`, `None` for a shadow or anything unknown.
    fn bind(&mut self, name: &str, target: Option<String>) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name.to_string(), target);
        }
    }

    /// The innermost binding of `name`, or `None` when it is not a local at all.
    fn lookup(&self, name: &str) -> Option<Option<String>> {
        for scope in self.scopes.iter().rev() {
            if let Some(bound) = scope.get(name) {
                return Some(bound.clone());
            }
        }
        None
    }

    /// `name` now holds something this pass cannot reason about. The binding is
    /// poisoned where it was introduced, not where the assignment sits: the
    /// value outlives the block it was assigned in.
    fn poison(&mut self, name: &str) {
        for scope in self.scopes.iter_mut().rev() {
            if scope.contains_key(name) {
                scope.insert(name.to_string(), None);
                return;
            }
        }
        self.bind(name, None);
    }

    /// The top-level function an expression names, if it names one.
    ///
    /// A local binding wins over the item of the same name, and only a binding
    /// that is still an alias resolves: `let g = conn` is, `var g = conn` and
    /// `g = other` are not.
    fn expr_alias(&self, expr: &Expr) -> Option<String> {
        let ExprKind::Ident(name) = &expr.kind else {
            return None;
        };
        match self.lookup(name) {
            Some(bound) => bound,
            None => self.sigs.contains_key(name).then(|| name.clone()),
        }
    }

    /// The declaration a call at `callee` binds against, and the name to report.
    ///
    /// A bare name that is a local alias of a top-level function resolves to
    /// that function: `let g = conn; g("h")` binds like `conn("h")`, which is
    /// what keeps the two planes from disagreeing about the omitted default.
    fn callee_shape(&self, callee: &Expr) -> Option<(String, Shape)> {
        let ExprKind::Ident(name) = &callee.kind else {
            return None;
        };
        // A local of this name shadows any top-level function of the same name.
        let target = match self.lookup(name) {
            Some(bound) => bound?,
            None if self.sigs.contains_key(name) => name.clone(),
            None => return None,
        };
        self.sigs.get(&target).cloned().map(|shape| (target, shape))
    }

    // ── The walk ──────────────────────────────────────────────────────────

    fn walk_block(&mut self, block: &mut Block) {
        self.push_scope();
        for stmt in &mut block.stmts {
            self.walk_stmt(stmt);
        }
        self.pop_scope();
    }

    fn walk_stmt(&mut self, stmt: &mut Stmt) {
        match &mut stmt.kind {
            StmtKind::Let { name, value, .. } => {
                self.walk_expr(value);
                // `let g = conn` is the one binding shape that keeps a
                // signature statically known through the local name.
                let target = self.expr_alias(value);
                self.bind(name, target);
            }
            StmtKind::Var { name, value, .. } => {
                self.walk_expr(value);
                // A `var` may be assigned later; the alias is not a promise.
                self.bind(name, None);
            }
            StmtKind::LetDestructure { names, value } => {
                self.walk_expr(value);
                let names: Vec<String> = names.clone();
                for name in &names {
                    self.bind(name, None);
                }
            }
            StmtKind::Expr { expr: value } | StmtKind::Bail(value) => self.walk_expr(value),
            StmtKind::Return(Some(value)) => self.walk_expr(value),
            StmtKind::Return(None) => {}
            StmtKind::For {
                binding,
                iter,
                body,
                ..
            } => {
                self.walk_expr(iter);
                let binding = binding.clone();
                self.push_scope();
                self.bind(&binding, None);
                self.walk_block(body);
                self.pop_scope();
            }
            StmtKind::While {
                condition, body, ..
            } => {
                self.walk_expr(condition);
                self.walk_block(body);
            }
            StmtKind::WhileLet {
                pattern,
                expr,
                body,
                ..
            } => {
                self.walk_expr(expr);
                let mut names = Vec::new();
                pattern_names(pattern, &mut names);
                self.push_scope();
                for name in &names {
                    self.bind(name, None);
                }
                self.walk_block(body);
                self.pop_scope();
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
                // Resolve the callee before rewriting. Only a bare identifier
                // can name a declaration — directly, or through a local that
                // still holds one — so every other callee shape is left alone.
                let span = expr.span;
                let spliced = match self.callee_shape(callee) {
                    Some((name, shape)) => {
                        let spliced = self.rewrite(&name, &shape, args, span);
                        if spliced {
                            // The arguments about to be walked may contain
                            // clones of this function's defaults, so a call back
                            // into it must not splice again (see "Termination").
                            self.expanding.push(name);
                        }
                        spliced
                    }
                    None => false,
                };
                self.walk_expr(callee);
                for arg in args.iter_mut() {
                    self.walk_expr(&mut arg.value);
                }
                if spliced {
                    self.expanding.pop();
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
                // `let g = conn; g = other` — the alias is gone from here on.
                if let ExprKind::Ident(name) = &target.kind {
                    let name = name.clone();
                    self.poison(&name);
                }
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
            ExprKind::Closure { params, body } => {
                let params: Vec<String> = params.iter().map(|p| p.name.clone()).collect();
                self.push_scope();
                for name in &params {
                    self.bind(name, None);
                }
                for stmt in body {
                    self.walk_stmt(stmt);
                }
                self.pop_scope();
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
    /// call would be a second, wrong program. Returns whether a default was
    /// spliced — the caller has to know, because the spliced nodes are walked.
    fn rewrite(&mut self, name: &str, shape: &Shape, args: &mut Vec<CallArg>, span: Span) -> bool {
        if args.is_empty() && shape.defaults.iter().all(|d| d.is_none()) {
            return false;
        }
        let mut failed = false;
        let mut spliced = false;

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
                    if self.expanding.iter().any(|expanding| expanding == name) {
                        // Termination guard: `name`'s defaults are already
                        // being expanded further up this walk, so splicing
                        // another clone would never end. The declaration-time
                        // cycle check refuses this program (E0125); reaching
                        // here means that check missed a shape, and the call is
                        // left as written rather than made to mean something
                        // nobody decided.
                        let from = self
                            .expanding
                            .iter()
                            .position(|expanding| expanding == name)
                            .unwrap_or(0);
                        let cycle = closed_cycle(&self.expanding[from..].to_vec());
                        self.diags.push(
                            Diagnostic::error("E0125", cycle_message(&cycle), span).with_help(
                                "a default is spliced at the call site, so these defaults would \
                                 expand without end; give one of them a value that does not call \
                                 into the cycle, or make the parameter required and pass it at \
                                 each call instead",
                            ),
                        );
                        return false;
                    }
                    slots[slot] = Some(default.clone());
                    bound_by[slot] = Some("its declared default".to_string());
                    spliced = true;
                }
                Some(_) => {
                    // Native default: leave the hole for the dispatcher.
                    return false;
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
            return false;
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
        spliced
    }
}

/// The names a pattern binds.
fn pattern_names(pattern: &Pattern, out: &mut Vec<String>) {
    match pattern {
        Pattern::Ident(name) => out.push(name.clone()),
        Pattern::Tuple(items) => {
            for item in items {
                pattern_names(item, out);
            }
        }
        Pattern::Variant { fields, .. } => {
            for field in fields {
                pattern_names(&field.pattern, out);
            }
        }
        Pattern::Literal(_) | Pattern::Wildcard => {}
    }
}

/// `f -> g -> f`, the path an E0125 names.
fn cycle_message(cycle: &[String]) -> String {
    format!("default parameter cycle: {}", cycle.join(" -> "))
}

/// Rotate a cycle path to start at its alphabetically first name, then close it
/// (`["g", "f"]` → `["f", "g", "f"]`).
///
/// The search reaches a cycle from whichever node it starts at, and a `HashMap`
/// yields its keys in no particular order, so without this the same declaration
/// would report `f -> g -> f` or `g -> f -> g` depending on the run. The rule is
/// a property of the declarations, so the message is too.
fn closed_cycle(path: &[String]) -> Vec<String> {
    let Some(at) = path
        .iter()
        .enumerate()
        .min_by_key(|(_, name)| *name)
        .map(|(at, _)| at)
    else {
        return Vec::new();
    };
    let mut rotated: Vec<String> = path[at..].to_vec();
    rotated.extend(path[..at].iter().cloned());
    if let Some(first) = rotated.first().cloned() {
        rotated.push(first);
    }
    rotated
}

/// A rotation-invariant key for a cycle, so one cycle found from two entry
/// points is reported once. `cycle` ends with the name it starts from; the
/// repeat is dropped before rotating to the alphabetically first name.
fn canonical_cycle(cycle: &[String]) -> String {
    let names = &cycle[..cycle.len().saturating_sub(1)];
    let Some(at) = names
        .iter()
        .enumerate()
        .min_by_key(|(_, name)| *name)
        .map(|(at, _)| at)
    else {
        return String::new();
    };
    let mut rotated: Vec<&str> = names[at..].iter().map(|name| name.as_str()).collect();
    rotated.extend(names[..at].iter().map(|name| name.as_str()));
    rotated.join(" -> ")
}

/// Whether `rewrite` would splice a default into this call.
///
/// Exactly the decision `rewrite` makes at its slot-filling step: a defaulted
/// parameter the call does not bind, on a function whose defaults this pass
/// owns. Only these calls can re-enter the walk, so only these are edges in
/// the cycle graph.
fn splices_default(shape: &Shape, args: &[CallArg]) -> bool {
    if shape.native {
        return false;
    }
    let mut bound = vec![false; shape.params.len()];
    for (index, arg) in args.iter().enumerate() {
        let slot = match &arg.name {
            Some(name) => shape.params.iter().position(|p| p == name),
            None => Some(index).filter(|index| *index < shape.params.len()),
        };
        if let Some(slot) = slot {
            if let Some(flag) = bound.get_mut(slot) {
                *flag = true;
            }
        }
    }
    shape
        .params
        .iter()
        .enumerate()
        .any(|(slot, _)| !bound[slot] && shape.defaults[slot].is_some())
}

/// Every call in `expr` that would splice a default, with the span of the call.
///
/// The traversal mirrors `collect_idents` deliberately: the question is asked
/// of the text, not of a resolution.
fn collect_splicing_calls(
    expr: &Expr,
    sigs: &HashMap<String, Shape>,
    out: &mut Vec<(String, Span)>,
) {
    match &expr.kind {
        ExprKind::Call { callee, args } => {
            if let ExprKind::Ident(target) = &callee.kind {
                if let Some(shape) = sigs.get(target) {
                    if splices_default(shape, args) {
                        out.push((target.clone(), expr.span));
                    }
                }
            }
            collect_splicing_calls(callee, sigs, out);
            for arg in args {
                collect_splicing_calls(&arg.value, sigs, out);
            }
        }
        ExprKind::Binary { left, right, .. } => {
            collect_splicing_calls(left, sigs, out);
            collect_splicing_calls(right, sigs, out);
        }
        ExprKind::Unary { operand, .. } => collect_splicing_calls(operand, sigs, out),
        ExprKind::MethodCall { object, args, .. } => {
            collect_splicing_calls(object, sigs, out);
            for arg in args {
                collect_splicing_calls(&arg.value, sigs, out);
            }
        }
        ExprKind::FieldAccess { object, .. } => collect_splicing_calls(object, sigs, out),
        ExprKind::Index { object, index } => {
            collect_splicing_calls(object, sigs, out);
            collect_splicing_calls(index, sigs, out);
        }
        ExprKind::If {
            condition,
            then_block,
            else_branch,
        } => {
            collect_splicing_calls(condition, sigs, out);
            collect_splicing_calls_in_block(then_block, sigs, out);
            if let Some(ElseBranch::ElseIf(e)) = else_branch {
                collect_splicing_calls(e, sigs, out);
            } else if let Some(ElseBranch::Block(b)) = else_branch {
                collect_splicing_calls_in_block(b, sigs, out);
            }
        }
        ExprKind::Block(b) => collect_splicing_calls_in_block(b, sigs, out),
        ExprKind::Loop { body, .. } => collect_splicing_calls_in_block(body, sigs, out),
        ExprKind::Array(elements) => {
            for element in elements {
                collect_splicing_calls(element, sigs, out);
            }
        }
        ExprKind::MapLit(entries) => {
            for (key, value) in entries {
                collect_splicing_calls(key, sigs, out);
                collect_splicing_calls(value, sigs, out);
            }
        }
        ExprKind::Try(inner) | ExprKind::Await(inner) | ExprKind::Bail(inner) => {
            collect_splicing_calls(inner, sigs, out)
        }
        ExprKind::Assign { target, value } => {
            collect_splicing_calls(target, sigs, out);
            collect_splicing_calls(value, sigs, out);
        }
        ExprKind::StructLit { fields, spread, .. } => {
            for field in fields {
                collect_splicing_calls(&field.value, sigs, out);
            }
            if let Some(spread) = spread {
                collect_splicing_calls(spread, sigs, out);
            }
        }
        ExprKind::Cast { expr, .. } => collect_splicing_calls(expr, sigs, out),
        ExprKind::Interpolation(parts) => {
            for part in parts {
                if let StringPart::Expr(e) = part {
                    collect_splicing_calls(e, sigs, out);
                }
            }
        }
        ExprKind::Match { subject, arms } => {
            collect_splicing_calls(subject, sigs, out);
            for arm in arms {
                collect_splicing_calls(&arm.body, sigs, out);
            }
        }
        ExprKind::Closure { body, .. } => {
            for stmt in body {
                collect_splicing_calls_in_stmt(stmt, sigs, out);
            }
        }
        ExprKind::IfLet {
            expr, then_block, ..
        } => {
            collect_splicing_calls(expr, sigs, out);
            collect_splicing_calls_in_block(then_block, sigs, out);
        }
        ExprKind::Spawn { func, args } => {
            collect_splicing_calls(func, sigs, out);
            for arg in args {
                collect_splicing_calls(arg, sigs, out);
            }
        }
        ExprKind::Select { cases, default } => {
            for case in cases {
                match &case.op {
                    SelectOp::Recv(ch) => collect_splicing_calls(ch, sigs, out),
                    SelectOp::Send { ch, val } => {
                        collect_splicing_calls(ch, sigs, out);
                        collect_splicing_calls(val, sigs, out);
                    }
                }
                collect_splicing_calls(&case.body, sigs, out);
            }
            if let Some(default) = default {
                collect_splicing_calls(default, sigs, out);
            }
        }
        _ => {}
    }
}

fn collect_splicing_calls_in_block(
    block: &Block,
    sigs: &HashMap<String, Shape>,
    out: &mut Vec<(String, Span)>,
) {
    for stmt in &block.stmts {
        collect_splicing_calls_in_stmt(stmt, sigs, out);
    }
}

fn collect_splicing_calls_in_stmt(
    stmt: &Stmt,
    sigs: &HashMap<String, Shape>,
    out: &mut Vec<(String, Span)>,
) {
    match &stmt.kind {
        StmtKind::Let { value, .. }
        | StmtKind::Var { value, .. }
        | StmtKind::LetDestructure { value, .. }
        | StmtKind::Expr { expr: value }
        | StmtKind::Bail(value) => collect_splicing_calls(value, sigs, out),
        StmtKind::Return(Some(v)) => collect_splicing_calls(v, sigs, out),
        StmtKind::For { iter, body, .. } => {
            collect_splicing_calls(iter, sigs, out);
            collect_splicing_calls_in_block(body, sigs, out);
        }
        StmtKind::While {
            condition, body, ..
        } => {
            collect_splicing_calls(condition, sigs, out);
            collect_splicing_calls_in_block(body, sigs, out);
        }
        StmtKind::WhileLet { expr, body, .. } => {
            collect_splicing_calls(expr, sigs, out);
            collect_splicing_calls_in_block(body, sigs, out);
        }
        StmtKind::Loop { body, .. } | StmtKind::Defer { body } => {
            collect_splicing_calls_in_block(body, sigs, out)
        }
        _ => {}
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
