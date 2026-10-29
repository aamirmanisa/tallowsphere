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
//! default of `F` calls `G` in a way this pass will splice (a call whose callee
//! resolves to a non-`native` function that leaves at least one of `G`'s
//! defaulted parameters unbound — the shapes that re-enter `rewrite`). A cycle
//! in that graph is refused as **E0125**, naming the path:
//!
//! ```text
//! error[E0125]: default parameter cycle: f -> g -> f
//! ```
//!
//! A depth limit was the alternative and is not what is implemented: it turns
//! an abort into a refusal at an arbitrary depth, on inputs whose expansion is
//! unbounded, so the same declaration would be legal or illegal depending on
//! how many other defaults happened to sit between the call site and the
//! cycle. The graph rule is a property of the declarations alone.
//!
//! The graph is built by the *same* traversal `rewrite` uses
//! ([`WalkPurpose`]), not by a second hand-written mirror of it. A shape the
//! rewrite walk reaches — the `else` branch of an `if let`, the value of a
//! `break`, a call through a `let` alias — is an edge in the graph for exactly
//! that reason, so a cycle through it is refused at the declaration and not
//! only where some call site happens to expand it.
//!
//! The walk keeps a second, redundant guard: the names of the functions whose
//! defaults are being expanded right now (`Normalizer::expanding`). A call to a
//! name already on that stack does not splice. With the shared traversal in
//! place this is not reachable on a shape the graph models; it exists so that a
//! shape neither walk models still terminates instead of aborting, and if it
//! ever does fire it reports E0125 rather than silently dropping a default. The
//! two producers de-duplicate on the cycle, not on the code, so a program with
//! two cycles is refused for both.
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
    /// The file this declaration came from, when it is not the entry file.
    ///
    /// A default's span is an offset into *its own* source, so a diagnostic
    /// raised while expanding an imported function's default has to carry the
    /// file or it renders against unrelated text in the entry file (audit N-9).
    imported_from: Option<std::path::PathBuf>,
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
        edges: Vec::new(),
        reported_cycles: HashSet::new(),
        used_spans: HashSet::new(),
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
            pass.walk_block(&mut f.body, WalkPurpose::Rewrite);
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
                imported_from: f.imported_from.clone(),
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
    /// Edges found by the last [`WalkPurpose::Collect`] traversal.
    ///
    /// Scratch space for the cycle-graph builder: the graph grows one node at a
    /// time, and the traversal is the same one `rewrite` uses, so the calls it
    /// reports are exactly the calls the walk would re-enter.
    edges: Vec<(String, Span)>,
    /// Canonical keys of the cycles already reported, by either producer.
    ///
    /// The de-duplication key is the cycle, not the diagnostic code: a program
    /// with two different cycles is refused for both, while the walk's guard
    /// does not repeat a cycle the declaration check already named (with a
    /// different span).
    reported_cycles: HashSet<String>,
    /// `(start, end)` of every span already used by an E0125.
    ///
    /// The driver collapses diagnostics that agree on both code and span
    /// (`Diagnostics::dedupe_same_site`). Two cycles that share an edge also
    /// share the call that closes them, so the second one is anchored on an
    /// earlier edge of its own path rather than being silently dropped.
    used_spans: HashSet<(usize, usize)>,
}

/// What a traversal is being run for.
///
/// The *traversal* — which nodes are visited, in what order, and how `let`
/// bindings are tracked — is one function so the declaration graph and
/// `rewrite` cannot disagree about a shape. Only the action at a call node
/// differs: the graph records the calls that would splice; the rewrite walk
/// splices and rewrites them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalkPurpose {
    /// Read-only: collect the calls in a default that would splice.
    Collect,
    /// The normalising walk: bind arguments and splice defaults.
    Rewrite,
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
        // The declaration each node's edges belong to: an edge's span is inside
        // that function's default, so that is the file the diagnostic names.
        let mut owners: HashMap<String, Option<std::path::PathBuf>> = HashMap::new();
        for item in &program.items {
            let Item::Fn(f) = item else { continue };
            // A `native fn`'s defaults are the dispatcher's rule: this pass
            // never splices them, so its edges cannot recurse here.
            if f.is_native {
                continue;
            }
            // The graph walks a clone of each default with the *same* traversal
            // `rewrite` uses. Nothing here is rewritten (`WalkPurpose::Collect`
            // records instead of splicing), but every shape the walk can reach
            // — `if let`'s else branch, `break <value>`, a call through a `let`
            // alias — is an edge, so a cycle in it is refused at the
            // declaration rather than only where some call site happens to
            // expand it.
            self.edges.clear();
            for param in &f.params {
                let Some(default) = &param.default else {
                    continue;
                };
                // Each default is spliced on its own, in the caller's scope; a
                // `let` inside one cannot name anything inside another.
                self.push_scope();
                let mut default = default.clone();
                self.walk_expr(&mut default, WalkPurpose::Collect);
                self.pop_scope();
            }
            if !self.edges.is_empty() {
                graph
                    .entry(f.name.clone())
                    .or_default()
                    .extend(self.edges.drain(..));
                owners.insert(f.name.clone(), f.imported_from.clone());
            }
        }

        // Iterative depth-first search: an explicit stack so that a long chain
        // of defaulted declarations cannot overflow this one.
        //
        // There is deliberately no global `completed` set. A node shared by two
        // cycles can be popped from one branch and then reached again from
        // another; marking it *completed* made the second cycle invisible, so
        // whether two cycles were disclosed depended on which names sorted
        // first (§7.3 of the audit). Restricting each search to names not
        // smaller than its start still reaches every cycle from its
        // alphabetically first node, and the canonical key de-duplicates the
        // rotations, so the set of reported cycles is a property of the graph.
        let mut starts: Vec<String> = capable_nodes(&graph).into_iter().collect();
        starts.sort();
        let rank: HashMap<&str, usize> = starts
            .iter()
            .enumerate()
            .map(|(at, name)| (name.as_str(), at))
            .collect();
        for start in starts.iter() {
            let start_rank = rank[start.as_str()];
            // Each frame keeps the span of the edge that entered it, so a cycle
            // can be anchored on a call of its own path (see `report_cycle`).
            let mut stack: Vec<(String, usize, Span)> = vec![(start.clone(), 0, Span::new(0, 0))];
            let mut on_stack: HashSet<String> = HashSet::from([start.clone()]);
            while let Some((node, index, _)) = stack.last().cloned() {
                let edges = graph.get(&node).cloned().unwrap_or_default();
                if index >= edges.len() {
                    on_stack.remove(&node);
                    stack.pop();
                    continue;
                }
                stack.last_mut().expect("frame was just read").1 = index + 1;
                let (target, span) = edges[index].clone();
                if on_stack.contains(&target) {
                    let from = stack
                        .iter()
                        .position(|(name, _, _)| *name == target)
                        .expect("an on-stack name has a frame");
                    let path: Vec<String> = stack[from..]
                        .iter()
                        .map(|(name, _, _)| name.clone())
                        .collect();
                    // The calls on the cycle: the edge that entered each frame
                    // after the start, then the closing call.
                    let spans: Vec<Span> = stack[from + 1..]
                        .iter()
                        .map(|(_, _, span)| *span)
                        .chain(std::iter::once(span))
                        .collect();
                    let cycle = closed_cycle(&path);
                    // The closing call sits inside `node`'s default, so the
                    // span is an offset into `node`'s file.
                    let file = owners.get(&node).cloned().flatten();
                    self.report_cycle(&cycle, &spans, file);
                } else if rank
                    .get(target.as_str())
                    .is_some_and(|at| *at >= start_rank)
                {
                    on_stack.insert(target.clone());
                    stack.push((target, 0, span));
                }
            }
        }
    }

    /// Report one cycle, anchored on a call that belongs to it.
    ///
    /// The closing call is the natural anchor and the one every non-colliding
    /// cycle uses. Two cycles can share their closing call (they share an
    /// edge), and the driver collapses diagnostics that agree on code *and*
    /// span — so once a span has been claimed, the next cycle is anchored on
    /// the latest earlier call of its own path instead of being lost. Both
    /// anchors name a call inside the cycle, so the location stays true.
    fn report_cycle(&mut self, cycle: &[String], spans: &[Span], file: Option<std::path::PathBuf>) {
        if !self.reported_cycles.insert(canonical_cycle(cycle)) {
            return;
        }
        let chosen = spans
            .iter()
            .rev()
            .find(|span| !self.used_spans.contains(&(span.start, span.end)))
            .copied()
            .unwrap_or_else(|| spans.first().copied().unwrap_or(Span::new(0, 0)));
        self.used_spans.insert((chosen.start, chosen.end));
        let mut diag = Diagnostic::error("E0125", cycle_message(cycle), chosen).with_help(
            "a default is spliced at the call site, so these defaults would expand without \
             end; give one of them a value that does not call into the cycle, or make the \
             parameter required and pass it at each call instead",
        );
        if let Some(path) = file {
            diag = diag.with_file(path);
        }
        self.diags.push(diag);
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

    fn walk_block(&mut self, block: &mut Block, purpose: WalkPurpose) {
        self.push_scope();
        for stmt in &mut block.stmts {
            self.walk_stmt(stmt, purpose);
        }
        self.pop_scope();
    }

    fn walk_stmt(&mut self, stmt: &mut Stmt, purpose: WalkPurpose) {
        match &mut stmt.kind {
            StmtKind::Let { name, value, .. } => {
                self.walk_expr(value, purpose);
                // `let g = conn` is the one binding shape that keeps a
                // signature statically known through the local name.
                let target = self.expr_alias(value);
                self.bind(name, target);
            }
            StmtKind::Var { name, value, .. } => {
                self.walk_expr(value, purpose);
                // A `var` may be assigned later; the alias is not a promise.
                self.bind(name, None);
            }
            StmtKind::LetDestructure { pattern, value } => {
                self.walk_expr(value, purpose);
                let names = pattern.bound_names();
                for name in &names {
                    self.bind(name, None);
                }
            }
            StmtKind::Expr { expr: value } | StmtKind::Bail(value) => {
                self.walk_expr(value, purpose)
            }
            StmtKind::Return(Some(value)) => self.walk_expr(value, purpose),
            StmtKind::Return(None) => {}
            StmtKind::For {
                pattern,
                iter,
                body,
                ..
            } => {
                self.walk_expr(iter, purpose);
                let names = pattern.bound_names();
                self.push_scope();
                for name in &names {
                    self.bind(name, None);
                }
                self.walk_block(body, purpose);
                self.pop_scope();
            }
            StmtKind::While {
                condition, body, ..
            } => {
                self.walk_expr(condition, purpose);
                self.walk_block(body, purpose);
            }
            StmtKind::WhileLet {
                pattern,
                expr,
                body,
                ..
            } => {
                self.walk_expr(expr, purpose);
                let mut names = Vec::new();
                pattern_names(pattern, &mut names);
                self.push_scope();
                for name in &names {
                    self.bind(name, None);
                }
                self.walk_block(body, purpose);
                self.pop_scope();
            }
            StmtKind::Break { value, .. } => {
                if let Some(v) = value {
                    self.walk_expr(v, purpose);
                }
            }
            StmtKind::Continue { .. } => {}
            StmtKind::Loop { body, .. } | StmtKind::Defer { body } => {
                self.walk_block(body, purpose)
            }
        }
    }

    fn walk_expr(&mut self, expr: &mut Expr, purpose: WalkPurpose) {
        match &mut expr.kind {
            ExprKind::IntLit(_)
            | ExprKind::FloatLit(_)
            | ExprKind::StringLit(_)
            | ExprKind::BoolLit(_)
            | ExprKind::Nil
            | ExprKind::Ident(_)
            | ExprKind::DotIdent(_) => {}

            ExprKind::Binary { left, right, .. } => {
                self.walk_expr(left, purpose);
                self.walk_expr(right, purpose);
            }
            ExprKind::Unary { operand, .. } => self.walk_expr(operand, purpose),

            ExprKind::Call { callee, args } => {
                // Resolve the callee before rewriting. Only a bare identifier
                // can name a declaration — directly, or through a local that
                // still holds one — so every other callee shape is left alone.
                let span = expr.span;
                if purpose == WalkPurpose::Collect {
                    // Read-only: record the calls `rewrite` would splice. The
                    // resolution is `callee_shape`, the same one the rewrite
                    // uses, so an alias is an edge here for exactly the reason
                    // it is spliced there.
                    if let Some((name, shape)) = self.callee_shape(callee) {
                        if splices_default(&shape, args) {
                            self.edges.push((name, span));
                        }
                    }
                    self.walk_expr(callee, purpose);
                    for arg in args.iter_mut() {
                        self.walk_expr(&mut arg.value, purpose);
                    }
                    return;
                }
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
                self.walk_expr(callee, purpose);
                for arg in args.iter_mut() {
                    self.walk_expr(&mut arg.value, purpose);
                }
                if spliced {
                    self.expanding.pop();
                }
            }
            ExprKind::MethodCall { object, args, .. } => {
                self.walk_expr(object, purpose);
                for arg in args.iter_mut() {
                    self.walk_expr(&mut arg.value, purpose);
                }
            }
            ExprKind::FieldAccess { object, .. } => self.walk_expr(object, purpose),
            ExprKind::Index { object, index } => {
                self.walk_expr(object, purpose);
                self.walk_expr(index, purpose);
            }
            ExprKind::If {
                condition,
                then_block,
                else_branch,
            } => {
                self.walk_expr(condition, purpose);
                self.walk_block(then_block, purpose);
                if let Some(else_branch) = else_branch {
                    match else_branch {
                        ElseBranch::Block(b) => self.walk_block(b, purpose),
                        ElseBranch::ElseIf(e) => self.walk_expr(e, purpose),
                    }
                }
            }
            ExprKind::IfLet {
                expr: scrutinee,
                then_block,
                else_branch,
                ..
            } => {
                self.walk_expr(scrutinee, purpose);
                self.walk_block(then_block, purpose);
                if let Some(else_branch) = else_branch {
                    match else_branch {
                        ElseBranch::Block(b) => self.walk_block(b, purpose),
                        ElseBranch::ElseIf(e) => self.walk_expr(e, purpose),
                    }
                }
            }
            ExprKind::Match { subject, arms } => {
                self.walk_expr(subject, purpose);
                for arm in arms {
                    // A pattern literal is an expression node too, but it holds
                    // no call: literals are the only pattern payload.
                    self.walk_expr(&mut arm.body, purpose);
                }
            }
            ExprKind::Block(b) => self.walk_block(b, purpose),
            ExprKind::Loop { body, .. } => self.walk_block(body, purpose),
            ExprKind::Array(elements) => {
                for element in elements {
                    self.walk_expr(element, purpose);
                }
            }
            ExprKind::MapLit(entries) => {
                for (key, value) in entries {
                    self.walk_expr(key, purpose);
                    self.walk_expr(value, purpose);
                }
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) | ExprKind::Bail(inner) => {
                self.walk_expr(inner, purpose)
            }
            ExprKind::Assign { target, value } => {
                self.walk_expr(target, purpose);
                self.walk_expr(value, purpose);
                // `let g = conn; g = other` — the alias is gone from here on.
                if let ExprKind::Ident(name) = &target.kind {
                    let name = name.clone();
                    self.poison(&name);
                }
            }
            ExprKind::StructLit { fields, spread, .. } => {
                for field in fields {
                    self.walk_expr(&mut field.value, purpose);
                }
                if let Some(spread) = spread {
                    self.walk_expr(spread, purpose);
                }
            }
            ExprKind::Cast { expr: inner, .. } => self.walk_expr(inner, purpose),
            ExprKind::Interpolation(parts) => {
                for part in parts {
                    if let StringPart::Expr(e) = part {
                        self.walk_expr(e, purpose);
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
                    self.walk_stmt(stmt, purpose);
                }
                self.pop_scope();
            }
            ExprKind::Spawn { func, args } => {
                self.walk_expr(func, purpose);
                for arg in args {
                    self.walk_expr(arg, purpose);
                }
            }
            ExprKind::Select { cases, default } => {
                for case in cases {
                    match &mut case.op {
                        SelectOp::Recv(ch) => self.walk_expr(ch, purpose),
                        SelectOp::Send { ch, val } => {
                            self.walk_expr(ch, purpose);
                            self.walk_expr(val, purpose);
                        }
                    }
                    self.walk_expr(&mut case.body, purpose);
                }
                if let Some(default) = default {
                    self.walk_expr(default, purpose);
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
                        // The declaration-time check has almost certainly
                        // already refused this program; report the walk's own
                        // view only when it has not *already named this cycle*,
                        // so one cycle is not reported twice with two different
                        // spans, while a second, different cycle is still
                        // disclosed.
                        //
                        // The closing call is read from the default of the
                        // innermost function being expanded, so *that*
                        // declaration owns the span (audit N-9).
                        let file = self.expanding.last().and_then(|owner| {
                            self.sigs.get(owner).and_then(|s| s.imported_from.clone())
                        });
                        self.report_cycle(&cycle, &[span], file);
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
        Pattern::Array { elems, rest } => {
            for p in elems {
                pattern_names(p, out);
            }
            if let Some(rest) = rest {
                pattern_names(rest, out);
            }
        }
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

/// The names that can lie on a cycle: a self-loop, or a member of a strongly
/// connected component with more than one node.
///
/// The all-cycles search below runs without a global `completed` set (that is
/// what made a second cycle sharing a node invisible), so without this bound a
/// large *acyclic* fan-out of defaults would be walked once per distinct path.
/// A node outside every cycle cannot appear in a report, so it is not searched.
fn capable_nodes(graph: &HashMap<String, Vec<(String, Span)>>) -> HashSet<String> {
    let mut nodes: Vec<&str> = graph.keys().map(|name| name.as_str()).collect();
    nodes.sort_unstable();

    // Kosaraju, first pass: finishing order over the forward edges. Iterative,
    // because a long chain of defaulted declarations must not overflow.
    let mut seen: HashSet<&str> = HashSet::new();
    let mut order: Vec<&str> = Vec::new();
    for root in &nodes {
        if !seen.insert(*root) {
            continue;
        }
        let mut stack: Vec<(&str, usize)> = vec![(*root, 0)];
        while let Some((node, index)) = stack.last().copied() {
            let edges = graph.get(node).map(|edges| edges.as_slice()).unwrap_or(&[]);
            if index < edges.len() {
                stack.last_mut().expect("frame was just read").1 = index + 1;
                let target = edges[index].0.as_str();
                if seen.insert(target) {
                    stack.push((target, 0));
                }
            } else {
                order.push(node);
                stack.pop();
            }
        }
    }

    // Second pass over the reversed edges, labelling each component.
    let mut reverse: HashMap<&str, Vec<&str>> = HashMap::new();
    for (node, edges) in graph {
        for (target, _) in edges {
            reverse
                .entry(target.as_str())
                .or_default()
                .push(node.as_str());
        }
    }
    let mut component: HashMap<&str, usize> = HashMap::new();
    let mut sizes: Vec<usize> = Vec::new();
    for root in order.iter().rev().copied() {
        if component.contains_key(root) {
            continue;
        }
        let id = sizes.len();
        let mut size = 0usize;
        let mut stack: Vec<&str> = vec![root];
        component.insert(root, id);
        while let Some(node) = stack.pop() {
            size += 1;
            for source in reverse.get(node).into_iter().flatten().copied() {
                if !component.contains_key(source) {
                    component.insert(source, id);
                    stack.push(source);
                }
            }
        }
        sizes.push(size);
    }

    let mut capable = HashSet::new();
    for (node, edges) in graph {
        let in_nontrivial = sizes[component[node.as_str()]] > 1;
        let self_loop = edges.iter().any(|(target, _)| target == node);
        if in_nontrivial || self_loop {
            capable.insert(node.clone());
        }
    }
    capable
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
