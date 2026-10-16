//! Program-level OPSEC policy gates (E5001–E5004) — task A5.2.2 / ruleset A5.2.1.
//!
//! This pass is the *program-policy* half of Tallow's OPSEC enforcement. The
//! per-function gates stay where they are (`opsec_pass.rs` E0900 compartment
//! isolation, `stealth_pass.rs` E0400/E0403, `legal_pass.rs` E0100,
//! `cra_pass.rs` W1900); this pass closes the "collection run leaks identity
//! by composition" gap by policing the *mission as a whole*:
//!
//! - **E5001** identity mixing — one program (build unit) must act as exactly
//!   one `@persona`. Fires when the program declares more than one distinct
//!   `@persona(id: ...)` string literal, with a cheap call-graph reachability
//!   refinement appended when two different-persona functions are connected.
//! - **E5002** direct-egress opt-out misuse — `TALLOW_ALLOW_DIRECT` is an
//!   *operator* process-level decision, never a program affordance. Fires on a
//!   string literal exactly equal to `"TALLOW_ALLOW_DIRECT"` and on
//!   `allow_direct_egress: true` in struct/config literals, unless a logged
//!   `@opsec_waiver` covers the rule.
//! - **E5003** fingerprint/persona reuse — (a) a persona whose disposal
//!   `@burn_plan(persona: "p")` pairs on one unit must not be re-declared by
//!   `@persona(id: "p")` on a different unit (pair declaration + disposal in
//!   one build unit);
//!   (b) two `@persona` annotations with *different* ids must not share one
//!   `fingerprint_seed` literal. Rotation produces a fresh seed per persona.
//! - **E5004** missing plan bundle — a *collection program* (network or browser
//!   navigation reachable from `main`) must carry `@legal` + `@cra_class` +
//!   `@persona` + `@burn_plan` at program scope, plus `@stealth` when browser
//!   navigation is reachable. ONE combined error lists every missing category
//!   (it complements, never replaces, the per-function gates).
//!
//! # Decidability boundary (conservative — A5.2.1 §3)
//! This pass fires only on literal/annotation facts. Dynamic values are
//! explicitly **RUNTIME-ONLY** and are skipped here (never guessed); each such
//! case is marked in this file where it is skipped:
//! - dynamic `@persona(id: <expr>)` / `seed: <expr>` → persona-use boundary at
//!   vault open (A5.1.2) asserts a single active persona and hard-fails
//!   (`E5001-RT` / `E5003-RT`), audit-logged;
//! - the `TALLOW_ALLOW_DIRECT` process env actually being set → checked by the
//!   egress layer at first network op (`egress_direct=true` audit marking);
//! - reuse of a persona/fingerprint *across separate runs* → persona registry
//!   (A5.1.2), not statically decidable;
//! - `@burn_plan` actually executing at run end → logged run-end event.
//!
//! # Waivers
//! `@opsec_waiver(rule: "E5xxx", reason: "...", reviewer: "...")` on the
//! offending function **or** on `main` suppresses exactly that one rule and
//! emits `W5001` ("waiver in effect") so the escape is visible in every build.
//! This is a logged, auditable escape — not a silent bypass (A5.2.1 §4).
//!
//! # Program scope
//! `.tl` annotations attach to items, so the only program-scope carrier is the
//! `main` function (the ruleset's "`main` or top-of-file" — top-of-file does
//! not exist in this AST). The E5004 bundle check reads `main`'s annotations.
//!
//! Error codes: E5001–E5004 (errors), W5001 (warning). Wired into the compile
//! pipeline at Phase 11b of `main.rs` (`OpsecGatesPass::new(&program, &env).check()`,
//! diagnostics folded with the other passes — A5.2.2 call site).

use std::collections::{HashMap, HashSet, VecDeque};

use crate::ast::*;
use crate::error::{Diagnostic, Diagnostics};
use crate::lexer::Span;
use crate::typeck::TypeEnv;

// ── Collected annotation facts ───────────────────────────────────────────────

/// One `@persona(...)` annotation use.
#[derive(Debug, Clone)]
struct PersonaUse {
    /// Function carrying the annotation (impl methods use the method name).
    fn_name: String,
    /// `id:` literal. `None` when absent or dynamic — RUNTIME-ONLY, skipped.
    id: Option<String>,
    /// `fingerprint_seed:` literal. `None` when absent or dynamic.
    seed: Option<String>,
    span: Span,
}

/// One `@burn_plan(...)` annotation use.
#[derive(Debug, Clone)]
struct BurnUse {
    fn_name: String,
    /// `persona:` literal. `None` when absent or dynamic — RUNTIME-ONLY.
    persona: Option<String>,
    span: Span,
}

/// One `@opsec_waiver(...)` annotation use.
#[derive(Debug, Clone)]
struct WaiverUse {
    /// `rule:` literal (e.g. "E5002"). `None` → never matches (dynamic rule).
    rule: Option<String>,
    reason: Option<String>,
    reviewer: Option<String>,
    /// Function carrying the waiver; `"main"` means program scope.
    fn_name: String,
    span: Span,
}

/// Kind of direct-egress opt-out fact found in program data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EgressOptIn {
    /// A string literal exactly equal to `"TALLOW_ALLOW_DIRECT"`.
    FlagLiteral,
    /// `allow_direct_egress: true` in a struct or map literal.
    AllowDirectTrue,
}

/// A single E5002-relevant fact discovered by the body scan.
#[derive(Debug, Clone)]
struct EgressFact {
    fn_name: String,
    span: Span,
    kind: EgressOptIn,
}

// ── Free helpers over the AST ────────────────────────────────────────────────

/// Visit every function declaration in the program (top-level fns and impl
/// methods), matching how `OpsecPass`/`StealthPass` walk `program.items`.
fn each_fn<'p>(program: &'p Program, mut f: impl FnMut(&'p FnDecl)) {
    for item in &program.items {
        match item {
            Item::Fn(fd) => f(fd),
            Item::Impl(imp) => {
                for m in &imp.methods {
                    f(m);
                }
            }
            _ => {}
        }
    }
}

/// Extract a named string-literal argument from an annotation.
fn ann_arg_str(ann: &Annotation, arg_name: &str) -> Option<String> {
    for arg in &ann.args {
        if arg.name == arg_name {
            if let ExprKind::StringLit(ref s) = arg.value.kind {
                return Some(s.clone());
            }
        }
    }
    None
}

/// Collect all `@persona` uses, program-wide.
///
/// RUNTIME-ONLY: a non-literal `id:` / `fingerprint_seed:` expression yields
/// `None` here and is skipped statically — the runtime persona boundary
/// (A5.1.2 vault) must assert single-active-persona and hard-fail instead
/// (`E5001-RT` / `E5003-RT`). Never guessed here.
fn collect_personas(program: &Program) -> Vec<PersonaUse> {
    let mut out = Vec::new();
    each_fn(program, |f| {
        for ann in &f.annotations {
            if ann.name == "persona" {
                out.push(PersonaUse {
                    fn_name: f.name.clone(),
                    id: ann_arg_str(ann, "id"),
                    seed: ann_arg_str(ann, "fingerprint_seed"),
                    span: ann.span,
                });
            }
        }
    });
    out
}

/// Collect all `@burn_plan` uses, program-wide (v1: annotation facts only —
/// the persona registry integration is A5.1.2's runtime, not this pass).
fn collect_burns(program: &Program) -> Vec<BurnUse> {
    let mut out = Vec::new();
    each_fn(program, |f| {
        for ann in &f.annotations {
            if ann.name == "burn_plan" {
                out.push(BurnUse {
                    fn_name: f.name.clone(),
                    persona: ann_arg_str(ann, "persona"),
                    span: ann.span,
                });
            }
        }
    });
    out
}

/// Collect all `@opsec_waiver` uses, program-wide.
fn collect_waivers(program: &Program) -> Vec<WaiverUse> {
    let mut out = Vec::new();
    each_fn(program, |f| {
        for ann in &f.annotations {
            if ann.name == "opsec_waiver" {
                out.push(WaiverUse {
                    rule: ann_arg_str(ann, "rule"),
                    reason: ann_arg_str(ann, "reason"),
                    reviewer: ann_arg_str(ann, "reviewer"),
                    fn_name: f.name.clone(),
                    span: ann.span,
                });
            }
        }
    });
    out
}

/// The program entry point, if any.
fn find_main(program: &Program) -> Option<&FnDecl> {
    program.items.iter().find_map(|item| match item {
        Item::Fn(f) if f.name == "main" => Some(f),
        _ => None,
    })
}

/// Build the intra-program call graph: fn name → called fn names (idents in
/// `Call` callees and `spawn` targets). Method calls are not local functions
/// and are skipped; stdlib names may appear as leaves — harmless for the
/// membership tests this graph feeds.
fn call_graph(program: &Program) -> HashMap<String, Vec<String>> {
    let mut g: HashMap<String, Vec<String>> = HashMap::new();
    each_fn(program, |f| {
        let entry = g.entry(f.name.clone()).or_default();
        let mut visit = |e: &Expr| match &e.kind {
            ExprKind::Call { callee, .. } => {
                if let ExprKind::Ident(name) = &callee.kind {
                    entry.push(name.clone());
                }
            }
            ExprKind::Spawn { func, .. } => {
                if let ExprKind::Ident(name) = &func.kind {
                    entry.push(name.clone());
                }
            }
            _ => {}
        };
        walk_block(&f.body, &mut visit);
    });
    g
}

/// Names reachable from `root` (inclusive) over the call graph.
fn reachable_from(g: &HashMap<String, Vec<String>>, root: &str) -> Vec<String> {
    let mut seen: Vec<String> = vec![root.to_string()];
    let mut queue: VecDeque<String> = VecDeque::from([root.to_string()]);
    while let Some(n) = queue.pop_front() {
        if let Some(callees) = g.get(&n) {
            for c in callees {
                if !seen.contains(c) {
                    seen.push(c.clone());
                    queue.push_back(c.clone());
                }
            }
        }
    }
    seen
}

/// Cheap reachability refinement for E5001: does `from` reach `to`?
fn fn_reaches(g: &HashMap<String, Vec<String>>, from: &str, to: &str) -> bool {
    let mut seen: Vec<String> = vec![from.to_string()];
    let mut stack: Vec<String> = vec![from.to_string()];
    while let Some(n) = stack.pop() {
        if n == to {
            return true;
        }
        if let Some(callees) = g.get(&n) {
            for c in callees {
                if !seen.contains(c) {
                    seen.push(c.clone());
                    stack.push(c.clone());
                }
            }
        }
    }
    false
}

// ── Generic AST walkers (expression facts) ───────────────────────────────────
//
// Mirrors the walkers in the sibling passes, covering every ExprKind so the
// scan cannot silently miss a subtree.

fn walk_block<F: FnMut(&Expr)>(block: &Block, f: &mut F) {
    for stmt in &block.stmts {
        walk_stmt(stmt, f);
    }
}

fn walk_stmt<F: FnMut(&Expr)>(stmt: &Stmt, f: &mut F) {
    match &stmt.kind {
        StmtKind::Let { value, .. }
        | StmtKind::Var { value, .. }
        | StmtKind::LetDestructure { value, .. }
        | StmtKind::Bail(value) => walk_expr(value, f),
        StmtKind::Expr { expr } => walk_expr(expr, f),
        StmtKind::Return(Some(expr)) => walk_expr(expr, f),
        StmtKind::Return(None) | StmtKind::Break | StmtKind::Continue => {}
        StmtKind::For { iter, body, .. } => {
            walk_expr(iter, f);
            walk_block(body, f);
        }
        StmtKind::While { condition, body } => {
            walk_expr(condition, f);
            walk_block(body, f);
        }
        StmtKind::WhileLet { expr, body, .. } => {
            walk_expr(expr, f);
            walk_block(body, f);
        }
        StmtKind::Loop { body } | StmtKind::Defer { body } => walk_block(body, f),
    }
}

fn walk_expr<F: FnMut(&Expr)>(expr: &Expr, f: &mut F) {
    f(expr);
    match &expr.kind {
        ExprKind::Call { callee, args } => {
            walk_expr(callee, f);
            for a in args {
                walk_expr(&a.value, f);
            }
        }
        ExprKind::MethodCall { object, args, .. } => {
            walk_expr(object, f);
            for a in args {
                walk_expr(&a.value, f);
            }
        }
        ExprKind::FieldAccess { object, .. } => walk_expr(object, f),
        ExprKind::Index { object, index } => {
            walk_expr(object, f);
            walk_expr(index, f);
        }
        ExprKind::Binary { left, right, .. } => {
            walk_expr(left, f);
            walk_expr(right, f);
        }
        ExprKind::Unary { operand, .. } => walk_expr(operand, f),
        ExprKind::If {
            condition,
            then_block,
            else_branch,
        } => {
            walk_expr(condition, f);
            walk_block(then_block, f);
            if let Some(eb) = else_branch {
                match eb {
                    ElseBranch::Block(b) => walk_block(b, f),
                    ElseBranch::ElseIf(e) => walk_expr(e, f),
                }
            }
        }
        ExprKind::IfLet {
            expr: scrutinee,
            then_block,
            else_branch,
            ..
        } => {
            walk_expr(scrutinee, f);
            walk_block(then_block, f);
            if let Some(eb) = else_branch {
                match eb {
                    ElseBranch::Block(b) => walk_block(b, f),
                    ElseBranch::ElseIf(e) => walk_expr(e, f),
                }
            }
        }
        ExprKind::Match { subject, arms } => {
            walk_expr(subject, f);
            for arm in arms {
                walk_expr(&arm.body, f);
            }
        }
        ExprKind::Block(b) => walk_block(b, f),
        ExprKind::Array(elems) => {
            for e in elems {
                walk_expr(e, f);
            }
        }
        ExprKind::MapLit(pairs) => {
            for (k, v) in pairs {
                walk_expr(k, f);
                walk_expr(v, f);
            }
        }
        ExprKind::Try(inner) | ExprKind::Await(inner) => walk_expr(inner, f),
        ExprKind::Assign { target, value } => {
            walk_expr(target, f);
            walk_expr(value, f);
        }
        ExprKind::StructLit { fields, spread, .. } => {
            for fl in fields {
                walk_expr(&fl.value, f);
            }
            if let Some(s) = spread {
                walk_expr(s, f);
            }
        }
        ExprKind::Cast { expr: inner, .. } => walk_expr(inner, f),
        ExprKind::Interpolation(parts) => {
            for p in parts {
                if let StringPart::Expr(e) = p {
                    walk_expr(e, f);
                }
            }
        }
        ExprKind::Closure { body, .. } => {
            for s in body {
                walk_stmt(s, f);
            }
        }
        ExprKind::Bail(inner) => walk_expr(inner, f),
        ExprKind::Spawn { func, args } => {
            walk_expr(func, f);
            for a in args {
                walk_expr(a, f);
            }
        }
        ExprKind::Select { cases, default } => {
            for c in cases {
                match &c.op {
                    SelectOp::Recv(ch) => walk_expr(ch, f),
                    SelectOp::Send { ch, val } => {
                        walk_expr(ch, f);
                        walk_expr(val, f);
                    }
                }
                walk_expr(&c.body, f);
            }
            if let Some(d) = default {
                walk_expr(d, f);
            }
        }
        ExprKind::IntLit(_)
        | ExprKind::FloatLit(_)
        | ExprKind::StringLit(_)
        | ExprKind::BoolLit(_)
        | ExprKind::Nil
        | ExprKind::Ident(_)
        | ExprKind::DotIdent(_) => {}
    }
}

// ── The pass ─────────────────────────────────────────────────────────────────

/// Program-level OPSEC policy pass (E5001–E5004 + W5001 waivers).
///
/// Mirrors the sibling passes' shape: `new(&Program, &TypeEnv)` then
/// `.check() -> Diagnostics`. Not wired into the build here (A5.2.2 call site
/// is the parent's).
pub struct OpsecGatesPass<'a> {
    program: &'a Program,
    env: &'a TypeEnv,
    pub diags: Diagnostics,
    /// All `@opsec_waiver` uses, collected once in `new`.
    waivers: Vec<WaiverUse>,
    /// `(rule, fn)` pairs already reported via W5001 — avoids flooding.
    waiver_reported: HashSet<String>,
}

impl<'a> OpsecGatesPass<'a> {
    pub fn new(program: &'a Program, env: &'a TypeEnv) -> Self {
        Self {
            program,
            env,
            diags: Diagnostics::new(),
            waivers: collect_waivers(program),
            waiver_reported: HashSet::new(),
        }
    }

    /// Run the program-policy gates. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        self.check_identity_mixing();
        self.check_direct_egress();
        self.check_fingerprint_reuse();
        self.check_plan_bundle();
        self.diags
    }

    // ── Waiver plumbing ─────────────────────────────────────────────────

    /// Is `rule` waived at `fn_name` (or at program scope, `main`)?
    /// When it suppresses, records W5001 so the escape is visible.
    fn waiver_suppresses(&mut self, rule: &str, fn_name: &str) -> bool {
        let found = self
            .waivers
            .iter()
            .find(|w| {
                w.rule.as_deref() == Some(rule) && (w.fn_name == fn_name || w.fn_name == "main")
            })
            .cloned();
        match found {
            Some(w) => {
                self.note_waiver(&w);
                true
            }
            None => false,
        }
    }

    /// Emit the (deduplicated) W5001 "waiver in effect" warning.
    fn note_waiver(&mut self, w: &WaiverUse) {
        let key = format!("{}::{}", w.rule.clone().unwrap_or_default(), w.fn_name);
        if !self.waiver_reported.insert(key) {
            return;
        }
        self.diags.push(
            Diagnostic::warning(
                "W5001",
                format!(
                    "opsec waiver in effect: rule `{}` waived on `{}` by reviewer '{}' (reason: '{}') — \
                     the escape is logged in this build, not silent",
                    w.rule.clone().unwrap_or_else(|| "?".into()),
                    w.fn_name,
                    w.reviewer.clone().unwrap_or_else(|| "unspecified".into()),
                    w.reason.clone().unwrap_or_else(|| "unspecified".into()),
                ),
                w.span,
            )
            .with_help(
                "waivers are single-rule and auditable; remove once the underlying condition is \
                 resolved (A5.2.1 §4)",
            ),
        );
    }

    // ── E5001 · identity mixing ─────────────────────────────────────────

    fn check_identity_mixing(&mut self) {
        let program = self.program;
        let personas = collect_personas(program);
        if personas.len() < 2 {
            return;
        }

        // Distinct literal ids, in program order, with their first site.
        // RUNTIME-ONLY: personas whose `id:` is a non-literal expression are
        // skipped statically — the runtime persona-use boundary (A5.1.2 vault)
        // asserts a single active persona per run and hard-fails (E5001-RT).
        let mut id_sites: Vec<(String, String)> = Vec::new();
        for p in &personas {
            if let Some(id) = &p.id {
                if !id_sites.iter().any(|(i, _)| i == id) {
                    id_sites.push((id.clone(), p.fn_name.clone()));
                }
            }
        }
        if id_sites.len() <= 1 {
            return;
        }

        // Deterministic error site: the annotation that first introduced a
        // second distinct id.
        let mut first_seen: Vec<String> = Vec::new();
        let mut site: Option<PersonaUse> = None;
        for p in &personas {
            if let Some(id) = &p.id {
                if !first_seen.contains(id) {
                    if first_seen.is_empty() {
                        first_seen.push(id.clone());
                    } else {
                        site = Some(p.clone());
                        break;
                    }
                }
            }
        }
        let Some(site) = site else { return };

        // Cheap reachability refinement (A5.2.1 §2): if two functions carrying
        // *different* persona ids are connected by call edges, the composition
        // leak also exists dynamically (shared process state). The rule fires
        // on |distinct ids| > 1 regardless; this only sharpens the message.
        let graph = call_graph(program);
        let mut reach_note = String::new();
        'pairs: for (i, a) in personas.iter().enumerate() {
            for b in personas.iter().skip(i + 1) {
                let (Some(ida), Some(idb)) = (&a.id, &b.id) else {
                    continue;
                };
                if ida == idb || a.fn_name == b.fn_name {
                    continue;
                }
                if fn_reaches(&graph, &a.fn_name, &b.fn_name)
                    || fn_reaches(&graph, &b.fn_name, &a.fn_name)
                {
                    reach_note = format!(
                        "; additionally `{}` (persona {ida}) and `{}` (persona {idb}) are \
                         connected in the call graph",
                        a.fn_name, b.fn_name
                    );
                    break 'pairs;
                }
            }
        }

        // E5001 is program-level: a waiver covering ANY conflicting persona
        // site (or `main`, via the fallback in `waiver_suppresses`) suppresses
        // it — module doc: "on the offending function or on `main`". Check
        // every persona site, not just the deterministic error site.
        let mut sites_to_check: Vec<String> =
            personas.iter().map(|p| p.fn_name.clone()).collect();
        sites_to_check.sort();
        sites_to_check.dedup();
        let mut waived = false;
        for f in &sites_to_check {
            if self.waiver_suppresses("E5001", f) {
                waived = true;
                break;
            }
        }
        if waived {
            return;
        }

        let sites = id_sites
            .iter()
            .map(|(id, f)| format!("{id} on `{f}`"))
            .collect::<Vec<_>>()
            .join(", ");
        self.diags.push(
            Diagnostic::error(
                "E5001",
                format!(
                    "identity mixing: program declares {} distinct @persona ids ({}); a program \
                     (build unit) must act as one identity — multi-persona work is compartmentation \
                     by build unit, split it into separate programs/packages{reach_note}",
                    id_sites.len(),
                    sites
                ),
                site.span,
            )
            .with_help(
                "one run = one cover. Split the personas into separate build units (A5.1.1); the \
                 only in-build escape is a logged @opsec_waiver(rule: \"E5001\", reason: ..., \
                 reviewer: ...)",
            ),
        );
    }

    // ── E5002 · direct-egress opt-out misuse ────────────────────────────

    fn check_direct_egress(&mut self) {
        let program = self.program;
        let mut facts: Vec<EgressFact> = Vec::new();

        each_fn(program, |f| {
            let fn_name = f.name.clone();
            let mut visit = |e: &Expr| {
                match &e.kind {
                    // (a) references the operator opt-out literal, e.g.
                    // `env.get("TALLOW_ALLOW_DIRECT")` / `env.set(...)`.
                    // Case-sensitive, exact-content match on the literal.
                    ExprKind::StringLit(s) if s == "TALLOW_ALLOW_DIRECT" => {
                        facts.push(EgressFact {
                            fn_name: fn_name.clone(),
                            span: e.span,
                            kind: EgressOptIn::FlagLiteral,
                        });
                    }
                    // (c) `allow_direct_egress: true` in struct/config data.
                    ExprKind::StructLit { fields, .. } => {
                        for fl in fields {
                            if fl.name == "allow_direct_egress"
                                && matches!(fl.value.kind, ExprKind::BoolLit(true))
                            {
                                facts.push(EgressFact {
                                    fn_name: fn_name.clone(),
                                    span: fl.span,
                                    kind: EgressOptIn::AllowDirectTrue,
                                });
                            }
                        }
                    }
                    // Same pair expressed as a map literal.
                    ExprKind::MapLit(pairs) => {
                        for (k, v) in pairs {
                            if let (ExprKind::StringLit(k), ExprKind::BoolLit(true)) =
                                (&k.kind, &v.kind)
                            {
                                if k == "allow_direct_egress" {
                                    facts.push(EgressFact {
                                        fn_name: fn_name.clone(),
                                        span: e.span,
                                        kind: EgressOptIn::AllowDirectTrue,
                                    });
                                }
                            }
                        }
                    }
                    _ => {}
                }
            };
            walk_block(&f.body, &mut visit);
        });

        // Const initializers are program data too.
        for item in &program.items {
            if let Item::Const(c) = item {
                let const_name = c.name.clone();
                let mut visit = |e: &Expr| {
                    if let ExprKind::StringLit(s) = &e.kind {
                        if s == "TALLOW_ALLOW_DIRECT" {
                            facts.push(EgressFact {
                                fn_name: const_name.clone(),
                                span: e.span,
                                kind: EgressOptIn::FlagLiteral,
                            });
                        }
                    }
                };
                walk_expr(&c.value, &mut visit);
            }
        }

        // RUNTIME-ONLY: whether the process env actually has the flag set is
        // checked by the egress layer at first network op (audit marking
        // `egress_direct=true`); a `.tl` program cannot decide it, and this
        // pass never guesses it. Test-only programs (path/target-based) are a
        // call-site concern: the pass sees no file path, so it treats every
        // program as production unless a waiver is present.
        for fact in facts {
            if self.waiver_suppresses("E5002", &fact.fn_name) {
                continue;
            }
            let detail = match fact.kind {
                EgressOptIn::FlagLiteral => {
                    "references the operator opt-out literal \"TALLOW_ALLOW_DIRECT\" (e.g. \
                     env.get/env.set)"
                }
                EgressOptIn::AllowDirectTrue => "sets `allow_direct_egress: true` in program data",
            };
            self.diags.push(
                Diagnostic::error(
                    "E5002",
                    format!(
                        "direct-egress opt-out misuse: function `{}` {detail}; the flag is a \
                         process-level operator decision, never a program affordance — a \
                         collection run must not be able to silently downgrade to direct egress",
                        fact.fn_name
                    ),
                    fact.span,
                )
                .with_help(
                    "remove the flag reference / opt-in, or carry a logged \
                     @opsec_waiver(rule: \"E5002\", reason: ..., reviewer: ...); direct egress \
                     for debug is an operator action (process env), not source code",
                ),
            );
        }
    }

    // ── E5003 · fingerprint / persona reuse ─────────────────────────────

    fn check_fingerprint_reuse(&mut self) {
        let program = self.program;
        let personas = collect_personas(program);
        let burns = collect_burns(program);

        // (a) burn-then-reuse: a persona whose @burn_plan disposal pairs on
        // one build unit must not be re-declared by @persona on ANOTHER unit
        // (the identity outlives its burn; the compliant pair — declaration
        // and disposal together — stays clean). Emitted per offending
        // @persona site so each reuse is independently waived/audited.
        // RUNTIME-ONLY: reuse across separate runs cannot be decided
        // statically — the A5.1.2 persona registry hard-fails and quarantines
        // on it (E5003-RT).
        let burned: Vec<(String, String)> = burns
            .iter()
            .filter_map(|b| b.persona.clone().map(|p| (p, b.fn_name.clone())))
            .collect();
        for p in &personas {
            let Some(id) = &p.id else { continue };
            let Some((_, burn_fn)) = burned.iter().find(|(bp, _)| bp == id) else {
                continue;
            };
            // Declaration + disposal pair in one unit (same function) is the
            // compliant pattern; a *different* unit re-declaring the disposed
            // id is the reuse this rule fires on.
            if &p.fn_name == burn_fn {
                continue;
            }
            if self.waiver_suppresses("E5003", &p.fn_name) {
                continue;
            }
            self.diags.push(
                Diagnostic::error(
                    "E5003",
                    format!(
                        "fingerprint/persona reuse: @persona(id: \"{id}\") on `{}` re-uses a \
                         persona already burned by @burn_plan on `{burn_fn}`; burn-then-reuse \
                         re-exposes everything the burn was meant to contain — a burned identity \
                         must never be re-used",
                        p.fn_name
                    ),
                    p.span,
                )
                .with_help(
                    "rotation must produce a fresh persona + seed per run (A5.1.3); cross-run \
                     reuse is hard-failed at runtime (E5003-RT) by the persona registry",
                ),
            );
        }

        // (b) shared fingerprint_seed across distinct persona ids. Literal
        // facts only; dynamic seeds / cross-run reuse are RUNTIME-ONLY (vault
        // registry). Same id seen twice is not flagged here — duplicate
        // declaration of one identity is not cross-persona reuse (the burn
        // rule (a) covers the dangerous same-id case).
        let mut seen: Vec<(String, String, String)> = Vec::new(); // (seed, id, fn)
        let mut reported_seeds: Vec<String> = Vec::new();
        for p in &personas {
            let (Some(id), Some(seed)) = (&p.id, &p.seed) else {
                continue;
            };
            if let Some((_, prev_id, prev_fn)) =
                seen.iter().find(|(s, i, _)| s == seed && i != id)
            {
                if !reported_seeds.contains(seed) {
                    reported_seeds.push(seed.clone());
                    if self.waiver_suppresses("E5003", &p.fn_name) {
                        continue;
                    }
                    self.diags.push(
                        Diagnostic::error(
                            "E5003",
                            format!(
                                "fingerprint/persona reuse: fingerprint_seed \"{seed}\" is shared \
                                 by distinct persona ids '{prev_id}' (on `{prev_fn}`) and '{id}' \
                                 (on `{}`); reusing one fingerprint links the two identities — \
                                 rotation must produce a fresh seed per persona",
                                p.fn_name
                            ),
                            p.span,
                        )
                        .with_help(
                            "give each persona its own unique fingerprint_seed literal, or carry \
                             @opsec_waiver(rule: \"E5003\", reason: ..., reviewer: ...) for an \
                             audited exception",
                        ),
                    );
                }
            }
            seen.push((seed.clone(), id.clone(), p.fn_name.clone()));
        }
    }

    // ── E5004 · missing plan bundle ─────────────────────────────────────

    fn check_plan_bundle(&mut self) {
        let program = self.program;
        let env = self.env;

        let Some(main_fn) = find_main(program) else {
            // No `main` → no program entry point, so "reachable from main" is
            // undefined; the collection-program rule is skipped rather than
            // guessed. Library-ish build units are outside this gate.
            return;
        };

        // Collection program = any fn in env.network_functions or
        // env.browser_nav_functions reachable from `main` (the same signals
        // legal_pass/stealth_pass consume: typeck's per-function scan).
        let graph = call_graph(program);
        let reachable = reachable_from(&graph, "main");
        let is_network = |n: &String| env.network_functions.iter().any(|f| f == n);
        let is_browser_nav = |n: &String| env.browser_nav_functions.iter().any(|f| f == n);
        let is_collection = reachable.iter().any(|n| is_network(n) || is_browser_nav(n));
        if !is_collection {
            return;
        }
        let uses_browser_nav = reachable.iter().any(is_browser_nav);

        // Program-scope annotations live on `main` (see module doc).
        let has = |name: &str| main_fn.annotations.iter().any(|a| a.name == name);
        let mut missing: Vec<&str> = Vec::new();
        if !has("legal") {
            missing.push("@legal");
        }
        if !has("cra_class") {
            missing.push("@cra_class");
        }
        if !has("persona") {
            missing.push("@persona");
        }
        if !has("burn_plan") {
            missing.push("@burn_plan");
        }
        if uses_browser_nav && !has("stealth") {
            missing.push("@stealth");
        }
        if missing.is_empty() {
            return;
        }

        if self.waiver_suppresses("E5004", "main") {
            return;
        }

        // Very common cause, worth naming: the plan block was written above a
        // HELPER fn instead of above `main`. Annotations attach to the next item,
        // so a helper placed between the block and `fn main` silently steals them
        // and the author sees "missing" for annotations they can see on screen.
        let mut misplaced: Option<String> = None;
        each_fn(program, |f| {
            if f.name != "main" && misplaced.is_none() {
                let carries_all = ["legal", "cra_class", "persona", "burn_plan"]
                    .iter()
                    .all(|n| f.annotations.iter().any(|a| a.name == *n));
                if carries_all {
                    misplaced = Some(f.name.clone());
                }
            }
        });

        // ONE combined error listing ONLY the missing categories (present
        // ones must not appear — the required-bundle recap lives in the
        // module doc). Complements, not replaces, E0100/E0400/W1900.
        let mut help = String::from(
            "add the missing annotations to `main` (program scope). \
             @burn_plan(persona: \"<id>\", after: .run, method: .revoke_and_quarantine, \
             artifacts: .quarantine) is the new disposal contract (A5.2.1 §2 E5004)",
        );
        if let Some(other) = misplaced {
            help.push_str(&format!(
                " — program scope is `main`, not `{other}`: this unit already carries the plan \
                 block on `{other}`. Annotations attach to the NEXT item, so move the block so it \
                 sits directly above `fn main` (keep helper fns BELOW `main`)."
            ));
        }
        self.diags.push(
            Diagnostic::error(
                "E5004",
                format!(
                    "collection program (network/browser-reachable from `main`) is missing \
                     required plan annotations at program scope: {} — one run = one cover, \
                     with a disposal plan",
                    missing.join(", ")
                ),
                main_fn.span,
            )
            .with_help(help),
        );
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;
    use crate::parser::Parser;
    use crate::typeck::TypeChecker;

    fn run_gates_pass(source: &str) -> Diagnostics {
        let (tokens, _) = lexer::tokenize(source);
        let program = Parser::parse(tokens).unwrap();
        let (env, _) = TypeChecker::new(&program).check();
        OpsecGatesPass::new(&program, &env).check()
    }

    fn has(diags: &Diagnostics, code: &str) -> bool {
        diags.items.iter().any(|d| d.code == code)
    }

    fn count(diags: &Diagnostics, code: &str) -> usize {
        diags.items.iter().filter(|d| d.code == code).count()
    }

    // ── E5001 ────────────────────────────────────────────────────────────

    #[test]
    fn e5001_identity_mixing_two_personas() {
        let diags = run_gates_pass(
            r#"
@legal(basis: .public_data, purpose: "corpus", personal_data: false)
@cra_class(.default)
@persona(id: "alex-01", cover_class: .journalist, compartment: "press-a")
fn collect_a() -> String {
    let r = fetch("https://example.org/a")
    r.text()
}

@persona(id: "morgan-02", cover_class: .researcher, compartment: "acad-b")
fn collect_b() -> String {
    let r = fetch("https://example.org/b")
    r.text()
}

fn main() {
    let a = collect_a()
    let b = collect_b()
    print(a + b)
}
"#,
        );
        assert!(has(&diags, "E5001"), "expected E5001, got: {:?}", diags.items);
        assert_eq!(count(&diags, "E5001"), 1, "one combined E5001 expected");
    }

    #[test]
    fn e5001_single_persona_ok() {
        let diags = run_gates_pass(
            r#"
@persona(id: "alex-01", cover_class: .journalist, compartment: "press-a")
fn collect_a() -> String { "a" }

fn main() { print(collect_a()) }
"#,
        );
        assert!(!has(&diags, "E5001"), "single persona must not mix: {:?}", diags.items);
        // No network/browser in this program — E5004 must not fire either.
        assert!(!has(&diags, "E5004"), "non-collection program: {:?}", diags.items);
    }

    #[test]
    fn e5001_waiver_suppresses_and_emits_w5001() {
        let diags = run_gates_pass(
            r#"
@opsec_waiver(rule: "E5001", reason: "benign dev sandbox", reviewer: "ops-lead")
@persona(id: "alpha-1", compartment: "x")
fn one() { print("1") }

@persona(id: "beta-2", compartment: "y")
fn two() { print("2") }

fn main() { one() }
"#,
        );
        assert!(!has(&diags, "E5001"), "waived rule must not error: {:?}", diags.items);
        assert!(has(&diags, "W5001"), "waiver must be visible as W5001: {:?}", diags.items);
    }

    // ── E5002 ────────────────────────────────────────────────────────────

    #[test]
    fn e5002_direct_egress_flag_literal() {
        let diags = run_gates_pass(
            r#"
@legal(basis: .public_data, purpose: "corpus", personal_data: false)
@cra_class(.default)
fn main() {
    let mode = env.get("TALLOW_ALLOW_DIRECT")
    if mode == "1" {
        print("direct egress requested by program logic")
    }
}
"#,
        );
        assert!(has(&diags, "E5002"), "expected E5002, got: {:?}", diags.items);
    }

    #[test]
    fn e5002_waiver_suppresses_and_emits_w5001() {
        let diags = run_gates_pass(
            r#"
@opsec_waiver(rule: "E5002", reason: "operator debug rescue", reviewer: "ops-lead")
@legal(basis: .public_data, purpose: "corpus", personal_data: false)
fn main() {
    let mode = env.get("TALLOW_ALLOW_DIRECT")
    print(mode)
}
"#,
        );
        assert!(!has(&diags, "E5002"), "waived rule must not error: {:?}", diags.items);
        assert!(has(&diags, "W5001"), "waiver must be visible as W5001: {:?}", diags.items);
    }

    #[test]
    fn e5002_allow_direct_egress_struct_literal() {
        let diags = run_gates_pass(
            r#"
struct HttpConfig { allow_direct_egress: bool }

@legal(basis: .public_data, purpose: "corpus", personal_data: false)
fn main() {
    let cfg = HttpConfig { allow_direct_egress: true }
    print("built")
}
"#,
        );
        assert!(has(&diags, "E5002"), "expected E5002 for config opt-in: {:?}", diags.items);
    }

    // ── E5003 ────────────────────────────────────────────────────────────

    #[test]
    fn e5003_burned_persona_reuse() {
        let diags = run_gates_pass(
            r#"
@burn_plan(persona: "p-7", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@legal(basis: .public_data, purpose: "corpus", personal_data: false)
@cra_class(.default)
fn main() {
    run_one()
}

@persona(id: "p-7", cover_class: .engineer, compartment: "lab-c", fingerprint_seed: "seed-abc123")
fn run_one() {
    print("one")
}
"#,
        );
        assert!(has(&diags, "E5003"), "expected E5003 burn-then-reuse: {:?}", diags.items);
    }

    #[test]
    fn e5003_shared_seed_across_distinct_personas() {
        // Note: two distinct personas also trip E5001 (by design); this test
        // targets the seed sub-rule specifically.
        let diags = run_gates_pass(
            r#"
@persona(id: "a-1", compartment: "x", fingerprint_seed: "seed-dup")
fn one() { print("1") }

@persona(id: "b-2", compartment: "y", fingerprint_seed: "seed-dup")
fn two() { print("2") }

fn main() {
    one()
    two()
}
"#,
        );
        assert!(has(&diags, "E5003"), "expected E5003 shared seed: {:?}", diags.items);
    }

    #[test]
    fn e5003_unique_seed_and_unrelated_burn_clean() {
        let diags = run_gates_pass(
            r#"
@burn_plan(persona: "old-9", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@persona(id: "fresh-1", compartment: "z", fingerprint_seed: "s1")
fn main() { print("ok") }
"#,
        );
        assert!(!has(&diags, "E5003"), "unrelated burn must not fire: {:?}", diags.items);
    }

    // ── E5004 ────────────────────────────────────────────────────────────

    #[test]
    fn e5004_missing_bundle_zero_annotations() {
        let diags = run_gates_pass(
            r#"
fn main() {
    let r = fetch("https://example.org/list")
    let browser = Browser.launch(true).unwrap()
    let page = browser.new_page().unwrap()
    page.goto("https://example.org/list")
    print(r.text())
    browser.close()
}
"#,
        );
        assert!(has(&diags, "E5004"), "expected E5004, got: {:?}", diags.items);
        assert_eq!(count(&diags, "E5004"), 1, "one combined E5004 expected");
        let msg = &diags.items.iter().find(|d| d.code == "E5004").unwrap().msg;
        for cat in ["@legal", "@cra_class", "@persona", "@burn_plan", "@stealth"] {
            assert!(msg.contains(cat), "message must list {cat}: {msg}");
        }
    }

    #[test]
    fn e5004_missing_burn_plan_only() {
        let diags = run_gates_pass(
            r#"
@legal(basis: .public_data, purpose: "corpus", personal_data: false)
@cra_class(.default)
@stealth(profile: .chrome_windows, evasions: .all)
@persona(id: "burnless-01", cover_class: .engineer, compartment: "lab-d", fingerprint_seed: "seed-77c1")
fn main() {
    let browser = Browser.launch(true).unwrap()
    let page = browser.new_page().unwrap()
    page.goto("https://example.org/report")
    browser.close()
}
"#,
        );
        assert!(has(&diags, "E5004"), "expected E5004, got: {:?}", diags.items);
        let msg = &diags.items.iter().find(|d| d.code == "E5004").unwrap().msg;
        assert!(msg.contains("@burn_plan"), "must name the missing burn plan: {msg}");
        assert!(!msg.contains("@legal"), "legal is present, must not be listed: {msg}");
        assert!(!msg.contains("@stealth"), "stealth is present, must not be listed: {msg}");
    }

    #[test]
    fn e5004_names_the_function_that_stole_the_plan_block() {
        // Annotations attach to the NEXT item, so a helper written between the
        // plan block and `fn main` steals it. The author sees "missing" for
        // annotations that are plainly on screen — name the culprit.
        let diags = run_gates_pass(
            r#"
@legal(basis: .public_data, purpose: "corpus", personal_data: false)
@cra_class(.default)
@persona(id: "misplaced-01", cover_class: .engineer, compartment: "lab-x", fingerprint_seed: "seed-11aa")
@burn_plan(persona: "misplaced-01", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
fn helper() -> String { "x" }

fn main() {
    let r = fetch("https://example.org/a")
    print(helper())
    print(r.text())
}
"#,
        );
        assert!(has(&diags, "E5004"), "expected E5004, got: {:?}", diags.items);
        let d = diags.items.iter().find(|d| d.code == "E5004").unwrap();
        let help = d.help.clone().unwrap_or_default();
        assert!(
            help.contains("`helper`"),
            "help must name the function holding the plan block: {help}"
        );
        assert!(
            help.contains("above `fn main`"),
            "help must state the fix (move the block above main): {help}"
        );
    }

    #[test]
    fn e5004_clean_control_stays_green() {
        let diags = run_gates_pass(
            r#"
@legal(basis: .public_data, purpose: "corpus: clean control", personal_data: false)
@cra_class(.default)
@persona(id: "control-01", cover_class: .researcher, compartment: "ctrl-1", fingerprint_seed: "ctrl-seed-4f9a")
@burn_plan(persona: "control-01", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
fn main() {
    let r = fetch("https://example.org/ok")
    print(r.text())
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "clean control must stay green, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn e5004_non_collection_program_ok() {
        let diags = run_gates_pass(
            r#"
fn main() {
    print("hello")
}
"#,
        );
        assert!(!has(&diags, "E5004"), "plain program is not a collection program: {:?}", diags.items);
    }

    #[test]
    fn e5004_waiver_suppresses_and_emits_w5001() {
        let diags = run_gates_pass(
            r#"
@opsec_waiver(rule: "E5004", reason: "internal dry-run tooling", reviewer: "ops-lead")
fn main() {
    let r = fetch("https://example.org/dry")
    print(r.text())
}
"#,
        );
        assert!(!has(&diags, "E5004"), "waived rule must not error: {:?}", diags.items);
        assert!(has(&diags, "W5001"), "waiver must be visible as W5001: {:?}", diags.items);
    }

    // ── Egress flag must not be confused with plain text ────────────────

    #[test]
    fn e5002_unrelated_string_no_error() {
        let diags = run_gates_pass(
            r#"
@legal(basis: .public_data, purpose: "corpus", personal_data: false)
fn main() {
    let s = "TALLOW_PROXY is respected by default"
    print(s)
}
"#,
        );
        assert!(!has(&diags, "E5002"), "only the exact flag literal is misuse: {:?}", diags.items);
    }
}
