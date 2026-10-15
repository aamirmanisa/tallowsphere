//! Compile-time fingerprint policy pass (agent-03 R-1 / matrix row #33).
//!
//! Forces every program that is a **browser/network program** (or that uses
//! any stealth/fingerprint feature) to declare, at program scope, its
//! **fingerprint policy** and **bot-identity stance**:
//!
//! ```tallow
//! @fingerprint_policy(
//!     policy: .normalize,                                    // .normalize | .cohort_uniform | .none
//!     bot_identity: "TallowScraper/0.1 (+https://example.org/bot)",  // literal, or .browser
//!     network: .hostile,                                     // .monitored (default) | .hostile
//! )
//! fn main() { ... }
//! ```
//!
//! Program-scope annotations live on `main` (the same convention E5004 uses
//! for `@legal` / `@persona` / `@burn_plan`). `@fingerprint_policy` is the
//! declaration these gates read; [`ProgramFingerprintPolicy`] is the parsed
//! form downstream consumers (codegen / runtime gates) can consult via
//! [`declared_policy`].
//!
//! # What the declaration means
//!
//! * `policy: .normalize` — fingerprints are normalized to the declared
//!   identity; per-session randomization is refused (uniqueness drift).
//! * `policy: .cohort_uniform` — a cohort must be a fixed set of *coherent*
//!   members; per-session randomization / rotation of attributes is refused.
//! * `policy: .none` — the program uses no stealth/fingerprint features at
//!   all; using one is refused.
//! * `bot_identity:` — either a string literal (the honest declared-bot
//!   identity, P-INV-4: `TallowScraper/<v> (+contact)`) or `.browser` (the
//!   sanctioned Chrome-for-Testing path is the only impersonation surface).
//! * `network: .monitored` (default) — the operator's own monitoring sees
//!   this traffic. Grey-zone features (TLS ClientHello/record fragmentation,
//!   ECH) are refused; declaring `network: .hostile` is the explicit opt-in
//!   for censored/hostile networks (grey-zone features stay opt-in,
//!   documented and policy-gated — agent-03 F10/R-1).
//!
//! # Gates (error codes)
//! * **E5100** — browser/network program (or feature-using program) has no
//!   `@fingerprint_policy` declaration on `main`.
//! * **E5101** — malformed declaration: unknown/missing `policy:` value,
//!   missing/invalid `bot_identity:`, unknown `network:` value.
//! * **E5102** — fingerprint randomization
//!   (`Fingerprint.generate` / `Fingerprint.rotate` /
//!   `StealthProfile.randomize`) under `policy: .normalize` or
//!   `.cohort_uniform` — random draws create *new unique* profiles and cannot
//!   be proven coherent at build time; use named fixed profiles.
//! * **E5103** — a stealth/fingerprint feature is used while `policy: .none`.
//! * **E5104** — grey-zone feature (TLS fragmentation / ECH) used in
//!   `network: .monitored` mode; must opt in with `network: .hostile`.
//! * **W5100** — declared-bot identity hygiene: missing version token and/or
//!   missing contact info.
//!
//! Escapes are the existing, logged `@opsec_waiver(rule: "...", reason: ...,
//! reviewer: ...)` annotation (same vocabulary as the sibling E5001–E5004
//! gates: the waiver suppresses the rule and emits W5001, never silently).
//!
//! # Scope note
//! This pass is static: it gates *sources* (annotations, known stdlib
//! calls, data flags). Runtime-enforced properties (actual coherence of a
//! generated profile, actual fragmentation on the wire) are out of scope and
//! belong to the runtime audit (U-102 / agent-03 R-2). Fragment/ECH module
//! detection matches receiver-module names so future surfaces are covered by
//! the same gate; today no `.tl`-callable fragment module exists, and the
//! `stealth: true` / `@stealth` / `@fingerprint` / `Fingerprint.*` /
//! `StealthProfile.*` / `AntiDetect.*` surfaces are the live ones.

use crate::ast::*;
use crate::error::{Diagnostic, Diagnostics};
use crate::lexer::Span;
use crate::typeck::TypeEnv;

// ── Feature taxonomy ─────────────────────────────────────────────────────────

/// The declaration argument names and valid values.
pub const ANNOTATION_NAME: &str = "fingerprint_policy";
const VALID_POLICIES: &[&str] = &["normalize", "cohort_uniform", "none"];
const VALID_NETWORK_MODES: &[&str] = &["monitored", "hostile"];

/// Fingerprint posture declared by `policy:`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintPosture {
    /// Normalize to the declared identity; no per-session randomization.
    Normalize,
    /// Fixed, coherent cohort members; no per-session randomization.
    CohortUniform,
    /// No stealth/fingerprint features used at all.
    NoFeatures,
}

impl FingerprintPosture {
    fn from_ident(s: &str) -> Option<Self> {
        match s {
            "normalize" => Some(Self::Normalize),
            "cohort_uniform" => Some(Self::CohortUniform),
            "none" => Some(Self::NoFeatures),
            _ => None,
        }
    }
}

/// Bot-identity stance declared by `bot_identity:`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BotIdentity {
    /// Honest declared-bot identity literal (P-INV-4), e.g.
    /// `"TallowScraper/0.1 (+https://example.org/bot)"`.
    Declared(String),
    /// The sanctioned browser path is the only impersonation surface.
    Browser,
}

/// Network trust mode declared by `network:` (default `.monitored`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// Operator's own monitoring sees this traffic — grey-zone features refused.
    Monitored,
    /// Explicit opt-in for censored/hostile networks (fragmentation/ECH allowed).
    Hostile,
}

/// Parsed, valid program-scope fingerprint policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramFingerprintPolicy {
    pub posture: FingerprintPosture,
    pub bot_identity: BotIdentity,
    pub network: NetworkMode,
}

/// Parse a program's `@fingerprint_policy` declaration without diagnostics
/// (missing/invalid values yield `None`). Downstream consumers use this to
/// consult the declared posture; the pass itself reports E5100/E5101.
pub fn declared_policy(program: &Program) -> Option<ProgramFingerprintPolicy> {
    let main_fn = find_main(program)?;
    let ann = main_fn.annotations.iter().find(|a| a.name == ANNOTATION_NAME)?;
    let posture = FingerprintPosture::from_ident(&ann_arg_ident(ann, "policy")?)?;
    let bot_identity = match ann_arg_bot_identity(ann)? {
        BotId::Literal(s) if !s.is_empty() => BotIdentity::Declared(s),
        BotId::Browser => BotIdentity::Browser,
        _ => return None,
    };
    let network = match ann_arg_ident(ann, "network") {
        None => NetworkMode::Monitored,
        Some(v) => match v.as_str() {
            "monitored" => NetworkMode::Monitored,
            "hostile" => NetworkMode::Hostile,
            _ => return None,
        },
    };
    Some(ProgramFingerprintPolicy {
        posture,
        bot_identity,
        network,
    })
}

// ── Gated feature vocabulary ─────────────────────────────────────────────────
//
// These tables are the *sources* the gate understands. `RANDOMIZATION` draws
// fresh attribute values per call (the incoherent-randomization hazard);
// `STEALTH` are the named-profile/evasion surfaces; fragment/ECH modules are
// detected by receiver name so future `.tl` surfaces ride the same gate.

const RANDOMIZATION_CALLS: &[(&str, &str)] = &[
    ("Fingerprint", "generate"),
    ("Fingerprint", "rotate"),
    ("StealthProfile", "randomize"),
];

const STEALTH_CALLS: &[(&str, &str)] = &[
    ("StealthProfile", "create"),
    ("Fingerprint", "inject_js"),
    ("Fingerprint", "to_headers"),
    ("AntiDetect", "check"),
    ("AntiDetect", "fingerprint"),
    ("AntiDetect", "webrtc_leak_check"),
];

/// Audit-only surfaces that never gate (reading the current browser
/// fingerprint / validating a profile changes no posture).
const AUDIT_ONLY_CALLS: &[(&str, &str)] = &[("StealthProfile", "validate")];

/// Which gated family a detected site belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FeatureKind {
    /// Randomization draws (grey to coherence; refused under normalize/cohort).
    Randomization,
    /// Named-profile / evasion / probe surfaces.
    Stealth,
    /// `@stealth(...)` annotation.
    AnnotationStealth,
    /// `@fingerprint(...)` annotation (pins a client profile).
    AnnotationFingerprint,
    /// TLS ClientHello/record fragmentation ("fragment" receiver module).
    Fragment,
    /// ECH config/call surface ("ECH"/"Ech" receiver module).
    Ech,
    /// `stealth: true` flag in program data.
    StealthFlag,
}

impl FeatureKind {
    /// Human label used in diagnostics.
    fn label(self) -> &'static str {
        match self {
            Self::Randomization => "fingerprint randomization",
            Self::Stealth => "stealth feature",
            Self::AnnotationStealth => "@stealth annotation",
            Self::AnnotationFingerprint => "@fingerprint annotation",
            Self::Fragment => "TLS fragmentation (grey-zone)",
            Self::Ech => "ECH (grey-zone)",
            Self::StealthFlag => "stealth flag (stealth: true)",
        }
    }

    /// Grey-zone features per agent-03 F10/R-1 (fragmentation + ECH): refused
    /// in `network: .monitored`.
    fn is_grey_zone(self) -> bool {
        matches!(self, Self::Fragment | Self::Ech)
    }
}

/// One detected use of a gated feature.
#[derive(Debug, Clone)]
struct FeatureUse {
    fn_name: String,
    kind: FeatureKind,
    /// Rendered call/flag site, e.g. `Fingerprint.generate()`.
    site: String,
    span: Span,
}

// ── Waivers (shared `@opsec_waiver` vocabulary) ──────────────────────────────

#[derive(Debug, Clone)]
struct WaiverUse {
    rule: Option<String>,
    reason: Option<String>,
    reviewer: Option<String>,
    fn_name: String,
    span: Span,
}

// ── Free helpers over the AST ────────────────────────────────────────────────

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

fn find_main(program: &Program) -> Option<&FnDecl> {
    program.items.iter().find_map(|item| match item {
        Item::Fn(f) if f.name == "main" => Some(f),
        _ => None,
    })
}

/// Named string-literal annotation argument.
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

/// Named `.ident` annotation argument.
fn ann_arg_ident(ann: &Annotation, arg_name: &str) -> Option<String> {
    for arg in &ann.args {
        if arg.name == arg_name {
            if let ExprKind::DotIdent(ref v) = arg.value.kind {
                return Some(v.clone());
            }
        }
    }
    None
}

/// `bot_identity:` value, in either accepted form.
enum BotId {
    Literal(String),
    Browser,
}

fn ann_arg_bot_identity(ann: &Annotation) -> Option<BotId> {
    for arg in &ann.args {
        if arg.name == "bot_identity" {
            return match &arg.value.kind {
                ExprKind::StringLit(s) => Some(BotId::Literal(s.clone())),
                ExprKind::DotIdent(v) if v == "browser" => Some(BotId::Browser),
                _ => None,
            };
        }
    }
    None
}

/// Collect `@opsec_waiver` uses program-wide (same annotation the E5001–E5004
/// gates consume).
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

/// Intra-program call graph (fn name → callee names), same shape the sibling
/// gates build; used for "reachable from `main`" program classification.
fn call_graph(program: &Program) -> std::collections::HashMap<String, Vec<String>> {
    use std::collections::HashMap;
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

fn reachable_from(
    g: &std::collections::HashMap<String, Vec<String>>,
    root: &str,
) -> Vec<String> {
    use std::collections::VecDeque;
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

// ── Generic AST walkers (mirrors the sibling passes; every ExprKind covered) ─

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

// ── Site classification ──────────────────────────────────────────────────────

/// Classify a `Module.method` call site, if it is a gated feature.
fn classify_call(module: &str, method: &str) -> Option<FeatureKind> {
    if AUDIT_ONLY_CALLS.contains(&(module, method)) {
        return None;
    }
    if RANDOMIZATION_CALLS.contains(&(module, method)) {
        return Some(FeatureKind::Randomization);
    }
    if STEALTH_CALLS.contains(&(module, method)) {
        return Some(FeatureKind::Stealth);
    }
    let lower = module.to_ascii_lowercase();
    if lower.contains("fragment") {
        return Some(FeatureKind::Fragment);
    }
    if module == "ECH" || module.starts_with("Ech") {
        return Some(FeatureKind::Ech);
    }
    None
}

// ── The pass ─────────────────────────────────────────────────────────────────

/// Compile-time fingerprint policy pass (E5100–E5104, W5100, W5001 waivers).
///
/// Shape matches the sibling passes: `new(&Program, &TypeEnv)` then
/// `.check() -> Diagnostics`. The parsed declaration stays available through
/// [`declared_policy`] for downstream consumers.
pub struct FingerprintPolicyPass<'a> {
    program: &'a Program,
    env: &'a TypeEnv,
    pub diags: Diagnostics,
    waivers: Vec<WaiverUse>,
    waiver_reported: std::collections::HashSet<String>,
    /// Parsed declaration, when present and structurally valid.
    policy: Option<ProgramFingerprintPolicy>,
}

impl<'a> FingerprintPolicyPass<'a> {
    pub fn new(program: &'a Program, env: &'a TypeEnv) -> Self {
        Self {
            program,
            env,
            diags: Diagnostics::new(),
            waivers: collect_waivers(program),
            waiver_reported: std::collections::HashSet::new(),
            policy: None,
        }
    }

    /// The parsed declaration as seen by `check()` (Valid after `check`).
    pub fn declared(&self) -> Option<&ProgramFingerprintPolicy> {
        self.policy.as_ref()
    }

    /// Run the fingerprint policy gates. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        // Bind the `'a` references first so program/typeck borrows never
        // overlap the `&mut self` needed for waiver bookkeeping.
        let program = self.program;
        let env = self.env;

        let features = self.collect_features();
        let main_fn = find_main(program);

        // ── Program classification: browser/network reachable from `main` ──
        let is_network_program = match main_fn {
            Some(_) => {
                let graph = call_graph(program);
                let reachable = reachable_from(&graph, "main");
                reachable.iter().any(|n| {
                    env.network_functions.iter().any(|f| f == n)
                        || env.browser_nav_functions.iter().any(|f| f == n)
                })
            }
            None => {
                // No entry point to anchor "reachable"; any network/browser
                // function in the unit still marks it as a collection unit.
                !env.network_functions.is_empty() || !env.browser_nav_functions.is_empty()
            }
        };

        // ── E5100 · missing program-scope declaration ───────────────────────
        let decl_ann = main_fn.and_then(|f| {
            f.annotations
                .iter()
                .find(|a| a.name == ANNOTATION_NAME)
                .cloned()
        });

        if decl_ann.is_none() {
            if is_network_program || !features.is_empty() {
                // Program-level rule: a waiver for E5100 may live on `main` or
                // on any feature site (single-rule, still logged via W5001).
                if !self.waiver_for_rule_anywhere("E5100") {
                    let anchor = main_fn
                        .map(|f| f.span)
                        .or_else(|| features.first().map(|u| u.span));
                    if let Some(span) = anchor {
                        self.diags.push(
                            Diagnostic::error(
                                "E5100",
                                format!(
                                    "{} without a program-scope fingerprint policy: this build \
                                     unit is a browser/network program or uses {} stealth/\
                                     fingerprint feature site(s), but declares no \
                                     @fingerprint_policy on `main` — the fingerprint posture and \
                                     bot-identity stance must be auditable in source",
                                    if is_network_program {
                                        "browser/network program"
                                    } else {
                                        "feature-using program"
                                    },
                                    features.len()
                                ),
                                span,
                            )
                            .with_help(
                                "add to `main`: @fingerprint_policy(policy: .normalize | \
                                 .cohort_uniform | .none, bot_identity: \"TallowScraper/0.1 \
                                 (+contact)\" | .browser, network: .monitored | .hostile); \
                                 escape only via a logged @opsec_waiver(rule: \"E5100\", ...)",
                            ),
                        );
                    }
                }
            }
            // Without a declaration there is nothing to gate against; one
            // program-level diagnostic is enough (never a per-site flood).
            return self.diags;
        }

        // ── E5101 · malformed declaration ───────────────────────────────────
        let Some(ann) = decl_ann else { unreachable!() };
        let mut posture: Option<FingerprintPosture> = None;
        let mut bot_identity: Option<BotIdentity> = None;
        let mut network = NetworkMode::Monitored;

        match ann_arg_ident(&ann, "policy") {
            Some(v) => match FingerprintPosture::from_ident(&v) {
                Some(p) => posture = Some(p),
                None => self.diags.push(
                    Diagnostic::error(
                        "E5101",
                        format!("unknown fingerprint policy: .{v}"),
                        ann.span,
                    )
                    .with_help(format!(
                        "valid policies: {}",
                        VALID_POLICIES
                            .iter()
                            .map(|p| format!(".{p}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                ),
            },
            None => self.diags.push(
                Diagnostic::error(
                    "E5101",
                    "@fingerprint_policy requires a `policy:` argument \
                     (.normalize | .cohort_uniform | .none)",
                    ann.span,
                )
                .with_help(
                    "e.g. @fingerprint_policy(policy: .normalize, bot_identity: \
                     \"TallowScraper/0.1 (+contact)\")",
                ),
            ),
        }

        match ann_arg_bot_identity(&ann) {
            Some(BotId::Literal(s)) if !s.is_empty() => {
                // W5100 · declared-bot identity hygiene (P-INV-4):
                // `TallowScraper/<version> (+contact)`.
                let has_version = s
                    .split('/')
                    .nth(1)
                    .map(|rest| {
                        rest.chars()
                            .next()
                            .map(|c| c.is_ascii_digit())
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                if !has_version {
                    self.diags.push(
                        Diagnostic::warning(
                            "W5100",
                            format!(
                                "declared bot identity \"{s}\" carries no version token \
                                 (TallowScraper/<version>); versioned identities let servers \
                                 route, rate-limit and contact the crawler correctly"
                            ),
                            ann.span,
                        )
                        .with_help("e.g. bot_identity: \"TallowScraper/0.1 (+https://example.org/bot)\""),
                    );
                }
                let has_contact = s.contains("http") || s.contains('@');
                if !has_contact {
                    self.diags.push(
                        Diagnostic::warning(
                            "W5100",
                            format!(
                                "declared bot identity \"{s}\" has no contact information; \
                                 recommended form is `TallowScraper/<version> (+contact-url)` \
                                 so operators can reach you before blocking"
                            ),
                            ann.span,
                        )
                        .with_help("e.g. bot_identity: \"TallowScraper/0.1 (+https://example.org/bot)\""),
                    );
                }
                bot_identity = Some(BotIdentity::Declared(s));
            }
            Some(BotId::Browser) => {
                bot_identity = Some(BotIdentity::Browser);
            }
            Some(BotId::Literal(_)) => {
                self.diags.push(
                    Diagnostic::error(
                        "E5101",
                        "@fingerprint_policy `bot_identity:` string literal must not be empty",
                        ann.span,
                    )
                    .with_help("declare e.g. \"TallowScraper/0.1 (+https://example.org/bot)\""),
                );
            }
            None => {
                // Distinguish "present but wrong type" from "absent".
                let has_arg = ann.args.iter().any(|a| a.name == "bot_identity");
                let msg = if has_arg {
                    "@fingerprint_policy `bot_identity:` must be a string literal (the declared \
                     bot identity) or `.browser` (sanctioned browser path only)"
                } else {
                    "@fingerprint_policy requires a `bot_identity:` argument (literal or .browser)"
                };
                self.diags.push(
                    Diagnostic::error("E5101", msg, ann.span).with_help(
                        "e.g. bot_identity: \"TallowScraper/0.1 (+https://example.org/bot)\" or \
                         bot_identity: .browser",
                    ),
                );
            }
        }

        if let Some(v) = ann_arg_ident(&ann, "network") {
            match v.as_str() {
                "monitored" => network = NetworkMode::Monitored,
                "hostile" => network = NetworkMode::Hostile,
                _ => self.diags.push(
                    Diagnostic::error(
                        "E5101",
                        format!("unknown network mode: .{v}"),
                        ann.span,
                    )
                    .with_help(format!(
                        "valid network modes: {} (default .monitored)",
                        VALID_NETWORK_MODES
                            .iter()
                            .map(|p| format!(".{p}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                ),
            }
        }

        let (Some(posture), Some(bot_identity)) = (posture, bot_identity) else {
            // Malformed declaration: gates cannot be evaluated against a
            // posture that was never validly declared.
            return self.diags;
        };

        self.policy = Some(ProgramFingerprintPolicy {
            posture,
            bot_identity,
            network,
        });

        // ── Per-site gates ─────────────────────────────────────────────────
        // Precedence per site: E5104 (monitored grey-zone) > E5103 (.none) >
        // E5102 (randomization under normalize/cohort_uniform).
        for use_site in &features {
            let rule = if network == NetworkMode::Monitored && use_site.kind.is_grey_zone() {
                "E5104"
            } else if posture == FingerprintPosture::NoFeatures {
                "E5103"
            } else if use_site.kind == FeatureKind::Randomization
                && matches!(
                    posture,
                    FingerprintPosture::Normalize | FingerprintPosture::CohortUniform
                )
            {
                "E5102"
            } else {
                continue;
            };

            if self.waiver_suppresses(rule, &use_site.fn_name) {
                continue;
            }

            match rule {
                "E5104" => self.report_monitored(use_site),
                "E5103" => self.report_none_posture(use_site),
                "E5102" => self.report_randomization(use_site, posture),
                _ => {}
            }
        }

        self.diags
    }

    // ── Feature collection ──────────────────────────────────────────────

    fn collect_features(&self) -> Vec<FeatureUse> {
        let mut out: Vec<FeatureUse> = Vec::new();
        each_fn(self.program, |f| {
            let fn_name = f.name.clone();
            for ann in &f.annotations {
                match ann.name.as_str() {
                    "stealth" => out.push(FeatureUse {
                        fn_name: fn_name.clone(),
                        kind: FeatureKind::AnnotationStealth,
                        site: "@stealth".to_string(),
                        span: ann.span,
                    }),
                    "fingerprint" => out.push(FeatureUse {
                        fn_name: fn_name.clone(),
                        kind: FeatureKind::AnnotationFingerprint,
                        site: "@fingerprint".to_string(),
                        span: ann.span,
                    }),
                    _ => {}
                }
            }

            let record_call = |module: &str, method: &str, span: Span, out: &mut Vec<FeatureUse>| {
                if let Some(kind) = classify_call(module, method) {
                    out.push(FeatureUse {
                        fn_name: fn_name.clone(),
                        kind,
                        site: format!("{module}.{method}()"),
                        span,
                    });
                }
            };

            let mut visit = |e: &Expr| match &e.kind {
                // `Module.method(args)` — the live stdlib surface.
                ExprKind::MethodCall { object, method, .. } => {
                    if let ExprKind::Ident(m) = &object.kind {
                        record_call(m, method, e.span, &mut out);
                    }
                }
                // Defensive: `Module.method(args)` seen as a field-access callee.
                ExprKind::Call { callee, .. } => {
                    if let ExprKind::FieldAccess { object, field } = &callee.kind {
                        if let ExprKind::Ident(m) = &object.kind {
                            record_call(m, field, e.span, &mut out);
                        }
                    }
                }
                // `... {stealth: true}` struct-literal flag.
                ExprKind::StructLit { fields, .. } => {
                    for fl in fields {
                        if fl.name == "stealth"
                            && matches!(fl.value.kind, ExprKind::BoolLit(true))
                        {
                            out.push(FeatureUse {
                                fn_name: fn_name.clone(),
                                kind: FeatureKind::StealthFlag,
                                site: "stealth: true".to_string(),
                                span: fl.span,
                            });
                        }
                    }
                }
                // `{"stealth": true}` / `{stealth: true}` map-literal flag
                // (bare-ident keys parse as `Ident`, quoted keys as `StringLit`).
                ExprKind::MapLit(pairs) => {
                    for (k, v) in pairs {
                        if !matches!(v.kind, ExprKind::BoolLit(true)) {
                            continue;
                        }
                        let key = match &k.kind {
                            ExprKind::StringLit(s) => Some(s.as_str()),
                            ExprKind::Ident(s) => Some(s.as_str()),
                            _ => None,
                        };
                        if key == Some("stealth") {
                            out.push(FeatureUse {
                                fn_name: fn_name.clone(),
                                kind: FeatureKind::StealthFlag,
                                site: "\"stealth\": true".to_string(),
                                span: e.span,
                            });
                        }
                    }
                }
                _ => {}
            };
            walk_block(&f.body, &mut visit);
        });
        out
    }

    // ── Waiver plumbing (same semantics as the E5001–E5004 gates) ───────

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

    /// Program-level lookup: any `@opsec_waiver(rule: ...)` site counts
    /// (used for E5100, which is reported on `main` regardless of where the
    /// offending feature sites live).
    fn waiver_for_rule_anywhere(&mut self, rule: &str) -> bool {
        let found = self
            .waivers
            .iter()
            .find(|w| w.rule.as_deref() == Some(rule))
            .cloned();
        match found {
            Some(w) => {
                self.note_waiver(&w);
                true
            }
            None => false,
        }
    }

    fn note_waiver(&mut self, w: &WaiverUse) {
        let key = format!("{}::{}", w.rule.clone().unwrap_or_default(), w.fn_name);
        if !self.waiver_reported.insert(key) {
            return;
        }
        self.diags.push(
            Diagnostic::warning(
                "W5001",
                format!(
                    "opsec waiver in effect: fingerprint rule `{}` waived on `{}` by reviewer \
                     '{}' (reason: '{}') — the escape is logged in this build, not silent",
                    w.rule.clone().unwrap_or_else(|| "?".into()),
                    w.fn_name,
                    w.reviewer.clone().unwrap_or_else(|| "unspecified".into()),
                    w.reason.clone().unwrap_or_else(|| "unspecified".into()),
                ),
                w.span,
            )
            .with_help(
                "waivers are single-rule and auditable; remove once the underlying condition \
                 is resolved (agent-03 R-1)",
            ),
        );
    }

    // ── Per-site reporters ───────────────────────────────────────────────

    fn report_monitored(&mut self, u: &FeatureUse) {
        self.diags.push(
            Diagnostic::error(
                "E5104",
                format!(
                    "monitored-network refusal: `{}` uses {} at {} — in `network: .monitored` \
                     mode the operator's own monitoring sees this traffic, and grey-zone \
                     features deliberately evade the classification that monitoring relies on",
                    u.fn_name,
                    u.kind.label(),
                    u.site
                ),
                u.span,
            )
            .with_help(
                "grey-zone features stay opt-in: declare `network: .hostile` in \
                 @fingerprint_policy on `main` only for genuinely censored/hostile networks, \
                 or carry a logged @opsec_waiver(rule: \"E5104\", reason: ..., reviewer: ...)",
            ),
        );
    }

    fn report_none_posture(&mut self, u: &FeatureUse) {
        self.diags.push(
            Diagnostic::error(
                "E5103",
                format!(
                    "fingerprint policy `none` violated: `{}` uses {} at {}, but the program \
                     declared policy: .none — a `.none` posture promises no stealth/fingerprint \
                     features are used",
                    u.fn_name,
                    u.kind.label(),
                    u.site
                ),
                u.span,
            )
            .with_help(
                "either remove the feature, or declare the real posture \
                 (.normalize / .cohort_uniform) in @fingerprint_policy on `main`; escape only \
                 via a logged @opsec_waiver(rule: \"E5103\", ...)",
            ),
        );
    }

    fn report_randomization(&mut self, u: &FeatureUse, posture: FingerprintPosture) {
        let posture_name = match posture {
            FingerprintPosture::Normalize => ".normalize",
            FingerprintPosture::CohortUniform => ".cohort_uniform",
            FingerprintPosture::NoFeatures => ".none",
        };
        self.diags.push(
            Diagnostic::error(
                "E5102",
                format!(
                    "incoherent randomization: `{}` calls {} at {}, but policy {} requires {}; \
                     random attribute draws create new unique profiles per session and cannot \
                     be proven coherent at build time",
                    u.fn_name,
                    u.kind.label(),
                    u.site,
                    posture_name,
                    if posture == FingerprintPosture::CohortUniform {
                        "a fixed set of coherent cohort members"
                    } else {
                        "normalization to the declared identity"
                    }
                ),
                u.span,
            )
            .with_help(
                "use named fixed profiles (StealthProfile.create(\"chrome_windows\") / \
                 @fingerprint(.chrome_131) / a fixed Fingerprint) so every attribute stays \
                 coherent; escape only via a logged @opsec_waiver(rule: \"E5102\", ...)",
            ),
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

    fn run_fp_pass(source: &str) -> Diagnostics {
        let (tokens, _) = lexer::tokenize(source);
        let program = Parser::parse(tokens).unwrap();
        let (env, _) = TypeChecker::new(&program).check();
        FingerprintPolicyPass::new(&program, &env).check()
    }

    fn has(diags: &Diagnostics, code: &str) -> bool {
        diags.items.iter().any(|d| d.code == code)
    }

    fn count(diags: &Diagnostics, code: &str) -> usize {
        diags.items.iter().filter(|d| d.code == code).count()
    }

    // ── E5100 ────────────────────────────────────────────────────────────

    #[test]
    fn e5100_browser_program_without_declaration() {
        let diags = run_fp_pass(
            r#"
@legal(basis: .public_data, purpose: "scraping")
fn scrape(url: String) { browser.goto(url) }

fn main() { scrape("https://example.org") }
"#,
        );
        assert!(has(&diags, "E5100"), "expected E5100, got: {:?}", diags.items);
        assert_eq!(count(&diags, "E5100"), 1, "one program-level E5100 expected");
    }

    #[test]
    fn e5100_network_program_without_declaration() {
        let diags = run_fp_pass(
            r#"
fn collect() -> String {
    let r = fetch("https://example.org/a")
    r.text()
}

fn main() { print(collect()) }
"#,
        );
        assert!(has(&diags, "E5100"), "expected E5100, got: {:?}", diags.items);
    }

    #[test]
    fn e5100_stealth_annotation_without_declaration() {
        let diags = run_fp_pass(
            r#"
@stealth(profile: .chrome_windows, evasions: .all)
@legal(basis: .public_data, purpose: "scraping")
fn scrape(url: String) { browser.goto(url) }

fn main() { scrape("https://example.org") }
"#,
        );
        assert!(has(&diags, "E5100"), "expected E5100, got: {:?}", diags.items);
    }

    #[test]
    fn no_declaration_no_network_no_features_is_clean() {
        let diags = run_fp_pass(
            r#"
fn add(a: i32, b: i32) -> i32 { a + b }

fn main() { print(add(1, 2)) }
"#,
        );
        assert!(
            !has(&diags, "E5100") && !diags.has_errors(),
            "plain program must be clean: {:?}",
            diags.items
        );
    }

    #[test]
    fn e5100_waiver_suppresses_and_emits_w5001() {
        let diags = run_fp_pass(
            r#"
@opsec_waiver(rule: "E5100", reason: "internal dry-run tooling", reviewer: "ops-lead")
fn collect() -> String {
    let r = fetch("https://example.org/a")
    r.text()
}

fn main() { print(collect()) }
"#,
        );
        assert!(!has(&diags, "E5100"), "waived: {:?}", diags.items);
        assert!(has(&diags, "W5001"), "waiver must be visible: {:?}", diags.items);
    }

    // ── Happy path ───────────────────────────────────────────────────────

    #[test]
    fn valid_declaration_browser_program_passes() {
        let diags = run_fp_pass(
            r#"
@legal(basis: .public_data, purpose: "scraping")
fn scrape(url: String) { browser.goto(url) }

@fingerprint_policy(policy: .normalize, bot_identity: "TallowScraper/0.1 (+https://example.org/bot)")
fn main() { scrape("https://example.org") }
"#,
        );
        assert!(
            !diags.has_errors(),
            "valid declaration must pass: {:?}",
            diags.items
        );
        assert!(!has(&diags, "W5100"), "versioned+contact identity must not warn");
    }

    #[test]
    fn declared_policy_free_fn_parses() {
        let (tokens, _) = lexer::tokenize(
            r#"
@fingerprint_policy(policy: .cohort_uniform, bot_identity: .browser, network: .hostile)
fn main() { print("ok") }
"#,
        );
        let program = Parser::parse(tokens).unwrap();
        let p = declared_policy(&program).expect("policy should parse");
        assert_eq!(p.posture, FingerprintPosture::CohortUniform);
        assert_eq!(p.bot_identity, BotIdentity::Browser);
        assert_eq!(p.network, NetworkMode::Hostile);
    }

    // ── E5101 ────────────────────────────────────────────────────────────

    #[test]
    fn e5101_unknown_policy_value() {
        let diags = run_fp_pass(
            r#"
@fingerprint_policy(policy: .randomize_sometimes, bot_identity: "TallowScraper/0.1 (+https://x)")
fn main() { print("ok") }
"#,
        );
        assert!(has(&diags, "E5101"), "expected E5101, got: {:?}", diags.items);
    }

    #[test]
    fn e5101_missing_bot_identity() {
        let diags = run_fp_pass(
            r#"
@fingerprint_policy(policy: .normalize)
fn main() { print("ok") }
"#,
        );
        assert!(has(&diags, "E5101"), "expected E5101, got: {:?}", diags.items);
    }

    #[test]
    fn e5101_unknown_network_mode() {
        let diags = run_fp_pass(
            r#"
@fingerprint_policy(policy: .normalize, bot_identity: "TallowScraper/0.1 (+https://x)", network: .sometimes)
fn main() { print("ok") }
"#,
        );
        assert!(has(&diags, "E5101"), "expected E5101, got: {:?}", diags.items);
    }

    // ── W5100 ────────────────────────────────────────────────────────────

    #[test]
    fn w5100_identity_hygiene_warns_without_version_and_contact() {
        let diags = run_fp_pass(
            r#"
@fingerprint_policy(policy: .normalize, bot_identity: "TallowScraper")
fn main() { print("ok") }
"#,
        );
        assert!(!diags.has_errors(), "hygiene is a warning: {:?}", diags.items);
        assert_eq!(count(&diags, "W5100"), 2, "version + contact warnings expected");
    }

    // ── E5102 ────────────────────────────────────────────────────────────

    #[test]
    fn e5102_randomization_under_normalize() {
        let diags = run_fp_pass(
            r#"
fn rotate_fp() -> String {
    let fp = Fingerprint.generate()
    fp.user_agent
}

@fingerprint_policy(policy: .normalize, bot_identity: "TallowScraper/0.1 (+https://x)")
fn main() { print(rotate_fp()) }
"#,
        );
        assert!(has(&diags, "E5102"), "expected E5102, got: {:?}", diags.items);
        assert!(
            !has(&diags, "E5103") && !has(&diags, "E5104"),
            "one gate per site: {:?}",
            diags.items
        );
    }

    #[test]
    fn e5102_stealth_profile_randomize_under_cohort_uniform() {
        let diags = run_fp_pass(
            r#"
fn rotate_profile() -> String {
    let p = StealthProfile.randomize()
    p.user_agent
}

@fingerprint_policy(policy: .cohort_uniform, bot_identity: .browser)
fn main() { print(rotate_profile()) }
"#,
        );
        assert!(has(&diags, "E5102"), "expected E5102, got: {:?}", diags.items);
    }

    #[test]
    fn named_fixed_profile_under_cohort_uniform_is_allowed() {
        let diags = run_fp_pass(
            r#"
fn fixed() -> String {
    let p = StealthProfile.create("chrome_windows")
    p.user_agent
}

@fingerprint_policy(policy: .cohort_uniform, bot_identity: .browser)
fn main() { print(fixed()) }
"#,
        );
        assert!(
            !diags.has_errors(),
            "fixed named profiles are the sanctioned path: {:?}",
            diags.items
        );
    }

    // ── E5103 ────────────────────────────────────────────────────────────

    #[test]
    fn e5103_feature_under_policy_none() {
        let diags = run_fp_pass(
            r#"
fn probe() -> String {
    let p = StealthProfile.create("chrome_windows")
    p.user_agent
}

@fingerprint_policy(policy: .none, bot_identity: .browser)
fn main() { print(probe()) }
"#,
        );
        assert!(has(&diags, "E5103"), "expected E5103, got: {:?}", diags.items);
    }

    #[test]
    fn e5103_stealth_annotation_under_policy_none() {
        let diags = run_fp_pass(
            r#"
@stealth(profile: .chrome_windows, evasions: .all)
@legal(basis: .public_data, purpose: "scraping")
fn scrape(url: String) { browser.goto(url) }

@fingerprint_policy(policy: .none, bot_identity: .browser)
fn main() { scrape("https://example.org") }
"#,
        );
        assert!(has(&diags, "E5103"), "expected E5103, got: {:?}", diags.items);
    }

    // ── E5104 ────────────────────────────────────────────────────────────

    #[test]
    fn e5104_fragment_call_refused_in_monitored_mode() {
        let diags = run_fp_pass(
            r#"
fn sneak() {
    TlsFragment.fragment_hello("example.org")
}

@fingerprint_policy(policy: .normalize, bot_identity: "TallowScraper/0.1 (+https://x)")
fn main() { sneak() }
"#,
        );
        assert!(has(&diags, "E5104"), "expected E5104, got: {:?}", diags.items);
        assert!(!has(&diags, "E5102"), "E5104 takes precedence: {:?}", diags.items);
    }

    #[test]
    fn e5104_default_network_mode_is_monitored() {
        // network: omitted -> .monitored -> grey zone refused.
        let diags = run_fp_pass(
            r#"
fn ech_call() {
    ECH.fetch_config("example.org")
}

@fingerprint_policy(policy: .normalize, bot_identity: "TallowScraper/0.1 (+https://x)")
fn main() { ech_call() }
"#,
        );
        assert!(has(&diags, "E5104"), "expected E5104, got: {:?}", diags.items);
    }

    #[test]
    fn e5104_waiver_suppresses() {
        let diags = run_fp_pass(
            r#"
@opsec_waiver(rule: "E5104", reason: "censored-network field use", reviewer: "ops-lead")
fn sneak() {
    TlsFragment.fragment_hello("example.org")
}

@fingerprint_policy(policy: .normalize, bot_identity: "TallowScraper/0.1 (+https://x)")
fn main() { sneak() }
"#,
        );
        assert!(!has(&diags, "E5104"), "waived: {:?}", diags.items);
        assert!(has(&diags, "W5001"));
    }

    #[test]
    fn hostile_network_allows_fragment() {
        let diags = run_fp_pass(
            r#"
fn sneak() {
    TlsFragment.fragment_hello("example.org")
}

@fingerprint_policy(policy: .normalize, bot_identity: "TallowScraper/0.1 (+https://x)", network: .hostile)
fn main() { sneak() }
"#,
        );
        assert!(
            !diags.has_errors(),
            "explicit .hostile opt-in allows the grey zone: {:?}",
            diags.items
        );
    }

    #[test]
    fn monitored_mode_allows_named_stealth_features() {
        // Named profiles are not grey-zone; the declaration is what gates them.
        let diags = run_fp_pass(
            r#"
fn fixed() -> String {
    let p = StealthProfile.create("chrome_windows")
    p.user_agent
}

@fingerprint_policy(policy: .normalize, bot_identity: "TallowScraper/0.1 (+https://x)")
fn main() { print(fixed()) }
"#,
        );
        assert!(
            !diags.has_errors(),
            "named profiles under a declared policy stay allowed: {:?}",
            diags.items
        );
    }

    #[test]
    fn audit_only_validate_never_gates() {
        let diags = run_fp_pass(
            r#"
fn audit_one() -> String {
    let p = StealthProfile.create("chrome_windows")
    let v = StealthProfile.validate(p)
    "checked"
}

@fingerprint_policy(policy: .none, bot_identity: .browser)
fn main() { print(audit_one()) }
"#,
        );
        // create() still gates (E5103); validate() must not add its own code.
        assert!(has(&diags, "E5103"), "create() is gated: {:?}", diags.items);
        assert_eq!(count(&diags, "E5103"), 1, "validate() must not gate: {:?}", diags.items);
    }

    #[test]
    fn stealth_flag_in_data_is_a_feature() {
        let diags = run_fp_pass(
            r#"
fn make_cfg() -> String { "cfg" }

fn main() {
    let cfg = {"stealth": true, "tor": false}
    BrowserPool.create("pool", cfg)
    print(make_cfg())
}
"#,
        );
        assert!(has(&diags, "E5100"), "stealth flag needs a declaration: {:?}", diags.items);
    }
}
