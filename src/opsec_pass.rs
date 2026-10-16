//! Opsec (operational security) compartmentalization pass.
//!
//! Enforces identity isolation at compile time:
//!
//! - `@opsec(profile: "name")` assigns a function to an identity profile
//! - Cross-profile function calls produce E0900 errors
//! - Functions without `@opsec` are unrestricted (callable from any profile)
//! - Same-profile calls are always allowed
//!
//! # Mapping compile-time profiles to runtime campaigns (G8 §1)
//! The compile-time call-graph isolation (E0900) is one half of
//! compartmentation; the other is that a function tagged
//! `@opsec(profile: "X")` must only touch state stamped with the same
//! identity. Tallow's convention: **`@opsec(profile: "X")` ⟺ runtime
//! `campaign_id == Some("X")`**. Concretely, a `profile:"X"` function should
//! pass `"X"` as the campaign to:
//! - `stdlib::request_queue::RequestQueue.new(name, "X")` (scopes the global
//!   queue store), and
//! - `BrowserSession::with_context(...).with_campaign(Some("X"))` (stamps the
//!   persisted session),
//! then guard shared state access with [`assert_campaign_isolation`] so no
//! two different profiles ever touch the same state store.
//!
//! The runtime helpers in this module ([`assert_campaign_isolation`],
//! [`env_guard`]) are the activation-time enforcement layer that the static
//! pass cannot express; they belong here so the compile-time identity model
//! and the runtime tenant model live in one module.

use std::collections::HashMap;

use crate::ast::*;
use crate::error::Diagnostics;
use crate::typeck::TypeEnv;

// ── Opsec Pass ──────────────────────────────────────────────────────────────

pub struct OpsecPass<'a> {
    program: &'a Program,
    #[allow(dead_code)]
    env: &'a TypeEnv,
    pub diags: Diagnostics,
    /// Maps function name -> opsec profile name.
    profile_map: HashMap<String, String>,
}

impl<'a> OpsecPass<'a> {
    pub fn new(program: &'a Program, env: &'a TypeEnv) -> Self {
        Self {
            program,
            env,
            diags: Diagnostics::new(),
            profile_map: HashMap::new(),
        }
    }

    /// Run the opsec pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        // Phase 1: Collect all @opsec annotations
        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.collect_fn_annotation(f),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.collect_fn_annotation(m);
                    }
                }
                _ => {}
            }
        }

        // Phase 2: Validate cross-profile calls
        let profile_map = self.profile_map.clone();
        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.validate_fn_body(f, &profile_map),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.validate_fn_body(m, &profile_map);
                    }
                }
                _ => {}
            }
        }

        self.diags
    }

    /// Extract @opsec(profile: "name") from a function declaration.
    fn collect_fn_annotation(&mut self, f: &FnDecl) {
        for ann in &f.annotations {
            if ann.name == "opsec" {
                for arg in &ann.args {
                    if arg.name == "profile" {
                        if let ExprKind::StringLit(ref s) = arg.value.kind {
                            self.profile_map.insert(f.name.clone(), s.clone());
                        }
                    }
                }
            }
        }
    }

    /// Walk a function body checking for cross-profile calls.
    fn validate_fn_body(&mut self, f: &FnDecl, profile_map: &HashMap<String, String>) {
        let caller_profile = match profile_map.get(&f.name) {
            Some(p) => p,
            // If caller has no @opsec, it's unrestricted -- skip validation
            None => return,
        };
        self.walk_block(&f.body, &f.name, caller_profile, profile_map);
    }

    fn walk_block(
        &mut self,
        block: &Block,
        caller_name: &str,
        caller_profile: &str,
        profile_map: &HashMap<String, String>,
    ) {
        for stmt in &block.stmts {
            self.walk_stmt(stmt, caller_name, caller_profile, profile_map);
        }
    }

    fn walk_stmt(
        &mut self,
        stmt: &Stmt,
        caller_name: &str,
        caller_profile: &str,
        profile_map: &HashMap<String, String>,
    ) {
        match &stmt.kind {
            StmtKind::Let { value, .. }
            | StmtKind::Var { value, .. }
            | StmtKind::LetDestructure { value, .. }
            | StmtKind::Bail(value) => {
                self.walk_expr(value, caller_name, caller_profile, profile_map);
            }
            StmtKind::Expr { expr } => {
                self.walk_expr(expr, caller_name, caller_profile, profile_map);
            }
            StmtKind::Return(Some(e)) => {
                self.walk_expr(e, caller_name, caller_profile, profile_map);
            }
            StmtKind::While { condition, body } => {
                self.walk_expr(condition, caller_name, caller_profile, profile_map);
                self.walk_block(body, caller_name, caller_profile, profile_map);
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.walk_expr(expr, caller_name, caller_profile, profile_map);
                self.walk_block(body, caller_name, caller_profile, profile_map);
            }
            StmtKind::For { iter, body, .. } => {
                self.walk_expr(iter, caller_name, caller_profile, profile_map);
                self.walk_block(body, caller_name, caller_profile, profile_map);
            }
            StmtKind::Loop { body } => {
                self.walk_block(body, caller_name, caller_profile, profile_map);
            }
            StmtKind::Return(None) | StmtKind::Break | StmtKind::Continue => {}
            StmtKind::Defer { .. } => {}
        }
    }

    fn walk_expr(
        &mut self,
        expr: &Expr,
        caller_name: &str,
        caller_profile: &str,
        profile_map: &HashMap<String, String>,
    ) {
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                // Check the callee for cross-profile violation
                if let Some(callee_name) = Self::extract_fn_name(callee) {
                    if let Some(callee_profile) = profile_map.get(&callee_name) {
                        if callee_profile != caller_profile {
                            self.diags.error(
                                "E0900",
                                format!(
                                    "cross-profile call: function '{}' (profile '{}') calls '{}' (profile '{}')",
                                    caller_name, caller_profile, callee_name, callee_profile
                                ),
                                expr.span,
                            );
                        }
                    }
                    // If callee has no @opsec, it's shared -- allowed
                }
                // Walk callee and args recursively
                self.walk_expr(callee, caller_name, caller_profile, profile_map);
                for arg in args {
                    self.walk_expr(&arg.value, caller_name, caller_profile, profile_map);
                }
            }
            ExprKind::MethodCall { object, args, .. } => {
                self.walk_expr(object, caller_name, caller_profile, profile_map);
                for arg in args {
                    self.walk_expr(&arg.value, caller_name, caller_profile, profile_map);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.walk_expr(left, caller_name, caller_profile, profile_map);
                self.walk_expr(right, caller_name, caller_profile, profile_map);
            }
            ExprKind::Unary { operand, .. } => {
                self.walk_expr(operand, caller_name, caller_profile, profile_map);
            }
            ExprKind::Block(b) => {
                self.walk_block(b, caller_name, caller_profile, profile_map);
            }
            ExprKind::If {
                condition,
                then_block,
                else_branch,
                ..
            } => {
                self.walk_expr(condition, caller_name, caller_profile, profile_map);
                self.walk_block(then_block, caller_name, caller_profile, profile_map);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => {
                            self.walk_block(b, caller_name, caller_profile, profile_map);
                        }
                        ElseBranch::ElseIf(e) => {
                            self.walk_expr(e, caller_name, caller_profile, profile_map);
                        }
                    }
                }
            }
            ExprKind::IfLet {
                expr: scrutinee,
                then_block,
                else_branch,
                ..
            } => {
                self.walk_expr(scrutinee, caller_name, caller_profile, profile_map);
                self.walk_block(then_block, caller_name, caller_profile, profile_map);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => {
                            self.walk_block(b, caller_name, caller_profile, profile_map);
                        }
                        ElseBranch::ElseIf(e) => {
                            self.walk_expr(e, caller_name, caller_profile, profile_map);
                        }
                    }
                }
            }
            ExprKind::Match { subject, arms } => {
                self.walk_expr(subject, caller_name, caller_profile, profile_map);
                for arm in arms {
                    self.walk_expr(&arm.body, caller_name, caller_profile, profile_map);
                }
            }
            ExprKind::Closure { body, .. } => {
                for s in body {
                    self.walk_stmt(s, caller_name, caller_profile, profile_map);
                }
            }
            ExprKind::Array(elems) => {
                for e in elems {
                    self.walk_expr(e, caller_name, caller_profile, profile_map);
                }
            }
            ExprKind::MapLit(pairs) => {
                for (k, v) in pairs {
                    self.walk_expr(k, caller_name, caller_profile, profile_map);
                    self.walk_expr(v, caller_name, caller_profile, profile_map);
                }
            }
            ExprKind::Index { object, index } => {
                self.walk_expr(object, caller_name, caller_profile, profile_map);
                self.walk_expr(index, caller_name, caller_profile, profile_map);
            }
            ExprKind::FieldAccess { object, .. } => {
                self.walk_expr(object, caller_name, caller_profile, profile_map);
            }
            ExprKind::StructLit { fields, spread, .. } => {
                for f in fields {
                    self.walk_expr(&f.value, caller_name, caller_profile, profile_map);
                }
                if let Some(s) = spread {
                    self.walk_expr(s, caller_name, caller_profile, profile_map);
                }
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) => {
                self.walk_expr(inner, caller_name, caller_profile, profile_map);
            }
            ExprKind::Assign { target, value } => {
                self.walk_expr(target, caller_name, caller_profile, profile_map);
                self.walk_expr(value, caller_name, caller_profile, profile_map);
            }
            ExprKind::Cast { expr: inner, .. } => {
                self.walk_expr(inner, caller_name, caller_profile, profile_map);
            }
            _ => {}
        }
    }

    /// Extract a function name from a call expression callee.
    fn extract_fn_name(expr: &Expr) -> Option<String> {
        match &expr.kind {
            ExprKind::Ident(name) => Some(name.clone()),
            _ => None,
        }
    }
}

// ── Runtime compartmentation & environment-conditioned activation ────────────
//
// These are the activation-time counterparts to the compile-time `OpsecPass`.
// They live here so the static identity model (E0900) and the runtime tenant /
// environment model share one module. They are pure Rust and require no pass
// plumbing.

/// Observed environment descriptors used by [`env_guard`] (G8 §5).
#[derive(Debug, Clone, Default)]
pub struct ObservedEnv {
    /// Resolved geo descriptor (e.g. ISO 3166-1 alpha-2 "US", or a fuller
    /// "US-Texas-Houston" style) of the active proxy/egress path.
    pub geo: Option<String>,
    /// Host fingerprint derived from `/etc/hostname` (fallback: `$HOSTNAME`).
    pub host_fingerprint: Option<String>,
}

/// Sample the observed environment.
///
/// - Host fingerprint: first non-empty line of `/etc/hostname`, else `$HOSTNAME`.
/// - Geo: currently sourced from the `TALLOW_GEO` env var, which a proxy
///   bootstrap/egress component sets from the active exit node's geolocation
///   (the actual `geoip` lookup lives in the egress/proxy path; this helper
///   only reads the resolved value so callers stay dependency-free). A future
///   `geo` crate could be wired here behind a feature flag.
pub fn observe_env() -> ObservedEnv {
    let host_fingerprint = std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()));

    let geo = std::env::var("TALLOW_GEO").ok().filter(|s| !s.is_empty());

    ObservedEnv { geo, host_fingerprint }
}

/// Stuxnet-style environment-conditioned activation / anti-misdelivery gate.
///
/// Aborts (returns `Err`) unless the *observed* environment matches the
/// required one. If a requirement is `Some` and the observed value is missing
/// or mismatched, activation is refused — the unit of work must not proceed to
/// touch the network or any state store. This is the runtime half of the
/// `@env_guard(geo:[...], host_fingerprint:[...])` idea from G8 §5: Tallow can
/// *choose* an exit geo, and this lets it *refuse to run* when its own observed
/// environment doesn't match — the canonical anti-analysis / anti-misdelivery
/// control (a build compiled for "US-Texas-Houston" / host `ops-us-01` simply
/// won't activate on a different host or through a non-US exit).
///
/// # Usage
/// ```no_run
/// // At the top of a campaign entry point:
/// tallow::opsec_pass::env_guard(Some("US"), Some("ops-us-01"))
///     .expect("refusing to activate: environment mismatch");
/// ```
pub fn env_guard(
    required_geo: Option<&str>,
    required_host_fingerprint: Option<&str>,
) -> Result<(), String> {
    let observed = observe_env();

    if let Some(rg) = required_geo {
        let ok = observed
            .geo
            .as_deref()
            .map(|og| og.eq_ignore_ascii_case(rg))
            .unwrap_or(false);
        if !ok {
            return Err(format!(
                "env_guard: geo mismatch — required '{rg}', observed {:?}; \
                 refusing to activate (anti-misdelivery)",
                observed.geo
            ));
        }
    }

    if let Some(rh) = required_host_fingerprint {
        let ok = observed.host_fingerprint.as_deref() == Some(rh);
        if !ok {
            return Err(format!(
                "env_guard: host fingerprint mismatch — required '{rh}', observed {:?}; \
                 refusing to activate",
                observed.host_fingerprint
            ));
        }
    }

    Ok(())
}

/// Runtime compartmentation guard: rejects when two distinct `campaign_id`s
/// would touch the same state store.
///
/// Callers pass the campaign bound to the operation about to run and the
/// campaign already stamped on the target state (session DB, request queue,
/// trace archive). If both are present and differ, the operation must not
/// proceed — a single shared artifact would otherwise link the two campaigns
/// (the APT1 "one recovered artifact unravels the operation" failure mode,
/// G8 §1).
///
/// Returns `Ok(())` when safe (either campaign is `None`, or both equal), and
/// an actionable `Err` naming both campaigns on a violation.
///
/// # Usage
/// ```no_run
/// // Before writing a session/queue tagged for campaign B into a store
/// // that already holds campaign A's data:
/// tallow::opsec_pass::assert_campaign_isolation(
///     Some("alpha"),             // this operation's campaign
///     Some("beta"),              // campaign already bound to the store
/// ).expect("campaign isolation violation: state leak");
/// ```
pub fn assert_campaign_isolation(
    campaign_a: Option<&str>,
    campaign_b: Option<&str>,
) -> Result<(), String> {
    match (campaign_a, campaign_b) {
        (Some(a), Some(b)) if a != b => Err(format!(
            "campaign isolation violation: campaign '{a}' is about to touch \
             state already owned by campaign '{b}' — refusing to share a state store"
        )),
        _ => Ok(()),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;
    use crate::parser::Parser;
    use crate::typeck::TypeChecker;

    fn run_opsec_pass(source: &str) -> Diagnostics {
        let (tokens, _) = lexer::tokenize(source);
        let program = Parser::parse(tokens).unwrap();
        let (env, _) = TypeChecker::new(&program).check();
        OpsecPass::new(&program, &env).check()
    }

    #[test]
    fn opsec_cross_profile_call_e0900() {
        let diags = run_opsec_pass(
            r#"
@opsec(profile: "alpha")
fn alpha_work() -> String { "alpha" }

@opsec(profile: "beta")
fn beta_work() -> String { alpha_work() }

fn main() {
    let x = beta_work()
    print(x)
}
"#,
        );
        assert!(diags.has_errors(), "expected E0900 cross-profile error");
        assert!(
            diags.items.iter().any(|d| d.code == "E0900"),
            "expected E0900 code"
        );
    }

    #[test]
    fn opsec_same_profile_allowed() {
        let diags = run_opsec_pass(
            r#"
@opsec(profile: "alpha")
fn alpha_work() -> String { "alpha" }

@opsec(profile: "alpha")
fn alpha_helper() -> String { alpha_work() }

fn main() {
    let x = alpha_helper()
    print(x)
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "same-profile calls should be allowed, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn opsec_unrestricted_caller_ok() {
        let diags = run_opsec_pass(
            r#"
@opsec(profile: "alpha")
fn alpha_work() -> String { "alpha" }

fn main() {
    let x = alpha_work()
    print(x)
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "unrestricted caller should be able to call opsec functions, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn opsec_annotated_calling_non_opsec_ok() {
        let diags = run_opsec_pass(
            r#"
fn shared_util() -> String { "shared" }

@opsec(profile: "alpha")
fn alpha_work() -> String { shared_util() }

fn main() {
    let x = alpha_work()
    print(x)
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "opsec function calling non-opsec should be allowed, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn opsec_three_profiles_isolated() {
        let diags = run_opsec_pass(
            r#"
@opsec(profile: "alpha")
fn alpha_work() -> String { "alpha" }

@opsec(profile: "beta")
fn beta_work() -> String { "beta" }

@opsec(profile: "gamma")
fn gamma_work() -> String { alpha_work() }

fn main() {
    print("done")
}
"#,
        );
        assert!(diags.has_errors(), "gamma calling alpha should be E0900");
        assert!(
            diags.items.iter().any(|d| d.code == "E0900"),
            "expected E0900"
        );
        let e0900_count = diags.items.iter().filter(|d| d.code == "E0900").count();
        assert_eq!(e0900_count, 1, "expected exactly 1 E0900 error");
    }

    #[test]
    fn opsec_no_annotations_no_errors() {
        let diags = run_opsec_pass(
            r#"
fn helper() -> String { "help" }

fn work() -> String { helper() }

fn main() {
    let x = work()
    print(x)
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "no annotations should produce no errors, got: {:?}",
            diags.items
        );
    }
}
