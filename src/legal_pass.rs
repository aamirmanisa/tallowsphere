//! @legal annotation validation pass.
//!
//! This pass enforces Tallow's core invariant:
//! **Every function that touches the network or stores data MUST have a @legal annotation.**
//!
//! Validates:
//! - Network functions have @legal
//! - Legal basis is appropriate for the data handled
//! - personal_data: true requires retain_for
//! - retain_for: .forever is forbidden for personal data
//! - legitimate_interest requires lia_completed: true
//! - Functions returning private types must declare personal_data: true

use crate::ast::*;
use crate::error::{Diagnostic, Diagnostics};
use crate::lexer::Span;
use crate::typeck::TypeEnv;

// ── Parsed Legal Annotation ──────────────────────────────────────────────────

#[derive(Debug)]
struct LegalInfo {
    basis: Option<String>,
    purpose: Option<String>,
    personal_data: Option<bool>,
    retain_for: bool,           // whether retain_for is present
    retain_forever: bool,       // whether retain_for is .forever
    lia_completed: Option<bool>,
    consent_ref: Option<String>,
    robots_txt: Option<String>,
    rate_limit: Option<String>,
    jurisdictions: Vec<String>,
    span: Span,
}

impl LegalInfo {
    fn from_annotation(ann: &Annotation) -> Self {
        let mut info = LegalInfo {
            basis: None,
            purpose: None,
            personal_data: None,
            retain_for: false,
            retain_forever: false,
            lia_completed: None,
            consent_ref: None,
            robots_txt: None,
            rate_limit: None,
            jurisdictions: Vec::new(),
            span: ann.span,
        };

        for arg in &ann.args {
            match arg.name.as_str() {
                "basis" => {
                    if let ExprKind::DotIdent(ref val) = arg.value.kind {
                        info.basis = Some(val.clone());
                    }
                }
                "purpose" => {
                    if let ExprKind::StringLit(ref val) = arg.value.kind {
                        info.purpose = Some(val.clone());
                    }
                }
                "personal_data" => {
                    if let ExprKind::BoolLit(val) = arg.value.kind {
                        info.personal_data = Some(val);
                    }
                }
                "retain_for" => {
                    info.retain_for = true;
                    if let ExprKind::DotIdent(ref val) = arg.value.kind {
                        if val == "forever" {
                            info.retain_forever = true;
                        }
                    }
                }
                "lia_completed" => {
                    if let ExprKind::BoolLit(val) = arg.value.kind {
                        info.lia_completed = Some(val);
                    }
                }
                "consent_ref" => {
                    if let ExprKind::StringLit(ref val) = arg.value.kind {
                        info.consent_ref = Some(val.clone());
                    }
                }
                "robots_txt" => {
                    if let ExprKind::DotIdent(ref val) = arg.value.kind {
                        info.robots_txt = Some(val.clone());
                    }
                }
                "rate_limit" => {
                    // Capture rate_limit value for audit metadata
                    if let ExprKind::MethodCall { object, method, .. } = &arg.value.kind {
                        if let ExprKind::IntLit(n) = &object.kind {
                            info.rate_limit = Some(format!("{n}.{method}"));
                        }
                    }
                }
                "jurisdictions" => {
                    // Accept `jurisdictions: [.eu, .us]` (DotIdent) or
                    // `jurisdictions: ["eu", "us"]` (StringLit) list literals.
                    if let ExprKind::Array(items) = &arg.value.kind {
                        for item in items {
                            match &item.kind {
                                ExprKind::DotIdent(j) => info.jurisdictions.push(j.clone()),
                                ExprKind::StringLit(j) => info.jurisdictions.push(j.clone()),
                                _ => {}
                            }
                        }
                    }
                }
                _ => {} // ignore unknown args (could warn)
            }
        }

        info
    }
}

// ── Legal Pass ───────────────────────────────────────────────────────────────

/// Audit metadata for a browser-touching function.
#[derive(Debug, Clone)]
pub struct BrowserAuditEntry {
    pub function_name: String,
    pub legal_basis: String,
    pub purpose: String,
    pub has_robots_txt_config: bool,
    pub has_rate_limit: bool,
    pub browser_ops: Vec<String>,
}

pub struct LegalPass<'a> {
    program: &'a Program,
    env: &'a TypeEnv,
    pub diags: Diagnostics,
    pub browser_audit_entries: Vec<BrowserAuditEntry>,
    composed_legal: Option<crate::pkg::legal_propagation::ComposedLegal>,
}

impl<'a> LegalPass<'a> {
    pub fn new(program: &'a Program, env: &'a TypeEnv) -> Self {
        Self {
            program,
            env,
            diags: Diagnostics::new(),
            browser_audit_entries: Vec::new(),
            composed_legal: None,
        }
    }

    /// Set composed legal metadata from transitive dependencies.
    /// When set, each @legal-annotated function is additionally validated
    /// against these composed constraints.
    pub fn set_composed_legal(&mut self, composed: crate::pkg::legal_propagation::ComposedLegal) {
        self.composed_legal = Some(composed);
    }

    /// Run the legal pass. Returns diagnostics and browser audit entries.
    pub fn check(mut self) -> (Diagnostics, Vec<BrowserAuditEntry>) {
        for item in &self.program.items {
            if let Item::Fn(f) = item {
                self.check_function(f);
            }
        }
        (self.diags, self.browser_audit_entries)
    }

    fn check_function(&mut self, f: &FnDecl) {
        let is_network_fn = self.env.network_functions.contains(&f.name);
        let returns_private = self.returns_private_type(f);
        let legal_ann = f
            .annotations
            .iter()
            .find(|a| a.name == "legal");

        // ── Rule 1: Network functions MUST have @legal ───────────────────
        if is_network_fn && legal_ann.is_none() {
            self.diags.push(
                Diagnostic::error(
                    "E0100",
                    format!(
                        "function `{}` touches the network but has no @legal annotation",
                        f.name
                    ),
                    f.span,
                )
                .with_help("add @legal(basis: ..., purpose: \"...\") to this function"),
            );
            return; // can't validate further without annotation
        }

        // If no annotation and not network, skip
        let Some(ann) = legal_ann else {
            return;
        };

        let info = LegalInfo::from_annotation(ann);

        // ── Rule 2: basis is required ────────────────────────────────────
        if info.basis.is_none() {
            self.diags.push(
                Diagnostic::error(
                    "E0101",
                    format!("@legal on `{}` is missing required field: basis", f.name),
                    info.span,
                )
                .with_help("add basis: .public_data, .consent, .research, etc."),
            );
        }

        // ── Rule 3: purpose is required ──────────────────────────────────
        if info.purpose.is_none() {
            self.diags.push(
                Diagnostic::error(
                    "E0102",
                    format!(
                        "@legal on `{}` is missing required field: purpose",
                        f.name
                    ),
                    info.span,
                )
                .with_help("add purpose: \"description of why this data is processed\""),
            );
        }

        // ── Rule 4: personal_data: true requires retain_for ──────────────
        if info.personal_data == Some(true) && !info.retain_for {
            self.diags.push(
                Diagnostic::error(
                    "E0103",
                    format!(
                        "@legal on `{}` declares personal_data: true but has no retain_for",
                        f.name
                    ),
                    info.span,
                )
                .with_help(
                    "GDPR Art.5(1)(e) requires a data retention limit for personal data",
                ),
            );
        }

        // ── Rule 5: retain_for: .forever is forbidden for personal data ──
        if info.personal_data == Some(true) && info.retain_forever {
            self.diags.push(
                Diagnostic::error(
                    "E0104",
                    format!(
                        "@legal on `{}` uses retain_for: .forever with personal_data: true",
                        f.name
                    ),
                    info.span,
                )
                .with_help("GDPR Art.5(1)(e) prohibits indefinite retention of personal data"),
            );
        }

        // ── Rule 6: legitimate_interest requires lia_completed ───────────
        if info.basis.as_deref() == Some("legitimate_interest")
            && info.lia_completed != Some(true)
        {
            self.diags.push(
                Diagnostic::error(
                    "E0105",
                    format!(
                        "@legal on `{}` uses basis: .legitimate_interest without lia_completed: true",
                        f.name
                    ),
                    info.span,
                )
                .with_help(
                    "legitimate interest basis requires a documented Legitimate Interest Assessment",
                ),
            );
        }

        // ── Rule 6b: consent basis requires consent_ref ─────────────────
        if info.basis.as_deref() == Some("consent") && info.consent_ref.is_none() {
            self.diags.push(
                Diagnostic::error(
                    "E0108",
                    format!(
                        "@legal on `{}` uses basis: .consent without consent_ref",
                        f.name
                    ),
                    info.span,
                )
                .with_help("consent basis requires a consent_ref pointing to the consent record"),
            );
        }

        // ── Rule 7: Functions returning private types need personal_data ─
        if returns_private && info.personal_data != Some(true) {
            self.diags.push(
                Diagnostic::error(
                    "E0106",
                    format!(
                        "function `{}` returns privacy-sensitive types but @legal declares personal_data: false",
                        f.name
                    ),
                    info.span,
                )
                .with_help("set personal_data: true when handling Email, Name, Phone, etc."),
            );
        }

        // ── Rule 8: Validate legal basis is recognized ───────────────────
        if let Some(ref basis) = info.basis {
            let valid_bases = [
                "public_data",
                "consent",
                "legitimate_interest",
                "research",
                "contract",
                "vital_interests",
                "legal_obligation",
            ];
            if !valid_bases.contains(&basis.as_str()) {
                self.diags.push(
                    Diagnostic::error(
                        "E0107",
                        format!("unknown legal basis: .{basis}"),
                        info.span,
                    )
                    .with_help(format!(
                        "valid bases: {}",
                        valid_bases
                            .iter()
                            .map(|b| format!(".{b}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                );
            }
        }

        // ── Rule 9a: Composed legal validation (dependency propagation) ──
        if let Some(ref composed) = self.composed_legal {
            let consumer_personal_data = info.personal_data == Some(true);
            // E0114 jurisdiction propagation: read the jurisdictions declared
            // on the consumer's OWN @legal annotation (list of dot-idents or
            // strings, e.g. `jurisdictions: [.eu, .us]`). Previously hardcoded
            // empty, which made the superset check dead.
            let consumer_jurisdictions: std::collections::HashSet<String> =
                info.jurisdictions.iter().cloned().collect();
            let consumer_consent_ref = info.consent_ref.is_some();

            let violations = crate::pkg::legal_propagation::validate_consumer_legal(
                info.basis.as_deref(),
                consumer_personal_data,
                &consumer_jurisdictions,
                consumer_consent_ref,
                composed,
            );

            for v in violations {
                let code: &'static str = match v.code.as_str() {
                    "E0113" => "E0113",
                    "E0114" => "E0114",
                    _ => "E0112",
                };
                // Real, actionable per-code help for composed-legal (transitive dependency)
                // constraint violations. These arise because @legal annotations compose across
                // the dependency tree: a consumer inherits the legal requirements of every
                // package it transitively depends on.
                let help = match v.code.as_str() {
                    "E0113" => {
                        "A transitive dependency handles personal data, so this consumer must too. \
                         Add `personal_data: true` (plus a `retain_for` limit) to this @legal \
                         annotation so the inherited personal-data flow is covered."
                    }
                    "E0114" => {
                        "A transitive dependency's data flows require jurisdiction coverage that this \
                         @legal does not satisfy. Add the missing jurisdiction(s) to the package's \
                         `[legal]` `jurisdictions` (or `default_jurisdiction`) so the consumer's \
                         coverage is a superset of every dependency's coverage."
                    }
                    _ => {
                        "A transitive dependency's data flow uses a legal basis this @legal does not \
                         cover. Add the matching basis, or for `.consent` flows add a `consent_ref`, \
                         so the consumer is legally covered for the data it inherits from its \
                         dependencies."
                    }
                };
                self.diags.push(
                    Diagnostic::error(
                        code,
                        format!(
                            "transitive dependency legal constraint on `{}`: {}",
                            f.name, v.message
                        ),
                        info.span,
                    )
                    .with_help(help),
                );
            }
        }

        // ── Rule 9b: Browser save operations require retain_for ──────────
        if Self::has_browser_save_ops(&f.body) && !info.retain_for {
            self.diags.push(
                Diagnostic::error(
                    "E0109",
                    format!(
                        "function `{}` contains browser save operation but @legal has no retain_for",
                        f.name
                    ),
                    info.span,
                )
                .with_help(
                    "browser save operations (screenshot, save_pdf, download) write to disk and require a retention policy",
                ),
            );
        }

        // ── Advisory W0100: fetch() with personal_data may need browser ─
        // If a function declares personal_data: true and uses fetch() (network)
        // but does NOT use any browser navigation methods, it might be fetching
        // JS-rendered pages without a browser. This is advisory only — the user
        // might legitimately use fetch() for API endpoints returning personal data.
        if info.personal_data == Some(true)
            && is_network_fn
            && !self.env.browser_nav_functions.contains(&f.name)
        {
            self.diags.warning(
                "W0100",
                format!(
                    "function `{}` uses fetch() with personal_data: true but no browser operations. \
                     If the target page requires JavaScript rendering, use Browser.launch() + page.goto() instead of fetch().",
                    f.name
                ),
                info.span,
            );
        }

        // ── Collect browser audit metadata ───────────────────────────────
        let browser_ops = Self::collect_browser_ops(&f.body);
        if !browser_ops.is_empty() {
            self.browser_audit_entries.push(BrowserAuditEntry {
                function_name: f.name.clone(),
                legal_basis: info.basis.clone().unwrap_or_else(|| "unspecified".into()),
                purpose: info.purpose.clone().unwrap_or_else(|| "unspecified".into()),
                has_robots_txt_config: info.robots_txt.is_some(),
                has_rate_limit: info.rate_limit.is_some(),
                browser_ops,
            });
        }
    }

    /// Collect browser method names called in a function body.
    fn collect_browser_ops(block: &Block) -> Vec<String> {
        let mut ops = Vec::new();
        let browser_methods = [
            "goto", "navigate", "new_page", "new_context",
            "reload", "go_back", "go_forward", "launch",
            "screenshot", "save_pdf", "save_page", "download",
        ];
        Self::collect_browser_ops_block(block, &browser_methods, &mut ops);
        ops
    }

    fn collect_browser_ops_block(block: &Block, methods: &[&str], ops: &mut Vec<String>) {
        for stmt in &block.stmts {
            Self::collect_browser_ops_stmt(stmt, methods, ops);
        }
    }

    fn collect_browser_ops_stmt(stmt: &Stmt, methods: &[&str], ops: &mut Vec<String>) {
        match &stmt.kind {
            StmtKind::Expr { expr } => Self::collect_browser_ops_expr(expr, methods, ops),
            StmtKind::Let { value, .. }
            | StmtKind::Var { value, .. }
            | StmtKind::LetDestructure { value, .. } => {
                Self::collect_browser_ops_expr(value, methods, ops)
            }
            StmtKind::Return(Some(expr)) => Self::collect_browser_ops_expr(expr, methods, ops),
            StmtKind::For { iter, body, .. } => {
                Self::collect_browser_ops_expr(iter, methods, ops);
                Self::collect_browser_ops_block(body, methods, ops);
            }
            StmtKind::While { condition, body } => {
                Self::collect_browser_ops_expr(condition, methods, ops);
                Self::collect_browser_ops_block(body, methods, ops);
            }
            _ => {}
        }
    }

    fn collect_browser_ops_expr(expr: &Expr, methods: &[&str], ops: &mut Vec<String>) {
        match &expr.kind {
            ExprKind::MethodCall { method, object, args, .. } => {
                if methods.contains(&method.as_str()) {
                    ops.push(method.clone());
                }
                Self::collect_browser_ops_expr(object, methods, ops);
                for arg in args {
                    Self::collect_browser_ops_expr(&arg.value, methods, ops);
                }
            }
            ExprKind::Call { callee, args, .. } => {
                Self::collect_browser_ops_expr(callee, methods, ops);
                for arg in args {
                    Self::collect_browser_ops_expr(&arg.value, methods, ops);
                }
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) => {
                Self::collect_browser_ops_expr(inner, methods, ops);
            }
            ExprKind::Binary { left, right, .. } => {
                Self::collect_browser_ops_expr(left, methods, ops);
                Self::collect_browser_ops_expr(right, methods, ops);
            }
            ExprKind::Block(block) => {
                Self::collect_browser_ops_block(block, methods, ops);
            }
            _ => {}
        }
    }

    /// Check if a function body contains browser save/download method calls.
    fn has_browser_save_ops(block: &Block) -> bool {
        let save_methods = ["screenshot", "save_pdf", "save_page", "download"];
        let ops = Self::collect_browser_ops(block);
        ops.iter().any(|op| save_methods.contains(&op.as_str()))
    }

    /// Check if a function's return type contains private types.
    fn returns_private_type(&self, f: &FnDecl) -> bool {
        let Some(ref ret) = f.return_type else {
            return false;
        };
        self.type_expr_is_private(ret)
    }

    fn type_expr_is_private(&self, ty: &TypeExpr) -> bool {
        match &ty.kind {
            TypeExprKind::Named(name) => {
                // Check if this is a known private type
                let private_types = [
                    "Email",
                    "IPAddress",
                    "Name",
                    "Phone",
                    "Location",
                    "SSN",
                ];
                private_types.contains(&name.as_str())
                    || self
                        .env
                        .type_aliases
                        .get(name)
                        .is_some_and(|t| t.is_private() || t.is_secret())
            }
            TypeExprKind::Generic { args, .. } => {
                args.iter().any(|a| self.type_expr_is_private(a))
            }
            TypeExprKind::Slice(inner) | TypeExprKind::Optional(inner) => {
                self.type_expr_is_private(inner)
            }
            TypeExprKind::Tuple(types) => {
                types.iter().any(|t| self.type_expr_is_private(t))
            }
            TypeExprKind::Function { params, return_type } => {
                params.iter().any(|p| self.type_expr_is_private(p))
                    || self.type_expr_is_private(return_type)
            }
            TypeExprKind::Boxed(inner) => self.type_expr_is_private(inner),
            TypeExprKind::ImplTrait(_) | TypeExprKind::DynTrait(_) => false,
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;
    use crate::parser::Parser;
    use crate::typeck::TypeChecker;

    fn run_legal_pass(source: &str) -> Diagnostics {
        let (tokens, _) = lexer::tokenize(source);
        let program = Parser::parse(tokens).unwrap();
        let (env, _) = TypeChecker::new(&program).check();
        let (diags, _) = LegalPass::new(&program, &env).check();
        diags
    }

    fn run_legal_pass_with_audit(source: &str) -> (Diagnostics, Vec<super::BrowserAuditEntry>) {
        let (tokens, _) = lexer::tokenize(source);
        let program = Parser::parse(tokens).unwrap();
        let (env, _) = TypeChecker::new(&program).check();
        LegalPass::new(&program, &env).check()
    }

    #[test]
    fn legal_valid_passes() {
        let diags = run_legal_pass(
            r#"@legal(basis: .public_data, purpose: "test", retain_for: 7.days)
fn fetch_data(url: String) -> String { fetch(url) }"#,
        );
        assert!(
            !diags.has_errors(),
            "expected no errors, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn missing_legal_on_network_fn() {
        let diags = run_legal_pass(
            r#"fn fetch_data(url: String) -> String { fetch(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(diags.items[0].code == "E0100");
    }

    #[test]
    fn missing_basis() {
        let diags = run_legal_pass(
            r#"@legal(purpose: "test")
fn fetch_data(url: String) -> String { fetch(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0101"));
    }

    #[test]
    fn missing_purpose() {
        let diags = run_legal_pass(
            r#"@legal(basis: .public_data)
fn fetch_data(url: String) -> String { fetch(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0102"));
    }

    #[test]
    fn personal_data_without_retention() {
        let diags = run_legal_pass(
            r#"@legal(basis: .consent, purpose: "collect emails", personal_data: true)
fn collect(url: String) -> String { fetch(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0103"));
    }

    #[test]
    fn forever_retention_forbidden() {
        let diags = run_legal_pass(
            r#"@legal(basis: .consent, purpose: "test", personal_data: true, retain_for: .forever)
fn collect(url: String) -> String { fetch(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0104"));
    }

    #[test]
    fn legitimate_interest_needs_lia() {
        let diags = run_legal_pass(
            r#"@legal(basis: .legitimate_interest, purpose: "analytics")
fn track(url: String) -> String { fetch(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0105"));
    }

    #[test]
    fn legitimate_interest_with_lia_passes() {
        let diags = run_legal_pass(
            r#"@legal(basis: .legitimate_interest, purpose: "analytics", lia_completed: true)
fn track(url: String) -> String { fetch(url) }"#,
        );
        // Should not have E0105
        assert!(!diags.items.iter().any(|d| d.code == "E0105"));
    }

    #[test]
    fn private_return_needs_personal_data() {
        let diags = run_legal_pass(
            r#"@legal(basis: .consent, purpose: "get emails", personal_data: false, retain_for: 30.days)
fn get_emails(url: String) -> []Email { fetch(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0106"));
    }

    #[test]
    fn invalid_legal_basis() {
        let diags = run_legal_pass(
            r#"@legal(basis: .yolo, purpose: "test")
fn fetch_data(url: String) -> String { fetch(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0107"));
    }

    #[test]
    fn non_network_fn_no_annotation_ok() {
        let diags = run_legal_pass("fn add(a: i32, b: i32) -> i32 { a + b }");
        assert!(!diags.has_errors());
    }

    #[test]
    fn consent_requires_consent_ref() {
        let diags = run_legal_pass(
            r#"@legal(basis: .consent, purpose: "collect data", personal_data: true, retain_for: 30.days)
fn collect(url: String) -> String { fetch(url) }"#,
        );
        // Should warn about missing consent_ref for consent basis
        assert!(diags.has_errors() || diags.items.iter().any(|d| d.code == "E0108"));
    }

    #[test]
    fn public_data_no_personal_ok() {
        let diags = run_legal_pass(
            r#"@legal(basis: .public_data, purpose: "price monitoring", personal_data: false)
fn scrape(url: String) -> String { fetch(url) }"#,
        );
        // public_data with no personal data should pass
        assert!(!diags.items.iter().any(|d| d.code == "E0103" || d.code == "E0104"));
    }

    #[test]
    fn research_basis_passes() {
        let diags = run_legal_pass(
            r#"@legal(basis: .research, purpose: "academic research")
fn gather(url: String) -> String { fetch(url) }"#,
        );
        assert!(!diags.items.iter().any(|d| d.code == "E0107"));
    }

    #[test]
    fn multiple_annotations_all_checked() {
        let diags = run_legal_pass(
            r#"@legal(basis: .public_data, purpose: "scraping")
fn scrape(url: String) -> String { fetch(url) }

fn network_no_legal(url: String) -> String { fetch(url) }"#,
        );
        // Second function should fail E0100
        assert!(diags.items.iter().any(|d| d.code == "E0100"));
    }

    // ── Additional legal pass tests ───────────────────────────────────────

    #[test]
    fn contract_basis_valid() {
        let diags = run_legal_pass(
            r#"@legal(basis: .contract, purpose: "service delivery")
fn api_call(url: String) -> String { fetch(url) }"#,
        );
        assert!(!diags.has_errors(), "contract basis should be valid: {:?}", diags.items);
    }

    #[test]
    fn vital_interests_basis_valid() {
        let diags = run_legal_pass(
            r#"@legal(basis: .vital_interests, purpose: "emergency response")
fn emergency(url: String) -> String { fetch(url) }"#,
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn legal_obligation_basis_valid() {
        let diags = run_legal_pass(
            r#"@legal(basis: .legal_obligation, purpose: "tax reporting")
fn report(url: String) -> String { fetch(url) }"#,
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn consent_with_ref_passes() {
        let diags = run_legal_pass(
            r#"@legal(basis: .consent, purpose: "marketing", consent_ref: "consent-v2")
fn track(url: String) -> String { fetch(url) }"#,
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn personal_data_with_retention_passes() {
        let diags = run_legal_pass(
            r#"@legal(basis: .consent, purpose: "user tracking", personal_data: true, retain_for: 30, consent_ref: "v1")
fn collect(email: Email) -> String { fetch("https://api.example.com") }"#,
        );
        assert!(!diags.has_errors(), "personal data with retention should pass: {:?}", diags.items);
    }

    #[test]
    fn legitimate_interest_without_lia_e0105() {
        let diags = run_legal_pass(
            r#"@legal(basis: .legitimate_interest, purpose: "analytics")
fn track(url: String) -> String { fetch(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0105"));
    }

    #[test]
    fn multiple_network_fns_one_missing_legal() {
        let diags = run_legal_pass(
            r#"@legal(basis: .public_data, purpose: "scraping")
fn scrape_a(url: String) -> String { fetch(url) }

@legal(basis: .research, purpose: "research")
fn scrape_b(url: String) -> String { fetch(url) }

fn scrape_c(url: String) -> String { fetch(url) }"#,
        );
        // Only scrape_c should fail
        let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E0100").collect();
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn forever_retention_with_personal_data_fails() {
        let diags = run_legal_pass(
            r#"@legal(basis: .consent, purpose: "tracking", personal_data: true, retain_for: .forever, consent_ref: "v1")
fn collect(url: String) -> String { fetch(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0104"));
    }

    #[test]
    fn non_network_fn_with_legal_annotation_ok() {
        // Having @legal on a non-network function shouldn't cause errors
        let diags = run_legal_pass(
            r#"@legal(basis: .public_data, purpose: "processing")
fn compute(x: i32) -> i32 { x + 1 }"#,
        );
        assert!(!diags.has_errors());
    }

    // ── Edge case tests ─────────────────────────────────────────────────

    #[test]
    fn empty_program_no_errors() {
        let diags = run_legal_pass("");
        assert!(!diags.has_errors());
    }

    #[test]
    fn multiple_valid_legal_annotations() {
        let diags = run_legal_pass(
            r#"@legal(basis: .public_data, purpose: "scraping")
fn scrape(url: String) -> String { fetch(url) }

@legal(basis: .research, purpose: "analysis")
fn analyze(url: String) -> String { fetch(url) }"#,
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn personal_data_true_with_finite_retention() {
        let diags = run_legal_pass(
            r#"@legal(basis: .consent, purpose: "data collection", personal_data: true, retain_for: 30.days, consent_ref: "v1")
fn collect(url: String) -> String { fetch(url) }"#,
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn legal_obligation_basis_no_errors() {
        let diags = run_legal_pass(
            r#"@legal(basis: .legal_obligation, purpose: "compliance reporting")
fn report(url: String) -> String { fetch(url) }"#,
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn contract_basis_with_personal_data_needs_retention() {
        let diags = run_legal_pass(
            r#"@legal(basis: .contract, purpose: "user service", personal_data: true)
fn serve(url: String) -> String { fetch(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0103"));
    }

    #[test]
    fn vital_interests_basis_passes() {
        let diags = run_legal_pass(
            r#"@legal(basis: .vital_interests, purpose: "emergency")
fn emergency(url: String) -> String { fetch(url) }"#,
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn missing_both_basis_and_purpose() {
        let diags = run_legal_pass(
            r#"@legal()
fn scrape(url: String) -> String { fetch(url) }"#,
        );
        assert!(diags.has_errors());
    }

    #[test]
    fn non_network_fn_no_errors() {
        let diags = run_legal_pass(
            r#"fn add(a: i32, b: i32) -> i32 { a + b }"#,
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn struct_and_fn_no_errors() {
        let diags = run_legal_pass(
            r#"struct Config { port: u16 }
fn pure(x: i32) -> i32 { x * 2 }"#,
        );
        assert!(!diags.has_errors());
    }

    // ── Batch: additional legal pass coverage ─────────────────────────

    #[test]
    fn research_basis_no_personal_data_ok() {
        let diags = run_legal_pass(
            r#"@legal(basis: .research, purpose: "academic study", personal_data: false)
fn study(url: String) -> String { fetch(url) }"#,
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn legitimate_interest_without_lia_fails() {
        let diags = run_legal_pass(
            r#"@legal(basis: .legitimate_interest, purpose: "analytics")
fn analyze(url: String) -> String { fetch(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0105"));
    }

    #[test]
    fn legitimate_interest_with_lia_completed_ok() {
        let diags = run_legal_pass(
            r#"@legal(basis: .legitimate_interest, purpose: "analytics", lia_completed: true)
fn analyze(url: String) -> String { fetch(url) }"#,
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn consent_without_consent_ref_fails() {
        let diags = run_legal_pass(
            r#"@legal(basis: .consent, purpose: "marketing")
fn market(url: String) -> String { fetch(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0108"));
    }

    #[test]
    fn consent_with_consent_ref_ok() {
        let diags = run_legal_pass(
            r#"@legal(basis: .consent, purpose: "marketing", consent_ref: "consent-v3")
fn market(url: String) -> String { fetch(url) }"#,
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn missing_purpose_fails() {
        let diags = run_legal_pass(
            r#"@legal(basis: .public_data)
fn scrape(url: String) -> String { fetch(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0102"));
    }

    #[test]
    fn missing_basis_fails() {
        let diags = run_legal_pass(
            r#"@legal(purpose: "data collection")
fn collect(url: String) -> String { fetch(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0101"));
    }

    #[test]
    fn three_network_fns_all_legal_ok() {
        let diags = run_legal_pass(
            r#"@legal(basis: .public_data, purpose: "monitor a")
fn scrape_a(url: String) -> String { fetch(url) }

@legal(basis: .public_data, purpose: "monitor b")
fn scrape_b(url: String) -> String { fetch(url) }

@legal(basis: .research, purpose: "monitor c")
fn scrape_c(url: String) -> String { fetch(url) }"#,
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn personal_data_false_no_retention_needed() {
        let diags = run_legal_pass(
            r#"@legal(basis: .public_data, purpose: "scraping", personal_data: false)
fn scrape(url: String) -> String { fetch(url) }"#,
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn async_network_fn_needs_legal() {
        let diags = run_legal_pass(
            r#"async fn download(url: String) -> String { fetch(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0100"));
    }

    // ── New coverage tests ──────────────────────────────────────────

    #[test]
    fn e0100_early_return_skips_downstream() {
        // Missing @legal entirely on network fn — should only get E0100
        let diags = run_legal_pass(
            r#"fn scrape(url: String) -> String { fetch(url) }"#,
        );
        assert!(diags.items.iter().any(|d| d.code == "E0100"));
        // Should NOT have E0101/E0102 etc since E0100 returns early
        assert!(!diags.items.iter().any(|d| d.code == "E0101"));
        assert!(!diags.items.iter().any(|d| d.code == "E0102"));
    }

    #[test]
    fn missing_both_basis_and_purpose_emits_both() {
        let diags = run_legal_pass(
            r#"@legal()
fn scrape(url: String) -> String { fetch(url) }"#,
        );
        assert!(diags.items.iter().any(|d| d.code == "E0101"));
        assert!(diags.items.iter().any(|d| d.code == "E0102"));
    }

    #[test]
    fn forever_retention_ok_when_not_personal_data() {
        let diags = run_legal_pass(
            r#"@legal(basis: .public_data, purpose: "cache", personal_data: false, retain_for: .forever)
fn cache(url: String) -> String { fetch(url) }"#,
        );
        // .forever is only forbidden when personal_data: true
        assert!(!diags.items.iter().any(|d| d.code == "E0104"));
    }

    #[test]
    fn legitimate_interest_with_explicit_false_lia() {
        let diags = run_legal_pass(
            r#"@legal(basis: .legitimate_interest, purpose: "analytics", lia_completed: false)
fn track(url: String) -> String { fetch(url) }"#,
        );
        assert!(diags.items.iter().any(|d| d.code == "E0105"));
    }

    #[test]
    fn legitimate_interest_passes_with_lia() {
        let diags = run_legal_pass(
            r#"@legal(basis: .legitimate_interest, purpose: "analytics", lia_completed: true)
fn track(url: String) -> String { fetch(url) }"#,
        );
        assert!(!diags.items.iter().any(|d| d.code == "E0105"));
    }

    #[test]
    fn consent_with_consent_ref_passes() {
        let diags = run_legal_pass(
            r#"@legal(basis: .consent, purpose: "collect", consent_ref: "consent-v3", personal_data: true, retain_for: 30.days)
fn collect(url: String) -> String { fetch(url) }"#,
        );
        assert!(!diags.items.iter().any(|d| d.code == "E0108"));
    }

    #[test]
    fn multiple_network_fns_all_need_legal() {
        let diags = run_legal_pass(
            r#"fn a(url: String) -> String { fetch(url) }
fn b(url: String) -> String { fetch(url) }"#,
        );
        let e0100_count = diags.items.iter().filter(|d| d.code == "E0100").count();
        assert_eq!(e0100_count, 2, "both fns should get E0100");
    }

    #[test]
    fn research_basis_no_personal_data_passes() {
        let diags = run_legal_pass(
            r#"@legal(basis: .research, purpose: "academic study")
fn study(url: String) -> String { fetch(url) }"#,
        );
        assert!(!diags.has_errors(), "research basis without personal_data should be OK: {:?}", diags.items);
    }

    #[test]
    fn vital_interests_basis_accepted() {
        let diags = run_legal_pass(
            r#"@legal(basis: .vital_interests, purpose: "emergency lookup")
fn emergency(url: String) -> String { fetch(url) }"#,
        );
        assert!(!diags.has_errors(), "vital_interests should be valid: {:?}", diags.items);
    }

    #[test]
    fn legal_obligation_basis_accepted() {
        let diags = run_legal_pass(
            r#"@legal(basis: .legal_obligation, purpose: "regulatory compliance")
fn comply(url: String) -> String { fetch(url) }"#,
        );
        assert!(!diags.has_errors(), "legal_obligation should be valid: {:?}", diags.items);
    }

    // ── Browser @legal enforcement tests ────────────────────────────────

    #[test]
    fn browser_goto_without_legal_is_error() {
        let diags = run_legal_pass(
            r#"fn scrape(url: String) { browser.goto(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0100"),
            "browser.goto without @legal should produce E0100");
    }

    #[test]
    fn browser_goto_with_legal_passes() {
        let diags = run_legal_pass(
            r#"@legal(basis: .public_data, purpose: "scraping")
fn scrape(url: String) { browser.goto(url) }"#,
        );
        assert!(!diags.has_errors(), "browser.goto with @legal should pass: {:?}", diags.items);
    }

    #[test]
    fn browser_screenshot_without_retain_for_is_error() {
        let diags = run_legal_pass(
            r#"@legal(basis: .public_data, purpose: "capture pages")
fn capture(url: String) { page.screenshot("out.png") }"#,
        );
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0109"),
            "browser screenshot without retain_for should produce E0109");
    }

    #[test]
    fn browser_screenshot_with_retain_for_passes() {
        let diags = run_legal_pass(
            r#"@legal(basis: .public_data, purpose: "capture pages", retain_for: 30.days)
fn capture(url: String) { page.screenshot("out.png") }"#,
        );
        assert!(!diags.items.iter().any(|d| d.code == "E0109"),
            "browser screenshot with retain_for should not produce E0109: {:?}", diags.items);
    }

    #[test]
    fn browser_save_pdf_without_retain_for_is_error() {
        let diags = run_legal_pass(
            r#"@legal(basis: .research, purpose: "archiving")
fn archive(url: String) { page.save_pdf("doc.pdf") }"#,
        );
        assert!(diags.items.iter().any(|d| d.code == "E0109"));
    }

    #[test]
    fn browser_download_without_retain_for_is_error() {
        let diags = run_legal_pass(
            r#"@legal(basis: .public_data, purpose: "download files")
fn dl(url: String) { page.download("file.zip") }"#,
        );
        assert!(diags.items.iter().any(|d| d.code == "E0109"));
    }

    #[test]
    fn browser_navigate_without_legal_is_error() {
        let diags = run_legal_pass(
            r#"fn nav(url: String) { page.navigate(url) }"#,
        );
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0100"));
    }

    #[test]
    fn browser_audit_entries_collected() {
        let (diags, audit) = run_legal_pass_with_audit(
            r#"@legal(basis: .public_data, purpose: "scraping")
fn scrape(url: String) { browser.goto(url) }"#,
        );
        assert!(!diags.has_errors());
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].function_name, "scrape");
        assert!(audit[0].browser_ops.contains(&"goto".to_string()));
    }

    #[test]
    fn browser_audit_multiple_ops_collected() {
        let (diags, audit) = run_legal_pass_with_audit(
            r#"@legal(basis: .public_data, purpose: "scraping", retain_for: 7.days)
fn scrape(url: String) {
    browser.goto(url)
    page.screenshot("out.png")
}"#,
        );
        assert!(!diags.has_errors(), "should pass with retain_for: {:?}", diags.items);
        assert_eq!(audit.len(), 1);
        assert!(audit[0].browser_ops.contains(&"goto".to_string()));
        assert!(audit[0].browser_ops.contains(&"screenshot".to_string()));
    }

    #[test]
    fn non_browser_fn_no_audit_entries() {
        let (_, audit) = run_legal_pass_with_audit(
            r#"@legal(basis: .public_data, purpose: "data fetch")
fn get_data(url: String) -> String { fetch(url) }"#,
        );
        assert!(audit.is_empty(), "non-browser function should not generate browser audit entries");
    }

    // ── W0100: fetch() with personal_data advisory warning ──────────

    #[test]
    fn w0100_fetch_with_personal_data_warns() {
        let diags = run_legal_pass(
            r#"@legal(basis: .consent, purpose: "collect emails", personal_data: true, retain_for: 30.days, consent_ref: "v1")
fn collect(url: String) -> String { fetch(url) }"#,
        );
        assert!(!diags.has_errors(), "should not error: {:?}", diags.items);
        assert!(
            diags.items.iter().any(|d| d.code == "W0100"),
            "fetch() with personal_data: true should produce W0100 advisory warning"
        );
    }

    #[test]
    fn w0100_not_emitted_when_browser_ops_present() {
        let diags = run_legal_pass(
            r#"@legal(basis: .consent, purpose: "collect data", personal_data: true, retain_for: 30.days, consent_ref: "v1")
fn collect(url: String) -> String { browser.goto(url) }"#,
        );
        assert!(
            !diags.items.iter().any(|d| d.code == "W0100"),
            "W0100 should not fire when browser ops are present: {:?}", diags.items
        );
    }

    #[test]
    fn w0100_not_emitted_without_personal_data() {
        let diags = run_legal_pass(
            r#"@legal(basis: .public_data, purpose: "scraping", personal_data: false)
fn scrape(url: String) -> String { fetch(url) }"#,
        );
        assert!(
            !diags.items.iter().any(|d| d.code == "W0100"),
            "W0100 should not fire without personal_data: true: {:?}", diags.items
        );
    }

    #[test]
    fn w0100_not_emitted_for_non_network_fn() {
        let diags = run_legal_pass(
            r#"@legal(basis: .contract, purpose: "process data", personal_data: true, retain_for: 30.days)
fn process(data: String) -> String { data }"#,
        );
        assert!(
            !diags.items.iter().any(|d| d.code == "W0100"),
            "W0100 should not fire for non-network functions: {:?}", diags.items
        );
    }
}
