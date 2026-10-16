//! Consent chain validation and jurisdiction enforcement pass.
//!
//! Enforces:
//! - `Consent<T>` values cannot be accessed directly (must use `.with_consent {}`) — E0502
//! - Withdrawn consent values error at runtime — E0503
//! - `@jurisdiction(.eu)` types cannot cross to non-adequate countries — E0504
//! - US transfers emit W0501 warning about DPF certification requirement

use std::collections::HashMap;

use crate::ast::*;
use crate::error::{Diagnostic, Diagnostics};
use crate::typeck::TypeEnv;

// ── EU Adequacy Tables ─────────────────────────────────────────────────────

/// Countries with EU adequacy decisions (full adequacy).
const EU_ADEQUATE: &[&str] = &[
    "eu", "eea", "ad", "ar", "ca", "fo", "gg", "im", "il", "je",
    "nz", "ch", "uy", "jp", "uk", "kr", "br",
];

/// Countries with conditional adequacy (require additional certification).
const EU_CONDITIONAL: &[&str] = &["us"]; // US: Data Privacy Framework only

/// Check if a transfer from `source` jurisdiction to `dest` jurisdiction is adequate.
/// Returns (is_adequate, is_conditional).
fn is_adequate_transfer(source: &str, dest: &str) -> (bool, bool) {
    // Same jurisdiction is always adequate
    if source == dest {
        return (true, false);
    }

    // Only EU/EEA source jurisdictions trigger adequacy checks
    if source != "eu" && source != "eea" {
        return (true, false);
    }

    // Check if dest is in the adequate list
    if EU_ADEQUATE.contains(&dest) {
        return (true, false);
    }

    // Check if dest is conditionally adequate
    if EU_CONDITIONAL.contains(&dest) {
        return (true, true); // adequate but conditional
    }

    // Not adequate
    (false, false)
}

// ── Consent Pass ───────────────────────────────────────────────────────────

pub struct ConsentPass<'a> {
    program: &'a Program,
    #[allow(dead_code)]
    env: &'a TypeEnv,
    pub diags: Diagnostics,
    /// Map of type name -> jurisdiction from @jurisdiction annotations on TypeAlias items.
    jurisdiction_map: HashMap<String, String>,
}

impl<'a> ConsentPass<'a> {
    pub fn new(program: &'a Program, env: &'a TypeEnv) -> Self {
        Self {
            program,
            env,
            diags: Diagnostics::new(),
            jurisdiction_map: HashMap::new(),
        }
    }

    /// Run the consent pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        // Phase 1: Collect @jurisdiction annotations from TypeAlias items
        self.collect_jurisdiction_annotations();

        // Phase 2: Check consent access patterns and jurisdiction violations
        let jurisdiction_map = self.jurisdiction_map.clone();
        for item in &self.program.items {
            if let Item::Fn(f) = item {
                self.check_function(f, &jurisdiction_map);
            }
        }

        self.diags
    }

    /// Collect @jurisdiction annotations from type aliases.
    fn collect_jurisdiction_annotations(&mut self) {
        for item in &self.program.items {
            if let Item::TypeAlias(ta) = item {
                for ann in &ta.annotations {
                    if ann.name == "jurisdiction" {
                        if let Some(jurisdiction) = self.extract_jurisdiction(ann) {
                            self.jurisdiction_map.insert(ta.name.clone(), jurisdiction);
                        }
                    }
                }
            }
        }
    }

    /// Extract jurisdiction value from @jurisdiction(.eu) annotation.
    fn extract_jurisdiction(&self, ann: &Annotation) -> Option<String> {
        for arg in &ann.args {
            match &arg.value.kind {
                ExprKind::DotIdent(s) => return Some(s.clone()),
                ExprKind::StringLit(s) => return Some(s.clone()),
                ExprKind::Ident(s) => return Some(s.clone()),
                _ => {}
            }
        }
        None
    }

    /// Check a function for consent access violations and jurisdiction transfers.
    fn check_function(&mut self, f: &FnDecl, jurisdiction_map: &HashMap<String, String>) {
        // Check for direct Consent<T> access (not via .with_consent)
        self.check_consent_access(&f.body, f);

        // Check for cross-border jurisdiction violations
        self.check_jurisdiction_transfers(f, jurisdiction_map);
    }

    /// Walk a function body checking for direct access to Consent-typed variables.
    /// Direct access = any usage that isn't .with_consent {}
    fn check_consent_access(&mut self, block: &Block, f: &FnDecl) {
        for stmt in &block.stmts {
            self.check_stmt_consent(stmt, f);
        }
    }

    fn check_stmt_consent(&mut self, stmt: &Stmt, f: &FnDecl) {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.check_expr_consent(value, f);
            }
            StmtKind::Expr { expr } => {
                self.check_expr_consent(expr, f);
            }
            StmtKind::Return(Some(e)) => {
                self.check_expr_consent(e, f);
            }
            StmtKind::While { condition, body } => {
                self.check_expr_consent(condition, f);
                self.check_consent_access(body, f);
            }
            StmtKind::For { iter, body, .. } => {
                self.check_expr_consent(iter, f);
                self.check_consent_access(body, f);
            }
            _ => {}
        }
    }

    fn check_expr_consent(&mut self, expr: &Expr, f: &FnDecl) {
        match &expr.kind {
            // Method call on a consent-typed param: .with_consent is OK, others are violations
            ExprKind::MethodCall { object, method, args } => {
                if method == "with_consent" || method == "withdraw" || method == "consent_id" {
                    // These are valid Consent method calls — skip checking the object
                    // But still check args
                    for a in args {
                        self.check_expr_consent(&a.value, f);
                    }
                    return;
                }
                // Check if object is a Consent-typed parameter
                if self.is_consent_typed_ident(object, f) {
                    self.diags.push(Diagnostic::error(
                        "E0502",
                        format!(
                            "direct access to Consent value via .{method}() — use .with_consent {{}} to access inner data",
                        ),
                        expr.span,
                    ));
                }
                self.check_expr_consent(object, f);
                for a in args {
                    self.check_expr_consent(&a.value, f);
                }
            }
            // Field access on a consent-typed param is a violation
            ExprKind::FieldAccess { object, field } => {
                if self.is_consent_typed_ident(object, f) {
                    self.diags.push(Diagnostic::error(
                        "E0502",
                        format!(
                            "direct field access .{field} on Consent value — use .with_consent {{}} to access inner data",
                        ),
                        expr.span,
                    ));
                }
                self.check_expr_consent(object, f);
            }
            // Passing a consent value to a function that doesn't expect Consent<T> is a violation
            ExprKind::Call { callee, args } => {
                // Check if any arg is a bare consent-typed ident being passed to a non-consent-aware fn
                for a in args {
                    if self.is_consent_typed_ident(&a.value, f) {
                        // Check if callee function expects Consent type
                        if let ExprKind::Ident(fn_name) = &callee.kind {
                            if !self.fn_accepts_consent(fn_name) {
                                self.diags.push(Diagnostic::error(
                                    "E0502",
                                    format!(
                                        "passing Consent value to function `{fn_name}` which does not accept Consent<T> — use .with_consent {{}} to unwrap first",
                                    ),
                                    a.value.span,
                                ));
                            }
                        }
                    }
                    self.check_expr_consent(&a.value, f);
                }
                self.check_expr_consent(callee, f);
            }
            ExprKind::Binary { left, right, .. } => {
                self.check_expr_consent(left, f);
                self.check_expr_consent(right, f);
            }
            ExprKind::Unary { operand, .. } => {
                self.check_expr_consent(operand, f);
            }
            ExprKind::Block(block) => {
                self.check_consent_access(block, f);
            }
            ExprKind::If { condition, then_block, else_branch, .. } => {
                self.check_expr_consent(condition, f);
                self.check_consent_access(then_block, f);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::ElseIf(e) => self.check_expr_consent(e, f),
                        ElseBranch::Block(b) => self.check_consent_access(b, f),
                    }
                }
            }
            ExprKind::Assign { value, .. } => {
                self.check_expr_consent(value, f);
            }
            _ => {}
        }
    }

    /// Check if an expression is an identifier that has a Consent<T> parameter type.
    fn is_consent_typed_ident(&self, expr: &Expr, f: &FnDecl) -> bool {
        if let ExprKind::Ident(name) = &expr.kind {
            // Check function parameters for Consent<T> type
            for param in &f.params {
                if param.name == *name {
                    return self.is_consent_type_expr(&param.ty);
                }
            }
        }
        false
    }

    /// Check if a TypeExpr is Consent<T>.
    fn is_consent_type_expr(&self, ty: &TypeExpr) -> bool {
        if let TypeExprKind::Generic { name, .. } = &ty.kind {
            return name == "Consent";
        }
        // Also check named types that resolve to Consent
        if let TypeExprKind::Named(name) = &ty.kind {
            if let Some(resolved) = self.env.type_aliases.get(name) {
                return resolved.is_consent();
            }
        }
        false
    }

    /// Check if a function accepts Consent<T> parameters.
    fn fn_accepts_consent(&self, fn_name: &str) -> bool {
        for item in &self.program.items {
            if let Item::Fn(f) = item {
                if f.name == fn_name {
                    for param in &f.params {
                        if self.is_consent_type_expr(&param.ty) {
                            return true;
                        }
                    }
                    return false;
                }
            }
        }
        false
    }

    /// Check for cross-border jurisdiction violations in function calls.
    fn check_jurisdiction_transfers(
        &mut self,
        f: &FnDecl,
        jurisdiction_map: &HashMap<String, String>,
    ) {
        // Collect this function's jurisdiction annotation (if any)
        let fn_jurisdiction = self.get_fn_jurisdiction(f);

        // Walk the function body looking for calls that pass jurisdiction-typed values
        // to functions with different jurisdiction annotations
        self.check_jurisdiction_in_block(&f.body, f, &fn_jurisdiction, jurisdiction_map);
    }

    /// Get the jurisdiction annotation from a function, if any.
    fn get_fn_jurisdiction(&self, f: &FnDecl) -> Option<String> {
        for ann in &f.annotations {
            if ann.name == "jurisdiction" {
                return self.extract_jurisdiction(ann);
            }
        }
        None
    }

    /// Walk a block checking for jurisdiction transfer violations.
    fn check_jurisdiction_in_block(
        &mut self,
        block: &Block,
        f: &FnDecl,
        fn_jurisdiction: &Option<String>,
        jurisdiction_map: &HashMap<String, String>,
    ) {
        for stmt in &block.stmts {
            self.check_jurisdiction_in_stmt(stmt, f, fn_jurisdiction, jurisdiction_map);
        }
    }

    fn check_jurisdiction_in_stmt(
        &mut self,
        stmt: &Stmt,
        f: &FnDecl,
        fn_jurisdiction: &Option<String>,
        jurisdiction_map: &HashMap<String, String>,
    ) {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.check_jurisdiction_in_expr(value, f, fn_jurisdiction, jurisdiction_map);
            }
            StmtKind::Expr { expr } => {
                self.check_jurisdiction_in_expr(expr, f, fn_jurisdiction, jurisdiction_map);
            }
            StmtKind::Return(Some(e)) => {
                self.check_jurisdiction_in_expr(e, f, fn_jurisdiction, jurisdiction_map);
            }
            StmtKind::While { condition, body } => {
                self.check_jurisdiction_in_expr(condition, f, fn_jurisdiction, jurisdiction_map);
                self.check_jurisdiction_in_block(body, f, fn_jurisdiction, jurisdiction_map);
            }
            StmtKind::For { iter, body, .. } => {
                self.check_jurisdiction_in_expr(iter, f, fn_jurisdiction, jurisdiction_map);
                self.check_jurisdiction_in_block(body, f, fn_jurisdiction, jurisdiction_map);
            }
            _ => {}
        }
    }

    fn check_jurisdiction_in_expr(
        &mut self,
        expr: &Expr,
        f: &FnDecl,
        fn_jurisdiction: &Option<String>,
        jurisdiction_map: &HashMap<String, String>,
    ) {
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                // Check if calling a function with a different jurisdiction
                if let ExprKind::Ident(callee_name) = &callee.kind {
                    let callee_jurisdiction = self.get_callee_jurisdiction(callee_name);

                    // Check each arg: if it has a jurisdiction-typed parameter,
                    // verify the transfer is adequate
                    for arg in args {
                        let arg_jurisdiction = self.get_expr_jurisdiction(&arg.value, f, jurisdiction_map);
                        if let Some(ref source_j) = arg_jurisdiction {
                            if let Some(ref dest_j) = callee_jurisdiction {
                                let (adequate, conditional) = is_adequate_transfer(source_j, dest_j);
                                if !adequate {
                                    self.diags.push(Diagnostic::error(
                                        "E0504",
                                        format!(
                                            "cross-border transfer violation: data with @jurisdiction(.{source_j}) cannot be transferred to function with @jurisdiction(.{dest_j}) — no adequacy decision",
                                        ),
                                        arg.value.span,
                                    ));
                                } else if conditional {
                                    self.diags.push(Diagnostic::warning(
                                        "W0501",
                                        format!(
                                            "conditional adequacy: transfer to .{dest_j} requires Data Privacy Framework certification — verify DPF status",
                                        ),
                                        arg.value.span,
                                    ));
                                }
                            }
                        }
                        self.check_jurisdiction_in_expr(&arg.value, f, fn_jurisdiction, jurisdiction_map);
                    }
                    self.check_jurisdiction_in_expr(callee, f, fn_jurisdiction, jurisdiction_map);
                }
            }
            ExprKind::MethodCall { object, args, .. } => {
                self.check_jurisdiction_in_expr(object, f, fn_jurisdiction, jurisdiction_map);
                for a in args {
                    self.check_jurisdiction_in_expr(&a.value, f, fn_jurisdiction, jurisdiction_map);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.check_jurisdiction_in_expr(left, f, fn_jurisdiction, jurisdiction_map);
                self.check_jurisdiction_in_expr(right, f, fn_jurisdiction, jurisdiction_map);
            }
            ExprKind::Unary { operand, .. } => {
                self.check_jurisdiction_in_expr(operand, f, fn_jurisdiction, jurisdiction_map);
            }
            ExprKind::Block(block) => {
                self.check_jurisdiction_in_block(block, f, fn_jurisdiction, jurisdiction_map);
            }
            ExprKind::If { condition, then_block, else_branch, .. } => {
                self.check_jurisdiction_in_expr(condition, f, fn_jurisdiction, jurisdiction_map);
                self.check_jurisdiction_in_block(then_block, f, fn_jurisdiction, jurisdiction_map);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::ElseIf(e) => self.check_jurisdiction_in_expr(e, f, fn_jurisdiction, jurisdiction_map),
                        ElseBranch::Block(b) => self.check_jurisdiction_in_block(b, f, fn_jurisdiction, jurisdiction_map),
                    }
                }
            }
            ExprKind::Assign { value, .. } => {
                self.check_jurisdiction_in_expr(value, f, fn_jurisdiction, jurisdiction_map);
            }
            _ => {}
        }
    }

    /// Get the jurisdiction of a callee function from its annotations.
    fn get_callee_jurisdiction(&self, fn_name: &str) -> Option<String> {
        for item in &self.program.items {
            if let Item::Fn(f) = item {
                if f.name == fn_name {
                    return self.get_fn_jurisdiction(f);
                }
            }
        }
        None
    }

    /// Get the jurisdiction of an expression by checking if it references a jurisdiction-typed parameter.
    fn get_expr_jurisdiction(
        &self,
        expr: &Expr,
        f: &FnDecl,
        jurisdiction_map: &HashMap<String, String>,
    ) -> Option<String> {
        if let ExprKind::Ident(name) = &expr.kind {
            // Check if the ident is a parameter with a jurisdiction-annotated type
            for param in &f.params {
                if param.name == *name {
                    // Get the type name and check jurisdiction_map
                    if let Some(type_name) = self.get_type_name(&param.ty) {
                        if let Some(j) = jurisdiction_map.get(&type_name) {
                            return Some(j.clone());
                        }
                    }
                }
            }
        }
        None
    }

    /// Extract the type name from a TypeExpr.
    fn get_type_name(&self, ty: &TypeExpr) -> Option<String> {
        match &ty.kind {
            TypeExprKind::Named(name) => Some(name.clone()),
            TypeExprKind::Generic { name, .. } => Some(name.clone()),
            _ => None,
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

    fn run_consent_pass(source: &str) -> Diagnostics {
        let (tokens, _) = lexer::tokenize(source);
        let program = Parser::parse(tokens).unwrap();
        let (env, _) = TypeChecker::new(&program).check();
        ConsentPass::new(&program, &env).check()
    }

    // ── Consent Access Tests ──

    #[test]
    fn consent_valid_with_consent_access() {
        let diags = run_consent_pass(
            r#"
fn process(data: Consent<String>) -> String {
    data.with_consent { val -> val }
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "expected no errors, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn consent_valid_withdraw() {
        let diags = run_consent_pass(
            r#"
fn revoke(data: Consent<String>) -> Consent<String> {
    data.withdraw()
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "expected no errors for withdraw, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn consent_valid_consent_id() {
        let diags = run_consent_pass(
            r#"
fn get_id(data: Consent<String>) -> String {
    data.consent_id()
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "expected no errors for consent_id, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn consent_invalid_direct_method_access() {
        let diags = run_consent_pass(
            r#"
fn bad(data: Consent<String>) -> String {
    data.len()
}
"#,
        );
        assert!(diags.has_errors());
        assert!(
            diags.items.iter().any(|d| d.code == "E0502"),
            "expected E0502, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn consent_invalid_pass_to_non_consent_fn() {
        let diags = run_consent_pass(
            r#"
fn process_raw(data: String) -> String { data }

fn bad(data: Consent<String>) -> String {
    process_raw(data)
}
"#,
        );
        assert!(diags.has_errors());
        assert!(
            diags.items.iter().any(|d| d.code == "E0502"),
            "expected E0502, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn consent_valid_pass_to_consent_fn() {
        let diags = run_consent_pass(
            r#"
fn forward(data: Consent<String>) -> String {
    data.with_consent { val -> val }
}

fn caller(data: Consent<String>) -> String {
    forward(data)
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "expected no errors, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn consent_no_consent_params_no_errors() {
        let diags = run_consent_pass(
            r#"
fn normal(x: i32) -> i32 { x }
"#,
        );
        assert!(
            !diags.has_errors(),
            "expected no errors, got: {:?}",
            diags.items
        );
    }

    // ── Jurisdiction Tests ──

    #[test]
    fn jurisdiction_eu_to_eu_valid() {
        let diags = run_consent_pass(
            r#"
@jurisdiction(.eu)
type EUData = private String

@jurisdiction(.eu)
fn process_eu(data: EUData) -> String { "ok" }

@jurisdiction(.eu)
fn caller(data: EUData) -> String {
    process_eu(data)
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "expected no errors for EU-to-EU, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn jurisdiction_eu_to_uk_adequate() {
        let diags = run_consent_pass(
            r#"
@jurisdiction(.eu)
type EUData = private String

@jurisdiction(.uk)
fn process_uk(data: EUData) -> String { "ok" }

@jurisdiction(.eu)
fn caller(data: EUData) -> String {
    process_uk(data)
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "expected no errors for EU-to-UK (adequate), got: {:?}",
            diags.items
        );
    }

    #[test]
    fn jurisdiction_eu_to_us_conditional_warning() {
        let diags = run_consent_pass(
            r#"
@jurisdiction(.eu)
type EUData = private String

@jurisdiction(.us)
fn process_us(data: EUData) -> String { "ok" }

@jurisdiction(.eu)
fn caller(data: EUData) -> String {
    process_us(data)
}
"#,
        );
        // Should NOT have errors, but SHOULD have W0501 warning
        assert!(
            !diags.has_errors(),
            "expected no errors for EU-to-US conditional, got: {:?}",
            diags.items
        );
        assert!(
            diags.items.iter().any(|d| d.code == "W0501"),
            "expected W0501 warning, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn jurisdiction_eu_to_cn_blocked() {
        let diags = run_consent_pass(
            r#"
@jurisdiction(.eu)
type EUData = private String

@jurisdiction(.cn)
fn process_cn(data: EUData) -> String { "ok" }

@jurisdiction(.eu)
fn caller(data: EUData) -> String {
    process_cn(data)
}
"#,
        );
        assert!(diags.has_errors());
        assert!(
            diags.items.iter().any(|d| d.code == "E0504"),
            "expected E0504, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn jurisdiction_non_eu_no_restriction() {
        // Non-EU source jurisdictions don't trigger adequacy checks
        let diags = run_consent_pass(
            r#"
@jurisdiction(.us)
type USData = private String

@jurisdiction(.cn)
fn process_cn(data: USData) -> String { "ok" }

@jurisdiction(.us)
fn caller(data: USData) -> String {
    process_cn(data)
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "expected no errors for US-to-CN (no EU restrictions), got: {:?}",
            diags.items
        );
    }

    #[test]
    fn jurisdiction_eu_to_jp_adequate() {
        let diags = run_consent_pass(
            r#"
@jurisdiction(.eu)
type EUData = private String

@jurisdiction(.jp)
fn process_jp(data: EUData) -> String { "ok" }

@jurisdiction(.eu)
fn caller(data: EUData) -> String {
    process_jp(data)
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "expected no errors for EU-to-JP (adequate), got: {:?}",
            diags.items
        );
    }

    #[test]
    fn jurisdiction_eu_to_ru_blocked() {
        let diags = run_consent_pass(
            r#"
@jurisdiction(.eu)
type EUData = private String

@jurisdiction(.ru)
fn process_ru(data: EUData) -> String { "ok" }

@jurisdiction(.eu)
fn caller(data: EUData) -> String {
    process_ru(data)
}
"#,
        );
        assert!(diags.has_errors());
        assert!(
            diags.items.iter().any(|d| d.code == "E0504"),
            "expected E0504 for EU-to-RU, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn jurisdiction_eu_to_ch_adequate() {
        let diags = run_consent_pass(
            r#"
@jurisdiction(.eu)
type EUData = private String

@jurisdiction(.ch)
fn process_ch(data: EUData) -> String { "ok" }

@jurisdiction(.eu)
fn caller(data: EUData) -> String {
    process_ch(data)
}
"#,
        );
        assert!(
            !diags.has_errors(),
            "expected no errors for EU-to-CH (adequate), got: {:?}",
            diags.items
        );
    }

    // ── Adequacy Table Tests ──

    #[test]
    fn adequacy_table_coverage() {
        // All 17 adequate countries should pass
        let adequate_countries = vec![
            "eu", "eea", "ad", "ar", "ca", "fo", "gg", "im", "il", "je",
            "nz", "ch", "uy", "jp", "uk", "kr", "br",
        ];
        for country in &adequate_countries {
            let (adequate, conditional) = is_adequate_transfer("eu", country);
            assert!(adequate, "expected {country} to be adequate for EU transfer");
            assert!(!conditional, "expected {country} to not be conditional");
        }

        // US is conditional
        let (adequate, conditional) = is_adequate_transfer("eu", "us");
        assert!(adequate, "US should be adequate (conditional)");
        assert!(conditional, "US should be conditional");

        // CN is not adequate
        let (adequate, _) = is_adequate_transfer("eu", "cn");
        assert!(!adequate, "CN should not be adequate for EU transfer");
    }
}
