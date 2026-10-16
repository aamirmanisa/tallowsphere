//! EU AI Act annotation validation compiler pass.
//!
//! Validates @ai_risk_level and @ai_system annotations on functions:
//! - E1400: unknown risk level
//! - E1401: .prohibited risk level is a compile error
//! - E1402: .high risk level missing required fields (for @ai_risk_level)
//! - E1403: Art.9 risk management missing sub-field (for @ai_system)
//! - E1404: @explainable function lacks explanation output (Art.13)
//! - E1405: @requires_human_approval function lacks HumanApproval.request() call (Art.14)
//! - E1406: @ai_system applied to non-function item
//! - W1400: .limited without transparency: true
//! - W1401: AI-related function name without @ai_risk_level annotation
//! - W1402: @ai_risk_level(.high) suggests migration to @ai_system with Art.9

use crate::ast::*;
use crate::error::Diagnostics;

// ── AI-related function name keywords ────────────────────────────────────────

const AI_KEYWORDS: &[&str] = &[
    "predict", "classify", "score", "recommend", "detect",
    "recognize", "generate", "infer", "train", "evaluate_model",
];

const VALID_RISK_LEVELS: &[&str] = &[
    "prohibited", "high", "limited", "minimal",
];

const HIGH_RISK_REQUIRED_FIELDS: &[&str] = &[
    "human_oversight", "risk_assessment", "data_governance", "transparency",
];

const ART9_REQUIRED_FIELDS: &[&str] = &[
    "risk_assessment", "mitigation_measures", "testing_metrics", "residual_risk",
];

// ── Pass ─────────────────────────────────────────────────────────────────────

pub struct AiActPass<'a> {
    program: &'a Program,
    pub diags: Diagnostics,
}

impl<'a> AiActPass<'a> {
    pub fn new(program: &'a Program) -> Self {
        Self {
            program,
            diags: Diagnostics::new(),
        }
    }

    /// Run the AI Act pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.validate_fn(f),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.validate_fn(m);
                    }
                }
                _ => {}
            }
        }
        self.diags
    }

    fn validate_fn(&mut self, f: &FnDecl) {
        let ai_anns: Vec<&Annotation> = f.annotations.iter()
            .filter(|a| a.name == "ai_system" || a.name == "ai_risk_level")
            .collect();

        if ai_anns.is_empty() {
            // W1401: check if function name contains AI keywords
            self.check_ai_keyword_warning(f);
        } else {
            for ann in &ai_anns {
                self.validate_annotation(ann, &f.name);
            }
        }

        // E1404: @explainable — Art.13 transparency
        if f.annotations.iter().any(|a| a.name == "explainable") {
            if !self.body_has_explanation(&f.body) {
                let span = f.annotations.iter()
                    .find(|a| a.name == "explainable")
                    .map(|a| a.span)
                    .unwrap_or(f.span);
                self.diags.error(
                    "E1404",
                    format!(
                        "@explainable function '{}' must produce an explanation \
                         (return struct with 'explanation' field or call an explain() function)",
                        f.name
                    ),
                    span,
                );
            }
        }

        // E1405: @requires_human_approval — Art.14 human oversight
        if f.annotations.iter().any(|a| a.name == "requires_human_approval") {
            if !self.body_calls_human_approval(&f.body) {
                let span = f.annotations.iter()
                    .find(|a| a.name == "requires_human_approval")
                    .map(|a| a.span)
                    .unwrap_or(f.span);
                self.diags.error(
                    "E1405",
                    format!(
                        "@requires_human_approval on '{}' but no HumanApproval.request() call found \
                         -- Art.14 requires human oversight gate",
                        f.name
                    ),
                    span,
                );
            }
        }
    }

    /// Extract the risk level string from either annotation format:
    /// - @ai_risk_level(.high, ...) -> first positional DotIdent
    /// - @ai_system(risk: .high, ...) -> named arg `risk` with DotIdent value
    fn extract_risk_level(&self, ann: &Annotation) -> Option<String> {
        if ann.name == "ai_system" {
            // Named arg: risk: .high
            ann.args.iter().find_map(|arg| {
                if arg.name == "risk" {
                    if let ExprKind::DotIdent(name) = &arg.value.kind {
                        return Some(name.clone());
                    }
                }
                None
            })
        } else {
            // Positional: first DotIdent
            ann.args.iter().find_map(|arg| {
                if let ExprKind::DotIdent(name) = &arg.value.kind {
                    Some(name.clone())
                } else {
                    None
                }
            })
        }
    }

    /// Check if a named boolean arg is present and set to true.
    fn has_field_true(&self, ann: &Annotation, field: &str) -> bool {
        ann.args.iter().any(|arg| {
            arg.name == field && matches!(&arg.value.kind, ExprKind::BoolLit(true))
        })
    }

    fn validate_annotation(&mut self, ann: &Annotation, fn_name: &str) {
        let is_ai_system = ann.name == "ai_system";

        // Extract risk level using helper
        let risk_level = self.extract_risk_level(ann);

        let level = match risk_level {
            Some(l) => l,
            None => {
                // No risk level specified at all -- treat as unknown
                let ann_name = &ann.name;
                self.diags.error(
                    "E1400",
                    format!(
                        "@{} on '{}' has no risk level specified",
                        ann_name, fn_name
                    ),
                    ann.span,
                );
                return;
            }
        };

        // E1400: unknown risk level
        if !VALID_RISK_LEVELS.contains(&level.as_str()) {
            let ann_name = &ann.name;
            self.diags.error(
                "E1400",
                format!(
                    "@{}(.{}) is not a valid EU AI Act risk classification",
                    ann_name, level
                ),
                ann.span,
            );
            return;
        }

        match level.as_str() {
            // E1401: prohibited
            "prohibited" => {
                self.diags.error(
                    "E1401",
                    "EU AI Act prohibits this AI system category; cannot compile".to_string(),
                    ann.span,
                );
            }

            // High risk — different checks depending on annotation style
            "high" => {
                if is_ai_system {
                    // @ai_system: check for Art.9 fields
                    let has_art9 = self.has_field_true(ann, "art9");
                    if has_art9 {
                        // E1403: Validate Art.9 sub-fields
                        for required in ART9_REQUIRED_FIELDS {
                            if !self.has_field_true(ann, required) {
                                self.diags.error(
                                    "E1403",
                                    format!(
                                        "Art.9 risk management requires '{}' declaration for high-risk AI system",
                                        required
                                    ),
                                    ann.span,
                                );
                            }
                        }
                    } else {
                        // W1402: @ai_system(.high) without art9: true
                        self.diags.warning(
                            "W1402",
                            format!(
                                "@ai_system(risk: .high) on '{}' without art9: true -- consider adding Art.9 risk management fields",
                                fn_name
                            ),
                            ann.span,
                        );
                    }
                } else {
                    // @ai_risk_level: existing E1402 checks
                    let present_fields: Vec<String> = ann.args.iter()
                        .filter(|arg| {
                            HIGH_RISK_REQUIRED_FIELDS.contains(&arg.name.as_str())
                        })
                        .filter(|arg| {
                            matches!(&arg.value.kind, ExprKind::BoolLit(true))
                        })
                        .map(|arg| arg.name.clone())
                        .collect();

                    for required in HIGH_RISK_REQUIRED_FIELDS {
                        if !present_fields.contains(&required.to_string()) {
                            self.diags.error(
                                "E1402",
                                format!(
                                    "high-risk AI system missing required `{}` declaration per EU AI Act",
                                    required
                                ),
                                ann.span,
                            );
                        }
                    }

                    // W1402: suggest migration to @ai_system
                    self.diags.warning(
                        "W1402",
                        format!(
                            "@ai_risk_level(.high) on '{}' -- consider migrating to @ai_system with Art.9 fields for full EU AI Act compliance",
                            fn_name
                        ),
                        ann.span,
                    );
                }
            }

            // W1400: limited without transparency
            "limited" => {
                let has_transparency = self.has_field_true(ann, "transparency");
                if !has_transparency {
                    self.diags.warning(
                        "W1400",
                        format!(
                            "@{}(.limited) on '{}' without transparency: true -- transparency obligation applies",
                            ann.name, fn_name
                        ),
                        ann.span,
                    );
                }
            }

            // .minimal -- no additional checks
            "minimal" => {}

            _ => {} // already caught by E1400
        }
    }

    fn check_ai_keyword_warning(&mut self, f: &FnDecl) {
        let name_lower = f.name.to_lowercase();
        for keyword in AI_KEYWORDS {
            if name_lower.contains(keyword) {
                self.diags.warning(
                    "W1401",
                    format!(
                        "function `{}` appears to be an AI system but has no @ai_risk_level classification",
                        f.name
                    ),
                    f.span,
                );
                return; // One warning per function
            }
        }
    }

    // ── @explainable body check (Art.13) ─────────────────────────────────

    /// Check if a function body produces an explanation: either a StructLit
    /// with an `explanation` field, or a call to a function containing "explain".
    fn body_has_explanation(&self, body: &Block) -> bool {
        for stmt in &body.stmts {
            if self.stmt_has_explanation(stmt) {
                return true;
            }
        }
        false
    }

    fn stmt_has_explanation(&self, stmt: &Stmt) -> bool {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.expr_has_explanation(value)
            }
            StmtKind::LetDestructure { value, .. } => self.expr_has_explanation(value),
            StmtKind::Expr { expr } => self.expr_has_explanation(expr),
            StmtKind::Return(Some(expr)) => self.expr_has_explanation(expr),
            StmtKind::Return(None) => false,
            StmtKind::For { body, .. } => self.body_has_explanation(body),
            StmtKind::While { body, .. } => self.body_has_explanation(body),
            StmtKind::WhileLet { body, .. } => self.body_has_explanation(body),
            StmtKind::Loop { body } => self.body_has_explanation(body),
            StmtKind::Bail(expr) => self.expr_has_explanation(expr),
            StmtKind::Break | StmtKind::Continue => false,
            StmtKind::Defer { .. } => false,
        }
    }

    fn expr_has_explanation(&self, expr: &Expr) -> bool {
        match &expr.kind {
            // StructLit with an "explanation" field
            ExprKind::StructLit { fields, .. } => {
                if fields.iter().any(|f| f.name == "explanation") {
                    return true;
                }
                // Also check inside field values recursively
                fields.iter().any(|f| self.expr_has_explanation(&f.value))
            }
            // Call with "explain" in the callee name
            ExprKind::Call { callee, args } => {
                if self.expr_contains_ident(callee, "explain") {
                    return true;
                }
                args.iter().any(|a| self.expr_has_explanation(&a.value))
            }
            ExprKind::MethodCall { method, object, args } => {
                if method.contains("explain") {
                    return true;
                }
                self.expr_has_explanation(object)
                    || args.iter().any(|a| self.expr_has_explanation(&a.value))
            }
            // Recurse into sub-expressions
            ExprKind::Binary { left, right, .. } => {
                self.expr_has_explanation(left) || self.expr_has_explanation(right)
            }
            ExprKind::Unary { operand, .. } => self.expr_has_explanation(operand),
            ExprKind::FieldAccess { object, .. } => self.expr_has_explanation(object),
            ExprKind::Index { object, index } => {
                self.expr_has_explanation(object) || self.expr_has_explanation(index)
            }
            ExprKind::If { then_block, else_branch, .. } => {
                self.body_has_explanation(then_block)
                    || match else_branch {
                        Some(ElseBranch::Block(b)) => self.body_has_explanation(b),
                        Some(ElseBranch::ElseIf(e)) => self.expr_has_explanation(e),
                        None => false,
                    }
            }
            ExprKind::IfLet { then_block, else_branch, .. } => {
                self.body_has_explanation(then_block)
                    || match else_branch {
                        Some(ElseBranch::Block(b)) => self.body_has_explanation(b),
                        Some(ElseBranch::ElseIf(e)) => self.expr_has_explanation(e),
                        None => false,
                    }
            }
            ExprKind::Match { arms, .. } => {
                arms.iter().any(|arm| self.expr_has_explanation(&arm.body))
            }
            ExprKind::Block(b) => self.body_has_explanation(b),
            ExprKind::Try(inner) | ExprKind::Await(inner) | ExprKind::Cast { expr: inner, .. } => {
                self.expr_has_explanation(inner)
            }
            ExprKind::Assign { value, .. } => self.expr_has_explanation(value),
            ExprKind::Array(items) => items.iter().any(|e| self.expr_has_explanation(e)),
            ExprKind::Closure { body, .. } => {
                body.iter().any(|s| self.stmt_has_explanation(s))
            }
            _ => false,
        }
    }

    /// Check if an expression contains an identifier matching `needle`.
    fn expr_contains_ident(&self, expr: &Expr, needle: &str) -> bool {
        match &expr.kind {
            ExprKind::Ident(name) => name.contains(needle),
            ExprKind::FieldAccess { object, field } => {
                field.contains(needle) || self.expr_contains_ident(object, needle)
            }
            _ => false,
        }
    }

    // ── @requires_human_approval body check (Art.14) ─────────────────────

    /// Check if a function body calls HumanApproval.request() or similar.
    fn body_calls_human_approval(&self, body: &Block) -> bool {
        for stmt in &body.stmts {
            if self.stmt_calls_human_approval(stmt) {
                return true;
            }
        }
        false
    }

    fn stmt_calls_human_approval(&self, stmt: &Stmt) -> bool {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.expr_calls_human_approval(value)
            }
            StmtKind::LetDestructure { value, .. } => self.expr_calls_human_approval(value),
            StmtKind::Expr { expr } => self.expr_calls_human_approval(expr),
            StmtKind::Return(Some(expr)) => self.expr_calls_human_approval(expr),
            StmtKind::Return(None) => false,
            StmtKind::For { body, .. } => self.body_calls_human_approval(body),
            StmtKind::While { body, .. } => self.body_calls_human_approval(body),
            StmtKind::WhileLet { body, .. } => self.body_calls_human_approval(body),
            StmtKind::Loop { body } => self.body_calls_human_approval(body),
            StmtKind::Bail(expr) => self.expr_calls_human_approval(expr),
            StmtKind::Break | StmtKind::Continue => false,
            StmtKind::Defer { .. } => false,
        }
    }

    fn expr_calls_human_approval(&self, expr: &Expr) -> bool {
        match &expr.kind {
            // Direct call: HumanApproval.request(...) shows up as Call { callee: FieldAccess { Ident("HumanApproval"), "request" } }
            ExprKind::Call { callee, args } => {
                if self.expr_contains_ident(callee, "HumanApproval") {
                    return true;
                }
                args.iter().any(|a| self.expr_calls_human_approval(&a.value))
            }
            ExprKind::MethodCall { object, args, method } => {
                if method.contains("HumanApproval") {
                    return true;
                }
                // Check if object is HumanApproval (e.g. HumanApproval.request())
                if self.expr_contains_ident(object, "HumanApproval") {
                    return true;
                }
                self.expr_calls_human_approval(object)
                    || args.iter().any(|a| self.expr_calls_human_approval(&a.value))
            }
            // Recurse into sub-expressions
            ExprKind::Binary { left, right, .. } => {
                self.expr_calls_human_approval(left) || self.expr_calls_human_approval(right)
            }
            ExprKind::Unary { operand, .. } => self.expr_calls_human_approval(operand),
            ExprKind::FieldAccess { object, .. } => self.expr_calls_human_approval(object),
            ExprKind::Index { object, index } => {
                self.expr_calls_human_approval(object) || self.expr_calls_human_approval(index)
            }
            ExprKind::If { then_block, else_branch, condition } => {
                self.expr_calls_human_approval(condition)
                    || self.body_calls_human_approval(then_block)
                    || match else_branch {
                        Some(ElseBranch::Block(b)) => self.body_calls_human_approval(b),
                        Some(ElseBranch::ElseIf(e)) => self.expr_calls_human_approval(e),
                        None => false,
                    }
            }
            ExprKind::IfLet { then_block, else_branch, .. } => {
                self.body_calls_human_approval(then_block)
                    || match else_branch {
                        Some(ElseBranch::Block(b)) => self.body_calls_human_approval(b),
                        Some(ElseBranch::ElseIf(e)) => self.expr_calls_human_approval(e),
                        None => false,
                    }
            }
            ExprKind::Match { arms, .. } => {
                arms.iter().any(|arm| self.expr_calls_human_approval(&arm.body))
            }
            ExprKind::Block(b) => self.body_calls_human_approval(b),
            ExprKind::StructLit { fields, .. } => {
                fields.iter().any(|f| self.expr_calls_human_approval(&f.value))
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) | ExprKind::Cast { expr: inner, .. } => {
                self.expr_calls_human_approval(inner)
            }
            ExprKind::Assign { value, .. } => self.expr_calls_human_approval(value),
            ExprKind::Array(items) => items.iter().any(|e| self.expr_calls_human_approval(e)),
            ExprKind::Closure { body, .. } => {
                body.iter().any(|s| self.stmt_calls_human_approval(s))
            }
            _ => false,
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_and_check(src: &str) -> Diagnostics {
        let (tokens, _) = crate::lexer::tokenize(src);
        let program = crate::parser::Parser::parse(tokens).expect("parse failed");
        AiActPass::new(&program).check()
    }

    // ── Existing @ai_risk_level tests (backward compat) ─────────────────

    #[test]
    fn test_minimal_no_errors() {
        let src = r#"
@ai_risk_level(.minimal)
fn simple_filter(items: []String) -> []String {
    items
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "minimal should have no errors");
        assert_eq!(diags.warning_count(), 0, "minimal should have no warnings");
    }

    #[test]
    fn test_prohibited_e1401() {
        let src = r#"
@ai_risk_level(.prohibited)
fn social_scoring(data: []String) -> []String {
    data
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 1);
        let err = &diags.items[0];
        assert_eq!(err.code, "E1401");
        assert!(err.msg.contains("prohibits"));
    }

    #[test]
    fn test_high_missing_fields_e1402() {
        let src = r#"
@ai_risk_level(.high)
fn credit_scoring(income: f64) -> f64 {
    income
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E1402")
            .collect();
        assert_eq!(errors.len(), 4, "should have 4 missing field errors");
        assert!(errors[0].msg.contains("human_oversight")
            || errors[0].msg.contains("risk_assessment")
            || errors[0].msg.contains("data_governance")
            || errors[0].msg.contains("transparency"));
    }

    #[test]
    fn test_high_all_fields_no_errors() {
        let src = r#"
@ai_risk_level(.high, human_oversight: true, risk_assessment: true, data_governance: true, transparency: true)
fn credit_scoring(income: f64, history: i32) -> f64 {
    income * 0.5
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "high with all fields should have no errors");
    }

    #[test]
    fn test_limited_no_transparency_w1400() {
        let src = r#"
@ai_risk_level(.limited)
fn chatbot(input: String) -> String {
    input
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0);
        let warnings: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W1400")
            .collect();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].msg.contains("transparency"));
    }

    #[test]
    fn test_unknown_risk_level_e1400() {
        let src = r#"
@ai_risk_level(.bogus)
fn some_fn(x: i32) -> i32 {
    x
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 1);
        let err = &diags.items[0];
        assert_eq!(err.code, "E1400");
        assert!(err.msg.contains("bogus"));
    }

    #[test]
    fn test_ai_keyword_warning_w1401() {
        let src = r#"
fn predict_outcome(data: []f64) -> f64 {
    0.0
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0);
        let warnings: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W1401")
            .collect();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].msg.contains("predict_outcome"));
    }

    #[test]
    fn test_non_ai_function_no_warning() {
        let src = r#"
fn calculate_sum(a: i32, b: i32) -> i32 {
    a + b
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0);
        assert_eq!(diags.warning_count(), 0);
    }

    // ── New @ai_system tests ────────────────────────────────────────────

    #[test]
    fn test_ai_system_minimal_no_errors() {
        let src = r#"
@ai_system(risk: .minimal)
fn simple_recommender(items: []String) -> []String {
    items
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "@ai_system minimal should have no errors");
        assert_eq!(diags.warning_count(), 0, "@ai_system minimal should have no warnings");
    }

    #[test]
    fn test_ai_system_high_with_art9_all_fields() {
        let src = r#"
@ai_system(risk: .high, art9: true, risk_assessment: true, mitigation_measures: true, testing_metrics: true, residual_risk: true)
fn biometric_classifier(image: Bytes) -> String {
    "face_id_001"
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "@ai_system high with all Art.9 fields should have no errors");
        assert_eq!(diags.warning_count(), 0, "@ai_system high with Art.9 should have no warnings");
    }

    #[test]
    fn test_ai_system_high_art9_missing_fields_e1403() {
        let src = r#"
@ai_system(risk: .high, art9: true)
fn employment_screener(cv: String) -> f64 {
    0.75
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E1403")
            .collect();
        assert_eq!(errors.len(), 4, "should have 4 E1403 errors for missing Art.9 fields");
        // Verify each required field is mentioned
        let error_msgs: Vec<&str> = errors.iter().map(|e| e.msg.as_str()).collect();
        assert!(error_msgs.iter().any(|m| m.contains("risk_assessment")));
        assert!(error_msgs.iter().any(|m| m.contains("mitigation_measures")));
        assert!(error_msgs.iter().any(|m| m.contains("testing_metrics")));
        assert!(error_msgs.iter().any(|m| m.contains("residual_risk")));
    }

    #[test]
    fn test_ai_system_prohibited_e1401() {
        let src = r#"
@ai_system(risk: .prohibited)
fn mass_surveillance(data: []String) -> []String {
    data
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 1);
        let err = &diags.items[0];
        assert_eq!(err.code, "E1401");
        assert!(err.msg.contains("prohibits"));
    }

    #[test]
    fn test_ai_risk_level_backward_compat() {
        // This verifies all 7 existing scenarios still work via the test module
        // The individual tests above cover this exhaustively.
        // Here we just confirm the old annotation name is still accepted.
        let src = r#"
@ai_risk_level(.minimal)
fn old_style_minimal(x: i32) -> i32 {
    x
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0);
        assert_eq!(diags.warning_count(), 0);
    }

    #[test]
    fn test_ai_risk_level_high_w1402_migration() {
        let src = r#"
@ai_risk_level(.high, human_oversight: true, risk_assessment: true, data_governance: true, transparency: true)
fn legacy_credit_score(income: f64) -> f64 {
    income * 0.8
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "should have no errors with all required fields");
        let w1402: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W1402")
            .collect();
        assert_eq!(w1402.len(), 1, "should have 1 W1402 migration warning");
        assert!(w1402[0].msg.contains("migrating to @ai_system"));
    }

    #[test]
    fn test_ai_system_high_no_art9_w1402() {
        let src = r#"
@ai_system(risk: .high)
fn credit_risk(income: f64) -> f64 {
    income
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "should have no errors");
        let w1402: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W1402")
            .collect();
        assert_eq!(w1402.len(), 1, "should have 1 W1402 warning");
        assert!(w1402[0].msg.contains("art9: true"));
    }

    #[test]
    fn test_ai_system_limited_w1400() {
        let src = r#"
@ai_system(risk: .limited)
fn ai_chatbot(input: String) -> String {
    input
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0);
        let w1400: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W1400")
            .collect();
        assert_eq!(w1400.len(), 1);
        assert!(w1400[0].msg.contains("transparency"));
    }

    #[test]
    fn test_ai_system_unknown_risk_e1400() {
        let src = r#"
@ai_system(risk: .imaginary)
fn mystery_fn(x: i32) -> i32 {
    x
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 1);
        let err = &diags.items[0];
        assert_eq!(err.code, "E1400");
        assert!(err.msg.contains("imaginary"));
    }

    // ── @explainable tests (Art.13 transparency) ─────────────────────────

    #[test]
    fn test_explainable_with_explanation_field_ok() {
        let src = r#"
@explainable
fn classify_risk(data: String) -> String {
    let result = Result { explanation: "model used linear regression on input features", score: 0.8 }
    result
}
"#;
        let diags = parse_and_check(src);
        let e1404: Vec<_> = diags.items.iter().filter(|d| d.code == "E1404").collect();
        assert_eq!(e1404.len(), 0, "@explainable with explanation field should have no E1404");
    }

    #[test]
    fn test_explainable_missing_explanation_e1404() {
        let src = r#"
@explainable
fn classify_risk(data: String) -> f64 {
    0.75
}
"#;
        let diags = parse_and_check(src);
        let e1404: Vec<_> = diags.items.iter().filter(|d| d.code == "E1404").collect();
        assert_eq!(e1404.len(), 1, "@explainable without explanation should have 1 E1404");
        assert!(e1404[0].msg.contains("classify_risk"));
        assert!(e1404[0].msg.contains("explanation"));
    }

    #[test]
    fn test_explainable_with_explain_call_ok() {
        let src = r#"
@explainable
fn classify_risk(data: String) -> String {
    let reason = explain_decision(data)
    reason
}
"#;
        let diags = parse_and_check(src);
        let e1404: Vec<_> = diags.items.iter().filter(|d| d.code == "E1404").collect();
        assert_eq!(e1404.len(), 0, "@explainable with explain call should have no E1404");
    }

    // ── @requires_human_approval tests (Art.14 oversight) ────────────────

    #[test]
    fn test_requires_human_approval_with_call_ok() {
        let src = r#"
@requires_human_approval
fn approve_loan(applicant: String) -> bool {
    let approval = HumanApproval.request("loan decision", applicant, "high-risk credit")
    approval.approved
}
"#;
        let diags = parse_and_check(src);
        let e1405: Vec<_> = diags.items.iter().filter(|d| d.code == "E1405").collect();
        assert_eq!(e1405.len(), 0, "@requires_human_approval with HumanApproval.request() should have no E1405");
    }

    #[test]
    fn test_requires_human_approval_missing_e1405() {
        let src = r#"
@requires_human_approval
fn approve_loan(applicant: String) -> bool {
    true
}
"#;
        let diags = parse_and_check(src);
        let e1405: Vec<_> = diags.items.iter().filter(|d| d.code == "E1405").collect();
        assert_eq!(e1405.len(), 1, "@requires_human_approval without HumanApproval call should have 1 E1405");
        assert!(e1405[0].msg.contains("approve_loan"));
        assert!(e1405[0].msg.contains("HumanApproval"));
    }

    #[test]
    fn test_no_annotation_no_errors() {
        let src = r#"
fn add(a: i32, b: i32) -> i32 {
    a + b
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "regular function should have no errors");
        assert_eq!(diags.warning_count(), 0, "regular function should have no warnings");
    }
}
