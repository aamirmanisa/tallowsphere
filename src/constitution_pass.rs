//! Constitution Pass — Hierarchical constitution enforcement for AI agents.
//!
//! Constitutions define the safety boundaries for AI agents at three layers:
//!
//! 1. **Global** (hardcoded in compiler): Immutable safety floor. Cannot be weakened.
//!    - max_spawn_depth: 10, max_total_agents: 1000
//!    - require_encryption_output: true, require_legal_annotation: true
//!    - max_autonomy: L5
//!
//! 2. **Project** (from `[constitution]` in tallow.toml): Restricts global defaults.
//!    Can only reduce, never expand.
//!
//! 3. **Agent** (from `@agent_task` annotation fields or `constitution:` reference):
//!    Restricts the effective (global + project) constitution. Can only reduce, never expand.
//!
//! Each layer can only restrict the layer above — never expand.
//! Constitution violations are compile errors (E08xx).
//!
//! Error codes:
//! - E0800: L5 agent missing constitution reference
//! - E0801: Agent constitution exceeds effective (project or global) constitution
//! - E0802: Project constitution exceeds global constitution
//! - E0804: Agent calls a prohibited action
//! - E0805: Constitution requires @legal annotation but agent has none

use crate::ast::*;
use crate::error::{Diagnostic, Diagnostics};
use crate::typeck::TypeEnv;

// ── Constitution ────────────────────────────────────────────────────────────

/// Represents a constitution -- a set of safety constraints for agents.
/// Each field is an Option -- None means "inherit from parent level."
#[derive(Debug, Clone)]
pub struct Constitution {
    pub max_autonomy: Option<AgentLevel>,
    pub max_spawn_depth: Option<u32>,
    pub max_total_agents: Option<u32>,
    pub require_encryption_output: Option<bool>,
    pub require_legal_annotation: Option<bool>,
    pub max_budget_usd: Option<f64>,
    pub max_requests_per_minute: Option<u32>,
    pub allowed_domains: Option<Vec<String>>,
    pub blocked_domains: Option<Vec<String>>,
    pub prohibited_actions: Option<Vec<String>>,
}

impl Constitution {
    /// Create an empty constitution (all fields None — inherit everything).
    pub fn empty() -> Self {
        Self {
            max_autonomy: None,
            max_spawn_depth: None,
            max_total_agents: None,
            require_encryption_output: None,
            require_legal_annotation: None,
            max_budget_usd: None,
            max_requests_per_minute: None,
            allowed_domains: None,
            blocked_domains: None,
            prohibited_actions: None,
        }
    }
}

// ── Global Constitution ─────────────────────────────────────────────────────

/// Returns the global constitution — immutable, hardcoded in the compiler.
/// This cannot be weakened by any project or agent constitution.
pub fn global_constitution() -> Constitution {
    Constitution {
        max_autonomy: Some(AgentLevel::L5),
        max_spawn_depth: Some(10),
        max_total_agents: Some(1000),
        require_encryption_output: Some(true),
        require_legal_annotation: Some(true),
        max_budget_usd: None,        // no global USD limit
        max_requests_per_minute: None, // no global rate limit
        allowed_domains: None,
        blocked_domains: None,
        prohibited_actions: None,
    }
}

// ── TOML Parsing ────────────────────────────────────────────────────────────

impl Constitution {
    /// Parse a `[constitution]` section from tallow.toml content.
    /// Returns None if no `[constitution]` section is found.
    pub fn parse_from_toml(content: &str) -> Option<Constitution> {
        let mut in_section = false;
        let mut c = Constitution::empty();
        let mut found = false;

        for line in content.lines() {
            let trimmed = line.trim();

            // Detect section headers
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                let section_name = trimmed[1..trimmed.len() - 1].trim();
                in_section = section_name == "constitution";
                if in_section {
                    found = true;
                }
                continue;
            }

            if !in_section {
                continue;
            }

            // Skip blank lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Parse key = value
            let Some((key, value)) = trimmed.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();

            match key {
                "max_autonomy" => {
                    let s = value.trim_matches('"');
                    if let Some(level) = AgentLevel::from_str(s) {
                        c.max_autonomy = Some(level);
                    }
                }
                "max_spawn_depth" => {
                    if let Ok(n) = value.parse::<u32>() {
                        c.max_spawn_depth = Some(n);
                    }
                }
                "max_total_agents" => {
                    if let Ok(n) = value.parse::<u32>() {
                        c.max_total_agents = Some(n);
                    }
                }
                "require_encryption_output" => {
                    c.require_encryption_output = Some(value == "true");
                }
                "require_legal_annotation" => {
                    c.require_legal_annotation = Some(value == "true");
                }
                "max_budget_usd" => {
                    if let Ok(n) = value.parse::<f64>() {
                        c.max_budget_usd = Some(n);
                    }
                }
                "max_requests_per_minute" => {
                    if let Ok(n) = value.parse::<u32>() {
                        c.max_requests_per_minute = Some(n);
                    }
                }
                "allowed_domains" => {
                    c.allowed_domains = Some(parse_toml_string_array(value));
                }
                "blocked_domains" => {
                    c.blocked_domains = Some(parse_toml_string_array(value));
                }
                "prohibited_actions" => {
                    c.prohibited_actions = Some(parse_toml_string_array(value));
                }
                _ => {} // ignore unknown keys
            }
        }

        if found { Some(c) } else { None }
    }

    /// Parse constitution fields from an @agent_task annotation.
    ///
    /// Supports three modes:
    /// - `constitution: .project` — use project constitution as-is (returns empty, meaning inherit)
    /// - `constitution: .global` — use global constitution as-is (returns empty, meaning inherit)
    /// - Individual fields like `max_spawn_depth: 3` in the annotation override the inherited constitution
    pub fn parse_from_annotation(ann: &Annotation) -> (Constitution, ConstitutionRef) {
        let mut c = Constitution::empty();
        let mut cref = ConstitutionRef::None;

        for arg in &ann.args {
            match arg.name.as_str() {
                "constitution" => {
                    match &arg.value.kind {
                        ExprKind::DotIdent(s) => match s.as_str() {
                            "project" => cref = ConstitutionRef::Project,
                            "global" => cref = ConstitutionRef::Global,
                            _ => {}
                        },
                        ExprKind::StringLit(s) => {
                            // Existing path-based constitution reference
                            cref = ConstitutionRef::Path(s.clone());
                        }
                        _ => {}
                    }
                }
                // Constitution override fields in annotation
                "max_spawn_depth" => {
                    if let ExprKind::IntLit(n) = &arg.value.kind {
                        c.max_spawn_depth = Some(*n as u32);
                    }
                }
                "max_total_agents" => {
                    if let ExprKind::IntLit(n) = &arg.value.kind {
                        c.max_total_agents = Some(*n as u32);
                    }
                }
                "max_requests_per_minute" => {
                    if let ExprKind::IntLit(n) = &arg.value.kind {
                        c.max_requests_per_minute = Some(*n as u32);
                    }
                }
                "max_budget_usd" => {
                    match &arg.value.kind {
                        ExprKind::FloatLit(n) => {
                            c.max_budget_usd = Some(*n);
                        }
                        ExprKind::IntLit(n) => {
                            c.max_budget_usd = Some(*n as f64);
                        }
                        _ => {}
                    }
                }
                _ => {} // Other @agent_task fields handled by typeck
            }
        }

        (c, cref)
    }

    /// Merge two constitutions (parent + child). The child can only be MORE restrictive
    /// than the parent. Returns Err with list of violation descriptions if child tries to expand.
    ///
    /// "More restrictive" means:
    /// - Numeric fields: child value <= parent value
    /// - Boolean require_*: child can set true but cannot set false if parent is true
    /// - allowed_domains: child must be a subset of parent's allowed list
    /// - blocked_domains: child can add more blocked domains (always valid)
    /// - prohibited_actions: child can add more prohibited actions (always valid)
    /// - max_autonomy: child level <= parent level
    pub fn merge(parent: &Constitution, child: &Constitution) -> Result<Constitution, Vec<String>> {
        let mut violations = Vec::new();
        let mut merged = parent.clone();

        // max_autonomy: child level must be <= parent level
        if let Some(child_level) = child.max_autonomy {
            if let Some(parent_level) = parent.max_autonomy {
                if child_level > parent_level {
                    violations.push(format!(
                        "max_autonomy: {} exceeds parent {}",
                        level_name(child_level),
                        level_name(parent_level),
                    ));
                } else {
                    merged.max_autonomy = Some(child_level);
                }
            } else {
                merged.max_autonomy = Some(child_level);
            }
        }

        // max_spawn_depth: child <= parent
        check_numeric_field(
            "max_spawn_depth",
            parent.max_spawn_depth,
            child.max_spawn_depth,
            &mut merged.max_spawn_depth,
            &mut violations,
        );

        // max_total_agents: child <= parent
        check_numeric_field(
            "max_total_agents",
            parent.max_total_agents,
            child.max_total_agents,
            &mut merged.max_total_agents,
            &mut violations,
        );

        // max_requests_per_minute: child <= parent
        check_numeric_field(
            "max_requests_per_minute",
            parent.max_requests_per_minute,
            child.max_requests_per_minute,
            &mut merged.max_requests_per_minute,
            &mut violations,
        );

        // max_budget_usd: child <= parent
        if let Some(child_val) = child.max_budget_usd {
            if let Some(parent_val) = parent.max_budget_usd {
                if child_val > parent_val {
                    violations.push(format!(
                        "max_budget_usd: {} exceeds parent {}",
                        child_val, parent_val
                    ));
                } else {
                    merged.max_budget_usd = Some(child_val);
                }
            } else {
                merged.max_budget_usd = Some(child_val);
            }
        }

        // require_encryption_output: child cannot weaken (set false when parent is true)
        check_require_field(
            "require_encryption_output",
            parent.require_encryption_output,
            child.require_encryption_output,
            &mut merged.require_encryption_output,
            &mut violations,
        );

        // require_legal_annotation: child cannot weaken
        check_require_field(
            "require_legal_annotation",
            parent.require_legal_annotation,
            child.require_legal_annotation,
            &mut merged.require_legal_annotation,
            &mut violations,
        );

        // allowed_domains: child must be a subset of parent
        if let Some(ref child_domains) = child.allowed_domains {
            if let Some(ref parent_domains) = parent.allowed_domains {
                let not_in_parent: Vec<&String> = child_domains
                    .iter()
                    .filter(|d| !parent_domains.contains(d))
                    .collect();
                if !not_in_parent.is_empty() {
                    violations.push(format!(
                        "allowed_domains: {:?} not in parent allowed list",
                        not_in_parent
                    ));
                } else {
                    merged.allowed_domains = Some(child_domains.clone());
                }
            } else {
                // Parent has no restriction — child can set any domains
                merged.allowed_domains = Some(child_domains.clone());
            }
        }

        // blocked_domains: child can always add more (union with parent)
        if let Some(ref child_blocked) = child.blocked_domains {
            let mut combined = parent
                .blocked_domains
                .clone()
                .unwrap_or_default();
            for d in child_blocked {
                if !combined.contains(d) {
                    combined.push(d.clone());
                }
            }
            merged.blocked_domains = Some(combined);
        }

        // prohibited_actions: child can always add more (union with parent)
        if let Some(ref child_actions) = child.prohibited_actions {
            let mut combined = parent
                .prohibited_actions
                .clone()
                .unwrap_or_default();
            for a in child_actions {
                if !combined.contains(a) {
                    combined.push(a.clone());
                }
            }
            merged.prohibited_actions = Some(combined);
        }

        if violations.is_empty() {
            Ok(merged)
        } else {
            Err(violations)
        }
    }
}

/// What the `constitution:` annotation argument references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstitutionRef {
    /// No constitution reference specified.
    None,
    /// `constitution: .project` — inherit from project constitution.
    Project,
    /// `constitution: .global` — inherit from global constitution only.
    Global,
    /// `constitution: "path/to/file.md"` — path-based reference (existing behavior).
    Path(String),
}

fn level_name(level: AgentLevel) -> String {
    format!("L{} ({})", level as u8 + 1, level.name())
}

fn check_numeric_field(
    name: &str,
    parent: Option<u32>,
    child: Option<u32>,
    merged: &mut Option<u32>,
    violations: &mut Vec<String>,
) {
    if let Some(child_val) = child {
        if let Some(parent_val) = parent {
            if child_val > parent_val {
                violations.push(format!(
                    "{}: {} exceeds parent {}",
                    name, child_val, parent_val
                ));
            } else {
                *merged = Some(child_val);
            }
        } else {
            *merged = Some(child_val);
        }
    }
}

fn check_require_field(
    name: &str,
    parent: Option<bool>,
    child: Option<bool>,
    merged: &mut Option<bool>,
    violations: &mut Vec<String>,
) {
    if let Some(child_val) = child {
        if let Some(parent_val) = parent {
            if parent_val && !child_val {
                violations.push(format!(
                    "{}: cannot weaken from true to false",
                    name
                ));
            } else {
                *merged = Some(child_val);
            }
        } else {
            *merged = Some(child_val);
        }
    }
}

/// Parse a simple TOML array of strings like `["a", "b", "c"]`.
fn parse_toml_string_array(value: &str) -> Vec<String> {
    let trimmed = value.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return Vec::new();
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    inner
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

// ── Constitution Pass ───────────────────────────────────────────────────────

/// Compiler pass that enforces the three-layer constitution hierarchy.
pub struct ConstitutionPass<'a> {
    program: &'a Program,
    env: &'a TypeEnv,
    global: Constitution,
    project: Option<Constitution>,
    diags: Diagnostics,
}

impl<'a> ConstitutionPass<'a> {
    pub fn new(program: &'a Program, env: &'a TypeEnv, project_toml: Option<&str>) -> Self {
        let global = global_constitution();
        let project = project_toml.and_then(|t| Constitution::parse_from_toml(t));
        Self {
            program,
            env,
            global,
            project,
            diags: Diagnostics::new(),
        }
    }

    pub fn check(mut self) -> Diagnostics {
        // 1. Validate project constitution against global
        self.validate_project_vs_global();
        // 2. For each agent, validate agent constitution against effective constitution
        self.validate_agents();
        self.diags
    }

    /// Validate that the project constitution does not exceed the global constitution.
    fn validate_project_vs_global(&mut self) {
        let Some(ref project) = self.project else {
            return;
        };

        if let Err(violations) = Constitution::merge(&self.global, project) {
            for v in violations {
                self.diags.push(
                    Diagnostic::error(
                        "E0802",
                        format!("project constitution exceeds global constitution: {}", v),
                        crate::lexer::Span::new(0, 0),
                    )
                    .with_help("Project constitution can only restrict global defaults, never expand them"),
                );
            }
        }
    }

    /// Compute the effective constitution: global merged with project (if valid).
    fn effective_constitution(&self) -> Constitution {
        if let Some(ref project) = self.project {
            Constitution::merge(&self.global, project).unwrap_or_else(|_| self.global.clone())
        } else {
            self.global.clone()
        }
    }

    /// Validate each agent's constitution against the effective constitution.
    fn validate_agents(&mut self) {
        let effective = self.effective_constitution();

        for item in &self.program.items {
            let f = match item {
                Item::Fn(f) => f,
                _ => continue,
            };

            let info = match self.env.agent_functions.get(&f.name) {
                Some(info) => info,
                None => continue,
            };

            // Find the @agent_task annotation
            let ann = match f.annotations.iter().find(|a| a.name == "agent_task") {
                Some(a) => a,
                None => continue,
            };

            let (agent_constitution, cref) = Constitution::parse_from_annotation(ann);

            // E0800: L5 agent must have a constitution reference
            if info.level == AgentLevel::L5 && cref == ConstitutionRef::None {
                // Check if the agent has ANY constitution-related field (like max_spawn_depth in annotation)
                let has_constitution_fields = agent_constitution.max_spawn_depth.is_some()
                    || agent_constitution.max_total_agents.is_some()
                    || agent_constitution.max_requests_per_minute.is_some()
                    || agent_constitution.max_budget_usd.is_some();

                if !has_constitution_fields {
                    self.diags.push(
                        Diagnostic::error(
                            "E0800",
                            format!(
                                "L5 ({}) agent `{}` requires a constitution reference in @agent_task",
                                info.level.name(),
                                f.name
                            ),
                            info.span,
                        )
                        .with_help("Add constitution: .project or constitution: .global to @agent_task"),
                    );
                }
            }

            // Determine which base constitution the agent inherits from
            let base = match cref {
                ConstitutionRef::Global => self.global.clone(),
                ConstitutionRef::Project => {
                    if let Some(ref proj) = self.project {
                        Constitution::merge(&self.global, proj)
                            .unwrap_or_else(|_| self.global.clone())
                    } else {
                        // No project constitution — fall back to global
                        self.global.clone()
                    }
                }
                ConstitutionRef::Path(_) => effective.clone(),
                ConstitutionRef::None => effective.clone(),
            };

            // Merge agent constitution overrides with the base
            if let Err(violations) = Constitution::merge(&base, &agent_constitution) {
                for v in violations {
                    self.diags.push(
                        Diagnostic::error(
                            "E0801",
                            format!(
                                "agent `{}` constitution exceeds effective constitution: {}",
                                f.name, v
                            ),
                            info.span,
                        )
                        .with_help("Agent constitution can only restrict the effective constitution, never expand it"),
                    );
                }
            }

            // Compute final effective constitution for this agent
            let agent_effective = Constitution::merge(&base, &agent_constitution)
                .unwrap_or(base.clone());

            // Check max_autonomy: if constitution says max is lower than agent level
            if let Some(max_level) = agent_effective.max_autonomy {
                if info.level > max_level {
                    self.diags.push(
                        Diagnostic::error(
                            "E0801",
                            format!(
                                "agent `{}` level {} exceeds constitution max_autonomy {}",
                                f.name,
                                level_name(info.level),
                                level_name(max_level),
                            ),
                            info.span,
                        )
                        .with_help("Reduce agent level or increase constitution max_autonomy"),
                    );
                }
            }

            // E0804: Check prohibited actions in agent body
            if let Some(ref prohibited) = agent_effective.prohibited_actions {
                if !prohibited.is_empty() {
                    self.check_prohibited_actions(f, info, prohibited);
                }
            }

            // E0805: Constitution requires @legal but agent has none
            if agent_effective.require_legal_annotation == Some(true) {
                let has_legal = f.annotations.iter().any(|a| a.name == "legal");
                if !has_legal {
                    self.diags.push(
                        Diagnostic::error(
                            "E0805",
                            format!(
                                "constitution requires @legal annotation on agent `{}` but none found",
                                f.name
                            ),
                            info.span,
                        )
                        .with_help("Add a @legal annotation with appropriate basis and purpose"),
                    );
                }
            }
        }
    }

    /// Walk the agent function body and check for calls to prohibited actions.
    fn check_prohibited_actions(
        &mut self,
        f: &FnDecl,
        info: &crate::typeck::AgentFunctionInfo,
        prohibited: &[String],
    ) {
        self.walk_block_for_prohibited(&f.body, &f.name, info.span, prohibited);
    }

    fn walk_block_for_prohibited(
        &mut self,
        block: &Block,
        agent_name: &str,
        span: crate::lexer::Span,
        prohibited: &[String],
    ) {
        for stmt in &block.stmts {
            self.walk_stmt_for_prohibited(stmt, agent_name, span, prohibited);
        }
    }

    fn walk_stmt_for_prohibited(
        &mut self,
        stmt: &Stmt,
        agent_name: &str,
        span: crate::lexer::Span,
        prohibited: &[String],
    ) {
        match &stmt.kind {
            StmtKind::Let { value, .. }
            | StmtKind::Var { value, .. }
            | StmtKind::Expr { expr: value }
            | StmtKind::Bail(value) => {
                self.walk_expr_for_prohibited(value, agent_name, span, prohibited);
            }
            StmtKind::Return(Some(expr)) => {
                self.walk_expr_for_prohibited(expr, agent_name, span, prohibited);
            }
            StmtKind::For { iter, body, .. } => {
                self.walk_expr_for_prohibited(iter, agent_name, span, prohibited);
                self.walk_block_for_prohibited(body, agent_name, span, prohibited);
            }
            StmtKind::While { condition, body } => {
                self.walk_expr_for_prohibited(condition, agent_name, span, prohibited);
                self.walk_block_for_prohibited(body, agent_name, span, prohibited);
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.walk_expr_for_prohibited(expr, agent_name, span, prohibited);
                self.walk_block_for_prohibited(body, agent_name, span, prohibited);
            }
            StmtKind::Loop { body } => {
                self.walk_block_for_prohibited(body, agent_name, span, prohibited);
            }
            StmtKind::LetDestructure { value, .. } => {
                self.walk_expr_for_prohibited(value, agent_name, span, prohibited);
            }
            StmtKind::Return(None) | StmtKind::Break | StmtKind::Continue => {}
            StmtKind::Defer { .. } => {}
        }
    }

    fn walk_expr_for_prohibited(
        &mut self,
        expr: &Expr,
        agent_name: &str,
        agent_span: crate::lexer::Span,
        prohibited: &[String],
    ) {
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                // Check callee name
                if let ExprKind::Ident(name) = &callee.kind {
                    if prohibited.contains(name) {
                        self.diags.push(
                            Diagnostic::error(
                                "E0804",
                                format!(
                                    "agent `{}` calls prohibited action `{}`",
                                    agent_name, name
                                ),
                                expr.span,
                            )
                            .with_help("This action is forbidden by the effective constitution"),
                        );
                    }
                }
                self.walk_expr_for_prohibited(callee, agent_name, agent_span, prohibited);
                for arg in args {
                    self.walk_expr_for_prohibited(&arg.value, agent_name, agent_span, prohibited);
                }
            }
            ExprKind::MethodCall { object, method, args } => {
                if prohibited.contains(method) {
                    self.diags.push(
                        Diagnostic::error(
                            "E0804",
                            format!(
                                "agent `{}` calls prohibited action `{}`",
                                agent_name, method
                            ),
                            expr.span,
                        )
                        .with_help("This action is forbidden by the effective constitution"),
                    );
                }
                self.walk_expr_for_prohibited(object, agent_name, agent_span, prohibited);
                for arg in args {
                    self.walk_expr_for_prohibited(&arg.value, agent_name, agent_span, prohibited);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.walk_expr_for_prohibited(left, agent_name, agent_span, prohibited);
                self.walk_expr_for_prohibited(right, agent_name, agent_span, prohibited);
            }
            ExprKind::Unary { operand, .. } => {
                self.walk_expr_for_prohibited(operand, agent_name, agent_span, prohibited);
            }
            ExprKind::If { condition, then_block, else_branch } => {
                self.walk_expr_for_prohibited(condition, agent_name, agent_span, prohibited);
                self.walk_block_for_prohibited(then_block, agent_name, agent_span, prohibited);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::ElseIf(inner) => {
                            self.walk_expr_for_prohibited(inner, agent_name, agent_span, prohibited);
                        }
                        ElseBranch::Block(block) => {
                            self.walk_block_for_prohibited(block, agent_name, agent_span, prohibited);
                        }
                    }
                }
            }
            ExprKind::IfLet { expr: inner, then_block, else_branch, .. } => {
                self.walk_expr_for_prohibited(inner, agent_name, agent_span, prohibited);
                self.walk_block_for_prohibited(then_block, agent_name, agent_span, prohibited);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::ElseIf(inner_expr) => {
                            self.walk_expr_for_prohibited(inner_expr, agent_name, agent_span, prohibited);
                        }
                        ElseBranch::Block(block) => {
                            self.walk_block_for_prohibited(block, agent_name, agent_span, prohibited);
                        }
                    }
                }
            }
            ExprKind::Match { subject, arms } => {
                self.walk_expr_for_prohibited(subject, agent_name, agent_span, prohibited);
                for arm in arms {
                    self.walk_expr_for_prohibited(&arm.body, agent_name, agent_span, prohibited);
                }
            }
            ExprKind::FieldAccess { object, .. } => {
                self.walk_expr_for_prohibited(object, agent_name, agent_span, prohibited);
            }
            ExprKind::Index { object, index } => {
                self.walk_expr_for_prohibited(object, agent_name, agent_span, prohibited);
                self.walk_expr_for_prohibited(index, agent_name, agent_span, prohibited);
            }
            ExprKind::Array(items) => {
                for item in items {
                    self.walk_expr_for_prohibited(item, agent_name, agent_span, prohibited);
                }
            }
            ExprKind::Closure { body, .. } => {
                for stmt in body {
                    self.walk_stmt_for_prohibited(stmt, agent_name, agent_span, prohibited);
                }
            }
            ExprKind::Block(block) => {
                self.walk_block_for_prohibited(block, agent_name, agent_span, prohibited);
            }
            ExprKind::StructLit { fields, spread, .. } => {
                for f in fields {
                    self.walk_expr_for_prohibited(&f.value, agent_name, agent_span, prohibited);
                }
                if let Some(s) = spread {
                    self.walk_expr_for_prohibited(s, agent_name, agent_span, prohibited);
                }
            }
            ExprKind::MapLit(pairs) => {
                for (k, v) in pairs {
                    self.walk_expr_for_prohibited(k, agent_name, agent_span, prohibited);
                    self.walk_expr_for_prohibited(v, agent_name, agent_span, prohibited);
                }
            }
            ExprKind::Assign { target, value } => {
                self.walk_expr_for_prohibited(target, agent_name, agent_span, prohibited);
                self.walk_expr_for_prohibited(value, agent_name, agent_span, prohibited);
            }
            ExprKind::Cast { expr: inner, .. } => {
                self.walk_expr_for_prohibited(inner, agent_name, agent_span, prohibited);
            }
            ExprKind::Interpolation(parts) => {
                for part in parts {
                    if let StringPart::Expr(e) = part {
                        self.walk_expr_for_prohibited(e, agent_name, agent_span, prohibited);
                    }
                }
            }
            ExprKind::Bail(inner) => {
                self.walk_expr_for_prohibited(inner, agent_name, agent_span, prohibited);
            }
            ExprKind::Try(inner) => {
                self.walk_expr_for_prohibited(inner, agent_name, agent_span, prohibited);
            }
            ExprKind::Await(inner) => {
                self.walk_expr_for_prohibited(inner, agent_name, agent_span, prohibited);
            }
            _ => {} // Literals, identifiers, etc. — no calls
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;
    use crate::parser::Parser;
    use crate::typeck::TypeChecker;

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn check(source: &str) -> Diagnostics {
        check_with_toml(source, None)
    }

    fn check_with_toml(source: &str, toml: Option<&str>) -> Diagnostics {
        let (tokens, _) = lexer::tokenize(source);
        let program = Parser::parse(tokens).unwrap();
        let (env, _) = TypeChecker::new(&program).check();
        ConstitutionPass::new(&program, &env, toml).check()
    }

    fn has_error(diags: &Diagnostics, code: &str) -> bool {
        diags.items.iter().any(|d| d.code == code)
    }

    fn error_count(diags: &Diagnostics, code: &str) -> usize {
        diags.items.iter().filter(|d| d.code == code).count()
    }

    // ── Global Constitution Tests ───────────────────────────────────────────

    #[test]
    fn global_constitution_defaults() {
        let g = global_constitution();
        assert_eq!(g.max_autonomy, Some(AgentLevel::L5));
        assert_eq!(g.max_spawn_depth, Some(10));
        assert_eq!(g.max_total_agents, Some(1000));
        assert_eq!(g.require_encryption_output, Some(true));
        assert_eq!(g.require_legal_annotation, Some(true));
        assert!(g.max_budget_usd.is_none());
        assert!(g.max_requests_per_minute.is_none());
        assert!(g.allowed_domains.is_none());
        assert!(g.blocked_domains.is_none());
        assert!(g.prohibited_actions.is_none());
    }

    // ── TOML Parsing Tests ──────────────────────────────────────────────────

    #[test]
    fn parse_toml_valid_section() {
        let toml = r#"
[package]
name = "test"

[constitution]
max_autonomy = "L3"
max_spawn_depth = 5
max_total_agents = 50
require_encryption_output = true
require_legal_annotation = true
max_budget_usd = 100.0
max_requests_per_minute = 60
allowed_domains = ["example.com", "api.test.com"]
blocked_domains = ["evil.com"]
prohibited_actions = ["delete_file", "execute"]
"#;
        let c = Constitution::parse_from_toml(toml).unwrap();
        assert_eq!(c.max_autonomy, Some(AgentLevel::L3));
        assert_eq!(c.max_spawn_depth, Some(5));
        assert_eq!(c.max_total_agents, Some(50));
        assert_eq!(c.require_encryption_output, Some(true));
        assert_eq!(c.require_legal_annotation, Some(true));
        assert_eq!(c.max_budget_usd, Some(100.0));
        assert_eq!(c.max_requests_per_minute, Some(60));
        assert_eq!(c.allowed_domains, Some(vec!["example.com".into(), "api.test.com".into()]));
        assert_eq!(c.blocked_domains, Some(vec!["evil.com".into()]));
        assert_eq!(c.prohibited_actions, Some(vec!["delete_file".into(), "execute".into()]));
    }

    #[test]
    fn parse_toml_no_section() {
        let toml = r#"
[package]
name = "test"
version = "0.1.0"
"#;
        assert!(Constitution::parse_from_toml(toml).is_none());
    }

    #[test]
    fn parse_toml_partial_section() {
        let toml = r#"
[constitution]
max_spawn_depth = 3
"#;
        let c = Constitution::parse_from_toml(toml).unwrap();
        assert_eq!(c.max_spawn_depth, Some(3));
        assert!(c.max_autonomy.is_none());
        assert!(c.max_total_agents.is_none());
    }

    // ── Annotation Parsing Tests ────────────────────────────────────────────

    #[test]
    fn parse_annotation_project_ref() {
        let (tokens, _) = lexer::tokenize(r#"
            @agent_task(id: task_id, timeout: 60.seconds, level: .L5, constitution: .project, max_requests: 100)
            async fn agent() -> String { "done" }
        "#);
        let program = Parser::parse(tokens).unwrap();
        let f = match &program.items[0] {
            Item::Fn(f) => f,
            _ => panic!("expected function"),
        };
        let ann = f.annotations.iter().find(|a| a.name == "agent_task").unwrap();
        let (_c, cref) = Constitution::parse_from_annotation(ann);
        assert_eq!(cref, ConstitutionRef::Project);
    }

    #[test]
    fn parse_annotation_global_ref() {
        let (tokens, _) = lexer::tokenize(r#"
            @agent_task(id: task_id, timeout: 60.seconds, level: .L5, constitution: .global, max_requests: 100)
            async fn agent() -> String { "done" }
        "#);
        let program = Parser::parse(tokens).unwrap();
        let f = match &program.items[0] {
            Item::Fn(f) => f,
            _ => panic!("expected function"),
        };
        let ann = f.annotations.iter().find(|a| a.name == "agent_task").unwrap();
        let (_c, cref) = Constitution::parse_from_annotation(ann);
        assert_eq!(cref, ConstitutionRef::Global);
    }

    #[test]
    fn parse_annotation_path_ref() {
        let (tokens, _) = lexer::tokenize(r#"
            @agent_task(id: task_id, timeout: 60.seconds, level: .L5, constitution: "safety/const.md", max_requests: 100)
            async fn agent() -> String { "done" }
        "#);
        let program = Parser::parse(tokens).unwrap();
        let f = match &program.items[0] {
            Item::Fn(f) => f,
            _ => panic!("expected function"),
        };
        let ann = f.annotations.iter().find(|a| a.name == "agent_task").unwrap();
        let (_c, cref) = Constitution::parse_from_annotation(ann);
        assert_eq!(cref, ConstitutionRef::Path("safety/const.md".into()));
    }

    // ── Merge Tests ─────────────────────────────────────────────────────────

    #[test]
    fn merge_child_more_restrictive_ok() {
        let parent = Constitution {
            max_spawn_depth: Some(10),
            max_total_agents: Some(1000),
            max_autonomy: Some(AgentLevel::L5),
            require_encryption_output: Some(true),
            require_legal_annotation: Some(true),
            ..Constitution::empty()
        };
        let child = Constitution {
            max_spawn_depth: Some(5),
            max_total_agents: Some(50),
            max_autonomy: Some(AgentLevel::L3),
            ..Constitution::empty()
        };
        let merged = Constitution::merge(&parent, &child).unwrap();
        assert_eq!(merged.max_spawn_depth, Some(5));
        assert_eq!(merged.max_total_agents, Some(50));
        assert_eq!(merged.max_autonomy, Some(AgentLevel::L3));
        assert_eq!(merged.require_encryption_output, Some(true)); // inherited
    }

    #[test]
    fn merge_child_expands_max_spawn_depth_err() {
        let parent = Constitution {
            max_spawn_depth: Some(5),
            ..Constitution::empty()
        };
        let child = Constitution {
            max_spawn_depth: Some(10),
            ..Constitution::empty()
        };
        let result = Constitution::merge(&parent, &child);
        assert!(result.is_err());
        let violations = result.unwrap_err();
        assert!(violations[0].contains("max_spawn_depth"));
    }

    #[test]
    fn merge_child_weakens_require_encryption_err() {
        let parent = Constitution {
            require_encryption_output: Some(true),
            ..Constitution::empty()
        };
        let child = Constitution {
            require_encryption_output: Some(false),
            ..Constitution::empty()
        };
        let result = Constitution::merge(&parent, &child);
        assert!(result.is_err());
        let violations = result.unwrap_err();
        assert!(violations[0].contains("require_encryption_output"));
    }

    #[test]
    fn merge_allowed_domains_subset_ok() {
        let parent = Constitution {
            allowed_domains: Some(vec!["a.com".into(), "b.com".into(), "c.com".into()]),
            ..Constitution::empty()
        };
        let child = Constitution {
            allowed_domains: Some(vec!["a.com".into(), "b.com".into()]),
            ..Constitution::empty()
        };
        let merged = Constitution::merge(&parent, &child).unwrap();
        assert_eq!(merged.allowed_domains, Some(vec!["a.com".into(), "b.com".into()]));
    }

    #[test]
    fn merge_allowed_domains_superset_err() {
        let parent = Constitution {
            allowed_domains: Some(vec!["a.com".into()]),
            ..Constitution::empty()
        };
        let child = Constitution {
            allowed_domains: Some(vec!["a.com".into(), "b.com".into()]),
            ..Constitution::empty()
        };
        let result = Constitution::merge(&parent, &child);
        assert!(result.is_err());
    }

    #[test]
    fn merge_blocked_domains_additive() {
        let parent = Constitution {
            blocked_domains: Some(vec!["evil.com".into()]),
            ..Constitution::empty()
        };
        let child = Constitution {
            blocked_domains: Some(vec!["worse.com".into()]),
            ..Constitution::empty()
        };
        let merged = Constitution::merge(&parent, &child).unwrap();
        let domains = merged.blocked_domains.unwrap();
        assert!(domains.contains(&"evil.com".into()));
        assert!(domains.contains(&"worse.com".into()));
    }

    #[test]
    fn merge_prohibited_actions_additive() {
        let parent = Constitution {
            prohibited_actions: Some(vec!["delete_file".into()]),
            ..Constitution::empty()
        };
        let child = Constitution {
            prohibited_actions: Some(vec!["execute".into()]),
            ..Constitution::empty()
        };
        let merged = Constitution::merge(&parent, &child).unwrap();
        let actions = merged.prohibited_actions.unwrap();
        assert!(actions.contains(&"delete_file".into()));
        assert!(actions.contains(&"execute".into()));
    }

    #[test]
    fn merge_child_expands_max_autonomy_err() {
        let parent = Constitution {
            max_autonomy: Some(AgentLevel::L3),
            ..Constitution::empty()
        };
        let child = Constitution {
            max_autonomy: Some(AgentLevel::L5),
            ..Constitution::empty()
        };
        let result = Constitution::merge(&parent, &child);
        assert!(result.is_err());
    }

    // ── ConstitutionPass Integration Tests ──────────────────────────────────

    #[test]
    fn l5_agent_without_constitution_e0800() {
        // L5 agent without any constitution reference or fields -> E0800
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 120.seconds, level: .L5, max_requests: 100)
            async fn self_directed() -> String {
                "done"
            }
        "#);
        assert!(has_error(&diags, "E0800"), "L5 without constitution should emit E0800");
    }

    #[test]
    fn l5_agent_with_constitution_project_ok() {
        // L5 agent with constitution: .project -> ok
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 120.seconds, level: .L5, constitution: .project, max_requests: 100)
            @legal(basis: .research, purpose: "test")
            async fn self_directed() -> String {
                "done"
            }
        "#);
        assert!(!has_error(&diags, "E0800"), "L5 with constitution: .project should not emit E0800");
    }

    #[test]
    fn l5_agent_with_constitution_global_ok() {
        // L5 agent with constitution: .global -> ok
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 120.seconds, level: .L5, constitution: .global, max_requests: 100)
            @legal(basis: .research, purpose: "test")
            async fn self_directed() -> String {
                "done"
            }
        "#);
        assert!(!has_error(&diags, "E0800"), "L5 with constitution: .global should not emit E0800");
    }

    #[test]
    fn l4_agent_without_constitution_ok() {
        // L4 agents don't require constitution
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, level: .L4, max_requests: 100)
            @legal(basis: .research, purpose: "test")
            async fn autonomous() -> String {
                "done"
            }
        "#);
        assert!(!has_error(&diags, "E0800"), "L4 without constitution should pass");
    }

    #[test]
    fn project_exceeds_global_max_spawn_depth_e0802() {
        // Project constitution tries to expand max_spawn_depth beyond global (10)
        let toml = r#"
[constitution]
max_spawn_depth = 20
"#;
        let diags = check_with_toml(r#"
            fn main() { }
        "#, Some(toml));
        assert!(has_error(&diags, "E0802"), "Project exceeding global max_spawn_depth should emit E0802");
    }

    #[test]
    fn project_exceeds_global_max_total_agents_e0802() {
        // Project constitution tries to expand max_total_agents beyond global (1000)
        let toml = r#"
[constitution]
max_total_agents = 5000
"#;
        let diags = check_with_toml(r#"
            fn main() { }
        "#, Some(toml));
        assert!(has_error(&diags, "E0802"), "Project exceeding global max_total_agents should emit E0802");
    }

    #[test]
    fn project_restricts_global_ok() {
        // Project constitution restricts global defaults -> valid
        let toml = r#"
[constitution]
max_spawn_depth = 5
max_total_agents = 50
max_autonomy = "L4"
"#;
        let diags = check_with_toml(r#"
            fn main() { }
        "#, Some(toml));
        assert!(!has_error(&diags, "E0802"), "Project restricting global should not emit E0802");
    }

    #[test]
    fn agent_exceeds_project_max_spawn_depth_e0801() {
        // Project says max_spawn_depth: 3, agent tries max_spawn_depth: 5
        let toml = r#"
[constitution]
max_spawn_depth = 3
"#;
        let diags = check_with_toml(r#"
            @agent_task(id: task_id, timeout: 60.seconds, level: .L4, constitution: .project, max_spawn_depth: 5, max_requests: 100)
            @legal(basis: .research, purpose: "test")
            async fn agent() -> String {
                "done"
            }
        "#, Some(toml));
        assert!(has_error(&diags, "E0801"), "Agent exceeding project max_spawn_depth should emit E0801");
    }

    #[test]
    fn agent_restricts_project_max_spawn_depth_ok() {
        // Project says max_spawn_depth: 5, agent says max_spawn_depth: 3 -> ok
        let toml = r#"
[constitution]
max_spawn_depth = 5
"#;
        let diags = check_with_toml(r#"
            @agent_task(id: task_id, timeout: 60.seconds, level: .L4, constitution: .project, max_spawn_depth: 3, max_requests: 100)
            @legal(basis: .research, purpose: "test")
            async fn agent() -> String {
                "done"
            }
        "#, Some(toml));
        assert!(!has_error(&diags, "E0801"), "Agent restricting project should not emit E0801");
    }

    #[test]
    fn project_max_autonomy_l4_with_l5_agent_e0801() {
        // Project says max_autonomy: L4, but agent is L5 -> E0801
        let toml = r#"
[constitution]
max_autonomy = "L4"
"#;
        let diags = check_with_toml(r#"
            @agent_task(id: task_id, timeout: 120.seconds, level: .L5, constitution: .project, max_requests: 100)
            @legal(basis: .research, purpose: "test")
            async fn self_directed() -> String {
                "done"
            }
        "#, Some(toml));
        assert!(has_error(&diags, "E0801"), "L5 agent with project max_autonomy L4 should emit E0801");
    }

    #[test]
    fn agent_calls_prohibited_action_e0804() {
        // Project prohibits "delete_file", agent calls delete_file -> E0804
        let toml = r#"
[constitution]
prohibited_actions = ["delete_file"]
"#;
        let diags = check_with_toml(r#"
            @agent_task(id: task_id, timeout: 60.seconds, level: .L3)
            @legal(basis: .research, purpose: "test")
            fn agent() -> String {
                delete_file("important.txt")
                "done"
            }
        "#, Some(toml));
        assert!(has_error(&diags, "E0804"), "Agent calling prohibited action should emit E0804");
    }

    #[test]
    fn agent_no_prohibited_actions_ok() {
        // Project prohibits "delete_file", agent doesn't call it -> ok
        let toml = r#"
[constitution]
prohibited_actions = ["delete_file"]
"#;
        let diags = check_with_toml(r#"
            @agent_task(id: task_id, timeout: 60.seconds, level: .L3)
            @legal(basis: .research, purpose: "test")
            fn agent() -> String {
                fetch("https://example.com")
                "done"
            }
        "#, Some(toml));
        assert!(!has_error(&diags, "E0804"), "Agent not calling prohibited action should not emit E0804");
    }

    #[test]
    fn constitution_requires_legal_no_legal_e0805() {
        // Global requires @legal, agent has no @legal -> E0805
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, level: .L3)
            fn agent() -> String {
                "done"
            }
        "#);
        assert!(has_error(&diags, "E0805"), "Agent without @legal should emit E0805 when constitution requires it");
    }

    #[test]
    fn constitution_requires_legal_has_legal_ok() {
        // Global requires @legal, agent HAS @legal -> ok
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, level: .L3)
            @legal(basis: .research, purpose: "test")
            fn agent() -> String {
                "done"
            }
        "#);
        assert!(!has_error(&diags, "E0805"), "Agent with @legal should not emit E0805");
    }

    #[test]
    fn no_project_constitution_agents_use_global() {
        // No tallow.toml -> agents validated against global defaults only
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, level: .L3)
            @legal(basis: .research, purpose: "test")
            fn agent() -> String {
                "done"
            }
        "#);
        assert_eq!(diags.error_count(), 0, "Agent with global defaults should have no errors");
    }

    #[test]
    fn multiple_violations_all_reported() {
        // Agent with multiple constitution violations -> all emitted
        let toml = r#"
[constitution]
max_spawn_depth = 3
prohibited_actions = ["delete_file", "execute"]
"#;
        let diags = check_with_toml(r#"
            @agent_task(id: task_id, timeout: 60.seconds, level: .L3, constitution: .project, max_spawn_depth: 10)
            @legal(basis: .research, purpose: "test")
            fn agent() -> String {
                delete_file("test.txt")
                execute("rm -rf /")
                "done"
            }
        "#, Some(toml));
        // E0801 for max_spawn_depth exceeding project, E0804 for prohibited actions
        assert!(has_error(&diags, "E0801"), "Should report max_spawn_depth violation");
        assert!(has_error(&diags, "E0804"), "Should report prohibited action violation");
        assert!(error_count(&diags, "E0804") >= 2, "Should report both prohibited actions");
    }

    #[test]
    fn project_allowed_domains_agent_subset_ok() {
        // Project allows ["a.com", "b.com"], agent annotation doesn't override -> ok
        let toml = r#"
[constitution]
allowed_domains = ["a.com", "b.com"]
"#;
        let diags = check_with_toml(r#"
            @agent_task(id: task_id, timeout: 60.seconds, level: .L3, constitution: .project)
            @legal(basis: .research, purpose: "test")
            fn agent() -> String {
                "done"
            }
        "#, Some(toml));
        assert!(!has_error(&diags, "E0801"), "Agent inheriting project domains should not emit E0801");
    }

    #[test]
    fn non_agent_functions_not_checked() {
        // Regular functions should not be checked by ConstitutionPass
        let toml = r#"
[constitution]
prohibited_actions = ["delete_file"]
"#;
        let diags = check_with_toml(r#"
            fn normal() -> String {
                delete_file("test.txt")
                "done"
            }
        "#, Some(toml));
        assert!(!has_error(&diags, "E0804"), "Non-agent functions should not trigger E0804");
    }

    #[test]
    fn l5_with_constitution_fields_no_e0800() {
        // L5 agent that has constitution override fields (e.g., max_spawn_depth) but no explicit
        // constitution: .project/.global -- should still pass E0800 check since it has constitution fields
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 120.seconds, level: .L5, max_spawn_depth: 3, max_requests: 100)
            @legal(basis: .research, purpose: "test")
            async fn self_directed() -> String {
                "done"
            }
        "#);
        assert!(!has_error(&diags, "E0800"), "L5 with constitution fields should not emit E0800");
    }

    #[test]
    fn project_weakens_require_encryption_e0802() {
        // Project tries to set require_encryption_output = false (global is true) -> E0802
        let toml = r#"
[constitution]
require_encryption_output = false
"#;
        let diags = check_with_toml(r#"
            fn main() { }
        "#, Some(toml));
        assert!(has_error(&diags, "E0802"), "Project weakening require_encryption should emit E0802");
    }

    #[test]
    fn prohibited_action_in_method_call_e0804() {
        // Prohibited action called as method -> E0804
        let toml = r#"
[constitution]
prohibited_actions = ["save"]
"#;
        let diags = check_with_toml(r#"
            @agent_task(id: task_id, timeout: 60.seconds, level: .L3)
            @legal(basis: .research, purpose: "test")
            fn agent() -> String {
                data.save()
                "done"
            }
        "#, Some(toml));
        assert!(has_error(&diags, "E0804"), "Method call to prohibited action should emit E0804");
    }
}
