//! Agent Safety Pass — L1-L5 autonomy level capability validation and inter-agent safety.
//!
//! Validates that @agent_task annotated functions do not exceed the capabilities
//! allowed by their declared autonomy level. Each level acts as a ceiling:
//!
//! - L1 (Tool): max 1 external operation, no branching, no write/store/spawn
//! - L2 (Script): fixed sequence, no conditional branching on external results, no write/store/spawn
//! - L3 (Reactive): branching allowed, write/store allowed, no spawning
//! - L4 (Autonomous): spawning allowed, planning, adaptation
//! - L5 (Self-directed): requires constitution reference
//!
//! Additional safety checks:
//! - Permission non-escalation: child agents cannot exceed parent capabilities (E0610-E0613)
//! - Memory isolation: agents cannot access module-level mutable state (E0614)
//! - Spawn bounds: child spawn depth/count must be strictly less than parent (E0615-E0616)
//! - Budget bounds: L4/L5 agents require resource budget fields (E0617)
//! - Info flow control: private/secret types at agent boundaries require explicit handling (E0618)
//! - Trust type compatibility: Unverified<T> cannot be passed where Trusted<T> expected (E0700)
//! - Redundant verify warning: .verify() on already-Trusted value (W0702)
//! - Fresh storage check: Fresh values stored in non-Fresh struct fields (E0703)
//!
//! Error codes: E0600, E0610-E0619, E0621, E0622, E0623, E0700, W0702, E0703, E0900

use std::collections::HashMap;

use crate::ast::*;
use crate::error::{Diagnostic, Diagnostics};
use crate::lexer::Span;
use crate::typeck::{AgentFunctionInfo, Type, TypeEnv};

// ── Capability Presets ──────────────────────────────────────────────────────

/// What each autonomy level allows as a ceiling.
#[derive(Debug, Clone)]
struct AgentCapabilities {
    can_spawn: bool,
    can_write: bool,
    can_store: bool,
    can_branch_external: bool, // if/match on external operation results
    max_external_ops: Option<u32>, // L1: Some(1), others: None (unlimited)
    requires_constitution: bool,
}

impl AgentLevel {
    fn max_capabilities(&self) -> AgentCapabilities {
        match self {
            AgentLevel::L1 => AgentCapabilities {
                can_spawn: false,
                can_write: false,
                can_store: false,
                can_branch_external: false,
                max_external_ops: Some(1),
                requires_constitution: false,
            },
            AgentLevel::L2 => AgentCapabilities {
                can_spawn: false,
                can_write: false,
                can_store: false,
                can_branch_external: false,
                max_external_ops: None,
                requires_constitution: false,
            },
            AgentLevel::L3 => AgentCapabilities {
                can_spawn: false,
                can_write: true,
                can_store: true,
                can_branch_external: true,
                max_external_ops: None,
                requires_constitution: false,
            },
            AgentLevel::L4 => AgentCapabilities {
                can_spawn: true,
                can_write: true,
                can_store: true,
                can_branch_external: true,
                max_external_ops: None,
                requires_constitution: false,
            },
            AgentLevel::L5 => AgentCapabilities {
                can_spawn: true,
                can_write: true,
                can_store: true,
                can_branch_external: true,
                max_external_ops: None,
                requires_constitution: true,
            },
        }
    }
}

// ── External Operation Detection ────────────────────────────────────────────

/// Functions considered external operations (I/O, network, spawn).
fn is_external_function(name: &str) -> bool {
    matches!(
        name,
        "fetch"
            | "connect"
            | "listen"
            | "bind"
            | "write_file"
            | "create_file"
            | "delete_file"
            | "read_file"
            | "mkdir"
            | "remove_dir"
            | "spawn"
            | "spawn_agent"
            | "parallel_map"
    )
}

/// Methods considered external operations.
fn is_external_method(method: &str) -> bool {
    matches!(
        method,
        "get" | "post"
            | "put"
            | "send"
            | "connect"
            | "write"
            | "insert"
            | "delete"
            | "create"
            | "save"
            | "store"
            | "spawn"
            | "parallel_map"
            | "await_all"
            | "fetch"
            | "query"
    )
}

/// Functions/methods that are spawn operations specifically.
fn is_spawn_function(name: &str) -> bool {
    matches!(name, "spawn" | "spawn_agent" | "parallel_map")
}

fn is_spawn_method(method: &str) -> bool {
    matches!(method, "spawn" | "parallel_map" | "await_all")
}

// ── Agent Safety Pass ───────────────────────────────────────────────────────

pub struct AgentSafetyPass<'a> {
    program: &'a Program,
    env: &'a TypeEnv,
    diags: Diagnostics,
}

impl<'a> AgentSafetyPass<'a> {
    pub fn new(program: &'a Program, env: &'a TypeEnv) -> Self {
        Self {
            program,
            env,
            diags: Diagnostics::new(),
        }
    }

    pub fn check(mut self) -> Diagnostics {
        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.check_function(f),
                Item::Impl(impl_block) => {
                    for method in &impl_block.methods {
                        self.check_function(method);
                    }
                }
                _ => {}
            }
        }
        self.diags
    }

    fn check_function(&mut self, f: &FnDecl) {
        // Only check @agent_task annotated functions that are registered
        let info = match self.env.agent_functions.get(&f.name) {
            Some(info) => info,
            None => return,
        };

        let caps = info.level.max_capabilities();

        // E0600: L5 agent missing constitution
        if caps.requires_constitution && info.constitution.is_none() {
            self.diags.push(
                Diagnostic::error(
                    "E0600",
                    format!(
                        "L5 ({}) agent `{}` requires a `constitution` field in @agent_task",
                        info.level.name(),
                        f.name
                    ),
                    info.span,
                )
                .with_help("Add constitution: \"path/to/constitution.md\" to @agent_task"),
            );
        }

        // E0623: Explicit permissions exceeding level ceiling
        self.check_permission_ceiling(info, &caps);

        // E0619: L1 agent has more than 1 external operation
        if let Some(max_ops) = caps.max_external_ops {
            let count = self.count_external_ops(&f.body);
            if count > max_ops {
                self.diags.push(
                    Diagnostic::error(
                        "E0619",
                        format!(
                            "L1 ({}) agent `{}` allows at most {} external operation(s), found {}",
                            info.level.name(),
                            f.name,
                            max_ops,
                            count
                        ),
                        info.span,
                    )
                    .with_help("L1 agents perform a single I/O action and return immediately"),
                );
            }
        }

        // E0621: L2 agent contains conditional branching on external results
        if !caps.can_branch_external {
            self.check_no_external_branching(&f.body, info);
        }

        // E0622: L3 agent attempts to spawn
        if !caps.can_spawn {
            self.check_no_spawn(&f.body, info);
        }

        // E0610-E0613: Permission non-escalation (child agent calls)
        self.check_non_escalation(&f.body, info);

        // E0614: Memory isolation (no module-level mutable state access)
        self.check_memory_isolation(&f.body, f, info);

        // E0615-E0616: Spawn bounds (depth/count limits)
        self.check_spawn_bounds(&f.body, info);

        // E0617: Budget bounds (L4/L5 require resource budgets)
        self.check_budget_bounds(info);

        // E0618: Information flow control (private/secret at agent boundaries)
        self.check_info_flow(f, info);

        // E0700: Trust type compatibility (Unverified passed where Trusted expected)
        // W0702: Redundant verify on already-Trusted value
        self.check_trust_compatibility(&f.body, f);

        // E0703: Fresh value stored in non-Fresh struct field
        self.check_fresh_storage(&f.body);

        // E0900: Non-orchestrator agent creating channel
        // Only orchestrator agents (can_spawn: true) should create channels.
        // Peer-to-peer channels within the same group are created by the orchestrator
        // and passed to children.
        if !info.can_spawn {
            self.check_no_channel_creation(&f.body, info);
        }

        // E0950: Agent handling secret types requires llm_policy: .local_only
        // W0951: Agent handling private types with allow_cloud policy
        self.check_llm_policy(f, info);
    }

    /// Check that explicit annotation permissions don't exceed level ceiling.
    fn check_permission_ceiling(&mut self, info: &AgentFunctionInfo, caps: &AgentCapabilities) {
        if info.can_write && !caps.can_write {
            self.diags.push(
                Diagnostic::error(
                    "E0623",
                    format!(
                        "explicit permission `can_write: true` exceeds level {} ({}) capabilities",
                        format!("L{}", info.level as u8 + 1),
                        info.level.name()
                    ),
                    info.span,
                )
                .with_help(format!(
                    "Level {} does not allow write operations; use L3 or higher",
                    format!("L{}", info.level as u8 + 1)
                )),
            );
        }

        if info.can_store && !caps.can_store {
            self.diags.push(
                Diagnostic::error(
                    "E0623",
                    format!(
                        "explicit permission `can_store: true` exceeds level {} ({}) capabilities",
                        format!("L{}", info.level as u8 + 1),
                        info.level.name()
                    ),
                    info.span,
                )
                .with_help(format!(
                    "Level {} does not allow store operations; use L3 or higher",
                    format!("L{}", info.level as u8 + 1)
                )),
            );
        }

        if info.can_spawn && !caps.can_spawn {
            self.diags.push(
                Diagnostic::error(
                    "E0623",
                    format!(
                        "explicit permission `can_spawn: true` exceeds level {} ({}) capabilities",
                        format!("L{}", info.level as u8 + 1),
                        info.level.name()
                    ),
                    info.span,
                )
                .with_help(format!(
                    "Level {} does not allow spawning; use L4 or higher",
                    format!("L{}", info.level as u8 + 1)
                )),
            );
        }
    }

    // ── Count external operations ───────────────────────────────────────────

    fn count_external_ops(&self, block: &Block) -> u32 {
        let mut count = 0u32;
        for stmt in &block.stmts {
            count += self.count_external_ops_stmt(stmt);
        }
        count
    }

    fn count_external_ops_stmt(&self, stmt: &Stmt) -> u32 {
        match &stmt.kind {
            StmtKind::Expr { expr } => self.count_external_ops_expr(expr),
            StmtKind::Let { value, .. }
            | StmtKind::Var { value, .. }
            | StmtKind::LetDestructure { value, .. } => self.count_external_ops_expr(value),
            StmtKind::Return(Some(e)) | StmtKind::Bail(e) => self.count_external_ops_expr(e),
            StmtKind::Return(None) => 0,
            StmtKind::For { iter, body, .. } => {
                self.count_external_ops_expr(iter) + self.count_external_ops(body)
            }
            StmtKind::While { condition, body } => {
                self.count_external_ops_expr(condition) + self.count_external_ops(body)
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.count_external_ops_expr(expr) + self.count_external_ops(body)
            }
            StmtKind::Loop { body } => self.count_external_ops(body),
            StmtKind::Break | StmtKind::Continue => 0,
            StmtKind::Defer { .. } => 0,
        }
    }

    fn count_external_ops_expr(&self, expr: &Expr) -> u32 {
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                let mut count = 0u32;
                if let ExprKind::Ident(name) = &callee.kind {
                    if is_external_function(name) {
                        count += 1;
                    }
                }
                for arg in args {
                    count += self.count_external_ops_expr(&arg.value);
                }
                count
            }
            ExprKind::MethodCall {
                object,
                method,
                args,
            } => {
                let mut count = 0u32;
                if is_external_method(method) {
                    count += 1;
                }
                count += self.count_external_ops_expr(object);
                for arg in args {
                    count += self.count_external_ops_expr(&arg.value);
                }
                count
            }
            ExprKind::Binary { left, right, .. } => {
                self.count_external_ops_expr(left) + self.count_external_ops_expr(right)
            }
            ExprKind::If {
                condition,
                then_block,
                else_branch,
            } => {
                let mut count = self.count_external_ops_expr(condition)
                    + self.count_external_ops(then_block);
                if let Some(eb) = else_branch {
                    count += match eb {
                        ElseBranch::Block(b) => self.count_external_ops(b),
                        ElseBranch::ElseIf(e) => self.count_external_ops_expr(e),
                    };
                }
                count
            }
            ExprKind::IfLet {
                expr,
                then_block,
                else_branch,
                ..
            } => {
                let mut count =
                    self.count_external_ops_expr(expr) + self.count_external_ops(then_block);
                if let Some(eb) = else_branch {
                    count += match eb {
                        ElseBranch::Block(b) => self.count_external_ops(b),
                        ElseBranch::ElseIf(e) => self.count_external_ops_expr(e),
                    };
                }
                count
            }
            ExprKind::Match { subject, arms } => {
                let mut count = self.count_external_ops_expr(subject);
                for arm in arms {
                    count += self.count_external_ops_expr(&arm.body);
                }
                count
            }
            ExprKind::Block(b) => self.count_external_ops(b),
            ExprKind::Closure { body, .. } => {
                let mut count = 0u32;
                for s in body {
                    count += self.count_external_ops_stmt(s);
                }
                count
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) => self.count_external_ops_expr(inner),
            _ => 0,
        }
    }

    // ── Check for conditional branching on external results (L1/L2) ─────────

    fn check_no_external_branching(&mut self, block: &Block, info: &AgentFunctionInfo) {
        for stmt in &block.stmts {
            self.check_stmt_no_external_branching(stmt, info);
        }
    }

    fn check_stmt_no_external_branching(&mut self, stmt: &Stmt, info: &AgentFunctionInfo) {
        match &stmt.kind {
            StmtKind::Expr { expr } => self.check_expr_no_external_branching(expr, info),
            StmtKind::Let { value, .. }
            | StmtKind::Var { value, .. }
            | StmtKind::LetDestructure { value, .. } => {
                self.check_expr_no_external_branching(value, info)
            }
            StmtKind::Return(Some(e)) | StmtKind::Bail(e) => {
                self.check_expr_no_external_branching(e, info)
            }
            StmtKind::Return(None) => {}
            StmtKind::For { iter, body, .. } => {
                self.check_expr_no_external_branching(iter, info);
                self.check_no_external_branching(body, info);
            }
            StmtKind::While { condition, body } => {
                self.check_expr_no_external_branching(condition, info);
                self.check_no_external_branching(body, info);
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.check_expr_no_external_branching(expr, info);
                self.check_no_external_branching(body, info);
            }
            StmtKind::Loop { body } => {
                self.check_no_external_branching(body, info);
            }
            StmtKind::Break | StmtKind::Continue => {}
            StmtKind::Defer { .. } => {}
        }
    }

    fn check_expr_no_external_branching(&mut self, expr: &Expr, info: &AgentFunctionInfo) {
        match &expr.kind {
            ExprKind::If {
                condition,
                then_block,
                else_branch,
            } => {
                // Check if the condition involves an external operation
                if self.expr_has_external_op(condition) {
                    self.diags.push(
                        Diagnostic::error(
                            "E0621",
                            format!(
                                "L{} ({}) agent `{}` cannot branch on external operation results",
                                info.level as u8 + 1,
                                info.level.name(),
                                info.name
                            ),
                            expr.span,
                        )
                        .with_help("L1/L2 agents execute a fixed sequence without conditional branching on external results"),
                    );
                }
                // Still recurse into branches to catch nested violations
                self.check_no_external_branching(then_block, info);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => self.check_no_external_branching(b, info),
                        ElseBranch::ElseIf(e) => {
                            self.check_expr_no_external_branching(e, info)
                        }
                    }
                }
            }
            ExprKind::IfLet {
                expr: inner_expr,
                then_block,
                else_branch,
                ..
            } => {
                // if let on external results is branching
                if self.expr_has_external_op(inner_expr) {
                    self.diags.push(
                        Diagnostic::error(
                            "E0621",
                            format!(
                                "L{} ({}) agent `{}` cannot branch on external operation results",
                                info.level as u8 + 1,
                                info.level.name(),
                                info.name
                            ),
                            expr.span,
                        )
                        .with_help("L1/L2 agents execute a fixed sequence without conditional branching on external results"),
                    );
                }
                self.check_no_external_branching(then_block, info);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => self.check_no_external_branching(b, info),
                        ElseBranch::ElseIf(e) => {
                            self.check_expr_no_external_branching(e, info)
                        }
                    }
                }
            }
            ExprKind::Match { subject, arms } => {
                // Match on external result is branching
                if self.expr_has_external_op(subject) {
                    self.diags.push(
                        Diagnostic::error(
                            "E0621",
                            format!(
                                "L{} ({}) agent `{}` cannot branch on external operation results",
                                info.level as u8 + 1,
                                info.level.name(),
                                info.name
                            ),
                            expr.span,
                        )
                        .with_help("L1/L2 agents execute a fixed sequence without conditional branching on external results"),
                    );
                }
                for arm in arms {
                    self.check_expr_no_external_branching(&arm.body, info);
                }
            }
            ExprKind::Call { args, .. } => {
                for arg in args {
                    self.check_expr_no_external_branching(&arg.value, info);
                }
            }
            ExprKind::MethodCall { object, args, .. } => {
                self.check_expr_no_external_branching(object, info);
                for arg in args {
                    self.check_expr_no_external_branching(&arg.value, info);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.check_expr_no_external_branching(left, info);
                self.check_expr_no_external_branching(right, info);
            }
            ExprKind::Block(b) => {
                self.check_no_external_branching(b, info);
            }
            ExprKind::Closure { body, .. } => {
                for s in body {
                    self.check_stmt_no_external_branching(s, info);
                }
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) => {
                self.check_expr_no_external_branching(inner, info);
            }
            _ => {}
        }
    }

    /// Check if an expression directly involves an external operation call.
    fn expr_has_external_op(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Call { callee, .. } => {
                if let ExprKind::Ident(name) = &callee.kind {
                    if is_external_function(name) {
                        return true;
                    }
                }
                false
            }
            ExprKind::MethodCall { method, .. } => is_external_method(method),
            ExprKind::Try(inner) | ExprKind::Await(inner) => self.expr_has_external_op(inner),
            _ => false,
        }
    }

    // ── Check for spawn operations (L1/L2/L3) ──────────────────────────────

    fn check_no_spawn(&mut self, block: &Block, info: &AgentFunctionInfo) {
        for stmt in &block.stmts {
            self.check_stmt_no_spawn(stmt, info);
        }
    }

    fn check_stmt_no_spawn(&mut self, stmt: &Stmt, info: &AgentFunctionInfo) {
        match &stmt.kind {
            StmtKind::Expr { expr } => self.check_expr_no_spawn(expr, info),
            StmtKind::Let { value, .. }
            | StmtKind::Var { value, .. }
            | StmtKind::LetDestructure { value, .. } => {
                self.check_expr_no_spawn(value, info)
            }
            StmtKind::Return(Some(e)) | StmtKind::Bail(e) => self.check_expr_no_spawn(e, info),
            StmtKind::Return(None) => {}
            StmtKind::For { iter, body, .. } => {
                self.check_expr_no_spawn(iter, info);
                self.check_no_spawn(body, info);
            }
            StmtKind::While { condition, body } => {
                self.check_expr_no_spawn(condition, info);
                self.check_no_spawn(body, info);
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.check_expr_no_spawn(expr, info);
                self.check_no_spawn(body, info);
            }
            StmtKind::Loop { body } => {
                self.check_no_spawn(body, info);
            }
            StmtKind::Break | StmtKind::Continue => {}
            StmtKind::Defer { .. } => {}
        }
    }

    fn check_expr_no_spawn(&mut self, expr: &Expr, info: &AgentFunctionInfo) {
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                if let ExprKind::Ident(name) = &callee.kind {
                    if is_spawn_function(name) {
                        self.diags.push(
                            Diagnostic::error(
                                "E0622",
                                format!(
                                    "L{} ({}) agent `{}` cannot spawn child agents",
                                    info.level as u8 + 1,
                                    info.level.name(),
                                    info.name,
                                ),
                                expr.span,
                            )
                            .with_help(format!(
                                "Level {} does not allow spawning; use L4 or higher",
                                format!("L{}", info.level as u8 + 1)
                            )),
                        );
                    }
                }
                for arg in args {
                    self.check_expr_no_spawn(&arg.value, info);
                }
            }
            ExprKind::MethodCall {
                object,
                method,
                args,
            } => {
                if is_spawn_method(method) {
                    self.diags.push(
                        Diagnostic::error(
                            "E0622",
                            format!(
                                "L{} ({}) agent `{}` cannot spawn child agents",
                                info.level as u8 + 1,
                                info.level.name(),
                                info.name,
                            ),
                            expr.span,
                        )
                        .with_help(format!(
                            "Level {} does not allow spawning; use L4 or higher",
                            format!("L{}", info.level as u8 + 1)
                        )),
                    );
                }
                self.check_expr_no_spawn(object, info);
                for arg in args {
                    self.check_expr_no_spawn(&arg.value, info);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.check_expr_no_spawn(left, info);
                self.check_expr_no_spawn(right, info);
            }
            ExprKind::If {
                condition,
                then_block,
                else_branch,
            } => {
                self.check_expr_no_spawn(condition, info);
                self.check_no_spawn(then_block, info);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => self.check_no_spawn(b, info),
                        ElseBranch::ElseIf(e) => self.check_expr_no_spawn(e, info),
                    }
                }
            }
            ExprKind::IfLet {
                expr: inner,
                then_block,
                else_branch,
                ..
            } => {
                self.check_expr_no_spawn(inner, info);
                self.check_no_spawn(then_block, info);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => self.check_no_spawn(b, info),
                        ElseBranch::ElseIf(e) => self.check_expr_no_spawn(e, info),
                    }
                }
            }
            ExprKind::Match { subject, arms } => {
                self.check_expr_no_spawn(subject, info);
                for arm in arms {
                    self.check_expr_no_spawn(&arm.body, info);
                }
            }
            ExprKind::Block(b) => {
                self.check_no_spawn(b, info);
            }
            ExprKind::Closure { body, .. } => {
                for s in body {
                    self.check_stmt_no_spawn(s, info);
                }
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) => {
                self.check_expr_no_spawn(inner, info);
            }
            _ => {}
        }
    }

    // ── Permission Non-Escalation (E0610-E0613) ─────────────────────────────

    /// Walk an @agent_task function body. For every call to another @agent_task function,
    /// validate that the child's capabilities do not exceed the parent's.
    fn check_non_escalation(&mut self, block: &Block, parent: &AgentFunctionInfo) {
        for stmt in &block.stmts {
            self.check_stmt_non_escalation(stmt, parent);
        }
    }

    fn check_stmt_non_escalation(&mut self, stmt: &Stmt, parent: &AgentFunctionInfo) {
        match &stmt.kind {
            StmtKind::Expr { expr } => self.check_expr_non_escalation(expr, parent),
            StmtKind::Let { value, .. }
            | StmtKind::Var { value, .. }
            | StmtKind::LetDestructure { value, .. } => {
                self.check_expr_non_escalation(value, parent)
            }
            StmtKind::Return(Some(e)) | StmtKind::Bail(e) => {
                self.check_expr_non_escalation(e, parent)
            }
            StmtKind::Return(None) => {}
            StmtKind::For { iter, body, .. } => {
                self.check_expr_non_escalation(iter, parent);
                self.check_non_escalation(body, parent);
            }
            StmtKind::While { condition, body } => {
                self.check_expr_non_escalation(condition, parent);
                self.check_non_escalation(body, parent);
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.check_expr_non_escalation(expr, parent);
                self.check_non_escalation(body, parent);
            }
            StmtKind::Loop { body } => {
                self.check_non_escalation(body, parent);
            }
            StmtKind::Break | StmtKind::Continue => {}
            StmtKind::Defer { .. } => {}
        }
    }

    fn check_expr_non_escalation(&mut self, expr: &Expr, parent: &AgentFunctionInfo) {
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                if let ExprKind::Ident(name) = &callee.kind {
                    if let Some(child) = self.env.agent_functions.get(name.as_str()) {
                        self.validate_non_escalation(expr.span, parent, child);
                    }
                }
                for arg in args {
                    self.check_expr_non_escalation(&arg.value, parent);
                }
            }
            ExprKind::MethodCall {
                object, args, ..
            } => {
                self.check_expr_non_escalation(object, parent);
                for arg in args {
                    self.check_expr_non_escalation(&arg.value, parent);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.check_expr_non_escalation(left, parent);
                self.check_expr_non_escalation(right, parent);
            }
            ExprKind::If {
                condition,
                then_block,
                else_branch,
            } => {
                self.check_expr_non_escalation(condition, parent);
                self.check_non_escalation(then_block, parent);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => self.check_non_escalation(b, parent),
                        ElseBranch::ElseIf(e) => self.check_expr_non_escalation(e, parent),
                    }
                }
            }
            ExprKind::IfLet {
                expr: inner,
                then_block,
                else_branch,
                ..
            } => {
                self.check_expr_non_escalation(inner, parent);
                self.check_non_escalation(then_block, parent);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => self.check_non_escalation(b, parent),
                        ElseBranch::ElseIf(e) => self.check_expr_non_escalation(e, parent),
                    }
                }
            }
            ExprKind::Match { subject, arms } => {
                self.check_expr_non_escalation(subject, parent);
                for arm in arms {
                    self.check_expr_non_escalation(&arm.body, parent);
                }
            }
            ExprKind::Block(b) => {
                self.check_non_escalation(b, parent);
            }
            ExprKind::Closure { body, .. } => {
                for s in body {
                    self.check_stmt_non_escalation(s, parent);
                }
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) => {
                self.check_expr_non_escalation(inner, parent);
            }
            _ => {}
        }
    }

    /// Validate that child agent capabilities do not exceed parent's.
    fn validate_non_escalation(
        &mut self,
        call_span: Span,
        parent: &AgentFunctionInfo,
        child: &AgentFunctionInfo,
    ) {
        // E0610: capability escalation (can_write, can_store, can_execute)
        if child.can_write && !parent.can_write {
            self.diags.push(
                Diagnostic::error(
                    "E0610",
                    format!(
                        "child agent `{}` has `can_write: true` but parent `{}` has `can_write: false`",
                        child.name, parent.name
                    ),
                    call_span,
                )
                .with_help("child agent capabilities cannot exceed parent — remove can_write from child or grant it to parent"),
            );
        }
        if child.can_store && !parent.can_store {
            self.diags.push(
                Diagnostic::error(
                    "E0610",
                    format!(
                        "child agent `{}` has `can_store: true` but parent `{}` has `can_store: false`",
                        child.name, parent.name
                    ),
                    call_span,
                )
                .with_help("child agent capabilities cannot exceed parent — remove can_store from child or grant it to parent"),
            );
        }
        if child.can_execute && !parent.can_execute {
            self.diags.push(
                Diagnostic::error(
                    "E0610",
                    format!(
                        "child agent `{}` has `can_execute: true` but parent `{}` has `can_execute: false`",
                        child.name, parent.name
                    ),
                    call_span,
                )
                .with_help("child agent capabilities cannot exceed parent — remove can_execute from child or grant it to parent"),
            );
        }

        // E0611: child level exceeds parent level
        if child.level > parent.level {
            self.diags.push(
                Diagnostic::error(
                    "E0611",
                    format!(
                        "child agent `{}` (L{} {}) exceeds parent `{}` (L{} {}) autonomy level",
                        child.name,
                        child.level as u8 + 1,
                        child.level.name(),
                        parent.name,
                        parent.level as u8 + 1,
                        parent.level.name(),
                    ),
                    call_span,
                )
                .with_help("child agent level must be less than or equal to parent level"),
            );
        }

        // E0612: child can_spawn but parent cannot
        if child.can_spawn && !parent.can_spawn {
            self.diags.push(
                Diagnostic::error(
                    "E0612",
                    format!(
                        "child agent `{}` has `can_spawn: true` but parent `{}` has `can_spawn: false`",
                        child.name, parent.name
                    ),
                    call_span,
                )
                .with_help("child agent cannot spawn if parent cannot — remove can_spawn from child or grant it to parent"),
            );
        }

        // E0613: child can_network but parent cannot
        if child.can_network && !parent.can_network {
            self.diags.push(
                Diagnostic::error(
                    "E0613",
                    format!(
                        "child agent `{}` has `can_network: true` but parent `{}` has `can_network: false`",
                        child.name, parent.name
                    ),
                    call_span,
                )
                .with_help("child agent cannot use network if parent cannot — set can_network: false on child or grant it to parent"),
            );
        }
    }

    // ── Memory Isolation (E0614) ────────────────────────────────────────────

    /// Check that @agent_task functions do not reference module-level mutable state.
    /// Top-level `let` (immutable) and `const` are allowed; top-level `var` is not.
    fn check_memory_isolation(
        &mut self,
        block: &Block,
        f: &FnDecl,
        info: &AgentFunctionInfo,
    ) {
        // Collect module-level mutable variable names (top-level `var` statements).
        // In Tallow, top-level items are Item variants. We look for functions whose
        // bodies contain top-level var declarations that could serve as shared state.
        // Since Tallow doesn't have Item::Var, we look at the main function's top-level
        // var bindings as a conservative proxy for module-level mutable state.
        let mut module_vars: Vec<String> = Vec::new();
        for item in &self.program.items {
            if let Item::Fn(other_f) = item {
                // "main" function's top-level vars are module-level mutable state
                if other_f.name == "main" && other_f.name != f.name {
                    for stmt in &other_f.body.stmts {
                        if let StmtKind::Var { name, .. } = &stmt.kind {
                            module_vars.push(name.clone());
                        }
                    }
                }
            }
        }

        // Also collect local variable names for this function (params + let/var bindings)
        let mut local_vars: Vec<String> = Vec::new();
        for p in &f.params {
            local_vars.push(p.name.clone());
        }
        self.collect_local_vars(&block.stmts, &mut local_vars);

        // Walk the body looking for identifiers that match module-level vars
        // and are NOT local to this function
        self.check_block_isolation(block, &module_vars, &local_vars, info);
    }

    fn collect_local_vars(&self, stmts: &[Stmt], locals: &mut Vec<String>) {
        for stmt in stmts {
            match &stmt.kind {
                StmtKind::Let { name, .. } | StmtKind::Var { name, .. } => {
                    locals.push(name.clone());
                }
                StmtKind::LetDestructure { names, .. } => {
                    locals.extend(names.iter().cloned());
                }
                StmtKind::For { binding, body, .. } => {
                    locals.push(binding.clone());
                    self.collect_local_vars(&body.stmts, locals);
                }
                StmtKind::While { body, .. }
                | StmtKind::WhileLet { body, .. }
                | StmtKind::Loop { body } => {
                    self.collect_local_vars(&body.stmts, locals);
                }
                _ => {}
            }
        }
    }

    fn check_block_isolation(
        &mut self,
        block: &Block,
        module_vars: &[String],
        local_vars: &[String],
        info: &AgentFunctionInfo,
    ) {
        for stmt in &block.stmts {
            self.check_stmt_isolation(stmt, module_vars, local_vars, info);
        }
    }

    fn check_stmt_isolation(
        &mut self,
        stmt: &Stmt,
        module_vars: &[String],
        local_vars: &[String],
        info: &AgentFunctionInfo,
    ) {
        match &stmt.kind {
            StmtKind::Expr { expr } => {
                self.check_expr_isolation(expr, module_vars, local_vars, info);
            }
            StmtKind::Let { value, .. }
            | StmtKind::Var { value, .. }
            | StmtKind::LetDestructure { value, .. } => {
                self.check_expr_isolation(value, module_vars, local_vars, info);
            }
            StmtKind::Return(Some(e)) | StmtKind::Bail(e) => {
                self.check_expr_isolation(e, module_vars, local_vars, info);
            }
            StmtKind::Return(None) => {}
            StmtKind::For { iter, body, .. } => {
                self.check_expr_isolation(iter, module_vars, local_vars, info);
                self.check_block_isolation(body, module_vars, local_vars, info);
            }
            StmtKind::While { condition, body } => {
                self.check_expr_isolation(condition, module_vars, local_vars, info);
                self.check_block_isolation(body, module_vars, local_vars, info);
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.check_expr_isolation(expr, module_vars, local_vars, info);
                self.check_block_isolation(body, module_vars, local_vars, info);
            }
            StmtKind::Loop { body } => {
                self.check_block_isolation(body, module_vars, local_vars, info);
            }
            StmtKind::Break | StmtKind::Continue => {}
            StmtKind::Defer { .. } => {}
        }
    }

    fn check_expr_isolation(
        &mut self,
        expr: &Expr,
        module_vars: &[String],
        local_vars: &[String],
        info: &AgentFunctionInfo,
    ) {
        match &expr.kind {
            ExprKind::Ident(name) => {
                if module_vars.contains(name) && !local_vars.contains(name) {
                    self.diags.push(
                        Diagnostic::error(
                            "E0614",
                            format!(
                                "agent function `{}` cannot access module-level mutable state `{}`",
                                info.name, name
                            ),
                            expr.span,
                        )
                        .with_help("agents must be isolated — use function parameters to pass data instead of shared mutable state"),
                    );
                }
            }
            ExprKind::Call { callee, args } => {
                self.check_expr_isolation(callee, module_vars, local_vars, info);
                for arg in args {
                    self.check_expr_isolation(&arg.value, module_vars, local_vars, info);
                }
            }
            ExprKind::MethodCall {
                object, args, ..
            } => {
                self.check_expr_isolation(object, module_vars, local_vars, info);
                for arg in args {
                    self.check_expr_isolation(&arg.value, module_vars, local_vars, info);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.check_expr_isolation(left, module_vars, local_vars, info);
                self.check_expr_isolation(right, module_vars, local_vars, info);
            }
            ExprKind::If {
                condition,
                then_block,
                else_branch,
            } => {
                self.check_expr_isolation(condition, module_vars, local_vars, info);
                self.check_block_isolation(then_block, module_vars, local_vars, info);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => {
                            self.check_block_isolation(b, module_vars, local_vars, info);
                        }
                        ElseBranch::ElseIf(e) => {
                            self.check_expr_isolation(e, module_vars, local_vars, info);
                        }
                    }
                }
            }
            ExprKind::IfLet {
                expr: inner,
                then_block,
                else_branch,
                ..
            } => {
                self.check_expr_isolation(inner, module_vars, local_vars, info);
                self.check_block_isolation(then_block, module_vars, local_vars, info);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => {
                            self.check_block_isolation(b, module_vars, local_vars, info);
                        }
                        ElseBranch::ElseIf(e) => {
                            self.check_expr_isolation(e, module_vars, local_vars, info);
                        }
                    }
                }
            }
            ExprKind::Match { subject, arms } => {
                self.check_expr_isolation(subject, module_vars, local_vars, info);
                for arm in arms {
                    self.check_expr_isolation(&arm.body, module_vars, local_vars, info);
                }
            }
            ExprKind::Block(b) => {
                self.check_block_isolation(b, module_vars, local_vars, info);
            }
            ExprKind::Closure { body, .. } => {
                for s in body {
                    self.check_stmt_isolation(s, module_vars, local_vars, info);
                }
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) => {
                self.check_expr_isolation(inner, module_vars, local_vars, info);
            }
            ExprKind::Assign { target, value } => {
                self.check_expr_isolation(target, module_vars, local_vars, info);
                self.check_expr_isolation(value, module_vars, local_vars, info);
            }
            ExprKind::FieldAccess { object, .. } => {
                self.check_expr_isolation(object, module_vars, local_vars, info);
            }
            ExprKind::Index { object, index } => {
                self.check_expr_isolation(object, module_vars, local_vars, info);
                self.check_expr_isolation(index, module_vars, local_vars, info);
            }
            ExprKind::Array(elements) => {
                for e in elements {
                    self.check_expr_isolation(e, module_vars, local_vars, info);
                }
            }
            _ => {}
        }
    }

    // ── Spawn Bounds (E0615-E0616) ──────────────────────────────────────────

    /// Check that child agents have spawn depth/count strictly less than parent.
    fn check_spawn_bounds(&mut self, block: &Block, parent: &AgentFunctionInfo) {
        for stmt in &block.stmts {
            self.check_stmt_spawn_bounds(stmt, parent);
        }
    }

    fn check_stmt_spawn_bounds(&mut self, stmt: &Stmt, parent: &AgentFunctionInfo) {
        match &stmt.kind {
            StmtKind::Expr { expr } => self.check_expr_spawn_bounds(expr, parent),
            StmtKind::Let { value, .. }
            | StmtKind::Var { value, .. }
            | StmtKind::LetDestructure { value, .. } => {
                self.check_expr_spawn_bounds(value, parent)
            }
            StmtKind::Return(Some(e)) | StmtKind::Bail(e) => {
                self.check_expr_spawn_bounds(e, parent)
            }
            StmtKind::Return(None) => {}
            StmtKind::For { iter, body, .. } => {
                self.check_expr_spawn_bounds(iter, parent);
                self.check_spawn_bounds(body, parent);
            }
            StmtKind::While { condition, body } => {
                self.check_expr_spawn_bounds(condition, parent);
                self.check_spawn_bounds(body, parent);
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.check_expr_spawn_bounds(expr, parent);
                self.check_spawn_bounds(body, parent);
            }
            StmtKind::Loop { body } => {
                self.check_spawn_bounds(body, parent);
            }
            StmtKind::Break | StmtKind::Continue => {}
            StmtKind::Defer { .. } => {}
        }
    }

    fn check_expr_spawn_bounds(&mut self, expr: &Expr, parent: &AgentFunctionInfo) {
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                if let ExprKind::Ident(name) = &callee.kind {
                    if let Some(child) = self.env.agent_functions.get(name.as_str()) {
                        self.validate_spawn_bounds(expr.span, parent, child);
                    }
                }
                for arg in args {
                    self.check_expr_spawn_bounds(&arg.value, parent);
                }
            }
            ExprKind::MethodCall {
                object, args, ..
            } => {
                self.check_expr_spawn_bounds(object, parent);
                for arg in args {
                    self.check_expr_spawn_bounds(&arg.value, parent);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.check_expr_spawn_bounds(left, parent);
                self.check_expr_spawn_bounds(right, parent);
            }
            ExprKind::If {
                condition,
                then_block,
                else_branch,
            } => {
                self.check_expr_spawn_bounds(condition, parent);
                self.check_spawn_bounds(then_block, parent);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => self.check_spawn_bounds(b, parent),
                        ElseBranch::ElseIf(e) => self.check_expr_spawn_bounds(e, parent),
                    }
                }
            }
            ExprKind::IfLet {
                expr: inner,
                then_block,
                else_branch,
                ..
            } => {
                self.check_expr_spawn_bounds(inner, parent);
                self.check_spawn_bounds(then_block, parent);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => self.check_spawn_bounds(b, parent),
                        ElseBranch::ElseIf(e) => self.check_expr_spawn_bounds(e, parent),
                    }
                }
            }
            ExprKind::Match { subject, arms } => {
                self.check_expr_spawn_bounds(subject, parent);
                for arm in arms {
                    self.check_expr_spawn_bounds(&arm.body, parent);
                }
            }
            ExprKind::Block(b) => {
                self.check_spawn_bounds(b, parent);
            }
            ExprKind::Closure { body, .. } => {
                for s in body {
                    self.check_stmt_spawn_bounds(s, parent);
                }
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) => {
                self.check_expr_spawn_bounds(inner, parent);
            }
            _ => {}
        }
    }

    fn validate_spawn_bounds(
        &mut self,
        call_span: Span,
        parent: &AgentFunctionInfo,
        child: &AgentFunctionInfo,
    ) {
        // E0615: max_spawn_depth — child must have strictly less than parent
        if let Some(parent_depth) = parent.max_spawn_depth {
            match child.max_spawn_depth {
                Some(child_depth) if child_depth < parent_depth => {
                    // OK: child depth is strictly less
                }
                Some(child_depth) => {
                    self.diags.push(
                        Diagnostic::error(
                            "E0615",
                            format!(
                                "child agent `{}` max_spawn_depth ({}) must be strictly less than parent `{}` max_spawn_depth ({})",
                                child.name, child_depth, parent.name, parent_depth
                            ),
                            call_span,
                        )
                        .with_help("reduce child's max_spawn_depth to be less than parent's"),
                    );
                }
                None => {
                    self.diags.push(
                        Diagnostic::error(
                            "E0615",
                            format!(
                                "child agent `{}` must declare max_spawn_depth (parent `{}` has max_spawn_depth: {})",
                                child.name, parent.name, parent_depth
                            ),
                            call_span,
                        )
                        .with_help("add max_spawn_depth to child @agent_task annotation with a value less than parent's"),
                    );
                }
            }
        }

        // E0616: max_total_agents — child must have strictly less than parent
        if let Some(parent_total) = parent.max_total_agents {
            match child.max_total_agents {
                Some(child_total) if child_total < parent_total => {
                    // OK
                }
                Some(child_total) => {
                    self.diags.push(
                        Diagnostic::error(
                            "E0616",
                            format!(
                                "child agent `{}` max_total_agents ({}) must be strictly less than parent `{}` max_total_agents ({})",
                                child.name, child_total, parent.name, parent_total
                            ),
                            call_span,
                        )
                        .with_help("reduce child's max_total_agents to be less than parent's"),
                    );
                }
                None => {
                    self.diags.push(
                        Diagnostic::error(
                            "E0616",
                            format!(
                                "child agent `{}` must declare max_total_agents (parent `{}` has max_total_agents: {})",
                                child.name, parent.name, parent_total
                            ),
                            call_span,
                        )
                        .with_help("add max_total_agents to child @agent_task annotation with a value less than parent's"),
                    );
                }
            }
        }
    }

    // ── Budget Bounds (E0617) ───────────────────────────────────────────────

    /// L4 and L5 agents must declare at least one resource budget (max_requests or memory_limit).
    /// Timeout is already required by E0301 in agent_pass.
    fn check_budget_bounds(&mut self, info: &AgentFunctionInfo) {
        let level_num = info.level as u8 + 1;
        if level_num >= 4 && !info.has_max_requests && !info.has_memory_limit {
            self.diags.push(
                Diagnostic::error(
                    "E0617",
                    format!(
                        "L{} ({}) agent `{}` requires at least one resource budget field (max_requests or memory_limit)",
                        level_num,
                        info.level.name(),
                        info.name
                    ),
                    info.span,
                )
                .with_help("add max_requests: N or memory_limit: N.mb to @agent_task for L4/L5 agents"),
            );
        }
    }

    // ── Information Flow Control (E0618) ─────────────────────────────────────

    /// Check that private/secret types don't flow through agent boundaries without
    /// explicit encryption or stripping.
    fn check_info_flow(&mut self, f: &FnDecl, info: &AgentFunctionInfo) {
        // Get function signature from TypeEnv
        let sig = match self.env.functions.get(&f.name) {
            Some(sig) => sig,
            None => return,
        };

        // Check if any parameter has a sensitive type
        let has_private_param = sig.params.iter().any(|(_, ty)| ty.is_private());
        let has_secret_param = sig.params.iter().any(|(_, ty)| ty.is_secret());

        // If no sensitive params, no info flow concern at agent boundary
        if !has_private_param && !has_secret_param {
            // But still check: secret types can NEVER appear in agent return types
            if self.return_type_contains_secret(&sig.return_type) {
                self.diags.push(
                    Diagnostic::error(
                        "E0618",
                        format!(
                            "agent function `{}` returns a secret type -- secret types can never cross agent boundaries",
                            info.name
                        ),
                        info.span,
                    )
                    .with_help("agent functions cannot return secret types -- use .hash() or encrypt the data"),
                );
            }
            return;
        }

        let return_type = &sig.return_type;

        // Secret types can NEVER appear in agent return types
        if has_secret_param && self.return_type_contains_secret(return_type) {
            self.diags.push(
                Diagnostic::error(
                    "E0618",
                    format!(
                        "agent function `{}` receives secret input and returns a secret type -- secret types can never cross agent boundaries",
                        info.name
                    ),
                    info.span,
                )
                .with_help("encrypt or strip secret data before returning from agent functions"),
            );
            return;
        }

        // For private params: check return type
        if has_private_param {
            // Check if return type is an "encrypted" pattern (ok)
            if self.is_encrypted_type(return_type) {
                return; // OK -- output is encrypted
            }

            // Check if return type contains private data (not stripped)
            if self.return_type_contains_private(return_type) {
                let private_param_names: Vec<&str> = sig
                    .params
                    .iter()
                    .filter(|(_, ty)| ty.is_private())
                    .map(|(name, _)| name.as_str())
                    .collect();

                self.diags.push(
                    Diagnostic::error(
                        "E0618",
                        format!(
                            "private type received as input ({}) flows to unprotected output in agent function `{}` -- agent boundary requires explicit handling",
                            private_param_names.join(", "),
                            info.name
                        ),
                        info.span,
                    )
                    .with_help("encrypt, redact, or strip privacy from the return type at agent boundaries"),
                );
            }
            // If return type has NO private types, it's OK (stripped/transformed)
        }
    }

    /// Check if a type matches an "encrypted" pattern (EncryptedResult, EncryptedData, etc.)
    fn is_encrypted_type(&self, ty: &Type) -> bool {
        match ty {
            Type::Named(name) => name.starts_with("Encrypted"),
            Type::Result(inner) => self.is_encrypted_type(inner),
            Type::Optional(inner) => self.is_encrypted_type(inner),
            Type::Array(inner) => self.is_encrypted_type(inner),
            _ => false,
        }
    }

    /// Check if a return type contains private data.
    fn return_type_contains_private(&self, ty: &Type) -> bool {
        match ty {
            Type::Private(_) => true,
            Type::Result(inner) => self.return_type_contains_private(inner),
            Type::Optional(inner) => self.return_type_contains_private(inner),
            Type::Array(inner) => self.return_type_contains_private(inner),
            Type::Tuple(types) => types.iter().any(|t| self.return_type_contains_private(t)),
            _ => false,
        }
    }

    /// Check if a return type contains secret data.
    fn return_type_contains_secret(&self, ty: &Type) -> bool {
        match ty {
            Type::Secret(_) => true,
            Type::Result(inner) => self.return_type_contains_secret(inner),
            Type::Optional(inner) => self.return_type_contains_secret(inner),
            Type::Array(inner) => self.return_type_contains_secret(inner),
            Type::Tuple(types) => types.iter().any(|t| self.return_type_contains_secret(t)),
            _ => false,
        }
    }

    // ── Trust Type Compatibility (E0700, W0702) ───────────────────────────────

    /// Check trust type compatibility in function calls within @agent_task functions.
    /// E0700: Unverified<T> passed where Trusted<T> expected.
    /// W0702: .verify() called on already-Trusted value.
    fn check_trust_compatibility(&mut self, block: &Block, f: &FnDecl) {
        for stmt in &block.stmts {
            self.check_stmt_trust(stmt, f);
        }
    }

    fn check_stmt_trust(&mut self, stmt: &Stmt, f: &FnDecl) {
        match &stmt.kind {
            StmtKind::Expr { expr } => self.check_expr_trust(expr, f),
            StmtKind::Let { value, .. }
            | StmtKind::Var { value, .. }
            | StmtKind::LetDestructure { value, .. } => self.check_expr_trust(value, f),
            StmtKind::Return(Some(e)) | StmtKind::Bail(e) => self.check_expr_trust(e, f),
            StmtKind::Return(None) => {}
            StmtKind::For { iter, body, .. } => {
                self.check_expr_trust(iter, f);
                self.check_trust_compatibility(body, f);
            }
            StmtKind::While { condition, body } => {
                self.check_expr_trust(condition, f);
                self.check_trust_compatibility(body, f);
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.check_expr_trust(expr, f);
                self.check_trust_compatibility(body, f);
            }
            StmtKind::Loop { body } => self.check_trust_compatibility(body, f),
            StmtKind::Break | StmtKind::Continue => {}
            StmtKind::Defer { .. } => {}
        }
    }

    fn check_expr_trust(&mut self, expr: &Expr, f: &FnDecl) {
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                // Check if callee is a known function
                if let ExprKind::Ident(name) = &callee.kind {
                    if let Some(sig) = self.env.functions.get(name) {
                        // Compare each argument type against parameter type
                        for (i, arg) in args.iter().enumerate() {
                            if let Some((_pname, ptype)) = sig.params.get(i) {
                                let arg_type = self.infer_trust_type(&arg.value, f);
                                // E0700: Unverified passed where Trusted expected
                                if ptype.is_trusted() && arg_type.is_unverified() {
                                    let inner_name = format!("{:?}", ptype.strip_trust());
                                    self.diags.push(
                                        Diagnostic::error(
                                            "E0700",
                                            format!(
                                                "cannot pass `Unverified<{}>` where `Trusted<{}>` expected -- call `.verify()` first",
                                                inner_name, inner_name
                                            ),
                                            arg.value.span,
                                        )
                                        .with_help("call .verify() on the unverified value before passing it"),
                                    );
                                }
                            }
                        }
                    }
                }
                // Recurse into args
                for arg in args {
                    self.check_expr_trust(&arg.value, f);
                }
            }
            ExprKind::MethodCall { object, method, args, .. } => {
                // W0702: .verify() on already-Trusted value
                if method == "verify" {
                    let obj_type = self.infer_trust_type(object, f);
                    if obj_type.is_trusted() {
                        self.diags.push(
                            Diagnostic::warning(
                                "W0702",
                                "`.verify()` called on already-trusted value".to_string(),
                                expr.span,
                            )
                            .with_help("this value is already Trusted -- .verify() is redundant"),
                        );
                    }
                }
                self.check_expr_trust(object, f);
                for arg in args {
                    self.check_expr_trust(&arg.value, f);
                }
            }
            ExprKind::If { condition, then_block, else_branch } => {
                self.check_expr_trust(condition, f);
                self.check_trust_compatibility(then_block, f);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => self.check_trust_compatibility(b, f),
                        ElseBranch::ElseIf(e) => self.check_expr_trust(e, f),
                    }
                }
            }
            ExprKind::IfLet { expr: inner, then_block, else_branch, .. } => {
                self.check_expr_trust(inner, f);
                self.check_trust_compatibility(then_block, f);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => self.check_trust_compatibility(b, f),
                        ElseBranch::ElseIf(e) => self.check_expr_trust(e, f),
                    }
                }
            }
            ExprKind::Match { subject, arms } => {
                self.check_expr_trust(subject, f);
                for arm in arms {
                    self.check_expr_trust(&arm.body, f);
                }
            }
            ExprKind::Block(b) => self.check_trust_compatibility(b, f),
            ExprKind::Binary { left, right, .. } => {
                self.check_expr_trust(left, f);
                self.check_expr_trust(right, f);
            }
            ExprKind::Closure { body, .. } => {
                for s in body {
                    self.check_stmt_trust(s, f);
                }
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) => {
                self.check_expr_trust(inner, f);
            }
            _ => {}
        }
    }

    /// Infer trust type of an expression based on parameter declarations.
    /// Conservative: only returns trust types when they're explicitly declared.
    fn infer_trust_type(&self, expr: &Expr, f: &FnDecl) -> Type {
        match &expr.kind {
            ExprKind::Ident(name) => {
                // Check function parameters for explicit trust type annotations
                for param in &f.params {
                    if &param.name == name {
                        return self.resolve_param_trust_type(&param.ty);
                    }
                }
                Type::Unknown
            }
            ExprKind::MethodCall { object, method, .. } => {
                if method == "verify" {
                    let obj_type = self.infer_trust_type(object, f);
                    if obj_type.is_unverified() {
                        return Type::Trusted(Box::new(obj_type.strip_trust().clone()));
                    }
                    if obj_type.is_trusted() {
                        return obj_type;
                    }
                }
                if method == "value" {
                    let obj_type = self.infer_trust_type(object, f);
                    return obj_type.strip_trust().clone();
                }
                Type::Unknown
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) => self.infer_trust_type(inner, f),
            _ => Type::Unknown,
        }
    }

    /// Resolve a TypeExpr to a trust Type (conservative -- just checks for Trusted/Unverified/Fresh wrappers).
    fn resolve_param_trust_type(&self, ty: &TypeExpr) -> Type {
        match &ty.kind {
            TypeExprKind::Generic { name, args } => {
                match name.as_str() {
                    "Trusted" => {
                        let inner = args.first().map(|a| self.resolve_param_trust_type(a))
                            .unwrap_or(Type::Unknown);
                        Type::Trusted(Box::new(inner))
                    }
                    "Unverified" => {
                        let inner = args.first().map(|a| self.resolve_param_trust_type(a))
                            .unwrap_or(Type::Unknown);
                        Type::Unverified(Box::new(inner))
                    }
                    "Fresh" => {
                        let inner = args.first().map(|a| self.resolve_param_trust_type(a))
                            .unwrap_or(Type::Unknown);
                        let ttl = args.get(1).and_then(|a| {
                            if let TypeExprKind::Named(s) = &a.kind { s.parse::<u64>().ok() } else { None }
                        }).unwrap_or(0);
                        Type::Fresh(Box::new(inner), ttl)
                    }
                    _ => Type::Named(name.clone()),
                }
            }
            TypeExprKind::Named(name) => {
                match name.as_str() {
                    "String" => Type::String,
                    "Bytes" => Type::Bytes,
                    "bool" => Type::Bool,
                    "f64" => Type::Float(crate::typeck::FloatSize::F64),
                    "f32" => Type::Float(crate::typeck::FloatSize::F32),
                    "i32" => Type::Int(crate::typeck::IntSize::I32),
                    "i64" => Type::Int(crate::typeck::IntSize::I64),
                    "u32" => Type::Int(crate::typeck::IntSize::U32),
                    "u64" => Type::Int(crate::typeck::IntSize::U64),
                    _ => Type::Named(name.clone()),
                }
            }
            _ => Type::Unknown,
        }
    }

    // ── Fresh Storage Check (E0703) ───────────────────────────────────────────

    /// Check that Fresh-typed values are not stored in non-Fresh struct fields.
    fn check_fresh_storage(&mut self, block: &Block) {
        for stmt in &block.stmts {
            self.check_stmt_fresh_storage(stmt);
        }
    }

    fn check_stmt_fresh_storage(&mut self, stmt: &Stmt) {
        match &stmt.kind {
            StmtKind::Expr { expr } => self.check_expr_fresh_storage(expr),
            StmtKind::Let { value, .. }
            | StmtKind::Var { value, .. }
            | StmtKind::LetDestructure { value, .. } => self.check_expr_fresh_storage(value),
            StmtKind::Return(Some(e)) | StmtKind::Bail(e) => self.check_expr_fresh_storage(e),
            StmtKind::Return(None) => {}
            StmtKind::For { iter, body, .. } => {
                self.check_expr_fresh_storage(iter);
                self.check_fresh_storage(body);
            }
            StmtKind::While { condition, body } => {
                self.check_expr_fresh_storage(condition);
                self.check_fresh_storage(body);
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.check_expr_fresh_storage(expr);
                self.check_fresh_storage(body);
            }
            StmtKind::Loop { body } => self.check_fresh_storage(body),
            StmtKind::Break | StmtKind::Continue => {}
            StmtKind::Defer { .. } => {}
        }
    }

    fn check_expr_fresh_storage(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::StructLit { name, fields, .. } => {
                // Check if any field value is a variable with Fresh type and
                // the struct field type (from declarations) is not Fresh.
                // Best-effort: check field type names from struct declarations.
                for field in fields {
                    // Look for field values that reference Fresh-typed params or variables
                    if let ExprKind::Ident(var_name) = &field.value.kind {
                        // Check if the variable has a Fresh type by looking at
                        // the enclosing function's locals. For Phase 6, we do a
                        // simple check: look at struct field declarations and
                        // see if the field type is Generic with name "Fresh".
                        if let Some(struct_decl) = self.find_struct_decl(name) {
                            if let Some(field_decl) = struct_decl.fields.iter()
                                .find(|fd| fd.name == field.name)
                            {
                                let field_is_fresh = matches!(
                                    &field_decl.ty.kind,
                                    TypeExprKind::Generic { name, .. } if name == "Fresh"
                                );
                                // Check if the variable is typed Fresh in any
                                // enclosing function's params
                                let var_is_fresh = self.is_var_fresh_typed(var_name);
                                if var_is_fresh && !field_is_fresh {
                                    self.diags.push(
                                        Diagnostic::error(
                                            "E0703",
                                            format!(
                                                "Fresh value `{}` stored in non-temporal field `{}.{}` loses freshness tracking -- use `Fresh<...>` as field type",
                                                var_name, name, field.name
                                            ),
                                            field.value.span,
                                        )
                                        .with_help("wrap the struct field type with Fresh<T, D> to preserve freshness tracking"),
                                    );
                                }
                            }
                        }
                    }
                    // Recurse into field values
                    self.check_expr_fresh_storage(&field.value);
                }
            }
            ExprKind::Call { args, .. } => {
                for arg in args {
                    self.check_expr_fresh_storage(&arg.value);
                }
            }
            ExprKind::MethodCall { object, args, .. } => {
                self.check_expr_fresh_storage(object);
                for arg in args {
                    self.check_expr_fresh_storage(&arg.value);
                }
            }
            ExprKind::If { condition, then_block, else_branch } => {
                self.check_expr_fresh_storage(condition);
                self.check_fresh_storage(then_block);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => self.check_fresh_storage(b),
                        ElseBranch::ElseIf(e) => self.check_expr_fresh_storage(e),
                    }
                }
            }
            ExprKind::IfLet { expr: inner, then_block, else_branch, .. } => {
                self.check_expr_fresh_storage(inner);
                self.check_fresh_storage(then_block);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => self.check_fresh_storage(b),
                        ElseBranch::ElseIf(e) => self.check_expr_fresh_storage(e),
                    }
                }
            }
            ExprKind::Match { subject, arms } => {
                self.check_expr_fresh_storage(subject);
                for arm in arms {
                    self.check_expr_fresh_storage(&arm.body);
                }
            }
            ExprKind::Block(b) => self.check_fresh_storage(b),
            ExprKind::Binary { left, right, .. } => {
                self.check_expr_fresh_storage(left);
                self.check_expr_fresh_storage(right);
            }
            ExprKind::Closure { body, .. } => {
                for s in body {
                    self.check_stmt_fresh_storage(s);
                }
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) => self.check_expr_fresh_storage(inner),
            _ => {}
        }
    }

    // ── E0900: Channel creation restriction ───────────────────────────

    /// Check that non-orchestrator agents (can_spawn: false) do not create channels.
    /// Only orchestrator agents should create channels; peer-to-peer channels within
    /// the same group are created by the orchestrator and passed to children.
    fn check_no_channel_creation(&mut self, block: &Block, info: &AgentFunctionInfo) {
        for stmt in &block.stmts {
            self.check_stmt_no_channel(stmt, info);
        }
    }

    fn check_stmt_no_channel(&mut self, stmt: &Stmt, info: &AgentFunctionInfo) {
        match &stmt.kind {
            StmtKind::Expr { expr } => self.check_expr_no_channel(expr, info),
            StmtKind::Let { value, .. }
            | StmtKind::Var { value, .. }
            | StmtKind::LetDestructure { value, .. } => self.check_expr_no_channel(value, info),
            StmtKind::Return(Some(e)) | StmtKind::Bail(e) => {
                self.check_expr_no_channel(e, info)
            }
            StmtKind::Return(None) => {}
            StmtKind::For { iter, body, .. } => {
                self.check_expr_no_channel(iter, info);
                self.check_no_channel_creation(body, info);
            }
            StmtKind::While { condition, body } => {
                self.check_expr_no_channel(condition, info);
                self.check_no_channel_creation(body, info);
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.check_expr_no_channel(expr, info);
                self.check_no_channel_creation(body, info);
            }
            StmtKind::Loop { body } => {
                self.check_no_channel_creation(body, info);
            }
            StmtKind::Break | StmtKind::Continue => {}
            StmtKind::Defer { .. } => {}
        }
    }

    fn check_expr_no_channel(&mut self, expr: &Expr, info: &AgentFunctionInfo) {
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                if let ExprKind::Ident(name) = &callee.kind {
                    if name == "channel" {
                        self.diags.push(
                            Diagnostic::error(
                                "E0900",
                                format!(
                                    "agent `{}` cannot create channels without `can_spawn: true`",
                                    info.name,
                                ),
                                expr.span,
                            )
                            .with_help(
                                "only orchestrator agents (can_spawn: true) should create channels; \
                                 receive channels as function arguments instead"
                            ),
                        );
                    }
                }
                for arg in args {
                    self.check_expr_no_channel(&arg.value, info);
                }
            }
            ExprKind::MethodCall {
                object,
                method,
                args,
            } => {
                // Detect Chan.new() pattern
                if method == "new" {
                    if let ExprKind::Ident(name) = &object.kind {
                        if name == "Chan" {
                            self.diags.push(
                                Diagnostic::error(
                                    "E0900",
                                    format!(
                                        "agent `{}` cannot create channels without `can_spawn: true`",
                                        info.name,
                                    ),
                                    expr.span,
                                )
                                .with_help(
                                    "only orchestrator agents (can_spawn: true) should create channels; \
                                     receive channels as function arguments instead"
                                ),
                            );
                        }
                    }
                }
                self.check_expr_no_channel(object, info);
                for arg in args {
                    self.check_expr_no_channel(&arg.value, info);
                }
            }
            ExprKind::If {
                condition,
                then_block,
                else_branch,
            } => {
                self.check_expr_no_channel(condition, info);
                self.check_no_channel_creation(then_block, info);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => self.check_no_channel_creation(b, info),
                        ElseBranch::ElseIf(e) => self.check_expr_no_channel(e, info),
                    }
                }
            }
            ExprKind::IfLet {
                expr: inner,
                then_block,
                else_branch,
                ..
            } => {
                self.check_expr_no_channel(inner, info);
                self.check_no_channel_creation(then_block, info);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => self.check_no_channel_creation(b, info),
                        ElseBranch::ElseIf(e) => self.check_expr_no_channel(e, info),
                    }
                }
            }
            ExprKind::Match { subject, arms } => {
                self.check_expr_no_channel(subject, info);
                for arm in arms {
                    self.check_expr_no_channel(&arm.body, info);
                }
            }
            ExprKind::Block(b) => self.check_no_channel_creation(b, info),
            ExprKind::Binary { left, right, .. } => {
                self.check_expr_no_channel(left, info);
                self.check_expr_no_channel(right, info);
            }
            ExprKind::Closure { body, .. } => {
                for s in body {
                    self.check_stmt_no_channel(s, info);
                }
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) => {
                self.check_expr_no_channel(inner, info)
            }
            _ => {}
        }
    }

    /// Find a struct declaration by name in the program.
    fn find_struct_decl(&self, name: &str) -> Option<&StructDecl> {
        for item in &self.program.items {
            if let Item::Struct(s) = item {
                if s.name == name {
                    return Some(s);
                }
            }
        }
        None
    }

    // ── LLM Policy Validation (E0950, W0951) ────────────────────────────────

    /// Check that agents handling secret types have llm_policy: .local_only,
    /// and warn when private types are used with allow_cloud.
    fn check_llm_policy(&mut self, f: &FnDecl, info: &AgentFunctionInfo) {
        use crate::agent_reasoning::LlmPolicy;

        let sig = match self.env.functions.get(&f.name) {
            Some(sig) => sig,
            None => return,
        };

        let has_secret_param = sig.params.iter().any(|(_, ty)| ty.is_secret());
        let has_secret_return = self.return_type_contains_secret(&sig.return_type);
        let has_private_param = sig.params.iter().any(|(_, ty)| ty.is_private());
        let has_private_return = self.return_type_contains_private(&sig.return_type);

        let handles_secret = has_secret_param || has_secret_return;
        let handles_private = has_private_param || has_private_return;

        // E0950: secret types + non-local policy
        if handles_secret {
            let is_local_only = matches!(info.llm_policy, Some(LlmPolicy::LocalOnly));
            if !is_local_only {
                self.diags.push(
                    Diagnostic::error(
                        "E0950",
                        format!(
                            "agent `{}` handles secret types but llm_policy is not `.local_only` -- secret data must never reach cloud APIs",
                            f.name
                        ),
                        info.span,
                    )
                    .with_help("add `llm_policy: .local_only` to @agent_task annotation"),
                );
            }
        }

        // W0951: private types + allow_cloud
        if handles_private && !handles_secret {
            if matches!(info.llm_policy, Some(LlmPolicy::AllowCloud)) {
                self.diags.push(
                    Diagnostic::warning(
                        "W0951",
                        format!(
                            "agent `{}` handles private types with `llm_policy: .allow_cloud`; consider `.redact_private`",
                            f.name
                        ),
                        info.span,
                    ),
                );
            }
        }
    }

    /// Check if a variable name corresponds to a Fresh-typed parameter in any
    /// @agent_task function. Best-effort for Phase 6.
    fn is_var_fresh_typed(&self, var_name: &str) -> bool {
        // Check all agent functions' parameters
        for item in &self.program.items {
            if let Item::Fn(f) = item {
                if self.env.agent_functions.contains_key(&f.name) {
                    for param in &f.params {
                        if param.name == var_name {
                            return matches!(
                                &param.ty.kind,
                                TypeExprKind::Generic { name, .. } if name == "Fresh"
                            );
                        }
                    }
                }
            }
        }
        false
    }
}

// ── Trust Score Registry ──────────────────────────────────────────────────────

/// Runtime trust score tracking between agent pairs.
/// This struct is used by the interpreter at runtime, not at compile time.
/// Agents start with a default trust score of 0.5 toward each other.
#[derive(Debug, Clone)]
pub struct TrustScoreRegistry {
    /// Map of (agent_a, agent_b) -> trust score (0.0 to 1.0)
    pub scores: HashMap<(String, String), f64>,
}

impl TrustScoreRegistry {
    pub fn new() -> Self {
        Self {
            scores: HashMap::new(),
        }
    }

    /// Get trust score from one agent toward another.
    /// Returns 0.5 (neutral) if no score has been established.
    pub fn get_score(&self, from: &str, to: &str) -> f64 {
        *self
            .scores
            .get(&(from.to_string(), to.to_string()))
            .unwrap_or(&0.5)
    }

    /// Update trust score from one agent toward another.
    /// Delta can be positive (increase trust) or negative (decrease).
    /// Score is clamped to [0.0, 1.0].
    pub fn update_score(&mut self, from: &str, to: &str, delta: f64) {
        let key = (from.to_string(), to.to_string());
        let current = self.scores.entry(key).or_insert(0.5);
        *current = (*current + delta).clamp(0.0, 1.0);
    }

    /// Set trust score directly (clamped to [0.0, 1.0]).
    pub fn set_score(&mut self, from: &str, to: &str, score: f64) {
        let key = (from.to_string(), to.to_string());
        self.scores.insert(key, score.clamp(0.0, 1.0));
    }
}

impl Default for TrustScoreRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;
    use crate::parser::Parser;
    use crate::typeck::TypeChecker;

    fn check(source: &str) -> Diagnostics {
        let (tokens, _) = lexer::tokenize(source);
        let program = Parser::parse(tokens).unwrap();
        let (env, _typeck_diags) = TypeChecker::new(&program).check();
        AgentSafetyPass::new(&program, &env).check()
    }

    fn has_error(diags: &Diagnostics, code: &str) -> bool {
        diags.items.iter().any(|d| d.code == code)
    }

    fn has_warning(diags: &Diagnostics, code: &str) -> bool {
        diags.items.iter().any(|d| d.code == code && d.severity == crate::error::Severity::Warning)
    }

    // ── L1 Tests: Tool level ─────────────────────────────────────────────

    #[test]
    fn l1_single_fetch_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 5.seconds, level: .L1)
            fn tool(url: String) -> String {
                fetch(url)
            }
        "#);
        assert_eq!(diags.error_count(), 0, "L1 with single fetch should pass");
    }

    #[test]
    fn l1_two_fetches_e0619() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 5.seconds, level: .L1)
            fn tool(url: String) -> String {
                let a = fetch("https://a.com")
                let b = fetch("https://b.com")
                a
            }
        "#);
        assert!(has_error(&diags, "E0619"), "L1 with 2 fetches should emit E0619");
    }

    #[test]
    fn l1_fetch_and_write_e0619() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 5.seconds, level: .L1)
            fn tool() -> String {
                let data = fetch("https://a.com")
                write_file("out.txt")
                "done"
            }
        "#);
        assert!(has_error(&diags, "E0619"), "L1 with fetch + write_file should emit E0619");
    }

    #[test]
    fn l1_no_external_ops_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 5.seconds, level: .L1)
            fn tool() -> String {
                let x = 42
                "done"
            }
        "#);
        assert_eq!(diags.error_count(), 0, "L1 with no external ops should pass");
    }

    // ── L2 Tests: Script level ───────────────────────────────────────────

    #[test]
    fn l2_sequence_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L2)
            fn script() -> String {
                let a = fetch("https://a.com")
                let b = fetch("https://b.com")
                let c = fetch("https://c.com")
                "done"
            }
        "#);
        assert_eq!(diags.error_count(), 0, "L2 with sequential fetches should pass");
    }

    #[test]
    fn l2_if_on_fetch_result_e0621() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L2)
            fn script() -> String {
                if fetch("https://a.com") {
                    "ok"
                } else {
                    "fail"
                }
            }
        "#);
        assert!(has_error(&diags, "E0621"), "L2 with if on fetch result should emit E0621");
    }

    #[test]
    fn l2_match_on_fetch_result_e0621() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L2)
            fn script() -> String {
                fetch("https://a.com") match {
                    Ok(v) -> v
                    Err(e) -> "error"
                }
            }
        "#);
        assert!(has_error(&diags, "E0621"), "L2 with match on fetch result should emit E0621");
    }

    #[test]
    fn l2_if_on_local_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L2)
            fn script() -> String {
                let x = 42
                if x > 10 {
                    "big"
                } else {
                    "small"
                }
            }
        "#);
        assert_eq!(diags.error_count(), 0, "L2 with if on local variable should pass");
    }

    #[test]
    fn l2_no_spawn_e0622() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L2)
            fn script() -> String {
                spawn_agent("child")
                "done"
            }
        "#);
        assert!(has_error(&diags, "E0622"), "L2 with spawn should emit E0622");
    }

    // ── L3 Tests: Reactive level ─────────────────────────────────────────

    #[test]
    fn l3_branching_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds, level: .L3)
            fn reactive() -> String {
                if fetch("https://a.com") {
                    "ok"
                } else {
                    "fail"
                }
            }
        "#);
        assert_eq!(diags.error_count(), 0, "L3 with branching on fetch should pass");
    }

    #[test]
    fn l3_spawn_e0622() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds, level: .L3)
            fn reactive() -> String {
                spawn_agent("child")
                "done"
            }
        "#);
        assert!(has_error(&diags, "E0622"), "L3 with spawn should emit E0622");
    }

    #[test]
    fn l3_parallel_map_e0622() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds, level: .L3)
            fn reactive() -> String {
                tasks.parallel_map()
                "done"
            }
        "#);
        assert!(has_error(&diags, "E0622"), "L3 with parallel_map should emit E0622");
    }

    #[test]
    fn l3_write_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds, level: .L3, can_write: true)
            fn reactive() -> String {
                write_file("output.txt")
                "done"
            }
        "#);
        // L3 allows write, and explicit can_write: true doesn't exceed ceiling
        assert!(!has_error(&diags, "E0623"), "L3 with can_write: true should not emit E0623");
    }

    // ── L4 Tests: Autonomous level ───────────────────────────────────────

    #[test]
    fn l4_spawn_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, level: .L4, can_spawn: true, max_requests: 100)
            fn autonomous() -> String {
                spawn_agent("child")
                "done"
            }
        "#);
        assert!(!has_error(&diags, "E0622"), "L4 with spawn should not emit E0622");
    }

    #[test]
    fn l4_without_constitution_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, level: .L4, max_requests: 100)
            fn autonomous() -> String {
                "done"
            }
        "#);
        assert!(!has_error(&diags, "E0600"), "L4 without constitution should pass");
    }

    // ── L5 Tests: Self-directed level ────────────────────────────────────

    #[test]
    fn l5_without_constitution_e0600() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 120.seconds, level: .L5, max_requests: 100)
            fn self_directed() -> String {
                "done"
            }
        "#);
        assert!(has_error(&diags, "E0600"), "L5 without constitution should emit E0600");
    }

    #[test]
    fn l5_with_constitution_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 120.seconds, level: .L5, constitution: "safety/constitution.md", max_requests: 100)
            fn self_directed() -> String {
                "done"
            }
        "#);
        assert!(!has_error(&diags, "E0600"), "L5 with constitution should pass");
    }

    #[test]
    fn l5_spawn_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 120.seconds, level: .L5, constitution: "const.md", can_spawn: true, max_requests: 100)
            fn self_directed() -> String {
                spawn_agent("child")
                "done"
            }
        "#);
        assert!(!has_error(&diags, "E0622"), "L5 with constitution and spawn should not emit E0622");
    }

    // ── Permission Ceiling Tests (E0623) ─────────────────────────────────

    #[test]
    fn l1_can_write_exceeds_e0623() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 5.seconds, level: .L1, can_write: true)
            fn tool() -> String {
                "done"
            }
        "#);
        assert!(has_error(&diags, "E0623"), "L1 with can_write: true should emit E0623");
    }

    #[test]
    fn l1_can_spawn_exceeds_e0623() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 5.seconds, level: .L1, can_spawn: true)
            fn tool() -> String {
                "done"
            }
        "#);
        assert!(has_error(&diags, "E0623"), "L1 with can_spawn: true should emit E0623");
    }

    #[test]
    fn l2_can_store_exceeds_e0623() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L2, can_store: true)
            fn script() -> String {
                "done"
            }
        "#);
        assert!(has_error(&diags, "E0623"), "L2 with can_store: true should emit E0623");
    }

    #[test]
    fn l3_can_spawn_exceeds_e0623() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds, level: .L3, can_spawn: true)
            fn reactive() -> String {
                "done"
            }
        "#);
        assert!(has_error(&diags, "E0623"), "L3 with can_spawn: true should emit E0623");
    }

    #[test]
    fn l4_can_write_no_e0623() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, level: .L4, can_write: true, max_requests: 100)
            fn autonomous() -> String {
                "done"
            }
        "#);
        assert!(!has_error(&diags, "E0623"), "L4 with can_write: true should not emit E0623");
    }

    // ── Default Level Tests ──────────────────────────────────────────────

    #[test]
    fn default_level_is_l3() {
        // When no level is specified, default is L3 (Reactive)
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds)
            fn agent() -> String {
                if fetch("https://example.com") {
                    "ok"
                } else {
                    "fail"
                }
            }
        "#);
        // L3 allows branching, so this should pass
        assert_eq!(diags.error_count(), 0, "Default level (L3) should allow branching");
    }

    #[test]
    fn default_level_blocks_spawn() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds)
            fn agent() -> String {
                spawn_agent("child")
                "done"
            }
        "#);
        // Default L3 blocks spawning
        assert!(has_error(&diags, "E0622"), "Default level (L3) should block spawn");
    }

    // ── Non-agent Function Tests ─────────────────────────────────────────

    #[test]
    fn non_agent_function_ignored() {
        let diags = check(r#"
            fn normal() -> String {
                fetch("https://a.com")
                fetch("https://b.com")
                spawn_agent("child")
                "done"
            }
        "#);
        assert_eq!(diags.error_count(), 0, "Non-agent functions should not be checked");
    }

    // ── Edge Cases ───────────────────────────────────────────────────────

    #[test]
    fn l1_method_call_as_external_op() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 5.seconds, level: .L1)
            fn tool() -> String {
                db.insert("key", "val")
                db.query("SELECT *")
                "done"
            }
        "#);
        assert!(has_error(&diags, "E0619"), "L1 with 2 method external ops should emit E0619");
    }

    #[test]
    fn l2_if_on_try_fetch_e0621() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L2)
            fn script() -> String {
                if fetch("https://a.com")? {
                    "ok"
                } else {
                    "fail"
                }
            }
        "#);
        assert!(has_error(&diags, "E0621"), "L2 with if on fetch()? should emit E0621");
    }

    #[test]
    fn empty_program_no_errors() {
        let diags = check("");
        assert_eq!(diags.error_count(), 0);
    }

    #[test]
    fn l1_single_write_ok() {
        // L1 allows 1 external op, even if it's a write (the ceiling permission check
        // won't fire because can_write defaults to false in the annotation, and the
        // safety pass doesn't re-check agent_pass permissions — just level capabilities)
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 5.seconds, level: .L1)
            fn tool() -> String {
                read_file("input.txt")
            }
        "#);
        // read_file is 1 external op, L1 allows 1
        assert!(!has_error(&diags, "E0619"), "L1 with single read_file should not emit E0619");
    }

    #[test]
    fn l3_multiple_external_ops_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds, level: .L3)
            fn reactive() -> String {
                let a = fetch("https://a.com")
                let b = fetch("https://b.com")
                let c = fetch("https://c.com")
                write_file("out.txt")
                "done"
            }
        "#);
        // L3 has no max_external_ops limit
        assert!(!has_error(&diags, "E0619"), "L3 should allow multiple external ops");
    }

    // ── Non-Escalation Tests (E0610-E0613) ────────────────────────────────

    #[test]
    fn escalation_can_write_e0610() {
        let diags = check(r#"
            @agent_task(id: child_id, timeout: 10.seconds, level: .L3, can_write: true)
            fn child_agent() -> String { "done" }

            @agent_task(id: parent_id, timeout: 30.seconds, level: .L4, can_spawn: true)
            fn parent_agent() -> String {
                child_agent()
            }
        "#);
        assert!(has_error(&diags, "E0610"), "child can_write: true but parent can_write: false should emit E0610");
    }

    #[test]
    fn escalation_can_store_e0610() {
        let diags = check(r#"
            @agent_task(id: child_id, timeout: 10.seconds, level: .L3, can_store: true)
            fn child_agent() -> String { "done" }

            @agent_task(id: parent_id, timeout: 30.seconds, level: .L4, can_spawn: true)
            fn parent_agent() -> String {
                child_agent()
            }
        "#);
        assert!(has_error(&diags, "E0610"), "child can_store: true but parent can_store: false should emit E0610");
    }

    #[test]
    fn escalation_level_e0611() {
        let diags = check(r#"
            @agent_task(id: child_id, timeout: 60.seconds, level: .L4, can_spawn: true, max_requests: 100)
            fn child_agent() -> String { "done" }

            @agent_task(id: parent_id, timeout: 30.seconds, level: .L2)
            fn parent_agent() -> String {
                child_agent()
            }
        "#);
        assert!(has_error(&diags, "E0611"), "child L4 exceeds parent L2 should emit E0611");
    }

    #[test]
    fn escalation_can_spawn_e0612() {
        let diags = check(r#"
            @agent_task(id: child_id, timeout: 10.seconds, level: .L4, can_spawn: true, max_requests: 100)
            fn child_agent() -> String { "done" }

            @agent_task(id: parent_id, timeout: 30.seconds, level: .L4, max_requests: 100)
            fn parent_agent() -> String {
                child_agent()
            }
        "#);
        assert!(has_error(&diags, "E0612"), "child can_spawn: true but parent can_spawn: false should emit E0612");
    }

    #[test]
    fn escalation_can_network_e0613() {
        let diags = check(r#"
            @agent_task(id: child_id, timeout: 10.seconds, level: .L3, can_network: true)
            fn child_agent() -> String { "done" }

            @agent_task(id: parent_id, timeout: 30.seconds, level: .L4, can_network: false, can_spawn: true, max_requests: 100)
            fn parent_agent() -> String {
                child_agent()
            }
        "#);
        assert!(has_error(&diags, "E0613"), "child can_network: true but parent can_network: false should emit E0613");
    }

    #[test]
    fn same_level_call_ok() {
        let diags = check(r#"
            @agent_task(id: child_id, timeout: 10.seconds, level: .L3)
            fn child_agent() -> String { "done" }

            @agent_task(id: parent_id, timeout: 30.seconds, level: .L3)
            fn parent_agent() -> String {
                child_agent()
            }
        "#);
        assert!(!has_error(&diags, "E0611"), "same level L3 call should not emit E0611");
    }

    #[test]
    fn parent_l4_calls_child_l2_ok() {
        let diags = check(r#"
            @agent_task(id: child_id, timeout: 10.seconds, level: .L2)
            fn child_agent() -> String { "done" }

            @agent_task(id: parent_id, timeout: 30.seconds, level: .L4, can_spawn: true, max_requests: 100)
            fn parent_agent() -> String {
                child_agent()
            }
        "#);
        assert!(!has_error(&diags, "E0611"), "parent L4 calling child L2 should not emit E0611");
        assert!(!has_error(&diags, "E0610"), "child has no escalated permissions");
    }

    #[test]
    fn parent_with_write_calls_child_with_write_ok() {
        let diags = check(r#"
            @agent_task(id: child_id, timeout: 10.seconds, level: .L3, can_write: true)
            fn child_agent() -> String { "done" }

            @agent_task(id: parent_id, timeout: 30.seconds, level: .L4, can_write: true, can_spawn: true, max_requests: 100)
            fn parent_agent() -> String {
                child_agent()
            }
        "#);
        assert!(!has_error(&diags, "E0610"), "both have can_write so no escalation");
    }

    #[test]
    fn multiple_escalation_errors_same_call() {
        let diags = check(r#"
            @agent_task(id: child_id, timeout: 10.seconds, level: .L4, can_write: true, can_store: true, can_spawn: true, max_requests: 100)
            fn child_agent() -> String { "done" }

            @agent_task(id: parent_id, timeout: 30.seconds, level: .L3)
            fn parent_agent() -> String {
                child_agent()
            }
        "#);
        // Child escalates: level (L4 > L3), can_write, can_store, can_spawn
        assert!(has_error(&diags, "E0610"), "should detect capability escalation");
        assert!(has_error(&diags, "E0611"), "should detect level escalation");
        assert!(has_error(&diags, "E0612"), "should detect spawn escalation");
    }

    #[test]
    fn non_agent_call_from_agent_ok() {
        let diags = check(r#"
            fn helper() -> String { "done" }

            @agent_task(id: parent_id, timeout: 30.seconds, level: .L3)
            fn parent_agent() -> String {
                helper()
            }
        "#);
        assert!(!has_error(&diags, "E0610"), "calling non-agent function should not trigger escalation");
        assert!(!has_error(&diags, "E0611"), "calling non-agent function should not trigger level check");
    }

    // ── Memory Isolation Tests (E0614) ────────────────────────────────────

    #[test]
    fn agent_accesses_module_var_e0614() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent() -> String {
                shared_state
            }

            fn main() {
                var shared_state = "mutable"
                agent()
            }
        "#);
        assert!(has_error(&diags, "E0614"), "agent accessing module-level var should emit E0614");
    }

    #[test]
    fn agent_accesses_module_let_ok() {
        // Immutable bindings are fine
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent() -> String {
                "done"
            }

            fn main() {
                let config = "immutable"
                agent()
            }
        "#);
        assert!(!has_error(&diags, "E0614"), "agent accessing immutable let should not emit E0614");
    }

    #[test]
    fn agent_uses_own_local_var_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent() -> String {
                var local_state = "mine"
                local_state
            }
        "#);
        assert!(!has_error(&diags, "E0614"), "agent using own local var should not emit E0614");
    }

    #[test]
    fn agent_uses_own_params_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent(input: String) -> String {
                input
            }
        "#);
        assert!(!has_error(&diags, "E0614"), "agent using own params should not emit E0614");
    }

    // ── Spawn Bounds Tests (E0615-E0616) ──────────────────────────────────

    #[test]
    fn spawn_depth_child_ge_parent_e0615() {
        let diags = check(r#"
            @agent_task(id: child_id, timeout: 10.seconds, level: .L3, max_spawn_depth: 3)
            fn child_agent() -> String { "done" }

            @agent_task(id: parent_id, timeout: 30.seconds, level: .L4, can_spawn: true, max_spawn_depth: 3, max_requests: 100)
            fn parent_agent() -> String {
                child_agent()
            }
        "#);
        assert!(has_error(&diags, "E0615"), "child spawn depth >= parent should emit E0615");
    }

    #[test]
    fn spawn_depth_child_not_declared_e0615() {
        let diags = check(r#"
            @agent_task(id: child_id, timeout: 10.seconds, level: .L3)
            fn child_agent() -> String { "done" }

            @agent_task(id: parent_id, timeout: 30.seconds, level: .L4, can_spawn: true, max_spawn_depth: 3, max_requests: 100)
            fn parent_agent() -> String {
                child_agent()
            }
        "#);
        assert!(has_error(&diags, "E0615"), "child without max_spawn_depth when parent has it should emit E0615");
    }

    #[test]
    fn spawn_depth_child_lt_parent_ok() {
        let diags = check(r#"
            @agent_task(id: child_id, timeout: 10.seconds, level: .L3, max_spawn_depth: 2)
            fn child_agent() -> String { "done" }

            @agent_task(id: parent_id, timeout: 30.seconds, level: .L4, can_spawn: true, max_spawn_depth: 5, max_requests: 100)
            fn parent_agent() -> String {
                child_agent()
            }
        "#);
        assert!(!has_error(&diags, "E0615"), "child depth 2 < parent depth 5 should pass");
    }

    #[test]
    fn total_agents_child_ge_parent_e0616() {
        let diags = check(r#"
            @agent_task(id: child_id, timeout: 10.seconds, level: .L3, max_total_agents: 10)
            fn child_agent() -> String { "done" }

            @agent_task(id: parent_id, timeout: 30.seconds, level: .L4, can_spawn: true, max_total_agents: 5, max_requests: 100)
            fn parent_agent() -> String {
                child_agent()
            }
        "#);
        assert!(has_error(&diags, "E0616"), "child total_agents 10 >= parent 5 should emit E0616");
    }

    #[test]
    fn total_agents_child_lt_parent_ok() {
        let diags = check(r#"
            @agent_task(id: child_id, timeout: 10.seconds, level: .L3, max_total_agents: 3)
            fn child_agent() -> String { "done" }

            @agent_task(id: parent_id, timeout: 30.seconds, level: .L4, can_spawn: true, max_total_agents: 10, max_requests: 100)
            fn parent_agent() -> String {
                child_agent()
            }
        "#);
        assert!(!has_error(&diags, "E0616"), "child total_agents 3 < parent 10 should pass");
    }

    #[test]
    fn no_spawn_bounds_when_parent_has_none() {
        let diags = check(r#"
            @agent_task(id: child_id, timeout: 10.seconds, level: .L3, max_spawn_depth: 5)
            fn child_agent() -> String { "done" }

            @agent_task(id: parent_id, timeout: 30.seconds, level: .L4, can_spawn: true, max_requests: 100)
            fn parent_agent() -> String {
                child_agent()
            }
        "#);
        assert!(!has_error(&diags, "E0615"), "no spawn bounds check when parent has no max_spawn_depth");
    }

    // ── Budget Bounds Tests (E0617) ───────────────────────────────────────

    #[test]
    fn l4_without_budget_e0617() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, level: .L4, can_spawn: true)
            fn autonomous() -> String {
                "done"
            }
        "#);
        assert!(has_error(&diags, "E0617"), "L4 without max_requests or memory_limit should emit E0617");
    }

    #[test]
    fn l5_without_budget_e0617() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 120.seconds, level: .L5, constitution: "const.md")
            fn self_directed() -> String {
                "done"
            }
        "#);
        assert!(has_error(&diags, "E0617"), "L5 without max_requests or memory_limit should emit E0617");
    }

    #[test]
    fn l4_with_max_requests_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, level: .L4, max_requests: 500)
            fn autonomous() -> String {
                "done"
            }
        "#);
        assert!(!has_error(&diags, "E0617"), "L4 with max_requests should pass");
    }

    #[test]
    fn l4_with_memory_limit_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, level: .L4, memory_limit: 512.mb)
            fn autonomous() -> String {
                "done"
            }
        "#);
        assert!(!has_error(&diags, "E0617"), "L4 with memory_limit should pass");
    }

    #[test]
    fn l5_with_both_budget_fields_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 120.seconds, level: .L5, constitution: "const.md", max_requests: 1000, memory_limit: 1024.mb)
            fn self_directed() -> String {
                "done"
            }
        "#);
        assert!(!has_error(&diags, "E0617"), "L5 with both budget fields should pass");
    }

    #[test]
    fn l3_without_budget_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds, level: .L3)
            fn reactive() -> String {
                "done"
            }
        "#);
        assert!(!has_error(&diags, "E0617"), "L3 should not require budget fields");
    }

    #[test]
    fn l2_without_budget_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L2)
            fn script() -> String {
                "done"
            }
        "#);
        assert!(!has_error(&diags, "E0617"), "L2 should not require budget fields");
    }

    // ── Edge Cases ───────────────────────────────────────────────────────

    #[test]
    fn escalation_with_can_execute_e0610() {
        let diags = check(r#"
            @agent_task(id: child_id, timeout: 10.seconds, level: .L3, can_execute: true)
            fn child_agent() -> String { "done" }

            @agent_task(id: parent_id, timeout: 30.seconds, level: .L4, can_spawn: true, max_requests: 100)
            fn parent_agent() -> String {
                child_agent()
            }
        "#);
        assert!(has_error(&diags, "E0610"), "child can_execute: true but parent can_execute: false should emit E0610");
    }

    #[test]
    fn no_escalation_both_have_all_perms() {
        let diags = check(r#"
            @agent_task(id: child_id, timeout: 10.seconds, level: .L4, can_write: true, can_store: true, can_spawn: true, can_network: true, can_execute: true, max_requests: 50)
            fn child_agent() -> String { "done" }

            @agent_task(id: parent_id, timeout: 30.seconds, level: .L4, can_write: true, can_store: true, can_spawn: true, can_network: true, can_execute: true, max_requests: 100)
            fn parent_agent() -> String {
                child_agent()
            }
        "#);
        assert!(!has_error(&diags, "E0610"), "no escalation when both have same permissions");
        assert!(!has_error(&diags, "E0611"), "no level escalation when both L4");
        assert!(!has_error(&diags, "E0612"), "no spawn escalation when both can_spawn");
        assert!(!has_error(&diags, "E0613"), "no network escalation when both can_network");
    }

    // ── Info Flow Control Tests (E0618) ───────────────────────────────────

    #[test]
    fn agent_receives_email_returns_string_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent(email: Email) -> String {
                "stripped"
            }
        "#);
        assert!(!has_error(&diags, "E0618"), "agent receives private, returns String should pass (stripped)");
    }

    #[test]
    fn agent_receives_email_returns_email_e0618() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent(email: Email) -> Email {
                email
            }
        "#);
        assert!(has_error(&diags, "E0618"), "agent receives Email and returns Email should emit E0618");
    }

    #[test]
    fn agent_receives_password_returns_anything_e0618() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent(pw: Password) -> Password {
                pw
            }
        "#);
        assert!(has_error(&diags, "E0618"), "agent receives secret Password and returns it should emit E0618");
    }

    #[test]
    fn agent_receives_email_returns_encrypted_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent(email: Email) -> EncryptedResult {
                email.encrypt()
            }
        "#);
        assert!(!has_error(&diags, "E0618"), "agent returns EncryptedResult should pass");
    }

    #[test]
    fn agent_no_private_params_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent(url: String) -> String {
                "done"
            }
        "#);
        assert!(!has_error(&diags, "E0618"), "agent with no private params should not emit E0618");
    }

    #[test]
    fn agent_receives_private_returns_result_string_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent(email: Email) -> Result<String> {
                "stripped"
            }
        "#);
        assert!(!has_error(&diags, "E0618"), "agent returns Result<String> should pass (stripped inner type)");
    }

    #[test]
    fn agent_receives_private_returns_result_email_e0618() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent(email: Email) -> Result<Email> {
                email
            }
        "#);
        assert!(has_error(&diags, "E0618"), "agent returns Result<Email> should emit E0618 (private leaks through Result)");
    }

    #[test]
    fn non_agent_with_private_params_no_e0618() {
        let diags = check(r#"
            fn helper(email: Email) -> Email {
                email
            }
        "#);
        assert!(!has_error(&diags, "E0618"), "non-agent function should not trigger E0618");
    }

    #[test]
    fn agent_returns_encrypted_result_wrapped_ok() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent(email: Email) -> Result<EncryptedResult> {
                email.encrypt()
            }
        "#);
        assert!(!has_error(&diags, "E0618"), "Result<EncryptedResult> should pass");
    }

    #[test]
    fn agent_secret_return_without_secret_input_e0618() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent(data: String) -> Token {
                data
            }
        "#);
        assert!(has_error(&diags, "E0618"), "agent returning secret type should emit E0618 even without secret input");
    }

    // ── Trust Type Compatibility Tests ────────────────────────────────────

    #[test]
    fn trust_unverified_where_trusted_expected_e0700() {
        let diags = check(r#"
            fn process(data: Trusted<String>) -> String {
                data.value()
            }
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent(raw: Unverified<String>) -> String {
                process(raw)
            }
        "#);
        assert!(has_error(&diags, "E0700"), "passing Unverified where Trusted expected should emit E0700");
    }

    #[test]
    fn trust_trusted_where_trusted_expected_ok() {
        let diags = check(r#"
            fn process(data: Trusted<String>) -> String {
                data.value()
            }
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent(verified: Trusted<String>) -> String {
                process(verified)
            }
        "#);
        assert!(!has_error(&diags, "E0700"), "passing Trusted where Trusted expected should not emit E0700");
    }

    #[test]
    fn trust_raw_string_where_trusted_expected_ok() {
        let diags = check(r#"
            fn process(data: Trusted<String>) -> String {
                data.value()
            }
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent(plain: String) -> String {
                process(plain)
            }
        "#);
        // Raw types are Unknown, not Unverified -- only explicit Unverified triggers E0700
        assert!(!has_error(&diags, "E0700"), "passing plain String where Trusted expected should not emit E0700");
    }

    #[test]
    fn trust_verify_on_unverified_ok() {
        let diags = check(r#"
            fn process(data: Trusted<String>) -> String {
                data.value()
            }
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent(raw: Unverified<String>) -> String {
                let verified = raw.verify()
                process(verified)
            }
        "#);
        // After .verify(), it should be Trusted -- no E0700
        assert!(!has_error(&diags, "E0700"), ".verify() should convert Unverified to Trusted");
    }

    #[test]
    fn trust_verify_on_trusted_w0702() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent(data: Trusted<String>) -> String {
                let redundant = data.verify()
                redundant.value()
            }
        "#);
        assert!(has_warning(&diags, "W0702"), ".verify() on Trusted should emit W0702");
    }

    #[test]
    fn trust_fresh_in_non_fresh_field_e0703() {
        let diags = check(r#"
            struct CacheEntry {
                data: String
            }
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent(val: Fresh<String, 5000>) -> String {
                let entry = CacheEntry { data: val }
                "done"
            }
        "#);
        assert!(has_error(&diags, "E0703"), "storing Fresh in non-Fresh field should emit E0703");
    }

    #[test]
    fn trust_fresh_in_fresh_field_ok() {
        let diags = check(r#"
            struct CacheEntry {
                data: Fresh<String, 5000>
            }
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent(val: Fresh<String, 5000>) -> String {
                let entry = CacheEntry { data: val }
                "done"
            }
        "#);
        assert!(!has_error(&diags, "E0703"), "storing Fresh in Fresh field should not emit E0703");
    }

    #[test]
    fn trust_fresh_resolves_with_duration() {
        // Just verify parsing Fresh<String, 300000> doesn't crash
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent(data: Fresh<String, 300000>) -> String {
                "done"
            }
        "#);
        // No trust-related errors expected
        assert!(!has_error(&diags, "E0700"));
        assert!(!has_error(&diags, "E0703"));
    }

    #[test]
    fn trust_nested_trusted_unverified_valid() {
        // Nested trust: Trusted<Unverified<T>> -- unusual but valid
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 10.seconds, level: .L3)
            fn agent(data: Trusted<String>) -> String {
                "done"
            }
        "#);
        assert!(!has_error(&diags, "E0700"));
    }

    // ── TrustScoreRegistry Tests ─────────────────────────────────────────

    #[test]
    fn trust_score_default_is_half() {
        let registry = super::TrustScoreRegistry::new();
        assert_eq!(registry.get_score("agent_a", "agent_b"), 0.5);
    }

    #[test]
    fn trust_score_update_increases() {
        let mut registry = super::TrustScoreRegistry::new();
        registry.update_score("agent_a", "agent_b", 0.1);
        assert!((registry.get_score("agent_a", "agent_b") - 0.6).abs() < 0.001);
    }

    #[test]
    fn trust_score_update_decreases() {
        let mut registry = super::TrustScoreRegistry::new();
        registry.update_score("agent_a", "agent_b", -0.2);
        assert!((registry.get_score("agent_a", "agent_b") - 0.3).abs() < 0.001);
    }

    #[test]
    fn trust_score_clamp_to_max() {
        let mut registry = super::TrustScoreRegistry::new();
        registry.update_score("agent_a", "agent_b", 0.8); // 0.5 + 0.8 = 1.3 -> 1.0
        assert_eq!(registry.get_score("agent_a", "agent_b"), 1.0);
    }

    #[test]
    fn trust_score_clamp_to_min() {
        let mut registry = super::TrustScoreRegistry::new();
        registry.update_score("agent_a", "agent_b", -0.9); // 0.5 - 0.9 = -0.4 -> 0.0
        assert_eq!(registry.get_score("agent_a", "agent_b"), 0.0);
    }

    #[test]
    fn trust_score_set_direct() {
        let mut registry = super::TrustScoreRegistry::new();
        registry.set_score("agent_a", "agent_b", 0.75);
        assert_eq!(registry.get_score("agent_a", "agent_b"), 0.75);
    }

    #[test]
    fn trust_score_asymmetric() {
        let mut registry = super::TrustScoreRegistry::new();
        registry.update_score("agent_a", "agent_b", 0.3); // a->b = 0.8
        registry.update_score("agent_b", "agent_a", -0.1); // b->a = 0.4
        assert!((registry.get_score("agent_a", "agent_b") - 0.8).abs() < 0.001);
        assert!((registry.get_score("agent_b", "agent_a") - 0.4).abs() < 0.001);
    }

    // ── E0900 Tests: Channel creation restriction ───────────────────────

    #[test]
    fn e0900_non_spawning_agent_channel_call() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 5.seconds)
            fn worker() -> String {
                let ch = channel(10)
                "done"
            }
        "#);
        assert!(has_error(&diags, "E0900"), "non-spawning agent creating channel should emit E0900");
    }

    #[test]
    fn e0900_non_spawning_agent_chan_new() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 5.seconds)
            fn worker() -> String {
                let ch = Chan.new(10)
                "done"
            }
        "#);
        assert!(has_error(&diags, "E0900"), "non-spawning agent using Chan.new() should emit E0900");
    }

    #[test]
    fn e0900_not_for_orchestrator() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 5.seconds, can_spawn: true, level: .L4)
            fn orchestrator() -> String {
                let ch = channel(10)
                "done"
            }
        "#);
        assert!(!has_error(&diags, "E0900"), "orchestrator agent (can_spawn: true) should NOT get E0900");
    }

    #[test]
    fn e0900_not_for_non_agent_function() {
        let diags = check(r#"
            fn helper() -> String {
                let ch = channel(10)
                "done"
            }
        "#);
        assert!(!has_error(&diags, "E0900"), "non-agent function should NOT get E0900");
    }

    #[test]
    fn e0900_message_includes_guidance() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 5.seconds)
            fn worker() -> String {
                let ch = channel(10)
                "done"
            }
        "#);
        let e0900 = diags.items.iter().find(|d| d.code == "E0900").unwrap();
        assert!(e0900.msg.contains("cannot create channels"), "E0900 message should explain the restriction");
        assert!(e0900.help.is_some(), "E0900 should have a help message");
        let help = e0900.help.as_ref().unwrap();
        assert!(help.contains("can_spawn") || help.contains("orchestrator"), "E0900 help should mention can_spawn or orchestrator");
    }

    // ── E0950 / W0951: LLM Policy validation tests ──────────────────────

    #[test]
    fn e0950_secret_return_allow_cloud_error() {
        let diags = check(r#"
            type Token = secret String
            @agent_task(id: task_id, timeout: 60.seconds, llm_policy: .allow_cloud)
            fn handler() -> Token {
                "tok" as Token
            }
        "#);
        assert!(has_error(&diags, "E0950"), "secret return type + allow_cloud should emit E0950");
    }

    #[test]
    fn e0950_secret_return_local_only_ok() {
        let diags = check(r#"
            type Token = secret String
            @agent_task(id: task_id, timeout: 60.seconds, llm_policy: .local_only)
            fn handler() -> Token {
                "tok" as Token
            }
        "#);
        assert!(!has_error(&diags, "E0950"), "secret return type + local_only should not emit E0950");
    }

    #[test]
    fn e0950_secret_param_no_policy_error() {
        // No llm_policy set (defaults to None, which is not LocalOnly) -- should error
        let diags = check(r#"
            type APIKey = secret String
            @agent_task(id: task_id, timeout: 60.seconds)
            fn handler(key: APIKey) -> String {
                "ok"
            }
        "#);
        assert!(has_error(&diags, "E0950"), "secret param without llm_policy should emit E0950");
    }

    #[test]
    fn w0951_private_param_allow_cloud_warning() {
        let diags = check(r#"
            type Email = private String
            @agent_task(id: task_id, timeout: 60.seconds, llm_policy: .allow_cloud)
            fn handler(email: Email) -> String {
                "ok"
            }
        "#);
        assert!(has_warning(&diags, "W0951"), "private param + allow_cloud should emit W0951");
    }

    #[test]
    fn w0951_private_param_redact_private_no_warning() {
        let diags = check(r#"
            type Email = private String
            @agent_task(id: task_id, timeout: 60.seconds, llm_policy: .redact_private)
            fn handler(email: Email) -> String {
                "ok"
            }
        "#);
        assert!(!has_warning(&diags, "W0951"), "private param + redact_private should not warn");
    }

    #[test]
    fn e0950_tee_required_treated_as_local_for_secret() {
        // TeeRequired is NOT LocalOnly, so secret types should still error
        let diags = check(r#"
            type Token = secret String
            @agent_task(id: task_id, timeout: 60.seconds, llm_policy: .tee_required)
            fn handler() -> Token {
                "tok" as Token
            }
        "#);
        assert!(has_error(&diags, "E0950"), "secret + tee_required should emit E0950 (TEE treated as local_only only in routing, not in compile check)");
    }
}
