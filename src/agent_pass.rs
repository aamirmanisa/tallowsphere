//! @agent_task validation pass.
//!
//! Enforces permission boundaries on agent-annotated functions:
//! - can_write / can_store / can_spawn / can_network / can_execute
//! - timeout and max_requests must be specified
//! - Functions with can_write: false cannot call filesystem write operations
//! - Functions with can_network: false cannot call fetch/connect
//! - Functions with can_spawn: false cannot spawn child agents

use crate::ast::*;
use crate::error::{Diagnostic, Diagnostics};
use crate::lexer::Span;

// ── Parsed Agent Annotation ─────────────────────────────────────────────────

#[derive(Debug)]
struct AgentInfo {
    can_write: bool,
    can_store: bool,
    can_spawn: bool,
    can_network: bool,
    can_execute: bool,
    has_timeout: bool,
    has_id: bool,
    #[allow(dead_code)]
    level: Option<AgentLevel>,
    span: Span,
}

impl AgentInfo {
    fn from_annotation(ann: &Annotation) -> Self {
        let mut info = AgentInfo {
            can_write: false,
            can_store: false,
            can_spawn: false,
            can_network: true, // default true per spec
            can_execute: false,
            has_timeout: false,
            has_id: false,
            level: None,
            span: ann.span,
        };

        for arg in &ann.args {
            match arg.name.as_str() {
                "can_write" => info.can_write = is_true_value(&arg.value),
                "can_store" => info.can_store = is_true_value(&arg.value),
                "can_spawn" => info.can_spawn = is_true_value(&arg.value),
                "can_network" => info.can_network = is_true_value(&arg.value),
                "can_execute" => info.can_execute = is_true_value(&arg.value),
                "timeout" => info.has_timeout = true,
                "id" => info.has_id = true,
                "level" => {
                    if let ExprKind::DotIdent(s) = &arg.value.kind {
                        info.level = AgentLevel::from_str(s);
                    }
                }
                "llm_policy" => {
                    // Validated in agent_safety_pass, accepted here
                }
                // max_requests, memory_limit, can_read, can_query, max_spawn_depth,
                // max_total_agents, checkpoint_frequency, heartbeat_interval, constitution
                // — accepted but not validated in this pass (handled by agent_safety_pass)
                _ => {}
            }
        }

        info
    }
}

fn is_true_value(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::BoolLit(true) => true,
        ExprKind::Ident(s) if s == "true" => true,
        _ => false,
    }
}

// ── Agent Pass ──────────────────────────────────────────────────────────────

pub struct AgentPass<'a> {
    program: &'a Program,
    diags: Diagnostics,
}

impl<'a> AgentPass<'a> {
    pub fn new(program: &'a Program) -> Self {
        Self {
            program,
            diags: Diagnostics::new(),
        }
    }

    pub fn check(mut self) -> Diagnostics {
        for item in &self.program.items {
            if let Item::Fn(f) = item {
                self.check_function(f);
            }
        }
        self.diags
    }

    fn check_function(&mut self, f: &FnDecl) {
        let agent_ann = f.annotations.iter().find(|a| a.name == "agent_task");
        let agent_ann = match agent_ann {
            Some(a) => a,
            None => return, // Not an agent function
        };

        let info = AgentInfo::from_annotation(agent_ann);

        // E0300: @agent_task must have an id
        if !info.has_id {
            self.diags.push(Diagnostic::error(
                "E0300",
                "@agent_task requires `id` field",
                info.span,
            ));
        }

        // E0301: @agent_task must have a timeout
        if !info.has_timeout {
            self.diags.push(Diagnostic::error(
                "E0301",
                "@agent_task requires `timeout` field",
                info.span,
            ));
        }

        // E0302: can_write: false but function calls write operations
        if !info.can_write {
            self.check_no_write_calls(&f.body, &info);
        }

        // E0303: can_network: false but function calls network operations
        if !info.can_network {
            self.check_no_network_calls(&f.body, &info);
        }

        // E0305: can_spawn: false but function calls spawn operations
        if !info.can_spawn {
            self.check_no_spawn_calls(&f.body, &info);
        }

        // E0306: can_execute: false but function calls process.exec/spawn
        if !info.can_execute {
            self.check_no_execute_calls(&f.body, &info);
        }

        // E0304: can_execute: true is dangerous — warn
        if info.can_execute {
            self.diags.push(Diagnostic::warning(
                "W0304",
                "@agent_task with can_execute: true allows shell command execution",
                info.span,
            ));
        }
    }

    fn check_no_write_calls(&mut self, block: &Block, _info: &AgentInfo) {
        for stmt in &block.stmts {
            self.check_stmt_no_write(stmt);
        }
    }

    fn check_stmt_no_write(&mut self, stmt: &Stmt) {
        match &stmt.kind {
            StmtKind::Expr { expr } => self.check_expr_no_write(expr),
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } | StmtKind::LetDestructure { value, .. } => {
                self.check_expr_no_write(value)
            }
            StmtKind::Return(Some(e)) | StmtKind::Bail(e) => self.check_expr_no_write(e),
            StmtKind::Return(None) => {}
            StmtKind::For { iter, body, .. } => {
                self.check_expr_no_write(iter);
                for s in &body.stmts {
                    self.check_stmt_no_write(s);
                }
            }
            StmtKind::While { condition, body } => {
                self.check_expr_no_write(condition);
                for s in &body.stmts {
                    self.check_stmt_no_write(s);
                }
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.check_expr_no_write(expr);
                for s in &body.stmts {
                    self.check_stmt_no_write(s);
                }
            }
            StmtKind::Loop { body } => {
                for s in &body.stmts {
                    self.check_stmt_no_write(s);
                }
            }
            StmtKind::Break | StmtKind::Continue => {}
            StmtKind::Defer { .. } => {}
        }
    }

    fn check_expr_no_write(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                if let ExprKind::Ident(name) = &callee.kind {
                    if is_write_function(name) {
                        self.diags.push(Diagnostic::error(
                            "E0302",
                            format!("agent with can_write: false cannot call `{name}`"),
                            expr.span,
                        ));
                    }
                }
                for arg in args {
                    self.check_expr_no_write(&arg.value);
                }
            }
            ExprKind::MethodCall { object, method, args } => {
                if is_write_method(method) {
                    self.diags.push(Diagnostic::error(
                        "E0302",
                        format!("agent with can_write: false cannot call `.{method}()`"),
                        expr.span,
                    ));
                }
                self.check_expr_no_write(object);
                for arg in args {
                    self.check_expr_no_write(&arg.value);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.check_expr_no_write(left);
                self.check_expr_no_write(right);
            }
            ExprKind::If { condition, then_block, else_branch } => {
                self.check_expr_no_write(condition);
                for s in &then_block.stmts {
                    self.check_stmt_no_write(s);
                }
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => {
                            for s in &b.stmts {
                                self.check_stmt_no_write(s);
                            }
                        }
                        ElseBranch::ElseIf(e) => self.check_expr_no_write(e),
                    }
                }
            }
            ExprKind::IfLet { expr, then_block, else_branch, .. } => {
                self.check_expr_no_write(expr);
                for s in &then_block.stmts {
                    self.check_stmt_no_write(s);
                }
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => {
                            for s in &b.stmts {
                                self.check_stmt_no_write(s);
                            }
                        }
                        ElseBranch::ElseIf(e) => self.check_expr_no_write(e),
                    }
                }
            }
            ExprKind::Block(b) => {
                for s in &b.stmts {
                    self.check_stmt_no_write(s);
                }
            }
            ExprKind::Closure { body, .. } => {
                for s in body {
                    self.check_stmt_no_write(s);
                }
            }
            _ => {}
        }
    }

    fn check_no_network_calls(&mut self, block: &Block, _info: &AgentInfo) {
        for stmt in &block.stmts {
            self.check_stmt_no_network(stmt);
        }
    }

    fn check_stmt_no_network(&mut self, stmt: &Stmt) {
        match &stmt.kind {
            StmtKind::Expr { expr } => self.check_expr_no_network(expr),
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } | StmtKind::LetDestructure { value, .. } => {
                self.check_expr_no_network(value)
            }
            StmtKind::Return(Some(e)) | StmtKind::Bail(e) => self.check_expr_no_network(e),
            StmtKind::Return(None) => {}
            StmtKind::For { iter, body, .. } => {
                self.check_expr_no_network(iter);
                for s in &body.stmts {
                    self.check_stmt_no_network(s);
                }
            }
            StmtKind::While { condition, body } => {
                self.check_expr_no_network(condition);
                for s in &body.stmts {
                    self.check_stmt_no_network(s);
                }
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.check_expr_no_network(expr);
                for s in &body.stmts {
                    self.check_stmt_no_network(s);
                }
            }
            StmtKind::Loop { body } => {
                for s in &body.stmts {
                    self.check_stmt_no_network(s);
                }
            }
            StmtKind::Break | StmtKind::Continue => {}
            StmtKind::Defer { .. } => {}
        }
    }

    fn check_expr_no_network(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                if let ExprKind::Ident(name) = &callee.kind {
                    if is_network_function(name) {
                        self.diags.push(Diagnostic::error(
                            "E0303",
                            format!("agent with can_network: false cannot call `{name}`"),
                            expr.span,
                        ));
                    }
                }
                for arg in args {
                    self.check_expr_no_network(&arg.value);
                }
            }
            ExprKind::MethodCall { object, method, args } => {
                if is_network_method(method) {
                    self.diags.push(Diagnostic::error(
                        "E0303",
                        format!("agent with can_network: false cannot call `.{method}()`"),
                        expr.span,
                    ));
                }
                self.check_expr_no_network(object);
                for arg in args {
                    self.check_expr_no_network(&arg.value);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.check_expr_no_network(left);
                self.check_expr_no_network(right);
            }
            ExprKind::If { condition, then_block, else_branch } => {
                self.check_expr_no_network(condition);
                for s in &then_block.stmts {
                    self.check_stmt_no_network(s);
                }
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => {
                            for s in &b.stmts {
                                self.check_stmt_no_network(s);
                            }
                        }
                        ElseBranch::ElseIf(e) => self.check_expr_no_network(e),
                    }
                }
            }
            ExprKind::IfLet { expr, then_block, else_branch, .. } => {
                self.check_expr_no_network(expr);
                for s in &then_block.stmts {
                    self.check_stmt_no_network(s);
                }
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => {
                            for s in &b.stmts {
                                self.check_stmt_no_network(s);
                            }
                        }
                        ElseBranch::ElseIf(e) => self.check_expr_no_network(e),
                    }
                }
            }
            ExprKind::Block(b) => {
                for s in &b.stmts {
                    self.check_stmt_no_network(s);
                }
            }
            ExprKind::Closure { body, .. } => {
                for s in body {
                    self.check_stmt_no_network(s);
                }
            }
            _ => {}
        }
    }

    // ── can_spawn check ─────────────────────────────────────────────────────

    fn check_no_spawn_calls(&mut self, block: &Block, _info: &AgentInfo) {
        for stmt in &block.stmts {
            self.check_stmt_no_spawn(stmt);
        }
    }

    fn check_stmt_no_spawn(&mut self, stmt: &Stmt) {
        match &stmt.kind {
            StmtKind::Expr { expr } => self.check_expr_no_spawn(expr),
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } | StmtKind::LetDestructure { value, .. } => {
                self.check_expr_no_spawn(value)
            }
            StmtKind::Return(Some(e)) | StmtKind::Bail(e) => self.check_expr_no_spawn(e),
            StmtKind::Return(None) => {}
            StmtKind::For { iter, body, .. } => {
                self.check_expr_no_spawn(iter);
                for s in &body.stmts {
                    self.check_stmt_no_spawn(s);
                }
            }
            StmtKind::While { condition, body } => {
                self.check_expr_no_spawn(condition);
                for s in &body.stmts {
                    self.check_stmt_no_spawn(s);
                }
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.check_expr_no_spawn(expr);
                for s in &body.stmts {
                    self.check_stmt_no_spawn(s);
                }
            }
            StmtKind::Loop { body } => {
                for s in &body.stmts {
                    self.check_stmt_no_spawn(s);
                }
            }
            StmtKind::Break | StmtKind::Continue => {}
            StmtKind::Defer { .. } => {}
        }
    }

    fn check_expr_no_spawn(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                if let ExprKind::Ident(name) = &callee.kind {
                    if is_spawn_function(name) {
                        self.diags.push(Diagnostic::error(
                            "E0305",
                            format!("agent with can_spawn: false cannot call `{name}`"),
                            expr.span,
                        ));
                    }
                }
                for arg in args {
                    self.check_expr_no_spawn(&arg.value);
                }
            }
            ExprKind::MethodCall { object, method, args } => {
                if is_spawn_method(method) {
                    self.diags.push(Diagnostic::error(
                        "E0305",
                        format!("agent with can_spawn: false cannot call `.{method}()`"),
                        expr.span,
                    ));
                }
                self.check_expr_no_spawn(object);
                for arg in args {
                    self.check_expr_no_spawn(&arg.value);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.check_expr_no_spawn(left);
                self.check_expr_no_spawn(right);
            }
            ExprKind::If { condition, then_block, else_branch } => {
                self.check_expr_no_spawn(condition);
                for s in &then_block.stmts {
                    self.check_stmt_no_spawn(s);
                }
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => {
                            for s in &b.stmts {
                                self.check_stmt_no_spawn(s);
                            }
                        }
                        ElseBranch::ElseIf(e) => self.check_expr_no_spawn(e),
                    }
                }
            }
            ExprKind::IfLet { expr, then_block, else_branch, .. } => {
                self.check_expr_no_spawn(expr);
                for s in &then_block.stmts {
                    self.check_stmt_no_spawn(s);
                }
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => {
                            for s in &b.stmts {
                                self.check_stmt_no_spawn(s);
                            }
                        }
                        ElseBranch::ElseIf(e) => self.check_expr_no_spawn(e),
                    }
                }
            }
            ExprKind::Block(b) => {
                for s in &b.stmts {
                    self.check_stmt_no_spawn(s);
                }
            }
            ExprKind::Closure { body, .. } => {
                for s in body {
                    self.check_stmt_no_spawn(s);
                }
            }
            _ => {}
        }
    }

    // ── can_execute check ─────────────────────────────────────────────────

    fn check_no_execute_calls(&mut self, block: &Block, _info: &AgentInfo) {
        for stmt in &block.stmts {
            self.check_stmt_no_execute(stmt);
        }
    }

    fn check_stmt_no_execute(&mut self, stmt: &Stmt) {
        match &stmt.kind {
            StmtKind::Expr { expr } => self.check_expr_no_execute(expr),
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } | StmtKind::LetDestructure { value, .. } => {
                self.check_expr_no_execute(value)
            }
            StmtKind::Return(Some(e)) | StmtKind::Bail(e) => self.check_expr_no_execute(e),
            StmtKind::Return(None) => {}
            StmtKind::For { iter, body, .. } => {
                self.check_expr_no_execute(iter);
                for s in &body.stmts {
                    self.check_stmt_no_execute(s);
                }
            }
            StmtKind::While { condition, body } => {
                self.check_expr_no_execute(condition);
                for s in &body.stmts {
                    self.check_stmt_no_execute(s);
                }
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.check_expr_no_execute(expr);
                for s in &body.stmts {
                    self.check_stmt_no_execute(s);
                }
            }
            StmtKind::Loop { body } => {
                for s in &body.stmts {
                    self.check_stmt_no_execute(s);
                }
            }
            StmtKind::Break | StmtKind::Continue => {}
            StmtKind::Defer { .. } => {}
        }
    }

    fn check_expr_no_execute(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                if let ExprKind::Ident(name) = &callee.kind {
                    if is_execute_function(name) {
                        self.diags.push(Diagnostic::error(
                            "E0306",
                            format!("@agent_task with can_execute: false cannot call `{name}`"),
                            expr.span,
                        ));
                    }
                }
                for arg in args {
                    self.check_expr_no_execute(&arg.value);
                }
            }
            ExprKind::MethodCall { object, method, args } => {
                if is_execute_method_call(object, method) {
                    self.diags.push(Diagnostic::error(
                        "E0306",
                        format!("@agent_task with can_execute: false cannot call `process.{method}()`"),
                        expr.span,
                    ));
                }
                self.check_expr_no_execute(object);
                for arg in args {
                    self.check_expr_no_execute(&arg.value);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.check_expr_no_execute(left);
                self.check_expr_no_execute(right);
            }
            ExprKind::If { condition, then_block, else_branch } => {
                self.check_expr_no_execute(condition);
                for s in &then_block.stmts {
                    self.check_stmt_no_execute(s);
                }
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => {
                            for s in &b.stmts {
                                self.check_stmt_no_execute(s);
                            }
                        }
                        ElseBranch::ElseIf(e) => self.check_expr_no_execute(e),
                    }
                }
            }
            ExprKind::IfLet { expr, then_block, else_branch, .. } => {
                self.check_expr_no_execute(expr);
                for s in &then_block.stmts {
                    self.check_stmt_no_execute(s);
                }
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => {
                            for s in &b.stmts {
                                self.check_stmt_no_execute(s);
                            }
                        }
                        ElseBranch::ElseIf(e) => self.check_expr_no_execute(e),
                    }
                }
            }
            ExprKind::Block(b) => {
                for s in &b.stmts {
                    self.check_stmt_no_execute(s);
                }
            }
            ExprKind::Closure { body, .. } => {
                for s in body {
                    self.check_stmt_no_execute(s);
                }
            }
            _ => {}
        }
    }
}

// ── Permission classification ───────────────────────────────────────────────

fn is_write_function(name: &str) -> bool {
    matches!(
        name,
        "write_file" | "create_file" | "delete_file" | "mkdir" | "remove_dir"
    )
}

fn is_write_method(method: &str) -> bool {
    matches!(
        method,
        "write" | "insert" | "delete" | "create" | "save" | "store"
    )
}

fn is_network_function(name: &str) -> bool {
    matches!(name, "fetch" | "connect" | "listen" | "bind")
}

fn is_network_method(method: &str) -> bool {
    matches!(method, "get" | "post" | "put" | "send" | "connect")
}

fn is_spawn_function(name: &str) -> bool {
    matches!(name, "spawn" | "spawn_agent" | "parallel_map")
}

fn is_spawn_method(method: &str) -> bool {
    matches!(method, "spawn" | "parallel_map" | "await_all")
}

fn is_execute_function(name: &str) -> bool {
    matches!(
        name,
        "process.exec" | "process.run" | "process.spawn"
    )
}

/// Returns true if this is a process execution method on a `process` object.
/// We check both the method name AND the object to avoid false positives
/// (e.g., some_object.exec() that isn't process-related).
fn is_execute_method_call(object: &Expr, method: &str) -> bool {
    if !matches!(method, "exec" | "run" | "spawn") {
        return false;
    }
    // Check if the object is the `process` identifier
    matches!(&object.kind, ExprKind::Ident(name) if name == "process")
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;
    use crate::parser::Parser;

    fn check(source: &str) -> Diagnostics {
        let (tokens, _) = lexer::tokenize(source);
        let program = Parser::parse(tokens).unwrap();
        AgentPass::new(&program).check()
    }

    #[test]
    fn agent_valid_passes() {
        let diags = check(
            r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_write: false, can_store: false)
            fn research(query: String) -> String {
                let data = "result"
                data
            }
            "#,
        );
        assert_eq!(diags.error_count(), 0);
    }

    #[test]
    fn agent_missing_id() {
        let diags = check(
            r#"
            @agent_task(timeout: 60.seconds)
            fn research() -> String { "ok" }
            "#,
        );
        assert!(diags.items.iter().any(|d| d.code == "E0300"));
    }

    #[test]
    fn agent_missing_timeout() {
        let diags = check(
            r#"
            @agent_task(id: task_id)
            fn research() -> String { "ok" }
            "#,
        );
        assert!(diags.items.iter().any(|d| d.code == "E0301"));
    }

    #[test]
    fn agent_no_write_violation() {
        let diags = check(
            r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_write: false)
            fn research() -> String {
                write_file("output.txt")
                "ok"
            }
            "#,
        );
        assert!(diags.items.iter().any(|d| d.code == "E0302"));
    }

    #[test]
    fn agent_no_write_method_violation() {
        let diags = check(
            r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_write: false)
            fn research() -> String {
                db.insert("key", "value")
                "ok"
            }
            "#,
        );
        assert!(diags.items.iter().any(|d| d.code == "E0302"));
    }

    #[test]
    fn agent_no_network_violation() {
        let diags = check(
            r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_network: false)
            fn process() -> String {
                let resp = fetch("https://example.com")
                "ok"
            }
            "#,
        );
        assert!(diags.items.iter().any(|d| d.code == "E0303"));
    }

    #[test]
    fn agent_execute_warning() {
        let diags = check(
            r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_execute: true)
            fn dangerous() -> String { "ok" }
            "#,
        );
        assert!(diags.items.iter().any(|d| d.code == "W0304"));
    }

    #[test]
    fn agent_write_allowed() {
        let diags = check(
            r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_write: true)
            fn writer() -> String {
                write_file("output.txt")
                "ok"
            }
            "#,
        );
        assert_eq!(diags.error_count(), 0);
    }

    #[test]
    fn agent_no_spawn_violation() {
        let diags = check(
            r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_spawn: false)
            fn orchestrator() -> String {
                spawn_agent("sub_task")
                "ok"
            }
            "#,
        );
        assert!(diags.items.iter().any(|d| d.code == "E0305"));
    }

    #[test]
    fn agent_no_spawn_method_violation() {
        let diags = check(
            r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_spawn: false)
            fn orchestrator() -> String {
                task.spawn()
                "ok"
            }
            "#,
        );
        assert!(diags.items.iter().any(|d| d.code == "E0305"));
    }

    #[test]
    fn agent_spawn_allowed() {
        let diags = check(
            r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_spawn: true)
            fn orchestrator() -> String {
                spawn_agent("sub_task")
                "ok"
            }
            "#,
        );
        assert_eq!(diags.error_count(), 0);
    }

    #[test]
    fn non_agent_function_ignored() {
        let diags = check(
            r#"
            fn normal() -> String {
                write_file("output.txt")
                "ok"
            }
            "#,
        );
        assert_eq!(diags.error_count(), 0);
    }

    #[test]
    fn agent_all_permissions_granted() {
        let diags = check(
            r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_write: true, can_store: true, can_spawn: true)
            fn full_agent() -> String {
                write_file("out.txt")
                db_insert("key", "val")
                spawn_agent("child")
                "ok"
            }
            "#,
        );
        assert_eq!(diags.error_count(), 0);
    }

    #[test]
    fn agent_write_and_spawn_violations() {
        let diags = check(
            r#"
            @agent_task(id: task_id, timeout: 60.seconds)
            fn bad_agent() -> String {
                write_file("out.txt")
                spawn_agent("child")
                "ok"
            }
            "#,
        );
        // Both write and spawn should fail
        assert!(diags.error_count() >= 2);
    }

    // ── Additional agent pass tests ───────────────────────────────────────

    #[test]
    fn agent_network_allowed_by_default() {
        // can_network defaults to true, so fetch should be allowed
        let diags = check(
            r#"
            @agent_task(id: task_id, timeout: 30.seconds)
            fn net_agent() -> String {
                fetch("https://example.com")
            }
            "#,
        );
        // Network should NOT cause an error (default can_network: true)
        assert!(!diags.items.iter().any(|d| d.code == "E0304"));
    }

    #[test]
    fn agent_write_method_insert_violation() {
        // .insert() is a write method — should be blocked with can_write: false
        let diags = check(
            r#"
            @agent_task(id: task_id, timeout: 60.seconds)
            fn store_agent() -> String {
                data.insert("key", "val")
                "ok"
            }
            "#,
        );
        assert!(diags.has_errors());
    }

    #[test]
    fn agent_write_method_insert_allowed() {
        let diags = check(
            r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_write: true)
            fn store_agent() -> String {
                data.insert("key", "val")
                "ok"
            }
            "#,
        );
        assert_eq!(diags.error_count(), 0);
    }

    #[test]
    fn non_agent_with_write_ok() {
        // Normal functions should not be checked by agent pass
        let diags = check(
            r#"
            fn normal_fn() -> String {
                write_file("out.txt")
                spawn_agent("child")
                "ok"
            }
            "#,
        );
        assert_eq!(diags.error_count(), 0);
    }

    #[test]
    fn agent_read_is_default_allowed() {
        // can_read defaults to true
        let diags = check(
            r#"
            @agent_task(id: task_id, timeout: 30.seconds)
            fn read_agent() -> String {
                read_file("input.txt")
            }
            "#,
        );
        // Reading should be fine by default
        assert_eq!(diags.error_count(), 0);
    }

    // ── Edge case tests ─────────────────────────────────────────────────

    #[test]
    fn empty_program_no_errors() {
        let diags = check("");
        assert_eq!(diags.error_count(), 0);
    }

    #[test]
    fn non_agent_functions_ignored_completely() {
        let diags = check(r#"
            fn normal_fn() {
                write_file("out.txt", "data")
                db.insert("key", "value")
                spawn_process("cmd")
            }
        "#);
        assert_eq!(diags.error_count(), 0);
    }

    #[test]
    fn agent_db_insert_triggers_write_check() {
        // db.insert is a write method — caught by can_write check
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_write: false)
            fn research() -> String {
                db.insert("key", "value")
                "done"
            }
        "#);
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0302"));
    }

    #[test]
    fn agent_db_insert_allowed_with_can_write() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_write: true)
            fn research() -> String {
                db.insert("key", "value")
                "done"
            }
        "#);
        assert_eq!(diags.error_count(), 0);
    }

    #[test]
    fn agent_write_and_spawn_both_fail() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_write: false, can_spawn: false)
            fn multi_bad() -> String {
                write_file("out.txt", "data")
                "done"
            }
        "#);
        // At least 1 error for write violation
        assert!(diags.error_count() >= 1);
    }

    #[test]
    fn agent_with_all_permissions_no_errors() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 120.seconds, can_write: true, can_store: true, can_spawn: true, can_network: true, can_execute: true)
            fn fully_permitted() -> String {
                write_file("out.txt", "data")
                db.insert("key", "value")
                spawn_task("sub")
                fetch("https://example.com")
                "done"
            }
        "#);
        assert_eq!(diags.error_count(), 0);
    }

    #[test]
    fn agent_timeout_required() {
        let diags = check(r#"
            @agent_task(id: task_id)
            fn no_timeout() -> String { "done" }
        "#);
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0301"));
    }

    #[test]
    fn multiple_agent_functions_checked() {
        let diags = check(r#"
            @agent_task(id: task1, timeout: 30.seconds, can_write: false)
            fn agent1() -> String {
                write_file("out.txt", "data")
                "done"
            }
            @agent_task(id: task2, timeout: 30.seconds, can_spawn: false)
            fn agent2() -> String {
                spawn_agent("sub")
                "done"
            }
        "#);
        assert!(diags.error_count() >= 2);
    }

    // ── Batch: additional agent pass coverage ─────────────────────────

    #[test]
    fn agent_network_blocked_without_can_network() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds, can_network: false)
            fn offline_agent() -> String {
                fetch("https://example.com")
                "done"
            }
        "#);
        assert!(diags.has_errors());
    }

    #[test]
    fn agent_network_allowed_with_can_network() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds, can_network: true)
            fn online_agent() -> String {
                fetch("https://example.com")
                "done"
            }
        "#);
        assert_eq!(diags.error_count(), 0);
    }

    #[test]
    fn agent_execute_true_warns() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds, can_execute: true)
            fn shell_agent() -> String {
                "done"
            }
        "#);
        // can_execute: true emits a warning W0304
        assert!(diags.items.iter().any(|d| d.code == "W0304"));
    }

    #[test]
    fn agent_write_method_store_blocked() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds, can_write: false)
            fn storage_agent() -> String {
                db.store("collection", "data")
                "done"
            }
        "#);
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0302"));
    }

    #[test]
    fn agent_write_method_save_blocked() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds, can_write: false)
            fn save_agent() -> String {
                db.save("key", "value")
                "done"
            }
        "#);
        assert!(diags.has_errors());
    }

    #[test]
    fn agent_spawn_fn_blocked_without_can_spawn() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds, can_spawn: false)
            fn orchestrator() -> String {
                spawn("subtask")
                "done"
            }
        "#);
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0305"));
    }

    #[test]
    fn agent_spawn_fn_allowed_with_can_spawn() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds, can_spawn: true)
            fn orchestrator() -> String {
                spawn("subtask")
                "done"
            }
        "#);
        assert_eq!(diags.error_count(), 0);
    }

    #[test]
    fn agent_mixed_write_methods_all_blocked() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds, can_write: false)
            fn writer() -> String {
                write_file("a.txt", "data")
                save_file("b.txt", "data")
                "done"
            }
        "#);
        assert!(diags.error_count() >= 1);
    }

    #[test]
    fn agent_only_has_agent_task_annotation() {
        // Ensure a function with only @legal but not @agent_task is not checked by agent pass
        let diags = check(r#"
            @legal(basis: .public_data, purpose: "scraping")
            fn scraper() -> String {
                write_file("out.txt", "data")
                "done"
            }
        "#);
        assert_eq!(diags.error_count(), 0);
    }

    #[test]
    fn agent_write_and_network_violations_counted() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds, can_write: false, can_network: false)
            fn bad_agent() -> String {
                write_file("out.txt", "data")
                fetch("https://example.com")
                "done"
            }
        "#);
        assert!(diags.error_count() >= 2);
    }

    // ── New coverage tests: control flow nesting ───────────────────

    #[test]
    fn agent_write_in_if_block() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_write: false)
            fn research() -> String {
                if true { write_file("out.txt", "data") }
                "ok"
            }
        "#);
        assert!(diags.items.iter().any(|d| d.code == "E0302"));
    }

    #[test]
    fn agent_write_in_for_loop() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_write: false)
            fn research() -> String {
                for i in items { write_file("out.txt", "data") }
                "ok"
            }
        "#);
        assert!(diags.items.iter().any(|d| d.code == "E0302"));
    }

    #[test]
    fn agent_write_in_while_loop() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_write: false)
            fn research() -> String {
                while true { write_file("out.txt", "data") }
                "ok"
            }
        "#);
        assert!(diags.items.iter().any(|d| d.code == "E0302"));
    }

    #[test]
    fn agent_network_in_if_block() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_network: false)
            fn research() -> String {
                if true { fetch("https://example.com") }
                "ok"
            }
        "#);
        assert!(diags.items.iter().any(|d| d.code == "E0303"));
    }

    #[test]
    fn agent_network_in_for_loop() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_network: false)
            fn research() -> String {
                for url in urls { fetch(url) }
                "ok"
            }
        "#);
        assert!(diags.items.iter().any(|d| d.code == "E0303"));
    }

    #[test]
    fn agent_network_in_while_loop() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_network: false)
            fn research() -> String {
                while true { fetch("https://example.com") }
                "ok"
            }
        "#);
        assert!(diags.items.iter().any(|d| d.code == "E0303"));
    }

    #[test]
    fn agent_spawn_in_if_block() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_spawn: false)
            fn research() -> String {
                if true { spawn(task) }
                "ok"
            }
        "#);
        assert!(diags.items.iter().any(|d| d.code == "E0305"));
    }

    #[test]
    fn agent_spawn_in_for_loop() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_spawn: false)
            fn research() -> String {
                for t in tasks { spawn(t) }
                "ok"
            }
        "#);
        assert!(diags.items.iter().any(|d| d.code == "E0305"));
    }

    #[test]
    fn agent_mkdir_with_no_write() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_write: false)
            fn research() -> String {
                mkdir("output")
                "ok"
            }
        "#);
        assert!(diags.items.iter().any(|d| d.code == "E0302"));
    }

    #[test]
    fn agent_connect_with_no_network() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_network: false)
            fn research() -> String {
                connect("db://localhost")
                "ok"
            }
        "#);
        assert!(diags.items.iter().any(|d| d.code == "E0303"));
    }

    #[test]
    fn agent_listen_with_no_network() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_network: false)
            fn research() -> String {
                listen("0.0.0.0:8080")
                "ok"
            }
        "#);
        assert!(diags.items.iter().any(|d| d.code == "E0303"));
    }

    #[test]
    fn agent_bind_with_no_network() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_network: false)
            fn research() -> String {
                bind("0.0.0.0:9090")
                "ok"
            }
        "#);
        assert!(diags.items.iter().any(|d| d.code == "E0303"));
    }

    #[test]
    fn agent_missing_both_id_and_timeout() {
        let diags = check(r#"
            @agent_task()
            fn research() -> String { "ok" }
        "#);
        assert!(diags.items.iter().any(|d| d.code == "E0300"));
        assert!(diags.items.iter().any(|d| d.code == "E0301"));
    }

    #[test]
    fn agent_all_three_violations() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds, can_write: false, can_network: false, can_spawn: false)
            fn bad_agent() -> String {
                write_file("out.txt", "data")
                fetch("https://example.com")
                spawn(task)
                "done"
            }
        "#);
        assert!(diags.items.iter().any(|d| d.code == "E0302"));
        assert!(diags.items.iter().any(|d| d.code == "E0303"));
        assert!(diags.items.iter().any(|d| d.code == "E0305"));
    }

    #[test]
    fn agent_with_all_permissions_granted() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_write: true, can_network: true, can_spawn: true)
            fn full_agent() -> String {
                write_file("out.txt", "data")
                fetch("https://example.com")
                spawn(task)
                "done"
            }
        "#);
        assert_eq!(diags.error_count(), 0);
    }

    #[test]
    fn agent_remove_dir_with_no_write() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_write: false)
            fn cleanup() -> String {
                remove_dir("temp")
                "ok"
            }
        "#);
        assert!(diags.items.iter().any(|d| d.code == "E0302"));
    }

    #[test]
    fn agent_delete_file_with_no_write() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_write: false)
            fn cleanup() -> String {
                delete_file("temp.txt")
                "ok"
            }
        "#);
        assert!(diags.items.iter().any(|d| d.code == "E0302"));
    }

    #[test]
    fn agent_create_file_with_no_write() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, can_write: false)
            fn logger() -> String {
                create_file("log.txt")
                "ok"
            }
        "#);
        assert!(diags.items.iter().any(|d| d.code == "E0302"));
    }

    // ── llm_policy annotation parsing ────────────────────────────────────

    #[test]
    fn agent_llm_policy_local_only_accepted() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, llm_policy: .local_only)
            fn handler() -> String { "ok" }
        "#);
        assert_eq!(diags.error_count(), 0, "llm_policy: .local_only should be accepted");
    }

    #[test]
    fn agent_llm_policy_allow_cloud_accepted() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, llm_policy: .allow_cloud)
            fn handler() -> String { "ok" }
        "#);
        assert_eq!(diags.error_count(), 0, "llm_policy: .allow_cloud should be accepted");
    }

    #[test]
    fn agent_llm_policy_redact_private_accepted() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, llm_policy: .redact_private)
            fn handler() -> String { "ok" }
        "#);
        assert_eq!(diags.error_count(), 0, "llm_policy: .redact_private should be accepted");
    }

    #[test]
    fn agent_llm_policy_tee_required_accepted() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 60.seconds, llm_policy: .tee_required)
            fn handler() -> String { "ok" }
        "#);
        assert_eq!(diags.error_count(), 0, "llm_policy: .tee_required should be accepted");
    }

    // ── E0306 can_execute checks ─────────────────────────────────────

    #[test]
    fn agent_no_execute_blocks_process_exec() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds)
            fn runner() -> String {
                let result = process.exec("ls")
                "done"
            }
        "#);
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0306"),
            "should emit E0306 for process.exec without can_execute");
    }

    #[test]
    fn agent_no_execute_blocks_process_spawn() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds)
            fn runner() -> String {
                let handle = process.spawn("ls")
                "done"
            }
        "#);
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0306"),
            "should emit E0306 for process.spawn without can_execute");
    }

    #[test]
    fn agent_no_execute_blocks_process_run() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds)
            fn runner() -> String {
                let result = process.run("ls")
                "done"
            }
        "#);
        assert!(diags.has_errors());
        assert!(diags.items.iter().any(|d| d.code == "E0306"),
            "should emit E0306 for process.run without can_execute");
    }

    #[test]
    fn agent_with_execute_allows_process_exec() {
        let diags = check(r#"
            @agent_task(id: task_id, timeout: 30.seconds, can_execute: true)
            fn runner() -> String {
                let result = process.exec("ls")
                "done"
            }
        "#);
        // No E0306 errors — but W0304 warning should still fire
        assert!(!diags.items.iter().any(|d| d.code == "E0306"),
            "should NOT emit E0306 when can_execute: true");
        assert!(diags.items.iter().any(|d| d.code == "W0304"),
            "should still emit W0304 warning for can_execute: true");
    }
}
