//! @enclave annotation validation compiler pass.
//!
//! Validates @enclave annotations on functions for trusted execution environments:
//! - E1600: Network access in @enclave function (fetch, http.*, socket, connect)
//! - E1601: Filesystem access in @enclave function (read_file, write_file, fs.*)
//! - E1602: Invalid enclave platform (not .sgx, .tdx, .sev)
//! - E1603: Print/log in @enclave function (information leakage)
//! - W1600: @enclave function calls non-enclave function

use std::collections::HashSet;

use crate::ast::*;
use crate::error::Diagnostics;

// ── Valid enclave platforms ──────────────────────────────────────────────────

const VALID_PLATFORMS: &[&str] = &["sgx", "tdx", "sev"];

// ── Forbidden call patterns ─────────────────────────────────────────────────

const NETWORK_CALLS: &[&str] = &[
    "fetch", "http", "socket", "connect", "listen", "bind", "accept",
    "sendto", "recvfrom", "TLSConn",
];

const FS_CALLS: &[&str] = &[
    "read_file", "write_file", "fs", "open", "fopen",
];

const PRINT_LOG_CALLS: &[&str] = &[
    "print", "println", "log", "eprintln",
];

// ── Pass ────────────────────────────────────────────────────────────────────

pub struct EnclavePass<'a> {
    program: &'a Program,
    pub diags: Diagnostics,
    enclave_fns: HashSet<String>,
}

impl<'a> EnclavePass<'a> {
    pub fn new(program: &'a Program) -> Self {
        Self {
            program,
            diags: Diagnostics::new(),
            enclave_fns: HashSet::new(),
        }
    }

    /// Run the enclave pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        // Phase 1: Collect @enclave annotations and validate platform arg
        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.collect_enclave_fn(f),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.collect_enclave_fn(m);
                    }
                }
                _ => {}
            }
        }

        // Phase 2: Walk enclave function bodies for forbidden operations
        let enclave_fns = self.enclave_fns.clone();
        for item in &self.program.items {
            match item {
                Item::Fn(f) => {
                    if enclave_fns.contains(&f.name) {
                        self.check_enclave_body(f, &enclave_fns);
                    }
                }
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        if enclave_fns.contains(&m.name) {
                            self.check_enclave_body(m, &enclave_fns);
                        }
                    }
                }
                _ => {}
            }
        }

        self.diags
    }

    fn collect_enclave_fn(&mut self, f: &FnDecl) {
        for ann in &f.annotations {
            if ann.name != "enclave" {
                continue;
            }

            self.enclave_fns.insert(f.name.clone());

            // Validate platform argument
            let mut has_platform = false;
            for arg in &ann.args {
                if arg.name == "platform" || arg.name.is_empty() {
                    has_platform = true;
                    if let ExprKind::DotIdent(platform) = &arg.value.kind {
                        if !VALID_PLATFORMS.contains(&platform.as_str()) {
                            self.diags.error(
                                "E1602",
                                format!(
                                    "invalid enclave platform '.{platform}' on function '{}'; \
                                     expected .sgx, .tdx, or .sev",
                                    f.name
                                ),
                                arg.value.span,
                            );
                        }
                    } else if let ExprKind::Ident(platform) = &arg.value.kind {
                        if !VALID_PLATFORMS.contains(&platform.as_str()) {
                            self.diags.error(
                                "E1602",
                                format!(
                                    "invalid enclave platform '{platform}' on function '{}'; \
                                     expected .sgx, .tdx, or .sev",
                                    f.name
                                ),
                                arg.value.span,
                            );
                        }
                    }
                }
            }

            // If no platform arg at all but annotation has a positional DotIdent
            if !has_platform {
                // Check if there's a positional arg (first arg with empty name)
                let positional = ann.args.iter().find(|a| a.name.is_empty());
                if let Some(arg) = positional {
                    if let ExprKind::DotIdent(platform) = &arg.value.kind {
                        if !VALID_PLATFORMS.contains(&platform.as_str()) {
                            self.diags.error(
                                "E1602",
                                format!(
                                    "invalid enclave platform '.{platform}' on function '{}'; \
                                     expected .sgx, .tdx, or .sev",
                                    f.name
                                ),
                                arg.value.span,
                            );
                        }
                    }
                }
            }
        }
    }

    fn check_enclave_body(&mut self, f: &FnDecl, enclave_fns: &HashSet<String>) {
        for stmt in &f.body.stmts {
            self.check_stmt_enclave(stmt, &f.name, enclave_fns);
        }
    }

    fn check_stmt_enclave(
        &mut self,
        stmt: &Stmt,
        fn_name: &str,
        enclave_fns: &HashSet<String>,
    ) {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.walk_expr_enclave(value, fn_name, enclave_fns);
            }
            StmtKind::LetDestructure { value, .. } => {
                self.walk_expr_enclave(value, fn_name, enclave_fns);
            }
            StmtKind::Expr { expr } => {
                self.walk_expr_enclave(expr, fn_name, enclave_fns);
            }
            StmtKind::Return(Some(expr)) => {
                self.walk_expr_enclave(expr, fn_name, enclave_fns);
            }
            _ => {}
        }
    }

    fn walk_expr_enclave(
        &mut self,
        expr: &Expr,
        fn_name: &str,
        enclave_fns: &HashSet<String>,
    ) {
        match &expr.kind {
            ExprKind::Call { callee, args, .. } => {
                // Check the callee name
                let callee_name = self.extract_call_name(callee);
                if let Some(ref name) = callee_name {
                    self.check_forbidden_call(name, fn_name, expr.span, enclave_fns);
                }
                // Walk args
                for arg in args {
                    self.walk_expr_enclave(&arg.value, fn_name, enclave_fns);
                }
            }
            ExprKind::MethodCall { object, method, args, .. } => {
                // Check module.method style calls
                if let ExprKind::Ident(module) = &object.kind {
                    let qualified = format!("{module}.{method}");
                    self.check_forbidden_call(&qualified, fn_name, expr.span, enclave_fns);
                    // Also check just the module prefix
                    self.check_forbidden_call(module, fn_name, expr.span, enclave_fns);
                }
                self.walk_expr_enclave(object, fn_name, enclave_fns);
                for arg in args {
                    self.walk_expr_enclave(&arg.value, fn_name, enclave_fns);
                }
            }
            ExprKind::Block(block) => {
                for stmt in &block.stmts {
                    self.check_stmt_enclave(stmt, fn_name, enclave_fns);
                }
            }
            ExprKind::If { condition, then_block, else_branch, .. } => {
                self.walk_expr_enclave(condition, fn_name, enclave_fns);
                for stmt in &then_block.stmts {
                    self.check_stmt_enclave(stmt, fn_name, enclave_fns);
                }
                if let Some(branch) = else_branch {
                    match branch {
                        ElseBranch::Block(block) => {
                            for stmt in &block.stmts {
                                self.check_stmt_enclave(stmt, fn_name, enclave_fns);
                            }
                        }
                        ElseBranch::ElseIf(expr) => {
                            self.walk_expr_enclave(expr, fn_name, enclave_fns);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn extract_call_name(&self, expr: &Expr) -> Option<String> {
        match &expr.kind {
            ExprKind::Ident(name) => Some(name.clone()),
            ExprKind::FieldAccess { object, field, .. } => {
                if let ExprKind::Ident(module) = &object.kind {
                    Some(format!("{module}.{field}"))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn check_forbidden_call(
        &mut self,
        call_name: &str,
        fn_name: &str,
        span: crate::lexer::Span,
        enclave_fns: &HashSet<String>,
    ) {
        // Check for network access
        for pat in NETWORK_CALLS {
            if call_name == *pat || call_name.starts_with(&format!("{pat}.")) {
                self.diags.error(
                    "E1600",
                    format!(
                        "network access '{call_name}' in @enclave function '{fn_name}'; \
                         enclave functions cannot perform network I/O"
                    ),
                    span,
                );
                return;
            }
        }

        // Check for filesystem access
        for pat in FS_CALLS {
            if call_name == *pat || call_name.starts_with(&format!("{pat}.")) {
                self.diags.error(
                    "E1601",
                    format!(
                        "filesystem access '{call_name}' in @enclave function '{fn_name}'; \
                         enclave functions cannot perform filesystem I/O"
                    ),
                    span,
                );
                return;
            }
        }

        // Check for print/log (information leakage)
        for pat in PRINT_LOG_CALLS {
            if call_name == *pat || call_name.starts_with(&format!("{pat}.")) {
                self.diags.error(
                    "E1603",
                    format!(
                        "print/log '{call_name}' in @enclave function '{fn_name}'; \
                         enclave functions must not leak information via output"
                    ),
                    span,
                );
                return;
            }
        }

        // W1600: calling non-enclave function from enclave function
        // Only warn for user-defined function names (not builtins)
        if !enclave_fns.contains(call_name)
            && !call_name.contains('.')
            && !is_safe_builtin(call_name)
        {
            self.diags.warning(
                "W1600",
                format!(
                    "@enclave function '{fn_name}' calls non-enclave function '{call_name}'"
                ),
                span,
            );
        }
    }
}

/// Builtins that are safe within enclaves (pure computation).
fn is_safe_builtin(name: &str) -> bool {
    matches!(
        name,
        "len" | "push" | "pop" | "map" | "filter" | "contains"
            | "to_string" | "parse" | "hash" | "encrypt" | "decrypt"
            | "verify" | "sign"
    )
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_and_check(src: &str) -> Diagnostics {
        let (tokens, _) = crate::lexer::tokenize(src);
        let program = crate::parser::Parser::parse(tokens).expect("parse failed");
        EnclavePass::new(&program).check()
    }

    #[test]
    fn test_enclave_valid() {
        let src = r#"
@enclave(platform: .sgx)
fn secure_compute(data: Bytes) -> i32 {
    let x = 42
    x
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "valid enclave function should have no errors");
    }

    #[test]
    fn test_enclave_rejects_fetch() {
        let src = r#"
@enclave(platform: .sgx)
fn bad_enclave() {
    let resp = fetch("https://example.com")
}
"#;
        let diags = parse_and_check(src);
        assert!(diags.error_count() >= 1, "should reject fetch in enclave");
        let err = diags.items.iter().find(|d| d.code == "E1600").unwrap();
        assert!(err.msg.contains("fetch"));
        assert!(err.msg.contains("network"));
    }

    #[test]
    fn test_enclave_rejects_fs() {
        let src = r#"
@enclave(platform: .tdx)
fn bad_enclave() {
    let data = read_file("/etc/passwd")
}
"#;
        let diags = parse_and_check(src);
        assert!(diags.error_count() >= 1, "should reject read_file in enclave");
        let err = diags.items.iter().find(|d| d.code == "E1601").unwrap();
        assert!(err.msg.contains("read_file"));
        assert!(err.msg.contains("filesystem"));
    }

    #[test]
    fn test_enclave_invalid_platform() {
        let src = r#"
@enclave(platform: .arm_trustzone)
fn bad_platform() {
    let x = 1
}
"#;
        let diags = parse_and_check(src);
        assert!(diags.error_count() >= 1, "should reject invalid platform");
        let err = diags.items.iter().find(|d| d.code == "E1602").unwrap();
        assert!(err.msg.contains("arm_trustzone"));
    }

    #[test]
    fn test_enclave_rejects_print() {
        let src = r#"
@enclave(platform: .sev)
fn leaky_enclave() {
    print("secret data")
}
"#;
        let diags = parse_and_check(src);
        assert!(diags.error_count() >= 1, "should reject print in enclave");
        let err = diags.items.iter().find(|d| d.code == "E1603").unwrap();
        assert!(err.msg.contains("print"));
        assert!(err.msg.contains("leak"));
    }

    #[test]
    fn test_enclave_warns_non_enclave_call() {
        let src = r#"
fn helper() -> i32 {
    42
}

@enclave(platform: .sgx)
fn secure_fn() {
    let x = helper()
}
"#;
        let diags = parse_and_check(src);
        let warnings: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W1600")
            .collect();
        assert_eq!(warnings.len(), 1, "should warn about calling non-enclave function");
        assert!(warnings[0].msg.contains("helper"));
    }
}
