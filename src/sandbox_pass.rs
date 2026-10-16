//! @sandbox and @sandboxed annotation validation compiler pass.
//!
//! Validates @sandbox annotations on functions:
//! - E1100: unknown syscall in allow list
//! - E1101: duplicate @sandbox on same function
//! - W1100: @sandbox without deny_default: true (permissive)
//! - W1101: non-sandboxed function calls sandboxed function
//!
//! Validates @sandboxed annotations (Phase 42: Container & Cloud Security):
//! - E2500: @sandboxed function uses disallowed syscall (call to OS-level fn not in whitelist)
//! - W2500: @sandboxed without syscall whitelist (no allow list specified)
//!
//! This pass performs **compile-time** validation of the allow-list and the
//! call-graph (E1100/E1101/W1100, E2500/W2500). The **runtime** enforcement —
//! actually installing a seccomp-BPF / Landlock filter in the process — is the
//! [`install_seccomp_filter`] hook below. Compile-time validation
//! guarantees the policy is well-formed; the hook is the point where a codegen
//! backend turns that policy into a kernel-enforced filter. See
//! [`SeccompPolicy`] for the policy type and [`install_seccomp_filter`] for
//! the concrete libseccomp/Landlock calls it would make.
//!
//! **Enforcement status — check-time analysis only.** `SandboxPass::check`
//! validates `@sandbox` / `@sandboxed` policies, but nothing in the compiler
//! or runtime invokes [`install_seccomp_filter`] automatically: no codegen
//! backend calls it today, so running a `check`/`build` does **not** install a
//! kernel filter. Sandboxing is only actually enforced when a runtime that
//! hosts the compiled unit of work explicitly calls [`install_seccomp_filter`]
//! (or an equivalent Landlock setup) before executing it. Treat the pass as
//! policy validation, and the hook as an opt-in enforcement point that a
//! backend must wire in.

use std::collections::{HashMap, HashSet};

use crate::ast::*;
use crate::error::Diagnostics;

/// Names of functions (top-level and impl methods) annotated `@sandbox` /
/// `@sandboxed`. Used by `tallow run` to warn when annotated code is about to
/// execute unconfined (security-audit R3, runtime enforcement path).
pub fn annotated_functions(program: &Program) -> Vec<String> {
    let mut out = Vec::new();
    for item in &program.items {
        match item {
            Item::Fn(f) => {
                if f.annotations
                    .iter()
                    .any(|a| a.name == "sandbox" || a.name == "sandboxed")
                {
                    out.push(f.name.clone());
                }
            }
            Item::Impl(imp) => {
                for m in &imp.methods {
                    if m.annotations
                        .iter()
                        .any(|a| a.name == "sandbox" || a.name == "sandboxed")
                    {
                        out.push(m.name.clone());
                    }
                }
            }
            _ => {}
        }
    }
    out
}

// ── Valid syscalls ─────────────────────────────────────────────────────────

const VALID_SYSCALLS: &[&str] = &[
    "read", "write", "open", "close", "openat",
    "mmap", "munmap", "mprotect", "brk",
    "exit", "exit_group", "rt_sigreturn",
    "futex", "clock_gettime", "getrandom",
    "ioctl", "fcntl", "fstat", "stat", "lseek",
    "access", "pipe", "dup", "dup2",
    "socket", "connect", "bind", "listen", "accept",
    "sendto", "recvfrom",
    "epoll_create1", "epoll_ctl", "epoll_wait",
];

// OS-level function names that map to syscalls — if called from @sandboxed
// function body and not in the allow list, emit E2500
const OS_CALL_NAMES: &[&str] = &[
    "exec", "execve", "fork", "clone", "kill", "ptrace",
    "mount", "umount", "chroot", "pivot_root",
    "setuid", "setgid", "seteuid", "setegid",
    "chmod", "chown", "unlink", "rmdir", "rename",
    "socket", "bind", "listen", "connect", "accept",
    "sendto", "recvfrom", "sendmsg", "recvmsg",
    "mmap", "munmap", "mprotect", "mlock",
    "ioctl", "sysctl", "reboot", "shutdown",
];

// ── Pass ───────────────────────────────────────────────────────────────────

pub struct SandboxPass<'a> {
    program: &'a Program,
    pub diags: Diagnostics,
    /// Functions that have @sandbox annotation.
    sandboxed_fns: HashSet<String>,
    /// All function names for call graph checking.
    all_fns: HashMap<String, bool>, // name -> is_sandboxed
}

impl<'a> SandboxPass<'a> {
    pub fn new(program: &'a Program) -> Self {
        Self {
            program,
            diags: Diagnostics::new(),
            sandboxed_fns: HashSet::new(),
            all_fns: HashMap::new(),
        }
    }

    /// Run the sandbox pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        // Phase 1: Collect all @sandbox annotations and validate them
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

        // Phase 2: Check for non-sandboxed callers of sandboxed functions
        let sandboxed = self.sandboxed_fns.clone();
        let all_fns = self.all_fns.clone();
        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.check_caller(f, &sandboxed, &all_fns),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.check_caller(m, &sandboxed, &all_fns);
                    }
                }
                _ => {}
            }
        }

        // Phase 3: Validate @sandboxed annotations (Phase 42)
        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.validate_sandboxed_fn(f),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.validate_sandboxed_fn(m);
                    }
                }
                _ => {}
            }
        }

        self.diags
    }

    fn validate_fn(&mut self, f: &FnDecl) {
        let sandbox_anns: Vec<&Annotation> = f.annotations.iter()
            .filter(|a| a.name == "sandbox")
            .collect();

        let is_sandboxed = !sandbox_anns.is_empty();
        self.all_fns.insert(f.name.clone(), is_sandboxed);

        if is_sandboxed {
            self.sandboxed_fns.insert(f.name.clone());
        }

        // E1101: duplicate @sandbox
        if sandbox_anns.len() > 1 {
            self.diags.error(
                "E1101",
                format!("duplicate @sandbox annotation on function '{}'", f.name),
                sandbox_anns[1].span,
            );
        }

        for ann in &sandbox_anns {
            let mut has_deny_default = false;
            let mut deny_default_true = false;

            for arg in &ann.args {
                if arg.name == "allow" {
                    // Validate syscall names in the allow list
                    self.validate_allow_list(&arg.value, &f.name);
                } else if arg.name == "deny_default" {
                    has_deny_default = true;
                    if let ExprKind::BoolLit(val) = &arg.value.kind {
                        deny_default_true = *val;
                    }
                }
            }

            // W1100: @sandbox without deny_default: true
            if !has_deny_default || !deny_default_true {
                self.diags.warning(
                    "W1100",
                    format!(
                        "@sandbox on '{}' without deny_default: true is permissive",
                        f.name
                    ),
                    ann.span,
                );
            }
        }
    }

    fn validate_allow_list(&mut self, expr: &Expr, fn_name: &str) {
        match &expr.kind {
            ExprKind::Array(items) => {
                for item in items {
                    if let ExprKind::DotIdent(name) = &item.kind {
                        if !VALID_SYSCALLS.contains(&name.as_str()) {
                            self.diags.error(
                                "E1100",
                                format!(
                                    "unknown syscall '.{name}' in @sandbox allow list on '{fn_name}'"
                                ),
                                item.span,
                            );
                        }
                    }
                }
            }
            ExprKind::DotIdent(name) => {
                // Single syscall (not in array)
                if !VALID_SYSCALLS.contains(&name.as_str()) {
                    self.diags.error(
                        "E1100",
                        format!(
                            "unknown syscall '.{name}' in @sandbox allow list on '{fn_name}'"
                        ),
                        expr.span,
                    );
                }
            }
            _ => {}
        }
    }

    // ── @sandboxed validation (Phase 42) ─────────────────────────────────

    fn validate_sandboxed_fn(&mut self, f: &FnDecl) {
        let sandboxed_anns: Vec<&Annotation> = f.annotations.iter()
            .filter(|a| a.name == "sandboxed")
            .collect();

        if sandboxed_anns.is_empty() {
            return;
        }

        for ann in &sandboxed_anns {
            // Collect allowed syscalls from the annotation
            let mut allowed_syscalls: HashSet<String> = HashSet::new();
            let mut has_allow_list = false;

            for arg in &ann.args {
                if arg.name == "allow" || arg.name == "syscalls" {
                    has_allow_list = true;
                    self.collect_allowed_syscalls(&arg.value, &mut allowed_syscalls);
                }
            }

            // W2500: @sandboxed without syscall whitelist
            if !has_allow_list {
                self.diags.warning(
                    "W2500",
                    format!(
                        "@sandboxed on '{}' has no syscall whitelist — all OS calls implicitly blocked",
                        f.name
                    ),
                    ann.span,
                );
            }

            // E2500: Check function body for disallowed OS-level calls
            self.check_body_for_disallowed_calls(&f.body.stmts, &f.name, &allowed_syscalls, ann.span);
        }
    }

    fn collect_allowed_syscalls(&self, expr: &Expr, allowed: &mut HashSet<String>) {
        match &expr.kind {
            ExprKind::Array(items) => {
                for item in items {
                    if let ExprKind::DotIdent(name) = &item.kind {
                        allowed.insert(name.clone());
                    } else if let ExprKind::StringLit(s) = &item.kind {
                        allowed.insert(s.clone());
                    }
                }
            }
            ExprKind::DotIdent(name) => {
                allowed.insert(name.clone());
            }
            ExprKind::StringLit(s) => {
                allowed.insert(s.clone());
            }
            _ => {}
        }
    }

    fn check_body_for_disallowed_calls(
        &mut self,
        stmts: &[Stmt],
        fn_name: &str,
        allowed: &HashSet<String>,
        fn_span: crate::lexer::Span,
    ) {
        for stmt in stmts {
            self.check_stmt_for_disallowed(stmt, fn_name, allowed, fn_span);
        }
    }

    fn check_stmt_for_disallowed(
        &mut self,
        stmt: &Stmt,
        fn_name: &str,
        allowed: &HashSet<String>,
        fn_span: crate::lexer::Span,
    ) {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.walk_expr_for_disallowed(value, fn_name, allowed, fn_span);
            }
            StmtKind::LetDestructure { value, .. } => {
                self.walk_expr_for_disallowed(value, fn_name, allowed, fn_span);
            }
            StmtKind::Expr { expr } => {
                self.walk_expr_for_disallowed(expr, fn_name, allowed, fn_span);
            }
            StmtKind::Return(Some(expr)) => {
                self.walk_expr_for_disallowed(expr, fn_name, allowed, fn_span);
            }
            _ => {}
        }
    }

    fn walk_expr_for_disallowed(
        &mut self,
        expr: &Expr,
        fn_name: &str,
        allowed: &HashSet<String>,
        fn_span: crate::lexer::Span,
    ) {
        match &expr.kind {
            ExprKind::Call { callee, args, .. } => {
                if let ExprKind::Ident(name) = &callee.kind {
                    // Check if this is an OS-level call not in the allowed list
                    if OS_CALL_NAMES.contains(&name.as_str()) && !allowed.contains(name.as_str()) {
                        self.diags.error(
                            "E2500",
                            format!(
                                "@sandboxed function '{}' uses disallowed syscall '{}' — add to allow list or remove call",
                                fn_name, name
                            ),
                            expr.span,
                        );
                    }
                }
                // Walk args
                for arg in args {
                    self.walk_expr_for_disallowed(&arg.value, fn_name, allowed, fn_span);
                }
            }
            ExprKind::Block(block) => {
                self.check_body_for_disallowed_calls(&block.stmts, fn_name, allowed, fn_span);
            }
            _ => {}
        }
    }

    fn check_caller(
        &mut self,
        f: &FnDecl,
        sandboxed: &HashSet<String>,
        all_fns: &HashMap<String, bool>,
    ) {
        let caller_sandboxed = all_fns.get(&f.name).copied().unwrap_or(false);
        if caller_sandboxed {
            return; // Sandboxed callers are fine
        }

        // Walk function body looking for calls to sandboxed functions
        self.check_stmts_for_calls(&f.body.stmts, &f.name, sandboxed, f.span);
    }

    fn check_stmts_for_calls(
        &mut self,
        stmts: &[Stmt],
        caller_name: &str,
        sandboxed: &HashSet<String>,
        caller_span: crate::lexer::Span,
    ) {
        for stmt in stmts {
            self.check_expr_for_calls(stmt, caller_name, sandboxed, caller_span);
        }
    }

    fn check_expr_for_calls(
        &mut self,
        stmt: &Stmt,
        caller_name: &str,
        sandboxed: &HashSet<String>,
        caller_span: crate::lexer::Span,
    ) {
        // Walk expressions in the statement looking for function calls
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.walk_expr_for_calls(value, caller_name, sandboxed, caller_span);
            }
            StmtKind::LetDestructure { value, .. } => {
                self.walk_expr_for_calls(value, caller_name, sandboxed, caller_span);
            }
            StmtKind::Expr { expr } => {
                self.walk_expr_for_calls(expr, caller_name, sandboxed, caller_span);
            }
            StmtKind::Return(Some(expr)) => {
                self.walk_expr_for_calls(expr, caller_name, sandboxed, caller_span);
            }
            _ => {}
        }
    }

    fn walk_expr_for_calls(
        &mut self,
        expr: &Expr,
        caller_name: &str,
        sandboxed: &HashSet<String>,
        caller_span: crate::lexer::Span,
    ) {
        match &expr.kind {
            ExprKind::Call { callee, args, .. } => {
                if let ExprKind::Ident(name) = &callee.kind {
                    if sandboxed.contains(name.as_str()) {
                        self.diags.warning(
                            "W1101",
                            format!(
                                "non-sandboxed function '{}' calls sandboxed function '{}'",
                                caller_name, name
                            ),
                            expr.span,
                        );
                    }
                }
                // Also walk args
                for arg in args {
                    self.walk_expr_for_calls(&arg.value, caller_name, sandboxed, caller_span);
                }
            }
            ExprKind::Block(block) => {
                self.check_stmts_for_calls(&block.stmts, caller_name, sandboxed, caller_span);
            }
            _ => {}
        }
    }
}

// ── Runtime sandbox enforcement (G8 §8) ─────────────────────────────────────
//
// The compile-time pass above validates the syscall allow-list. The runtime
// half — actually installing a kernel-enforced filter — is implemented below
// as a real, self-contained seccomp-BPF installer (`install_seccomp_filter`,
// built on `libc` + `prctl` with no extra system dependency).
//
// IMPORTANT: this hook is currently UNWIRED — nothing in the compiler,
// interpreter, or runtime invokes it (the only callers are its own tests).
// It is an opt-in enforcement point: a runtime that hosts sandboxed units of
// work must call `install_seccomp_filter` (in a forked child) before running
// them. Until a backend wires it in, `@sandbox` / `@sandboxed` enforcement is
// check-time analysis only.

/// A syscall allow-list policy, mirroring what the compile-time pass validates
/// on `@sandbox` / `@sandboxed` (allow + `deny_default`). Syscall names are the
/// canonical libseccomp / `seccomp_export_bpf(3)` names (e.g. `"read"`,
/// `"write"`, `"execve"`).
#[derive(Debug, Clone)]
pub struct SeccompPolicy {
    /// Syscall names allowed when `deny_default` is `true` (deny-by-default
    /// allow-list). Empty + `deny_default: true` = deny everything.
    pub allowed: Vec<String>,
    /// When `true`, the default action is `SECCOMP_RET_ERRNO|EPERM` and only
    /// `allowed` syscalls pass; when `false`, the default action is `ALLOW`
    /// (permissive).
    pub deny_default: bool,
}

impl SeccompPolicy {
    /// Default deny-everything baseline (only what libseccomp implicitly
    /// permits — `exit`, `rt_sigreturn` — survives).
    pub fn deny_all() -> Self {
        SeccompPolicy { allowed: Vec::new(), deny_default: true }
    }
}

/// Install a real seccomp-BPF filter for the current process (Linux).
///
/// **Runtime enforcement hook (G8 §8).** This is the activation point that
/// turns the compile-time-validated `@sandbox` / `@sandboxed` policy into a
/// kernel-enforced filter. It is implemented here with `libc` directly
/// (`prctl(PR_SET_NO_NEW_PRIVS)` then `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`
/// with a minimal cBPF program), so no extra Cargo dependency is required on
/// Linux. A codegen backend calls this before running a sandboxed unit of work.
///
/// ## How the filter is built
/// - `prctl(PR_SET_NO_NEW_PRIVS, 1)` first — mandatory so the process cannot
///   gain privileges and cannot be traced by a privileged parent.
/// - A cBPF program (see [`build_seccomp_program`]) is loaded. It checks the
///   `seccomp_data.arch` field (kills on mismatch) and, for deny-by-default
///   policies, only lets the allow-listed syscalls pass; everything else gets
///   `SECCOMP_RET_ERRNO|EPERM`. `exit`, `exit_group` and `rt_sigreturn` are
///   always allowed so the process can never lock itself out of a clean exit.
/// - Permissive policies (`deny_default: false`) install an allow-all filter.
///
/// ## Why `libc` and not `nix` / `libseccomp`
/// `nix` 0.31 (the version pulled in transitively by `ctrlc`) no longer ships a
/// `sys::seccomp` (or `sys::landlock`) module, and it is not a direct dependency.
/// `libc` is a direct dependency, so the filter is built with raw `libc`. The
/// higher-level alternative is **`libseccomp`** (via the `seccompiler` or
/// `libseccomp-sys` crates, which link the system `libseccomp` library): its
/// `SeccompAction::Errno(EPERM)` / `Allow` rules and `export_bpf()` produce the
/// same cBPF `sock_fprog`, installed identically via `prctl`.
///
/// ## Landlock alternative (filesystem-only confinement, Linux >= 5.13)
/// Landlock restricts filesystem access rather than syscalls and can coexist
/// with the syscall filter. It is not wired here (the `nix` version in the
/// lockfile has no `sys::landlock` module either); to add it, link a crate that
/// exposes the three raw calls:
///
/// ```text
/// landlock_create_ruleset(handled = FS_READ_FILE|FS_READ_DIR|FS_EXECUTE, flags = 0) -> fd
/// landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, {path: read-only-root, allowed_access})
/// landlock_restrict_self(fd, 0)   // drops privileges permanently
/// ```
///
/// ## Operational notes
/// - Installing a filter is **irreversible** for the current thread/process; a
///   misconfigured allow-list can lock the process out of `exit`. Prefer
///   installing it in a forked child (via a `clone`/`fork` gate) right before
///   the sandboxed unit of work runs.
/// - Returns `Err` if `prctl` fails (e.g. the kernel has no seccomp or the
///   process could not drop privileges), so a caller never silently *believes*
///   sandboxing is active when it is not.
/// - Compile-time validation in `SandboxPass` remains fully intact and
///   unchanged.
pub fn install_seccomp_filter(policy: &SeccompPolicy) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("install_seccomp_filter: seccomp is Linux-only".to_string());
    }
    install_seccomp_linux(policy)
}

/// Build the classic BPF (cBPF) instruction list implementing `policy`.
///
/// Standard seccomp filter preamble:
///   LD arch  -> JEQ <AUDIT_ARCH> (skip on match) -> RET KILL_PROCESS (mismatch)
///   LD nr    -> for each allowed syscall: JEQ nr => RET ALLOW ; else default action
///
/// When `deny_default` is `true` the default action is `SECCOMP_RET_ERRNO|EPERM`
/// and only the allow-listed syscalls pass; `exit`, `exit_group` and
/// `rt_sigreturn` are always permitted. When `false` the default action is
/// `ALLOW` (permissive — nothing is blocked).
#[cfg(target_os = "linux")]
pub(crate) fn build_seccomp_program(policy: &SeccompPolicy) -> Result<Vec<libc::sock_filter>, String> {
    const BPF_LD_W_ABS: u16 = 0x20; // LD + W + ABS
    const BPF_JMP_JEQ_K: u16 = 0x15; // JMP + JEQ + K
    const BPF_RET: u16 = 0x06; // RET
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const OFF_ARCH: u32 = 4; // offsetof(struct seccomp_data, arch)
    const OFF_NR: u32 = 0; // offsetof(struct seccomp_data, nr)

    let arch: u32 = if cfg!(target_arch = "x86_64") {
        0xc000_003e // AUDIT_ARCH_X86_64
    } else if cfg!(target_arch = "aarch64") {
        0xc000_00b7 // AUDIT_ARCH_AARCH64
    } else {
        return Err(
            "install_seccomp_filter: unsupported target architecture (only x86_64/aarch64)"
                .to_string(),
        );
    };

    // Resolve the allow-list names to syscall numbers.
    let mut allow: HashSet<i32> = HashSet::new();
    for name in &policy.allowed {
        if let Some(n) = syscall_number(name) {
            allow.insert(n);
        }
    }
    if policy.deny_default {
        // Always permit process teardown so a bad policy can't lock us out.
        for name in ["exit", "exit_group", "rt_sigreturn"] {
            if let Some(n) = syscall_number(name) {
                allow.insert(n);
            }
        }
    }

    let mut prog: Vec<libc::sock_filter> = Vec::new();
    // [0] load arch, [1] jeq arch (skip kill on match), [2] kill on mismatch.
    prog.push(libc::sock_filter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: OFF_ARCH,
    });
    prog.push(libc::sock_filter {
        code: BPF_JMP_JEQ_K,
        jt: 1,
        jf: 0,
        k: arch,
    });
    prog.push(libc::sock_filter {
        code: BPF_RET,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });

    if policy.deny_default {
        prog.push(libc::sock_filter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: OFF_NR,
        });
        // Each allow-list entry: if nr == N, fall through to ALLOW; else skip it.
        for n in allow {
            prog.push(libc::sock_filter {
                code: BPF_JMP_JEQ_K,
                jt: 0,
                jf: 1,
                k: n as u32,
            });
            prog.push(libc::sock_filter {
                code: BPF_RET,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            });
        }
        prog.push(libc::sock_filter {
            code: BPF_RET,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | (libc::EPERM as u32),
        });
    } else {
        // Permissive: allow everything.
        prog.push(libc::sock_filter {
            code: BPF_RET,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        });
    }
    Ok(prog)
}

/// Install the seccomp-BPF filter built by [`build_seccomp_program`] via
/// `prctl(PR_SET_NO_NEW_PRIVS)` then `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`.
/// Irreversible for the current process once it succeeds.
#[cfg(target_os = "linux")]
fn install_seccomp_linux(policy: &SeccompPolicy) -> Result<(), String> {
    const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
    const PR_SET_SECCOMP: libc::c_int = 22;
    const SECCOMP_MODE_FILTER: libc::c_int = 2;

    // A process must be free of new privileges before it may install a filter.
    // SAFETY: prctl with a fixed option code and integer args — no pointers.
    let r = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if r != 0 {
        return Err(format!(
            "install_seccomp_filter: prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let prog = build_seccomp_program(policy)?;
    let mut fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: fprog points at a live, contiguous buffer of `prog.len()` filters
    // that lives for the whole prctl call.
    let r = unsafe {
        libc::prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER as libc::c_ulong,
            &mut fprog as *mut libc::sock_fprog as libc::c_ulong,
            0,
            0,
        )
    };
    if r != 0 {
        return Err(format!(
            "install_seccomp_filter: prctl(PR_SET_SECCOMP) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Map a canonical syscall name to its `libc::SYS_*` number on Linux.
///
/// Legacy syscalls that only exist on 32-bit/`x86_64` ABI (`open`, `stat`,
/// `fstat`, `dup2`, `accept`, `access`, `pipe`) are gated to `x86_64`; on
/// `aarch64` those names resolve to `None` (that ABI uses `openat`/`*at`
/// variants), which is the expected behaviour — they are simply not allow-listed.
#[cfg(target_os = "linux")]
fn syscall_number(name: &str) -> Option<i32> {
    use libc::*;
    Some(match name {
        "read" => SYS_read as i32,
        "write" => SYS_write as i32,
        "close" => SYS_close as i32,
        "openat" => SYS_openat as i32,
        "mmap" => SYS_mmap as i32,
        "munmap" => SYS_munmap as i32,
        "mprotect" => SYS_mprotect as i32,
        "brk" => SYS_brk as i32,
        "exit" => SYS_exit as i32,
        "exit_group" => SYS_exit_group as i32,
        "rt_sigreturn" => SYS_rt_sigreturn as i32,
        "futex" => SYS_futex as i32,
        "clock_gettime" => SYS_clock_gettime as i32,
        "getrandom" => SYS_getrandom as i32,
        "ioctl" => SYS_ioctl as i32,
        "fcntl" => SYS_fcntl as i32,
        "lseek" => SYS_lseek as i32,
        "dup" => SYS_dup as i32,
        "socket" => SYS_socket as i32,
        "connect" => SYS_connect as i32,
        "bind" => SYS_bind as i32,
        "listen" => SYS_listen as i32,
        "sendto" => SYS_sendto as i32,
        "recvfrom" => SYS_recvfrom as i32,
        "epoll_create1" => SYS_epoll_create1 as i32,
        "epoll_ctl" => SYS_epoll_ctl as i32,
        #[cfg(target_arch = "x86_64")]
        "epoll_wait" => SYS_epoll_wait as i32,
        #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
        "epoll_pwait" => SYS_epoll_pwait as i32,
        #[cfg(target_arch = "x86_64")]
        "open" => SYS_open as i32,
        #[cfg(target_arch = "x86_64")]
        "stat" => SYS_stat as i32,
        #[cfg(target_arch = "x86_64")]
        "fstat" => SYS_fstat as i32,
        #[cfg(target_arch = "x86_64")]
        "dup2" => SYS_dup2 as i32,
        #[cfg(target_arch = "x86_64")]
        "accept" => SYS_accept as i32,
        #[cfg(target_arch = "x86_64")]
        "access" => SYS_access as i32,
        #[cfg(target_arch = "x86_64")]
        "pipe" => SYS_pipe as i32,
        // ── Common runtime syscalls (additive; arch-gated where the ABI differs) ──
        "pipe2" => SYS_pipe2 as i32,
        "clone" => SYS_clone as i32,
        "execve" => SYS_execve as i32,
        "readv" => SYS_readv as i32,
        "writev" => SYS_writev as i32,
        "sendmsg" => SYS_sendmsg as i32,
        "recvmsg" => SYS_recvmsg as i32,
        "sendto" => SYS_sendto as i32,
        "recvfrom" => SYS_recvfrom as i32,
        "shutdown" => SYS_shutdown as i32,
        "getsockopt" => SYS_getsockopt as i32,
        "setsockopt" => SYS_setsockopt as i32,
        "getsockname" => SYS_getsockname as i32,
        "getpeername" => SYS_getpeername as i32,
        "getpid" => SYS_getpid as i32,
        "gettid" => SYS_gettid as i32,
        "nanosleep" => SYS_nanosleep as i32,
        "clock_nanosleep" => SYS_clock_nanosleep as i32,
        "restart_syscall" => SYS_restart_syscall as i32,
        "set_robust_list" => SYS_set_robust_list as i32,
        "prlimit64" => SYS_prlimit64 as i32,
        "uname" => SYS_uname as i32,
        "rt_sigaction" => SYS_rt_sigaction as i32,
        "rt_sigprocmask" => SYS_rt_sigprocmask as i32,
        "tgkill" => SYS_tgkill as i32,
        // aarch64 uses newfstatat / faccessat / openat (no stat/fstat/open/access).
        #[cfg(target_arch = "aarch64")]
        "newfstatat" => SYS_newfstatat as i32,
        #[cfg(target_arch = "aarch64")]
        "fstatat" => SYS_newfstatat as i32,
        #[cfg(target_arch = "x86_64")]
        "newfstatat" => SYS_newfstatat as i32,
        #[cfg(target_arch = "x86_64")]
        "fstat" => SYS_fstat as i32,
        #[cfg(target_arch = "x86_64")]
        "statx" => SYS_statx as i32,
        #[cfg(target_arch = "x86_64")]
        "faccessat" => SYS_faccessat as i32,
        #[cfg(target_arch = "x86_64")]
        "arch_prctl" => SYS_arch_prctl as i32,
        #[cfg(target_arch = "x86_64")]
        "set_tid_address" => SYS_set_tid_address as i32,
        #[cfg(target_arch = "x86_64")]
        "epoll_pwait" => SYS_epoll_pwait as i32,
        "accept4" => SYS_accept4 as i32,
        _ => return None,
    })
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_and_check(src: &str) -> Diagnostics {
        let (tokens, _) = crate::lexer::tokenize(src);
        let program = crate::parser::Parser::parse(tokens).expect("parse failed");
        SandboxPass::new(&program).check()
    }

    #[test]
    fn test_sandbox_valid_syscalls_accepted() {
        let src = r#"
@sandbox(allow: [.read, .write, .open, .close, .mmap, .brk, .exit, .exit_group, .rt_sigreturn, .futex], deny_default: true)
fn safe_fn() {
    let x = 1
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "valid syscalls should not produce errors");
        assert_eq!(diags.warning_count(), 0, "with deny_default: true should have no warnings");
    }

    #[test]
    fn test_sandbox_realistic_network_syscalls_resolve() {
        // The runtime allow-list for a sandboxed fetch function must resolve
        // common networking + process syscalls on both x86_64 and aarch64.
        // Regression: these previously returned None (-> silently dropped from
        // the allow set), so a legitimately-allowlisted function got EPERM.
        for name in [
            "pipe2", "clone", "execve", "readv", "writev", "sendmsg", "recvmsg",
            "getsockopt", "setsockopt", "getsockname", "getpeername", "getpid",
            "nanosleep", "clock_nanosleep", "restart_syscall", "set_robust_list",
            "prlimit64", "uname", "rt_sigaction", "rt_sigprocmask", "tgkill",
            "accept4",
        ] {
            assert!(syscall_number(name).is_some(), "syscall '{name}' should resolve");
        }
        // Stat-family: aarch64 resolves newfstatat; x86_64 additionally fstat/statx.
        assert!(syscall_number("newfstatat").is_some(), "newfstatat should resolve");
        #[cfg(target_arch = "x86_64")]
        assert!(syscall_number("fstat").is_some());
        #[cfg(target_arch = "x86_64")]
        assert!(syscall_number("statx").is_some());
    }

    #[test]
    fn test_sandbox_build_program_deny_default() {
        #[cfg(target_os = "linux")]
        {
            let pol = SeccompPolicy {
                allowed: vec![
                    "read".to_string(), "write".to_string(), "close".to_string(),
                    "openat".to_string(), "pipe2".to_string(), "sendmsg".to_string(),
                    "recvmsg".to_string(), "getsockopt".to_string(), "setsockopt".to_string(),
                    "connect".to_string(), "sendto".to_string(), "recvfrom".to_string(),
                    "getpid".to_string(), "mmap".to_string(), "exit".to_string(),
                    "exit_group".to_string(), "rt_sigreturn".to_string(), "futex".to_string(),
                ],
                deny_default: true,
            };
            let prog = build_seccomp_program(&pol);
            assert!(prog.is_ok(), "building a deny-default program should succeed");
            // The program must have the arch-check preamble + syscall allow rows.
            let p = prog.unwrap();
            assert!(p.len() > 3, "a deny-default policy produces >3 BPF instructions");
        }
    }

    #[test]
    fn test_sandbox_unknown_syscall_e1100() {
        let src = r#"
@sandbox(allow: [.read, .invalid_syscall, .write], deny_default: true)
fn bad_fn() {
    let x = 1
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 1);
        let err = &diags.items[0];
        assert_eq!(err.code, "E1100");
        assert!(err.msg.contains("invalid_syscall"));
    }

    #[test]
    fn test_sandbox_deny_default_false_warning_w1100() {
        let src = r#"
@sandbox(allow: [.read], deny_default: false)
fn permissive_fn() {
    let x = 1
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0);
        let warnings: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W1100")
            .collect();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].msg.contains("permissive"));
    }

    #[test]
    fn test_sandbox_missing_deny_default_warning_w1100() {
        let src = r#"
@sandbox(allow: [.read, .write])
fn no_deny_fn() {
    let x = 1
}
"#;
        let diags = parse_and_check(src);
        let warnings: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W1100")
            .collect();
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn test_sandbox_caller_not_sandboxed_w1101() {
        let src = r#"
@sandbox(allow: [.read], deny_default: true)
fn sandboxed_read() {
    let x = 1
}

fn caller() {
    sandboxed_read()
}
"#;
        let diags = parse_and_check(src);
        let warnings: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W1101")
            .collect();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].msg.contains("caller"));
        assert!(warnings[0].msg.contains("sandboxed_read"));
    }

    #[test]
    fn test_sandbox_duplicate_e1101() {
        let src = r#"
@sandbox(allow: [.read], deny_default: true)
@sandbox(allow: [.write], deny_default: true)
fn double_sandbox() {
    let x = 1
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E1101")
            .collect();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].msg.contains("duplicate"));
    }

    // ── Phase 42: @sandboxed tests ──────────────────────────────────────

    #[test]
    fn test_sandboxed_disallowed_syscall_e2500() {
        let src = r#"
@sandboxed(allow: [.read, .write])
fn restricted_fn() {
    exec("ls")
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2500")
            .collect();
        assert_eq!(errors.len(), 1, "exec is not in allow list");
        assert!(errors[0].msg.contains("exec"));
        assert!(errors[0].msg.contains("restricted_fn"));
    }

    #[test]
    fn test_sandboxed_allowed_syscall_no_error() {
        let src = r#"
@sandboxed(allow: [.read, .write, .socket])
fn network_fn() {
    socket()
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2500")
            .collect();
        assert_eq!(errors.len(), 0, "socket is in allow list, no E2500");
    }

    #[test]
    fn test_sandboxed_no_whitelist_w2500() {
        let src = r#"
@sandboxed()
fn bare_sandboxed() {
    let x = 1
}
"#;
        let diags = parse_and_check(src);
        let warnings: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W2500")
            .collect();
        assert_eq!(warnings.len(), 1, "no syscall whitelist should warn");
        assert!(warnings[0].msg.contains("no syscall whitelist"));
    }

    #[test]
    fn test_sandboxed_multiple_disallowed_e2500() {
        let src = r#"
@sandboxed(allow: [.read])
fn multi_bad() {
    exec("cmd")
    fork()
    kill()
}
"#;
        let diags = parse_and_check(src);
        let errors: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "E2500")
            .collect();
        assert_eq!(errors.len(), 3, "exec, fork, kill all disallowed");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_program_shape() {
        // Deny-by-default policy: arch preamble + per-syscall allow rules + ERRNO tail.
        let p = SeccompPolicy {
            allowed: vec!["read".into(), "write".into()],
            deny_default: true,
        };
        let prog = build_seccomp_program(&p).unwrap();
        // preamble[3] + LD nr[1] + 2*5 allowed (read,write + exit,exit_group,rt_sigreturn) + tail[1]
        assert_eq!(prog.len(), 3 + 1 + 10 + 1);
        assert_eq!(prog[0].code, 0x20, "first insn loads seccomp_data.arch");
        assert_eq!(prog[1].code, 0x15, "second insn JEQs the arch");
        assert_eq!(prog[2].code, 0x06, "third insn RETs (kill on arch mismatch)");
        let tail = prog.last().unwrap();
        assert_eq!(tail.code, 0x06);
        assert_eq!(tail.k, 0x0005_0000 | (libc::EPERM as u32), "default is ERRNO|EPERM");

        // Permissive policy: preamble + RET ALLOW only.
        let p2 = SeccompPolicy {
            allowed: vec![],
            deny_default: false,
        };
        let prog2 = build_seccomp_program(&p2).unwrap();
        assert_eq!(prog2.len(), 4);
        assert_eq!(prog2[3].code, 0x06);
        assert_eq!(prog2[3].k, 0x7fff_0000, "permissive default is ALLOW");
    }
}
