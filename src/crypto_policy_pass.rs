//! Crypto policy validation compiler pass (Phase 45).
//!
//! Validates cryptographic algorithm usage against project policy:
//! - E2700: Deprecated algorithm used (classical when PQC required)
//! - W2700: Classical algorithm used during PQC transition period
//!
//! Also provides `is_quantum_safe()` helper and `tallow crypto-inventory` support.

use std::collections::HashSet;

use crate::ast::*;
use crate::error::{Diagnostic, Diagnostics};

// ── Known algorithm classifications ─────────────────────────────────────────

/// Classical algorithms that are NOT quantum-safe.
const CLASSICAL_ALGORITHMS: &[&str] = &[
    "rsa", "rsa_2048", "rsa_4096",
    "ecdsa", "ecdsa_p256", "ecdsa_p384",
    "ed25519", "x25519", "curve25519",
    "dh", "diffie_hellman",
    "aes_128", // AES-128 has reduced quantum security (Grover's)
    "sha1", "md5",
    "dsa",
];

/// Post-quantum-safe algorithms.
const PQC_ALGORITHMS: &[&str] = &[
    "ml_kem_768", "ml_kem_1024", "ml_kem_512",
    "ml_dsa", "ml_dsa_44", "ml_dsa_65", "ml_dsa_87",
    "slh_dsa", "sphincs",
    "falcon", "falcon_512", "falcon_1024",
    "frodokem", "frodo",
    "mceliece", "classic_mceliece",
    "kyber", "kyber_768", "kyber_1024",
    "dilithium",
];

/// Algorithms that are quantum-safe (symmetric with sufficient key size, or PQC).
const QUANTUM_SAFE_SYMMETRIC: &[&str] = &[
    "aes_256", "aes_256_gcm", "aes_gcm",
    "chacha20", "chacha20_poly1305", "chacha20poly1305", "xchacha20",
    "blake3", "blake2b", "blake2s",
    "sha3_256", "sha3_512", "sha256", "sha2_256", "sha2_512", "sha512",
    "argon2", "argon2id", "bcrypt", "scrypt",
    "hkdf",
];

/// Returns true if the given algorithm name is quantum-safe.
pub fn is_quantum_safe(algo: &str) -> bool {
    let normalized = algo.to_lowercase().replace('-', "_").replace(' ', "_");
    let n = normalized.as_str();
    PQC_ALGORITHMS.iter().any(|a| n.contains(a))
        || QUANTUM_SAFE_SYMMETRIC.iter().any(|a| n.contains(a))
        || n == "hybrid"
}

/// Returns true if the given algorithm name is a known classical (non-quantum-safe) algorithm.
pub fn is_classical(algo: &str) -> bool {
    let normalized = algo.to_lowercase().replace('-', "_").replace(' ', "_");
    let n = normalized.as_str();
    CLASSICAL_ALGORITHMS.iter().any(|a| n.contains(a))
}

// ── Crypto inventory ────────────────────────────────────────────────────────

/// An entry in the crypto inventory.
#[derive(Debug, Clone)]
pub struct CryptoUsage {
    pub algorithm: String,
    pub location: String, // "function_name" or "file:line"
    pub quantum_safe: bool,
    pub category: String, // "encryption", "signing", "hashing", "key_exchange"
}

/// Scan a program and return all crypto algorithm usages found.
pub fn crypto_inventory(program: &Program) -> Vec<CryptoUsage> {
    let mut usages = Vec::new();

    for item in &program.items {
        match item {
            Item::Fn(f) => {
                collect_crypto_usages_in_fn(f, &mut usages);
            }
            Item::Impl(imp) => {
                for m in &imp.methods {
                    collect_crypto_usages_in_fn(m, &mut usages);
                }
            }
            _ => {}
        }
    }

    usages
}

fn collect_crypto_usages_in_fn(f: &FnDecl, usages: &mut Vec<CryptoUsage>) {
    for stmt in &f.body.stmts {
        collect_crypto_usages_in_stmt(stmt, &f.name, usages);
    }
}

fn collect_crypto_usages_in_stmt(stmt: &Stmt, fn_name: &str, usages: &mut Vec<CryptoUsage>) {
    match &stmt.kind {
        StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
            collect_crypto_usages_in_expr(value, fn_name, usages);
        }
        StmtKind::Expr { expr } => {
            collect_crypto_usages_in_expr(expr, fn_name, usages);
        }
        StmtKind::Return(Some(expr)) => {
            collect_crypto_usages_in_expr(expr, fn_name, usages);
        }
        StmtKind::For { iter, body, .. } => {
            collect_crypto_usages_in_expr(iter, fn_name, usages);
            for s in &body.stmts {
                collect_crypto_usages_in_stmt(s, fn_name, usages);
            }
        }
        StmtKind::While { condition, body } => {
            collect_crypto_usages_in_expr(condition, fn_name, usages);
            for s in &body.stmts {
                collect_crypto_usages_in_stmt(s, fn_name, usages);
            }
        }
        _ => {}
    }
}

fn collect_crypto_usages_in_expr(expr: &Expr, fn_name: &str, usages: &mut Vec<CryptoUsage>) {
    match &expr.kind {
        ExprKind::MethodCall { object, method, args } => {
            // Check for .encrypt(algo: ...) / .hash(algo: ...) / .sign(...) patterns
            let algo_methods = ["encrypt", "decrypt", "hash", "sign", "verify"];
            if algo_methods.contains(&method.as_str()) {
                // Check named args for algo specification
                for arg in args {
                    if let ExprKind::DotIdent(algo_name) = &arg.value.kind {
                        let category = categorize_method(method);
                        usages.push(CryptoUsage {
                            algorithm: algo_name.clone(),
                            location: fn_name.to_string(),
                            quantum_safe: is_quantum_safe(algo_name),
                            category,
                        });
                    }
                    if let ExprKind::StringLit(algo_name) = &arg.value.kind {
                        let category = categorize_method(method);
                        usages.push(CryptoUsage {
                            algorithm: algo_name.clone(),
                            location: fn_name.to_string(),
                            quantum_safe: is_quantum_safe(algo_name),
                            category,
                        });
                    }
                }
                // If no algo arg, it's using default (PQC)
                if args.is_empty() || !args.iter().any(|a| {
                    matches!(&a.value.kind, ExprKind::DotIdent(_) | ExprKind::StringLit(_))
                }) {
                    let category = categorize_method(method);
                    usages.push(CryptoUsage {
                        algorithm: default_algo_for_method(method).to_string(),
                        location: fn_name.to_string(),
                        quantum_safe: true,
                        category,
                    });
                }
            }
            collect_crypto_usages_in_expr(object, fn_name, usages);
            for arg in args {
                collect_crypto_usages_in_expr(&arg.value, fn_name, usages);
            }
        }
        ExprKind::Call { callee, args } => {
            // Check for KeyPair.generate(algo: ...), crypto.hash(...), etc.
            if let ExprKind::FieldAccess { object, field } = &callee.kind {
                if let ExprKind::Ident(module) = &object.kind {
                    if module == "KeyPair" || module == "crypto" {
                        for arg in args {
                            if let ExprKind::DotIdent(algo_name) = &arg.value.kind {
                                let category = if field.contains("sign") {
                                    "signing"
                                } else if field.contains("hash") {
                                    "hashing"
                                } else {
                                    "key_exchange"
                                };
                                usages.push(CryptoUsage {
                                    algorithm: algo_name.clone(),
                                    location: fn_name.to_string(),
                                    quantum_safe: is_quantum_safe(algo_name),
                                    category: category.to_string(),
                                });
                            }
                        }
                    }
                }
            }
            if let ExprKind::Ident(_) = &callee.kind {
                collect_crypto_usages_in_expr(callee, fn_name, usages);
            }
            for arg in args {
                collect_crypto_usages_in_expr(&arg.value, fn_name, usages);
            }
        }
        ExprKind::Binary { left, right, .. } => {
            collect_crypto_usages_in_expr(left, fn_name, usages);
            collect_crypto_usages_in_expr(right, fn_name, usages);
        }
        ExprKind::Block(block) => {
            for s in &block.stmts {
                collect_crypto_usages_in_stmt(s, fn_name, usages);
            }
        }
        ExprKind::If { condition, then_block, else_branch, .. } => {
            collect_crypto_usages_in_expr(condition, fn_name, usages);
            for s in &then_block.stmts {
                collect_crypto_usages_in_stmt(s, fn_name, usages);
            }
            if let Some(eb) = else_branch {
                match eb {
                    ElseBranch::ElseIf(expr) => collect_crypto_usages_in_expr(expr, fn_name, usages),
                    ElseBranch::Block(block) => {
                        for s in &block.stmts {
                            collect_crypto_usages_in_stmt(s, fn_name, usages);
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

fn categorize_method(method: &str) -> String {
    match method {
        "encrypt" | "decrypt" => "encryption".to_string(),
        "hash" => "hashing".to_string(),
        "sign" | "verify" => "signing".to_string(),
        _ => "other".to_string(),
    }
}

fn default_algo_for_method(method: &str) -> &'static str {
    match method {
        "encrypt" | "decrypt" => "ml_kem_768",
        "hash" => "blake3",
        "sign" | "verify" => "ml_dsa",
        _ => "unknown",
    }
}

// ── Policy levels ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum CryptoPolicy {
    /// Only PQC algorithms allowed; classical is an error.
    PqcRequired,
    /// PQC preferred; classical generates a warning (transition period).
    PqcPreferred,
    /// No restrictions.
    Unrestricted,
}

impl CryptoPolicy {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "pqc_required" | "pqc-required" | "required" => CryptoPolicy::PqcRequired,
            "pqc_preferred" | "pqc-preferred" | "preferred" | "transition" => {
                CryptoPolicy::PqcPreferred
            }
            _ => CryptoPolicy::Unrestricted,
        }
    }
}

// ── Compiler Pass ───────────────────────────────────────────────────────────

pub struct CryptoPolicyPass<'a> {
    program: &'a Program,
    pub diags: Diagnostics,
    policy: CryptoPolicy,
    /// Algorithms referenced in the program.
    found_algos: HashSet<String>,
}

impl<'a> CryptoPolicyPass<'a> {
    pub fn new(program: &'a Program, policy: CryptoPolicy) -> Self {
        Self {
            program,
            diags: Diagnostics::new(),
            policy,
            found_algos: HashSet::new(),
        }
    }

    /// Run the crypto policy pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
        if self.policy == CryptoPolicy::Unrestricted {
            return self.diags;
        }

        for item in &self.program.items {
            match item {
                Item::Fn(f) => self.check_fn(f),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        self.check_fn(m);
                    }
                }
                _ => {}
            }
        }

        self.diags
    }

    fn check_fn(&mut self, f: &FnDecl) {
        for stmt in &f.body.stmts {
            self.check_stmt(stmt, &f.name);
        }
    }

    fn check_stmt(&mut self, stmt: &Stmt, fn_name: &str) {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.check_expr(value, fn_name);
            }
            StmtKind::Expr { expr } => {
                self.check_expr(expr, fn_name);
            }
            StmtKind::Return(Some(expr)) => {
                self.check_expr(expr, fn_name);
            }
            StmtKind::For { iter, body, .. } => {
                self.check_expr(iter, fn_name);
                for s in &body.stmts {
                    self.check_stmt(s, fn_name);
                }
            }
            StmtKind::While { condition, body } => {
                self.check_expr(condition, fn_name);
                for s in &body.stmts {
                    self.check_stmt(s, fn_name);
                }
            }
            _ => {}
        }
    }

    fn check_expr(&mut self, expr: &Expr, fn_name: &str) {
        match &expr.kind {
            ExprKind::MethodCall { object, method, args } => {
                let algo_methods = ["encrypt", "decrypt", "hash", "sign", "verify"];
                if algo_methods.contains(&method.as_str()) {
                    for arg in args {
                        if let ExprKind::DotIdent(algo_name) = &arg.value.kind {
                            self.validate_algorithm(algo_name, expr.span, fn_name);
                        }
                        if let ExprKind::StringLit(algo_name) = &arg.value.kind {
                            self.validate_algorithm(algo_name, expr.span, fn_name);
                        }
                    }
                }
                self.check_expr(object, fn_name);
                for arg in args {
                    self.check_expr(&arg.value, fn_name);
                }
            }
            ExprKind::Call { callee, args } => {
                // Check for KeyPair.generate(algo: .ed25519) etc.
                if let ExprKind::FieldAccess { object, field: _ } = &callee.kind {
                    if let ExprKind::Ident(module) = &object.kind {
                        if module == "KeyPair" || module == "crypto" {
                            for arg in args {
                                if let ExprKind::DotIdent(algo_name) = &arg.value.kind {
                                    self.validate_algorithm(algo_name, expr.span, fn_name);
                                }
                            }
                        }
                    }
                }
                for arg in args {
                    self.check_expr(&arg.value, fn_name);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.check_expr(left, fn_name);
                self.check_expr(right, fn_name);
            }
            ExprKind::Block(block) => {
                for s in &block.stmts {
                    self.check_stmt(s, fn_name);
                }
            }
            ExprKind::If { condition, then_block, else_branch, .. } => {
                self.check_expr(condition, fn_name);
                for s in &then_block.stmts {
                    self.check_stmt(s, fn_name);
                }
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::ElseIf(expr) => self.check_expr(expr, fn_name),
                        ElseBranch::Block(block) => {
                            for s in &block.stmts {
                                self.check_stmt(s, fn_name);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn validate_algorithm(&mut self, algo: &str, span: crate::lexer::Span, fn_name: &str) {
        if !self.found_algos.insert(format!("{fn_name}:{algo}")) {
            return; // already reported for this algo in this function
        }

        if is_classical(algo) {
            match self.policy {
                CryptoPolicy::PqcRequired => {
                    self.diags.push(
                        Diagnostic::error(
                            "E2700",
                            format!(
                                "deprecated classical algorithm `{algo}` in `{fn_name}` — project crypto policy requires PQC"
                            ),
                            span,
                        )
                        .with_help(format!(
                            "Project crypto policy (`CryptoPolicy::PqcRequired`) forbids the classical \
                             algorithm `{algo}`. Replace it in `{fn_name}` with a NIST PQC standard \
                             (e.g. `ml_kem_768`, `ml_dsa_65`, or a hybrid scheme)."
                        )),
                    );
                }
                CryptoPolicy::PqcPreferred => {
                    self.diags.warning(
                        "W2700",
                        format!(
                            "classical algorithm `{algo}` in `{fn_name}` — consider migrating to PQC equivalent"
                        ),
                        span,
                    );
                }
                CryptoPolicy::Unrestricted => {}
            }
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_quantum_safe() {
        assert!(is_quantum_safe("ml_kem_768"));
        assert!(is_quantum_safe("ML-KEM-768"));
        assert!(is_quantum_safe("aes_256_gcm"));
        assert!(is_quantum_safe("blake3"));
        assert!(is_quantum_safe("argon2id"));
        assert!(is_quantum_safe("hybrid"));

        assert!(!is_quantum_safe("ed25519"));
        assert!(!is_quantum_safe("rsa"));
        assert!(!is_quantum_safe("ecdsa"));
        assert!(!is_quantum_safe("x25519"));
    }

    #[test]
    fn test_is_classical() {
        assert!(is_classical("ed25519"));
        assert!(is_classical("rsa_2048"));
        assert!(is_classical("ecdsa_p256"));
        assert!(is_classical("x25519"));
        assert!(is_classical("md5"));

        assert!(!is_classical("ml_kem_768"));
        assert!(!is_classical("aes_256"));
        assert!(!is_classical("blake3"));
    }

    #[test]
    fn test_crypto_policy_pass_deprecated_algo() {
        use crate::lexer;
        use crate::parser::Parser;

        let source = r#"
fn main() {
    let kp = KeyPair.generate(algo: .ed25519)
    let data = "hello"
    let sig = data.sign(algo: .ed25519)
}
"#;
        let (tokens, lex_errors) = lexer::tokenize(source);
        assert!(lex_errors.is_empty());
        let program = Parser::parse(tokens).unwrap();

        // PQC required → should get E2700 errors
        let pass = CryptoPolicyPass::new(&program, CryptoPolicy::PqcRequired);
        let diags = pass.check();
        let errors: Vec<_> = diags
            .items
            .iter()
            .filter(|d| d.code == "E2700")
            .collect();
        assert!(
            !errors.is_empty(),
            "expected E2700 errors for classical ed25519 under PqcRequired policy"
        );

        // PQC preferred → should get W2700 warnings
        let (tokens2, _) = lexer::tokenize(source);
        let program2 = Parser::parse(tokens2).unwrap();
        let pass2 = CryptoPolicyPass::new(&program2, CryptoPolicy::PqcPreferred);
        let diags2 = pass2.check();
        let warnings: Vec<_> = diags2
            .items
            .iter()
            .filter(|d| d.code == "W2700")
            .collect();
        assert!(
            !warnings.is_empty(),
            "expected W2700 warnings for classical ed25519 under PqcPreferred policy"
        );

        // Unrestricted → no diagnostics
        let (tokens3, _) = lexer::tokenize(source);
        let program3 = Parser::parse(tokens3).unwrap();
        let pass3 = CryptoPolicyPass::new(&program3, CryptoPolicy::Unrestricted);
        let diags3 = pass3.check();
        assert!(
            diags3.items.is_empty(),
            "expected no diagnostics under Unrestricted policy"
        );
    }

    #[test]
    fn test_crypto_policy_pqc_algo_no_errors() {
        use crate::lexer;
        use crate::parser::Parser;

        let source = r#"
fn main() {
    let kp = KeyPair.generate(algo: .ml_kem_768)
    let data = "hello"
    let sealed = data.encrypt(algo: .ml_kem_768)
}
"#;
        let (tokens, lex_errors) = lexer::tokenize(source);
        assert!(lex_errors.is_empty());
        let program = Parser::parse(tokens).unwrap();

        let pass = CryptoPolicyPass::new(&program, CryptoPolicy::PqcRequired);
        let diags = pass.check();
        assert!(
            diags.items.is_empty(),
            "PQC algorithms should not trigger errors under PqcRequired: {:?}",
            diags.items.iter().map(|d| &d.msg).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_crypto_inventory_basic() {
        use crate::lexer;
        use crate::parser::Parser;

        let source = r#"
fn main() {
    let data = "hello"
    let sealed = data.encrypt(algo: .aes_256_gcm)
    let h = data.hash()
}
"#;
        let (tokens, lex_errors) = lexer::tokenize(source);
        assert!(lex_errors.is_empty());
        let program = Parser::parse(tokens).unwrap();

        let inventory = crypto_inventory(&program);
        assert!(
            !inventory.is_empty(),
            "expected crypto inventory entries"
        );
        // Should find aes_256_gcm and default hash algorithm
        let algos: Vec<&str> = inventory.iter().map(|u| u.algorithm.as_str()).collect();
        assert!(algos.contains(&"aes_256_gcm"), "expected aes_256_gcm in inventory, got: {:?}", algos);
    }
}
