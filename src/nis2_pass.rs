//! NIS2 Directive crypto policy compiler pass — BSI TR-02102 algorithm compliance.
//!
//! Scans crypto function calls and maps algorithms to BSI TR-02102 recommendation status.
//! - E2000: forbidden algorithm (e.g. MD5)
//! - E2001: key size below BSI minimum (name carries explicit sub-min key bits)
//! - W2000: deprecated algorithm with recommended replacement
//! - W2002: classical algorithm used where PQC alternative exists

use crate::ast::*;
use crate::error::{Diagnostic, Diagnostics};

// ── BSI TR-02102 Algorithm Status ──────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BsiStatus {
    Recommended,
    Acceptable,
    Deprecated,
    Forbidden,
}

#[derive(Debug, Clone)]
pub struct AlgorithmPolicy {
    pub name: &'static str,
    pub status: BsiStatus,
    pub min_key_bits: Option<u32>,
    pub note: &'static str,
    pub recommended_replacement: Option<&'static str>,
}

// ── BSI TR-02102 Algorithm Table ───────────────────────────────────────────

pub static BSI_TR_02102_TABLE: &[AlgorithmPolicy] = &[
    // ─── Symmetric encryption (Recommended) ────────────────────────────────
    AlgorithmPolicy {
        name: "aes_256_gcm",
        status: BsiStatus::Recommended,
        min_key_bits: Some(256),
        note: "AES-256-GCM: BSI recommended for symmetric encryption",
        recommended_replacement: None,
    },
    AlgorithmPolicy {
        name: "aes_128_gcm",
        status: BsiStatus::Recommended,
        min_key_bits: Some(128),
        note: "AES-128-GCM: BSI recommended for symmetric encryption",
        recommended_replacement: None,
    },
    AlgorithmPolicy {
        name: "aes_gcm_siv",
        status: BsiStatus::Recommended,
        min_key_bits: Some(256),
        note: "AES-GCM-SIV: nonce-misuse resistant, BSI recommended",
        recommended_replacement: None,
    },
    AlgorithmPolicy {
        name: "chacha20_poly",
        status: BsiStatus::Recommended,
        min_key_bits: Some(256),
        note: "ChaCha20-Poly1305: BSI recommended, strong alternative to AES-GCM",
        recommended_replacement: None,
    },
    AlgorithmPolicy {
        name: "xchacha20_poly",
        status: BsiStatus::Recommended,
        min_key_bits: Some(256),
        note: "XChaCha20-Poly1305: extended nonce variant, BSI recommended",
        recommended_replacement: None,
    },
    AlgorithmPolicy {
        name: "aegis_128l",
        status: BsiStatus::Recommended,
        min_key_bits: Some(128),
        note: "AEGIS-128L: high-performance AEAD, BSI recommended",
        recommended_replacement: None,
    },
    AlgorithmPolicy {
        name: "aegis_256",
        status: BsiStatus::Recommended,
        min_key_bits: Some(256),
        note: "AEGIS-256: high-performance AEAD, BSI recommended",
        recommended_replacement: None,
    },

    // ─── Hash functions (Recommended) ──────────────────────────────────────
    AlgorithmPolicy {
        name: "sha2_256",
        status: BsiStatus::Recommended,
        min_key_bits: None,
        note: "SHA-256: BSI recommended for data integrity",
        recommended_replacement: None,
    },
    AlgorithmPolicy {
        name: "sha2_384",
        status: BsiStatus::Recommended,
        min_key_bits: None,
        note: "SHA-384: BSI recommended",
        recommended_replacement: None,
    },
    AlgorithmPolicy {
        name: "sha2_512",
        status: BsiStatus::Recommended,
        min_key_bits: None,
        note: "SHA-512: BSI recommended",
        recommended_replacement: None,
    },
    AlgorithmPolicy {
        name: "sha3_256",
        status: BsiStatus::Recommended,
        min_key_bits: None,
        note: "SHA3-256: BSI recommended (Keccak)",
        recommended_replacement: None,
    },
    AlgorithmPolicy {
        name: "sha3_512",
        status: BsiStatus::Recommended,
        min_key_bits: None,
        note: "SHA3-512: BSI recommended (Keccak)",
        recommended_replacement: None,
    },
    AlgorithmPolicy {
        name: "blake3",
        status: BsiStatus::Recommended,
        min_key_bits: None,
        note: "BLAKE3: modern high-performance hash, BSI recommended",
        recommended_replacement: None,
    },

    // ─── Password hashing (Recommended) ────────────────────────────────────
    AlgorithmPolicy {
        name: "argon2id",
        status: BsiStatus::Recommended,
        min_key_bits: None,
        note: "Argon2id: BSI recommended for password hashing",
        recommended_replacement: None,
    },

    // ─── Digital signatures (Recommended) ──────────────────────────────────
    AlgorithmPolicy {
        name: "ed25519",
        status: BsiStatus::Recommended,
        min_key_bits: Some(256),
        note: "Ed25519: BSI recommended for digital signatures",
        recommended_replacement: None,
    },

    // ─── Key exchange (Recommended) ────────────────────────────────────────
    AlgorithmPolicy {
        name: "x25519",
        status: BsiStatus::Recommended,
        min_key_bits: Some(256),
        note: "X25519: BSI recommended for key exchange",
        recommended_replacement: None,
    },

    // ─── PQC algorithms (Recommended) ──────────────────────────────────────
    AlgorithmPolicy {
        name: "ml_kem_768",
        status: BsiStatus::Recommended,
        min_key_bits: None,
        note: "ML-KEM-768 (FIPS 203): NIST PQC standard, BSI recommended",
        recommended_replacement: None,
    },
    AlgorithmPolicy {
        name: "ml_dsa",
        status: BsiStatus::Recommended,
        min_key_bits: None,
        note: "ML-DSA (FIPS 204): NIST PQC signature standard, BSI recommended",
        recommended_replacement: None,
    },
    AlgorithmPolicy {
        name: "slh_dsa",
        status: BsiStatus::Recommended,
        min_key_bits: None,
        note: "SLH-DSA (FIPS 205): stateless hash-based signatures, BSI recommended",
        recommended_replacement: None,
    },
    AlgorithmPolicy {
        name: "falcon",
        status: BsiStatus::Recommended,
        min_key_bits: None,
        note: "FALCON: compact PQC signatures, BSI recommended",
        recommended_replacement: None,
    },

    // ─── KDF / Key wrapping (Recommended) ──────────────────────────────────
    AlgorithmPolicy {
        name: "hkdf",
        status: BsiStatus::Recommended,
        min_key_bits: None,
        note: "HKDF: BSI recommended key derivation function",
        recommended_replacement: None,
    },
    AlgorithmPolicy {
        name: "aes_kw",
        status: BsiStatus::Recommended,
        min_key_bits: Some(128),
        note: "AES Key Wrap (RFC 3394): BSI recommended",
        recommended_replacement: None,
    },

    // ─── MAC functions (Recommended) ───────────────────────────────────────
    AlgorithmPolicy {
        name: "kmac",
        status: BsiStatus::Recommended,
        min_key_bits: None,
        note: "KMAC: Keccak-based MAC, BSI recommended",
        recommended_replacement: None,
    },
    AlgorithmPolicy {
        name: "siphash",
        status: BsiStatus::Recommended,
        min_key_bits: Some(128),
        note: "SipHash: BSI recommended for hash table defense",
        recommended_replacement: None,
    },
    AlgorithmPolicy {
        name: "poly1305",
        status: BsiStatus::Recommended,
        min_key_bits: None,
        note: "Poly1305: BSI recommended MAC (used with ChaCha20)",
        recommended_replacement: None,
    },

    // ─── Acceptable algorithms ─────────────────────────────────────────────
    AlgorithmPolicy {
        name: "bcrypt",
        status: BsiStatus::Acceptable,
        min_key_bits: None,
        note: "bcrypt: acceptable for legacy password hashing, prefer Argon2id",
        recommended_replacement: Some("argon2id"),
    },
    AlgorithmPolicy {
        name: "scrypt",
        status: BsiStatus::Acceptable,
        min_key_bits: None,
        note: "scrypt: acceptable memory-hard KDF, prefer Argon2id",
        recommended_replacement: Some("argon2id"),
    },
    AlgorithmPolicy {
        name: "ecdsa_p256",
        status: BsiStatus::Acceptable,
        min_key_bits: Some(256),
        note: "ECDSA P-256: acceptable, prefer Ed25519 or ML-DSA",
        recommended_replacement: Some("ed25519"),
    },
    AlgorithmPolicy {
        name: "frodo_kem",
        status: BsiStatus::Acceptable,
        min_key_bits: None,
        note: "FrodoKEM: conservative PQC, acceptable pending further analysis",
        recommended_replacement: Some("ml_kem_768"),
    },
    AlgorithmPolicy {
        name: "mceliece",
        status: BsiStatus::Acceptable,
        min_key_bits: None,
        note: "Classic McEliece: conservative PQC, acceptable (large keys)",
        recommended_replacement: Some("ml_kem_768"),
    },

    // ─── Deprecated algorithms (warn) ──────────────────────────────────────
    AlgorithmPolicy {
        name: "sha1",
        status: BsiStatus::Deprecated,
        min_key_bits: None,
        note: "SHA-1: deprecated by BSI TR-02102, collision attacks practical since 2017",
        recommended_replacement: Some("sha2_256"),
    },
    AlgorithmPolicy {
        name: "triple_des",
        status: BsiStatus::Deprecated,
        min_key_bits: Some(112),
        note: "3DES: deprecated by BSI, 64-bit block size vulnerable to Sweet32 attack",
        recommended_replacement: Some("aes_256_gcm"),
    },
    AlgorithmPolicy {
        name: "rsa_2048",
        status: BsiStatus::Deprecated,
        min_key_bits: Some(2048),
        note: "RSA-2048: acceptable until 2028 per BSI, transition to PQC recommended",
        recommended_replacement: Some("ml_kem_768"),
    },
    AlgorithmPolicy {
        name: "rsa_1024",
        status: BsiStatus::Deprecated,
        min_key_bits: Some(2048),
        note: "RSA-1024: below BSI TR-02102 minimum key size, must be migrated",
        recommended_replacement: Some("ml_kem_768"),
    },

    // ─── Forbidden algorithms (error) ──────────────────────────────────────
    AlgorithmPolicy {
        name: "md5",
        status: BsiStatus::Forbidden,
        min_key_bits: None,
        note: "MD5: forbidden by BSI TR-02102, trivially broken since 2004",
        recommended_replacement: Some("sha2_256"),
    },
];

/// Look up an algorithm in the BSI TR-02102 table by name.
pub fn lookup_bsi_policy(algo_name: &str) -> Option<&'static AlgorithmPolicy> {
    BSI_TR_02102_TABLE.iter().find(|p| p.name == algo_name)
}

/// Extract the nominal key size (in bits) from an algorithm name, when the
/// name carries one. Returns `None` when the name does not encode a key size
/// (e.g. `blake3`, `aes_kw`, `siphash`) or when the embedded number is not a
/// key size (e.g. the `20` in `chacha20` is a family name, not key bits).
fn extract_key_bits(algo: &str) -> Option<u32> {
    let n = algo.to_lowercase();
    // Fixed-key-size families: the first numeric token is the key size.
    if n.starts_with("aes_") || n.starts_with("rsa_") {
        return n
            .split(['_', '-'])
            .find_map(|t| t.parse::<u32>().ok());
    }
    // AEGIS names may carry a trailing 'l' (aegis_128l → 128).
    if n.starts_with("aegis_") {
        return n
            .split(['_', '-'])
            .find_map(|t| t.trim_end_matches('l').parse::<u32>().ok());
    }
    // ECDSA curves: ecdsa_p256 → 256.
    if n.starts_with("ecdsa_p") {
        return n
            .split(['_', '-'])
            .find_map(|t| t.trim_start_matches('p').parse::<u32>().ok());
    }
    // Curve names where the embedded number is the curve size, not the key
    // size: Ed25519/X25519 keys are 256 bits (32 bytes).
    match n.as_str() {
        "ed25519" | "x25519" => Some(256),
        // ChaCha20 family: the '20' is a family/round name; keys are 256 bits.
        "chacha20" | "chacha20_poly" | "xchacha20" | "xchacha20_poly" => Some(256),
        _ => None,
    }
}

// ── Crypto method names we scan for ────────────────────────────────────────

const CRYPTO_METHODS: &[&str] = &[
    "encrypt", "decrypt", "hash", "sign", "verify", "generate",
];

/// PQC alternatives for classical symmetric/asymmetric encryption methods.
/// When a classical encryption algorithm is used for key exchange, we suggest PQC.
const CLASSICAL_ENCRYPT_WITH_PQC_ALT: &[(&str, &str)] = &[
    ("aes_256_gcm", "ml_kem_768"),
    ("aes_128_gcm", "ml_kem_768"),
    ("aes_gcm_siv", "ml_kem_768"),
    ("chacha20_poly", "ml_kem_768"),
    ("xchacha20_poly", "ml_kem_768"),
    ("x25519", "ml_kem_768"),
    ("ecdsa_p256", "ml_dsa"),
    ("ed25519", "ml_dsa"),
    ("rsa_2048", "ml_kem_768"),
];

// ── NIS2 Pass ──────────────────────────────────────────────────────────────

pub struct Nis2Pass<'a> {
    program: &'a Program,
    pub diags: Diagnostics,
}

impl<'a> Nis2Pass<'a> {
    pub fn new(program: &'a Program) -> Self {
        Self {
            program,
            diags: Diagnostics::new(),
        }
    }

    /// Run the NIS2 pass. Returns diagnostics.
    pub fn check(mut self) -> Diagnostics {
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

    /// Collect all detected crypto algorithms from a program (for audit reports).
    pub fn collect_crypto_inventory(program: &Program) -> Vec<CryptoUsage> {
        let mut usages = Vec::new();
        for item in &program.items {
            match item {
                Item::Fn(f) => Self::collect_fn_crypto(f, &mut usages),
                Item::Impl(imp) => {
                    for m in &imp.methods {
                        Self::collect_fn_crypto(m, &mut usages);
                    }
                }
                _ => {}
            }
        }
        usages
    }

    fn collect_fn_crypto(f: &FnDecl, usages: &mut Vec<CryptoUsage>) {
        for stmt in &f.body.stmts {
            Self::collect_stmt_crypto(stmt, &f.name, usages);
        }
    }

    fn collect_stmt_crypto(stmt: &Stmt, fn_name: &str, usages: &mut Vec<CryptoUsage>) {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                Self::collect_expr_crypto(value, fn_name, usages);
            }
            StmtKind::Expr { expr } => {
                Self::collect_expr_crypto(expr, fn_name, usages);
            }
            StmtKind::Return(Some(expr)) => {
                Self::collect_expr_crypto(expr, fn_name, usages);
            }
            StmtKind::For { body, iter, .. } => {
                Self::collect_expr_crypto(iter, fn_name, usages);
                for s in &body.stmts {
                    Self::collect_stmt_crypto(s, fn_name, usages);
                }
            }
            StmtKind::While { condition, body } | StmtKind::WhileLet { expr: condition, body, .. } => {
                Self::collect_expr_crypto(condition, fn_name, usages);
                for s in &body.stmts {
                    Self::collect_stmt_crypto(s, fn_name, usages);
                }
            }
            _ => {}
        }
    }

    fn collect_expr_crypto(expr: &Expr, fn_name: &str, usages: &mut Vec<CryptoUsage>) {
        match &expr.kind {
            ExprKind::MethodCall { object, method, args, .. } => {
                if CRYPTO_METHODS.contains(&method.as_str()) {
                    // Look for algo: .xxx argument
                    if let Some(algo) = Self::extract_algo_arg(args) {
                        let policy = lookup_bsi_policy(&algo);
                        usages.push(CryptoUsage {
                            function_name: fn_name.to_string(),
                            method: method.clone(),
                            algorithm: algo,
                            bsi_status: policy.map(|p| p.status),
                            note: policy.map(|p| p.note).unwrap_or(""),
                        });
                    }
                }
                Self::collect_expr_crypto(object, fn_name, usages);
                for arg in args {
                    Self::collect_expr_crypto(&arg.value, fn_name, usages);
                }
            }
            ExprKind::Call { callee, args, .. } => {
                // Check for Ident-based calls like KeyPair.generate(algo: .xxx)
                if let ExprKind::FieldAccess { field, .. } = &callee.kind {
                    if CRYPTO_METHODS.contains(&field.as_str()) {
                        if let Some(algo) = Self::extract_algo_arg(args) {
                            let policy = lookup_bsi_policy(&algo);
                            usages.push(CryptoUsage {
                                function_name: fn_name.to_string(),
                                method: field.clone(),
                                algorithm: algo,
                                bsi_status: policy.map(|p| p.status),
                                note: policy.map(|p| p.note).unwrap_or(""),
                            });
                        }
                    }
                }
                Self::collect_expr_crypto(callee, fn_name, usages);
                for arg in args {
                    Self::collect_expr_crypto(&arg.value, fn_name, usages);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                Self::collect_expr_crypto(left, fn_name, usages);
                Self::collect_expr_crypto(right, fn_name, usages);
            }
            ExprKind::Block(block) => {
                for s in &block.stmts {
                    Self::collect_stmt_crypto(s, fn_name, usages);
                }
            }
            ExprKind::If { condition, then_block, else_branch } => {
                Self::collect_expr_crypto(condition, fn_name, usages);
                for s in &then_block.stmts {
                    Self::collect_stmt_crypto(s, fn_name, usages);
                }
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::ElseIf(e) => Self::collect_expr_crypto(e, fn_name, usages),
                        ElseBranch::Block(block) => {
                            for s in &block.stmts {
                                Self::collect_stmt_crypto(s, fn_name, usages);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn check_fn(&mut self, f: &FnDecl) {
        for stmt in &f.body.stmts {
            self.check_stmt(stmt, f);
        }
    }

    fn check_stmt(&mut self, stmt: &Stmt, f: &FnDecl) {
        match &stmt.kind {
            StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
                self.check_expr(value, f);
            }
            StmtKind::Expr { expr } => {
                self.check_expr(expr, f);
            }
            StmtKind::Return(Some(expr)) => {
                self.check_expr(expr, f);
            }
            StmtKind::For { body, iter, .. } => {
                self.check_expr(iter, f);
                for s in &body.stmts {
                    self.check_stmt(s, f);
                }
            }
            StmtKind::While { condition, body } | StmtKind::WhileLet { expr: condition, body, .. } => {
                self.check_expr(condition, f);
                for s in &body.stmts {
                    self.check_stmt(s, f);
                }
            }
            _ => {}
        }
    }

    fn check_expr(&mut self, expr: &Expr, f: &FnDecl) {
        match &expr.kind {
            ExprKind::MethodCall { object, method, args, .. } => {
                if CRYPTO_METHODS.contains(&method.as_str()) {
                    self.check_crypto_call(method, args, expr.span, f);
                }
                self.check_expr(object, f);
                for arg in args {
                    self.check_expr(&arg.value, f);
                }
            }
            ExprKind::Call { callee, args, .. } => {
                // Handle KeyPair.generate(algo: .xxx) style calls
                if let ExprKind::FieldAccess { field, .. } = &callee.kind {
                    if CRYPTO_METHODS.contains(&field.as_str()) {
                        self.check_crypto_call(field, args, expr.span, f);
                    }
                }
                self.check_expr(callee, f);
                for arg in args {
                    self.check_expr(&arg.value, f);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.check_expr(left, f);
                self.check_expr(right, f);
            }
            ExprKind::Block(block) => {
                for s in &block.stmts {
                    self.check_stmt(s, f);
                }
            }
            ExprKind::If { condition, then_block, else_branch } => {
                self.check_expr(condition, f);
                for s in &then_block.stmts {
                    self.check_stmt(s, f);
                }
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::ElseIf(e) => self.check_expr(e, f),
                        ElseBranch::Block(block) => {
                            for s in &block.stmts {
                                self.check_stmt(s, f);
                            }
                        }
                    }
                }
            }
            ExprKind::Match { subject, arms } => {
                self.check_expr(subject, f);
                for arm in arms {
                    self.check_expr(&arm.body, f);
                }
            }
            _ => {}
        }
    }

    fn check_crypto_call(
        &mut self,
        method: &str,
        args: &[CallArg],
        span: crate::lexer::Span,
        _f: &FnDecl,
    ) {
        let algo = match Self::extract_algo_arg(args) {
            Some(a) => a,
            None => return, // No explicit algo arg — using defaults (which are PQC-safe)
        };

        match lookup_bsi_policy(&algo) {
            Some(policy) => {
                match policy.status {
                    BsiStatus::Forbidden => {
                        let replacement = policy
                            .recommended_replacement
                            .map(|r| format!(" Replace it with `{r}`."))
                            .unwrap_or_default();
                        self.diags.push(
                            Diagnostic::error(
                                "E2000",
                                format!(
                                    "NIS2: forbidden algorithm `{}` — {}",
                                    algo, policy.note
                                ),
                                span,
                            )
                            .with_help(format!(
                                "`{algo}` is forbidden by BSI TR-02102-1.{replacement} Remove the \
                                 call and migrate to a BSI-recommended (PQC-safe) algorithm before \
                                 this code can be deployed."
                            )),
                        );
                    }
                    BsiStatus::Deprecated => {
                        let help = if let Some(repl) = policy.recommended_replacement {
                            format!("Replace with `{}`", repl)
                        } else {
                            "Migrate to a BSI-recommended algorithm".to_string()
                        };
                        self.diags.warning(
                            "W2000",
                            format!(
                                "NIS2: deprecated algorithm `{}` — {}",
                                algo, policy.note
                            ),
                            span,
                        );
                        // Add help hint
                        if let Some(last) = self.diags.items.last_mut() {
                            last.help = Some(help);
                        }
                    }
                    BsiStatus::Acceptable | BsiStatus::Recommended => {
                        // Check W2002: classical where PQC exists
                        if method == "encrypt" || method == "generate" {
                            if let Some((_, pqc_alt)) = CLASSICAL_ENCRYPT_WITH_PQC_ALT
                                .iter()
                                .find(|(classical, _)| *classical == algo)
                            {
                                self.diags.warning(
                                    "W2002",
                                    format!(
                                        "NIS2: classical algorithm `{}` used where PQC alternative `{}` is available",
                                        algo, pqc_alt
                                    ),
                                    span,
                                );
                            }
                        }
                    }
                }

                // E2001: key size below the BSI TR-02102 minimum. Only applies
                // when the algorithm name carries an explicit key size that we
                // can compare against `min_key_bits` (e.g. rsa_1024 → 1024
                // bits vs a 2048-bit minimum).
                if let Some(min_bits) = policy.min_key_bits {
                    if let Some(key_bits) = extract_key_bits(&algo) {
                        if key_bits < min_bits {
                            self.diags.push(
                                Diagnostic::error(
                                    "E2001",
                                    format!(
                                        "NIS2: key size {key_bits} bits for `{algo}` is below the BSI TR-02102 minimum of {min_bits} bits"
                                    ),
                                    span,
                                )
                                .with_help(format!(
                                    "BSI TR-02102-1 requires at least {min_bits}-bit keys for \
                                     `{algo}`. Migrate to a larger key or a PQC algorithm \
                                     (e.g. `ml_kem_768`)."
                                )),
                            );
                        }
                    }
                }
            }
            None => {
                // Unknown algorithm — not in BSI table, no diagnostic
            }
        }
    }

    fn extract_algo_arg(args: &[CallArg]) -> Option<String> {
        // Look for named arg `algo: .xxx`
        for arg in args {
            if arg.name.as_deref() == Some("algo") {
                if let ExprKind::DotIdent(name) = &arg.value.kind {
                    return Some(name.clone());
                }
            }
        }
        // Also check positional DotIdent in case of KeyPair.generate(.ml_kem_768)
        for arg in args {
            if arg.name.is_none() {
                if let ExprKind::DotIdent(name) = &arg.value.kind {
                    return Some(name.clone());
                }
            }
        }
        None
    }
}

// ── Crypto inventory for audit reports ─────────────────────────────────────

pub struct CryptoUsage {
    pub function_name: String,
    pub method: String,
    pub algorithm: String,
    pub bsi_status: Option<BsiStatus>,
    pub note: &'static str,
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_and_check(src: &str) -> Diagnostics {
        let (tokens, _) = crate::lexer::tokenize(src);
        let program = crate::parser::Parser::parse(tokens).expect("parse failed");
        Nis2Pass::new(&program).check()
    }

    // Test 1: MD5 produces E2000 (forbidden algorithm)
    #[test]
    fn test_md5_forbidden_e2000() {
        let src = r#"
fn bad_hash(data: String) -> String {
    let h = data.hash(algo: .md5)
    h
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 1, "MD5 should produce exactly 1 error");
        let err = &diags.items[0];
        assert_eq!(err.code, "E2000");
        assert!(err.msg.contains("md5"), "error message should mention md5");
        assert!(err.msg.contains("forbidden"), "error message should say forbidden");
    }

    // Test 2: SHA-1 produces W2000 (deprecated) with recommendation
    #[test]
    fn test_sha1_deprecated_w2000() {
        let src = r#"
fn weak_hash(data: String) -> String {
    let h = data.hash(algo: .sha1)
    h
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.warning_count(), 1, "SHA-1 should produce exactly 1 warning");
        let warn = &diags.items[0];
        assert_eq!(warn.code, "W2000");
        assert!(warn.msg.contains("sha1"), "warning should mention sha1");
        assert!(warn.msg.contains("deprecated"), "warning should say deprecated");
        assert!(warn.help.as_ref().unwrap().contains("sha2_256"),
            "help should recommend sha2_256");
    }

    // Test 3: AES-256-GCM produces no warnings for hash/decrypt (recommended)
    #[test]
    fn test_aes_256_gcm_no_warnings_decrypt() {
        let src = r#"
fn good_decrypt(data: String) -> String {
    let d = data.decrypt(algo: .aes_256_gcm)
    d
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "AES-256-GCM decrypt should have no errors");
        assert_eq!(diags.warning_count(), 0, "AES-256-GCM decrypt should have no warnings");
    }

    // Test 4: ChaCha20-Poly1305 produces no warnings for decrypt (recommended)
    #[test]
    fn test_chacha20_poly_no_warnings() {
        let src = r#"
fn good_chacha(data: String) -> String {
    let d = data.decrypt(algo: .chacha20_poly)
    d
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "ChaCha20 should have no errors");
        assert_eq!(diags.warning_count(), 0, "ChaCha20 should have no warnings");
    }

    // Test 5: bcrypt produces no errors (acceptable)
    #[test]
    fn test_bcrypt_acceptable_no_error() {
        let src = r#"
fn hash_password(password: String) -> String {
    let h = password.hash(algo: .bcrypt)
    h
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "bcrypt should have no errors (acceptable)");
    }

    // Test 6: W2002 for classical encrypt where PQC exists
    #[test]
    fn test_w2002_classical_encrypt_pqc_available() {
        let src = r#"
fn classical_encrypt(data: String) -> String {
    let sealed = data.encrypt(algo: .aes_256_gcm)
    sealed
}
"#;
        let diags = parse_and_check(src);
        let w2002: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W2002")
            .collect();
        assert_eq!(w2002.len(), 1, "should produce W2002 for classical encrypt");
        assert!(w2002[0].msg.contains("aes_256_gcm"), "should mention aes_256_gcm");
        assert!(w2002[0].msg.contains("ml_kem_768"), "should mention PQC alternative");
    }

    // Test 7: BSI table has at least 20 entries
    #[test]
    fn test_bsi_table_size() {
        assert!(
            BSI_TR_02102_TABLE.len() >= 20,
            "BSI table should have at least 20 entries, got {}",
            BSI_TR_02102_TABLE.len()
        );
    }

    // Test 8: lookup 3des returns Deprecated
    #[test]
    fn test_lookup_3des_deprecated() {
        let policy = lookup_bsi_policy("triple_des");
        assert!(policy.is_some(), "3des should be in BSI table");
        assert_eq!(policy.unwrap().status, BsiStatus::Deprecated);
    }

    // Test 9: lookup ml_kem_768 returns Recommended
    #[test]
    fn test_lookup_ml_kem_768_recommended() {
        let policy = lookup_bsi_policy("ml_kem_768");
        assert!(policy.is_some(), "ml_kem_768 should be in BSI table");
        assert_eq!(policy.unwrap().status, BsiStatus::Recommended);
    }

    // Test 10: Function with no crypto calls produces no diagnostics
    #[test]
    fn test_no_crypto_no_diagnostics() {
        let src = r#"
fn add(a: i32, b: i32) -> i32 {
    a + b
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0, "no crypto = no errors");
        assert_eq!(diags.warning_count(), 0, "no crypto = no warnings");
    }

    // Additional: E2001 for key size below minimum (3DES)
    #[test]
    fn test_3des_deprecated_w2000() {
        let src = r#"
fn old_encrypt(data: String) -> String {
    let enc = data.encrypt(algo: .triple_des)
    enc
}
"#;
        let diags = parse_and_check(src);
        let w2000: Vec<_> = diags.items.iter()
            .filter(|d| d.code == "W2000")
            .collect();
        assert_eq!(w2000.len(), 1, "3DES should produce W2000 deprecated warning");
    }

    // Additional: E2001 for key size below minimum (RSA-1024 vs 2048-bit min)
    #[test]
    fn test_e2001_key_size_below_minimum() {
        let src = r#"
fn old_encrypt(data: String) -> String {
    let enc = data.encrypt(algo: .rsa_1024)
    enc
}
"#;
        let diags = parse_and_check(src);
        let e2001: Vec<_> = diags
            .items
            .iter()
            .filter(|d| d.code == "E2001")
            .collect();
        assert_eq!(
            e2001.len(),
            1,
            "rsa_1024 should produce E2001 (1024 < 2048 BSI minimum), got: {:?}",
            diags.items
        );
        assert!(
            e2001[0].msg.contains("1024") && e2001[0].msg.contains("2048"),
            "E2001 should name both key sizes, got: {}",
            e2001[0].msg
        );
    }

    #[test]
    fn test_no_e2001_when_key_size_meets_minimum() {
        let src = r#"
fn good_encrypt(data: String) -> String {
    let enc = data.encrypt(algo: .rsa_2048)
    enc
}
"#;
        let diags = parse_and_check(src);
        let e2001: Vec<_> = diags
            .items
            .iter()
            .filter(|d| d.code == "E2001")
            .collect();
        assert!(
            e2001.is_empty(),
            "rsa_2048 meets the 2048-bit minimum — no E2001 expected, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn test_extract_key_bits_helpers() {
        assert_eq!(extract_key_bits("aes_128_gcm"), Some(128));
        assert_eq!(extract_key_bits("aes_256_gcm"), Some(256));
        assert_eq!(extract_key_bits("rsa_2048"), Some(2048));
        assert_eq!(extract_key_bits("rsa_1024"), Some(1024));
        assert_eq!(extract_key_bits("aegis_128l"), Some(128));
        assert_eq!(extract_key_bits("aegis_256"), Some(256));
        assert_eq!(extract_key_bits("ecdsa_p256"), Some(256));
        assert_eq!(extract_key_bits("ed25519"), Some(256));
        assert_eq!(extract_key_bits("x25519"), Some(256));
        assert_eq!(extract_key_bits("chacha20_poly"), Some(256));
        // Names without an extractable key size
        assert_eq!(extract_key_bits("blake3"), None);
        assert_eq!(extract_key_bits("aes_kw"), None);
        assert_eq!(extract_key_bits("siphash"), None);
        assert_eq!(extract_key_bits("ml_kem_768"), None);
    }

    // Additional: Multiple algorithms in one function
    #[test]
    fn test_multiple_algorithms() {
        let src = r#"
fn mixed_crypto(data: String) -> String {
    let h = data.hash(algo: .md5)
    let s = data.hash(algo: .sha1)
    let g = data.hash(algo: .blake3)
    h
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 1, "one forbidden (MD5)");
        assert_eq!(diags.warning_count(), 1, "one deprecated (SHA-1)");
    }

    // Additional: KeyPair.generate with algo detection
    #[test]
    fn test_keypair_generate_pqc() {
        let src = r#"
fn make_keys() -> String {
    let kp = KeyPair.generate(algo: .ml_kem_768)
    "done"
}
"#;
        let diags = parse_and_check(src);
        assert_eq!(diags.error_count(), 0);
        assert_eq!(diags.warning_count(), 0, "PQC algorithm should have no warnings");
    }

    // Collect inventory
    #[test]
    fn test_collect_crypto_inventory() {
        let src = r#"
fn do_crypto(data: String) -> String {
    let h = data.hash(algo: .sha1)
    let e = data.encrypt(algo: .aes_256_gcm)
    data
}
"#;
        let (tokens, _) = crate::lexer::tokenize(src);
        let program = crate::parser::Parser::parse(tokens).expect("parse failed");
        let inventory = Nis2Pass::collect_crypto_inventory(&program);
        assert_eq!(inventory.len(), 2, "should detect 2 crypto usages");
        assert_eq!(inventory[0].algorithm, "sha1");
        assert_eq!(inventory[1].algorithm, "aes_256_gcm");
    }
}
