//! SBOM (Software Bill of Materials) generation for Tallow.
//!
//! Generates CycloneDX 1.6 JSON SBOMs from Cargo.lock and tallow.lock files.
//! Also generates SPDX 2.3 JSON for CRA compliance and CycloneDX with
//! vulnerability cross-references and VEX status.
//! Used by the `tallow sbom` and `tallow audit --cra` CLI commands.

use serde_json::{json, Value};

/// A single component in the SBOM.
#[derive(Debug, Clone, PartialEq)]
pub struct SbomComponent {
    /// Package name
    pub name: String,
    /// Package version string
    pub version: String,
    /// Package URL (PURL) — e.g. `pkg:cargo/serde@1.0.210`
    pub purl: String,
    /// SHA-256 hash (from Cargo.lock checksum or tallow.lock integrity)
    pub hash_sha256: String,
    /// Component type: "library" for dependencies, "application" for root
    pub component_type: String,
}

/// Parse a Cargo.lock file (TOML format) and extract components.
///
/// Each `[[package]]` entry becomes an `SbomComponent` with:
/// - PURL: `pkg:cargo/{name}@{version}`
/// - SHA-256 hash from the `checksum` field
/// - Component type: "library" for external deps, "application" for root package (no source)
pub fn parse_cargo_lock(content: &str) -> Vec<SbomComponent> {
    // Cargo.lock is TOML with [[package]] arrays
    let parsed: toml::Value = match toml::from_str(content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let packages = match parsed.get("package").and_then(|p| p.as_array()) {
        Some(arr) => arr,
        None => return Vec::new(),
    };

    let mut components = Vec::new();

    for pkg in packages {
        let name = match pkg.get("name").and_then(|v| v.as_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let version = match pkg.get("version").and_then(|v| v.as_str()) {
            Some(v) => v.to_string(),
            None => continue,
        };

        let checksum = pkg
            .get("checksum")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Packages without a "source" field are the root project
        let has_source = pkg.get("source").is_some();
        let component_type = if has_source { "library" } else { "application" };

        let purl = format!("pkg:cargo/{name}@{version}");

        components.push(SbomComponent {
            name,
            version,
            purl,
            hash_sha256: checksum,
            component_type: component_type.to_string(),
        });
    }

    components
}

/// Parse a tallow.lock file and extract components.
///
/// The tallow.lock format uses `[[package]]` blocks with `name`, `version`,
/// `integrity` (blake3:hash), and `dependencies` fields.
pub fn parse_tallow_lock(content: &str) -> Vec<SbomComponent> {
    // tallow.lock is a custom text format, not pure TOML
    // We reuse the existing lockfile parser logic
    let mut components = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_hash: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "[[package]]" {
            // Flush previous package
            if let (Some(name), Some(version)) = (current_name.take(), current_version.take()) {
                let hash = current_hash.take().unwrap_or_default();
                let purl = format!("pkg:tallow/{name}@{version}");
                components.push(SbomComponent {
                    name,
                    version,
                    purl,
                    hash_sha256: hash,
                    component_type: "library".to_string(),
                });
            }
            current_name = None;
            current_version = None;
            current_hash = None;
            continue;
        }

        if trimmed.starts_with('#') || trimmed.is_empty() || trimmed.starts_with("lockfile-version") {
            continue;
        }

        // Parse key = "value"
        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim();
            let value = value.trim().trim_matches('"');

            match key {
                "name" => current_name = Some(value.to_string()),
                "version" => current_version = Some(value.to_string()),
                "integrity" => {
                    let hash = value.strip_prefix("blake3:").unwrap_or(value);
                    current_hash = Some(hash.to_string());
                }
                _ => {}
            }
        }
    }

    // Flush last package
    if let (Some(name), Some(version)) = (current_name, current_version) {
        let hash = current_hash.unwrap_or_default();
        let purl = format!("pkg:tallow/{name}@{version}");
        components.push(SbomComponent {
            name,
            version,
            purl,
            hash_sha256: hash,
            component_type: "library".to_string(),
        });
    }

    components
}

/// Generate a CycloneDX 1.6 JSON SBOM from components.
///
/// Produces a valid CycloneDX 1.6 BOM with:
/// - `bomFormat`: "CycloneDX"
/// - `specVersion`: "1.6"
/// - `version`: 1
/// - `metadata.tools`: tallow tool info
/// - `metadata.component`: root project info
/// - `components`: array of dependency components
pub fn generate_cyclonedx(
    components: &[SbomComponent],
    project_name: &str,
    project_version: &str,
) -> Value {
    let tallow_version = env!("CARGO_PKG_VERSION");

    let comp_array: Vec<Value> = components
        .iter()
        .map(|c| {
            let mut comp = json!({
                "type": c.component_type,
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
            });
            if !c.hash_sha256.is_empty() {
                comp["hashes"] = json!([{
                    "alg": "SHA-256",
                    "content": c.hash_sha256,
                }]);
            }
            comp
        })
        .collect();

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "tools": [{
                "vendor": "tallow-lang",
                "name": "tallow",
                "version": tallow_version,
            }],
            "component": {
                "type": "application",
                "name": project_name,
                "version": project_version,
            },
        },
        "components": comp_array,
    })
}

// ── Vulnerability tracking ───────────────────────────────────────────────────

/// A vulnerability entry for CRA-compliant SBOMs.
#[derive(Debug, Clone, PartialEq)]
pub struct SbomVulnerability {
    /// Vulnerability ID (e.g. "CVE-2024-12345" or "RUSTSEC-2024-0001")
    pub id: String,
    /// Source database (e.g. "NVD", "RustSec")
    pub source: String,
    /// URL to the advisory
    pub url: String,
    /// Severity: "critical", "high", "medium", "low", "info", "unknown"
    pub severity: String,
    /// BOM-ref of the affected component
    pub component_ref: String,
    /// VEX analysis status: "not_affected", "affected", "under_investigation", "fixed"
    pub vex_status: String,
    /// Justification text (required when vex_status is "not_affected")
    pub justification: String,
}

/// Generate an SPDX 2.3 JSON document from SBOM components.
///
/// Produces a valid SPDX 2.3 JSON with:
/// - `spdxVersion`: "SPDX-2.3"
/// - `dataLicense`: "CC0-1.0"
/// - `SPDXID`: "SPDXRef-DOCUMENT"
/// - `documentNamespace`: unique URI with project info
/// - `creationInfo`: tool name and ISO 8601 timestamp
/// - `packages`: array with SPDXID, name, versionInfo, externalRefs, checksums
pub fn generate_spdx(
    components: &[SbomComponent],
    project_name: &str,
    project_version: &str,
) -> Value {
    let tallow_version = env!("CARGO_PKG_VERSION");

    // Build a deterministic namespace using project name + version
    let namespace_hash = {
        let input = format!("{project_name}-{project_version}-tallow-{tallow_version}");
        let hash = blake3::hash(input.as_bytes());
        let hex = hash.to_hex();
        hex[..16].to_string()
    };
    let document_namespace = format!(
        "https://github.com/aamirmanisa/tallowsphere/spdx/{project_name}/{project_version}/{namespace_hash}"
    );

    // Build ISO 8601 timestamp
    let timestamp = iso8601_now();

    // Build packages array
    let packages: Vec<Value> = components
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let spdxid = format!("SPDXRef-Package-{}", i + 1);
            let mut pkg = json!({
                "SPDXID": spdxid,
                "name": c.name,
                "versionInfo": c.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": false,
                "supplier": "NOASSERTION",
            });
            // External reference: PURL
            pkg["externalRefs"] = json!([{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": c.purl,
            }]);
            // Checksum
            if !c.hash_sha256.is_empty() {
                pkg["checksums"] = json!([{
                    "algorithm": "SHA256",
                    "checksumValue": c.hash_sha256,
                }]);
            }
            pkg
        })
        .collect();

    json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("{project_name}-{project_version}"),
        "documentNamespace": document_namespace,
        "creationInfo": {
            "created": timestamp,
            "creators": [format!("Tool: tallow-{tallow_version}")],
            "licenseListVersion": "3.22",
        },
        "packages": packages,
    })
}

/// Generate a CycloneDX 1.6 JSON SBOM with CRA metadata and vulnerability data.
///
/// Extends the standard CycloneDX output with:
/// - `vulnerabilities` array with id, source, ratings, affects, analysis (VEX status)
/// - `metadata.properties` with `cra:class` and `cra:annex_i_compliant`
pub fn generate_cyclonedx_cra(
    components: &[SbomComponent],
    vulnerabilities: &[SbomVulnerability],
    project_name: &str,
    project_version: &str,
    cra_class: &str,
) -> Value {
    // Start from the base CycloneDX
    let mut bom = generate_cyclonedx(components, project_name, project_version);

    // Add CRA metadata properties
    if let Some(metadata) = bom.get_mut("metadata") {
        metadata["properties"] = json!([
            {
                "name": "cra:class",
                "value": cra_class,
            },
            {
                "name": "cra:annex_i_compliant",
                "value": "true",
            }
        ]);
    }

    // Add vulnerabilities array
    let vuln_array: Vec<Value> = vulnerabilities
        .iter()
        .map(|v| {
            let mut vuln = json!({
                "id": v.id,
                "source": {
                    "name": v.source,
                    "url": v.url,
                },
                "ratings": [{
                    "severity": v.severity,
                }],
            });

            // Affects
            if !v.component_ref.is_empty() {
                vuln["affects"] = json!([{
                    "ref": v.component_ref,
                }]);
            }

            // VEX analysis
            vuln["analysis"] = json!({
                "state": v.vex_status,
            });
            if !v.justification.is_empty() {
                vuln["analysis"]["justification"] = json!(v.justification);
            }

            vuln
        })
        .collect();

    bom["vulnerabilities"] = json!(vuln_array);

    bom
}

/// Simple ISO 8601 timestamp (avoids chrono dependency).
fn iso8601_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = now / 86400;
    let years = 1970 + days / 365;
    let remaining_days = days % 365;
    let month = remaining_days / 30 + 1;
    let day = remaining_days % 30 + 1;
    let secs_today = now % 86400;
    let hours = secs_today / 3600;
    let minutes = (secs_today % 3600) / 60;
    let seconds = secs_today % 60;
    format!("{years:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Generate a full SBOM by reading Cargo.lock and optionally tallow.lock from a directory.
pub fn generate_sbom(
    project_dir: &std::path::Path,
    project_name: &str,
    project_version: &str,
) -> Result<Value, String> {
    let mut all_components = Vec::new();

    // Read Cargo.lock
    let cargo_lock_path = project_dir.join("Cargo.lock");
    if cargo_lock_path.exists() {
        let content = std::fs::read_to_string(&cargo_lock_path)
            .map_err(|e| format!("failed to read Cargo.lock: {e}"))?;
        all_components.extend(parse_cargo_lock(&content));
    }

    // Read tallow.lock if present
    let tallow_lock_path = project_dir.join("tallow.lock");
    if tallow_lock_path.exists() {
        let content = std::fs::read_to_string(&tallow_lock_path)
            .map_err(|e| format!("failed to read tallow.lock: {e}"))?;
        all_components.extend(parse_tallow_lock(&content));
    }

    if all_components.is_empty() {
        return Err("no Cargo.lock or tallow.lock found".to_string());
    }

    Ok(generate_cyclonedx(&all_components, project_name, project_version))
}

// ── SPDX 3.0 JSON-LD ────────────────────────────────────────────────────────

/// Generate an SPDX 3.0 JSON-LD SBOM from components.
///
/// SPDX 3.0 uses a different structure from SPDX 2.3:
/// - `spdxVersion`: "3.0"
/// - Uses `@context` for JSON-LD
/// - `spdxDocument` with `rootElement`, `element`, `creationInfo`
pub fn generate_spdx3(
    components: &[SbomComponent],
    project_name: &str,
    project_version: &str,
) -> Value {
    let tallow_version = env!("CARGO_PKG_VERSION");
    let timestamp = iso8601_now();

    // Build a deterministic document ID
    let doc_id = {
        let input = format!("spdx3-{project_name}-{project_version}-{tallow_version}");
        let hash = blake3::hash(input.as_bytes());
        let hex = hash.to_hex();
        format!("urn:spdx:tallow:{}", &hex[..16])
    };

    // Build elements array (each component is a Package element)
    let elements: Vec<Value> = components
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let spdx_id = format!("SPDXRef-Package-{}", i + 1);
            let mut element = json!({
                "@type": "Package",
                "spdxId": spdx_id,
                "name": c.name,
                "packageVersion": c.version,
                "downloadLocation": "NOASSERTION",
                "packageUrl": c.purl,
            });
            if !c.hash_sha256.is_empty() {
                element["verifiedUsing"] = json!([{
                    "@type": "Hash",
                    "algorithm": "sha256",
                    "hashValue": c.hash_sha256,
                }]);
            }
            element
        })
        .collect();

    json!({
        "@context": "https://spdx.github.io/spdx-spec/v3.0/model/jsonld-context.json",
        "spdxVersion": "3.0",
        "spdxId": doc_id,
        "creationInfo": {
            "specVersion": "3.0.0",
            "created": timestamp,
            "createdBy": [format!("Tool: tallow-{tallow_version}")],
            "profile": ["core", "software"],
        },
        "name": format!("{project_name}-{project_version}-sbom"),
        "rootElement": format!("SPDXRef-{project_name}"),
        "element": elements,
        "dataLicense": "CC0-1.0",
    })
}

// ── Cryptographic BOM (CBOM) ────────────────────────────────────────────────

/// A crypto algorithm usage entry for the CBOM.
#[derive(Debug, Clone, PartialEq)]
pub struct CryptoUsage {
    /// Algorithm name (e.g. "ML-KEM-768", "AES-256-GCM", "Argon2id")
    pub algorithm: String,
    /// Category: "key-exchange", "encryption", "signing", "hashing", "password-hashing"
    pub category: String,
    /// Whether this is a post-quantum algorithm
    pub post_quantum: bool,
    /// Source location or module where the usage was found
    pub source: String,
}

/// Scan AST import declarations and method calls for crypto algorithm usage.
///
/// Looks for:
/// - Imports of `tallow.crypto`
/// - Method calls: `.encrypt()`, `.decrypt()`, `.hash()`, `.sign()`, `.verify()`
/// - Algorithm name literals in annotation args and call args
pub fn scan_crypto_usage(program: &crate::ast::Program) -> Vec<CryptoUsage> {
    let mut usages = Vec::new();

    // Track whether crypto module is imported
    let mut has_crypto_import = false;

    for item in &program.items {
        match item {
            crate::ast::Item::Import(import) => {
                let path_str = import.path.join(".");
                if path_str.contains("crypto") {
                    has_crypto_import = true;
                }
            }
            crate::ast::Item::Fn(f) => {
                // Scan function body for crypto method calls
                scan_fn_for_crypto(&f.name, &f.body.stmts, &mut usages);

                // Scan annotations for algorithm references
                for ann in &f.annotations {
                    for arg in &ann.args {
                        scan_expr_for_algo(&f.name, &arg.value, &mut usages);
                    }
                }
            }
            _ => {}
        }
    }

    // If crypto module is imported, note the default algorithms
    if has_crypto_import {
        let defaults = [
            ("ML-KEM-768", "key-exchange", true),
            ("ML-DSA", "signing", true),
            ("BLAKE3", "hashing", false),
            ("Argon2id", "password-hashing", false),
        ];
        for (algo, cat, pqc) in &defaults {
            if !usages.iter().any(|u| u.algorithm == *algo) {
                usages.push(CryptoUsage {
                    algorithm: algo.to_string(),
                    category: cat.to_string(),
                    post_quantum: *pqc,
                    source: "tallow.crypto (import)".to_string(),
                });
            }
        }
    }

    // Deduplicate
    usages.sort_by(|a, b| a.algorithm.cmp(&b.algorithm));
    usages.dedup_by(|a, b| a.algorithm == b.algorithm && a.category == b.category);

    usages
}

/// Recursively scan statements for crypto method calls.
fn scan_fn_for_crypto(
    fn_name: &str,
    stmts: &[crate::ast::Stmt],
    usages: &mut Vec<CryptoUsage>,
) {
    for stmt in stmts {
        scan_stmt_for_crypto(fn_name, &stmt.kind, usages);
    }
}

fn scan_stmt_for_crypto(
    fn_name: &str,
    kind: &crate::ast::StmtKind,
    usages: &mut Vec<CryptoUsage>,
) {
    match kind {
        crate::ast::StmtKind::Let { value, .. } | crate::ast::StmtKind::Var { value, .. } => {
            scan_expr_for_crypto(fn_name, value, usages);
        }
        crate::ast::StmtKind::Expr { expr } => {
            scan_expr_for_crypto(fn_name, expr, usages);
        }
        crate::ast::StmtKind::Return(Some(expr)) => {
            scan_expr_for_crypto(fn_name, expr, usages);
        }
        crate::ast::StmtKind::For { iter, body, .. } => {
            scan_expr_for_crypto(fn_name, iter, usages);
            scan_fn_for_crypto(fn_name, &body.stmts, usages);
        }
        _ => {}
    }
}

fn scan_expr_for_crypto(
    fn_name: &str,
    expr: &crate::ast::Expr,
    usages: &mut Vec<CryptoUsage>,
) {
    match &expr.kind {
        crate::ast::ExprKind::MethodCall {
            object,
            method,
            args,
        } => {
            let source = format!("fn {fn_name}");
            match method.as_str() {
                "encrypt" => {
                    let algo = extract_algo_arg(args).unwrap_or("ML-KEM-768".to_string());
                    let pqc = is_pqc_algo(&algo);
                    usages.push(CryptoUsage {
                        algorithm: algo,
                        category: "encryption".to_string(),
                        post_quantum: pqc,
                        source: source.clone(),
                    });
                }
                "decrypt" => {
                    let algo = extract_algo_arg(args).unwrap_or("ML-KEM-768".to_string());
                    let pqc = is_pqc_algo(&algo);
                    usages.push(CryptoUsage {
                        algorithm: algo,
                        category: "encryption".to_string(),
                        post_quantum: pqc,
                        source: source.clone(),
                    });
                }
                "hash" => {
                    let algo = extract_algo_arg(args).unwrap_or("BLAKE3".to_string());
                    let cat = if is_password_hash(&algo) {
                        "password-hashing"
                    } else {
                        "hashing"
                    };
                    usages.push(CryptoUsage {
                        algorithm: algo,
                        category: cat.to_string(),
                        post_quantum: false,
                        source: source.clone(),
                    });
                }
                "sign" | "verify" => {
                    let algo = extract_algo_arg(args).unwrap_or("ML-DSA".to_string());
                    let pqc = is_pqc_algo(&algo);
                    usages.push(CryptoUsage {
                        algorithm: algo,
                        category: "signing".to_string(),
                        post_quantum: pqc,
                        source: source.clone(),
                    });
                }
                _ => {}
            }
            scan_expr_for_crypto(fn_name, object, usages);
            for arg in args {
                scan_expr_for_crypto(fn_name, &arg.value, usages);
            }
        }
        crate::ast::ExprKind::Call { callee, args } => {
            // Check for KeyPair.generate(), TLSConn.connect(), etc.
            if let crate::ast::ExprKind::FieldAccess { object: _, field } = &callee.kind {
                let source = format!("fn {fn_name}");
                match field.as_str() {
                    "generate" => {
                        let algo =
                            extract_algo_arg(args).unwrap_or("ML-KEM-768".to_string());
                        let pqc = is_pqc_algo(&algo);
                        usages.push(CryptoUsage {
                            algorithm: algo,
                            category: "key-exchange".to_string(),
                            post_quantum: pqc,
                            source,
                        });
                    }
                    "connect" => {
                        usages.push(CryptoUsage {
                            algorithm: "TLS-1.3-hybrid".to_string(),
                            category: "key-exchange".to_string(),
                            post_quantum: true,
                            source,
                        });
                    }
                    _ => {}
                }
            }
            scan_expr_for_crypto(fn_name, callee, usages);
            for arg in args {
                scan_expr_for_crypto(fn_name, &arg.value, usages);
            }
        }
        crate::ast::ExprKind::Block(block) => {
            scan_fn_for_crypto(fn_name, &block.stmts, usages);
        }
        crate::ast::ExprKind::If {
            condition,
            then_block,
            else_branch,
        } => {
            scan_expr_for_crypto(fn_name, condition, usages);
            scan_fn_for_crypto(fn_name, &then_block.stmts, usages);
            if let Some(eb) = else_branch {
                match eb {
                    crate::ast::ElseBranch::ElseIf(expr) => {
                        scan_expr_for_crypto(fn_name, expr, usages);
                    }
                    crate::ast::ElseBranch::Block(block) => {
                        scan_fn_for_crypto(fn_name, &block.stmts, usages);
                    }
                }
            }
        }
        crate::ast::ExprKind::Assign { target, value } => {
            scan_expr_for_crypto(fn_name, target, usages);
            scan_expr_for_crypto(fn_name, value, usages);
        }
        crate::ast::ExprKind::Try(inner) | crate::ast::ExprKind::Await(inner) => {
            scan_expr_for_crypto(fn_name, inner, usages);
        }
        _ => {}
    }
}

/// Extract the `algo` named argument from a call arg list.
fn extract_algo_arg(args: &[crate::ast::CallArg]) -> Option<String> {
    for arg in args {
        if arg.name.as_deref() == Some("algo") {
            if let crate::ast::ExprKind::DotIdent(name) = &arg.value.kind {
                return Some(normalize_algo_name(name));
            }
            if let crate::ast::ExprKind::Ident(name) = &arg.value.kind {
                return Some(normalize_algo_name(name));
            }
        }
    }
    None
}

/// Scan an expression for algorithm name references (used in annotations).
fn scan_expr_for_algo(
    fn_name: &str,
    expr: &crate::ast::Expr,
    usages: &mut Vec<CryptoUsage>,
) {
    if let crate::ast::ExprKind::DotIdent(name) = &expr.kind {
        let algo = normalize_algo_name(name);
        if is_known_algo(&algo) {
            let cat = categorize_algo(&algo);
            let pqc = is_pqc_algo(&algo);
            usages.push(CryptoUsage {
                algorithm: algo,
                category: cat.to_string(),
                post_quantum: pqc,
                source: format!("fn {fn_name} (annotation)"),
            });
        }
    }
}

fn normalize_algo_name(name: &str) -> String {
    match name {
        "ml_kem_768" => "ML-KEM-768".to_string(),
        "ml_kem_1024" => "ML-KEM-1024".to_string(),
        "ml_dsa" => "ML-DSA".to_string(),
        "aes_256_gcm" => "AES-256-GCM".to_string(),
        "aes_256" => "AES-256".to_string(),
        "chacha20_poly" | "chacha20_poly1305" => "ChaCha20-Poly1305".to_string(),
        "hybrid" => "Hybrid-X25519-ML-KEM".to_string(),
        "argon2id" => "Argon2id".to_string(),
        "bcrypt" => "bcrypt".to_string(),
        "scrypt" => "scrypt".to_string(),
        "blake3" => "BLAKE3".to_string(),
        "sha3_256" => "SHA3-256".to_string(),
        "sha2_256" => "SHA2-256".to_string(),
        "ed25519" => "Ed25519".to_string(),
        "x25519" => "X25519".to_string(),
        other => other.to_uppercase(),
    }
}

fn is_pqc_algo(algo: &str) -> bool {
    matches!(
        algo,
        "ML-KEM-768"
            | "ML-KEM-1024"
            | "ML-DSA"
            | "Hybrid-X25519-ML-KEM"
            | "TLS-1.3-hybrid"
    )
}

fn is_password_hash(algo: &str) -> bool {
    matches!(algo, "Argon2id" | "bcrypt" | "scrypt")
}

fn is_known_algo(algo: &str) -> bool {
    matches!(
        algo,
        "ML-KEM-768"
            | "ML-KEM-1024"
            | "ML-DSA"
            | "AES-256-GCM"
            | "AES-256"
            | "ChaCha20-Poly1305"
            | "Hybrid-X25519-ML-KEM"
            | "Argon2id"
            | "bcrypt"
            | "scrypt"
            | "BLAKE3"
            | "SHA3-256"
            | "SHA2-256"
            | "Ed25519"
            | "X25519"
    )
}

fn categorize_algo(algo: &str) -> &'static str {
    match algo {
        "ML-KEM-768" | "ML-KEM-1024" | "X25519" | "Hybrid-X25519-ML-KEM" => "key-exchange",
        "AES-256-GCM" | "AES-256" | "ChaCha20-Poly1305" => "encryption",
        "ML-DSA" | "Ed25519" => "signing",
        "Argon2id" | "bcrypt" | "scrypt" => "password-hashing",
        "BLAKE3" | "SHA3-256" | "SHA2-256" => "hashing",
        _ => "unknown",
    }
}

/// Generate a Cryptographic Bill of Materials (CBOM) in CycloneDX 1.5+ format.
///
/// Lists all cryptographic algorithms discovered in the Tallow program.
pub fn generate_cbom(
    crypto_usages: &[CryptoUsage],
    project_name: &str,
    project_version: &str,
) -> Value {
    let tallow_version = env!("CARGO_PKG_VERSION");

    let components: Vec<Value> = crypto_usages
        .iter()
        .enumerate()
        .map(|(i, cu)| {
            json!({
                "type": "cryptographic-asset",
                "bom-ref": format!("crypto-{}", i + 1),
                "name": cu.algorithm,
                "properties": [
                    {
                        "name": "category",
                        "value": cu.category,
                    },
                    {
                        "name": "post-quantum",
                        "value": cu.post_quantum.to_string(),
                    },
                    {
                        "name": "source",
                        "value": cu.source,
                    }
                ],
            })
        })
        .collect();

    let pqc_count = crypto_usages.iter().filter(|u| u.post_quantum).count();
    let classical_count = crypto_usages.len() - pqc_count;

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": format!("urn:tallow:cbom:{project_name}:{project_version}"),
        "metadata": {
            "tools": [{
                "vendor": "tallow-lang",
                "name": "tallow",
                "version": tallow_version,
            }],
            "component": {
                "type": "application",
                "name": project_name,
                "version": project_version,
            },
            "properties": [
                {
                    "name": "cbom:type",
                    "value": "cryptographic-bill-of-materials",
                },
                {
                    "name": "cbom:pqc_count",
                    "value": pqc_count.to_string(),
                },
                {
                    "name": "cbom:classical_count",
                    "value": classical_count.to_string(),
                }
            ],
        },
        "components": components,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CARGO_LOCK: &str = r#"
# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "adler2"
version = "2.0.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "320119579fcad9c21884f5c4861d16174d0e06250625266f50fe6898340abefa"

[[package]]
name = "aes"
version = "0.8.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "b169f7a6d4742236a0a00c541b845991d0ac43e546831af1249753ab4c3aa3a0"
dependencies = [
 "cfg-if",
 "cipher",
]

[[package]]
name = "tallow"
version = "0.2.0"
dependencies = [
 "adler2",
 "aes",
]
"#;

    const SAMPLE_TALLOW_LOCK: &str = r#"# tallow.lock — generated by tallow
# Do not edit manually.
lockfile-version = 1

[[package]]
name = "my-lib"
version = "1.2.3"
integrity = "blake3:abc123def456"
dependencies = ["other-lib"]

[[package]]
name = "other-lib"
version = "0.5.0"
integrity = "blake3:789xyz000111"
dependencies = []
"#;

    #[test]
    fn sbom_parse_cargo_lock_extracts_components() {
        let components = parse_cargo_lock(SAMPLE_CARGO_LOCK);
        // Should find 3 packages (adler2, aes, tallow root)
        assert!(
            components.len() >= 2,
            "Expected at least 2 dependency components, got {}",
            components.len()
        );
        let adler = components.iter().find(|c| c.name == "adler2").expect("adler2 not found");
        assert_eq!(adler.version, "2.0.1");
        assert_eq!(
            adler.hash_sha256,
            "320119579fcad9c21884f5c4861d16174d0e06250625266f50fe6898340abefa"
        );
    }

    #[test]
    fn sbom_cyclonedx_format() {
        let components = parse_cargo_lock(SAMPLE_CARGO_LOCK);
        let bom = generate_cyclonedx(&components, "test-project", "0.1.0");
        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert_eq!(bom["specVersion"], "1.6");
        assert!(bom["metadata"]["tools"].is_array(), "metadata.tools should be array");
        assert!(bom["components"].is_array(), "components should be array");
    }

    #[test]
    fn sbom_purl_format() {
        let components = parse_cargo_lock(SAMPLE_CARGO_LOCK);
        let adler = components.iter().find(|c| c.name == "adler2").expect("adler2 not found");
        assert_eq!(adler.purl, "pkg:cargo/adler2@2.0.1");
    }

    #[test]
    fn sbom_parse_tallow_lock_components() {
        let components = parse_tallow_lock(SAMPLE_TALLOW_LOCK);
        assert_eq!(components.len(), 2, "Expected 2 tallow packages");
        let mylib = components.iter().find(|c| c.name == "my-lib").expect("my-lib not found");
        assert_eq!(mylib.version, "1.2.3");
        assert_eq!(mylib.purl, "pkg:tallow/my-lib@1.2.3");
        assert_eq!(mylib.hash_sha256, "abc123def456");
    }

    #[test]
    fn sbom_metadata_includes_tallow_info() {
        let components = parse_cargo_lock(SAMPLE_CARGO_LOCK);
        let bom = generate_cyclonedx(&components, "test-project", "0.1.0");
        let tools = &bom["metadata"]["tools"];
        let tool = &tools[0];
        assert_eq!(tool["vendor"], "tallow-lang");
        assert_eq!(tool["name"], "tallow");
        // Root component
        let root = &bom["metadata"]["component"];
        assert_eq!(root["type"], "application");
        assert_eq!(root["name"], "test-project");
        assert_eq!(root["version"], "0.1.0");
    }

    // ── SPDX 2.3 tests ─────────────────────────────────────────────────────

    #[test]
    fn sbom_spdx_23_valid_format() {
        let components = parse_cargo_lock(SAMPLE_CARGO_LOCK);
        let spdx = generate_spdx(&components, "test-project", "1.0.0");

        assert_eq!(spdx["spdxVersion"], "SPDX-2.3");
        assert_eq!(spdx["dataLicense"], "CC0-1.0");
        assert_eq!(spdx["SPDXID"], "SPDXRef-DOCUMENT");

        // documentNamespace must be a URL string
        let ns = spdx["documentNamespace"].as_str().unwrap();
        assert!(ns.starts_with("https://github.com/aamirmanisa/tallowsphere/spdx/"), "namespace should be a URL: {ns}");
        assert!(ns.contains("test-project"), "namespace should contain project name");

        // creationInfo
        assert!(spdx["creationInfo"]["created"].is_string());
        assert!(spdx["creationInfo"]["creators"].is_array());

        // packages
        assert!(spdx["packages"].is_array());
        let pkgs = spdx["packages"].as_array().unwrap();
        assert!(pkgs.len() >= 2, "should have at least 2 packages");

        // Each package should have SPDXID, name, versionInfo, externalRefs
        let first = &pkgs[0];
        assert!(first["SPDXID"].as_str().unwrap().starts_with("SPDXRef-"));
        assert!(first["name"].is_string());
        assert!(first["versionInfo"].is_string());
        assert!(first["externalRefs"].is_array());
    }

    // ── Vulnerability / VEX tests ───────────────────────────────────────────

    #[test]
    fn sbom_vulnerability_vex_status_serializes() {
        let vuln = SbomVulnerability {
            id: "CVE-2024-99999".to_string(),
            source: "NVD".to_string(),
            url: "https://nvd.nist.gov/vuln/detail/CVE-2024-99999".to_string(),
            severity: "high".to_string(),
            component_ref: "pkg:cargo/example@1.0.0".to_string(),
            vex_status: "not_affected".to_string(),
            justification: "Component not used in vulnerable configuration".to_string(),
        };

        // Verify fields are accessible
        assert_eq!(vuln.vex_status, "not_affected");
        assert_eq!(vuln.severity, "high");

        // Test with affected status
        let vuln2 = SbomVulnerability {
            vex_status: "affected".to_string(),
            justification: String::new(),
            ..vuln.clone()
        };
        assert_eq!(vuln2.vex_status, "affected");

        // Test under_investigation
        let vuln3 = SbomVulnerability {
            vex_status: "under_investigation".to_string(),
            ..vuln
        };
        assert_eq!(vuln3.vex_status, "under_investigation");
    }

    // ── CycloneDX CRA tests ────────────────────────────────────────────────

    #[test]
    fn sbom_cyclonedx_cra_includes_vulns_and_metadata() {
        let components = parse_cargo_lock(SAMPLE_CARGO_LOCK);
        let vulns = vec![
            SbomVulnerability {
                id: "CVE-2024-12345".to_string(),
                source: "NVD".to_string(),
                url: "https://nvd.nist.gov/vuln/detail/CVE-2024-12345".to_string(),
                severity: "critical".to_string(),
                component_ref: "pkg:cargo/adler2@2.0.1".to_string(),
                vex_status: "not_affected".to_string(),
                justification: "Not reachable in this configuration".to_string(),
            },
        ];

        let bom = generate_cyclonedx_cra(
            &components, &vulns, "test-project", "0.1.0", "class_ii",
        );

        // Standard CycloneDX fields
        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert_eq!(bom["specVersion"], "1.6");

        // CRA metadata properties
        let props = bom["metadata"]["properties"].as_array().unwrap();
        let cra_class_prop = props.iter().find(|p| p["name"] == "cra:class").unwrap();
        assert_eq!(cra_class_prop["value"], "class_ii");
        let annex_prop = props.iter().find(|p| p["name"] == "cra:annex_i_compliant").unwrap();
        assert_eq!(annex_prop["value"], "true");

        // Vulnerabilities array
        let vuln_array = bom["vulnerabilities"].as_array().unwrap();
        assert_eq!(vuln_array.len(), 1);
        let v = &vuln_array[0];
        assert_eq!(v["id"], "CVE-2024-12345");
        assert_eq!(v["source"]["name"], "NVD");
        assert_eq!(v["ratings"][0]["severity"], "critical");
        assert_eq!(v["analysis"]["state"], "not_affected");
        assert_eq!(v["affects"][0]["ref"], "pkg:cargo/adler2@2.0.1");
    }

    // ── SPDX 3.0 tests ─────────────────────────────────────────────────────

    #[test]
    fn test_spdx3_output() {
        let components = parse_cargo_lock(SAMPLE_CARGO_LOCK);
        let spdx3 = generate_spdx3(&components, "test-project", "1.0.0");

        // Must have spdxVersion "3.0"
        assert_eq!(spdx3["spdxVersion"], "3.0");
        assert_eq!(spdx3["dataLicense"], "CC0-1.0");

        // JSON-LD context
        let ctx = spdx3["@context"].as_str().unwrap();
        assert!(ctx.contains("spdx"), "should have SPDX JSON-LD context");

        // creationInfo
        assert_eq!(spdx3["creationInfo"]["specVersion"], "3.0.0");
        assert!(spdx3["creationInfo"]["created"].is_string());

        // element array (packages)
        let elements = spdx3["element"].as_array().unwrap();
        assert!(elements.len() >= 2);
        assert_eq!(elements[0]["@type"], "Package");
        assert!(elements[0]["spdxId"].as_str().unwrap().starts_with("SPDXRef-"));
        assert!(elements[0]["name"].is_string());
        assert!(elements[0]["packageVersion"].is_string());
    }

    // ── CBOM tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_cbom_crypto_inventory() {
        let usages = vec![
            CryptoUsage {
                algorithm: "ML-KEM-768".to_string(),
                category: "key-exchange".to_string(),
                post_quantum: true,
                source: "fn collect".to_string(),
            },
            CryptoUsage {
                algorithm: "AES-256-GCM".to_string(),
                category: "encryption".to_string(),
                post_quantum: false,
                source: "fn encrypt_data".to_string(),
            },
            CryptoUsage {
                algorithm: "BLAKE3".to_string(),
                category: "hashing".to_string(),
                post_quantum: false,
                source: "fn hash_input".to_string(),
            },
        ];

        let cbom = generate_cbom(&usages, "test-project", "1.0.0");

        // Must have bomFormat
        assert_eq!(cbom["bomFormat"], "CycloneDX");
        assert_eq!(cbom["specVersion"], "1.5");

        // Components
        let components = cbom["components"].as_array().unwrap();
        assert_eq!(components.len(), 3);

        // First component is ML-KEM-768
        assert_eq!(components[0]["name"], "ML-KEM-768");
        assert_eq!(components[0]["type"], "cryptographic-asset");

        // PQC/classical counts in metadata
        let props = cbom["metadata"]["properties"].as_array().unwrap();
        let pqc_prop = props.iter().find(|p| p["name"] == "cbom:pqc_count").unwrap();
        assert_eq!(pqc_prop["value"], "1");
        let classical_prop = props.iter().find(|p| p["name"] == "cbom:classical_count").unwrap();
        assert_eq!(classical_prop["value"], "2");
    }

    #[test]
    fn test_cbom_empty() {
        let cbom = generate_cbom(&[], "empty-project", "0.1.0");
        assert_eq!(cbom["bomFormat"], "CycloneDX");
        let components = cbom["components"].as_array().unwrap();
        assert_eq!(components.len(), 0);
    }

    // ── Crypto scanning tests ───────────────────────────────────────────────

    #[test]
    fn test_normalize_algo_names() {
        assert_eq!(normalize_algo_name("ml_kem_768"), "ML-KEM-768");
        assert_eq!(normalize_algo_name("aes_256_gcm"), "AES-256-GCM");
        assert_eq!(normalize_algo_name("argon2id"), "Argon2id");
        assert_eq!(normalize_algo_name("ed25519"), "Ed25519");
        assert_eq!(normalize_algo_name("blake3"), "BLAKE3");
        assert_eq!(normalize_algo_name("unknown_algo"), "UNKNOWN_ALGO");
    }

    #[test]
    fn test_algo_classification() {
        assert!(is_pqc_algo("ML-KEM-768"));
        assert!(is_pqc_algo("ML-DSA"));
        assert!(!is_pqc_algo("AES-256-GCM"));
        assert!(!is_pqc_algo("Ed25519"));

        assert!(is_password_hash("Argon2id"));
        assert!(is_password_hash("bcrypt"));
        assert!(!is_password_hash("BLAKE3"));

        assert_eq!(categorize_algo("ML-KEM-768"), "key-exchange");
        assert_eq!(categorize_algo("AES-256-GCM"), "encryption");
        assert_eq!(categorize_algo("Ed25519"), "signing");
        assert_eq!(categorize_algo("Argon2id"), "password-hashing");
        assert_eq!(categorize_algo("BLAKE3"), "hashing");
    }
}
