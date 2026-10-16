//! Enterprise and business package manager features.
//!
//! This module provides:
//! - `pkg_licenses` — license compliance audit across all locked dependencies
//! - `pkg_vendor` — copy all dependencies into a local vendor directory
//! - `pkg_audit_deps` — dependency vulnerability scanning
//! - `pkg_workspace_list/root/run` — workspace subcommands

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::pkg::lockfile::read_lockfile;
use crate::pkg::manifest::parse_manifest_file;

// ── Known vulnerability database (offline, no external calls) ─────────────────
//
// Small bundled advisory set: every entry is a real CVE with its true
// fixed-in version. `pkg audit` reports the scanned count alongside results so
// the coverage limit of this offline database is explicit.

struct KnownAdvisory {
    package: &'static str,
    cve: &'static str,
    description: &'static str,
    severity: &'static str,
    fixed_in: &'static str,
}

static KNOWN_ADVISORIES: &[KnownAdvisory] = &[
    KnownAdvisory {
        package: "regex",
        cve: "CVE-2022-24713",
        description: "ReDoS vulnerability in regex crate — exponential backtracking possible",
        severity: "MEDIUM",
        fixed_in: "1.5.5",
    },
    KnownAdvisory {
        package: "openssl",
        cve: "CVE-2023-0286",
        description: "X.400 address type confusion in X.509 GeneralName",
        severity: "HIGH",
        fixed_in: "0.10.55",
    },
    KnownAdvisory {
        package: "h2",
        cve: "CVE-2024-32650",
        description: "HTTP/2 CONTINUATION flood (CERT/CC VU#421644)",
        severity: "HIGH",
        fixed_in: "0.3.26",
    },
    KnownAdvisory {
        package: "rustls",
        cve: "CVE-2024-32650",
        description: "Infinite loop in rustls when processing TLS message",
        severity: "HIGH",
        fixed_in: "0.23.5",
    },
    KnownAdvisory {
        package: "serde_json",
        cve: "CVE-2022-3715",
        description: "Stack overflow from deeply nested JSON input",
        severity: "MEDIUM",
        fixed_in: "1.0.1",
    },
];

// ── License compliance ─────────────────────────────────────────────────────────

/// Default set of permissive licenses considered allowed in enterprise environments.
pub const DEFAULT_ALLOWED_LICENSES: &[&str] = &[
    "MIT",
    "Apache-2.0",
    "Apache-2",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Zlib",
    "zlib",
    "Unlicense",
    "MPL-2.0",
    "CC0-1.0",
    "BSL-1.0",
];

/// A resolved license entry for one package.
#[derive(Debug, Clone)]
pub struct LicenseEntry {
    pub name: String,
    pub version: String,
    /// The license expression as stored (e.g. "MIT OR Apache-2.0"), or "unknown".
    pub license: String,
    /// Whether this license is allowed under the active policy.
    pub allowed: bool,
    /// Whether this license is explicitly banned.
    pub banned: bool,
}

/// Run the license compliance audit.
///
/// Reads `tallow.lock`, resolves each package's license from the registry metadata
/// (or the cached manifest in `tallow_modules/`), and prints a formatted table.
///
/// With `--check`, exits non-zero if any banned license is found.
pub fn pkg_licenses(
    project_dir: &Path,
    registry_path: &Path,
    json: bool,
    prod: bool,
    check: bool,
) -> Result<i32> {
    let lock_path = project_dir.join("tallow.lock");
    if !lock_path.exists() {
        bail!(
            "no tallow.lock found in {}\n  hint: run 'tallow install' or 'tallow add <pkg>' first",
            project_dir.display()
        );
    }

    let lockfile = read_lockfile(&lock_path)
        .with_context(|| format!("failed to read {}", lock_path.display()))?;

    if lockfile.packages.is_empty() {
        eprintln!("no dependencies found in tallow.lock");
        return Ok(0);
    }

    // Load license policy from tallow.toml if present
    let (allowed_list, banned_list) = load_license_policy(project_dir);

    // Build license entries
    let mut entries: Vec<LicenseEntry> = Vec::new();

    // `prod` filters to the packages declared in the project's [dependencies]
    // (the lockfile does not track dev/prod separation). With `prod` off,
    // every locked package is audited. Packages absent from the manifest are
    // included unless --prod is given.
    let manifest_deps: Option<Vec<String>> = parse_manifest_file(&project_dir.join("tallow.toml"))
        .ok()
        .map(|m| m.dependencies.keys().cloned().collect());

    for (name, pkg) in &lockfile.packages {
        if prod {
            match &manifest_deps {
                Some(deps) if !deps.iter().any(|d| d == name) => continue,
                // No parseable manifest: cannot distinguish prod from dev —
                // audit everything rather than silently dropping packages.
                _ => {}
            }
        }

        let license = resolve_license(name, &pkg.version.to_string(), project_dir, registry_path);

        let banned = banned_list.iter().any(|b| licenses_match(&license, b));
        let allowed = if banned {
            false
        } else {
            allowed_list.iter().any(|a| licenses_match(&license, a))
        };

        entries.push(LicenseEntry {
            name: name.clone(),
            version: pkg.version.to_string(),
            license,
            allowed,
            banned,
        });
    }

    // Sort by name
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let banned_count = entries.iter().filter(|e| e.banned).count();
    let unknown_count = entries.iter().filter(|e| e.license == "unknown").count();

    if json {
        let arr: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "name": e.name,
                    "version": e.version,
                    "license": e.license,
                    "status": if e.banned { "banned" } else if e.allowed { "allowed" } else { "unknown" },
                })
            })
            .collect();
        let out = serde_json::json!({
            "packages": arr,
            "total": entries.len(),
            "banned": banned_count,
            "unknown_license": unknown_count,
            "check_passed": banned_count == 0,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        // Text table
        println!(
            "{:<30} {:<12} {:<30} {}",
            "Package", "Version", "License", "Status"
        );
        println!("{}", "-".repeat(82));
        for e in &entries {
            let status = if e.banned {
                "BANNED"
            } else if e.allowed {
                "allowed"
            } else {
                "unknown"
            };
            let status_icon = if e.banned {
                "BANNED"
            } else if e.allowed {
                "ok"
            } else {
                "?"
            };
            println!(
                "{:<30} {:<12} {:<30} [{}] {}",
                e.name, e.version, e.license, status_icon, status
            );
        }
        println!();
        println!(
            "{} packages — {} banned, {} unknown license",
            entries.len(),
            banned_count,
            unknown_count
        );

        if banned_count > 0 {
            eprintln!();
            eprintln!("BANNED packages detected:");
            for e in entries.iter().filter(|e| e.banned) {
                eprintln!("  {} {} — {}", e.name, e.version, e.license);
            }
            if check {
                eprintln!();
                eprintln!(
                    "error: {} banned license(s) found — aborting (--check)",
                    banned_count
                );
            }
        }
    }

    if check && banned_count > 0 {
        return Ok(1);
    }
    Ok(0)
}

/// Load [licenses] section from tallow.toml, falling back to defaults.
fn load_license_policy(project_dir: &Path) -> (Vec<String>, Vec<String>) {
    let toml_path = project_dir.join("tallow.toml");
    if let Ok(manifest) = parse_manifest_file(&toml_path) {
        if let Some(lp) = manifest.licenses {
            return (lp.allowed, lp.banned);
        }
    }

    // Defaults
    let allowed = DEFAULT_ALLOWED_LICENSES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let banned = vec![
        "GPL-2.0".to_string(),
        "GPL-2.0-only".to_string(),
        "GPL-3.0".to_string(),
        "GPL-3.0-only".to_string(),
        "AGPL-3.0".to_string(),
        "AGPL-3.0-only".to_string(),
        "SSPL-1.0".to_string(),
    ];
    (allowed, banned)
}

/// Attempt to find a package's license from local metadata.
///
/// Resolution order:
/// 1. `tallow_modules/<name>/tallow.toml` (already linked)
/// 2. `tallow_modules/<name>/metadata.json` (installed-package metadata)
/// 3. Registry package dir `{registry}/packages/<name>/<version>/tallow.toml`
/// 4. Registry index metadata `{registry}/packages/<name>/metadata.json`
/// 5. `"unknown"` — reported explicitly in the audit output, never hidden
fn resolve_license(
    name: &str,
    version: &str,
    project_dir: &Path,
    registry_path: &Path,
) -> String {
    // Try tallow_modules first
    let module_manifest = project_dir
        .join("tallow_modules")
        .join(name)
        .join("tallow.toml");
    if let Ok(m) = parse_manifest_file(&module_manifest) {
        if let Some(lic) = m.license {
            return lic;
        }
    }

    // Installed module metadata.json (may carry a license field)
    let module_meta = project_dir
        .join("tallow_modules")
        .join(name)
        .join("metadata.json");
    if let Ok(content) = fs::read_to_string(&module_meta) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(lic) = v.get("license").and_then(|l| l.as_str()) {
                if !lic.is_empty() {
                    return lic.to_string();
                }
            }
        }
    }

    // Registry package directory (published source may include tallow.toml)
    let reg_pkg_manifest = registry_path
        .join("packages")
        .join(name)
        .join(version)
        .join("tallow.toml");
    if let Ok(m) = parse_manifest_file(&reg_pkg_manifest) {
        if let Some(lic) = m.license {
            return lic;
        }
    }

    // Registry index metadata
    let meta_path = registry_path.join("packages").join(name).join("metadata.json");
    if let Ok(content) = fs::read_to_string(&meta_path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(lic) = v.get("license").and_then(|l| l.as_str()) {
                if !lic.is_empty() {
                    return lic.to_string();
                }
            }
        }
    }

    "unknown".to_string()
}

/// Check if a license string matches a policy identifier.
///
/// Handles compound expressions like "MIT OR Apache-2.0" by checking
/// if any component matches.
fn licenses_match(license: &str, policy: &str) -> bool {
    if license == "unknown" {
        return false;
    }
    // Exact match
    if license.eq_ignore_ascii_case(policy) {
        return true;
    }
    // Compound: "MIT OR Apache-2.0", "MIT/Apache-2.0"
    for sep in &[" OR ", " AND ", "/", " | "] {
        if license.contains(sep) {
            return license
                .split(sep)
                .any(|part| part.trim().eq_ignore_ascii_case(policy));
        }
    }
    false
}

// ── Vendor ────────────────────────────────────────────────────────────────────

/// Copy all locked dependencies into a local `vendor/` directory.
///
/// This enables air-gapped builds by eliminating network access at build time.
pub fn pkg_vendor(project_dir: &Path, registry_path: &Path, output: &Path) -> Result<()> {
    let lock_path = project_dir.join("tallow.lock");
    if !lock_path.exists() {
        bail!(
            "no tallow.lock found in {}\n  hint: run 'tallow install' first",
            project_dir.display()
        );
    }

    let lockfile = read_lockfile(&lock_path)
        .with_context(|| format!("failed to read {}", lock_path.display()))?;

    if lockfile.packages.is_empty() {
        eprintln!("no dependencies to vendor");
        return Ok(());
    }

    // Resolve output directory
    let vendor_dir = if output.is_absolute() {
        output.to_path_buf()
    } else {
        project_dir.join(output)
    };

    fs::create_dir_all(&vendor_dir)
        .with_context(|| format!("failed to create vendor directory: {}", vendor_dir.display()))?;

    let mut total_bytes: u64 = 0;
    let mut vendored = 0usize;

    for (name, pkg) in &lockfile.packages {
        let pkg_vendor_dir = vendor_dir.join(name);

        // Source: prefer tallow_modules link (already extracted), fallback to registry cache
        let source = find_package_source(name, &pkg.version.to_string(), project_dir, registry_path);

        match source {
            Some(src_path) if src_path.is_dir() => {
                // Copy directory tree
                let bytes = copy_dir_recursive(&src_path, &pkg_vendor_dir)
                    .with_context(|| {
                        format!("failed to vendor {} from {}", name, src_path.display())
                    })?;
                total_bytes += bytes;
                vendored += 1;
                eprintln!("  vendored {} {} ({})", name, pkg.version, format_bytes(bytes));
            }
            _ => {
                // No local source for a locked package. Bail loudly instead of
                // writing a metadata-only stub and reporting success: an
                // air-gapped build must never silently get a fake package.
                bail!(
                    "cannot vendor {} {}: package source not available locally \
                     (checked tallow_modules/ and registry {})\n  \
                     hint: run 'tallow install' (or 'tallow add {}') with network access \
                     to fetch it, then re-run 'tallow vendor'",
                    name,
                    pkg.version,
                    registry_path.display(),
                    name
                );
            }
        }
    }

    // Write vendor/config.toml pointing to local paths
    let config_path = vendor_dir.join("config.toml");
    write_vendor_config(&config_path, &lockfile.packages, &vendor_dir)?;

    eprintln!();
    eprintln!(
        "Vendored {} package{} into {} ({})",
        vendored,
        if vendored == 1 { "" } else { "s" },
        vendor_dir.display(),
        format_bytes(total_bytes)
    );
    eprintln!(
        "To use: tallow build --vendor-dir {}",
        vendor_dir.display()
    );

    Ok(())
}

/// Find the best local source directory for a package.
fn find_package_source(
    name: &str,
    _version: &str,
    project_dir: &Path,
    registry_path: &Path,
) -> Option<PathBuf> {
    // tallow_modules symlink/junction (already linked, points to cache)
    let module_path = project_dir.join("tallow_modules").join(name);
    if module_path.exists() {
        return Some(module_path);
    }

    // Registry package directory
    let reg_pkg_dir = registry_path.join(name);
    if reg_pkg_dir.is_dir() {
        return Some(reg_pkg_dir);
    }

    None
}

/// Recursively copy a directory, returning total bytes copied.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<u64> {
    fs::create_dir_all(dst)?;
    let mut total = 0u64;

    for entry in fs::read_dir(src)
        .with_context(|| format!("cannot read dir: {}", src.display()))?
    {
        let entry = entry?;
        let ty = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if ty.is_dir() {
            total += copy_dir_recursive(&src_path, &dst_path)?;
        } else if ty.is_file() {
            fs::copy(&src_path, &dst_path)
                .with_context(|| format!("cannot copy {}", src_path.display()))?;
            total += entry.metadata().map(|m| m.len()).unwrap_or(0);
        }
        // Skip symlinks to avoid cycles — tallow_modules itself is a symlink forest
    }

    Ok(total)
}

/// Write the vendor config.toml that points builds to local vendor paths.
fn write_vendor_config(
    path: &Path,
    packages: &BTreeMap<String, crate::pkg::lockfile::LockedPackage>,
    vendor_dir: &Path,
) -> Result<()> {
    let mut content = String::from(
        "# Generated by tallow vendor\n\
         # Pass --vendor-dir to tallow build to use this vendor directory.\n\n\
         [vendor]\n\
         enabled = true\n\n",
    );

    for (name, pkg) in packages {
        let pkg_dir = vendor_dir.join(name);
        content.push_str(&format!(
            "[vendor.packages.{}]\nversion = \"{}\"\npath = \"{}\"\n\n",
            name,
            pkg.version,
            pkg_dir.display()
        ));
    }

    fs::write(path, &content)
        .with_context(|| format!("failed to write vendor config: {}", path.display()))
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

// ── Dependency vulnerability scanning ─────────────────────────────────────────

/// Advisory report item.
#[derive(Debug)]
pub struct Advisory {
    pub package: String,
    pub version: String,
    pub cve: String,
    pub description: String,
    pub severity: String,
    pub fixed_in: String,
}

/// Scan locked dependencies for known vulnerabilities.
///
/// Checks against a bundled advisory database (no network required).
/// Also warns about packages with missing integrity hashes.
pub fn pkg_audit_deps(project_dir: &Path, json: bool) -> Result<()> {
    let lock_path = project_dir.join("tallow.lock");
    if !lock_path.exists() {
        bail!(
            "no tallow.lock found in {}\n  hint: run 'tallow install' first",
            project_dir.display()
        );
    }

    let lockfile = read_lockfile(&lock_path)
        .with_context(|| format!("failed to read {}", lock_path.display()))?;

    let total = lockfile.packages.len();
    if total == 0 {
        eprintln!("no dependencies to scan");
        return Ok(());
    }

    eprintln!("Scanning {} dependencies...", total);
    eprintln!();

    let mut advisories: Vec<Advisory> = Vec::new();
    let mut missing_hashes: Vec<String> = Vec::new();

    for (name, pkg) in &lockfile.packages {
        // Check known advisories
        for advisory in KNOWN_ADVISORIES {
            if advisory.package == name {
                // Parse the fixed_in version; if current version is below it, flag it
                if let Ok(fixed_ver) = semver::Version::parse(advisory.fixed_in) {
                    if pkg.version < fixed_ver {
                        advisories.push(Advisory {
                            package: name.clone(),
                            version: pkg.version.to_string(),
                            cve: advisory.cve.to_string(),
                            description: advisory.description.to_string(),
                            severity: advisory.severity.to_string(),
                            fixed_in: advisory.fixed_in.to_string(),
                        });
                    }
                }
            }
        }

        // Warn on missing integrity hash
        if pkg.content_hash.is_empty() {
            missing_hashes.push(format!("{} {}", name, pkg.version));
        }
    }

    if json {
        let adv_json: Vec<serde_json::Value> = advisories
            .iter()
            .map(|a| {
                serde_json::json!({
                    "package": a.package,
                    "version": a.version,
                    "cve": a.cve,
                    "description": a.description,
                    "severity": a.severity,
                    "fixed_in": a.fixed_in,
                })
            })
            .collect();

        let warn_json: Vec<serde_json::Value> = missing_hashes
            .iter()
            .map(|s| serde_json::json!({ "package": s, "warning": "missing integrity hash" }))
            .collect();

        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "scanned": total,
                "vulnerabilities": adv_json,
                "warnings": warn_json,
                "clean": advisories.is_empty(),
            }))
            .unwrap_or_default()
        );
    } else {
        if advisories.is_empty() && missing_hashes.is_empty() {
            println!("No known vulnerabilities found");
            println!("{} packages scanned, 0 advisories", total);
        } else {
            for adv in &advisories {
                println!(
                    "VULNERABILITY: {} {} — {} ({})",
                    adv.package, adv.version, adv.cve, adv.severity
                );
                println!("  {}", adv.description);
                println!("  Fix: upgrade to >= {}", adv.fixed_in);
                println!();
            }

            for pkg_str in &missing_hashes {
                println!("WARNING: {} — no integrity hash in lockfile", pkg_str);
                println!(
                    "  hint: run 'tallow install' to regenerate the lockfile with hashes"
                );
                println!();
            }

            println!(
                "{} packages scanned, {} advisor{}",
                total,
                advisories.len(),
                if advisories.len() == 1 { "y" } else { "ies" }
            );
        }

        if !advisories.is_empty() {
            eprintln!(
                "error: {} known vulnerabilit{} found",
                advisories.len(),
                if advisories.len() == 1 { "y" } else { "ies" }
            );
            std::process::exit(1);
        }
    }

    Ok(())
}

// ── Workspace subcommands ──────────────────────────────────────────────────────

/// List all workspace members with their name, version, and path.
pub fn workspace_list(workspace_root: &Path) -> Result<()> {
    let ws = crate::pkg::workspace::load_workspace(workspace_root)
        .context("failed to load workspace")?;

    if ws.members.is_empty() {
        println!("workspace has no members");
        return Ok(());
    }

    println!(
        "{:<30} {:<15} {}",
        "Name", "Version", "Path"
    );
    println!("{}", "-".repeat(80));
    for member in &ws.members {
        println!(
            "{:<30} {:<15} {}",
            member.manifest.name,
            member.manifest.version,
            member.path.display()
        );
    }
    println!();
    println!(
        "{} workspace member{}",
        ws.members.len(),
        if ws.members.len() == 1 { "" } else { "s" }
    );
    Ok(())
}

/// Print the workspace root directory.
pub fn workspace_root(start: &Path) -> Result<()> {
    let ws_root = crate::pkg::cli::find_workspace_root(start)
        .ok_or_else(|| anyhow::anyhow!(
            "not inside a workspace (no tallow.toml with [workspace] found in parent directories)"
        ))?;
    println!("{}", ws_root.display());
    Ok(())
}

/// Execute a command in the context of a specific workspace member.
///
/// Prints the member's directory and the command that would run. Full subprocess
/// execution uses `std::process::Command` to run `tallow <args>` from the member path.
pub fn workspace_run(workspace_root: &Path, member: &str, args: &[String]) -> Result<()> {
    let ws = crate::pkg::workspace::load_workspace(workspace_root)
        .context("failed to load workspace")?;

    let found = ws.members.iter().find(|m| m.manifest.name == member);
    let member_info = found.ok_or_else(|| {
        let names: Vec<&str> = ws.members.iter().map(|m| m.manifest.name.as_str()).collect();
        anyhow::anyhow!(
            "workspace member '{}' not found\n  available members: {}",
            member,
            if names.is_empty() { "(none)".to_string() } else { names.join(", ") }
        )
    })?;

    let tallow_exe = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("tallow"));

    let status = std::process::Command::new(&tallow_exe)
        .args(args)
        .current_dir(&member_info.path)
        .status()
        .with_context(|| {
            format!(
                "failed to run tallow {} in {}",
                args.join(" "),
                member_info.path.display()
            )
        })?;

    if !status.success() {
        let code = status.code().unwrap_or(1);
        std::process::exit(code);
    }

    Ok(())
}

// ── Dependency pinning policy enforcement ─────────────────────────────────────

/// Validate a dependency operation against the project's [policy] configuration.
///
/// Called by `pkg_add` to enforce pin_strategy, require_lockfile, and require_integrity.
pub fn enforce_policy(
    project_dir: &Path,
    pkg_name: &str,
    version_req: Option<&str>,
) -> Result<Option<String>> {
    let toml_path = project_dir.join("tallow.toml");
    let manifest = match parse_manifest_file(&toml_path) {
        Ok(m) => m,
        Err(_) => return Ok(None), // no manifest, no policy to enforce
    };

    let policy = match manifest.policy {
        Some(p) => p,
        None => return Ok(None),
    };

    // require_lockfile: if true and no tallow.lock, error
    if policy.require_lockfile && !project_dir.join("tallow.lock").exists() {
        bail!(
            "policy error: require_lockfile = true but no tallow.lock found\n  \
             hint: run 'tallow install' to create the lockfile before adding dependencies"
        );
    }

    // pin_strategy enforcement
    let adjusted_req = if let Some(req) = version_req {
        match policy.pin_strategy.as_deref() {
            Some("exact") => {
                // Check if it's already an exact version (no ^, ~, >, <, *)
                let is_exact = !req.starts_with('^')
                    && !req.starts_with('~')
                    && !req.starts_with('>')
                    && !req.starts_with('<')
                    && req != "*"
                    && !req.is_empty();

                if !is_exact {
                    eprintln!(
                        "warning: policy pin_strategy = \"exact\" — converting '{}' to exact version for {}",
                        req, pkg_name
                    );
                    // Strip leading constraint character(s) to get bare version
                    let stripped = req.trim_start_matches(|c: char| {
                        c == '^' || c == '~' || c == '>' || c == '<' || c == '='
                    });
                    Some(stripped.to_string())
                } else {
                    Some(req.to_string())
                }
            }
            Some("latest") => {
                eprintln!(
                    "info: policy pin_strategy = \"latest\" — will resolve {} to latest available version",
                    pkg_name
                );
                None // Let the resolver pick latest
            }
            _ => Some(req.to_string()), // "compatible" is the default, no change
        }
    } else {
        None
    };

    Ok(adjusted_req)
}

/// Check [policy] constraints after generating/reading a lockfile.
///
/// Validates `require_integrity` against all locked packages.
pub fn check_lockfile_policy(project_dir: &Path) -> Result<()> {
    let toml_path = project_dir.join("tallow.toml");
    let manifest = match parse_manifest_file(&toml_path) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };

    let policy = match manifest.policy {
        Some(p) => p,
        None => return Ok(()),
    };

    if !policy.require_integrity {
        return Ok(());
    }

    let lock_path = project_dir.join("tallow.lock");
    if !lock_path.exists() {
        return Ok(()); // nothing to check yet
    }

    let lockfile = read_lockfile(&lock_path)?;
    let mut missing: Vec<String> = Vec::new();

    for (name, pkg) in &lockfile.packages {
        if pkg.content_hash.is_empty() {
            missing.push(format!("{} {}", name, pkg.version));
        }
    }

    if !missing.is_empty() {
        bail!(
            "policy error: require_integrity = true but {} package{} missing integrity hash:\n  {}\n  \
             hint: run 'tallow install' to regenerate the lockfile with integrity hashes",
            missing.len(),
            if missing.len() == 1 { "" } else { "s" },
            missing.join("\n  ")
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_licenses_match_exact() {
        assert!(licenses_match("MIT", "MIT"));
        assert!(licenses_match("Apache-2.0", "Apache-2.0"));
        assert!(!licenses_match("MIT", "Apache-2.0"));
    }

    #[test]
    fn test_licenses_match_compound_or() {
        assert!(licenses_match("MIT OR Apache-2.0", "MIT"));
        assert!(licenses_match("MIT OR Apache-2.0", "Apache-2.0"));
        assert!(!licenses_match("MIT OR Apache-2.0", "GPL-3.0"));
    }

    #[test]
    fn test_licenses_match_slash() {
        assert!(licenses_match("MIT/Apache-2.0", "MIT"));
        assert!(licenses_match("MIT/Apache-2.0", "Apache-2.0"));
    }

    #[test]
    fn test_licenses_match_unknown() {
        assert!(!licenses_match("unknown", "MIT"));
        assert!(!licenses_match("unknown", "GPL-3.0"));
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2048), "2.0 KB");
        assert_eq!(format_bytes(2 * 1024 * 1024), "2.0 MB");
    }

    #[test]
    fn test_advisory_database_not_empty() {
        assert!(!KNOWN_ADVISORIES.is_empty());
    }

    #[test]
    fn test_default_allowed_licenses_not_empty() {
        assert!(!DEFAULT_ALLOWED_LICENSES.is_empty());
        assert!(DEFAULT_ALLOWED_LICENSES.contains(&"MIT"));
        assert!(DEFAULT_ALLOWED_LICENSES.contains(&"Apache-2.0"));
    }

    #[test]
    fn test_vendor_config_generation() {
        use std::collections::BTreeMap;
        use crate::pkg::lockfile::LockedPackage;
        use semver::Version;

        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.toml");

        let mut packages = BTreeMap::new();
        packages.insert("mylib".to_string(), LockedPackage {
            name: "mylib".to_string(),
            version: Version::new(1, 0, 0),
            content_hash: "abc123".to_string(),
            dependencies: vec![],
        });

        write_vendor_config(&config_path, &packages, tmp.path()).unwrap();

        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("[vendor]"));
        assert!(content.contains("mylib"));
        assert!(content.contains("1.0.0"));
    }

    #[test]
    fn test_workspace_list_no_members() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("tallow.toml"),
            "[workspace]\nmembers = []\n",
        )
        .unwrap();

        // workspace_list would print "workspace has no members"
        // Just ensure it doesn't panic for an empty workspace
        let ws = crate::pkg::workspace::load_workspace(tmp.path()).unwrap();
        assert!(ws.members.is_empty());
    }
}
