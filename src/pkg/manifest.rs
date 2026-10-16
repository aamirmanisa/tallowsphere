use anyhow::{Context, Result, bail};
use semver::Version;
use std::collections::HashMap;
use std::path::Path;

use crate::pkg::semver_req::{VersionReq, parse_version_req};

/// Parsed tallow.toml manifest.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub name: String,
    pub version: Version,
    pub author: Option<String>,
    pub license: Option<String>,
    pub dependencies: HashMap<String, DependencySpec>,
    /// Workspace configuration, if this is a workspace root manifest.
    pub workspace: Option<WorkspaceConfig>,
    /// License compliance policy from [licenses] section.
    pub licenses: Option<LicensePolicy>,
    /// Dependency pinning and integrity policy from [policy] section.
    pub policy: Option<PolicyConfig>,
    /// Authenticated registries from [[registries]] entries.
    pub registries: Vec<RegistryConfig>,
}

/// A single dependency specification from [dependencies].
#[derive(Debug, Clone)]
pub struct DependencySpec {
    /// Raw version requirement string as written in tallow.toml (e.g., "^1.2")
    pub version_req_raw: String,
    /// Parsed version requirement
    pub parsed: VersionReq,
    /// Optional path dependency (e.g., `foo = { path = "../foo" }`)
    pub path: Option<String>,
}

/// Workspace configuration from [workspace] section.
#[derive(Debug, Clone)]
pub struct WorkspaceConfig {
    /// Glob patterns for member packages (e.g., ["packages/*", "tools/*"])
    pub members: Vec<String>,
}

/// License compliance policy from [licenses] section.
///
/// Example tallow.toml:
/// ```toml
/// [licenses]
/// allowed = ["MIT", "Apache-2.0", "BSD-3-Clause"]
/// banned  = ["GPL-3.0", "AGPL-3.0"]
/// ```
#[derive(Debug, Clone)]
pub struct LicensePolicy {
    /// Licenses explicitly allowed (SPDX identifiers).
    pub allowed: Vec<String>,
    /// Licenses explicitly banned.
    pub banned: Vec<String>,
}

/// Dependency pinning and integrity policy from [policy] section.
///
/// Example tallow.toml:
/// ```toml
/// [policy]
/// pin_strategy      = "exact"   # "exact" | "compatible" (default) | "latest"
/// require_lockfile  = true
/// max_dependency_age = 365      # days; 0 = no limit
/// require_integrity = true
/// ```
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    /// Pin strategy: `"exact"`, `"compatible"` (default), or `"latest"`.
    pub pin_strategy: Option<String>,
    /// If `true`, operations fail when no tallow.lock exists.
    pub require_lockfile: bool,
    /// Maximum allowed dependency age in days (0 = no limit).
    pub max_dependency_age: u64,
    /// If `true`, every lockfile entry must have an integrity hash.
    pub require_integrity: bool,
}

/// Authenticated registry configuration from `[[registries]]` entries.
///
/// Example tallow.toml:
/// ```toml
/// [[registries]]
/// name = "internal"
/// url  = "https://pkg.company.com/tallow"
/// auth = "token"
/// ```
///
/// Token resolution order:
/// 1. `TALLOW_REGISTRY_TOKEN` environment variable
/// 2. `~/.tallow/credentials.toml` key matching `name`
/// 3. Error if not found
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Friendly name for this registry (used for credential lookup).
    pub name: String,
    /// Registry base URL.
    pub url: String,
    /// Authentication method: `"none"` (default), `"token"`, or `"basic"`.
    pub auth: String,
}

impl RegistryConfig {
    /// Resolve the authentication token for this registry.
    ///
    /// Checks `TALLOW_REGISTRY_TOKEN` env var first, then
    /// `~/.tallow/credentials.toml`, then returns `None` if
    /// auth is `"none"`.
    pub fn resolve_token(&self) -> Option<String> {
        if self.auth == "none" {
            return None;
        }

        // 1. Environment variable
        if let Ok(tok) = std::env::var("TALLOW_REGISTRY_TOKEN") {
            if !tok.is_empty() {
                return Some(tok);
            }
        }

        // 2. ~/.tallow/credentials.toml
        if let Some(home) = dirs::home_dir() {
            let cred_path = home.join(".tallow").join("credentials.toml");
            if let Ok(content) = std::fs::read_to_string(&cred_path) {
                if let Ok(doc) = content.parse::<toml::Table>() {
                    // Look for [registries.<name>] token = "..."
                    let token = doc
                        .get("registries")
                        .and_then(|v| v.as_table())
                        .and_then(|t| t.get(&self.name))
                        .and_then(|v| v.as_table())
                        .and_then(|t| t.get("token"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    if token.is_some() {
                        return token;
                    }
                }
            }
        }

        None
    }
}

/// Parse a tallow.toml manifest from its string content.
pub fn parse_manifest(content: &str) -> Result<Manifest> {
    let doc: toml::Table = content.parse::<toml::Table>()
        .context("failed to parse tallow.toml as TOML")?;

    // Parse [workspace] section if present
    let workspace = if let Some(ws) = doc.get("workspace").and_then(|v| v.as_table()) {
        let members = ws.get("members")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Some(WorkspaceConfig { members })
    } else {
        None
    };

    // Parse [package] section -- optional if [workspace] is present
    let package = doc.get("package").and_then(|v| v.as_table());

    if package.is_none() && workspace.is_none() {
        bail!("missing [package] section in tallow.toml");
    }

    let (name, version, author, license) = if let Some(package) = package {
        let name = package.get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing 'name' field in [package] section"))?
            .to_string();

        let version_str = package.get("version")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing 'version' field in [package] section"))?;

        let version = version_str.parse::<Version>()
            .map_err(|e| anyhow::anyhow!("invalid version '{}' in [package]: {}", version_str, e))?;

        let author = package.get("author")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let license = package.get("license")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        (name, version, author, license)
    } else {
        // Workspace-only root (no [package]): use synthetic values
        ("workspace-root".to_string(), Version::new(0, 0, 0), None, None)
    };

    // Parse [dependencies] section
    let mut dependencies = HashMap::new();
    if let Some(deps) = doc.get("dependencies").and_then(|v| v.as_table()) {
        for (pkg_name, value) in deps {
            let (version_req_raw, path) = match value {
                toml::Value::String(s) => (s.clone(), None),
                toml::Value::Table(t) => {
                    let path = t.get("path")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let ver = if let Some(v) = t.get("version").and_then(|v| v.as_str()) {
                        v.to_string()
                    } else if path.is_some() {
                        // Path dependencies don't require a version
                        "*".to_string()
                    } else {
                        bail!(
                            "dependency '{}': table form requires 'version' or 'path' field", pkg_name
                        );
                    };
                    (ver, path)
                }
                _ => bail!(
                    "dependency '{}': expected string or table, got {}",
                    pkg_name,
                    value.type_str()
                ),
            };

            let parsed = parse_version_req(&version_req_raw)
                .with_context(|| format!("dependency '{}': invalid version constraint '{}'", pkg_name, version_req_raw))?;

            dependencies.insert(pkg_name.clone(), DependencySpec {
                version_req_raw,
                parsed,
                path,
            });
        }
    }

    // Parse [licenses] section
    let licenses = if let Some(lic) = doc.get("licenses").and_then(|v| v.as_table()) {
        let allowed = lic
            .get("allowed")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let banned = lic
            .get("banned")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Some(LicensePolicy { allowed, banned })
    } else {
        None
    };

    // Parse [policy] section
    let policy = if let Some(pol) = doc.get("policy").and_then(|v| v.as_table()) {
        let pin_strategy = pol
            .get("pin_strategy")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let require_lockfile = pol
            .get("require_lockfile")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let max_dependency_age = pol
            .get("max_dependency_age")
            .and_then(|v| v.as_integer())
            .map(|i| i.max(0) as u64)
            .unwrap_or(0);

        let require_integrity = pol
            .get("require_integrity")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        Some(PolicyConfig {
            pin_strategy,
            require_lockfile,
            max_dependency_age,
            require_integrity,
        })
    } else {
        None
    };

    // Parse [[registries]] array
    let mut registries = Vec::new();
    if let Some(reg_arr) = doc.get("registries").and_then(|v| v.as_array()) {
        for entry in reg_arr {
            if let Some(t) = entry.as_table() {
                let name = t
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let url = t
                    .get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let auth = t
                    .get("auth")
                    .and_then(|v| v.as_str())
                    .unwrap_or("none")
                    .to_string();
                registries.push(RegistryConfig { name, url, auth });
            }
        }
    }

    Ok(Manifest {
        name,
        version,
        author,
        license,
        dependencies,
        workspace,
        licenses,
        policy,
        registries,
    })
}

/// Parse a tallow.toml manifest from a file path.
pub fn parse_manifest_file(path: &Path) -> Result<Manifest> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read manifest file: {}", path.display()))?;
    parse_manifest(&content)
        .with_context(|| format!("failed to parse manifest: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_manifest() {
        let toml = r#"
[package]
name = "my-app"
version = "0.1.0"
author = "Test User"
license = "MIT"

[dependencies]
"#;
        let manifest = parse_manifest(toml).unwrap();
        assert_eq!(manifest.name, "my-app");
        assert_eq!(manifest.version, Version::new(0, 1, 0));
        assert_eq!(manifest.author.as_deref(), Some("Test User"));
        assert_eq!(manifest.license.as_deref(), Some("MIT"));
        assert!(manifest.dependencies.is_empty());
        assert!(manifest.licenses.is_none());
        assert!(manifest.policy.is_none());
        assert!(manifest.registries.is_empty());
    }

    #[test]
    fn test_parse_with_dependencies() {
        let toml = r#"
[package]
name = "my-app"
version = "1.0.0"

[dependencies]
foo = "^1.2"
bar = "~0.3.0"
baz = "=2.0.0"
qux = "*"
plain = "1.5.0"
"#;
        let manifest = parse_manifest(toml).unwrap();
        assert_eq!(manifest.dependencies.len(), 5);

        let foo = &manifest.dependencies["foo"];
        assert_eq!(foo.version_req_raw, "^1.2");
        assert!(foo.parsed.matches(&Version::new(1, 9, 0)));
        assert!(!foo.parsed.matches(&Version::new(2, 0, 0)));

        let bar = &manifest.dependencies["bar"];
        assert_eq!(bar.version_req_raw, "~0.3.0");

        let baz = &manifest.dependencies["baz"];
        assert!(baz.parsed.matches(&Version::new(2, 0, 0)));
        assert!(!baz.parsed.matches(&Version::new(2, 0, 1)));

        let qux = &manifest.dependencies["qux"];
        assert!(qux.parsed.matches(&Version::new(99, 0, 0)));
    }

    #[test]
    fn test_parse_table_dependency() {
        let toml = r#"
[package]
name = "my-app"
version = "1.0.0"

[dependencies]
foo = { version = "^1.0" }
"#;
        let manifest = parse_manifest(toml).unwrap();
        assert_eq!(manifest.dependencies.len(), 1);
        let foo = &manifest.dependencies["foo"];
        assert_eq!(foo.version_req_raw, "^1.0");
    }

    #[test]
    fn test_missing_package_section() {
        let toml = r#"
[dependencies]
foo = "^1.0"
"#;
        let err = parse_manifest(toml).unwrap_err();
        assert!(err.to_string().contains("[package]"));
    }

    #[test]
    fn test_missing_name() {
        let toml = r#"
[package]
version = "1.0.0"
"#;
        let err = parse_manifest(toml).unwrap_err();
        assert!(err.to_string().contains("name"));
    }

    #[test]
    fn test_invalid_version() {
        let toml = r#"
[package]
name = "test"
version = "not.valid"
"#;
        let err = parse_manifest(toml).unwrap_err();
        assert!(err.to_string().contains("invalid version"));
    }

    #[test]
    fn test_invalid_dependency_constraint() {
        let toml = r#"
[package]
name = "test"
version = "1.0.0"

[dependencies]
foo = "^not.valid"
"#;
        let err = parse_manifest(toml).unwrap_err();
        assert!(err.to_string().contains("foo"));
    }

    #[test]
    fn test_no_dependencies_section() {
        let toml = r#"
[package]
name = "my-app"
version = "1.0.0"
"#;
        let manifest = parse_manifest(toml).unwrap();
        assert!(manifest.dependencies.is_empty());
    }

    #[test]
    fn test_empty_author_treated_as_none() {
        let toml = r#"
[package]
name = "test"
version = "1.0.0"
author = ""
"#;
        let manifest = parse_manifest(toml).unwrap();
        assert!(manifest.author.is_none());
    }

    #[test]
    fn test_parse_license_policy() {
        let toml = r#"
[package]
name = "my-app"
version = "1.0.0"

[licenses]
allowed = ["MIT", "Apache-2.0", "BSD-3-Clause"]
banned  = ["GPL-3.0", "AGPL-3.0"]
"#;
        let manifest = parse_manifest(toml).unwrap();
        let lic = manifest.licenses.unwrap();
        assert_eq!(lic.allowed, ["MIT", "Apache-2.0", "BSD-3-Clause"]);
        assert_eq!(lic.banned, ["GPL-3.0", "AGPL-3.0"]);
    }

    #[test]
    fn test_parse_policy_config() {
        let toml = r#"
[package]
name = "my-app"
version = "1.0.0"

[policy]
pin_strategy       = "exact"
require_lockfile   = true
max_dependency_age = 365
require_integrity  = true
"#;
        let manifest = parse_manifest(toml).unwrap();
        let pol = manifest.policy.unwrap();
        assert_eq!(pol.pin_strategy.as_deref(), Some("exact"));
        assert!(pol.require_lockfile);
        assert_eq!(pol.max_dependency_age, 365);
        assert!(pol.require_integrity);
    }

    #[test]
    fn test_parse_registries() {
        let toml = r#"
[package]
name = "my-app"
version = "1.0.0"

[[registries]]
name = "internal"
url  = "https://pkg.company.com/tallow"
auth = "token"

[[registries]]
name = "public"
url  = "https://github.com/aamirmanisa/tallowsphere/packages"
auth = "none"
"#;
        let manifest = parse_manifest(toml).unwrap();
        assert_eq!(manifest.registries.len(), 2);
        assert_eq!(manifest.registries[0].name, "internal");
        assert_eq!(manifest.registries[0].auth, "token");
        assert_eq!(manifest.registries[1].name, "public");
        assert_eq!(manifest.registries[1].auth, "none");
    }

    #[test]
    fn test_policy_defaults() {
        let toml = r#"
[package]
name = "my-app"
version = "1.0.0"

[policy]
"#;
        let manifest = parse_manifest(toml).unwrap();
        // Empty [policy] should parse as Some with all defaults
        let pol = manifest.policy.unwrap();
        assert!(pol.pin_strategy.is_none());
        assert!(!pol.require_lockfile);
        assert_eq!(pol.max_dependency_age, 0);
        assert!(!pol.require_integrity);
    }
}
