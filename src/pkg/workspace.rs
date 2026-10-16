use anyhow::{Context, Result};
use semver::Version;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::pkg::lockfile::{generate_lockfile, Lockfile};
use crate::pkg::manifest::{parse_manifest_file, Manifest};
use crate::pkg::resolver::{PackageRegistry, resolve_dependencies};
use crate::pkg::semver_req::VersionReq;

/// A member of a workspace.
#[derive(Debug, Clone)]
pub struct WorkspaceMember {
    /// Path to the member package directory.
    pub path: PathBuf,
    /// Parsed manifest of the member.
    pub manifest: Manifest,
}

/// A complete workspace with root and members.
#[derive(Debug, Clone)]
pub struct Workspace {
    /// Path to the workspace root directory.
    pub root: PathBuf,
    /// Root manifest (may be workspace-only or also a package).
    pub root_manifest: Manifest,
    /// All discovered member packages.
    pub members: Vec<WorkspaceMember>,
}

/// Discover member package directories by expanding glob patterns.
///
/// Supports simple `*` wildcard matching against directory names.
/// E.g., `"packages/*"` matches all subdirectories of `packages/`.
pub fn discover_members(root: &Path, patterns: &[String]) -> Result<Vec<PathBuf>> {
    let mut results = Vec::new();

    for pattern in patterns {
        // Split pattern into parent dir and glob part
        let parts: Vec<&str> = pattern.split('/').collect();

        if parts.len() == 1 && parts[0] == "*" {
            // "*" matches all subdirectories of root
            add_member_dirs(root, &mut results)?;
        } else if parts.len() == 2 && parts[1] == "*" {
            // "dir/*" matches all subdirectories of root/dir
            let parent = root.join(parts[0]);
            if parent.is_dir() {
                add_member_dirs(&parent, &mut results)?;
            }
        } else if parts.len() >= 2 && parts.last() == Some(&"*") {
            // "a/b/*" matches all subdirectories of root/a/b
            let mut parent = root.to_path_buf();
            for part in &parts[..parts.len() - 1] {
                parent = parent.join(part);
            }
            if parent.is_dir() {
                add_member_dirs(&parent, &mut results)?;
            }
        } else {
            // Literal path (no glob)
            let member_dir = root.join(pattern);
            if member_dir.join("tallow.toml").exists() {
                results.push(member_dir);
            }
        }
    }

    results.sort();
    results.dedup();
    Ok(results)
}

/// Add all subdirectories of `parent` that contain a tallow.toml.
fn add_member_dirs(parent: &Path, results: &mut Vec<PathBuf>) -> Result<()> {
    if !parent.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(parent)
        .with_context(|| format!("failed to read directory {}", parent.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() && path.join("tallow.toml").exists() {
            results.push(path);
        }
    }
    Ok(())
}

/// Load a complete workspace from its root directory.
///
/// Parses the root tallow.toml, discovers members, and loads each member manifest.
pub fn load_workspace(root: &Path) -> Result<Workspace> {
    let root_toml = root.join("tallow.toml");
    let root_manifest = parse_manifest_file(&root_toml)
        .with_context(|| format!("failed to parse workspace root manifest at {}", root.display()))?;

    let ws_config = root_manifest.workspace.as_ref()
        .ok_or_else(|| anyhow::anyhow!("no [workspace] section in {}", root_toml.display()))?;

    let member_dirs = discover_members(root, &ws_config.members)?;

    let mut members = Vec::new();
    for dir in member_dirs {
        let manifest = parse_manifest_file(&dir.join("tallow.toml"))
            .with_context(|| format!("failed to parse member manifest at {}", dir.display()))?;
        members.push(WorkspaceMember {
            path: dir,
            manifest,
        });
    }

    Ok(Workspace {
        root: root.to_path_buf(),
        root_manifest,
        members,
    })
}

/// Resolve all workspace members' dependencies together in a single solve.
///
/// Path dependencies between workspace members are injected as exact-version
/// local packages so the resolver sees them without needing a registry entry.
pub fn resolve_workspace(
    ws: &Workspace,
    registry: &dyn PackageRegistry,
) -> Result<HashMap<String, Version>> {
    // Build a combined in-memory registry that includes:
    // 1. All workspace member packages as local entries
    // 2. Falls back to the external registry for everything else
    let mut local_packages: HashMap<String, Version> = HashMap::new();
    let mut local_deps: HashMap<String, HashMap<String, VersionReq>> = HashMap::new();

    for member in &ws.members {
        let name = member.manifest.name.clone();
        let version = member.manifest.version.clone();
        local_packages.insert(name.clone(), version);

        let deps: HashMap<String, VersionReq> = member.manifest.dependencies.iter()
            .map(|(n, s)| (n.clone(), s.parsed.clone()))
            .collect();
        local_deps.insert(name, deps);
    }

    // Create a combined registry that serves local packages first
    let combined = WorkspaceRegistry {
        local_packages: &local_packages,
        local_deps: &local_deps,
        fallback: registry,
    };

    // Create a synthetic root manifest that depends on all members
    let mut root_deps = HashMap::new();
    for member in &ws.members {
        let version = &member.manifest.version;
        // Use exact version requirement for workspace members
        let req = crate::pkg::semver_req::parse_version_req(&format!("={}", version))?;
        root_deps.insert(member.manifest.name.clone(), crate::pkg::manifest::DependencySpec {
            version_req_raw: format!("={}", version),
            parsed: req,
            path: None,
        });
    }

    let root_manifest = Manifest {
        name: "workspace-root".to_string(),
        version: Version::new(0, 0, 0),
        author: None,
        license: None,
        dependencies: root_deps,
        workspace: None,
        licenses: None,
        policy: None,
        registries: Vec::new(),
    };

    resolve_dependencies(&root_manifest, &combined)
}

/// Generate a single shared lockfile for the entire workspace.
pub fn generate_workspace_lockfile(
    _ws: &Workspace,
    resolved: &HashMap<String, Version>,
    registry: &dyn PackageRegistry,
    content_hashes: &HashMap<String, String>,
) -> Lockfile {
    generate_lockfile(resolved, registry, content_hashes)
}

/// Registry wrapper that serves workspace members as local packages
/// and falls back to an external registry for everything else.
struct WorkspaceRegistry<'a> {
    local_packages: &'a HashMap<String, Version>,
    local_deps: &'a HashMap<String, HashMap<String, VersionReq>>,
    fallback: &'a dyn PackageRegistry,
}

impl PackageRegistry for WorkspaceRegistry<'_> {
    fn available_versions(&self, package: &str) -> Result<Vec<Version>> {
        if let Some(version) = self.local_packages.get(package) {
            Ok(vec![version.clone()])
        } else {
            self.fallback.available_versions(package)
        }
    }

    fn dependencies(&self, package: &str, version: &Version) -> Result<HashMap<String, VersionReq>> {
        if let Some(local_version) = self.local_packages.get(package) {
            if local_version == version {
                return Ok(self.local_deps.get(package).cloned().unwrap_or_default());
            }
        }
        self.fallback.dependencies(package, version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkg::{parse_manifest, InMemoryRegistry};

    #[test]
    fn test_discover_members() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        // Create packages/a and packages/b with tallow.toml
        let pkg_a = root.join("packages").join("a");
        let pkg_b = root.join("packages").join("b");
        fs::create_dir_all(&pkg_a).unwrap();
        fs::create_dir_all(&pkg_b).unwrap();
        fs::write(pkg_a.join("tallow.toml"), "[package]\nname = \"a\"\nversion = \"1.0.0\"\n").unwrap();
        fs::write(pkg_b.join("tallow.toml"), "[package]\nname = \"b\"\nversion = \"1.0.0\"\n").unwrap();

        // Also create a dir without tallow.toml (should be ignored)
        fs::create_dir_all(root.join("packages").join("no-manifest")).unwrap();

        let members = discover_members(root, &["packages/*".to_string()]).unwrap();
        assert_eq!(members.len(), 2);
        assert!(members.iter().any(|p| p.ends_with("a")));
        assert!(members.iter().any(|p| p.ends_with("b")));
    }

    #[test]
    fn test_load_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        // Root manifest
        fs::write(root.join("tallow.toml"), r#"
[workspace]
members = ["packages/*"]
"#).unwrap();

        // Member a
        let pkg_a = root.join("packages").join("a");
        fs::create_dir_all(&pkg_a).unwrap();
        fs::write(pkg_a.join("tallow.toml"), r#"
[package]
name = "a"
version = "1.0.0"
"#).unwrap();

        // Member b
        let pkg_b = root.join("packages").join("b");
        fs::create_dir_all(&pkg_b).unwrap();
        fs::write(pkg_b.join("tallow.toml"), r#"
[package]
name = "b"
version = "2.0.0"
"#).unwrap();

        let ws = load_workspace(root).unwrap();
        assert_eq!(ws.members.len(), 2);
        assert!(ws.members.iter().any(|m| m.manifest.name == "a"));
        assert!(ws.members.iter().any(|m| m.manifest.name == "b"));
        assert!(ws.root_manifest.workspace.is_some());
    }

    #[test]
    fn test_path_dependency_parsing() {
        let toml = r#"
[package]
name = "my-app"
version = "1.0.0"

[dependencies]
foo = { path = "../foo" }
bar = { version = "^1.0", path = "../bar" }
"#;
        let manifest = parse_manifest(toml).unwrap();
        assert_eq!(manifest.dependencies.len(), 2);

        let foo = &manifest.dependencies["foo"];
        assert_eq!(foo.path.as_deref(), Some("../foo"));
        assert_eq!(foo.version_req_raw, "*"); // no version means wildcard

        let bar = &manifest.dependencies["bar"];
        assert_eq!(bar.path.as_deref(), Some("../bar"));
        assert_eq!(bar.version_req_raw, "^1.0");
    }

    #[test]
    fn test_workspace_resolution() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        // Root manifest
        fs::write(root.join("tallow.toml"), r#"
[workspace]
members = ["packages/*"]
"#).unwrap();

        // Member a: no external deps
        let pkg_a = root.join("packages").join("a");
        fs::create_dir_all(&pkg_a).unwrap();
        fs::write(pkg_a.join("tallow.toml"), r#"
[package]
name = "a"
version = "1.0.0"
"#).unwrap();

        // Member b: depends on a via path
        let pkg_b = root.join("packages").join("b");
        fs::create_dir_all(&pkg_b).unwrap();
        fs::write(pkg_b.join("tallow.toml"), r#"
[package]
name = "b"
version = "2.0.0"

[dependencies]
a = { path = "../a" }
"#).unwrap();

        let ws = load_workspace(root).unwrap();

        // Resolve with empty external registry (no registry needed for path deps)
        let empty_registry = InMemoryRegistry::new();
        let resolved = resolve_workspace(&ws, &empty_registry).unwrap();

        // Both members should be resolved
        assert_eq!(resolved.get("a").unwrap(), &Version::new(1, 0, 0));
        assert_eq!(resolved.get("b").unwrap(), &Version::new(2, 0, 0));
    }

    #[test]
    fn test_workspace_only_manifest() {
        let toml = r#"
[workspace]
members = ["packages/*"]
"#;
        let manifest = parse_manifest(toml).unwrap();
        assert!(manifest.workspace.is_some());
        assert_eq!(manifest.name, "workspace-root");
        assert_eq!(manifest.version, Version::new(0, 0, 0));
    }
}
