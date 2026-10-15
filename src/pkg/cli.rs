use anyhow::{Context, Result, bail};
use semver::Version;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use crate::pkg::cache::GlobalCache;
use crate::pkg::lockfile::{generate_lockfile, write_lockfile, read_lockfile};
use crate::pkg::manifest::parse_manifest;
use crate::pkg::registry::LocalRegistry;
use crate::pkg::resolver::{PackageRegistry, resolve_dependencies};

/// Find the project root by walking up from `start` looking for tallow.toml.
pub fn find_project_root(start: &Path) -> Result<PathBuf> {
    let mut current = start.to_path_buf();
    loop {
        if current.join("tallow.toml").exists() {
            return Ok(current);
        }
        if !current.pop() {
            bail!("could not find tallow.toml in {} or any parent directory", start.display());
        }
    }
}

/// Return platform-appropriate default registry path.
pub fn default_registry_path() -> PathBuf {
    let base = if cfg!(windows) {
        dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."))
    } else {
        dirs::home_dir()
            .map(|h| h.join(".tallow"))
            .unwrap_or_else(|| PathBuf::from(".tallow"))
    };

    if cfg!(windows) {
        base.join("tallow").join("registry")
    } else {
        base.join("registry")
    }
}

/// Build content hashes map from registry metadata for all resolved packages.
fn get_content_hashes(
    registry: &LocalRegistry,
    resolved: &HashMap<String, Version>,
) -> HashMap<String, String> {
    let mut hashes = HashMap::new();
    for (name, version) in resolved {
        let version_str = version.to_string();
        let metadata_path = registry.metadata_path(name, &version_str);
        if let Ok(content) = fs::read_to_string(&metadata_path) {
            if let Ok(meta) = serde_json::from_str::<crate::pkg::registry::PackageMetadata>(&content) {
                hashes.insert(name.clone(), meta.content_hash);
            }
        }
    }
    hashes
}

/// Resolve, fetch, lock, and link all dependencies for a project.
fn resolve_and_link(
    project_dir: &Path,
    registry: &LocalRegistry,
    cache: &GlobalCache,
) -> Result<HashMap<String, Version>> {
    let toml_path = project_dir.join("tallow.toml");
    let toml_content = fs::read_to_string(&toml_path)
        .with_context(|| format!("failed to read {}", toml_path.display()))?;
    let manifest = parse_manifest(&toml_content)
        .context("failed to parse tallow.toml")?;

    let resolved = resolve_dependencies(&manifest, registry)
        .context("dependency resolution failed")?;

    // Fetch all resolved packages into cache
    for (name, version) in &resolved {
        registry.fetch_package(name, version)
            .with_context(|| format!("failed to fetch {} {}", name, version))?;
    }

    // Build content hashes and generate lockfile
    let content_hashes = get_content_hashes(registry, &resolved);
    let lockfile = generate_lockfile(&resolved, registry, &content_hashes);
    write_lockfile(&lockfile, &project_dir.join("tallow.lock"))?;

    // Link into tallow_modules/
    cache.link_all(&lockfile, project_dir)?;

    Ok(resolved)
}

/// Add a dependency to tallow.toml, resolve, lock, and link.
pub fn pkg_add(
    pkg_name: &str,
    version_req: Option<&str>,
    project_dir: &Path,
    registry_path: &Path,
) -> Result<()> {
    let toml_path = project_dir.join("tallow.toml");
    let toml_content = fs::read_to_string(&toml_path)
        .with_context(|| format!("failed to read {}", toml_path.display()))?;

    // Use toml_edit to preserve formatting
    let mut doc: toml_edit::DocumentMut = toml_content.parse::<toml_edit::DocumentMut>()
        .context("failed to parse tallow.toml")?;

    // Ensure [dependencies] table exists
    if doc.get("dependencies").is_none() {
        doc["dependencies"] = toml_edit::Item::Table(toml_edit::Table::new());
    }

    // Determine version constraint
    let version_str = if let Some(req) = version_req {
        req.to_string()
    } else {
        // Try to find latest version in registry to use ^latest
        let cache = GlobalCache::new(registry_path.join(".cache"));
        let registry = LocalRegistry::open(registry_path.to_path_buf(), cache);
        match registry.available_versions(pkg_name) {
            Ok(versions) if !versions.is_empty() => {
                let latest = versions.last().unwrap();
                format!("^{}", latest)
            }
            _ => "*".to_string(),
        }
    };

    // Add dependency
    doc["dependencies"][pkg_name] = toml_edit::value(&version_str);

    // Write back
    fs::write(&toml_path, doc.to_string())
        .context("failed to write tallow.toml")?;

    // Resolve, fetch, lock, link
    let cache = GlobalCache::new(registry_path.join(".cache"));
    let registry = LocalRegistry::open(registry_path.to_path_buf(), cache.clone());
    let resolved = resolve_and_link(project_dir, &registry, &cache)?;

    // Print summary
    if let Some(version) = resolved.get(pkg_name) {
        eprintln!("added {} {}", pkg_name, version);
    } else {
        eprintln!("added {} (version constraint: {})", pkg_name, version_str);
    }
    if resolved.len() > 1 {
        eprintln!("resolved {} total dependencies", resolved.len());
    }

    Ok(())
}

/// Remove a dependency from tallow.toml, re-resolve, and update lockfile.
pub fn pkg_remove(
    pkg_name: &str,
    project_dir: &Path,
    registry_path: &Path,
) -> Result<()> {
    let toml_path = project_dir.join("tallow.toml");
    let toml_content = fs::read_to_string(&toml_path)
        .with_context(|| format!("failed to read {}", toml_path.display()))?;

    let mut doc: toml_edit::DocumentMut = toml_content.parse::<toml_edit::DocumentMut>()
        .context("failed to parse tallow.toml")?;

    // Check dependency exists
    let deps = doc.get_mut("dependencies")
        .and_then(|d| d.as_table_like_mut());
    match deps {
        Some(table) => {
            if table.get(pkg_name).is_none() {
                bail!("package '{}' is not in [dependencies]", pkg_name);
            }
            table.remove(pkg_name);
        }
        None => {
            bail!("package '{}' is not in [dependencies] (no [dependencies] section)", pkg_name);
        }
    }

    // Write back
    fs::write(&toml_path, doc.to_string())
        .context("failed to write tallow.toml")?;

    // Re-resolve remaining deps
    let cache = GlobalCache::new(registry_path.join(".cache"));
    let registry = LocalRegistry::open(registry_path.to_path_buf(), cache.clone());
    let _resolved = resolve_and_link(project_dir, &registry, &cache)?;

    // Remove from tallow_modules/ if present
    let modules_path = project_dir.join("tallow_modules").join(pkg_name);
    if modules_path.exists() || modules_path.symlink_metadata().is_ok() {
        #[cfg(windows)]
        {
            if modules_path.is_dir() {
                let _ = fs::remove_dir(&modules_path);
            }
        }
        #[cfg(unix)]
        {
            let _ = fs::remove_file(&modules_path);
            let _ = fs::remove_dir(&modules_path);
        }
    }

    eprintln!("removed {}", pkg_name);
    Ok(())
}

/// Re-resolve all dependencies to latest compatible versions.
pub fn pkg_update(
    project_dir: &Path,
    registry_path: &Path,
) -> Result<()> {
    let cache = GlobalCache::new(registry_path.join(".cache"));
    let registry = LocalRegistry::open(registry_path.to_path_buf(), cache.clone());
    let resolved = resolve_and_link(project_dir, &registry, &cache)?;

    if resolved.is_empty() {
        eprintln!("no dependencies to update");
    } else {
        eprintln!("updated {} dependencies:", resolved.len());
        let mut sorted: Vec<_> = resolved.iter().collect();
        sorted.sort_by_key(|(name, _)| (*name).clone());
        for (name, version) in sorted {
            eprintln!("  {} {}", name, version);
        }
    }
    Ok(())
}

/// Auto-install missing dependencies before running a program.
///
/// Checks if tallow.toml exists in the project root. If it has dependencies:
/// 1. If tallow.lock exists, checks if tallow_modules/ has all packages. If any missing, runs pkg_install.
/// 2. If tallow.lock does NOT exist, runs pkg_update (full resolution) then install.
///
/// This is a no-op if:
/// - No tallow.toml is found (standalone script, no project)
/// - tallow.toml has no [dependencies] section or it's empty
/// - tallow_modules/ already exists and has all expected packages
pub fn auto_install_if_needed(source_file: &Path) -> Result<()> {
    auto_install_with_registry(source_file, &default_registry_path())
}

/// Testable variant of auto_install_if_needed that accepts an explicit registry path.
pub fn auto_install_with_registry(source_file: &Path, registry_path: &Path) -> Result<()> {
    // Find project root -- if none, this is a standalone script
    let parent = source_file.parent().unwrap_or(Path::new("."));
    let project_dir = match find_project_root(parent) {
        Ok(dir) => dir,
        Err(_) => return Ok(()), // standalone script, no project
    };

    // Check if tallow.toml has dependencies
    let toml_path = project_dir.join("tallow.toml");
    let manifest = match crate::pkg::manifest::parse_manifest_file(&toml_path) {
        Ok(m) => m,
        Err(_) => return Ok(()), // can't parse, skip silently
    };

    if manifest.dependencies.is_empty() {
        return Ok(()); // no deps, nothing to do
    }

    let lock_path = project_dir.join("tallow.lock");

    if lock_path.exists() {
        // Fast path: check if all locked packages exist in tallow_modules/
        let lockfile = read_lockfile(&lock_path)?;
        let modules_dir = project_dir.join("tallow_modules");
        let mut missing = 0usize;

        for name in lockfile.packages.keys() {
            if !modules_dir.join(name).exists() {
                missing += 1;
            }
        }

        if missing == 0 {
            return Ok(()); // everything already installed
        }

        // Some packages missing -- install from lockfile
        pkg_install(&project_dir, registry_path, false)?;
        eprintln!("auto-installed {} dependenc{}", missing, if missing == 1 { "y" } else { "ies" });
    } else {
        // No lockfile -- do full resolution
        pkg_update(&project_dir, registry_path)?;
        let dep_count = manifest.dependencies.len();
        eprintln!("auto-installed {} dependenc{}", dep_count, if dep_count == 1 { "y" } else { "ies" });
    }

    Ok(())
}

/// Install dependencies from tallow.lock.
pub fn pkg_install(
    project_dir: &Path,
    registry_path: &Path,
    offline: bool,
) -> Result<()> {
    let lock_path = project_dir.join("tallow.lock");
    if !lock_path.exists() {
        bail!("no tallow.lock found, run 'tallow add' first");
    }

    let lockfile = read_lockfile(&lock_path)?;
    let cache = GlobalCache::new(registry_path.join(".cache"));
    let registry = LocalRegistry::open(registry_path.to_path_buf(), cache.clone());

    for (name, pkg) in &lockfile.packages {
        if offline {
            if !cache.is_cached(&pkg.content_hash) {
                bail!(
                    "package {} {} not in cache, cannot install offline",
                    name, pkg.version
                );
            }
        } else {
            // Fetch into cache if not already there
            if !cache.is_cached(&pkg.content_hash) {
                registry.fetch_package(name, &pkg.version)
                    .with_context(|| format!("failed to fetch {} {}", name, pkg.version))?;
            }
        }
    }

    // Link all into tallow_modules/
    cache.link_all(&lockfile, project_dir)?;

    let count = lockfile.packages.len();
    eprintln!("installed {} package{}", count, if count == 1 { "" } else { "s" });
    Ok(())
}

/// Generate a .tli interface file for the project.
///
/// Parses the main source file, generates an interface containing only
/// public API surface (signatures, types, constants), and writes it to
/// `{project_dir}/pkg.tli`.
pub fn pkg_generate_interface(project_dir: &Path) -> Result<PathBuf> {
    // Look for src/main.tl or main.tl
    let source_path = if project_dir.join("src").join("main.tl").exists() {
        project_dir.join("src").join("main.tl")
    } else if project_dir.join("main.tl").exists() {
        project_dir.join("main.tl")
    } else {
        bail!("no main.tl found in {} or {}/src/", project_dir.display(), project_dir.display());
    };

    let source = fs::read_to_string(&source_path)
        .with_context(|| format!("failed to read {}", source_path.display()))?;

    let (tokens, _) = crate::lexer::tokenize(&source);
    let program = crate::parser::Parser::parse(tokens)
        .map_err(|e| anyhow::anyhow!("parse error: {:?}", e))?;

    let output_path = project_dir.join("pkg.tli");
    crate::pkg::interface_gen::write_interface(&program.items, &output_path)
        .with_context(|| format!("failed to write {}", output_path.display()))?;

    Ok(output_path)
}

/// Publish a package to a registry.
///
/// Wraps `HostedRegistry::publish`, prints "published {name} {version}".
pub fn pkg_publish(project_dir: &Path, registry_path: &Path) -> Result<()> {
    let cache = GlobalCache::new(registry_path.join(".cache"));
    let local = LocalRegistry::open(registry_path.to_path_buf(), cache);
    let hosted = crate::pkg::hosted_registry::HostedRegistry::new(local);

    let metadata = hosted.publish(project_dir)?;
    eprintln!("published {} {}", metadata.name, metadata.version);
    Ok(())
}

/// Search for packages in the registry.
///
/// Wraps `HostedRegistry::search`, prints a results table.
pub fn pkg_search(query: &str, registry_path: &Path) -> Result<()> {
    let cache = GlobalCache::new(registry_path.join(".cache"));
    let local = LocalRegistry::open(registry_path.to_path_buf(), cache);
    let hosted = crate::pkg::hosted_registry::HostedRegistry::new(local);

    let results = hosted.search(query)?;
    if results.is_empty() {
        eprintln!("no packages found matching '{}'", query);
    } else {
        eprintln!("{:<30} {:<15} {}", "NAME", "VERSION", "VERSIONS");
        eprintln!("{}", "-".repeat(55));
        for r in &results {
            eprintln!("{:<30} {:<15} {}", r.name, r.latest_version, r.version_count);
        }
        eprintln!("\n{} package{} found", results.len(), if results.len() == 1 { "" } else { "s" });
    }
    Ok(())
}

/// Find workspace root by walking up from `start` looking for tallow.toml with [workspace].
pub fn find_workspace_root(start: &Path) -> Option<PathBuf> {
    let mut current = start.to_path_buf();
    loop {
        let toml_path = current.join("tallow.toml");
        if toml_path.exists() {
            if let Ok(content) = fs::read_to_string(&toml_path) {
                if content.contains("[workspace]") {
                    return Some(current);
                }
            }
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Workspace-aware auto-install. If within a workspace, resolves all members' deps together.
pub fn auto_install_workspace_aware(source_file: &Path, registry_path: &Path) -> Result<()> {
    let parent = source_file.parent().unwrap_or(Path::new("."));

    // Check for workspace root first
    if let Some(ws_root) = find_workspace_root(parent) {
        let ws = crate::pkg::workspace::load_workspace(&ws_root)
            .context("failed to load workspace")?;

        // Check if all members have their deps in tallow_modules/
        let lock_path = ws_root.join("tallow.lock");
        if lock_path.exists() {
            let lockfile = crate::pkg::lockfile::read_lockfile(&lock_path)?;
            let modules_dir = ws_root.join("tallow_modules");
            let missing: usize = lockfile.packages.keys()
                .filter(|name| !modules_dir.join(name).exists())
                .count();
            if missing == 0 {
                return Ok(()); // everything installed
            }
        }

        // Resolve workspace deps
        let cache = GlobalCache::new(registry_path.join(".cache"));
        let registry = LocalRegistry::open(registry_path.to_path_buf(), cache.clone());
        let resolved = crate::pkg::workspace::resolve_workspace(&ws, &registry)?;

        // Separate workspace members from external deps
        let member_names: std::collections::HashSet<String> = ws.members.iter()
            .map(|m| m.manifest.name.clone())
            .collect();

        // Generate shared lockfile at workspace root (external deps only)
        let external_resolved: HashMap<String, semver::Version> = resolved.iter()
            .filter(|(name, _)| !member_names.contains(*name))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let content_hashes = HashMap::new();
        let lockfile = crate::pkg::workspace::generate_workspace_lockfile(
            &ws, &external_resolved, &registry, &content_hashes,
        );
        crate::pkg::lockfile::write_lockfile(&lockfile, &ws_root.join("tallow.lock"))?;

        // Fetch and link only external deps
        for (name, version) in &external_resolved {
            let _ = registry.fetch_package(name, version);
        }
        if !external_resolved.is_empty() {
            cache.link_all(&lockfile, &ws_root)?;
        }

        // Create symlinks for workspace members in tallow_modules/
        let modules_dir = ws_root.join("tallow_modules");
        if !ws.members.is_empty() {
            fs::create_dir_all(&modules_dir).ok();
            for member in &ws.members {
                let link_path = modules_dir.join(&member.manifest.name);
                if !link_path.exists() {
                    #[cfg(unix)]
                    { let _ = std::os::unix::fs::symlink(&member.path, &link_path); }
                    #[cfg(windows)]
                    { let _ = std::os::windows::fs::symlink_dir(&member.path, &link_path); }
                }
            }
        }

        let dep_count = resolved.len();
        eprintln!(
            "workspace: resolved {} dependenc{}",
            dep_count,
            if dep_count == 1 { "y" } else { "ies" }
        );
        return Ok(());
    }

    // Not in a workspace, fall back to normal auto-install
    auto_install_with_registry(source_file, registry_path)
}

// ── pkg why ──────────────────────────────────────────────────────────────────

/// Explain why a package is present in the dependency graph.
///
/// Reads `tallow.lock`, builds a reverse-dependency map, then BFS-walks from
/// the named package back to direct dependencies of the root project.
///
/// With `full = true` every path is printed; with `full = false` only the
/// shortest BFS path per distinct root is shown.
pub fn pkg_why(package: &str, full: bool, project_dir: &Path) -> Result<()> {
    let lock_path = project_dir.join("tallow.lock");
    if !lock_path.exists() {
        bail!("no tallow.lock found — run 'tallow install' first");
    }
    let lockfile = read_lockfile(&lock_path)?;

    if !lockfile.packages.contains_key(package) {
        bail!("package '{}' is not in tallow.lock", package);
    }

    // Build reverse-dep map: child -> list of packages that directly depend on it.
    let mut rdeps: HashMap<String, Vec<String>> = HashMap::new();
    for (name, pkg) in &lockfile.packages {
        for dep in &pkg.dependencies {
            rdeps.entry(dep.clone()).or_default().push(name.clone());
        }
    }

    let pkg_entry = &lockfile.packages[package];
    eprintln!("{} {}", package, pkg_entry.version);

    // BFS from `package` following rdeps to the root(s).
    // Each queue element is the path from `package` up to the current node.
    let mut queue: VecDeque<Vec<String>> = VecDeque::new();
    queue.push_back(vec![package.to_string()]);

    let mut seen_paths: HashSet<Vec<String>> = HashSet::new();

    while let Some(path) = queue.pop_front() {
        let current = path.last().unwrap().clone();
        let parents = rdeps.get(&current).cloned().unwrap_or_default();

        if parents.is_empty() {
            // This node has no rdeps — it is a direct/root dependency.
            if seen_paths.insert(path.clone()) {
                pkg_why_print_path(&path, &lockfile.packages);
            }
        } else {
            for parent in parents {
                let mut new_path = path.clone();
                // Guard against cycles.
                if new_path.contains(&parent) {
                    continue;
                }
                new_path.push(parent);
                if !seen_paths.contains(&new_path) {
                    if full {
                        queue.push_back(new_path);
                    } else {
                        // BFS finds shortest first; only explore each node once.
                        seen_paths.insert(new_path.clone());
                        queue.push_back(new_path);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Print a single BFS path as a nested tree from package up to the root.
fn pkg_why_print_path(
    path: &[String],
    packages: &std::collections::BTreeMap<String, crate::pkg::lockfile::LockedPackage>,
) {
    // path[0] = queried package, path[last] = direct root dep.
    // Render as: root dep -> ... -> package (outermost first).
    let reversed: Vec<&String> = path.iter().rev().collect();
    for (i, name) in reversed.iter().enumerate() {
        let indent = "    ".repeat(i);
        let version = packages.get(*name).map(|p| p.version.to_string()).unwrap_or_default();
        if i == 0 {
            eprintln!("  {} {}", name, version);
        } else {
            eprintln!("{}  └── required by {} {}", indent, name, version);
        }
    }
}

// ── pkg patch ────────────────────────────────────────────────────────────────

/// Extract a cached package to a directory for local editing.
pub fn pkg_patch(
    pkg_name: &str,
    edit_dir: Option<&Path>,
    project_dir: &Path,
    registry_path: &Path,
) -> Result<()> {
    let lock_path = project_dir.join("tallow.lock");
    if !lock_path.exists() {
        bail!("no tallow.lock found — run 'tallow install' first");
    }
    let lockfile = read_lockfile(&lock_path)?;
    let locked = lockfile.packages.get(pkg_name)
        .with_context(|| format!("package '{}' is not in tallow.lock", pkg_name))?;

    let dest: PathBuf = if let Some(d) = edit_dir {
        d.to_path_buf()
    } else {
        project_dir.join("patches").join(format!("{}-edit", pkg_name))
    };

    if dest.exists() {
        bail!(
            "edit directory already exists: {}\nRemove it first or use --edit-dir to choose a different path.",
            dest.display()
        );
    }

    let version_str = locked.version.to_string();
    let archive_name = format!("{}-{}.tar.zst", pkg_name, version_str);
    let archive_path = registry_path
        .join("packages")
        .join(pkg_name)
        .join(&version_str)
        .join(&archive_name);

    if !archive_path.exists() {
        bail!(
            "archive not found in registry: {}\nRun 'tallow install' to fetch dependencies first.",
            archive_path.display()
        );
    }

    fs::create_dir_all(&dest)
        .with_context(|| format!("failed to create edit dir {}", dest.display()))?;

    crate::pkg::archive::extract_archive(&archive_path, &dest)
        .with_context(|| format!("failed to extract {}", archive_path.display()))?;

    eprintln!("extracted {} {} to:", pkg_name, version_str);
    eprintln!("  {}", dest.display());
    eprintln!();
    eprintln!("Edit the files, then commit your changes with:");
    eprintln!("  tallow patch-commit {}", dest.display());

    Ok(())
}

/// Commit an edited directory as a named patch file.
pub fn pkg_patch_commit(edit_path: &Path, project_dir: &Path) -> Result<()> {
    if !edit_path.exists() {
        bail!("edit directory does not exist: {}", edit_path.display());
    }

    let dir_name = edit_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    let pkg_name = dir_name.strip_suffix("-edit").unwrap_or(dir_name);

    let lock_path = project_dir.join("tallow.lock");
    let version_str = if lock_path.exists() {
        if let Ok(lf) = read_lockfile(&lock_path) {
            lf.packages.get(pkg_name)
                .map(|p| p.version.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        } else {
            "unknown".to_string()
        }
    } else {
        "unknown".to_string()
    };

    let patches_dir = project_dir.join("patches");
    fs::create_dir_all(&patches_dir)
        .context("failed to create patches/ directory")?;

    let patch_name = format!("{}@{}.patch", pkg_name, version_str);
    let patch_path = patches_dir.join(&patch_name);

    let mut patch_content = String::new();
    patch_content.push_str(&format!("# tallow patch for {} {}\n", pkg_name, version_str));
    patch_content.push_str(&format!("# Generated by: tallow patch-commit {}\n", edit_path.display()));
    patch_content.push_str(&format!("# Edit directory: {}\n\n", edit_path.display()));

    let mut file_count = 0usize;
    pkg_patch_walk_dir(edit_path, edit_path, &mut patch_content, &mut file_count)?;
    patch_content.push_str(&format!("\n# {} file(s) recorded in patch\n", file_count));

    fs::write(&patch_path, &patch_content)
        .with_context(|| format!("failed to write {}", patch_path.display()))?;

    let toml_path = project_dir.join("tallow.toml");
    if toml_path.exists() {
        let toml_content = fs::read_to_string(&toml_path)
            .context("failed to read tallow.toml")?;
        let mut doc: toml_edit::DocumentMut = toml_content
            .parse::<toml_edit::DocumentMut>()
            .context("failed to parse tallow.toml")?;

        if doc.get("patches").is_none() {
            doc["patches"] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        doc["patches"][pkg_name] = toml_edit::value(patch_path.to_string_lossy().as_ref());

        fs::write(&toml_path, doc.to_string())
            .context("failed to write tallow.toml")?;
        eprintln!("tallow.toml updated: [patches].{} = \"{}\"", pkg_name, patch_path.display());
    }

    eprintln!("patch committed: {}", patch_path.display());
    Ok(())
}

fn pkg_patch_walk_dir(base: &Path, dir: &Path, out: &mut String, count: &mut usize) -> Result<()> {
    let entries = fs::read_dir(dir)
        .with_context(|| format!("failed to read {}", dir.display()))?;
    let mut entries: Vec<_> = entries.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let rel = path.strip_prefix(base).unwrap_or(&path);
        if path.is_dir() {
            pkg_patch_walk_dir(base, &path, out, count)?;
        } else {
            *count += 1;
            let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            out.push_str(&format!("# file: {} ({} bytes)\n", rel.display(), size));
        }
    }
    Ok(())
}

/// Remove a patch: delete the `.patch` file and the `[patches]` entry in tallow.toml.
pub fn pkg_patch_remove(pkg_name: &str, project_dir: &Path) -> Result<()> {
    let toml_path = project_dir.join("tallow.toml");
    let patches_dir = project_dir.join("patches");

    let mut removed_file = false;
    if patches_dir.exists() {
        for entry in fs::read_dir(&patches_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with(pkg_name) && name_str.ends_with(".patch") {
                fs::remove_file(entry.path())
                    .with_context(|| format!("failed to remove {}", entry.path().display()))?;
                eprintln!("removed patch file: {}", entry.path().display());
                removed_file = true;
            }
        }
    }

    let mut removed_toml = false;
    if toml_path.exists() {
        let toml_content = fs::read_to_string(&toml_path)
            .context("failed to read tallow.toml")?;
        let mut doc: toml_edit::DocumentMut = toml_content
            .parse::<toml_edit::DocumentMut>()
            .context("failed to parse tallow.toml")?;

        if let Some(patches) = doc.get_mut("patches").and_then(|v| v.as_table_like_mut()) {
            if patches.get(pkg_name).is_some() {
                patches.remove(pkg_name);
                removed_toml = true;
            }
        }

        if removed_toml {
            fs::write(&toml_path, doc.to_string())
                .context("failed to write tallow.toml")?;
            eprintln!("removed [patches].{} from tallow.toml", pkg_name);
        }
    }

    if !removed_file && !removed_toml {
        bail!("no patch found for '{}'", pkg_name);
    }

    Ok(())
}

// ── pkg tree ─────────────────────────────────────────────────────────────────

/// Print the dependency tree rooted at the current project.
pub fn pkg_tree(max_depth: usize, as_json: bool, project_dir: &Path) -> Result<()> {
    let toml_path = project_dir.join("tallow.toml");
    if !toml_path.exists() {
        bail!("no tallow.toml found in {}", project_dir.display());
    }

    let toml_content = fs::read_to_string(&toml_path)
        .context("failed to read tallow.toml")?;
    let manifest = parse_manifest(&toml_content)
        .context("failed to parse tallow.toml")?;

    let lock_path = project_dir.join("tallow.lock");
    let lockfile = if lock_path.exists() {
        Some(read_lockfile(&lock_path)?)
    } else {
        None
    };

    if as_json {
        let mut json = String::from("{\n");
        json.push_str(&format!("  \"name\": \"{}\",\n", manifest.name));
        json.push_str(&format!("  \"version\": \"{}\",\n", manifest.version));
        json.push_str("  \"dependencies\": {\n");
        let dep_names: Vec<&str> = manifest.dependencies.keys().map(|s| s.as_str()).collect();
        for (i, dep) in dep_names.iter().enumerate() {
            let ver = lockfile.as_ref()
                .and_then(|lf| lf.packages.get(*dep))
                .map(|p| p.version.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let comma = if i + 1 < dep_names.len() { "," } else { "" };
            json.push_str(&format!("    \"{}\": \"{}\"{}\n", dep, ver, comma));
        }
        json.push_str("  }\n}");
        println!("{}", json);
        return Ok(());
    }

    println!("{} v{}", manifest.name, manifest.version);

    let mut seen: HashSet<String> = HashSet::new();
    let mut direct: Vec<String> = manifest.dependencies.keys().cloned().collect();
    direct.sort();

    for (i, dep) in direct.iter().enumerate() {
        let is_last = i + 1 == direct.len();
        let prefix = if is_last { "└── " } else { "├── " };
        let child_prefix = if is_last { "    " } else { "│   " };

        let ver = lockfile.as_ref()
            .and_then(|lf| lf.packages.get(dep))
            .map(|p| p.version.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        if seen.contains(dep) {
            println!("{}{} v{} (*)", prefix, dep, ver);
        } else {
            println!("{}{} v{}", prefix, dep, ver);
            seen.insert(dep.clone());
            if let Some(ref lf) = lockfile {
                if max_depth > 1 {
                    pkg_tree_print_children(dep, lf, child_prefix, 2, max_depth, &mut seen);
                }
            }
        }
    }

    let has_children = lockfile.as_ref().map(|lf| {
        direct.iter().any(|d| {
            lf.packages.get(d).map(|p| !p.dependencies.is_empty()).unwrap_or(false)
        })
    }).unwrap_or(false);

    if has_children {
        println!();
        println!("(*) = duplicate, already shown above");
    }

    Ok(())
}

fn pkg_tree_print_children(
    pkg_name: &str,
    lockfile: &crate::pkg::lockfile::Lockfile,
    prefix: &str,
    depth: usize,
    max_depth: usize,
    seen: &mut HashSet<String>,
) {
    if depth > max_depth {
        return;
    }
    let pkg = match lockfile.packages.get(pkg_name) {
        Some(p) => p,
        None => return,
    };

    let mut children = pkg.dependencies.clone();
    children.sort();

    for (i, child) in children.iter().enumerate() {
        let is_last = i + 1 == children.len();
        let connector = if is_last { "└── " } else { "├── " };
        let child_prefix = if is_last {
            format!("{}    ", prefix)
        } else {
            format!("{}│   ", prefix)
        };

        let ver = lockfile.packages.get(child)
            .map(|p| p.version.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        if seen.contains(child) {
            println!("{}{}{} v{} (*)", prefix, connector, child, ver);
        } else {
            println!("{}{}{} v{}", prefix, connector, child, ver);
            seen.insert(child.clone());
            pkg_tree_print_children(child, lockfile, &child_prefix, depth + 1, max_depth, seen);
        }
    }
}

// ── pkg cache ────────────────────────────────────────────────────────────────

/// Show cache location, disk usage, and package count.
pub fn pkg_cache_info(registry_path: &Path) -> Result<()> {
    let cache_dir = registry_path.join(".cache");
    if !cache_dir.exists() {
        eprintln!("cache directory: {} (empty / not yet created)", cache_dir.display());
        return Ok(());
    }
    let (total_bytes, file_count, pkg_count) = cache_measure_dir(&cache_dir);
    eprintln!("cache directory: {}", cache_dir.display());
    eprintln!("  packages:      {}", pkg_count);
    eprintln!("  files:         {}", file_count);
    eprintln!("  total size:    {}", cache_format_bytes(total_bytes));
    Ok(())
}

/// Remove cached packages not referenced by any lockfile.
pub fn pkg_cache_prune(registry_path: &Path) -> Result<()> {
    let cache_dir = registry_path.join(".cache");
    if !cache_dir.exists() {
        eprintln!("cache is empty, nothing to prune");
        return Ok(());
    }

    let mut referenced: HashSet<String> = HashSet::new();
    if let Ok(cwd) = std::env::current_dir() {
        let lock_path = cwd.join("tallow.lock");
        if let Ok(lf) = read_lockfile(&lock_path) {
            for pkg in lf.packages.values() {
                referenced.insert(pkg.content_hash.clone());
            }
        }
    }

    let mut removed_count = 0usize;
    let mut removed_bytes = 0u64;

    if let Ok(shards) = fs::read_dir(&cache_dir) {
        for shard in shards.filter_map(|e| e.ok()) {
            if !shard.path().is_dir() { continue; }
            if let Ok(entries) = fs::read_dir(shard.path()) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let hash = entry.file_name().to_string_lossy().to_string();
                    if !referenced.contains(&hash) {
                        let (bytes, _, _) = cache_measure_dir(&entry.path());
                        removed_bytes += bytes;
                        removed_count += 1;
                        if let Err(e) = fs::remove_dir_all(entry.path()) {
                            eprintln!("  warning: failed to remove {}: {}", entry.path().display(), e);
                        }
                    }
                }
            }
        }
    }

    if removed_count == 0 {
        eprintln!("nothing to prune — all cached packages are referenced");
    } else {
        eprintln!("pruned {} package{} ({})",
            removed_count,
            if removed_count == 1 { "" } else { "s" },
            cache_format_bytes(removed_bytes));
    }
    Ok(())
}

/// Delete the entire package cache directory.
pub fn pkg_cache_clean(registry_path: &Path) -> Result<()> {
    let cache_dir = registry_path.join(".cache");
    if !cache_dir.exists() {
        eprintln!("cache is already empty");
        return Ok(());
    }
    let (total_bytes, _, pkg_count) = cache_measure_dir(&cache_dir);
    fs::remove_dir_all(&cache_dir)
        .with_context(|| format!("failed to remove {}", cache_dir.display()))?;
    eprintln!("cache cleared: {} package{} ({}) removed",
        pkg_count,
        if pkg_count == 1 { "" } else { "s" },
        cache_format_bytes(total_bytes));
    Ok(())
}

/// Verify BLAKE3 integrity of every file in the cache.
pub fn pkg_cache_verify(registry_path: &Path) -> Result<()> {
    let cache_dir = registry_path.join(".cache");
    if !cache_dir.exists() {
        eprintln!("cache is empty — nothing to verify");
        return Ok(());
    }

    let mut ok_count = 0usize;
    let mut bad_count = 0usize;

    let shards = fs::read_dir(&cache_dir)
        .with_context(|| format!("failed to read {}", cache_dir.display()))?;

    for shard in shards.filter_map(|e| e.ok()) {
        if !shard.path().is_dir() { continue; }
        let packages = fs::read_dir(shard.path())
            .with_context(|| format!("failed to read shard {}", shard.path().display()))?;

        for pkg_entry in packages.filter_map(|e| e.ok()) {
            let pkg_dir = pkg_entry.path();
            if !pkg_dir.is_dir() { continue; }
            let expected_hash = pkg_entry.file_name().to_string_lossy().to_string();
            let actual_hash = cache_hash_dir_blake3(&pkg_dir)?;

            if actual_hash == expected_hash || expected_hash.is_empty() {
                ok_count += 1;
            } else {
                let short_exp = &expected_hash[..8.min(expected_hash.len())];
                let short_act = &actual_hash[..8.min(actual_hash.len())];
                eprintln!("  CORRUPTED: {} (expected {}..., got {}...)",
                    pkg_dir.display(), short_exp, short_act);
                bad_count += 1;
            }
        }
    }

    if bad_count == 0 {
        eprintln!("verified {} package{} — all OK",
            ok_count, if ok_count == 1 { "" } else { "s" });
    } else {
        eprintln!("verified {} package{} — {} corrupted",
            ok_count + bad_count,
            if ok_count + bad_count == 1 { "" } else { "s" },
            bad_count);
        bail!("{} corrupted package{} found in cache",
            bad_count, if bad_count == 1 { "" } else { "s" });
    }
    Ok(())
}

/// Recursively measure a cache directory: (total_bytes, file_count, pkg_count).
fn cache_measure_dir(dir: &Path) -> (u64, usize, usize) {
    fn walk(path: &Path, bytes: &mut u64, files: &mut usize) {
        let Ok(rd) = fs::read_dir(path) else { return };
        for entry in rd.filter_map(|e| e.ok()) {
            let p = entry.path();
            if p.is_dir() { walk(&p, bytes, files); }
            else if p.is_file() {
                *files += 1;
                *bytes += fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            }
        }
    }

    let mut total_bytes = 0u64;
    let mut file_count = 0usize;
    let mut dir_count = 0usize;

    if let Ok(shards) = fs::read_dir(dir) {
        for shard in shards.filter_map(|e| e.ok()) {
            if shard.path().is_dir() {
                if let Ok(pkgs) = fs::read_dir(shard.path()) {
                    for pkg in pkgs.filter_map(|e| e.ok()) {
                        if pkg.path().is_dir() {
                            dir_count += 1;
                            walk(&pkg.path(), &mut total_bytes, &mut file_count);
                        }
                    }
                }
            }
        }
    }
    (total_bytes, file_count, dir_count)
}

fn cache_format_bytes(bytes: u64) -> String {
    if bytes < 1_024 {
        format!("{} B", bytes)
    } else if bytes < 1_024 * 1_024 {
        format!("{:.1} KB", bytes as f64 / 1_024.0)
    } else if bytes < 1_024 * 1_024 * 1_024 {
        format!("{:.1} MB", bytes as f64 / (1_024.0 * 1_024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1_024.0 * 1_024.0 * 1_024.0))
    }
}

fn cache_hash_dir_blake3(dir: &Path) -> Result<String> {
    fn collect(d: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = fs::read_dir(d) else { return };
        let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let p = e.path();
            if p.is_dir() { collect(&p, out); }
            else if p.is_file() { out.push(p); }
        }
    }
    let mut paths: Vec<PathBuf> = Vec::new();
    collect(dir, &mut paths);

    let mut hasher = blake3::Hasher::new();
    for path in &paths {
        let data = fs::read(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        hasher.update(&data);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

// ── pkg outdated ─────────────────────────────────────────────────────────────

/// Compare all locked dependency versions against the latest in the registry.
pub fn pkg_outdated(as_json: bool, project_dir: &Path, registry_path: &Path) -> Result<()> {
    let lock_path = project_dir.join("tallow.lock");
    if !lock_path.exists() {
        bail!("no tallow.lock found — run 'tallow install' first");
    }
    let lockfile = read_lockfile(&lock_path)?;

    if lockfile.packages.is_empty() {
        eprintln!("no dependencies found in tallow.lock");
        return Ok(());
    }

    let cache = GlobalCache::new(registry_path.join(".cache"));
    let registry = LocalRegistry::open(registry_path.to_path_buf(), cache);

    struct OutdatedEntry {
        name: String,
        current: Version,
        latest: Version,
        status: &'static str,
    }

    let mut entries: Vec<OutdatedEntry> = Vec::new();

    for (name, pkg) in &lockfile.packages {
        let current = pkg.version.clone();
        let latest = match registry.available_versions(name) {
            Ok(versions) if !versions.is_empty() => versions.last().unwrap().clone(),
            _ => current.clone(),
        };

        let status: &'static str = if latest <= current {
            "up-to-date"
        } else if latest.major > current.major {
            "major update"
        } else if latest.minor > current.minor {
            "minor update"
        } else {
            "patch update"
        };

        entries.push(OutdatedEntry { name: name.clone(), current, latest, status });
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));

    if as_json {
        println!("[");
        let last = entries.len().saturating_sub(1);
        for (i, e) in entries.iter().enumerate() {
            let comma = if i < last { "," } else { "" };
            println!(
                "  {{\"package\": \"{}\", \"current\": \"{}\", \"latest\": \"{}\", \"status\": \"{}\"}}{} ",
                e.name, e.current, e.latest, e.status, comma
            );
        }
        println!("]");
        return Ok(());
    }

    let col_name = entries.iter().map(|e| e.name.len()).max().unwrap_or(7).max(7);
    let col_cur  = entries.iter().map(|e| e.current.to_string().len()).max().unwrap_or(7).max(7);
    let col_lat  = entries.iter().map(|e| e.latest.to_string().len()).max().unwrap_or(6).max(6);

    eprintln!("{:<cn$}  {:<cc$}  {:<cl$}  {}",
        "Package", "Current", "Latest", "Status",
        cn = col_name, cc = col_cur, cl = col_lat);
    eprintln!("{}", "-".repeat(col_name + col_cur + col_lat + 22));

    for e in &entries {
        let marker = match e.status {
            "up-to-date"   => "  (up to date)",
            "patch update" => "  ! patch",
            "minor update" => "  !! minor",
            "major update" => "  !!! MAJOR",
            _              => "",
        };
        eprintln!("{:<cn$}  {:<cc$}  {:<cl$}{}",
            e.name, e.current.to_string(), e.latest.to_string(), marker,
            cn = col_name, cc = col_cur, cl = col_lat);
    }

    let outdated_count = entries.iter().filter(|e| e.status != "up-to-date").count();
    if outdated_count == 0 {
        eprintln!("\nAll {} dependencies are up to date.", entries.len());
    } else {
        eprintln!("\n{} of {} dependencies have updates available.", outdated_count, entries.len());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_project_root() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("a").join("b").join("c");
        fs::create_dir_all(&sub).unwrap();
        fs::write(tmp.path().join("tallow.toml"), "[package]\nname = \"test\"\nversion = \"1.0.0\"\n").unwrap();

        let root = find_project_root(&sub).unwrap();
        assert_eq!(root, tmp.path());
    }

    #[test]
    fn test_find_project_root_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("empty");
        fs::create_dir_all(&sub).unwrap();
        assert!(find_project_root(&sub).is_err());
    }

    #[test]
    fn test_default_registry_path() {
        let path = default_registry_path();
        assert!(path.to_string_lossy().contains("tallow"));
    }

    #[test]
    fn test_find_workspace_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join("tallow.toml"), "[workspace]\nmembers = [\"packages/*\"]\n").unwrap();
        let sub = root.join("packages").join("a");
        fs::create_dir_all(&sub).unwrap();

        let found = find_workspace_root(&sub);
        assert!(found.is_some());
        assert_eq!(found.unwrap(), root);
    }

    #[test]
    fn test_workspace_auto_install() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        // Workspace root
        fs::write(root.join("tallow.toml"), "[workspace]\nmembers = [\"packages/*\"]\n").unwrap();

        // Member a: no external deps
        let pkg_a = root.join("packages").join("a");
        fs::create_dir_all(pkg_a.join("src")).unwrap();
        fs::write(pkg_a.join("tallow.toml"), "[package]\nname = \"a\"\nversion = \"1.0.0\"\n").unwrap();
        fs::write(pkg_a.join("src").join("main.tl"), "fn main() {}\n").unwrap();

        // Member b: depends on a
        let pkg_b = root.join("packages").join("b");
        fs::create_dir_all(pkg_b.join("src")).unwrap();
        fs::write(pkg_b.join("tallow.toml"), "[package]\nname = \"b\"\nversion = \"2.0.0\"\n\n[dependencies]\na = { path = \"../a\" }\n").unwrap();
        fs::write(pkg_b.join("src").join("main.tl"), "fn main() {}\n").unwrap();

        // Create a registry (empty, since all deps are local)
        let reg_dir = tmp.path().join("test-registry");
        fs::create_dir_all(&reg_dir).unwrap();

        // Run workspace-aware auto-install from member b's source file
        let source = pkg_b.join("src").join("main.tl");
        let result = auto_install_workspace_aware(&source, &reg_dir);
        assert!(result.is_ok(), "workspace auto-install failed: {:?}", result.err());

        // Verify lockfile was created at workspace root
        assert!(root.join("tallow.lock").exists(), "tallow.lock should exist at workspace root");
    }

    #[test]
    fn test_pkg_why_not_in_lockfile() {
        let tmp = tempfile::tempdir().unwrap();
        let lock_content = "# tallow.lock -- DO NOT EDIT\n# Generated by tallow package manager\nlockfile-version = 1\n\n[[package]]\nname = \"blake3\"\nversion = \"1.8.0\"\nintegrity = \"blake3:\"\ndependencies = []\n";
        fs::write(tmp.path().join("tallow.lock"), lock_content).unwrap();
        let result = pkg_why("nonexistent", false, tmp.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not in tallow.lock"));
    }

    #[test]
    fn test_pkg_why_root_dep() {
        let tmp = tempfile::tempdir().unwrap();
        let lock_content = "# tallow.lock -- DO NOT EDIT\n# Generated by tallow package manager\nlockfile-version = 1\n\n[[package]]\nname = \"blake3\"\nversion = \"1.8.0\"\nintegrity = \"blake3:\"\ndependencies = []\n";
        fs::write(tmp.path().join("tallow.lock"), lock_content).unwrap();
        let result = pkg_why("blake3", false, tmp.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_pkg_why_transitive() {
        let tmp = tempfile::tempdir().unwrap();
        // serde_derive is required by serde; serde is a root dep
        let lock_content = "# tallow.lock -- DO NOT EDIT\nlockfile-version = 1\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nintegrity = \"blake3:\"\ndependencies = [\"serde_derive\"]\n\n[[package]]\nname = \"serde_derive\"\nversion = \"1.0.0\"\nintegrity = \"blake3:\"\ndependencies = []\n";
        fs::write(tmp.path().join("tallow.lock"), lock_content).unwrap();
        // serde_derive should trace back through serde to root
        let result = pkg_why("serde_derive", false, tmp.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_pkg_tree_no_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let result = pkg_tree(10, false, tmp.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no tallow.toml"));
    }

    #[test]
    fn test_pkg_tree_json_no_deps() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("tallow.toml"),
            "[package]\nname = \"myapp\"\nversion = \"0.1.0\"\n",
        ).unwrap();
        let result = pkg_tree(10, true, tmp.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_cache_format_bytes() {
        assert_eq!(cache_format_bytes(0), "0 B");
        assert_eq!(cache_format_bytes(512), "512 B");
        assert_eq!(cache_format_bytes(1_024), "1.0 KB");
        assert_eq!(cache_format_bytes(1_048_576), "1.0 MB");
    }

    #[test]
    fn test_pkg_cache_info_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let result = pkg_cache_info(tmp.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_pkg_cache_clean_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let result = pkg_cache_clean(tmp.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_pkg_cache_verify_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let result = pkg_cache_verify(tmp.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_pkg_cache_prune_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let result = pkg_cache_prune(tmp.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_pkg_outdated_no_lockfile() {
        let tmp = tempfile::tempdir().unwrap();
        let result = pkg_outdated(false, tmp.path(), tmp.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("tallow.lock"));
    }

    #[test]
    fn test_pkg_outdated_empty_lockfile() {
        let tmp = tempfile::tempdir().unwrap();
        let lock_content = "# tallow.lock -- DO NOT EDIT\nlockfile-version = 1\n";
        fs::write(tmp.path().join("tallow.lock"), lock_content).unwrap();
        let result = pkg_outdated(false, tmp.path(), tmp.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_pkg_patch_remove_no_patch() {
        let tmp = tempfile::tempdir().unwrap();
        let result = pkg_patch_remove("nonexistent", tmp.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no patch found"));
    }

    #[test]
    fn test_pkg_patch_no_lockfile() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = tmp.path().join("registry");
        fs::create_dir_all(&reg).unwrap();
        let result = pkg_patch("somepkg", None, tmp.path(), &reg);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("tallow.lock"));
    }

    #[test]
    fn test_pkg_patch_commit_missing_dir() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("tallow.toml"), "[package]\nname = \"myapp\"\nversion = \"1.0.0\"\n").unwrap();
        let result = pkg_patch_commit(&tmp.path().join("nonexistent-edit"), tmp.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }
}
