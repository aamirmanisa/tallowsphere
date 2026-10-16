// Tallow Package Manager CLI (`tallow-pm`)
//
// Commands:
//   init           Create a new Tallow project (tallow.toml + src/main.tl)
//   build          Compile the project
//   run            Build and run the project
//   add <pkg>      Add a dependency to tallow.toml
//   test           Run tests
//
// Architecture:
//   - `add` uses the tallow::pkg library directly (pubgrub resolver, content-addressed cache)
//   - `build` / `run` / `test` delegate to the `tallow` compiler binary
//   - `init` creates project scaffolding independently

use std::path::{Path, PathBuf};
use std::process;

/// Find the tallow compiler binary.
///
/// Searches:
/// 1. Same directory as the current running binary (so `tallow-pm` next to `tallow`)
/// 2. PATH
fn find_tallow_binary() -> Option<PathBuf> {
    // Look alongside the current executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("tallow");
            if candidate.exists() {
                return Some(candidate);
            }
            // Windows
            let candidate_exe = dir.join("tallow.exe");
            if candidate_exe.exists() {
                return Some(candidate_exe);
            }
        }
    }
    // Fall back to PATH
    let name = if cfg!(windows) { "tallow.exe" } else { "tallow" };
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Run the tallow compiler binary with the given arguments.
fn run_tallow(args: &[&str]) -> Result<(), String> {
    let binary = find_tallow_binary()
        .ok_or_else(|| "tallow compiler not found. Is it installed? Run `cargo build --bin tallow`.".to_string())?;
    let status = process::Command::new(&binary)
        .args(args)
        .status()
        .map_err(|e| format!("failed to run tallow ({}): {}", binary.display(), e))?;
    if !status.success() {
        return Err(format!("tallow exited with {}", status));
    }
    Ok(())
}

// ── init ──────────────────────────────────────────────────────────────────────

fn cmd_init(name: Option<&str>) -> Result<(), String> {
    let dir = if let Some(n) = name {
        let p = PathBuf::from(n);
        if p.exists() {
            return Err(format!("directory '{}' already exists", n));
        }
        p
    } else {
        PathBuf::from(".")
    };

    let toml_path = if name.is_some() {
        let _ = std::fs::create_dir_all(&dir);
        dir.join("tallow.toml")
    } else {
        let p = PathBuf::from("tallow.toml");
        if p.exists() {
            return Err("tallow.toml already exists in current directory".to_string());
        }
        p
    };

    // Derive package name from directory name
    let pkg_name = if let Some(n) = name {
        n.to_string()
    } else if let Ok(cwd) = std::env::current_dir() {
        cwd.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("my-project")
            .to_string()
    } else {
        "my-project".to_string()
    };

    // Create tallow.toml
    let toml_content = format!(
        r#"[package]
name    = "{pkg_name}"
version = "0.1.0"
author  = ""
license = "MIT"

[dependencies]
"#
    );
    std::fs::write(&toml_path, &toml_content)
        .map_err(|e| format!("failed to write {}: {}", toml_path.display(), e))?;
    eprintln!("created {}", toml_path.display());

    // Create src/main.tl
    let src_dir = if name.is_some() {
        dir.join("src")
    } else {
        PathBuf::from("src")
    };
    std::fs::create_dir_all(&src_dir)
        .map_err(|e| format!("failed to create src/: {}", e))?;

    let main_tl = src_dir.join("main.tl");
    let main_content = format!(
        r#"fn main() {{
    print("hello from {pkg_name}")
}}
"#
    );
    std::fs::write(&main_tl, &main_content)
        .map_err(|e| format!("failed to write {}: {}", main_tl.display(), e))?;
    eprintln!("created {}", main_tl.display());

    // Create tests/ directory
    let tests_dir = if name.is_some() {
        dir.join("tests")
    } else {
        PathBuf::from("tests")
    };
    let _ = std::fs::create_dir_all(&tests_dir);

    eprintln!("project {pkg_name} initialized");
    Ok(())
}

// ── build ─────────────────────────────────────────────────────────────────────

fn cmd_build(release: bool) -> Result<(), String> {
    let project_dir = tallow::pkg::cli::find_project_root(&std::env::current_dir()
        .map_err(|e| format!("current_dir: {}", e))?)
        .map_err(|e| format!("{}", e))?;

    // Auto-install deps if needed
    auto_install(&project_dir)?;

    let main_file = find_main_file(&project_dir)?;
    let mut args = vec!["build", &main_file];
    if release {
        args.push("--release");
    }
    let args_str: Vec<&str> = args.iter().map(|s| *s).collect();
    run_tallow(&args_str)
}

// ── run ───────────────────────────────────────────────────────────────────────

fn cmd_run(args: &[String]) -> Result<(), String> {
    let project_dir = tallow::pkg::cli::find_project_root(&std::env::current_dir()
        .map_err(|e| format!("current_dir: {}", e))?)
        .map_err(|e| format!("{}", e))?;

    // Auto-install deps if needed
    auto_install(&project_dir)?;

    let main_file = find_main_file(&project_dir)?;
    let mut tallow_args: Vec<String> = vec!["run".to_string(), main_file];
    if !args.is_empty() {
        tallow_args.push("--".to_string());
        tallow_args.extend(args.iter().cloned());
    }
    let tallow_args_str: Vec<&str> = tallow_args.iter().map(|s| s.as_str()).collect();
    run_tallow(&tallow_args_str)
}

// ── add ───────────────────────────────────────────────────────────────────────

fn cmd_add(package: &str, version: Option<&str>, path_dep: Option<&str>, registry: Option<&str>) -> Result<(), String> {
    let project_dir = tallow::pkg::cli::find_project_root(&std::env::current_dir()
        .map_err(|e| format!("current_dir: {}", e))?)
        .map_err(|e| format!("{}", e))?;

    let registry_path = if let Some(r) = registry {
        PathBuf::from(r)
    } else {
        tallow::pkg::cli::default_registry_path()
    };

    // If this is a local path dependency, add it directly to tallow.toml
    if let Some(path) = path_dep {
        let toml_path = project_dir.join("tallow.toml");
        let toml_content = std::fs::read_to_string(&toml_path)
            .map_err(|e| format!("failed to read {}: {}", toml_path.display(), e))?;

        let mut doc: toml_edit::DocumentMut = toml_content
            .parse::<toml_edit::DocumentMut>()
            .map_err(|e| format!("failed to parse tallow.toml: {}", e))?;

        // Ensure [dependencies] table exists
        if doc.get("dependencies").is_none() {
            doc["dependencies"] = toml_edit::Item::Table(toml_edit::Table::new());
        }

        // Canonicalize the path
        let abs_path = std::path::absolute(Path::new(path))
            .map_err(|e| format!("invalid path '{}': {}", path, e))?;
        let path_str = abs_path.to_string_lossy().to_string();

        // Add as table: { package = { path = "..." } }
        let mut dep_table = toml_edit::InlineTable::new();
        dep_table.insert("path", path_str.as_str().into());
        doc["dependencies"][package] = toml_edit::value(toml_edit::Value::InlineTable(dep_table));

        std::fs::write(&toml_path, doc.to_string())
            .map_err(|e| format!("failed to write {}: {}", toml_path.display(), e))?;

        eprintln!("added {} (path = \"{}\")", package, path_str);
        return Ok(());
    }

    // Use the pkg library for registry-based resolution
    tallow::pkg::cli::pkg_add(package, version, &project_dir, &registry_path)
        .map_err(|e| format!("{}", e))
}

// ── test ─────────────────────────────────────────────────────────────────────

fn cmd_test(filter: Option<&str>) -> Result<(), String> {
    let project_dir = tallow::pkg::cli::find_project_root(&std::env::current_dir()
        .map_err(|e| format!("current_dir: {}", e))?)
        .map_err(|e| format!("{}", e))?;

    // Auto-install deps if needed
    auto_install(&project_dir)?;

    let mut args = vec!["test".to_string()];
    if let Some(f) = filter {
        args.push("--filter".to_string());
        args.push(f.to_string());
    }
    let args_str: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run_tallow(&args_str)
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Find src/main.tl or main.tl in the project root.
fn find_main_file(project_dir: &Path) -> Result<String, String> {
    let candidates = [
        project_dir.join("src").join("main.tl"),
        project_dir.join("main.tl"),
    ];
    for c in &candidates {
        if c.exists() {
            return Ok(c.to_string_lossy().to_string());
        }
    }
    Err("no main.tl found (looked for src/main.tl and main.tl)".to_string())
}

/// Auto-install dependencies if tallow.toml exists and has deps.
fn auto_install(project_dir: &Path) -> Result<(), String> {
    let toml_path = project_dir.join("tallow.toml");
    if !toml_path.exists() {
        return Ok(());
    }

    let manifest = tallow::pkg::manifest::parse_manifest_file(&toml_path)
        .map_err(|e| format!("failed to parse {}: {}", toml_path.display(), e))?;

    if manifest.dependencies.is_empty() {
        return Ok(());
    }

    // Check if tallow_modules/ already has everything
    let modules_dir = project_dir.join("tallow_modules");
    let lock_path = project_dir.join("tallow.lock");

    if lock_path.exists() && modules_dir.exists() {
        let lockfile = tallow::pkg::lockfile::read_lockfile(&lock_path)
            .map_err(|e| format!("failed to read lockfile: {}", e))?;
        let all_present = lockfile.packages.keys().all(|name| modules_dir.join(name).exists());
        if all_present {
            return Ok(());
        }
    }

    // Install deps
    let registry_path = tallow::pkg::cli::default_registry_path();
    let cache = tallow::pkg::cache::GlobalCache::new(registry_path.join(".cache"));
    let registry = tallow::pkg::registry::LocalRegistry::open(registry_path, cache);
    let resolved = tallow::pkg::resolver::resolve_dependencies(&manifest, &registry)
        .map_err(|e| format!("dependency resolution failed: {}", e))?;

    // Fetch and link
    for (name, version) in &resolved {
        registry.fetch_package(name, version)
            .map_err(|e| format!("failed to fetch {} {}: {}", name, version, e))?;
    }

    let content_hashes = std::collections::HashMap::new(); // Will be populated by registry metadata
    let lockfile = tallow::pkg::lockfile::generate_lockfile(&resolved, &registry, &content_hashes);
    tallow::pkg::lockfile::write_lockfile(&lockfile, &lock_path)
        .map_err(|e| format!("failed to write lockfile: {}", e))?;
    tallow::pkg::cache::GlobalCache::new(
        tallow::pkg::cli::default_registry_path().join(".cache"),
    )
    .link_all(&lockfile, project_dir)
        .map_err(|e| format!("failed to link deps: {}", e))?;

    let count = resolved.len();
    eprintln!("installed {} dependenc{}", count, if count == 1 { "y" } else { "ies" });
    Ok(())
}

// ── CLI ───────────────────────────────────────────────────────────────────────

fn print_usage() {
    eprintln!("Tallow Package Manager (tallow-pm)");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  init [name]              Create a new Tallow project");
    eprintln!("  build [--release]        Compile the project");
    eprintln!("  run [-- <args>]          Build and run the project");
    eprintln!("  add <package> [options]  Add a dependency");
    eprintln!("  test [--filter <name>]   Run tests");
    eprintln!();
    eprintln!("Add options:");
    eprintln!("  --version <ver>   Version requirement (e.g., '^1.0')");
    eprintln!("  --path <path>     Local path dependency");
    eprintln!("  --registry <path> Registry path (default: ~/.tallow/registry)");
    eprintln!();
    eprintln!("Cache: ~/.tallow/cache/");
    eprintln!("Manifest: tallow.toml");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    let result = match args[1].as_str() {
        "init" => {
            let name = args.get(2).map(|s| s.as_str());
            cmd_init(name)
        }
        "build" => {
            let release = args.iter().any(|a| a == "--release");
            cmd_build(release)
        }
        "run" => {
            // Collect args after --
            let user_args: Vec<String> = if let Some(pos) = args.iter().position(|a| a == "--") {
                args[pos + 1..].to_vec()
            } else {
                args[2..].to_vec()
            };
            cmd_run(&user_args)
        }
        "add" => {
            let package = match args.get(2) {
                Some(p) => p.as_str(),
                None => {
                    eprintln!("error: add requires a package name");
                    eprintln!("usage: tallow-pm add <package> [--version <ver>] [--path <path>]");
                    process::exit(1);
                }
            };

            let mut version: Option<&str> = None;
            let mut path_dep: Option<&str> = None;
            let mut registry: Option<&str> = None;

            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--version" => {
                        i += 1;
                        version = args.get(i).map(|s| s.as_str());
                    }
                    "--path" => {
                        i += 1;
                        path_dep = args.get(i).map(|s| s.as_str());
                    }
                    "--registry" => {
                        i += 1;
                        registry = args.get(i).map(|s| s.as_str());
                    }
                    other if !other.starts_with("--") => {
                        // positional args after add are ignored (already captured package)
                    }
                    _ => {}
                }
                i += 1;
            }
            cmd_add(package, version, path_dep, registry)
        }
        "test" => {
            let mut filter: Option<&str> = None;
            let mut i = 2;
            while i < args.len() {
                if args[i] == "--filter" {
                    i += 1;
                    filter = args.get(i).map(|s| s.as_str());
                }
                i += 1;
            }
            cmd_test(filter)
        }
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        other => {
            eprintln!("error: unknown command '{}'", other);
            print_usage();
            process::exit(1);
        }
    };

    match result {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    }
}
