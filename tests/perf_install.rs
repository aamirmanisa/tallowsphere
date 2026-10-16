use tallow::pkg::cache::GlobalCache;
use tallow::pkg::cli::pkg_install;
use tallow::pkg::registry::LocalRegistry;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Helper: create and publish a test package to a registry.
fn publish_test_package(
    registry: &LocalRegistry,
    tmp: &Path,
    name: &str,
    version: &str,
    deps: &[(&str, &str)],
) {
    let pkg_dir = tmp.join(format!("__pub_{}_{}", name, version.replace('.', "_")));
    fs::create_dir_all(pkg_dir.join("src")).unwrap();

    let dep_lines: Vec<String> = deps.iter().map(|(n, v)| format!("{n} = \"{v}\"")).collect();
    let dep_section = if dep_lines.is_empty() {
        String::new()
    } else {
        format!("\n[dependencies]\n{}\n", dep_lines.join("\n"))
    };
    let toml = format!(
        "[package]\nname = \"{name}\"\nversion = \"{version}\"\n{dep_section}"
    );
    fs::write(pkg_dir.join("tallow.toml"), &toml).unwrap();
    fs::write(
        pkg_dir.join("src").join("main.tl"),
        format!("let x = 42\n"),
    )
    .unwrap();
    registry.publish_package(&pkg_dir).unwrap();
}

/// Create a synthetic ecosystem of 50 packages in a temp directory.
///
/// - Packages `pkg-001` through `pkg-040` have no dependencies.
/// - Packages `pkg-041` through `pkg-050` each depend on one of `pkg-001`..`pkg-010`.
/// - A project is created that depends on all 50 packages with `*` version constraints.
///
/// Returns (project_dir, registry_path).
fn create_test_ecosystem(tmp: &Path) -> (PathBuf, PathBuf) {
    let registry_path = tmp.join("registry");
    let cache = GlobalCache::new(registry_path.join(".cache"));
    let registry = LocalRegistry::open(registry_path.clone(), cache);

    // Publish 50 packages
    for i in 1..=50 {
        let name = format!("pkg-{:03}", i);
        let deps: Vec<(&str, &str)> = if i > 40 {
            // Packages 41-50 depend on one of packages 1-10
            let dep_idx = ((i - 41) % 10) + 1;
            let dep_name_owned = format!("pkg-{:03}", dep_idx);
            // We need to leak the string to get a &str with 'static lifetime
            // for this test helper. This is fine for test code.
            let dep_name: &str = Box::leak(dep_name_owned.into_boxed_str());
            vec![(dep_name, "*")]
        } else {
            vec![]
        };
        publish_test_package(&registry, tmp, &name, "1.0.0", &deps);
    }

    // Create project that depends on all 50
    let project_dir = tmp.join("project");
    fs::create_dir_all(&project_dir).unwrap();

    let mut toml = String::from("[package]\nname = \"perf-test\"\nversion = \"1.0.0\"\n\n[dependencies]\n");
    for i in 1..=50 {
        toml.push_str(&format!("pkg-{:03} = \"*\"\n", i));
    }
    fs::write(project_dir.join("tallow.toml"), &toml).unwrap();

    (project_dir, registry_path)
}

/// Perform a full cold install: resolve deps, fetch, generate lockfile, link.
fn cold_install(project_dir: &Path, registry_path: &Path) {
    use tallow::pkg::cache::GlobalCache;
    use tallow::pkg::cli::pkg_update;

    // pkg_update does resolve_and_link (resolve, fetch, lock, link)
    pkg_update(project_dir, registry_path).unwrap();
}

#[test]
fn perf_cold_install() {
    let tmp = tempfile::tempdir().unwrap();
    let (project_dir, registry_path) = create_test_ecosystem(tmp.path());

    let start = Instant::now();
    cold_install(&project_dir, &registry_path);
    let elapsed = start.elapsed();

    eprintln!("--- PERF: Cold install (50 deps) ---");
    eprintln!("  Elapsed: {:.3}s ({} ms)", elapsed.as_secs_f64(), elapsed.as_millis());

    // Verify all 50 packages are linked
    let modules_dir = project_dir.join("tallow_modules");
    assert!(modules_dir.exists(), "tallow_modules should exist");
    for i in 1..=50 {
        let pkg_dir = modules_dir.join(format!("pkg-{:03}", i));
        assert!(pkg_dir.exists(), "tallow_modules/pkg-{:03} should exist", i);
    }

    // Verify lockfile was created
    assert!(project_dir.join("tallow.lock").exists(), "tallow.lock should exist");

    // PERF-01: Cold install < 2 seconds
    assert!(
        elapsed.as_secs_f64() < 2.0,
        "Cold install took {:.3}s, expected < 2.0s",
        elapsed.as_secs_f64()
    );
}

#[test]
fn perf_warm_install() {
    let tmp = tempfile::tempdir().unwrap();
    let (project_dir, registry_path) = create_test_ecosystem(tmp.path());

    // Do a cold install first to populate cache + lockfile
    cold_install(&project_dir, &registry_path);

    // Delete tallow_modules/ but keep tallow.lock and cache intact
    let modules_dir = project_dir.join("tallow_modules");
    assert!(modules_dir.exists(), "tallow_modules should exist after cold install");
    fs::remove_dir_all(&modules_dir).unwrap();
    assert!(!modules_dir.exists(), "tallow_modules should be deleted");

    // Warm install: lockfile exists, cache populated, just needs symlinks/junctions
    let start = Instant::now();
    pkg_install(&project_dir, &registry_path, false).unwrap();
    let elapsed = start.elapsed();

    eprintln!("--- PERF: Warm install (50 deps) ---");
    eprintln!("  Elapsed: {:.3}s ({} ms)", elapsed.as_secs_f64(), elapsed.as_millis());

    // Verify all 50 packages are linked
    let modules_dir = project_dir.join("tallow_modules");
    assert!(modules_dir.exists(), "tallow_modules should exist after warm install");
    for i in 1..=50 {
        let pkg_dir = modules_dir.join(format!("pkg-{:03}", i));
        assert!(pkg_dir.exists(), "tallow_modules/pkg-{:03} should exist after warm install", i);
    }

    // PERF-02: Warm install < 500ms (generous bound for Windows junction overhead)
    // Actual target is < 100ms but Windows junctions can be slower
    assert!(
        elapsed.as_secs_f64() < 0.5,
        "Warm install took {:.3}s, expected < 0.5s",
        elapsed.as_secs_f64()
    );
}
