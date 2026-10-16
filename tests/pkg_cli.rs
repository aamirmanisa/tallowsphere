use tallow::pkg::cache::GlobalCache;
use tallow::pkg::cli::{pkg_add, pkg_remove, pkg_update, pkg_install, auto_install_with_registry};
use tallow::pkg::registry::LocalRegistry;
use std::fs;
use std::path::Path;

/// Helper: create a minimal project directory with tallow.toml
fn create_project(dir: &Path, name: &str, version: &str) {
    fs::create_dir_all(dir).unwrap();
    let toml = format!(
        "[package]\nname = \"{name}\"\nversion = \"{version}\"\n"
    );
    fs::write(dir.join("tallow.toml"), toml).unwrap();
}

/// Helper: create and publish a test package to a registry
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
    fs::write(pkg_dir.join("src").join("main.tl"), "fn main() { }\n").unwrap();
    registry.publish_package(&pkg_dir).unwrap();
}

/// Helper: set up temp dirs and return (project_dir, registry_path, registry, cache)
fn setup() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("project");
    let registry_path = tmp.path().join("registry");
    (tmp, project_dir, registry_path)
}

fn make_registry(registry_path: &Path) -> (LocalRegistry, GlobalCache) {
    let cache = GlobalCache::new(registry_path.join(".cache"));
    let registry = LocalRegistry::open(registry_path.to_path_buf(), cache.clone());
    (registry, cache)
}

#[test]
fn test_pkg_add_creates_dependency() {
    let (tmp, project_dir, registry_path) = setup();
    create_project(&project_dir, "myapp", "1.0.0");
    let (registry, _cache) = make_registry(&registry_path);

    // Publish foo 1.0.0
    publish_test_package(&registry, tmp.path(), "foo", "1.0.0", &[]);

    // Add foo
    pkg_add("foo", None, &project_dir, &registry_path).unwrap();

    // Verify tallow.toml has foo
    let toml_content = fs::read_to_string(project_dir.join("tallow.toml")).unwrap();
    assert!(toml_content.contains("foo"), "tallow.toml should contain foo dependency");

    // Verify tallow.lock exists with foo
    let lock_path = project_dir.join("tallow.lock");
    assert!(lock_path.exists(), "tallow.lock should exist");
    let lock_content = fs::read_to_string(&lock_path).unwrap();
    assert!(lock_content.contains("foo"), "tallow.lock should contain foo");
    assert!(lock_content.contains("1.0.0"), "tallow.lock should contain version 1.0.0");

    // Verify tallow_modules/foo exists
    let modules_foo = project_dir.join("tallow_modules").join("foo");
    assert!(modules_foo.exists(), "tallow_modules/foo should exist");
}

#[test]
fn test_pkg_add_with_version() {
    let (tmp, project_dir, registry_path) = setup();
    create_project(&project_dir, "myapp", "1.0.0");
    let (registry, _cache) = make_registry(&registry_path);

    publish_test_package(&registry, tmp.path(), "foo", "1.0.0", &[]);
    publish_test_package(&registry, tmp.path(), "foo", "1.1.0", &[]);

    // Add with explicit version constraint
    pkg_add("foo", Some("^1.0"), &project_dir, &registry_path).unwrap();

    let toml_content = fs::read_to_string(project_dir.join("tallow.toml")).unwrap();
    assert!(toml_content.contains("\"^1.0\""), "tallow.toml should contain ^1.0 constraint");

    // Lock should resolve to highest compatible: 1.1.0
    let lock_content = fs::read_to_string(project_dir.join("tallow.lock")).unwrap();
    assert!(lock_content.contains("1.1.0"), "lockfile should resolve to 1.1.0");
}

#[test]
fn test_pkg_remove_deletes_dependency() {
    let (tmp, project_dir, registry_path) = setup();
    create_project(&project_dir, "myapp", "1.0.0");
    let (registry, _cache) = make_registry(&registry_path);

    publish_test_package(&registry, tmp.path(), "foo", "1.0.0", &[]);

    // Add then remove
    pkg_add("foo", None, &project_dir, &registry_path).unwrap();
    assert!(project_dir.join("tallow_modules").join("foo").exists());

    pkg_remove("foo", &project_dir, &registry_path).unwrap();

    // Verify tallow.toml has empty deps
    let toml_content = fs::read_to_string(project_dir.join("tallow.toml")).unwrap();
    // foo should no longer be in the dependencies
    let doc: toml_edit::DocumentMut = toml_content.parse().unwrap();
    let deps = doc.get("dependencies").and_then(|d| d.as_table());
    assert!(deps.is_none() || deps.unwrap().is_empty(), "dependencies should be empty");

    // Lockfile should have no foo
    let lock_content = fs::read_to_string(project_dir.join("tallow.lock")).unwrap();
    assert!(!lock_content.contains("\"foo\""), "lockfile should not contain foo");

    // tallow_modules/foo should be gone
    assert!(!project_dir.join("tallow_modules").join("foo").exists());
}

#[test]
fn test_pkg_remove_nonexistent_fails() {
    let (_tmp, project_dir, registry_path) = setup();
    create_project(&project_dir, "myapp", "1.0.0");

    let result = pkg_remove("nonexistent", &project_dir, &registry_path);
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("not in [dependencies]"),
        "error should mention package not found"
    );
}

#[test]
fn test_pkg_update_gets_latest() {
    let (tmp, project_dir, registry_path) = setup();
    create_project(&project_dir, "myapp", "1.0.0");
    let (registry, _cache) = make_registry(&registry_path);

    // Publish 1.0.0, add it
    publish_test_package(&registry, tmp.path(), "foo", "1.0.0", &[]);
    pkg_add("foo", Some("^1.0"), &project_dir, &registry_path).unwrap();

    // Now publish 1.1.0
    publish_test_package(&registry, tmp.path(), "foo", "1.1.0", &[]);

    // Update
    pkg_update(&project_dir, &registry_path).unwrap();

    // Lock should now have 1.1.0
    let lock_content = fs::read_to_string(project_dir.join("tallow.lock")).unwrap();
    assert!(lock_content.contains("1.1.0"), "lockfile should contain updated version 1.1.0");
}

#[test]
fn test_pkg_install_from_lockfile() {
    let (tmp, project_dir, registry_path) = setup();
    create_project(&project_dir, "myapp", "1.0.0");
    let (registry, _cache) = make_registry(&registry_path);

    publish_test_package(&registry, tmp.path(), "foo", "1.0.0", &[]);
    pkg_add("foo", None, &project_dir, &registry_path).unwrap();

    // Delete tallow_modules
    let modules_dir = project_dir.join("tallow_modules");
    assert!(modules_dir.exists());
    fs::remove_dir_all(&modules_dir).unwrap();
    assert!(!modules_dir.exists());

    // Install from lockfile
    pkg_install(&project_dir, &registry_path, false).unwrap();

    // tallow_modules should be recreated
    assert!(project_dir.join("tallow_modules").join("foo").exists());
}

#[test]
fn test_pkg_install_offline_cached() {
    let (tmp, project_dir, registry_path) = setup();
    create_project(&project_dir, "myapp", "1.0.0");
    let (registry, _cache) = make_registry(&registry_path);

    publish_test_package(&registry, tmp.path(), "foo", "1.0.0", &[]);
    pkg_add("foo", None, &project_dir, &registry_path).unwrap();

    // Delete tallow_modules only (cache still populated)
    let modules_dir = project_dir.join("tallow_modules");
    fs::remove_dir_all(&modules_dir).unwrap();

    // Install offline -- should work because cache is populated
    pkg_install(&project_dir, &registry_path, true).unwrap();
    assert!(project_dir.join("tallow_modules").join("foo").exists());
}

#[test]
fn test_pkg_install_offline_uncached_fails() {
    let (tmp, project_dir, registry_path) = setup();
    create_project(&project_dir, "myapp", "1.0.0");
    let (registry, _cache) = make_registry(&registry_path);

    publish_test_package(&registry, tmp.path(), "foo", "1.0.0", &[]);
    pkg_add("foo", None, &project_dir, &registry_path).unwrap();

    // Delete BOTH tallow_modules AND the cache
    let modules_dir = project_dir.join("tallow_modules");
    let cache_dir = registry_path.join(".cache");
    fs::remove_dir_all(&modules_dir).unwrap();
    if cache_dir.exists() {
        fs::remove_dir_all(&cache_dir).unwrap();
    }

    // Install offline -- should fail because cache is empty
    let result = pkg_install(&project_dir, &registry_path, true);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not in cache") || err_msg.contains("cannot install offline"),
        "error should mention cache miss: got '{}'", err_msg
    );
}

// ── Auto-install tests ─────────────────────────────────────────────

#[test]
fn test_auto_install_standalone_script_noop() {
    let tmp = tempfile::tempdir().unwrap();
    // Just a .tl file, no tallow.toml
    let script = tmp.path().join("hello.tl");
    fs::write(&script, "fn main() { print(\"hello\") }").unwrap();

    let result = auto_install_with_registry(&script, &tmp.path().join("fake_registry"));
    assert!(result.is_ok(), "auto_install should succeed silently for standalone scripts");

    // No tallow_modules should be created
    assert!(!tmp.path().join("tallow_modules").exists());
}

#[test]
fn test_auto_install_no_deps_noop() {
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("project");
    fs::create_dir_all(&project_dir).unwrap();
    fs::write(
        project_dir.join("tallow.toml"),
        "[package]\nname = \"nodeps\"\nversion = \"1.0.0\"\n",
    ).unwrap();
    let script = project_dir.join("main.tl");
    fs::write(&script, "fn main() { }").unwrap();

    let result = auto_install_with_registry(&script, &tmp.path().join("fake_registry"));
    assert!(result.is_ok(), "auto_install should succeed silently when no deps");
    assert!(!project_dir.join("tallow_modules").exists());
}

#[test]
fn test_auto_install_creates_tallow_modules() {
    let (tmp, project_dir, registry_path) = setup();
    create_project(&project_dir, "myapp", "1.0.0");
    let (registry, _cache) = make_registry(&registry_path);

    // Publish and add foo
    publish_test_package(&registry, tmp.path(), "foo", "1.0.0", &[]);
    pkg_add("foo", None, &project_dir, &registry_path).unwrap();

    // Delete tallow_modules (lockfile remains)
    let modules_dir = project_dir.join("tallow_modules");
    assert!(modules_dir.exists());
    fs::remove_dir_all(&modules_dir).unwrap();
    assert!(!modules_dir.exists());

    // Auto-install should recreate tallow_modules/foo
    let script = project_dir.join("main.tl");
    fs::write(&script, "fn main() { }").unwrap();
    auto_install_with_registry(&script, &registry_path).unwrap();

    assert!(project_dir.join("tallow_modules").join("foo").exists(),
        "auto_install should recreate tallow_modules/foo");
}

#[test]
fn test_auto_install_skips_if_already_installed() {
    let (tmp, project_dir, registry_path) = setup();
    create_project(&project_dir, "myapp", "1.0.0");
    let (registry, _cache) = make_registry(&registry_path);

    publish_test_package(&registry, tmp.path(), "foo", "1.0.0", &[]);
    pkg_add("foo", None, &project_dir, &registry_path).unwrap();

    // tallow_modules/foo already exists -- auto_install should be a no-op
    assert!(project_dir.join("tallow_modules").join("foo").exists());

    let script = project_dir.join("main.tl");
    fs::write(&script, "fn main() { }").unwrap();
    let result = auto_install_with_registry(&script, &registry_path);
    assert!(result.is_ok(), "auto_install should succeed when already installed");
}

#[test]
fn test_install_offline_no_network() {
    // This is essentially the same as test_pkg_install_offline_cached
    // but framed as an end-to-end DX-06 validation
    let (tmp, project_dir, registry_path) = setup();
    create_project(&project_dir, "myapp", "1.0.0");
    let (registry, _cache) = make_registry(&registry_path);

    publish_test_package(&registry, tmp.path(), "bar", "2.0.0", &[]);
    pkg_add("bar", None, &project_dir, &registry_path).unwrap();

    // Delete tallow_modules only (cache still has bar)
    fs::remove_dir_all(project_dir.join("tallow_modules")).unwrap();

    // Offline install should succeed from cache
    pkg_install(&project_dir, &registry_path, true).unwrap();
    assert!(project_dir.join("tallow_modules").join("bar").exists(),
        "offline install should recreate tallow_modules/bar from cache");
}

#[test]
fn test_install_offline_missing_cache_fails() {
    let (tmp, project_dir, registry_path) = setup();
    create_project(&project_dir, "myapp", "1.0.0");
    let (registry, _cache) = make_registry(&registry_path);

    publish_test_package(&registry, tmp.path(), "baz", "1.0.0", &[]);
    pkg_add("baz", None, &project_dir, &registry_path).unwrap();

    // Delete both tallow_modules AND the cache
    fs::remove_dir_all(project_dir.join("tallow_modules")).unwrap();
    let cache_dir = registry_path.join(".cache");
    if cache_dir.exists() {
        fs::remove_dir_all(&cache_dir).unwrap();
    }

    // Offline install should fail with clear error
    let result = pkg_install(&project_dir, &registry_path, true);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not in cache") || err_msg.contains("cannot install offline"),
        "error should mention cache miss: got '{}'", err_msg
    );
}
