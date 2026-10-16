use tallow::pkg::registry::LocalRegistry;
use tallow::pkg::resolver::PackageRegistry;
use tallow::pkg::cache::GlobalCache;
use semver::Version;
use std::fs;
use std::path::Path;

/// Helper: create a minimal project directory with tallow.toml and src/main.tl
fn create_test_project(dir: &Path, name: &str, version: &str, deps: &[(&str, &str)]) {
    fs::create_dir_all(dir.join("src")).unwrap();
    let dep_lines: Vec<String> = deps.iter().map(|(n, v)| format!("{n} = \"{v}\"")).collect();
    let dep_section = if dep_lines.is_empty() {
        String::new()
    } else {
        format!("\n[dependencies]\n{}\n", dep_lines.join("\n"))
    };
    let toml = format!(
        r#"[package]
name = "{name}"
version = "{version}"
{dep_section}"#
    );
    fs::write(dir.join("tallow.toml"), toml).unwrap();
    fs::write(dir.join("src").join("main.tl"), "fn main() { print(\"hello\") }\n").unwrap();
}

#[test]
fn test_publish_creates_archive_in_registry() {
    let tmp = tempfile::tempdir().unwrap();
    let registry_root = tmp.path().join("registry");
    let cache_root = tmp.path().join("cache");
    let project_dir = tmp.path().join("myproject");

    create_test_project(&project_dir, "mypkg", "1.0.0", &[]);

    let cache = GlobalCache::new(cache_root);
    let registry = LocalRegistry::open(registry_root.clone(), cache);
    registry.publish_package(&project_dir).unwrap();

    // Verify directory structure: packages/mypkg/1.0.0/mypkg-1.0.0.tar.zst
    let archive_path = registry_root
        .join("packages")
        .join("mypkg")
        .join("1.0.0")
        .join("mypkg-1.0.0.tar.zst");
    assert!(archive_path.exists(), "archive should exist at {}", archive_path.display());

    // Verify metadata.json exists
    let metadata_path = registry_root
        .join("packages")
        .join("mypkg")
        .join("1.0.0")
        .join("metadata.json");
    assert!(metadata_path.exists(), "metadata.json should exist");

    // Verify index.json updated
    let index_path = registry_root.join("index.json");
    assert!(index_path.exists(), "index.json should exist");
    let index_content = fs::read_to_string(&index_path).unwrap();
    assert!(index_content.contains("mypkg"), "index should contain package name");
    assert!(index_content.contains("1.0.0"), "index should contain version");
}

#[test]
fn test_available_versions_lists_published() {
    let tmp = tempfile::tempdir().unwrap();
    let registry_root = tmp.path().join("registry");
    let cache_root = tmp.path().join("cache");

    let cache = GlobalCache::new(cache_root);
    let registry = LocalRegistry::open(registry_root, cache);

    // Publish two versions
    let project_v1 = tmp.path().join("proj_v1");
    create_test_project(&project_v1, "mypkg", "1.0.0", &[]);
    registry.publish_package(&project_v1).unwrap();

    let project_v2 = tmp.path().join("proj_v2");
    create_test_project(&project_v2, "mypkg", "2.0.0", &[]);
    registry.publish_package(&project_v2).unwrap();

    let versions = registry.available_versions("mypkg").unwrap();
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0], Version::new(1, 0, 0));
    assert_eq!(versions[1], Version::new(2, 0, 0));

    // Non-existent package returns empty
    let empty = registry.available_versions("nonexistent").unwrap();
    assert!(empty.is_empty());
}

#[test]
fn test_fetch_package_stores_in_cache() {
    let tmp = tempfile::tempdir().unwrap();
    let registry_root = tmp.path().join("registry");
    let cache_root = tmp.path().join("cache");
    let project_dir = tmp.path().join("myproject");

    create_test_project(&project_dir, "mypkg", "1.0.0", &[]);

    let cache = GlobalCache::new(cache_root.clone());
    let registry = LocalRegistry::open(registry_root, cache);
    registry.publish_package(&project_dir).unwrap();

    let cache_path = registry.fetch_package("mypkg", &Version::new(1, 0, 0)).unwrap();
    assert!(cache_path.exists(), "cached path should exist: {}", cache_path.display());

    // Verify the cached content includes tallow.toml
    assert!(cache_path.join("tallow.toml").exists(), "cached package should contain tallow.toml");
}

#[test]
fn test_dependencies_returns_correct_deps() {
    let tmp = tempfile::tempdir().unwrap();
    let registry_root = tmp.path().join("registry");
    let cache_root = tmp.path().join("cache");
    let project_dir = tmp.path().join("myproject");

    create_test_project(&project_dir, "mypkg", "1.0.0", &[("foo", "^1.0"), ("bar", "~2.3")]);

    let cache = GlobalCache::new(cache_root);
    let registry = LocalRegistry::open(registry_root, cache);
    registry.publish_package(&project_dir).unwrap();

    let deps = registry.dependencies("mypkg", &Version::new(1, 0, 0)).unwrap();
    assert_eq!(deps.len(), 2);
    assert!(deps.contains_key("foo"), "should have foo dependency");
    assert!(deps.contains_key("bar"), "should have bar dependency");

    // Verify the VersionReq matches expected versions
    assert!(deps["foo"].matches(&Version::new(1, 5, 0)));
    assert!(!deps["foo"].matches(&Version::new(2, 0, 0)));
}

#[test]
fn test_publish_duplicate_version_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let registry_root = tmp.path().join("registry");
    let cache_root = tmp.path().join("cache");

    let cache = GlobalCache::new(cache_root);
    let registry = LocalRegistry::open(registry_root, cache);

    let project_dir = tmp.path().join("proj1");
    create_test_project(&project_dir, "mypkg", "1.0.0", &[]);
    registry.publish_package(&project_dir).unwrap();

    // Second publish of same version should fail
    let project_dir2 = tmp.path().join("proj2");
    create_test_project(&project_dir2, "mypkg", "1.0.0", &[]);
    let result = registry.publish_package(&project_dir2);
    assert!(result.is_err(), "publishing same version twice should fail");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("already exists") || err_msg.contains("already published"),
        "error should mention duplicate: {err_msg}"
    );
}
