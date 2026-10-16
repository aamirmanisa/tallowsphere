use tallow::pkg::cache::GlobalCache;
use tallow::pkg::archive::create_archive;
use tallow::pkg::lockfile::{Lockfile, LockedPackage, LOCKFILE_VERSION};
use semver::Version;
use std::collections::BTreeMap;
use std::fs;
use tempfile::TempDir;

fn setup_package_dir(dir: &std::path::Path, name: &str, version: &str) {
    fs::write(
        dir.join("tallow.toml"),
        format!(
            r#"[package]
name = "{name}"
version = "{version}"

[dependencies]
"#
        ),
    )
    .unwrap();

    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("main.tl"), "fn main() { print(\"hello\") }\n").unwrap();
}

#[test]
fn test_store_creates_dir_by_content_hash() {
    let cache_root = TempDir::new().unwrap();
    let cache = GlobalCache::new(cache_root.path().to_path_buf());

    let pkg_dir = TempDir::new().unwrap();
    setup_package_dir(pkg_dir.path(), "mypkg", "1.0.0");

    let hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

    let cached_path = cache.store_package(hash, pkg_dir.path()).unwrap();

    // Should be stored at {root}/{hash[0..2]}/{hash}/
    assert!(cached_path.exists());
    assert!(cached_path.ends_with(hash));
    let parent = cached_path.parent().unwrap();
    assert!(parent.ends_with("ab")); // 2-char prefix shard

    // Verify contents were copied
    assert!(cached_path.join("tallow.toml").exists());
    assert!(cached_path.join("src").join("main.tl").exists());
}

#[test]
fn test_store_is_idempotent() {
    let cache_root = TempDir::new().unwrap();
    let cache = GlobalCache::new(cache_root.path().to_path_buf());

    let pkg_dir = TempDir::new().unwrap();
    setup_package_dir(pkg_dir.path(), "mypkg", "1.0.0");

    let hash = "1111111111111111111111111111111111111111111111111111111111111111";

    let path1 = cache.store_package(hash, pkg_dir.path()).unwrap();
    let path2 = cache.store_package(hash, pkg_dir.path()).unwrap();

    assert_eq!(path1, path2);
    assert!(cache.is_cached(hash));
}

#[test]
fn test_link_to_project_creates_tallow_modules() {
    let cache_root = TempDir::new().unwrap();
    let cache = GlobalCache::new(cache_root.path().to_path_buf());
    let project_dir = TempDir::new().unwrap();

    let pkg_dir = TempDir::new().unwrap();
    setup_package_dir(pkg_dir.path(), "linkpkg", "2.0.0");

    let hash = "2222222222222222222222222222222222222222222222222222222222222222";
    cache.store_package(hash, pkg_dir.path()).unwrap();

    cache.link_to_project(hash, "linkpkg", project_dir.path()).unwrap();

    let linked = project_dir.path().join("tallow_modules").join("linkpkg");
    assert!(linked.exists(), "tallow_modules/linkpkg should exist");

    // Verify linked contents are accessible
    let toml = fs::read_to_string(linked.join("tallow.toml")).unwrap();
    assert!(toml.contains("linkpkg"));
}

#[test]
fn test_link_all_from_lockfile() {
    let cache_root = TempDir::new().unwrap();
    let cache = GlobalCache::new(cache_root.path().to_path_buf());
    let project_dir = TempDir::new().unwrap();

    let hash_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let hash_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    // Store two packages
    let pkg_a = TempDir::new().unwrap();
    setup_package_dir(pkg_a.path(), "pkg-a", "1.0.0");
    cache.store_package(hash_a, pkg_a.path()).unwrap();

    let pkg_b = TempDir::new().unwrap();
    setup_package_dir(pkg_b.path(), "pkg-b", "2.0.0");
    cache.store_package(hash_b, pkg_b.path()).unwrap();

    // Create lockfile
    let mut packages = BTreeMap::new();
    packages.insert("pkg-a".to_string(), LockedPackage {
        name: "pkg-a".to_string(),
        version: Version::new(1, 0, 0),
        content_hash: hash_a.to_string(),
        dependencies: vec![],
    });
    packages.insert("pkg-b".to_string(), LockedPackage {
        name: "pkg-b".to_string(),
        version: Version::new(2, 0, 0),
        content_hash: hash_b.to_string(),
        dependencies: vec!["pkg-a".to_string()],
    });
    let lockfile = Lockfile {
        lockfile_version: LOCKFILE_VERSION,
        packages,
    };

    cache.link_all(&lockfile, project_dir.path()).unwrap();

    // Both should be linked
    assert!(project_dir.path().join("tallow_modules").join("pkg-a").exists());
    assert!(project_dir.path().join("tallow_modules").join("pkg-b").exists());
}

#[test]
fn test_cache_default_location() {
    // Just verify default_location doesn't panic and returns a reasonable path
    let cache = GlobalCache::default_location();
    let path = cache.cache_path("deadbeef00112233deadbeef00112233deadbeef00112233deadbeef00112233");
    let path_str = path.to_string_lossy();
    assert!(path_str.contains("tallow"));
    assert!(path_str.contains("cache"));
    assert!(path_str.contains("packages"));
    assert!(path_str.contains("de")); // 2-char prefix shard
}

#[test]
fn test_store_from_archive() {
    let cache_root = TempDir::new().unwrap();
    let cache = GlobalCache::new(cache_root.path().to_path_buf());

    // Create a project and archive it
    let project_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();
    setup_package_dir(project_dir.path(), "archived-pkg", "3.0.0");

    let meta = create_archive(project_dir.path(), output_dir.path()).unwrap();
    let archive_path = output_dir.path().join("archived-pkg-3.0.0.tar.zst");

    // Store from archive
    let (cached_path, cached_meta) = cache.store_from_archive(&archive_path).unwrap();

    assert!(cached_path.exists());
    assert_eq!(cached_meta.name, "archived-pkg");
    assert_eq!(cached_meta.version.to_string(), "3.0.0");
    assert_eq!(cached_meta.content_hash, meta.content_hash);
    assert!(cache.is_cached(&meta.content_hash));

    // Verify contents
    assert!(cached_path.join("tallow.toml").exists());
}
