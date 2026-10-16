use tallow::pkg::archive::{archive_content_hash, create_archive, extract_archive};
use std::fs;
use tempfile::TempDir;

fn setup_project(dir: &std::path::Path) {
    // Create tallow.toml
    fs::write(
        dir.join("tallow.toml"),
        r#"[package]
name = "test-pkg"
version = "1.0.0"

[dependencies]
"#,
    )
    .unwrap();

    // Create src/main.tl
    let src_dir = dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        src_dir.join("main.tl"),
        r#"fn main() {
    print("hello from test-pkg")
}
"#,
    )
    .unwrap();

    // Create src/lib.tl (nested file)
    fs::write(
        src_dir.join("lib.tl"),
        r#"fn helper() -> i32 {
    42
}
"#,
    )
    .unwrap();
}

#[test]
fn test_create_and_extract_archive() {
    let project_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();
    let extract_dir = TempDir::new().unwrap();

    setup_project(project_dir.path());

    // Create archive
    let meta = create_archive(project_dir.path(), output_dir.path()).unwrap();
    assert_eq!(meta.name, "test-pkg");
    assert_eq!(meta.version.to_string(), "1.0.0");
    assert!(!meta.content_hash.is_empty());
    assert_eq!(meta.content_hash.len(), 64); // BLAKE3 hex = 64 chars

    // Verify archive file exists
    let archive_path = output_dir.path().join("test-pkg-1.0.0.tar.zst");
    assert!(archive_path.exists());

    // Extract archive
    let extract_meta = extract_archive(&archive_path, extract_dir.path()).unwrap();
    assert_eq!(extract_meta.name, "test-pkg");
    assert_eq!(extract_meta.version.to_string(), "1.0.0");

    // Content hashes must match
    assert_eq!(meta.content_hash, extract_meta.content_hash);

    // Verify extracted contents
    let toml_content = fs::read_to_string(extract_dir.path().join("tallow.toml")).unwrap();
    assert!(toml_content.contains("test-pkg"));

    let main_content = fs::read_to_string(extract_dir.path().join("src/main.tl")).unwrap();
    assert!(main_content.contains("hello from test-pkg"));

    let lib_content = fs::read_to_string(extract_dir.path().join("src/lib.tl")).unwrap();
    assert!(lib_content.contains("helper"));
}

#[test]
fn test_content_hash_deterministic() {
    let data = b"some archive content for testing";
    let hash1 = archive_content_hash(data);
    let hash2 = archive_content_hash(data);
    assert_eq!(hash1, hash2);
    assert_eq!(hash1.len(), 64);
}

#[test]
fn test_create_archive_no_toml() {
    let dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();
    // No tallow.toml — should fail
    let result = create_archive(dir.path(), output_dir.path());
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("tallow.toml not found"));
}

#[test]
fn test_archive_hash_consistency() {
    // Create two identical projects, archives should have same hash
    let project1 = TempDir::new().unwrap();
    let project2 = TempDir::new().unwrap();
    let output1 = TempDir::new().unwrap();
    let output2 = TempDir::new().unwrap();

    setup_project(project1.path());
    setup_project(project2.path());

    let meta1 = create_archive(project1.path(), output1.path()).unwrap();
    let meta2 = create_archive(project2.path(), output2.path()).unwrap();

    assert_eq!(meta1.content_hash, meta2.content_hash);
}
