use tallow::pkg::manifest::parse_manifest;
use tallow::pkg::semver_req::parse_version_req;
use semver::Version;

#[test]
fn pkg_manifest_roundtrip_all_constraint_types() {
    let toml = r#"
[package]
name = "test-app"
version = "2.1.0"
author = "Tallow Team"
license = "MIT"

[dependencies]
caret = "^1.2.3"
tilde = "~0.3.0"
exact = "=2.0.0"
wildcard = "*"
bare = "1.5.0"
table = { version = "^3.0" }
"#;
    let manifest = parse_manifest(toml).unwrap();
    assert_eq!(manifest.name, "test-app");
    assert_eq!(manifest.version, Version::new(2, 1, 0));
    assert_eq!(manifest.author.as_deref(), Some("Tallow Team"));
    assert_eq!(manifest.license.as_deref(), Some("MIT"));
    assert_eq!(manifest.dependencies.len(), 6);

    // Verify each constraint type parses and matches correctly
    let caret = &manifest.dependencies["caret"];
    assert!(caret.parsed.matches(&Version::new(1, 9, 0)));
    assert!(!caret.parsed.matches(&Version::new(2, 0, 0)));

    let tilde = &manifest.dependencies["tilde"];
    assert!(tilde.parsed.matches(&Version::new(0, 3, 5)));
    assert!(!tilde.parsed.matches(&Version::new(0, 4, 0)));

    let exact = &manifest.dependencies["exact"];
    assert!(exact.parsed.matches(&Version::new(2, 0, 0)));
    assert!(!exact.parsed.matches(&Version::new(2, 0, 1)));

    let wildcard = &manifest.dependencies["wildcard"];
    assert!(wildcard.parsed.matches(&Version::new(99, 0, 0)));

    let bare = &manifest.dependencies["bare"];
    assert!(bare.parsed.matches(&Version::new(1, 5, 0)));
    assert!(bare.parsed.matches(&Version::new(1, 9, 0)));
    assert!(!bare.parsed.matches(&Version::new(2, 0, 0)));

    let table = &manifest.dependencies["table"];
    assert!(table.parsed.matches(&Version::new(3, 1, 0)));
    assert!(!table.parsed.matches(&Version::new(4, 0, 0)));
}

#[test]
fn pkg_manifest_tallow_template_compatible() {
    // Test that the tallow.toml template from `tallow new` parses correctly
    let toml = r#"
[package]
name    = "my-project"
version = "0.2.0"
author  = ""
license = "MIT"

[dependencies]

[legal]
default_jurisdiction = ["us", "eu"]
default_robots_txt   = "respect"
audit_log_path       = "logs/audit"

[build]
target   = "x86_64-linux"
optimize = "debug"

[runtime]
ip_pool_size    = 10000
log_level       = "info"
audit_enabled   = true
"#;
    let manifest = parse_manifest(toml).unwrap();
    assert_eq!(manifest.name, "my-project");
    assert_eq!(manifest.version, Version::new(0, 2, 0));
    assert!(manifest.author.is_none()); // empty string -> None
    assert_eq!(manifest.license.as_deref(), Some("MIT"));
    assert!(manifest.dependencies.is_empty());
}

#[test]
fn pkg_manifest_error_messages_are_clear() {
    // Missing [package]
    let err = parse_manifest("[dependencies]\nfoo = \"^1.0\"").unwrap_err();
    assert!(err.to_string().contains("[package]"), "Should say missing [package]: {}", err);

    // Missing name
    let err = parse_manifest("[package]\nversion = \"1.0.0\"").unwrap_err();
    assert!(err.to_string().contains("name"), "Should say missing name: {}", err);

    // Invalid version
    let err = parse_manifest("[package]\nname = \"x\"\nversion = \"bad\"").unwrap_err();
    assert!(err.to_string().contains("invalid version"), "Should say invalid version: {}", err);

    // Invalid constraint
    let toml = "[package]\nname = \"x\"\nversion = \"1.0.0\"\n[dependencies]\nfoo = \"^abc\"";
    let err = parse_manifest(toml).unwrap_err();
    assert!(err.to_string().contains("foo"), "Should mention dep name: {}", err);
}
