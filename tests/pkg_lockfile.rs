use tallow::pkg::lockfile::*;
use tallow::pkg::resolver::InMemoryRegistry;
use tallow::pkg::semver_req::parse_version_req;
use semver::Version;
use std::collections::HashMap;
use tempfile::TempDir;

fn make_resolved() -> (HashMap<String, Version>, InMemoryRegistry, HashMap<String, String>) {
    let mut registry = InMemoryRegistry::new();

    // foo 1.2.3 depends on bar
    let mut foo_deps = HashMap::new();
    foo_deps.insert("bar".to_string(), parse_version_req("^2.0.0").unwrap());
    registry.add_package("foo", Version::new(1, 2, 3), foo_deps);

    // bar 2.1.0 has no deps
    registry.add_package("bar", Version::new(2, 1, 0), HashMap::new());

    let mut resolved = HashMap::new();
    resolved.insert("foo".to_string(), Version::new(1, 2, 3));
    resolved.insert("bar".to_string(), Version::new(2, 1, 0));

    let mut hashes = HashMap::new();
    hashes.insert("foo".to_string(), "a".repeat(64));
    hashes.insert("bar".to_string(), "b".repeat(64));

    (resolved, registry, hashes)
}

#[test]
fn test_generate_lockfile() {
    let (resolved, registry, hashes) = make_resolved();
    let lockfile = generate_lockfile(&resolved, &registry, &hashes);

    assert_eq!(lockfile.lockfile_version, LOCKFILE_VERSION);
    assert_eq!(lockfile.packages.len(), 2);

    let bar = &lockfile.packages["bar"];
    assert_eq!(bar.name, "bar");
    assert_eq!(bar.version, Version::new(2, 1, 0));
    assert!(bar.dependencies.is_empty());

    let foo = &lockfile.packages["foo"];
    assert_eq!(foo.name, "foo");
    assert_eq!(foo.version, Version::new(1, 2, 3));
    assert_eq!(foo.dependencies, vec!["bar".to_string()]);
}

#[test]
fn test_serialize_deterministic() {
    let (resolved, registry, hashes) = make_resolved();
    let lockfile = generate_lockfile(&resolved, &registry, &hashes);

    let s1 = serialize_lockfile(&lockfile);
    let s2 = serialize_lockfile(&lockfile);

    // Byte-identical
    assert_eq!(s1, s2);
    assert_eq!(s1.as_bytes(), s2.as_bytes());

    // Contains expected structure
    assert!(s1.contains("lockfile-version = 1"));
    assert!(s1.contains("[[package]]"));
    assert!(s1.contains("name = \"bar\""));
    assert!(s1.contains("name = \"foo\""));
    assert!(s1.contains("integrity = \"blake3:"));

    // bar comes before foo (alphabetical in BTreeMap)
    let bar_pos = s1.find("name = \"bar\"").unwrap();
    let foo_pos = s1.find("name = \"foo\"").unwrap();
    assert!(bar_pos < foo_pos);

    // Uses \n not \r\n
    assert!(!s1.contains("\r\n"));
}

#[test]
fn test_round_trip() {
    let (resolved, registry, hashes) = make_resolved();
    let lockfile = generate_lockfile(&resolved, &registry, &hashes);

    let serialized = serialize_lockfile(&lockfile);
    let parsed = parse_lockfile(&serialized).unwrap();

    assert_eq!(parsed.lockfile_version, lockfile.lockfile_version);
    assert_eq!(parsed.packages.len(), lockfile.packages.len());

    for (name, pkg) in &lockfile.packages {
        let parsed_pkg = &parsed.packages[name];
        assert_eq!(pkg.name, parsed_pkg.name);
        assert_eq!(pkg.version, parsed_pkg.version);
        assert_eq!(pkg.content_hash, parsed_pkg.content_hash);
        assert_eq!(pkg.dependencies, parsed_pkg.dependencies);
    }
}

#[test]
fn test_write_and_read_lockfile() {
    let (resolved, registry, hashes) = make_resolved();
    let lockfile = generate_lockfile(&resolved, &registry, &hashes);

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("tallow.lock");

    write_lockfile(&lockfile, &path).unwrap();
    let read_back = read_lockfile(&path).unwrap();

    assert_eq!(read_back.lockfile_version, lockfile.lockfile_version);
    assert_eq!(read_back.packages.len(), lockfile.packages.len());

    // Verify file content uses \n
    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(!raw.contains("\r\n") || raw.replace("\r\n", "\n") == raw.replace("\r\n", "\n"));
}

#[test]
fn test_empty_lockfile() {
    let resolved = HashMap::new();
    let registry = InMemoryRegistry::new();
    let hashes = HashMap::new();

    let lockfile = generate_lockfile(&resolved, &registry, &hashes);
    assert_eq!(lockfile.packages.len(), 0);

    let serialized = serialize_lockfile(&lockfile);
    assert!(serialized.contains("lockfile-version = 1"));
    assert!(!serialized.contains("[[package]]"));

    let parsed = parse_lockfile(&serialized).unwrap();
    assert_eq!(parsed.packages.len(), 0);
}

#[test]
fn test_package_with_multiple_deps() {
    let mut registry = InMemoryRegistry::new();

    let mut deps = HashMap::new();
    deps.insert("zlib".to_string(), parse_version_req("^1.0.0").unwrap());
    deps.insert("alpha".to_string(), parse_version_req("^2.0.0").unwrap());
    deps.insert("moo".to_string(), parse_version_req("^3.0.0").unwrap());
    registry.add_package("complex", Version::new(0, 5, 0), deps);

    let mut resolved = HashMap::new();
    resolved.insert("complex".to_string(), Version::new(0, 5, 0));

    let mut hashes = HashMap::new();
    hashes.insert("complex".to_string(), "c".repeat(64));

    let lockfile = generate_lockfile(&resolved, &registry, &hashes);
    let pkg = &lockfile.packages["complex"];

    // Dependencies must be sorted alphabetically
    assert_eq!(pkg.dependencies, vec!["alpha", "moo", "zlib"]);
}
