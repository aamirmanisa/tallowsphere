use tallow::pkg::resolver::{InMemoryRegistry, resolve_dependencies};
use tallow::pkg::manifest::{Manifest, DependencySpec};
use tallow::pkg::semver_req::{VersionReq, parse_version_req};
use semver::Version;
use std::collections::HashMap;

fn make_manifest(name: &str, version: &str, deps: Vec<(&str, &str)>) -> Manifest {
    let mut dependencies = HashMap::new();
    for (dep_name, req_str) in deps {
        dependencies.insert(dep_name.to_string(), DependencySpec {
            version_req_raw: req_str.to_string(),
            parsed: parse_version_req(req_str).unwrap(),
            path: None,
        });
    }
    Manifest {
        name: name.to_string(),
        version: Version::parse(version).unwrap(),
        author: None,
        license: None,
        dependencies,
        workspace: None,
        licenses: None,
        policy: None,
        registries: Vec::new(),
    }
}

fn v(s: &str) -> Version {
    Version::parse(s).unwrap()
}

fn deps(pairs: Vec<(&str, &str)>) -> HashMap<String, VersionReq> {
    pairs.into_iter()
        .map(|(name, req)| (name.to_string(), parse_version_req(req).unwrap()))
        .collect()
}

#[test]
fn pkg_resolver_single_no_deps() {
    // Test 1: Single package with no deps resolves to that exact version
    let mut registry = InMemoryRegistry::new();
    registry.add_package("foo", v("1.0.0"), HashMap::new());

    let manifest = make_manifest("myapp", "0.1.0", vec![("foo", "^1.0")]);
    let solution = resolve_dependencies(&manifest, &registry).unwrap();

    assert_eq!(solution.len(), 1);
    assert_eq!(solution["foo"], v("1.0.0"));
}

#[test]
fn pkg_resolver_package_depends_on_another() {
    // Test 2: Package A depends on B ^1.0 - resolves both
    let mut registry = InMemoryRegistry::new();
    registry.add_package("a", v("1.0.0"), deps(vec![("b", "^1.0")]));
    registry.add_package("b", v("1.0.0"), HashMap::new());
    registry.add_package("b", v("1.5.0"), HashMap::new());

    let manifest = make_manifest("myapp", "0.1.0", vec![("a", "^1.0")]);
    let solution = resolve_dependencies(&manifest, &registry).unwrap();

    assert_eq!(solution["a"], v("1.0.0"));
    // Should pick highest compatible version of b
    assert_eq!(solution["b"], v("1.5.0"));
}

#[test]
fn pkg_resolver_diamond_dependency() {
    // Test 3: Diamond dependency (myapp->B ^1.0, myapp->C ^1.0, B->D ^2.0, C->D ^2.1)
    let mut registry = InMemoryRegistry::new();
    registry.add_package("b", v("1.0.0"), deps(vec![("d", "^2.0")]));
    registry.add_package("c", v("1.0.0"), deps(vec![("d", "^2.1")]));
    registry.add_package("d", v("2.0.0"), HashMap::new());
    registry.add_package("d", v("2.1.0"), HashMap::new());
    registry.add_package("d", v("2.5.0"), HashMap::new());

    let manifest = make_manifest("myapp", "0.1.0", vec![("b", "^1.0"), ("c", "^1.0")]);
    let solution = resolve_dependencies(&manifest, &registry).unwrap();

    assert_eq!(solution["b"], v("1.0.0"));
    assert_eq!(solution["c"], v("1.0.0"));
    // D must satisfy both ^2.0 (B) and ^2.1 (C) => picks highest: 2.5.0
    assert!(solution["d"] >= v("2.1.0"));
    assert_eq!(solution["d"], v("2.5.0"));
}

#[test]
fn pkg_resolver_conflicting_requirements() {
    // Test 4: Conflicting requirements (myapp needs foo ^1.0 AND foo ^2.0)
    let mut registry = InMemoryRegistry::new();
    registry.add_package("foo", v("1.0.0"), HashMap::new());
    registry.add_package("foo", v("1.5.0"), HashMap::new());
    registry.add_package("foo", v("2.0.0"), HashMap::new());
    registry.add_package("foo", v("2.3.0"), HashMap::new());

    // This creates a direct conflict: myapp wants both ^1.0 and ^2.0 of foo
    // We simulate this by having two packages that each require different major versions
    registry.add_package("a", v("1.0.0"), deps(vec![("foo", "^1.0")]));
    registry.add_package("b", v("1.0.0"), deps(vec![("foo", "^2.0")]));

    let manifest = make_manifest("myapp", "0.1.0", vec![("a", "^1.0"), ("b", "^1.0")]);
    let err = resolve_dependencies(&manifest, &registry).unwrap_err();

    let msg = err.to_string();
    assert!(msg.contains("foo"), "Error should mention 'foo': {}", msg);
}

#[test]
fn pkg_resolver_transitive_conflict() {
    // Test 5: Transitive conflict produces error chain showing full dependency path
    // myapp -> a ^1.0 -> b ^1.0 -> c ^1.0
    // myapp -> d ^1.0 -> c ^2.0
    // c ^1.0 and c ^2.0 conflict
    let mut registry = InMemoryRegistry::new();
    registry.add_package("a", v("1.0.0"), deps(vec![("b", "^1.0")]));
    registry.add_package("b", v("1.0.0"), deps(vec![("c", "^1.0")]));
    registry.add_package("c", v("1.0.0"), HashMap::new());
    registry.add_package("c", v("1.5.0"), HashMap::new());
    registry.add_package("c", v("2.0.0"), HashMap::new());
    registry.add_package("d", v("1.0.0"), deps(vec![("c", "^2.0")]));

    let manifest = make_manifest("myapp", "0.1.0", vec![("a", "^1.0"), ("d", "^1.0")]);
    let err = resolve_dependencies(&manifest, &registry).unwrap_err();

    let msg = err.to_string();
    // Error should mention the conflicting package and be human-readable
    assert!(msg.contains("c"), "Error should mention 'c': {}", msg);
    assert!(msg.contains("Dependency resolution failed"), "Should have prefix: {}", msg);
}
