use anyhow::Result;
use pubgrub::{
    DependencyConstraints, DependencyProvider, Dependencies, DefaultStringReporter,
    PackageResolutionStatistics, PubGrubError, Ranges, Reporter,
};
use semver::Version;
use std::collections::HashMap;
use std::convert::Infallible;

use crate::pkg::manifest::Manifest;
use crate::pkg::semver_req::VersionReq;

/// Version set type used throughout the resolver.
pub type SemverRanges = Ranges<Version>;

/// Trait for providing package version information to the resolver.
pub trait PackageRegistry {
    /// Return all available versions for a package, sorted ascending.
    fn available_versions(&self, package: &str) -> Result<Vec<Version>>;
    /// Return the dependencies of a specific package version.
    fn dependencies(&self, package: &str, version: &Version) -> Result<HashMap<String, VersionReq>>;
}

/// In-memory registry for testing. Stores packages with their versions and dependencies.
#[derive(Debug, Default)]
pub struct InMemoryRegistry {
    /// package_name -> version -> dependencies (dep_name -> version_req)
    packages: HashMap<String, HashMap<Version, HashMap<String, VersionReq>>>,
}

impl InMemoryRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a package version with its dependencies.
    pub fn add_package(&mut self, name: &str, version: Version, deps: HashMap<String, VersionReq>) {
        self.packages
            .entry(name.to_string())
            .or_default()
            .insert(version, deps);
    }
}

impl PackageRegistry for InMemoryRegistry {
    fn available_versions(&self, package: &str) -> Result<Vec<Version>> {
        match self.packages.get(package) {
            Some(versions) => {
                let mut v: Vec<Version> = versions.keys().cloned().collect();
                v.sort();
                Ok(v)
            }
            None => Ok(vec![]),
        }
    }

    fn dependencies(&self, package: &str, version: &Version) -> Result<HashMap<String, VersionReq>> {
        match self.packages.get(package).and_then(|vs| vs.get(version)) {
            Some(deps) => Ok(deps.clone()),
            None => Ok(HashMap::new()),
        }
    }
}

/// PubGrub DependencyProvider implementation wrapping a PackageRegistry.
struct TallowProvider<'a> {
    registry: &'a dyn PackageRegistry,
    root_package: String,
    root_version: Version,
    root_deps: HashMap<String, VersionReq>,
}

impl DependencyProvider for TallowProvider<'_> {
    type P = String;
    type V = Version;
    type VS = SemverRanges;
    type M = String;
    type Err = Infallible;
    type Priority = u64;

    fn prioritize(
        &self,
        package: &String,
        range: &SemverRanges,
        _stats: &PackageResolutionStatistics,
    ) -> Self::Priority {
        // Higher priority = resolved sooner.
        // Packages with fewer matching versions should be prioritized (more constrained).
        if package == &self.root_package {
            return u64::MAX; // Root always first
        }
        let versions = self.registry.available_versions(package).unwrap_or_default();
        let matching = versions.iter().filter(|v| range.contains(v)).count();
        // Fewer matches = higher priority (invert count)
        u64::MAX - matching as u64
    }

    fn choose_version(
        &self,
        package: &String,
        range: &SemverRanges,
    ) -> Result<Option<Version>, Infallible> {
        if package == &self.root_package {
            if range.contains(&self.root_version) {
                return Ok(Some(self.root_version.clone()));
            }
            return Ok(None);
        }

        let versions = self.registry.available_versions(package).unwrap_or_default();
        // Return highest compatible version
        let chosen = versions.into_iter().rev().find(|v| range.contains(v));
        Ok(chosen)
    }

    fn get_dependencies(
        &self,
        package: &String,
        version: &Version,
    ) -> Result<Dependencies<String, SemverRanges, String>, Infallible> {
        let deps = if package == &self.root_package && version == &self.root_version {
            self.root_deps.clone()
        } else {
            self.registry.dependencies(package, version).unwrap_or_default()
        };

        let mut constraints = DependencyConstraints::default();
        for (dep_name, version_req) in deps {
            constraints.insert(dep_name, version_req.to_pubgrub_range());
        }

        Ok(Dependencies::Available(constraints))
    }
}

/// Resolve all dependencies for a manifest against a registry.
///
/// Returns a map of package_name -> resolved_version for all transitive dependencies.
/// On conflict, returns a human-readable error explaining the dependency chain.
pub fn resolve_dependencies(
    manifest: &Manifest,
    registry: &dyn PackageRegistry,
) -> Result<HashMap<String, Version>> {
    let root_deps: HashMap<String, VersionReq> = manifest.dependencies.iter()
        .map(|(name, spec)| (name.clone(), spec.parsed.clone()))
        .collect();

    let provider = TallowProvider {
        registry,
        root_package: manifest.name.clone(),
        root_version: manifest.version.clone(),
        root_deps,
    };

    match pubgrub::resolve(&provider, manifest.name.clone(), manifest.version.clone()) {
        Ok(solution) => {
            let mut result = HashMap::new();
            for (pkg, version) in solution {
                if pkg != manifest.name {
                    result.insert(pkg, version);
                }
            }
            Ok(result)
        }
        Err(PubGrubError::NoSolution(mut derivation_tree)) => {
            derivation_tree.collapse_no_versions();
            let report = DefaultStringReporter::report(&derivation_tree);
            Err(anyhow::anyhow!("Dependency resolution failed:\n{}", report))
        }
        Err(PubGrubError::ErrorInShouldCancel(e)) => {
            Err(anyhow::anyhow!("Resolution cancelled: {:?}", e))
        }
        Err(PubGrubError::ErrorChoosingVersion { package, source }) => {
            Err(anyhow::anyhow!("Error choosing version for {}: {:?}", package, source))
        }
        Err(PubGrubError::ErrorRetrievingDependencies {
            package,
            version,
            source,
        }) => {
            Err(anyhow::anyhow!(
                "Error retrieving dependencies for {} {}: {:?}",
                package,
                version,
                source
            ))
        }
    }
}
