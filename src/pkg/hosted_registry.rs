use anyhow::{Context, Result, bail};
use semver::Version;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::pkg::registry::{LocalRegistry, PackageMetadata};
use crate::pkg::resolver::PackageRegistry;
use crate::pkg::semver_req::VersionReq;

/// Search result from the hosted registry.
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub name: String,
    pub latest_version: String,
    pub version_count: usize,
}

/// Hosted package registry that wraps a LocalRegistry and exposes REST-like API methods.
///
/// This simulates the `pkg.tallow-lang.org` hosted registry contract without an actual HTTP server.
/// Methods mirror the API: publish, search, get_versions, download.
pub struct HostedRegistry {
    inner: LocalRegistry,
}

impl HostedRegistry {
    /// Create a new hosted registry backed by the given local registry.
    pub fn new(inner: LocalRegistry) -> Self {
        Self { inner }
    }

    /// Publish a package from a project directory to the registry.
    ///
    /// Validates the project, creates an archive, stores it in the registry,
    /// and returns the package metadata.
    pub fn publish(&self, project_dir: &Path) -> Result<PackageMetadata> {
        // Delegate archive creation and storage to LocalRegistry
        self.inner.publish_package(project_dir)
            .context("failed to publish package")?;

        // Read back the metadata that was just written
        let toml_path = project_dir.join("tallow.toml");
        let toml_content = std::fs::read_to_string(&toml_path)
            .context("failed to read tallow.toml")?;
        let manifest = crate::pkg::manifest::parse_manifest(&toml_content)
            .context("failed to parse tallow.toml")?;

        let version_str = manifest.version.to_string();
        let metadata_path = self.inner.metadata_path(&manifest.name, &version_str);
        let metadata_content = std::fs::read_to_string(&metadata_path)
            .with_context(|| format!("failed to read metadata for {} {}", manifest.name, version_str))?;
        let metadata: PackageMetadata = serde_json::from_str(&metadata_content)
            .context("failed to parse package metadata")?;

        Ok(metadata)
    }

    /// Search for packages by substring match on package names.
    ///
    /// Returns matching packages with their latest version and total version count.
    pub fn search(&self, query: &str) -> Result<Vec<SearchResult>> {
        let index = self.inner.read_index()?;
        let query_lower = query.to_lowercase();

        let mut results = Vec::new();
        for (name, versions) in &index.packages {
            if name.to_lowercase().contains(&query_lower) {
                let latest = versions.last()
                    .cloned()
                    .unwrap_or_else(|| "0.0.0".to_string());
                results.push(SearchResult {
                    name: name.clone(),
                    latest_version: latest,
                    version_count: versions.len(),
                });
            }
        }

        // Sort results alphabetically by name
        results.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(results)
    }

    /// Get all available versions for a package, sorted ascending.
    pub fn get_versions(&self, name: &str) -> Result<Vec<Version>> {
        self.inner.available_versions(name)
    }

    /// Download (get the archive path for) a specific package version.
    ///
    /// Returns the path to the .tar.zst archive file in the registry.
    pub fn download(&self, name: &str, version: &Version) -> Result<PathBuf> {
        let version_str = version.to_string();
        let archive_name = format!("{}-{}.tar.zst", name, version_str);
        let archive_path = self.inner.archive_path(name, &version_str, &archive_name);

        if !archive_path.exists() {
            bail!(
                "package {} version {} not found in registry",
                name, version_str
            );
        }

        Ok(archive_path)
    }
}

impl PackageRegistry for HostedRegistry {
    fn available_versions(&self, package: &str) -> Result<Vec<Version>> {
        self.inner.available_versions(package)
    }

    fn dependencies(&self, package: &str, version: &Version) -> Result<HashMap<String, VersionReq>> {
        self.inner.dependencies(package, version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkg::cache::GlobalCache;

    /// Create a temporary project directory with tallow.toml and a source file.
    fn create_test_project(dir: &Path, name: &str, version: &str) {
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("tallow.toml"),
            format!(
                "[package]\nname = \"{}\"\nversion = \"{}\"\n",
                name, version
            ),
        )
        .unwrap();
        std::fs::write(
            dir.join("src").join("main.tl"),
            "fn main() { print(\"hello\") }\n",
        )
        .unwrap();
    }

    fn make_registry(root: &Path) -> HostedRegistry {
        let cache = GlobalCache::new(root.join(".cache"));
        let local = LocalRegistry::open(root.to_path_buf(), cache);
        HostedRegistry::new(local)
    }

    #[test]
    fn test_publish_and_search() {
        let tmp = tempfile::tempdir().unwrap();
        let reg_dir = tmp.path().join("registry");
        let proj_dir = tmp.path().join("my-pkg");
        std::fs::create_dir_all(&reg_dir).unwrap();
        create_test_project(&proj_dir, "my-pkg", "1.0.0");

        let registry = make_registry(&reg_dir);

        // Publish
        let metadata = registry.publish(&proj_dir).unwrap();
        assert_eq!(metadata.name, "my-pkg");
        assert_eq!(metadata.version, "1.0.0");
        assert!(!metadata.content_hash.is_empty());

        // Search
        let results = registry.search("my").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "my-pkg");
        assert_eq!(results[0].latest_version, "1.0.0");
        assert_eq!(results[0].version_count, 1);
    }

    #[test]
    fn test_publish_duplicate_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let reg_dir = tmp.path().join("registry");
        let proj_dir = tmp.path().join("dup-pkg");
        std::fs::create_dir_all(&reg_dir).unwrap();
        create_test_project(&proj_dir, "dup-pkg", "1.0.0");

        let registry = make_registry(&reg_dir);

        // First publish succeeds
        registry.publish(&proj_dir).unwrap();

        // Second publish of same version fails
        let err = registry.publish(&proj_dir).unwrap_err();
        let full_err = format!("{:#}", err);
        assert!(
            full_err.contains("already exists"),
            "expected 'already exists' error, got: {}",
            full_err
        );
    }

    #[test]
    fn test_get_versions() {
        let tmp = tempfile::tempdir().unwrap();
        let reg_dir = tmp.path().join("registry");
        std::fs::create_dir_all(&reg_dir).unwrap();

        let registry = make_registry(&reg_dir);

        // Publish 3 versions
        for ver in &["1.0.0", "2.0.0", "3.0.0"] {
            let proj = tmp.path().join(format!("proj-{}", ver));
            create_test_project(&proj, "versioned-pkg", ver);
            registry.publish(&proj).unwrap();
        }

        let versions = registry.get_versions("versioned-pkg").unwrap();
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0], Version::new(1, 0, 0));
        assert_eq!(versions[1], Version::new(2, 0, 0));
        assert_eq!(versions[2], Version::new(3, 0, 0));
    }

    #[test]
    fn test_download() {
        let tmp = tempfile::tempdir().unwrap();
        let reg_dir = tmp.path().join("registry");
        let proj_dir = tmp.path().join("dl-pkg");
        std::fs::create_dir_all(&reg_dir).unwrap();
        create_test_project(&proj_dir, "dl-pkg", "1.0.0");

        let registry = make_registry(&reg_dir);
        registry.publish(&proj_dir).unwrap();

        let archive_path = registry.download("dl-pkg", &Version::new(1, 0, 0)).unwrap();
        assert!(archive_path.exists(), "archive should exist at {}", archive_path.display());
        assert!(archive_path.to_string_lossy().contains("dl-pkg-1.0.0.tar.zst"));
    }

    #[test]
    fn test_search_no_results() {
        let tmp = tempfile::tempdir().unwrap();
        let reg_dir = tmp.path().join("registry");
        std::fs::create_dir_all(&reg_dir).unwrap();

        let registry = make_registry(&reg_dir);

        let results = registry.search("nonexistent").unwrap();
        assert!(results.is_empty());
    }
}
