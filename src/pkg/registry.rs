use anyhow::{Context, Result, bail};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use crate::pkg::archive::create_archive;
use crate::pkg::cache::GlobalCache;
use crate::pkg::manifest::parse_manifest;
use crate::pkg::resolver::PackageRegistry;
use crate::pkg::semver_req::VersionReq;

/// Metadata stored alongside each package version in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    pub name: String,
    pub version: String,
    pub content_hash: String,
    pub dependencies: BTreeMap<String, String>,
}

/// Index tracking all packages and their versions.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryIndex {
    pub packages: BTreeMap<String, Vec<String>>,
}

/// File-based local package registry.
///
/// Registry layout on disk:
/// ```text
/// {registry_root}/
///   index.json
///   packages/
///     {name}/
///       {version}/
///         {name}-{version}.tar.zst
///         metadata.json
/// ```
pub struct LocalRegistry {
    root: PathBuf,
    cache: GlobalCache,
}

impl LocalRegistry {
    /// Create a registry with just a root path (no cache integration).
    pub fn new(root: PathBuf) -> Self {
        Self {
            cache: GlobalCache::new(root.join(".cache")),
            root,
        }
    }

    /// Create a registry with a specific cache for package storage.
    pub fn open(root: PathBuf, cache: GlobalCache) -> Self {
        Self { root, cache }
    }

    /// Publish a package from a project directory to this registry.
    ///
    /// Reads tallow.toml, creates an archive, and stores it under
    /// `{root}/packages/{name}/{version}/`.
    /// Rejects duplicate publishes of the same version.
    pub fn publish_package(&self, project_dir: &Path) -> Result<()> {
        // Parse manifest
        let toml_path = project_dir.join("tallow.toml");
        let toml_content = fs::read_to_string(&toml_path)
            .with_context(|| format!("failed to read tallow.toml from {}", project_dir.display()))?;
        let manifest = parse_manifest(&toml_content)
            .context("failed to parse tallow.toml")?;

        let version_str = manifest.version.to_string();
        let pkg_dir = self.root.join("packages").join(&manifest.name).join(&version_str);

        // Check for duplicate
        if pkg_dir.exists() {
            bail!(
                "package {} version {} already exists in registry",
                manifest.name,
                version_str
            );
        }

        // Create archive
        fs::create_dir_all(&pkg_dir)
            .with_context(|| format!("failed to create registry dir {}", pkg_dir.display()))?;

        let archive_meta = create_archive(project_dir, &pkg_dir)
            .context("failed to create package archive")?;

        // Write metadata.json
        let deps: BTreeMap<String, String> = manifest
            .dependencies
            .iter()
            .map(|(name, spec)| (name.clone(), spec.version_req_raw.clone()))
            .collect();

        let metadata = PackageMetadata {
            name: manifest.name.clone(),
            version: version_str.clone(),
            content_hash: archive_meta.content_hash,
            dependencies: deps,
        };

        let metadata_json = serde_json::to_string_pretty(&metadata)
            .context("failed to serialize metadata")?;
        fs::write(pkg_dir.join("metadata.json"), metadata_json)
            .context("failed to write metadata.json")?;

        // Update index.json
        self.update_index(&manifest.name, &version_str)?;

        Ok(())
    }

    /// Fetch a package from the registry into the global cache.
    /// Returns the cache path where the package contents are stored.
    pub fn fetch_package(&self, name: &str, version: &Version) -> Result<PathBuf> {
        let version_str = version.to_string();
        let archive_name = format!("{}-{}.tar.zst", name, version_str);
        let archive_path = self.root
            .join("packages")
            .join(name)
            .join(&version_str)
            .join(&archive_name);

        if !archive_path.exists() {
            bail!(
                "package {} version {} not found in registry (expected {})",
                name,
                version_str,
                archive_path.display()
            );
        }

        let (cache_path, _metadata) = self.cache.store_from_archive(&archive_path)
            .with_context(|| format!("failed to cache package {} {}", name, version_str))?;

        Ok(cache_path)
    }

    /// Get the path to a package archive file.
    pub fn archive_path(&self, name: &str, version: &str, archive_name: &str) -> PathBuf {
        self.root
            .join("packages")
            .join(name)
            .join(version)
            .join(archive_name)
    }

    /// Read or create the registry index.
    pub fn read_index(&self) -> Result<RegistryIndex> {
        let index_path = self.root.join("index.json");
        if index_path.exists() {
            let content = fs::read_to_string(&index_path)
                .context("failed to read index.json")?;
            serde_json::from_str(&content)
                .context("failed to parse index.json")
        } else {
            Ok(RegistryIndex::default())
        }
    }

    /// Update the index with a new package version.
    fn update_index(&self, name: &str, version: &str) -> Result<()> {
        let mut index = self.read_index()?;

        let versions = index.packages.entry(name.to_string()).or_default();
        if !versions.contains(&version.to_string()) {
            versions.push(version.to_string());
            // Sort versions semantically
            versions.sort_by(|a, b| {
                let va = a.parse::<Version>().unwrap_or(Version::new(0, 0, 0));
                let vb = b.parse::<Version>().unwrap_or(Version::new(0, 0, 0));
                va.cmp(&vb)
            });
        }

        let index_json = serde_json::to_string_pretty(&index)
            .context("failed to serialize index")?;
        fs::create_dir_all(&self.root).ok();
        fs::write(self.root.join("index.json"), index_json)
            .context("failed to write index.json")?;

        Ok(())
    }

    /// Get the path to a package version's metadata.json.
    pub fn metadata_path(&self, name: &str, version: &str) -> PathBuf {
        self.root
            .join("packages")
            .join(name)
            .join(version)
            .join("metadata.json")
    }

    /// Read metadata for a specific package version.
    fn read_metadata(&self, name: &str, version: &str) -> Result<PackageMetadata> {
        let metadata_path = self.metadata_path(name, version);

        let content = fs::read_to_string(&metadata_path)
            .with_context(|| format!("failed to read metadata for {} {}", name, version))?;

        serde_json::from_str(&content)
            .with_context(|| format!("failed to parse metadata for {} {}", name, version))
    }
}

impl PackageRegistry for LocalRegistry {
    fn available_versions(&self, package: &str) -> Result<Vec<Version>> {
        let pkg_dir = self.root.join("packages").join(package);
        if !pkg_dir.exists() {
            return Ok(vec![]);
        }

        let mut versions = Vec::new();
        for entry in fs::read_dir(&pkg_dir)
            .with_context(|| format!("failed to read package dir {}", pkg_dir.display()))?
        {
            let entry = entry?;
            if entry.path().is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    if let Ok(ver) = name.parse::<Version>() {
                        versions.push(ver);
                    }
                }
            }
        }
        versions.sort();
        Ok(versions)
    }

    fn dependencies(&self, package: &str, version: &Version) -> Result<HashMap<String, VersionReq>> {
        let version_str = version.to_string();
        let metadata = self.read_metadata(package, &version_str)?;

        let mut deps = HashMap::new();
        for (dep_name, version_req_raw) in &metadata.dependencies {
            let parsed = crate::pkg::semver_req::parse_version_req(version_req_raw)
                .with_context(|| format!("invalid dependency constraint for {} in {} {}", dep_name, package, version))?;
            deps.insert(dep_name.clone(), parsed);
        }

        Ok(deps)
    }
}
