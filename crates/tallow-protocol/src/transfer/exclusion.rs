//! File exclusion and gitignore-aware directory walking
//!
//! Provides configurable file exclusion using gitignore-style patterns
//! and optional `.gitignore` integration via the `ignore` crate.

use crate::{ProtocolError, Result};
use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

/// Default file patterns to always exclude (OS junk, editor swap files)
pub const DEFAULT_IGNORES: &[&str] = &[
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    "*.swp",
    "*.swo",
    "*~",
];

/// Configuration for file exclusion during directory scanning
#[derive(Debug, Clone, Default)]
pub struct ExclusionConfig {
    /// Patterns to exclude (gitignore syntax)
    pub patterns: Vec<String>,
    /// Whether to respect .gitignore files
    pub respect_gitignore: bool,
}

impl ExclusionConfig {
    /// Create a config with the default ignore patterns pre-populated.
    ///
    /// Includes OS junk files (`.DS_Store`, `Thumbs.db`, `desktop.ini`)
    /// and editor swap files (`*.swp`, `*.swo`, `*~`).
    pub fn with_defaults() -> Self {
        Self {
            patterns: DEFAULT_IGNORES.iter().map(|s| (*s).to_string()).collect(),
            respect_gitignore: false,
        }
    }

    /// Create config from a comma-separated exclude string and gitignore flag
    ///
    /// # Arguments
    ///
    /// * `exclude` - Optional comma-separated list of gitignore-style patterns
    /// * `gitignore` - Whether to respect `.gitignore` files found during traversal
    pub fn from_exclude_str(exclude: Option<&str>, gitignore: bool) -> Self {
        let patterns = exclude
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        Self {
            patterns,
            respect_gitignore: gitignore,
        }
    }

    /// Returns true if this config has any active exclusion rules
    pub fn is_active(&self) -> bool {
        !self.patterns.is_empty() || self.respect_gitignore
    }

    /// Walk a directory with exclusion rules applied, returning matching file paths
    ///
    /// Uses the `ignore` crate for efficient, gitignore-aware directory traversal.
    /// Files matching exclusion patterns are omitted from the results.
    ///
    /// # Arguments
    ///
    /// * `root` - The root directory to walk
    ///
    /// # Returns
    ///
    /// A vector of file paths that passed the exclusion filters
    pub fn walk_directory(&self, root: &Path) -> Result<Vec<PathBuf>> {
        let mut builder = WalkBuilder::new(root);

        builder.git_ignore(self.respect_gitignore);
        builder.git_global(self.respect_gitignore);
        builder.git_exclude(self.respect_gitignore);
        builder.hidden(false); // Show hidden files by default
        builder.add_custom_ignore_filename(".tallowignore");

        if !self.patterns.is_empty() {
            let mut overrides = OverrideBuilder::new(root);
            for pattern in &self.patterns {
                overrides.add(&format!("!{}", pattern)).map_err(|e| {
                    ProtocolError::TransferFailed(format!(
                        "invalid exclude pattern '{}': {}",
                        pattern, e
                    ))
                })?;
            }
            let built = overrides.build().map_err(|e| {
                ProtocolError::TransferFailed(format!("failed to build overrides: {}", e))
            })?;
            builder.overrides(built);
        }

        let files: Vec<PathBuf> = builder
            .build()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_some_and(|ft| ft.is_file()))
            .map(|entry| entry.into_path())
            .collect();

        Ok(files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_empty_config_not_active() {
        let config = ExclusionConfig::default();
        assert!(!config.is_active());
    }

    #[test]
    fn test_gitignore_makes_active() {
        let config = ExclusionConfig::from_exclude_str(None, true);
        assert!(config.is_active());
    }

    #[test]
    fn test_patterns_make_active() {
        let config = ExclusionConfig::from_exclude_str(Some("*.log,tmp"), false);
        assert!(config.is_active());
        assert_eq!(config.patterns.len(), 2);
    }

    #[test]
    fn test_parse_exclude_str() {
        let config = ExclusionConfig::from_exclude_str(Some("node_modules, .git, *.log"), false);
        assert_eq!(config.patterns, vec!["node_modules", ".git", "*.log"]);
    }

    #[test]
    fn test_walk_with_exclude() {
        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path();

        // Create files
        fs::write(root.join("main.rs"), "fn main() {}").unwrap();
        fs::write(root.join("debug.log"), "debug info").unwrap();
        fs::create_dir_all(root.join("node_modules")).unwrap();
        fs::write(root.join("node_modules").join("pkg.js"), "module").unwrap();

        let config = ExclusionConfig::from_exclude_str(Some("*.log,node_modules"), false);
        let files = config.walk_directory(root).unwrap();

        let names: Vec<String> = files
            .iter()
            .map(|f| f.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(names.contains(&"main.rs".to_string()));
        assert!(!names.contains(&"debug.log".to_string()));
        assert!(!names.contains(&"pkg.js".to_string()));
    }

    #[test]
    fn test_with_defaults_has_patterns() {
        let config = ExclusionConfig::with_defaults();
        assert!(config.is_active());
        assert!(config.patterns.contains(&".DS_Store".to_string()));
        assert!(config.patterns.contains(&"Thumbs.db".to_string()));
        assert!(config.patterns.contains(&"*.swp".to_string()));
    }

    #[test]
    fn test_with_defaults_excludes_os_junk() {
        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path();

        fs::write(root.join("real.txt"), "data").unwrap();
        fs::write(root.join(".DS_Store"), "junk").unwrap();
        fs::write(root.join("Thumbs.db"), "junk").unwrap();
        fs::write(root.join("test.swp"), "swap").unwrap();

        let config = ExclusionConfig::with_defaults();
        let files = config.walk_directory(root).unwrap();

        let names: Vec<String> = files
            .iter()
            .map(|f| f.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(names.contains(&"real.txt".to_string()));
        assert!(!names.contains(&".DS_Store".to_string()));
        assert!(!names.contains(&"Thumbs.db".to_string()));
        assert!(!names.contains(&"test.swp".to_string()));
    }

    #[test]
    fn test_default_ignores_constant() {
        assert_eq!(DEFAULT_IGNORES.len(), 6);
        assert!(DEFAULT_IGNORES.contains(&".DS_Store"));
        assert!(DEFAULT_IGNORES.contains(&"desktop.ini"));
        assert!(DEFAULT_IGNORES.contains(&"*~"));
    }

    #[test]
    fn test_tallowignore_file() {
        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path();

        // Create files
        fs::write(root.join("keep.txt"), "keep").unwrap();
        fs::write(root.join("secret.key"), "secret").unwrap();
        fs::create_dir_all(root.join("build")).unwrap();
        fs::write(root.join("build").join("output.bin"), "bin").unwrap();

        // Create .tallowignore
        fs::write(root.join(".tallowignore"), "*.key\nbuild/\n").unwrap();

        let config = ExclusionConfig::default();
        let files = config.walk_directory(root).unwrap();

        let names: Vec<String> = files
            .iter()
            .map(|f| f.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(names.contains(&"keep.txt".to_string()));
        assert!(
            !names.contains(&"secret.key".to_string()),
            "Expected .tallowignore to exclude *.key files"
        );
        assert!(
            !names.contains(&"output.bin".to_string()),
            "Expected .tallowignore to exclude build/ directory"
        );
    }

    #[test]
    fn test_tallowignore_empty_file() {
        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path();

        fs::write(root.join("file.txt"), "data").unwrap();
        fs::write(root.join(".tallowignore"), "").unwrap();

        let config = ExclusionConfig::default();
        let files = config.walk_directory(root).unwrap();

        let names: Vec<String> = files
            .iter()
            .map(|f| f.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(names.contains(&"file.txt".to_string()));
    }

    #[test]
    fn test_tallowignore_with_comments() {
        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path();

        fs::write(root.join("keep.txt"), "keep").unwrap();
        fs::write(root.join("skip.log"), "log").unwrap();

        // .tallowignore supports comments (gitignore syntax)
        fs::write(root.join(".tallowignore"), "# Exclude logs\n*.log\n").unwrap();

        let config = ExclusionConfig::default();
        let files = config.walk_directory(root).unwrap();

        let names: Vec<String> = files
            .iter()
            .map(|f| f.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(names.contains(&"keep.txt".to_string()));
        assert!(!names.contains(&"skip.log".to_string()));
    }
}
