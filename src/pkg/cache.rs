use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::pkg::archive::{ArchiveMetadata, extract_archive};
use crate::pkg::lockfile::Lockfile;

// ── link mode ────────────────────────────────────────────────────────────────

/// How packages are projected from the global store into a project's
/// `tallow_modules/` directory.
///
/// The default is `Hardlink`, which gives pnpm-style zero-copy installs.
/// `Junction` is kept as a legacy fallback for Windows environments where
/// the store and the project live on different drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkMode {
    /// Create a hardlink for each file (zero extra disk space, works across
    /// filesystems only when source and destination are on the same volume).
    #[default]
    Hardlink,
    /// Plain file copy — always works, highest disk cost.
    Copy,
    /// Directory junction / Unix symlink pointing at the cached directory.
    /// This is the legacy behaviour preserved for backward compatibility.
    Junction,
}

// ── statistics & integrity types ─────────────────────────────────────────────

/// Snapshot of the global store's disk usage.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Number of distinct content-addressed entries (directories) in the store.
    pub entries: u64,
    /// Total number of regular files across all entries.
    pub total_files: u64,
    /// Sum of byte sizes of every file (counts the canonical copy, not hardlinks).
    pub total_bytes: u64,
    /// Files that have more than one hard-link count (i.e. actively used by ≥1 project).
    pub shared_files: u64,
}

/// Result of a prune operation.
#[derive(Debug, Clone, Default)]
pub struct PruneResult {
    /// Number of store entries removed (their link count was 1 — unreferenced).
    pub entries_removed: u64,
    /// Approximate bytes freed.
    pub bytes_freed: u64,
}

/// Result of a clean (full wipe) of the store.
#[derive(Debug, Clone, Default)]
pub struct CleanResult {
    /// Bytes that were freed.
    pub bytes_freed: u64,
}

/// A file whose on-disk content no longer matches the hash embedded in its
/// store path.
#[derive(Debug, Clone)]
pub struct IntegrityError {
    pub store_path: PathBuf,
    /// The hash that was expected (from the directory name).
    pub expected_hash: String,
    /// The hash that was actually measured.
    pub actual_hash: String,
}

// ── GlobalCache ───────────────────────────────────────────────────────────────

/// Content-addressed global package cache — pnpm-style store.
///
/// # Store layout
/// ```text
/// ~/.tallow/store/v1/
///   ab/                          ← first 2 chars of content hash
///     abcdef1234…/               ← full BLAKE3 hex hash
///       <package files>
/// ```
///
/// Packages are installed into a project's `tallow_modules/` via hardlinks
/// (default), plain copies, or directory junctions (legacy).
#[derive(Debug, Clone)]
pub struct GlobalCache {
    root: PathBuf,
    /// Controls how packages are materialised into a project's `tallow_modules/`.
    pub link_mode: LinkMode,
}

impl GlobalCache {
    // ── constructors ─────────────────────────────────────────────────────────

    /// Open the cache at the platform-default location with the default link mode.
    ///
    /// - Unix:    `~/.tallow/store/v1/`
    /// - Windows: `%LOCALAPPDATA%\tallow\store\v1\`
    pub fn default_location() -> Self {
        let base = if cfg!(windows) {
            dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."))
        } else {
            dirs::home_dir()
                .map(|h| h.join(".tallow"))
                .unwrap_or_else(|| PathBuf::from(".tallow"))
        };

        let root = if cfg!(windows) {
            base.join("tallow").join("store").join("v1")
        } else {
            base.join("store").join("v1")
        };

        Self {
            root,
            link_mode: LinkMode::default(),
        }
    }

    /// Open a cache at a custom root path (useful in tests).
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            link_mode: LinkMode::default(),
        }
    }

    /// Builder: override the link mode.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tallow::pkg::cache::{GlobalCache, LinkMode};
    /// let cache = GlobalCache::new("/tmp/store".into()).with_link_mode(LinkMode::Copy);
    /// assert_eq!(cache.link_mode, LinkMode::Copy);
    /// ```
    #[must_use]
    pub fn with_link_mode(mut self, mode: LinkMode) -> Self {
        self.link_mode = mode;
        self
    }

    // ── store paths ───────────────────────────────────────────────────────────

    /// Return the directory that holds a package identified by `content_hash`.
    ///
    /// Layout: `{root}/{hash[..2]}/{hash}/`
    pub fn cache_path(&self, content_hash: &str) -> PathBuf {
        let prefix = &content_hash[..2.min(content_hash.len())];
        self.root.join(prefix).join(content_hash)
    }

    /// Return `true` if a package with the given hash is already in the store.
    pub fn is_cached(&self, content_hash: &str) -> bool {
        self.cache_path(content_hash).exists()
    }

    // ── store writes ──────────────────────────────────────────────────────────

    /// Copy `source_dir` into the content-addressed store under `content_hash`.
    ///
    /// Idempotent: returns the existing path without touching the filesystem
    /// when the entry already exists.
    pub fn store_package(&self, content_hash: &str, source_dir: &Path) -> Result<PathBuf> {
        let dest = self.cache_path(content_hash);
        if dest.exists() {
            return Ok(dest);
        }

        fs::create_dir_all(&dest)
            .with_context(|| format!("failed to create store entry {}", dest.display()))?;

        copy_dir_recursive(source_dir, &dest)
            .with_context(|| format!("failed to populate store entry {}", dest.display()))?;

        Ok(dest)
    }

    /// Extract an archive and store its contents by content hash.
    ///
    /// Returns the store path and archive metadata.
    pub fn store_from_archive(&self, archive_path: &Path) -> Result<(PathBuf, ArchiveMetadata)> {
        let temp_dir = tempfile::tempdir()
            .context("failed to create temp dir for archive extraction")?;

        let metadata = extract_archive(archive_path, temp_dir.path())?;
        let store_path = self.store_package(&metadata.content_hash, temp_dir.path())?;

        Ok((store_path, metadata))
    }

    // ── project linking ───────────────────────────────────────────────────────

    /// Materialise a cached package into `{project_dir}/tallow_modules/{pkg_name}`.
    ///
    /// The strategy is controlled by `self.link_mode`:
    /// - `Hardlink`  — hardlink every file; falls back to copy on cross-volume.
    /// - `Copy`      — copy every file.
    /// - `Junction`  — create a single directory symlink / junction pointing at
    ///                 the store entry (legacy behaviour).
    pub fn link_to_project(
        &self,
        content_hash: &str,
        pkg_name: &str,
        project_dir: &Path,
    ) -> Result<()> {
        let store_path = self.cache_path(content_hash);
        if !store_path.exists() {
            anyhow::bail!(
                "package not in store: {} (hash: {})",
                pkg_name,
                content_hash
            );
        }

        let modules_dir = project_dir.join("tallow_modules");
        fs::create_dir_all(&modules_dir).context("failed to create tallow_modules")?;

        let target = modules_dir.join(pkg_name);
        remove_existing(&target);

        match self.link_mode {
            LinkMode::Junction => {
                create_dir_link(&store_path, &target).with_context(|| {
                    format!(
                        "failed to create junction {} -> {}",
                        target.display(),
                        store_path.display()
                    )
                })?;
            }
            LinkMode::Copy => {
                fs::create_dir_all(&target)?;
                copy_dir_recursive(&store_path, &target).with_context(|| {
                    format!("failed to copy {} into tallow_modules", pkg_name)
                })?;
            }
            LinkMode::Hardlink => {
                fs::create_dir_all(&target)?;
                hardlink_dir_recursive(&store_path, &target).with_context(|| {
                    format!("failed to hardlink {} into tallow_modules", pkg_name)
                })?;
            }
        }

        Ok(())
    }

    /// Link all packages from a lockfile into the project's `tallow_modules/`.
    ///
    /// Uses rayon-parallel hardlink/copy on all platforms, and a
    /// batch-script path for junction mode on Windows.
    pub fn link_all(&self, lockfile: &Lockfile, project_dir: &Path) -> Result<()> {
        match self.link_mode {
            // Junction mode: keep the legacy batch-script path on Windows for
            // maximum compat; use the parallel path everywhere else.
            LinkMode::Junction => {
                #[cfg(windows)]
                self.link_all_batch_junction(lockfile, project_dir)?;
                #[cfg(not(windows))]
                self.parallel_link_all(lockfile, project_dir)?;
            }
            // Hardlink + Copy: always use the parallel path (rayon).
            LinkMode::Hardlink | LinkMode::Copy => {
                self.parallel_link_all(lockfile, project_dir)?;
            }
        }
        Ok(())
    }

    /// Parallel link using rayon — used for Hardlink and Copy modes.
    fn parallel_link_all(&self, lockfile: &Lockfile, project_dir: &Path) -> Result<()> {
        use rayon::prelude::*;

        let modules_dir = project_dir.join("tallow_modules");
        fs::create_dir_all(&modules_dir).context("failed to create tallow_modules")?;

        // Validate all packages exist before touching the filesystem.
        for (name, pkg) in &lockfile.packages {
            if !self.is_cached(&pkg.content_hash) {
                anyhow::bail!(
                    "package not in store: {} (hash: {})",
                    name,
                    pkg.content_hash
                );
            }
        }

        let packages: Vec<(&String, &crate::pkg::lockfile::LockedPackage)> =
            lockfile.packages.iter().collect();

        // Use a shared error slot — first error wins.
        let first_error: Arc<std::sync::Mutex<Option<String>>> =
            Arc::new(std::sync::Mutex::new(None));

        packages.par_iter().for_each(|(name, pkg)| {
            if first_error.lock().unwrap().is_some() {
                return;
            }
            if let Err(e) = self.link_to_project(&pkg.content_hash, name, project_dir) {
                let mut slot = first_error.lock().unwrap();
                if slot.is_none() {
                    *slot = Some(format!("{}: {}", name, e));
                }
            }
        });

        let slot = first_error.lock().unwrap();
        if let Some(ref msg) = *slot {
            anyhow::bail!("link_all failed: {}", msg);
        }

        Ok(())
    }

    // ── parallel fetch ────────────────────────────────────────────────────────

    /// Download / verify multiple packages concurrently using rayon.
    ///
    /// `packages` is a slice of `(name, content_hash)` pairs.
    /// Already-cached entries are skipped immediately. The function returns
    /// the store path for each package, in input order.
    ///
    /// The `fetch_one` callback is called for packages not yet in the store.
    /// It receives `(name, content_hash)` and should return a path to a
    /// local archive that will be extracted into the store.
    pub fn parallel_fetch<F>(
        &self,
        packages: &[(String, String)],
        threads: usize,
        fetch_one: F,
    ) -> Result<Vec<PathBuf>>
    where
        F: Fn(&str, &str) -> Result<PathBuf> + Sync,
    {
        use rayon::prelude::*;

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads.max(1))
            .build()
            .context("failed to build rayon thread pool")?;

        let results: Vec<Result<PathBuf>> = pool.install(|| {
            packages
                .par_iter()
                .map(|(name, hash)| -> Result<PathBuf> {
                    if self.is_cached(hash) {
                        return Ok(self.cache_path(hash));
                    }
                    let archive = fetch_one(name, hash)?;
                    let (store_path, _) = self.store_from_archive(&archive)?;
                    Ok(store_path)
                })
                .collect()
        });

        // Flatten, surfacing the first error.
        let mut paths = Vec::with_capacity(packages.len());
        for r in results {
            paths.push(r?);
        }
        Ok(paths)
    }

    // ── store stats & maintenance ─────────────────────────────────────────────

    /// Compute disk-usage statistics for the entire store.
    ///
    /// Walks every file under the store root. This is I/O-bound so rayon is
    /// used to parallelise the `stat` calls across entries.
    pub fn cache_stats(&self) -> CacheStats {
        use rayon::prelude::*;

        if !self.root.exists() {
            return CacheStats::default();
        }

        // Collect shard bucket directories (2-char prefix dirs).
        let buckets: Vec<PathBuf> = match fs::read_dir(&self.root) {
            Ok(rd) => rd
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.is_dir())
                .collect(),
            Err(_) => return CacheStats::default(),
        };

        // Collect all entry directories (hash-named subdirs inside each bucket).
        let entries: Vec<PathBuf> = buckets
            .iter()
            .flat_map(|bucket| {
                fs::read_dir(bucket)
                    .into_iter()
                    .flatten()
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.is_dir())
            })
            .collect();

        let total_entries = entries.len() as u64;

        let (total_files, total_bytes, shared_files) = entries
            .par_iter()
            .map(|entry_dir| {
                let mut files: u64 = 0;
                let mut bytes: u64 = 0;
                let mut shared: u64 = 0;
                walk_files(entry_dir, &mut |path| {
                    files += 1;
                    if let Ok(meta) = fs::metadata(path) {
                        bytes += meta.len();
                        if hardlink_count(&meta) > 1 {
                            shared += 1;
                        }
                    }
                });
                (files, bytes, shared)
            })
            .reduce(
                || (0u64, 0u64, 0u64),
                |a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2),
            );

        CacheStats {
            entries: total_entries,
            total_files,
            total_bytes,
            shared_files,
        }
    }

    /// Remove store entries that are not hardlinked by any project.
    ///
    /// An entry is considered unreferenced when every file in it has a
    /// hardlink count of exactly 1 (only the store's own copy).
    /// On Windows, prune is conservatively a no-op because hardlink counts
    /// are not available on stable Rust.
    ///
    /// Returns the number of entries removed and bytes freed.
    pub fn cache_prune(&self) -> PruneResult {
        if !self.root.exists() {
            return PruneResult::default();
        }

        let mut result = PruneResult::default();

        let buckets: Vec<PathBuf> = fs::read_dir(&self.root)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_dir())
            .collect();

        for bucket in &buckets {
            let entries: Vec<PathBuf> = fs::read_dir(bucket)
                .into_iter()
                .flatten()
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.is_dir())
                .collect();

            for entry in entries {
                let (unreferenced, entry_bytes) = entry_is_unreferenced(&entry);
                if unreferenced {
                    if fs::remove_dir_all(&entry).is_ok() {
                        result.entries_removed += 1;
                        result.bytes_freed += entry_bytes;
                    }
                }
            }

            // Remove the now-empty shard bucket.
            let _ = fs::remove_dir(bucket);
        }

        result
    }

    /// Wipe the entire store.
    ///
    /// Returns the bytes that were freed (measured before deletion).
    pub fn cache_clean(&self) -> CleanResult {
        if !self.root.exists() {
            return CleanResult::default();
        }
        let stats = self.cache_stats();
        let _ = fs::remove_dir_all(&self.root);
        CleanResult {
            bytes_freed: stats.total_bytes,
        }
    }

    /// Verify the integrity of every file in the store by re-hashing and
    /// comparing against the expected hash embedded in the store path.
    ///
    /// Returns a (potentially empty) list of corrupted entries.
    pub fn store_verify(&self) -> Vec<IntegrityError> {
        use rayon::prelude::*;

        if !self.root.exists() {
            return Vec::new();
        }

        let buckets: Vec<PathBuf> = fs::read_dir(&self.root)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_dir())
            .collect();

        let entries: Vec<PathBuf> = buckets
            .iter()
            .flat_map(|b| {
                fs::read_dir(b)
                    .into_iter()
                    .flatten()
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.is_dir())
            })
            .collect();

        entries
            .par_iter()
            .filter_map(|entry_dir| verify_entry(entry_dir).err())
            .collect()
    }

    // ── legacy batch junction path (Windows only) ─────────────────────────────

    /// Batch-script junction install — preserved for `LinkMode::Junction` on
    /// Windows. Spawns a single cmd.exe process instead of one per package.
    #[cfg(windows)]
    fn link_all_batch_junction(&self, lockfile: &Lockfile, project_dir: &Path) -> Result<()> {
        let modules_dir = project_dir.join("tallow_modules");
        fs::create_dir_all(&modules_dir).context("failed to create tallow_modules")?;

        let mut junction_needed: Vec<(String, PathBuf, PathBuf)> = Vec::new();

        for (name, pkg) in &lockfile.packages {
            let store_path = self.cache_path(&pkg.content_hash);
            if !store_path.exists() {
                anyhow::bail!(
                    "package not in store: {} (hash: {})",
                    name,
                    pkg.content_hash
                );
            }

            let target = modules_dir.join(name);
            remove_existing(&target);

            match std::os::windows::fs::symlink_dir(&store_path, &target) {
                Ok(()) => continue,
                Err(_) => {
                    junction_needed.push((name.clone(), store_path, target));
                }
            }
        }

        if junction_needed.is_empty() {
            return Ok(());
        }

        let script_path = project_dir.join("__tallow_link.bat");
        let mut script = String::from("@echo off\r\n");
        for (_, source, target) in &junction_needed {
            script.push_str(&format!(
                "mklink /J \"{}\" \"{}\"\r\n",
                target.to_string_lossy(),
                source.to_string_lossy()
            ));
        }
        fs::write(&script_path, &script).context("failed to write junction batch script")?;

        let status = std::process::Command::new("cmd")
            .args(["/C", &script_path.to_string_lossy()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .context("failed to run junction batch script")?;

        let _ = fs::remove_file(&script_path);

        if !status.success() {
            for (name, _, _) in &junction_needed {
                if let Some(pkg) = lockfile.packages.get(name) {
                    self.link_to_project(&pkg.content_hash, name, project_dir)?;
                }
            }
        }

        Ok(())
    }
}

// ── directory linking ─────────────────────────────────────────────────────────

/// Create a directory symlink (Unix) or junction/symlink (Windows).
#[cfg(unix)]
fn create_dir_link(source: &Path, target: &Path) -> Result<()> {
    std::os::unix::fs::symlink(source, target).with_context(|| {
        format!(
            "symlink failed: {} -> {}",
            target.display(),
            source.display()
        )
    })
}

#[cfg(windows)]
fn create_dir_link(source: &Path, target: &Path) -> Result<()> {
    match std::os::windows::fs::symlink_dir(source, target) {
        Ok(()) => return Ok(()),
        Err(_) => {}
    }

    // Fall back to junction via cmd mklink /J
    let status = std::process::Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            &target.to_string_lossy(),
            &source.to_string_lossy(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("failed to run cmd mklink /J")?;

    if status.success() {
        Ok(())
    } else {
        anyhow::bail!(
            "failed to create junction {} -> {} (try enabling Developer Mode)",
            target.display(),
            source.display()
        )
    }
}

// ── file-level operations ─────────────────────────────────────────────────────

/// Attempt to hardlink `src` to `dst`.
///
/// Falls back to a plain copy when hardlinking fails (e.g. cross-filesystem).
fn hardlink_or_copy(src: &Path, dst: &Path) -> std::io::Result<()> {
    match fs::hard_link(src, dst) {
        Ok(()) => Ok(()),
        Err(_) => fs::copy(src, dst).map(|_| ()),
    }
}

/// Recursively mirror `src` into `dst` using hardlinks (with copy fallback).
fn hardlink_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            fs::create_dir_all(&dst_path)?;
            hardlink_dir_recursive(&src_path, &dst_path)?;
        } else {
            hardlink_or_copy(&src_path, &dst_path).with_context(|| {
                format!(
                    "hardlink/copy failed: {} -> {}",
                    src_path.display(),
                    dst_path.display()
                )
            })?;
        }
    }
    Ok(())
}

/// Recursively copy a directory's contents (plain copy, no hardlinks).
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            fs::create_dir_all(&dst_path)?;
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

/// Remove whatever is at `path` — file, symlink, directory, or junction.
///
/// Silently ignores "not found" errors.
fn remove_existing(path: &Path) {
    if path.exists() || path.symlink_metadata().is_ok() {
        let _ = fs::remove_file(path);
        let _ = fs::remove_dir(path);
        let _ = fs::remove_dir_all(path);
    }
}

// ── stats helpers ─────────────────────────────────────────────────────────────

/// Walk all regular files under `dir`, calling `f` for each.
fn walk_files(dir: &Path, f: &mut impl FnMut(&Path)) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for entry in rd.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            walk_files(&path, f);
        } else {
            f(&path);
        }
    }
}

/// Return the hard-link count for a file from its metadata.
#[cfg(unix)]
fn hardlink_count(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.nlink()
}

/// On Windows, `number_of_links()` requires the unstable `windows_by_handle`
/// feature, so we conservatively return 2 to prevent prune from removing any
/// entry — a safe over-approximation.
#[cfg(windows)]
fn hardlink_count(_meta: &std::fs::Metadata) -> u64 {
    2
}

#[cfg(not(any(unix, windows)))]
fn hardlink_count(_meta: &std::fs::Metadata) -> u64 {
    1
}

/// Return `(all_unreferenced, total_bytes)` for a store entry directory.
///
/// "Unreferenced" means every regular file has a hardlink count of 1 —
/// meaning only the store itself holds a reference.
fn entry_is_unreferenced(entry_dir: &Path) -> (bool, u64) {
    let mut total_bytes = 0u64;
    let mut any_shared = false;

    walk_files(entry_dir, &mut |path| {
        if let Ok(meta) = fs::metadata(path) {
            total_bytes += meta.len();
            if hardlink_count(&meta) > 1 {
                any_shared = true;
            }
        }
    });

    (!any_shared, total_bytes)
}

// ── integrity verification ────────────────────────────────────────────────────

/// Verify that the BLAKE3 hash of all files in an entry matches the hash
/// encoded in the entry's directory name.
///
/// Returns `Err(IntegrityError)` on mismatch, `Ok(())` when clean.
fn verify_entry(entry_dir: &Path) -> std::result::Result<(), IntegrityError> {
    let expected_hash = entry_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();

    if expected_hash.is_empty() {
        return Ok(());
    }

    // Hash all file contents together, sorted for determinism.
    let mut file_paths: Vec<PathBuf> = Vec::new();
    walk_files(entry_dir, &mut |p| file_paths.push(p.to_path_buf()));
    file_paths.sort();

    let mut hasher = blake3::Hasher::new();
    for path in &file_paths {
        if let Ok(data) = fs::read(path) {
            hasher.update(&data);
        }
    }
    let actual_hash = hasher.finalize().to_hex().to_string();

    if actual_hash == expected_hash {
        Ok(())
    } else {
        Err(IntegrityError {
            store_path: entry_dir.to_path_buf(),
            expected_hash,
            actual_hash,
        })
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cache(tmp: &Path) -> GlobalCache {
        GlobalCache::new(tmp.join("store"))
    }

    fn write_pkg(dir: &Path, files: &[(&str, &str)]) {
        for (name, contents) in files {
            let path = dir.join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, contents).unwrap();
        }
    }

    #[test]
    fn test_cache_path_sharding() {
        let cache = make_cache(Path::new("/tmp/test"));
        let hash = "abcdef1234567890";
        let p = cache.cache_path(hash);
        assert!(p.to_string_lossy().contains("ab"));
        assert!(p.to_string_lossy().contains(hash));
    }

    #[test]
    fn test_store_and_retrieve() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = make_cache(tmp.path());

        let src = tmp.path().join("src_pkg");
        fs::create_dir_all(&src).unwrap();
        write_pkg(&src, &[("lib.tl", "fn hello() {}"), ("README.txt", "hello")]);

        let hash = "deadbeef00112233";
        assert!(!cache.is_cached(hash));

        let dest = cache.store_package(hash, &src).unwrap();
        assert!(cache.is_cached(hash));
        assert!(dest.join("lib.tl").exists());

        // Idempotent second call must succeed.
        let dest2 = cache.store_package(hash, &src).unwrap();
        assert_eq!(dest, dest2);
    }

    #[test]
    fn test_hardlink_install() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = make_cache(tmp.path()).with_link_mode(LinkMode::Hardlink);

        let src = tmp.path().join("pkg_src");
        write_pkg(&src, &[("main.tl", "fn main() {}")]);
        let hash = "c0ffee0011223344";
        cache.store_package(hash, &src).unwrap();

        let proj = tmp.path().join("project");
        fs::create_dir_all(&proj).unwrap();

        cache.link_to_project(hash, "my-pkg", &proj).unwrap();
        assert!(
            proj.join("tallow_modules").join("my-pkg").join("main.tl").exists(),
            "hardlink install should produce tallow_modules/my-pkg/main.tl"
        );
    }

    #[test]
    fn test_copy_install() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = make_cache(tmp.path()).with_link_mode(LinkMode::Copy);

        let src = tmp.path().join("pkg_src2");
        write_pkg(&src, &[("api.tl", "fn api() {}")]);
        let hash = "aabbccddeeff0011";
        cache.store_package(hash, &src).unwrap();

        let proj = tmp.path().join("project2");
        fs::create_dir_all(&proj).unwrap();
        cache.link_to_project(hash, "api-pkg", &proj).unwrap();

        assert!(proj.join("tallow_modules").join("api-pkg").join("api.tl").exists());
    }

    #[test]
    fn test_cache_stats_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = make_cache(tmp.path());
        let stats = cache.cache_stats();
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.total_files, 0);
    }

    #[test]
    fn test_cache_stats_with_data() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = make_cache(tmp.path());

        let src = tmp.path().join("p");
        write_pkg(&src, &[("a.tl", "content_a"), ("b.tl", "content_b")]);
        cache.store_package("aabbcc001122", &src).unwrap();

        let stats = cache.cache_stats();
        assert_eq!(stats.entries, 1);
        assert_eq!(stats.total_files, 2);
        assert!(stats.total_bytes > 0);
    }

    #[test]
    fn test_cache_prune_unreferenced_unix() {
        // On Unix we can verify prune actually removes entries.
        // On Windows the conservative hardlink_count returns 2, so prune
        // will never remove entries — that is intentional safe behaviour.
        let tmp = tempfile::tempdir().unwrap();
        let cache = make_cache(tmp.path());

        let src = tmp.path().join("p2");
        write_pkg(&src, &[("x.tl", "hello")]);
        let hash = "deadc0de00112233";
        cache.store_package(hash, &src).unwrap();

        assert!(cache.is_cached(hash));

        let result = cache.cache_prune();

        #[cfg(unix)]
        {
            // On Unix hardlink count is real: store-only entry has nlink==1 → pruned.
            assert_eq!(result.entries_removed, 1);
            assert!(!cache.is_cached(hash));
        }
        #[cfg(windows)]
        {
            // On Windows we never prune to avoid false-positives.
            assert_eq!(result.entries_removed, 0);
            assert!(cache.is_cached(hash));
        }
    }

    #[test]
    fn test_cache_clean() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = make_cache(tmp.path());

        let src = tmp.path().join("p3");
        write_pkg(&src, &[("z.tl", "world")]);
        cache.store_package("ff00ff00112233aa", &src).unwrap();

        let clean = cache.cache_clean();
        assert!(clean.bytes_freed > 0);
        assert!(!cache.root.exists());
    }

    #[test]
    fn test_store_verify_empty_store() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = make_cache(tmp.path());
        let errors = cache.store_verify();
        assert!(errors.is_empty());
    }

    #[test]
    fn test_link_mode_default_is_hardlink() {
        let cache = GlobalCache::new(PathBuf::from("/tmp/x"));
        assert_eq!(cache.link_mode, LinkMode::Hardlink);
    }

    #[test]
    fn test_with_link_mode_builder() {
        let cache = GlobalCache::new(PathBuf::from("/tmp/y")).with_link_mode(LinkMode::Copy);
        assert_eq!(cache.link_mode, LinkMode::Copy);
    }

    #[test]
    fn test_parallel_fetch_cached_skips_fetch() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = make_cache(tmp.path());

        let src = tmp.path().join("pre");
        write_pkg(&src, &[("pre.tl", "fn pre() {}")]);
        let hash = "1122334455667788";
        cache.store_package(hash, &src).unwrap();

        // fetch_one must NOT be called since the entry is already cached.
        let fetch_called =
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fetch_called2 = fetch_called.clone();
        let packages = vec![("pre-pkg".to_string(), hash.to_string())];

        let result = cache.parallel_fetch(&packages, 2, move |_, _| {
            fetch_called2.store(true, std::sync::atomic::Ordering::SeqCst);
            Err(anyhow::anyhow!("should not be called"))
        });

        assert!(result.is_ok());
        assert_eq!(result.unwrap()[0], cache.cache_path(hash));
        assert!(!fetch_called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_parallel_link_all_empty_lockfile() {
        use std::collections::BTreeMap;
        let tmp = tempfile::tempdir().unwrap();
        let cache = make_cache(tmp.path());

        let lockfile = crate::pkg::lockfile::Lockfile {
            lockfile_version: 1,
            packages: BTreeMap::new(),
        };
        let proj = tmp.path().join("proj");
        fs::create_dir_all(&proj).unwrap();

        assert!(cache.link_all(&lockfile, &proj).is_ok());
    }
}
