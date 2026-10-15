//! One-way directory synchronization
//!
//! Compares a local directory manifest against a remote manifest and produces
//! a diff of new, changed, and deleted files. This is used by the `send --sync`
//! command to transfer only the files that have changed.

use crate::transfer::manifest::{FileEntry, FileManifest};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

/// Result of comparing local vs remote directory state.
///
/// Contains three categories of files: new (exist only locally), changed
/// (exist on both sides but with different hashes), and deleted (exist only
/// on the remote side).
#[derive(Debug, Clone)]
pub struct SyncDiff {
    /// Files that exist locally but not remotely
    pub new_files: Vec<FileEntry>,
    /// Files that exist on both sides but have different hashes
    pub changed_files: Vec<FileEntry>,
    /// Files that exist remotely but not locally
    pub deleted_files: Vec<FileEntry>,
}

impl SyncDiff {
    /// Returns true if there are no differences.
    pub fn is_empty(&self) -> bool {
        self.new_files.is_empty() && self.changed_files.is_empty() && self.deleted_files.is_empty()
    }

    /// Total number of files that need to be transferred (new + changed).
    pub fn transfer_count(&self) -> usize {
        self.new_files.len() + self.changed_files.len()
    }

    /// Total bytes that need to be transferred (new + changed).
    pub fn transfer_bytes(&self) -> u64 {
        let new_bytes: u64 = self.new_files.iter().map(|f| f.size).sum();
        let changed_bytes: u64 = self.changed_files.iter().map(|f| f.size).sum();
        new_bytes + changed_bytes
    }

    /// Fraction of remote files that would be deleted (safety check).
    ///
    /// Returns 0.0 if the remote has no files. Callers should warn or abort
    /// when the deletion fraction is above a configurable threshold (e.g., 0.5).
    pub fn deletion_fraction(&self, remote_file_count: usize) -> f64 {
        if remote_file_count == 0 {
            return 0.0;
        }
        self.deleted_files.len() as f64 / remote_file_count as f64
    }
}

/// Compute the diff between a local file list and a remote manifest.
///
/// Iterates through `local_files` and compares each entry against the
/// `remote_manifest` by relative path and BLAKE3 hash. Files present
/// only in the remote are marked as deleted.
pub fn compute_sync_diff(local_files: &[FileEntry], remote_manifest: &FileManifest) -> SyncDiff {
    let remote_map: HashMap<&PathBuf, &FileEntry> =
        remote_manifest.files.iter().map(|f| (&f.path, f)).collect();

    let mut new_files = Vec::new();
    let mut changed_files = Vec::new();

    for local in local_files {
        match remote_map.get(&local.path) {
            None => new_files.push(local.clone()),
            Some(remote) => {
                if local.hash != remote.hash {
                    changed_files.push(local.clone());
                }
            }
        }
    }

    let local_paths: HashSet<&PathBuf> = local_files.iter().map(|f| &f.path).collect();
    let deleted_files: Vec<FileEntry> = remote_manifest
        .files
        .iter()
        .filter(|f| !local_paths.contains(&f.path))
        .cloned()
        .collect();

    SyncDiff {
        new_files,
        changed_files,
        deleted_files,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a FileEntry with the given path, size, and hash byte.
    fn entry(path: &str, size: u64, hash_byte: u8) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            size,
            hash: [hash_byte; 32],
            chunk_count: size.div_ceil(64 * 1024),
        }
    }

    /// Helper to create a FileManifest from a list of FileEntry items.
    fn manifest_from(entries: Vec<FileEntry>) -> FileManifest {
        let total_size: u64 = entries.iter().map(|e| e.size).sum();
        let total_chunks: u64 = entries.iter().map(|e| e.chunk_count).sum();
        FileManifest {
            files: entries,
            total_size,
            total_chunks,
            chunk_size: 64 * 1024,
            compression: None,
            manifest_hash: None,
            transfer_type: Default::default(),
            per_chunk_compression: true,
        }
    }

    // ── identical manifests ──────────────────────────────────────

    #[test]
    fn identical_manifests_produce_empty_diff() {
        let files = vec![entry("a.txt", 100, 0xAA), entry("b.txt", 200, 0xBB)];
        let remote = manifest_from(files.clone());

        let diff = compute_sync_diff(&files, &remote);

        assert!(diff.is_empty());
        assert_eq!(diff.transfer_count(), 0);
        assert_eq!(diff.transfer_bytes(), 0);
    }

    // ── all new files ────────────────────────────────────────────

    #[test]
    fn all_new_files() {
        let local = vec![entry("new1.txt", 100, 0x01), entry("new2.txt", 200, 0x02)];
        let remote = manifest_from(vec![]);

        let diff = compute_sync_diff(&local, &remote);

        assert_eq!(diff.new_files.len(), 2);
        assert!(diff.changed_files.is_empty());
        assert!(diff.deleted_files.is_empty());
        assert_eq!(diff.transfer_count(), 2);
        assert_eq!(diff.transfer_bytes(), 300);
    }

    // ── all changed files ────────────────────────────────────────

    #[test]
    fn all_changed_files() {
        let local = vec![
            entry("a.txt", 150, 0x01), // different hash from remote
            entry("b.txt", 250, 0x02),
        ];
        let remote = manifest_from(vec![
            entry("a.txt", 100, 0xAA), // same path, different hash
            entry("b.txt", 200, 0xBB),
        ]);

        let diff = compute_sync_diff(&local, &remote);

        assert!(diff.new_files.is_empty());
        assert_eq!(diff.changed_files.len(), 2);
        assert!(diff.deleted_files.is_empty());
        assert_eq!(diff.transfer_count(), 2);
        // transfer_bytes uses local sizes (the files being sent)
        assert_eq!(diff.transfer_bytes(), 400);
    }

    // ── mixed: new, changed, and deleted ─────────────────────────

    #[test]
    fn mixed_new_changed_deleted() {
        let local = vec![
            entry("unchanged.txt", 100, 0xAA), // same hash on both sides
            entry("changed.txt", 300, 0x02),   // hash differs
            entry("brand_new.txt", 500, 0x03), // only local
        ];
        let remote = manifest_from(vec![
            entry("unchanged.txt", 100, 0xAA),
            entry("changed.txt", 200, 0xBB), // different hash
            entry("gone.txt", 400, 0xCC),    // only remote
        ]);

        let diff = compute_sync_diff(&local, &remote);

        assert_eq!(diff.new_files.len(), 1);
        assert_eq!(diff.new_files[0].path, PathBuf::from("brand_new.txt"));

        assert_eq!(diff.changed_files.len(), 1);
        assert_eq!(diff.changed_files[0].path, PathBuf::from("changed.txt"));

        assert_eq!(diff.deleted_files.len(), 1);
        assert_eq!(diff.deleted_files[0].path, PathBuf::from("gone.txt"));

        assert_eq!(diff.transfer_count(), 2); // new + changed
        assert_eq!(diff.transfer_bytes(), 800); // 500 + 300
    }

    // ── all deleted files ────────────────────────────────────────

    #[test]
    fn all_deleted_files() {
        let local: Vec<FileEntry> = vec![];
        let remote = manifest_from(vec![
            entry("old1.txt", 100, 0x01),
            entry("old2.txt", 200, 0x02),
            entry("old3.txt", 300, 0x03),
        ]);

        let diff = compute_sync_diff(&local, &remote);

        assert!(diff.new_files.is_empty());
        assert!(diff.changed_files.is_empty());
        assert_eq!(diff.deleted_files.len(), 3);
        assert_eq!(diff.transfer_count(), 0);
        assert_eq!(diff.transfer_bytes(), 0);
    }

    // ── both empty ───────────────────────────────────────────────

    #[test]
    fn both_empty() {
        let diff = compute_sync_diff(&[], &manifest_from(vec![]));
        assert!(diff.is_empty());
    }

    // ── deletion_fraction ────────────────────────────────────────

    #[test]
    fn deletion_fraction_zero_remote() {
        let diff = SyncDiff {
            new_files: vec![],
            changed_files: vec![],
            deleted_files: vec![entry("x.txt", 100, 0x01)],
        };
        // remote_file_count == 0 -> returns 0.0 (no division by zero)
        assert_eq!(diff.deletion_fraction(0), 0.0);
    }

    #[test]
    fn deletion_fraction_none_deleted() {
        let diff = SyncDiff {
            new_files: vec![entry("new.txt", 100, 0x01)],
            changed_files: vec![],
            deleted_files: vec![],
        };
        assert_eq!(diff.deletion_fraction(5), 0.0);
    }

    #[test]
    fn deletion_fraction_all_deleted() {
        let diff = SyncDiff {
            new_files: vec![],
            changed_files: vec![],
            deleted_files: vec![entry("a.txt", 100, 0x01), entry("b.txt", 200, 0x02)],
        };
        assert!((diff.deletion_fraction(2) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn deletion_fraction_partial() {
        let diff = SyncDiff {
            new_files: vec![],
            changed_files: vec![],
            deleted_files: vec![entry("a.txt", 100, 0x01)],
        };
        // 1 deleted out of 4 remote = 0.25
        assert!((diff.deletion_fraction(4) - 0.25).abs() < f64::EPSILON);
    }

    // ── transfer_bytes ───────────────────────────────────────────

    #[test]
    fn transfer_bytes_sums_new_and_changed() {
        let diff = SyncDiff {
            new_files: vec![entry("n.txt", 1000, 0x01)],
            changed_files: vec![entry("c1.txt", 2000, 0x02), entry("c2.txt", 3000, 0x03)],
            deleted_files: vec![entry("d.txt", 9999, 0x04)],
        };
        // Deleted files are NOT counted in transfer_bytes
        assert_eq!(diff.transfer_bytes(), 6000);
    }

    #[test]
    fn transfer_bytes_empty() {
        let diff = SyncDiff {
            new_files: vec![],
            changed_files: vec![],
            deleted_files: vec![],
        };
        assert_eq!(diff.transfer_bytes(), 0);
    }

    // ── is_empty ─────────────────────────────────────────────────

    #[test]
    fn is_empty_true_when_no_diffs() {
        let diff = SyncDiff {
            new_files: vec![],
            changed_files: vec![],
            deleted_files: vec![],
        };
        assert!(diff.is_empty());
    }

    #[test]
    fn is_empty_false_with_new() {
        let diff = SyncDiff {
            new_files: vec![entry("x.txt", 1, 0x01)],
            changed_files: vec![],
            deleted_files: vec![],
        };
        assert!(!diff.is_empty());
    }

    #[test]
    fn is_empty_false_with_changed() {
        let diff = SyncDiff {
            new_files: vec![],
            changed_files: vec![entry("x.txt", 1, 0x01)],
            deleted_files: vec![],
        };
        assert!(!diff.is_empty());
    }

    #[test]
    fn is_empty_false_with_deleted() {
        let diff = SyncDiff {
            new_files: vec![],
            changed_files: vec![],
            deleted_files: vec![entry("x.txt", 1, 0x01)],
        };
        assert!(!diff.is_empty());
    }
}
