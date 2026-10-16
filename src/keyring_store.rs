//! Keyring persistence + erasure audit surface (task A2.1.1 remainder ·
//! frozen interface §2).
//!
//! [`crate::shred::ShredKeyring`] holds crypto-shredding key material in
//! memory only. This module is its **durable metadata** counterpart: a
//! [`KeyringStore`] persists, per investigation, the *identity* of every key
//! ever issued — key id, fingerprint, allocation time, destroyed flag —
//! never the key bytes.
//!
//! # Design constraint: metadata-only, by design
//!
//! Raw key material is **never** written to disk here, not even encrypted:
//! persisting a readable copy of a key would defeat crypto-shredding, since
//! an attacker (or a subpoena) could recover the key from storage after the
//! in-memory copy was shredded. Storage therefore keeps only what an audit
//! needs to *attest* lifecycle facts:
//!
//! * which key ids existed for an investigation ([`KeyMeta::key_id`]),
//! * their deterministic fingerprints ([`KeyMeta::fp8`]),
//! * when they were allocated ([`KeyMeta::created_ms`]),
//! * whether they were destroyed ([`KeyMeta::destroyed`]).
//!
//! The pairing rule with [`crate::shred`]: destruction of key material
//! happens in memory ([`crate::shred::ShredKeyring::destroy`], which emits an
//! [`crate::shred::ErasureEvent`] tombstone for the ledger); this store's
//! [`KeyringStore::mark_destroyed`] / [`destroy_flow`] record the same fact in
//! the metadata file, and [`KeyringStore::destroy_on_disk`] erases even the
//! *audit surface*. The two halves are intentionally independent: losing the
//! metadata file never resurrects a shredded key, and losing the keyring
//! never blinds the audit.
//!
//! # File layout
//!
//! ```text
//! {root}/{investigation}/meta.json
//! ```
//!
//! `meta.json` is written atomically (write to a pid+seq-suffixed temp file
//! in the same directory, then `rename`), so a crash mid-write leaves either
//! the old or the new file, never a torn one. Investigation ids are validated
//! as single path components: empty, any `/`, or containing `..` (and the
//! lone `.`, which would collapse to the root itself) → [`KeyringStoreError::BadId`].
//! The rule is deliberately a *superset* of the frozen spec's three cases;
//! the extra `"."` rejection closes a path-collapse oddity rather than adding
//! functionality.
//!
//! # Bridge from the live keyring
//!
//! [`meta_from_keyring`] reads [`crate::shred::ShredKeyring`]'s public
//! enumeration surface (`records()`, which already includes destroyed keys)
//! and filters it by investigation. The `fp8` fingerprint is recovered from
//! the key id itself — `shred.rs` documents and tests the scheme
//! `shred-<seq:08x>-<fp8>` where `fp8` is the first 4 bytes of
//! `BLAKE3("tallow-shred-key-id-v1" ‖ key)` in lowercase hex — because the
//! raw key bytes are (correctly) not exposed. If an id does not match that
//! documented shape, the full id is stored as `fp8` (identity preserved, no
//! fabricated fingerprint) and the caller can treat the field as opaque.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// File name of the persisted keyring metadata inside each investigation
/// directory.
pub const META_FILE: &str = "meta.json";

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// Persisted metadata for one key: identity + lifecycle facts, never key
/// bytes. Serializable for exactly that reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyMeta {
    /// Key identity, `shred-<seq:08x>-<fp8>` (see [`crate::shred`] module
    /// docs for the scheme).
    pub key_id: String,
    /// Fingerprint segment of the key id (8 lowercase hex chars in the
    /// documented scheme; the full id if the shape is unknown — treat as
    /// opaque).
    pub fp8: String,
    /// Allocation time (Unix milliseconds, copied from the shred record).
    pub created_ms: i64,
    /// Whether the key's material has been shredded. A destroyed flag here
    /// is an *audit fact*; the readability of blobs under that key was ended
    /// in memory by [`crate::shred::ShredKeyring::destroy`].
    pub destroyed: bool,
}

/// Persisted metadata for one investigation: its key set, sorted by
/// `key_id` when produced by [`meta_from_keyring`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyringMeta {
    /// The investigation this keyring belongs to.
    pub investigation: String,
    /// Metadata for every key ever issued for the investigation (live and
    /// destroyed alike).
    pub keys: Vec<KeyMeta>,
}

/// Filesystem-backed keyring metadata store rooted at `root`; each
/// investigation is a subdirectory holding a single `meta.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyringStore {
    root: PathBuf,
}

/// Errors from [`KeyringStore`] operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyringStoreError {
    /// Filesystem failure (message carries the OS error; never key material —
    /// no key material ever passes through this module's I/O).
    Io(String),
    /// JSON encode/decode failure.
    Codec(String),
    /// No metadata exists for the investigation (or no such key inside it).
    NotFound,
    /// Investigation id is not a single path component (empty, contains
    /// `/`, contains `..`, or is `.`).
    BadId,
}

impl fmt::Display for KeyringStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyringStoreError::Io(msg) => write!(f, "keyring_store: io error: {msg}"),
            KeyringStoreError::Codec(msg) => write!(f, "keyring_store: codec error: {msg}"),
            KeyringStoreError::NotFound => {
                write!(f, "keyring_store: no keyring metadata found")
            }
            KeyringStoreError::BadId => write!(
                f,
                "keyring_store: bad investigation id (must be one path component: \
                 non-empty, no '/', no '..', not '.')"
            ),
        }
    }
}

impl std::error::Error for KeyringStoreError {}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

impl KeyringStore {
    /// New store rooted at `root` (the directory is created lazily on first
    /// successful [`KeyringStore::save`]).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The configured root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Persist `meta` atomically to `{root}/{investigation}/meta.json` and
    /// return that path. The investigation id comes from `meta.investigation`
    /// and is validated ([`KeyringStoreError::BadId`]); key ids are stored as
    /// data, not as path components, so they are not id-validated.
    pub fn save(&self, meta: &KeyringMeta) -> Result<PathBuf, KeyringStoreError> {
        let path = self.meta_path(&meta.investigation)?;
        let json = serde_json::to_string_pretty(meta)
            .map_err(|e| KeyringStoreError::Codec(e.to_string()))?;
        Self::write_atomic(&path, json.as_bytes())?;
        Ok(path)
    }

    /// Load the metadata for `investigation`; missing file →
    /// [`KeyringStoreError::NotFound`], undecodable file →
    /// [`KeyringStoreError::Codec`], bad id → [`KeyringStoreError::BadId`].
    pub fn load(&self, investigation: &str) -> Result<KeyringMeta, KeyringStoreError> {
        let path = self.meta_path(investigation)?;
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(KeyringStoreError::NotFound);
            }
            Err(e) => return Err(KeyringStoreError::Io(e.to_string())),
        };
        serde_json::from_slice(&bytes).map_err(|e| KeyringStoreError::Codec(e.to_string()))
    }

    /// Flip the `destroyed` flag of `key_id` inside `investigation`'s
    /// metadata, rewrite the file, and return the updated [`KeyMeta`].
    ///
    /// Unknown key → [`KeyringStoreError::NotFound`]. Calling this for an
    /// already-destroyed key is **idempotent** (returns `Ok` with
    /// `destroyed == true` and rewrites the file): the frozen error enum has
    /// no `AlreadyDestroyed` variant, and the durable fact — "this key was
    /// shredded" — is the same either way. The in-memory counterpart
    /// [`crate::shred::ShredKeyring::destroy`] *does* report
    /// `AlreadyDestroyed` for a double shred; the asymmetry is deliberate:
    /// the store records state, the keyring enforces the state machine.
    pub fn mark_destroyed(
        &self,
        investigation: &str,
        key_id: &str,
    ) -> Result<KeyMeta, KeyringStoreError> {
        let mut meta = self.load(investigation)?;
        let key = meta
            .keys
            .iter_mut()
            .find(|k| k.key_id == key_id)
            .ok_or(KeyringStoreError::NotFound)?;
        key.destroyed = true;
        let updated = key.clone();
        self.save(&meta)?;
        Ok(updated)
    }

    /// Erase the *audit surface* for `investigation`: best-effort overwrite
    /// of `meta.json` with zero bytes, then unlink the file, then remove the
    /// investigation directory (including any stray temp files).
    ///
    /// This is **not** the crypto-shredding step: key material lives only in
    /// [`crate::shred::ShredKeyring`] and is destroyed there
    /// ([`crate::shred::ShredKeyring::destroy`]). What this method erases is
    /// the persisted metadata trail for the investigation — after it runs,
    /// [`KeyringStore::load`] returns [`KeyringStoreError::NotFound`].
    ///
    /// Only a regular file is erased; a symlink or other non-regular entry at
    /// the meta path → [`KeyringStoreError::NotFound`] (fail closed — nothing
    /// is followed or overwritten through a link). Missing metadata →
    /// [`KeyringStoreError::NotFound`]. The overwrite pass is best-effort
    /// (some filesystems/security modules make it a no-op); the unlink and
    /// directory removal are authoritative and their failures surface as
    /// [`KeyringStoreError::Io`].
    pub fn destroy_on_disk(&self, investigation: &str) -> Result<(), KeyringStoreError> {
        let dir = self.dir_path(investigation)?;
        let path = dir.join(META_FILE);

        let md = match fs::symlink_metadata(&path) {
            Ok(md) => md,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(KeyringStoreError::NotFound);
            }
            Err(e) => return Err(KeyringStoreError::Io(e.to_string())),
        };
        if !md.is_file() {
            return Err(KeyringStoreError::NotFound);
        }

        Self::overwrite_zeros(&path, md.len());

        fs::remove_file(&path).map_err(|e| KeyringStoreError::Io(e.to_string()))?;
        fs::remove_dir_all(&dir).map_err(|e| KeyringStoreError::Io(e.to_string()))?;
        Ok(())
    }

    /// Sorted, deduplicated investigation ids that have persisted metadata
    /// under the root (a directory without `meta.json` is ignored; a missing
    /// or unreadable root lists nothing rather than failing).
    pub fn list(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.join(META_FILE).is_file() {
                    continue;
                }
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    out.push(name.to_string());
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    // -- internals ----------------------------------------------------------

    /// Validated directory for `investigation`.
    fn dir_path(&self, investigation: &str) -> Result<PathBuf, KeyringStoreError> {
        validate_id(investigation)?;
        Ok(self.root.join(investigation))
    }

    /// Validated `meta.json` path for `investigation`.
    fn meta_path(&self, investigation: &str) -> Result<PathBuf, KeyringStoreError> {
        Ok(self.dir_path(investigation)?.join(META_FILE))
    }

    /// Atomic write: temp file in the destination directory (pid + per-process
    /// sequence suffix), fsync, rename over the target. Cleans the temp file
    /// on any failure so a crashed save cannot poison [`KeyringStore::list`].
    fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), KeyringStoreError> {
        static TMP_SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = path
            .parent()
            .ok_or_else(|| KeyringStoreError::Io("metadata path has no parent".to_string()))?;
        fs::create_dir_all(dir).map_err(|e| KeyringStoreError::Io(e.to_string()))?;

        let tmp = dir.join(format!(
            "{META_FILE}.tmp-{}-{}",
            std::process::id(),
            TMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));

        let write_result = (|| -> std::io::Result<()> {
            let mut f = File::create(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            Ok(())
        })();
        if let Err(e) = write_result {
            let _ = fs::remove_file(&tmp);
            return Err(KeyringStoreError::Io(e.to_string()));
        }

        if let Err(e) = fs::rename(&tmp, path) {
            let _ = fs::remove_file(&tmp);
            return Err(KeyringStoreError::Io(e.to_string()));
        }
        Ok(())
    }

    /// Best-effort zero-overwrite of `len` bytes (ignores all errors — the
    /// caller's unlink is what makes erasure authoritative).
    fn overwrite_zeros(path: &Path, len: u64) {
        if let Ok(mut f) = OpenOptions::new().write(true).open(path) {
            let chunk = [0u8; 8192];
            let mut remaining = len;
            while remaining > 0 {
                let n = remaining.min(chunk.len() as u64) as usize;
                if f.write_all(&chunk[..n]).is_err() {
                    break;
                }
                remaining -= n as u64;
            }
            let _ = f.sync_all();
        }
    }
}

/// Investigation ids must be a single, ordinary path component: non-empty,
/// no `/` anywhere, no `..` anywhere (so `../x`, `a..b` and a bare `..` are
/// all rejected), and not the lone `.` (which would collapse the target path
/// onto the root itself). Deliberately stricter than "no separator": a
/// defense-in-depth rule with no legitimate name excluded except `.` and
/// `..`-containing strings.
fn validate_id(id: &str) -> Result<(), KeyringStoreError> {
    if id.is_empty() || id == "." || id.contains('/') || id.contains("..") {
        return Err(KeyringStoreError::BadId);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Bridge from the live keyring
// ---------------------------------------------------------------------------

/// Build the persistable [`KeyringMeta`] for `investigation` from a live
/// [`crate::shred::ShredKeyring`].
///
/// Reader strategy (documented, since [`crate::shred::ShredKeyring`] exposes
/// enumeration but not key bytes): iterate the ring's `records()` — the
/// public, ascending-by-`key_id`, live+destroyed history — filter by
/// `investigation`, and map each [`crate::shred::KeyRecord`] to a
/// [`KeyMeta`]. `fp8` is recovered from the documented key-id scheme
/// `shred-<seq:08x>-<fp8>`; ids that do not match the shape keep their full
/// id in `fp8`. Infallible: an unknown investigation simply yields an empty
/// key list. Output order is deterministic (ascending `key_id`).
pub fn meta_from_keyring(
    investigation: &str,
    keyring: &crate::shred::ShredKeyring,
) -> KeyringMeta {
    let keys = keyring
        .records()
        .filter(|r| r.investigation == investigation)
        .map(|r| KeyMeta {
            key_id: r.key_id.clone(),
            fp8: fp8_from_key_id(&r.key_id),
            created_ms: r.created_ms,
            destroyed: r.destroyed_ms.is_some(),
        })
        .collect();
    KeyringMeta {
        investigation: investigation.to_string(),
        keys,
    }
}

/// Convenience: persist the reconciliation of one key's destruction —
/// [`KeyringStore::mark_destroyed`] against the store. Kept as a named
/// function so callers (and audits) read a single intent-revealing entry
/// point: "this key's destruction has been recorded".
pub fn destroy_flow(
    store: &KeyringStore,
    investigation: &str,
    key_id: &str,
) -> Result<KeyMeta, KeyringStoreError> {
    store.mark_destroyed(investigation, key_id)
}

/// Recover the fingerprint segment of a `shred-<seq:08x>-<fp8>` key id;
/// falls back to the full id when the shape is unknown (never fabricates a
/// fingerprint, never truncates silently to something misleading).
fn fp8_from_key_id(key_id: &str) -> String {
    if let Some(body) = key_id.strip_prefix("shred-") {
        if let Some((seq, fp)) = body.split_once('-') {
            if seq.len() == 8
                && seq.chars().all(|c| c.is_ascii_hexdigit())
                && fp.len() == 8
                && fp.chars().all(|c| c.is_ascii_hexdigit())
            {
                return fp.to_ascii_lowercase();
            }
        }
    }
    key_id.to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    /// Unique, self-cleaning scratch root under the system temp dir
    /// (std-only: no `tempfile` dependency).
    fn tmp_root(tag: &str) -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "tallow-keyring-store-{}-{}-{}",
            std::process::id(),
            tag,
            n
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_meta() -> KeyringMeta {
        KeyringMeta {
            investigation: "inv-1".to_string(),
            keys: vec![
                KeyMeta {
                    key_id: "shred-00000001-0a0b0c0d".to_string(),
                    fp8: "0a0b0c0d".to_string(),
                    created_ms: 1_000,
                    destroyed: false,
                },
                KeyMeta {
                    key_id: "shred-00000002-1e2f3a4b".to_string(),
                    fp8: "1e2f3a4b".to_string(),
                    created_ms: 2_000,
                    destroyed: true,
                },
            ],
        }
    }

    #[test]
    fn meta_roundtrip_save_load_equality() {
        let root = tmp_root("roundtrip");
        let store = KeyringStore::new(&root);
        let meta = sample_meta();

        let path = store.save(&meta).unwrap();
        assert_eq!(path, root.join("inv-1").join("meta.json"));
        assert_eq!(store.load("inv-1").unwrap(), meta);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn atomic_path_shape_no_tmp_residue() {
        let root = tmp_root("shape");
        let store = KeyringStore::new(&root);
        store.save(&sample_meta()).unwrap();

        let dir = root.join("inv-1");
        let names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["meta.json".to_string()], "temp file residue: {names:?}");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn bad_ids_rejected() {
        let root = tmp_root("bad-ids");
        let store = KeyringStore::new(&root);

        for bad in ["", "..", ".", "a/b", "../escape", "x..y", "/abs", "trailing/"] {
            let mut meta = sample_meta();
            meta.investigation = bad.to_string();
            assert_eq!(
                store.save(&meta).unwrap_err(),
                KeyringStoreError::BadId,
                "save accepted bad id {bad:?}"
            );
            assert_eq!(store.load(bad).unwrap_err(), KeyringStoreError::BadId);
            assert_eq!(store.destroy_on_disk(bad).unwrap_err(), KeyringStoreError::BadId);
            assert_eq!(store.mark_destroyed(bad, "k").unwrap_err(), KeyringStoreError::BadId);
        }
        // Nothing was written outside the root (root itself is empty).
        assert_eq!(store.list(), Vec::<String>::new());
        assert!(!root.join("meta.json").exists(), "id traversal must not write at root");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn mark_destroyed_flips_and_persists() {
        let root = tmp_root("mark");
        let store = KeyringStore::new(&root);
        store.save(&sample_meta()).unwrap();

        let updated = store
            .mark_destroyed("inv-1", "shred-00000001-0a0b0c0d")
            .unwrap();
        assert!(updated.destroyed);
        assert_eq!(updated.key_id, "shred-00000001-0a0b0c0d");
        assert_eq!(updated.fp8, "0a0b0c0d");
        assert_eq!(updated.created_ms, 1_000);

        // Persisted across a fresh store instance over the same root.
        let reopened = KeyringStore::new(&root);
        let loaded = reopened.load("inv-1").unwrap();
        let k = loaded
            .keys
            .iter()
            .find(|k| k.key_id == "shred-00000001-0a0b0c0d")
            .unwrap();
        assert!(k.destroyed);
        // The other key is untouched.
        let other = loaded
            .keys
            .iter()
            .find(|k| k.key_id == "shred-00000002-1e2f3a4b")
            .unwrap();
        assert!(other.destroyed, "sample's second key was already destroyed");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn mark_destroyed_unknown_key_is_not_found() {
        let root = tmp_root("mark-unknown");
        let store = KeyringStore::new(&root);
        store.save(&sample_meta()).unwrap();

        assert_eq!(
            store.mark_destroyed("inv-1", "shred-deadbeef-deadbeef").unwrap_err(),
            KeyringStoreError::NotFound
        );
        // And for a missing investigation entirely.
        assert_eq!(
            store.mark_destroyed("no-such-inv", "shred-deadbeef-deadbeef").unwrap_err(),
            KeyringStoreError::NotFound
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn mark_destroyed_is_idempotent() {
        let root = tmp_root("mark-idem");
        let store = KeyringStore::new(&root);
        store.save(&sample_meta()).unwrap();

        let target = "shred-00000001-0a0b0c0d";
        let first = store.mark_destroyed("inv-1", target).unwrap();
        let second = store.mark_destroyed("inv-1", target).unwrap();
        assert!(first.destroyed && second.destroyed);
        assert_eq!(first, second);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn destroy_on_disk_removes_then_load_not_found() {
        let root = tmp_root("destroy");
        let store = KeyringStore::new(&root);
        store.save(&sample_meta()).unwrap();
        assert!(root.join("inv-1").join("meta.json").exists());

        store.destroy_on_disk("inv-1").unwrap();
        assert!(!root.join("inv-1").join("meta.json").exists());
        assert!(!root.join("inv-1").exists(), "investigation dir removed");
        assert_eq!(store.load("inv-1").unwrap_err(), KeyringStoreError::NotFound);
        assert_eq!(store.list(), Vec::<String>::new());
        // Second erase: already gone.
        assert_eq!(store.destroy_on_disk("inv-1").unwrap_err(), KeyringStoreError::NotFound);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn destroy_on_disk_missing_is_not_found() {
        let root = tmp_root("destroy-missing");
        let store = KeyringStore::new(&root);
        assert_eq!(store.destroy_on_disk("ghost").unwrap_err(), KeyringStoreError::NotFound);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn list_sorted_and_meta_only() {
        let root = tmp_root("list");
        let store = KeyringStore::new(&root);

        let mut a = sample_meta();
        a.investigation = "bravo".to_string();
        store.save(&a).unwrap();
        let mut b = sample_meta();
        b.investigation = "alpha".to_string();
        store.save(&b).unwrap();

        // A directory without meta.json must not be listed.
        fs::create_dir_all(root.join("not-an-investigation")).unwrap();

        assert_eq!(store.list(), vec!["alpha".to_string(), "bravo".to_string()]);

        // Missing root lists nothing (no panic).
        let nowhere = KeyringStore::new(root.join("does-not-exist"));
        assert_eq!(nowhere.list(), Vec::<String>::new());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn save_is_byte_deterministic() {
        let root = tmp_root("determinism");
        let store = KeyringStore::new(&root);
        let meta = sample_meta();

        let p1 = store.save(&meta).unwrap();
        let bytes1 = fs::read(&p1).unwrap();
        let p2 = store.save(&meta).unwrap();
        let bytes2 = fs::read(&p2).unwrap();
        assert_eq!(bytes1, bytes2, "same input must serialize to same bytes");
        assert_eq!(p1, p2, "same input must serialize to same path");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn serde_pins() {
        let km = KeyMeta {
            key_id: "shred-00000001-0a0b0c0d".to_string(),
            fp8: "0a0b0c0d".to_string(),
            created_ms: 1_000,
            destroyed: false,
        };
        assert_eq!(
            serde_json::to_string(&km).unwrap(),
            "{\"key_id\":\"shred-00000001-0a0b0c0d\",\"fp8\":\"0a0b0c0d\",\
             \"created_ms\":1000,\"destroyed\":false}"
        );
        assert_eq!(serde_json::from_str::<KeyMeta>(&serde_json::to_string(&km).unwrap()).unwrap(), km);

        let meta = sample_meta();
        let back: KeyringMeta =
            serde_json::from_str(&serde_json::to_string(&meta).unwrap()).unwrap();
        assert_eq!(back, meta);

        // Error enum pins.
        assert_eq!(serde_json::to_string(&KeyringStoreError::NotFound).unwrap(), "\"NotFound\"");
        assert_eq!(serde_json::to_string(&KeyringStoreError::BadId).unwrap(), "\"BadId\"");
        assert_eq!(
            serde_json::to_string(&KeyringStoreError::Io("disk fell over".to_string())).unwrap(),
            "{\"Io\":\"disk fell over\"}"
        );
        let e: KeyringStoreError =
            serde_json::from_str("{\"Codec\":\"bad json\"}").unwrap();
        assert_eq!(e, KeyringStoreError::Codec("bad json".to_string()));

        // Display is prefixed and leak-free.
        assert!(format!("{}", KeyringStoreError::Codec("x".to_string())).starts_with("keyring_store:"));
    }

    #[test]
    fn meta_from_keyring_bridge_filters_by_investigation() {
        use crate::shred::ShredKeyring;

        let mut ring = ShredKeyring::new();
        let k1 = ring.new_key("inv-b", 1_000);
        let _k2 = ring.new_key("inv-a", 2_000); // other investigation: filtered out
        let k3 = ring.new_key("inv-b", 3_000);
        ring.destroy(&k3, 9_000).unwrap();

        let meta = meta_from_keyring("inv-b", &ring);
        assert_eq!(meta.investigation, "inv-b");
        assert_eq!(meta.keys.len(), 2, "only inv-b keys");

        // Order is the ring's canonical ascending key_id order.
        let ids: Vec<&str> = meta.keys.iter().map(|k| k.key_id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted);

        let km1 = meta.keys.iter().find(|k| k.key_id == k1).unwrap();
        assert_eq!(km1.fp8, k1.rsplit('-').next().unwrap());
        assert_eq!(km1.fp8.len(), 8);
        assert_eq!(km1.created_ms, 1_000);
        assert!(!km1.destroyed);

        let km3 = meta.keys.iter().find(|k| k.key_id == k3).unwrap();
        assert!(km3.destroyed, "shredded key must carry destroyed=true");
        assert_eq!(km3.fp8, k3.rsplit('-').next().unwrap());

        // Unknown investigation → empty key set, no error.
        assert!(meta_from_keyring("nope", &ring).keys.is_empty());

        // Deterministic: same ring, same output.
        assert_eq!(meta_from_keyring("inv-b", &ring), meta);

        // Bridge output round-trips through serde exactly.
        let back: KeyringMeta =
            serde_json::from_str(&serde_json::to_string(&meta).unwrap()).unwrap();
        assert_eq!(back, meta);
    }

    #[test]
    fn fp8_fallback_shape() {
        assert_eq!(fp8_from_key_id("shred-00000001-0A0B0C0D"), "0a0b0c0d");
        // Unknown shapes keep the full id (never a fabricated fingerprint).
        assert_eq!(fp8_from_key_id("legacy-key-id"), "legacy-key-id");
        assert_eq!(fp8_from_key_id("shred-short-ff"), "shred-short-ff");
        assert_eq!(fp8_from_key_id("shred-00000001-zzzzzzzz"), "shred-00000001-zzzzzzzz");
    }

    #[test]
    fn destroy_flow_convenience() {
        let root = tmp_root("flow");
        let store = KeyringStore::new(&root);
        store.save(&sample_meta()).unwrap();

        let k = destroy_flow(&store, "inv-1", "shred-00000001-0a0b0c0d").unwrap();
        assert!(k.destroyed);
        assert!(store.load("inv-1").unwrap().keys[0].destroyed);

        assert_eq!(
            destroy_flow(&store, "inv-1", "shred-deadbeef-deadbeef").unwrap_err(),
            KeyringStoreError::NotFound
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn persistence_is_instance_independent() {
        let root = tmp_root("instances");
        {
            let store = KeyringStore::new(&root);
            store.save(&sample_meta()).unwrap();
        }
        // A fresh store over the same root sees the same data (durable).
        let store2 = KeyringStore::new(&root);
        assert_eq!(store2.load("inv-1").unwrap(), sample_meta());
        assert_eq!(store2.list(), vec!["inv-1".to_string()]);

        let _ = fs::remove_dir_all(&root);
    }
}
