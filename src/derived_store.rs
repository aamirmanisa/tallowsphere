//! Versioned derived-layer store (frozen interface §4 — task A1.2.2).
//!
//! A content-addressed store for *derived* artifacts (parse output, extracted
//! text, intermediate reports) keyed by the pair `(source_hash, pipeline_version)`:
//!
//! ```text
//! key = sha256_hex(source_hash + '\n' + pipeline_version)
//! ```
//!
//! Layout under the store root:
//!
//! ```text
//! <root>/derived/<key>      opaque derived bytes  (create_new — NEVER rewritten)
//! <root>/meta/<key>.json    {"source_hash","pipeline_version","ts_ms"}  (written once)
//! ```
//!
//! The derived layer is intentionally independent of the raw layer
//! (`src/raw_store.rs`, a sibling agent's module): each store owns its own
//! root/sidecar scheme. If a caller points both stores at the same root the
//! sidecar JSON shapes are disjoint, and [`DerivedStore::list_for_source`]
//! skips sidecars whose JSON is not a derived-store sidecar — so sharing a root
//! degrades nothing. A version bump yields a NEW key; old derived bytes are
//! never touched, which makes the store safe for lock-free re-derivation and
//! cheap "is my cache stale?" checks via [`DerivedStore::derive_required`].
//!
//! **A1.2.3 adoption:** [`DerivedStore::store_extraction`] is the migration
//! path for current extraction outputs — the output bytes are stored
//! verbatim (byte-compatible read-back; no wrapping or transformation) and
//! [`ExtractionStoreOutcome`] reports whether a fresh artifact was written
//! or an existing one replayed. `tests/extraction_migration.rs` pins the
//! migration behavior.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

// ── local hex encoding (the `hex` crate is not a dependency) ────────────────

/// Lowercase hex encoding of `bytes`.
#[allow(dead_code)]
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// `key = sha256_hex(source_hash + '\n' + pipeline_version)`.
///
/// Inputs are used VERBATIM — no trimming, case-folding, or normalization —
/// so the key is a pure function of exactly what the caller supplied.
/// Deterministic across processes, machines, and re-runs.
#[allow(dead_code)]
fn key_for(source_hash: &str, pipeline_version: &str) -> String {
    let mut h = Sha256::new();
    h.update(source_hash.as_bytes());
    h.update(b"\n");
    h.update(pipeline_version.as_bytes());
    to_hex(&h.finalize())
}

/// True iff `key` has the exact shape this store ever mints: 64 lowercase
/// hex chars. Used to reject path-traversal / garbage keys on read and to
/// ignore foreign files when scanning sidecars.
#[allow(dead_code)]
fn is_valid_key(key: &str) -> bool {
    key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[allow(dead_code)]
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Write `bytes` to `path` with `create_new`: fails `AlreadyExists` instead of
/// overwriting. In this store an existing file is the signal to skip the write.
#[allow(dead_code)]
fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(bytes)?;
    f.flush()?;
    Ok(())
}

/// Sidecar metadata for one derived artifact. Field names are the frozen
/// interface's: `{"source_hash","pipeline_version","ts_ms"}`.
#[derive(serde::Serialize, serde::Deserialize)]
struct Sidecar {
    source_hash: String,
    pipeline_version: String,
    ts_ms: i64,
}

// ── A1.2.3 adoption: extraction-output migration ─────────────────────────────

/// Outcome of [`DerivedStore::store_extraction`] (A1.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractionStoreOutcome {
    /// Derived key the extraction output lives under.
    pub key: String,
    /// `true` when this call wrote a fresh artifact; `false` when the pair
    /// already had bytes (idempotent re-run — the existing bytes won).
    pub stored: bool,
    /// Byte length of the extraction output as supplied.
    pub byte_len: usize,
}

impl ExtractionStoreOutcome {
    /// `true` when the store already held this output (a re-run).
    pub fn replayed(&self) -> bool {
        !self.stored
    }
}

// ── store ────────────────────────────────────────────────────────────────────

/// Versioned derived-layer store rooted at a directory (see module docs §4).
#[allow(dead_code)]
pub struct DerivedStore {
    root: PathBuf,
}

impl DerivedStore {
    /// Open (creating if needed) a store at `root`. Creates `root/derived/`
    /// and `root/meta/`.
    #[allow(dead_code)]
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("derived"))?;
        fs::create_dir_all(root.join("meta"))?;
        Ok(DerivedStore { root })
    }

    /// Store `bytes` as the derived artifact for `(source_hash, pipeline_version)`
    /// and return its key. Idempotent: if the key already exists the bytes are
    /// left untouched (bytes are written `create_new`, never rewritten).
    ///
    /// Write order is bytes-first, sidecar-second: the artifact is
    /// authoritative and the sidecar is metadata, so a crash in between
    /// degrades listing (the sidecar is missing) but never claims bytes that
    /// do not exist. A later `put_derived` for the same pair heals the missing
    /// sidecar; existing sidecars are never rewritten, so `ts_ms` is the
    /// first-write time.
    #[allow(dead_code)]
    pub fn put_derived(
        &self,
        source_hash: &str,
        pipeline_version: &str,
        bytes: &[u8],
    ) -> io::Result<String> {
        let key = key_for(source_hash, pipeline_version);

        let byte_path = self.root.join("derived").join(&key);
        match write_new(&byte_path, bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }

        let sidecar_path = self.root.join("meta").join(format!("{key}.json"));
        if !sidecar_path.exists() {
            let side = Sidecar {
                source_hash: source_hash.to_string(),
                pipeline_version: pipeline_version.to_string(),
                ts_ms: now_ms(),
            };
            let json = serde_json::to_vec(&side)
                .map_err(|e| io::Error::other(format!("derived_store: sidecar encode: {e}")))?;
            match write_new(&sidecar_path, &json) {
                Ok(()) => {}
                // Raced by another writer: its sidecar is as good as ours.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }

        Ok(key)
    }

    /// A1.2.3 adoption — store one **extraction output** on the derived
    /// layer, byte-compatibly: `bytes` are the extractor's output EXACTLY as
    /// produced and are persisted verbatim (no wrapping, no transformation —
    /// `get_derived` returns them byte-identical), keyed by
    /// `(source_hash, pipeline_version)` so a re-derivation under a new
    /// pipeline version never touches an old output.
    ///
    /// Idempotent: re-storing the same pair reports
    /// [`ExtractionStoreOutcome::replayed`] and leaves the existing bytes
    /// untouched.
    #[allow(dead_code)]
    pub fn store_extraction(
        &self,
        source_hash: &str,
        pipeline_version: &str,
        bytes: &[u8],
    ) -> io::Result<ExtractionStoreOutcome> {
        let fresh = self.derive_required(source_hash, pipeline_version);
        let key = self.put_derived(source_hash, pipeline_version, bytes)?;
        Ok(ExtractionStoreOutcome {
            key,
            stored: fresh,
            byte_len: bytes.len(),
        })
    }

    /// Read the derived bytes stored under `key`. Unknown keys and
    /// malformed keys both yield `NotFound` (malformed keys are rejected
    /// before touching the filesystem, so `get_derived("../../etc/passwd")`
    /// cannot escape the store).
    #[allow(dead_code)]
    pub fn get_derived(&self, key: &str) -> io::Result<Vec<u8>> {
        if !is_valid_key(key) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("derived_store: malformed key: {key:?}"),
            ));
        }
        fs::read(self.root.join("derived").join(key))
    }

    /// `true` when no derived artifact exists yet for this pair — i.e. the
    /// caller must re-derive. `false` when the key already exists.
    #[allow(dead_code)]
    pub fn derive_required(&self, source_hash: &str, pipeline_version: &str) -> bool {
        !self
            .root
            .join("derived")
            .join(key_for(source_hash, pipeline_version))
            .exists()
    }

    /// All derived versions stored for `source_hash`: `(key, pipeline_version)`
    /// pairs, sorted by `pipeline_version` then `key` (deterministic). Driven
    /// by sidecar scan; sidecars that are not derived-store sidecars (foreign
    /// JSON, e.g. raw-store metadata shared under the same root) and
    /// unreadable/corrupt sidecars are skipped.
    #[allow(dead_code)]
    pub fn list_for_source(&self, source_hash: &str) -> io::Result<Vec<(String, String)>> {
        let meta_dir = self.root.join("meta");
        let mut out: Vec<(String, String)> = Vec::new();
        for entry in fs::read_dir(&meta_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Some(key) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if !is_valid_key(key) {
                continue;
            }
            let Ok(raw) = fs::read(&path) else {
                continue;
            };
            let Ok(side) = serde_json::from_slice::<Sidecar>(&raw) else {
                continue;
            };
            if side.source_hash == source_hash {
                out.push((key.to_string(), side.pipeline_version));
            }
        }
        // Deterministic, human-useful order: by pipeline_version, then key.
        out.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        Ok(out)
    }

    /// Purge derived artifacts (bytes + sidecar) for which `is_expired(key)`
    /// returns `true` — the derived-layer twin of
    /// `raw_store::RawStore::purge_expired` (P4 / N6 closure).
    ///
    /// The callback receives the derived store **key** (the 64-hex identity
    /// of `(source_hash, pipeline_version)`, which is also what a retention
    /// registry would track for this layer), keeping the store decoupled from
    /// any registry. For each expired artifact the derived bytes at
    /// `<root>/derived/<key>` AND the sidecar `<root>/meta/<key>.json` are
    /// removed (missing sidecar is tolerated). Returns the number of
    /// artifacts actually removed; idempotent — a second run over the same
    /// predicate removes 0. Foreign files and malformed keys are never
    /// touched.
    #[allow(dead_code)]
    pub fn purge_expired_derived(
        &self,
        is_expired: &dyn Fn(&str) -> bool,
    ) -> io::Result<usize> {
        let mut removed = 0usize;
        let rd = match fs::read_dir(self.root.join("derived")) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        for entry in rd.flatten() {
            let key = entry.file_name().to_string_lossy().into_owned();
            if !is_valid_key(&key) || !entry.path().is_file() || !is_expired(&key) {
                continue;
            }
            match fs::remove_file(entry.path()) {
                Ok(()) => {
                    // Metadata dies with the artifact it describes.
                    let _ = fs::remove_file(
                        self.root.join("meta").join(format!("{key}.json")),
                    );
                    removed += 1;
                }
                // Lost a race with another purge: already gone.
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(removed)
    }
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn open_store() -> (tempfile::TempDir, DerivedStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = DerivedStore::open(dir.path().join("nested/derived_root")).expect("open");
        (dir, store)
    }

    fn sidecar_json(store: &DerivedStore, key: &str) -> serde_json::Value {
        let raw = fs::read(store.root.join("meta").join(format!("{key}.json"))).expect("sidecar");
        serde_json::from_slice(&raw).expect("sidecar json")
    }

    #[test]
    fn open_creates_dirs_and_key_matches_sha256_formula() {
        let (dir, store) = open_store();
        assert!(dir.path().join("nested/derived_root/derived").is_dir());
        assert!(dir.path().join("nested/derived_root/meta").is_dir());

        // Independently recompute the frozen formula: sha256_hex(source + '\n' + version).
        let source = "a".repeat(64); // shape mirrors a sha256 source hash
        let version = "parse-v3";
        let mut h = Sha256::new();
        h.update(format!("{source}\n{version}").as_bytes());
        let expect = to_hex(&h.finalize());
        assert_eq!(key_for(&source, version), expect);
        assert_eq!(key_for(&source, version).len(), 64);
        assert!(is_valid_key(&expect));

        // Same inputs -> same key, regardless of store root (pure function).
        let (_other_dir, other) = open_store();
        let k1 = store.put_derived(&source, version, b"bytes-1").unwrap();
        let k2 = other.put_derived(&source, version, b"bytes-1").unwrap();
        assert_eq!(k1, expect);
        assert_eq!(k1, k2);
    }

    #[test]
    fn same_inputs_same_key_and_no_rewrite() {
        let (_dir, store) = open_store();
        let source = "deadbeef".repeat(8);
        let k_a = store.put_derived(&source, "v1", b"first-bytes").unwrap();

        // Same pair, DIFFERENT bytes: must return the same key and must NOT
        // clobber what is already on disk (create_new never rewrites).
        let before = sidecar_json(&store, &k_a);
        let k_b = store.put_derived(&source, "v1", b"second-bytes-different").unwrap();
        assert_eq!(k_a, k_b);
        assert_eq!(store.get_derived(&k_a).unwrap(), b"first-bytes");
        let after = sidecar_json(&store, &k_a);
        assert_eq!(before, after, "sidecar must not be rewritten");

        // Exact same inputs again: still the original key + bytes.
        let k_c = store.put_derived(&source, "v1", b"first-bytes").unwrap();
        assert_eq!(k_c, k_a);
        assert_eq!(store.get_derived(&k_c).unwrap(), b"first-bytes");
    }

    #[test]
    fn version_bump_new_key_old_bytes_untouched() {
        let (_dir, store) = open_store();
        let source = "aa11".repeat(16);
        let k1 = store.put_derived(&source, "pipeline-v1", b"v1 output").unwrap();
        let k2 = store.put_derived(&source, "pipeline-v2", b"v2 output").unwrap();
        assert_ne!(k1, k2, "version bump must mint a new key");

        // Old bytes still retrievable byte-for-byte via the old key.
        assert_eq!(store.get_derived(&k1).unwrap(), b"v1 output");
        assert_eq!(store.get_derived(&k2).unwrap(), b"v2 output");

        // Both sidecars exist with the right (source, version) pairing.
        let s1 = sidecar_json(&store, &k1);
        let s2 = sidecar_json(&store, &k2);
        assert_eq!(s1["source_hash"], serde_json::json!(source));
        assert_eq!(s1["pipeline_version"], serde_json::json!("pipeline-v1"));
        assert_eq!(s2["pipeline_version"], serde_json::json!("pipeline-v2"));
        assert!(s1["ts_ms"].as_i64().unwrap() > 0);
        // Sidecar carries exactly the frozen fields.
        let obj = s1.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
        keys.sort();
        assert_eq!(keys, ["pipeline_version", "source_hash", "ts_ms"]);
    }

    #[test]
    fn derive_required_flips() {
        let (_dir, store) = open_store();
        let source = "cafe".repeat(16);
        assert!(store.derive_required(&source, "v1"));
        store.put_derived(&source, "v1", b"out").unwrap();
        assert!(!store.derive_required(&source, "v1"));

        // A version bump flips it back to required, and one more put clears it.
        assert!(store.derive_required(&source, "v2"));
        store.put_derived(&source, "v2", b"out2").unwrap();
        assert!(!store.derive_required(&source, "v2"));

        // A different source is independent.
        assert!(store.derive_required(&"beef".repeat(16), "v1"));
    }

    #[test]
    fn list_for_source_returns_all_versions() {
        let (_dir, store) = open_store();
        let source = "ab".repeat(32);
        let other_source = "cd".repeat(32);

        // Insert out of version order to prove deterministic sorting.
        let k2 = store.put_derived(&source, "v2", b"two").unwrap();
        let k1 = store.put_derived(&source, "v1", b"one").unwrap();
        let k3 = store.put_derived(&source, "v10", b"ten").unwrap();
        let held_o = store.put_derived(&other_source, "v1", b"o").unwrap();

        let got = store.list_for_source(&source).unwrap();
        assert_eq!(
            got,
            vec![
                (k1.clone(), "v1".to_string()),
                (k3.clone(), "v10".to_string()),
                (k2.clone(), "v2".to_string()),
            ]
        );

        let got_other = store.list_for_source(&other_source).unwrap();
        assert_eq!(got_other, vec![(held_o, "v1".to_string())]);

        assert!(store.list_for_source(&"00".repeat(32)).unwrap().is_empty());

        // Every listed key actually resolves to bytes.
        for (key, _v) in got {
            assert!(store.get_derived(&key).is_ok());
        }
    }

    #[test]
    fn foreign_and_corrupt_sidecars_are_ignored() {
        let (_dir, store) = open_store();
        let source = "12".repeat(32);
        let key = store.put_derived(&source, "v1", b"x").unwrap();

        // A raw-store style sidecar (same shape of filename, different JSON):
        let foreign_key = "ff".repeat(32);
        fs::write(
            store.root.join("meta").join(format!("{foreign_key}.json")),
            br#"{"url":"https://example.org","content_type":"text/html","ts_ms":1}"#,
        )
        .unwrap();
        // A corrupt sidecar:
        let corrupt_key = "ee".repeat(32);
        fs::write(
            store.root.join("meta").join(format!("{corrupt_key}.json")),
            b"{not json",
        )
        .unwrap();
        // Non-sidecar junk files:
        fs::write(store.root.join("meta").join("README.txt"), b"junk").unwrap();
        fs::write(store.root.join("meta").join("notahexkey.json"), b"{}").unwrap();

        let got = store.list_for_source(&source).unwrap();
        assert_eq!(got, vec![(key, "v1".to_string())]);
        // The foreign source is not ours: no listing for it.
        assert!(store.list_for_source(&foreign_key).unwrap().is_empty());
    }

    #[test]
    fn get_derived_rejects_missing_and_malformed_keys() {
        let (_dir, store) = open_store();
        // Unknown but well-formed key -> NotFound.
        let e = store.get_derived(&"0a".repeat(32)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);

        // Malformed / traversal keys -> NotFound, no filesystem escape.
        let uppercase = "A".repeat(64);
        for bad in ["../../etc/passwd", "abc", "", uppercase.as_str()] {
            let e = store.get_derived(bad).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::NotFound, "key {bad:?}");
        }
    }

    // ── P4 / N6: derived-layer retention purge ───────────────────────────

    #[test]
    fn purge_expired_derived_removes_key_and_meta_idempotently() {
        let (_dir, store) = open_store();
        let src_dead = "e1".repeat(32);
        let src_live = "e2".repeat(32);
        let k_dead = store.put_derived(&src_dead, "v1", b"dead bytes").unwrap();
        let k_live = store.put_derived(&src_live, "v1", b"live bytes").unwrap();
        let is_expired = |k: &str| k == k_dead.as_str();

        // First purge: exactly the expired artifact (bytes + sidecar) goes.
        assert_eq!(store.purge_expired_derived(&is_expired).unwrap(), 1);
        assert!(
            store.get_derived(&k_dead).is_err(),
            "expired derived bytes must be gone"
        );
        assert!(
            !store
                .root
                .join("meta")
                .join(format!("{k_dead}.json"))
                .exists(),
            "sidecar must die with the artifact"
        );

        // The live artifact survives, bytes and sidecar intact.
        assert_eq!(store.get_derived(&k_live).unwrap(), b"live bytes");
        assert!(store
            .root
            .join("meta")
            .join(format!("{k_live}.json"))
            .exists());
        assert_eq!(store.list_for_source(&src_live).unwrap().len(), 1);

        // Idempotent: nothing left to purge.
        assert_eq!(store.purge_expired_derived(&is_expired).unwrap(), 0);
    }

    // ── A1.2.3: extraction-output migration ──────────────────────────────

    #[test]
    fn store_extraction_is_byte_compatible_and_idempotent() {
        let (_dir, store) = open_store();
        let src = "ab".repeat(32);
        let v1 = br#"{"items":[{"t":"alpha"},{"t":"beta"}],"pipeline":"extract/v1"}"#;
        let out = store.store_extraction(&src, "extract/v1", v1).unwrap();
        assert!(out.stored);
        assert_eq!(out.byte_len, v1.len());
        assert_eq!(
            store.get_derived(&out.key).unwrap(),
            v1,
            "read-back is byte-identical to the extraction output"
        );

        // Re-run with different bytes: idempotent — the existing bytes win.
        let again = store
            .store_extraction(&src, "extract/v1", br#"{"items":[]}"#)
            .unwrap();
        assert!(again.replayed());
        assert_eq!(again.key, out.key);
        assert_eq!(store.get_derived(&out.key).unwrap(), v1);

        // Version bump: a NEW key; the old output is untouched.
        let out2 = store.store_extraction(&src, "extract/v2", v1).unwrap();
        assert!(out2.stored);
        assert_ne!(out2.key, out.key);
        assert_eq!(store.get_derived(&out.key).unwrap(), v1);
        assert_eq!(store.get_derived(&out2.key).unwrap(), v1);
        assert!(!store.derive_required(&src, "extract/v2"));
        assert_eq!(store.list_for_source(&src).unwrap().len(), 2);
    }
}
