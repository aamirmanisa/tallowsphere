//! Raw store — content-addressed raw-immutable capture for the intel pipeline
//! (task A1.2.1, frozen interface §3).
//!
//! Every byte captured (HTTP body, dropped file, pasted blob) lands under a
//! sha256 content address: `root/<ab>/<cd>/<hash>` where `ab`/`cd` are the
//! first two / next two hex chars of the hash. Content addressing buys us:
//!
//! - **deduplication** — identical bytes hash identically; a repeat `put`
//!   never rewrites the object;
//! - **immutability (freeze-on-write)** — objects are created with
//!   `create_new(true)` and, on Unix, frozen to mode 0o444 (best effort). A
//!   `put` whose hash already exists verifies the stored bytes and *refuses*
//!   (rather than overwrites) on divergence;
//! - **frozen provenance** — [`RawStore::put_fetch`] additionally records a
//!   write-once sidecar `root/meta/<hash>.json` = `{"url","content_type","ts_ms"}`.
//!
//! `RawStore` is synchronous and dependency-light (`sha2` only). It is safe
//! for concurrent writers: the `create_new` + verify dance makes racing
//! writers converge on one object, and the first sidecar wins.

use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// sha256 of `bytes`, lowercase hex (64 chars).
fn hash_of(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    to_hex(h.finalize().as_slice())
}

/// Lowercase hex encoding — local helper, no extra dependency.
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Canonical content-address shape: exactly 64 lowercase hex chars. Strict on
/// purpose — a hash is used as a path component and must never be able to
/// escape `root/` (no `/`, `.`, or other surprises), and only our own
/// canonical form is accepted from callers.
fn is_valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// True iff `s` is exactly two lowercase hex chars — the shape of a shard
/// path component (`root/<ab>/<cd>/<hash>`). Used by [`RawStore::purge_expired`]
/// to skip `meta/` and any foreign directories without touching them.
fn is_shard_component(s: &str) -> bool {
    s.len() == 2 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Best-effort freeze of a freshly written object: strip write bits on Unix.
/// Freeze failure (exotic FS) is not an error — `create_new` + content
/// addressing already guarantee the object is never overwritten.
fn freeze(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Unix ms since epoch. Never panics (0 only if the clock predates 1970).
fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Provenance metadata for a fetched payload (sidecar
/// `root/meta/<hash>.json`), as read back by [`RawStore::fetch_meta`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchMeta {
    /// The URL the bytes were fetched from (first fetch wins).
    pub url: String,
    /// The response content type (`""` when absent from the sidecar).
    pub content_type: String,
    /// When the fetch was recorded (ms since epoch; `0` when absent).
    pub ts_ms: i64,
    /// As-of stamp: when the payload was OBSERVED. Legacy sidecars (written
    /// before the B3.5.3 stamp) migrate the as-of from `ts_ms`.
    pub as_of_ms: i64,
}

impl FetchMeta {
    /// The as-of stamp in the decoupled decay vocabulary
    /// ([`crate::decay_model::AsOfStamp`]).
    pub fn stamp(&self) -> crate::decay_model::AsOfStamp {
        crate::decay_model::AsOfStamp {
            as_of_ms: self.as_of_ms,
        }
    }
}

// ── RawStore ─────────────────────────────────────────────────────────────────

/// Content-addressed, immutable store for raw captured bytes.
#[derive(Debug, Clone)]
pub struct RawStore {
    root: PathBuf,
}

impl RawStore {
    /// Open (creating if needed) a raw store rooted at `root`.
    ///
    /// Layout: `root/<ab>/<cd>/<sha256hex>` for objects,
    /// `root/meta/<hash>.json` for provenance sidecars.
    pub fn open(root: impl Into<PathBuf>) -> std::io::Result<Self> {
        let root = root.into();
        // Create the sidecar dir eagerly so the layout is complete from open.
        std::fs::create_dir_all(root.join("meta"))?;
        Ok(RawStore { root })
    }

    /// Store `bytes` and return their sha256 hex id (64 lowercase chars).
    ///
    /// Write-once: the object is created with `create_new` at
    /// `root/<ab>/<cd>/<hash>`. If it already exists, the stored bytes are
    /// verified to equal `bytes` and the same id is returned — the existing
    /// object is **never overwritten**. A mismatch (hash collision or on-disk
    /// corruption) is an `InvalidData` error and leaves the stored object
    /// untouched.
    pub fn put_bytes(&self, bytes: &[u8]) -> std::io::Result<String> {
        let hash = hash_of(bytes);
        let path = self.path_for(&hash);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                let written = f.write_all(bytes).and_then(|()| f.sync_all());
                drop(f);
                if let Err(e) = written {
                    // Never leave a torn object wedged at a content address:
                    // remove the partial file so a retry can succeed cleanly.
                    let _ = std::fs::remove_file(&path);
                    return Err(e);
                }
                freeze(&path);
                Ok(hash)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = std::fs::read(&path)?;
                if existing == bytes {
                    Ok(hash)
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "raw_store: existing object {hash} differs from incoming bytes \
                             (collision or corruption at {})",
                            path.display()
                        ),
                    ))
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Read the object stored under `hash`.
    ///
    /// Malformed ids (not 64 lowercase hex) are rejected with `InvalidInput`
    /// before touching the filesystem.
    pub fn get(&self, hash: &str) -> std::io::Result<Vec<u8>> {
        if !is_valid_hash(hash) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("raw_store: not a sha256 hex id: {hash:?}"),
            ));
        }
        std::fs::read(self.path_for(hash))
    }

    /// Gate-form read (P4 / N6 closure): `Some(bytes)` only when the object
    /// exists **and** `is_expired(hash)` is `false`.
    ///
    /// The callback keeps the store decoupled from any retention registry —
    /// callers pass e.g. `|h| !privacy::may_serve(registry, h)`. Expired,
    /// missing, and malformed ids all yield `None` (default-to-tightest;
    /// malformed ids can never be live). The expiry predicate is consulted
    /// *before* any bytes are read, so expired content is not even loaded.
    /// Real I/O errors other than `NotFound` still surface as `Err`.
    pub fn get_if_live(
        &self,
        hash: &str,
        is_expired: &dyn Fn(&str) -> bool,
    ) -> std::io::Result<Option<Vec<u8>>> {
        if !is_valid_hash(hash) {
            return Ok(None); // malformed ids can never address a live object
        }
        if is_expired(hash) {
            return Ok(None); // expired: refuse without touching the bytes
        }
        match self.get(hash) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Purge every stored object for which `is_expired(hash)` returns `true`.
    ///
    /// Same decoupling as [`RawStore::get_if_live`]. For each expired object
    /// the bytes AND the write-once provenance sidecar
    /// `root/meta/<hash>.json` are removed (`NotFound` on the sidecar is
    /// tolerated — objects without provenance still purge). Returns the
    /// number of objects actually removed. Idempotent: re-running over the
    /// same predicate removes 0. Scans only the canonical object layout
    /// `root/<ab>/<cd>/<hash>` (the `meta/` dir and foreign files are never
    /// touched).
    pub fn purge_expired(&self, is_expired: &dyn Fn(&str) -> bool) -> std::io::Result<usize> {
        let mut removed = 0usize;
        let shard1 = match std::fs::read_dir(&self.root) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        for a in shard1.flatten() {
            if !a.path().is_dir() || !is_shard_component(&a.file_name().to_string_lossy()) {
                continue;
            }
            for b in std::fs::read_dir(a.path())?.flatten() {
                if !b.path().is_dir() || !is_shard_component(&b.file_name().to_string_lossy()) {
                    continue;
                }
                for obj in std::fs::read_dir(b.path())?.flatten() {
                    let hash = obj.file_name().to_string_lossy().into_owned();
                    if !is_valid_hash(&hash) || !is_expired(&hash) {
                        continue;
                    }
                    match std::fs::remove_file(obj.path()) {
                        Ok(()) => {
                            // Provenance dies with the bytes it describes.
                            let _ = std::fs::remove_file(
                                self.root.join("meta").join(format!("{hash}.json")),
                            );
                            removed += 1;
                        }
                        // Lost a race with another purge: already gone.
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        Ok(removed)
    }

    /// Whether an object exists under `hash` (false for malformed ids).
    pub fn exists(&self, hash: &str) -> bool {
        is_valid_hash(hash) && self.path_for(hash).is_file()
    }

    /// Store a fetched payload plus its provenance sidecar.
    ///
    /// Bytes are stored exactly like [`RawStore::put_bytes`]. In addition a
    /// metadata file `root/meta/<hash>.json` =
    /// `{"url","content_type","ts_ms"}` is written **once** (`create_new`).
    /// Re-fetching identical bytes from a different URL keeps the first
    /// sidecar: provenance is frozen together with the object. Returns the
    /// content hash.
    pub fn put_fetch(
        &self,
        url: &str,
        content_type: &str,
        bytes: &[u8],
    ) -> std::io::Result<String> {
        let hash = self.put_bytes(bytes)?;
        let meta_path = self.root.join("meta").join(format!("{hash}.json"));
        let observed_ms = now_ms();
        // B3.5.3: the sidecar carries the observation (as-of) stamp next to
        // the legacy `ts_ms` — equal at capture time; readers migrate legacy
        // sidecars by inheriting `ts_ms` as the as-of.
        let meta = serde_json::json!({
            "url": url,
            "content_type": content_type,
            "ts_ms": observed_ms,
            "as_of_ms": observed_ms,
        });
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&meta_path)
        {
            Ok(mut f) => {
                let written = f
                    .write_all(meta.to_string().as_bytes())
                    .and_then(|()| f.sync_all());
                drop(f);
                if let Err(e) = written {
                    let _ = std::fs::remove_file(&meta_path);
                    return Err(e);
                }
                freeze(&meta_path);
            }
            // Already recorded: first fetch wins; sidecars are never rewritten.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        Ok(hash)
    }

    /// Read the fetch provenance sidecar (`root/meta/<hash>.json`) with the
    /// B3.5.3 as-of stamp.
    ///
    /// **Migration rule:** sidecars written before the stamp existed carry no
    /// `as_of_ms` field; their observation time (`ts_ms`) is inherited as the
    /// as-of — old stores migrate on read, and frozen sidecars are never
    /// rewritten. Malformed hashes, a missing sidecar, unparseable JSON, and
    /// JSON that is not a fetch sidecar (neither `url` nor `content_type` is
    /// present) all return `Ok(None)`.
    pub fn fetch_meta(&self, hash: &str) -> std::io::Result<Option<FetchMeta>> {
        if !is_valid_hash(hash) {
            return Ok(None);
        }
        let path = self.root.join("meta").join(format!("{hash}.json"));
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
            return Ok(None);
        };
        let url = v.get("url").and_then(|x| x.as_str());
        let content_type = v.get("content_type").and_then(|x| x.as_str());
        if url.is_none() && content_type.is_none() {
            return Ok(None); // not a fetch sidecar (e.g. a derived-store sidecar)
        }
        let ts_ms = v.get("ts_ms").and_then(|x| x.as_i64()).unwrap_or(0);
        let as_of_ms = v.get("as_of_ms").and_then(|x| x.as_i64()).unwrap_or(ts_ms);
        Ok(Some(FetchMeta {
            url: url.unwrap_or_default().to_string(),
            content_type: content_type.unwrap_or_default().to_string(),
            ts_ms,
            as_of_ms,
        }))
    }

    /// Convenience: the as-of stamp of a fetch as the decoupled decay
    /// vocabulary type, when the sidecar exists
    /// ([`crate::decay_model::AsOfStamp`]).
    pub fn fetch_stamp(&self, hash: &str) -> std::io::Result<Option<crate::decay_model::AsOfStamp>> {
        Ok(self.fetch_meta(hash)?.map(|m| m.stamp()))
    }

    /// Re-hash the stored object and compare it to `hash` (fixity check).
    /// `Ok(false)` means the bytes on disk no longer match their address.
    #[allow(dead_code)] // wired in by the later fixity/repair flow (A1.3.x)
    pub fn verify(&self, hash: &str) -> std::io::Result<bool> {
        let bytes = self.get(hash)?;
        Ok(hash_of(&bytes) == hash)
    }

    /// Object path: `root/<first 2>/<next 2>/<hash>`.
    fn path_for(&self, hash: &str) -> PathBuf {
        debug_assert!(is_valid_hash(hash));
        self.root.join(&hash[..2]).join(&hash[2..4]).join(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn store() -> (tempfile::TempDir, RawStore) {
        let dir = tempfile::tempdir().unwrap();
        let s = RawStore::open(dir.path()).unwrap();
        (dir, s)
    }

    #[test]
    fn roundtrip_put_get() {
        let (_d, s) = store();
        let h = s.put_bytes(b"hello tallow").unwrap();
        assert_eq!(h.len(), 64);
        assert!(s.exists(&h));
        assert_eq!(s.get(&h).unwrap(), b"hello tallow");
        // Empty payload is a valid object too.
        let he = s.put_bytes(b"").unwrap();
        assert_eq!(
            he,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(s.get(&he).unwrap(), b"");
    }

    #[test]
    fn same_bytes_same_hash_and_no_rewrite() {
        let (_d, s) = store();
        let h1 = s.put_bytes(b"identical").unwrap();
        let p = s.path_for(&h1);
        let m1 = std::fs::metadata(&p).unwrap().modified().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let h2 = s.put_bytes(b"identical").unwrap();
        assert_eq!(h1, h2);
        let m2 = std::fs::metadata(&p).unwrap().modified().unwrap();
        assert_eq!(m1, m2, "same bytes must not rewrite the object");
        assert_eq!(std::fs::read(&p).unwrap(), b"identical");
    }

    #[test]
    fn different_bytes_different_hash() {
        let (_d, s) = store();
        let a = s.put_bytes(b"one").unwrap();
        let b = s.put_bytes(b"two").unwrap();
        assert_ne!(a, b);
        assert_eq!(s.get(&a).unwrap(), b"one");
        assert_eq!(s.get(&b).unwrap(), b"two");
    }

    #[test]
    fn sharding_path_is_first_two_next_two() {
        let (_d, s) = store();
        let h = s.put_bytes(b"sharded").unwrap();
        let p = s.root.join(&h[..2]).join(&h[2..4]).join(&h);
        assert!(
            p.is_file(),
            "object must live at root/<ab>/<cd>/<hash>: {}",
            p.display()
        );
        let rel: Vec<String> = p
            .strip_prefix(&s.root)
            .unwrap()
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        assert_eq!(rel.len(), 3);
        assert_eq!(rel[0], h[..2]);
        assert_eq!(rel[1], h[2..4]);
        assert_eq!(rel[2], h);
    }

    #[test]
    fn sidecar_written_once_and_correct() {
        let (_d, s) = store();
        let before = now_ms();
        let h = s
            .put_fetch("https://example.com/a", "text/html", b"<html>hi</html>")
            .unwrap();
        let after = now_ms();
        let mp = s.root.join("meta").join(format!("{h}.json"));
        assert!(mp.is_file(), "sidecar missing: {}", mp.display());
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&mp).unwrap()).unwrap();
        assert_eq!(v["url"], "https://example.com/a");
        assert_eq!(v["content_type"], "text/html");
        let ts = v["ts_ms"].as_i64().unwrap();
        assert!(ts >= before && ts <= after, "ts_ms {ts} outside [{before},{after}]");
        assert_eq!(s.get(&h).unwrap(), b"<html>hi</html>");

        // Same bytes re-fetched from another URL: same hash, sidecar untouched
        // (first fetch wins — provenance is frozen with the object).
        let m1 = std::fs::metadata(&mp).unwrap().modified().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let h2 = s
            .put_fetch("https://other.example/b", "text/plain", b"<html>hi</html>")
            .unwrap();
        assert_eq!(h2, h);
        let v2: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&mp).unwrap()).unwrap();
        assert_eq!(v2["url"], "https://example.com/a", "sidecar is write-once");
        let m2 = std::fs::metadata(&mp).unwrap().modified().unwrap();
        assert_eq!(m1, m2, "sidecar must not be rewritten");
    }

    #[test]
    fn preexisting_mismatched_object_is_rejected() {
        let (_d, s) = store();
        let payload = b"genuine bytes";
        let h = hash_of(payload);
        let p = s.root.join(&h[..2]).join(&h[2..4]).join(&h);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"corrupted bytes").unwrap();
        let err = s.put_bytes(payload).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        // No silent overwrite: the diverging object is left as found.
        assert_eq!(std::fs::read(&p).unwrap(), b"corrupted bytes");
    }

    #[test]
    fn missing_and_invalid_hash_handling() {
        let (_d, s) = store();
        let missing = "0".repeat(64);
        assert!(!s.exists(&missing));
        assert_eq!(
            s.get(&missing).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        // Malformed ids: rejected up front, no filesystem access.
        assert!(!s.exists("not-a-hash"));
        assert_eq!(
            s.get("../etc/passwd").unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            s.get(&"A".repeat(64)).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[cfg(unix)]
    #[test]
    fn objects_are_frozen_read_only() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, s) = store();
        let h = s.put_bytes(b"frozen").unwrap();
        let mode = std::fs::metadata(s.path_for(&h))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o444, "object must be frozen read-only on write");
        let hf = s.put_fetch("https://example.com/x", "text/plain", b"frozen meta").unwrap();
        let m_mode = std::fs::metadata(s.root.join("meta").join(format!("{hf}.json")))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(m_mode, 0o444, "sidecar must be frozen read-only on write");
    }

    #[cfg(unix)]
    #[test]
    fn verify_detects_corruption() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, s) = store();
        let h = s.put_bytes(b"intact").unwrap();
        assert!(s.verify(&h).unwrap());
        // Simulate out-of-band corruption: thaw, tamper, re-check fixity.
        let p = s.path_for(&h);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&p, b"tampered").unwrap();
        assert!(!s.verify(&h).unwrap());
    }

    // ── P4 / N6: retention purge + live-read gate ────────────────────────

    #[test]
    fn purge_expired_and_get_if_live_respect_retention() {
        let (_d, s) = store();
        let h_live = s.put_bytes(b"live bytes").unwrap();
        let h_dead = s
            .put_fetch("https://example.com/dead", "text/plain", b"expired bytes")
            .unwrap();
        let is_expired = |h: &str| h == h_dead.as_str();

        // get_if_live: live is returned; expired, missing, malformed → None.
        assert_eq!(
            s.get_if_live(&h_live, &is_expired).unwrap(),
            Some(b"live bytes".to_vec())
        );
        assert_eq!(s.get_if_live(&h_dead, &is_expired).unwrap(), None);
        assert_eq!(s.get_if_live(&"0".repeat(64), &is_expired).unwrap(), None);
        assert_eq!(s.get_if_live("not-a-hash", &is_expired).unwrap(), None);

        // purge_expired removes the expired object AND its sidecar, count=1.
        assert_eq!(s.purge_expired(&is_expired).unwrap(), 1);
        assert!(!s.exists(&h_dead));
        assert!(s.get(&h_dead).is_err(), "dead bytes must be gone");
        assert!(
            !s.root.join("meta").join(format!("{h_dead}.json")).exists(),
            "provenance sidecar must die with the bytes"
        );

        // The live object survives, bytes and sidecar intact.
        assert!(s.exists(&h_live));
        assert_eq!(s.get(&h_live).unwrap(), b"live bytes");

        // Idempotent: nothing left to purge.
        assert_eq!(s.purge_expired(&is_expired).unwrap(), 0);
    }

    // ── B3.5.3: as-of stamps on fetch sidecars ──────────────────────────────

    #[test]
    fn fetch_sidecar_carries_as_of_stamp() {
        let (_d, s) = store();
        let h = s
            .put_fetch("https://example.org/a", "text/html", b"<p>x</p>")
            .unwrap();
        let m = s.fetch_meta(&h).unwrap().expect("sidecar exists");
        assert_eq!(m.url, "https://example.org/a");
        assert_eq!(m.content_type, "text/html");
        assert_eq!(m.as_of_ms, m.ts_ms, "capture stamps as-of = observation time");
        assert!(m.ts_ms > 0);
        assert_eq!(s.fetch_stamp(&h).unwrap(), Some(m.stamp()));
        // Missing + malformed ids: no stamp, no error.
        assert_eq!(s.fetch_meta(&"0".repeat(64)).unwrap(), None);
        assert_eq!(s.fetch_stamp("not-a-hash").unwrap(), None);
    }

    #[test]
    fn legacy_sidecar_migrates_as_of_from_ts_ms() {
        let (d, _s) = store();
        let h = "ab".repeat(32);
        std::fs::write(
            d.path().join("meta").join(format!("{h}.json")),
            r#"{"url":"https://legacy.example/p","content_type":"application/json","ts_ms":1710000000000}"#,
        )
        .unwrap();
        // Reopen through the store to read it back.
        let s = RawStore::open(d.path()).unwrap();
        let m = s.fetch_meta(&h).unwrap().expect("legacy sidecar reads");
        assert_eq!(m.ts_ms, 1_710_000_000_000);
        assert_eq!(m.as_of_ms, 1_710_000_000_000, "as-of migrates from ts_ms");
    }

    #[test]
    fn non_fetch_sidecar_reads_as_none() {
        let (d, _s) = store();
        let h = "cd".repeat(32);
        std::fs::write(
            d.path().join("meta").join(format!("{h}.json")),
            r#"{"source_hash":"x","pipeline_version":"v1","ts_ms":1}"#,
        )
        .unwrap();
        let s = RawStore::open(d.path()).unwrap();
        assert_eq!(s.fetch_meta(&h).unwrap(), None);
    }
}
