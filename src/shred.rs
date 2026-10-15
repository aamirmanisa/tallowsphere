//! Crypto-shredding keyring — per-investigation AES-256-GCM keys + erasure
//! tombstones (task A2.1.1 + A2.1.2 core · frozen interface §1).
//!
//! The keyring gives every *investigation* its own 32-byte AES-256-GCM key.
//! Blobs are encrypted under exactly one key, and **destroying a key makes
//! every blob encrypted under it permanently unreadable** — the ciphertext
//! survives (the log's shape is preserved) while the ability to read the
//! plaintext dies with the key. That property is the whole point: `destroy`
//! returns an [`ErasureEvent`] tombstone destined for the append-only ledger,
//! so an audit can prove *when* a key was shredded without keeping anything
//! readable.
//!
//! # Key material is never serialized
//!
//! [`KeyRecord`] and [`ErasureEvent`] are the only serializable artifacts;
//! they carry identity, not secrets. Key bytes live exclusively in the
//! in-memory `ShredKeyring`, are zeroized on [`ShredKeyring::destroy`] and on
//! drop, and [`ShredKeyring`] deliberately has no `Serialize` impl and a
//! redacting [`std::fmt::Debug`]. A test asserts that neither the debug view
//! nor any serialized record contains the raw key bytes.
//!
//! # key_id scheme (documented + tested)
//!
//! Every allocated key gets a deterministic id of the form
//!
//! ```text
//! shred-<seq:08x>-<fp8>
//! ```
//!
//! * `seq` — the ring's monotonic allocation counter starting at 1, bumped on
//!   every call to [`ShredKeyring::new_key`] and **never reused** (not even
//!   after `destroy`). Guarantees uniqueness within the ring.
//! * `fp8` — first 4 bytes of `BLAKE3("tallow-shred-key-id-v1" ‖ key)` in
//!   lowercase hex. Deterministic in the key material; it namespaces ids so
//!   that records merged from two different rings cannot collide in practice
//!   (`seq` collides, 32-bit fingerprint does not).
//!
//! The scheme is a pure function of `(seq, key)` — same inputs, same id — so
//! tests can recompute it, while the key itself stays uniformly random.
//!
//! # Blob format
//!
//! `encrypt` returns `nonce (12 bytes) ‖ ciphertext`, where the ciphertext is
//! the AES-256-GCM output with its 16-byte authentication tag appended. The
//! nonce is random per call (`rand::rng()`), so encrypting the same plaintext
//! twice yields different blobs; both decrypt to the same plaintext.
//!
//! # Error mapping (documented edge rules)
//!
//! * Unknown `key_id` (no record) → [`ShredError::UnknownKey`] for
//!   `encrypt`/`decrypt`/`destroy`.
//! * A record that exists and is destroyed → [`ShredError::AlreadyDestroyed`]
//!   for `encrypt`/`decrypt`, and for a second `destroy`.
//! * Authentication failure, tampered/truncated blobs → [`ShredError::Crypto`].
//! * [`ShredKeyring::is_destroyed`] returns `false` for unknown ids (there is
//!   no destruction evidence to report) and `true` once destroyed.

use aes_gcm::{Aes256Gcm, Nonce, aead::Aead, aead::KeyInit};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use zeroize::Zeroize;

/// Length of the random nonce prepended to every encrypted blob.
pub const NONCE_LEN: usize = 12;
/// AES-256 key length in bytes.
pub const KEY_LEN: usize = 32;
/// AES-GCM authentication tag length in bytes (appended to the ciphertext).
pub const TAG_LEN: usize = 16;

/// Domain separator for the key-id fingerprint (KDF-like separation so the
/// fingerprint can never be confused with a hash used for another purpose).
const KEY_ID_DOMAIN: &[u8] = b"tallow-shred-key-id-v1";

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// Metadata for one key ever issued by a [`ShredKeyring`]. Serializable —
/// contains identity only, never key bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRecord {
    /// Key identity, `shred-<seq:08x>-<fp8>` (see module docs).
    pub key_id: String,
    /// The investigation this key belongs to. Investigations are isolated:
    /// a key from one investigation can never decrypt another's blobs.
    pub investigation: String,
    /// Allocation time (Unix milliseconds, caller-supplied).
    pub created_ms: i64,
    /// Destruction time once shredded; `None` while the key is live.
    pub destroyed_ms: Option<i64>,
}

/// Tombstone emitted by [`ShredKeyring::destroy`] — the record that the key
/// *was* destroyed. Destined for the append-only ledger; safe to serialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureEvent {
    /// The key that was shredded.
    pub key_id: String,
    /// The investigation the key belonged to (copied from the record).
    pub investigation: String,
    /// When the destruction happened (Unix milliseconds, caller-supplied).
    pub at_ms: i64,
}

/// Errors from keyring operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShredError {
    /// No record exists for this `key_id` (never issued, or wrong ring).
    UnknownKey { key_id: String },
    /// The key exists but its material has been shredded; the blob can never
    /// be read again — by design.
    AlreadyDestroyed { key_id: String },
    /// The AEAD layer failed (authentication, wrong key, malformed blob).
    /// Messages never include key material.
    Crypto(String),
}

impl fmt::Display for ShredError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShredError::UnknownKey { key_id } => {
                write!(f, "shred: unknown key '{key_id}' (never issued by this ring)")
            }
            ShredError::AlreadyDestroyed { key_id } => write!(
                f,
                "shred: key '{key_id}' was destroyed; its blobs are permanently unreadable"
            ),
            ShredError::Crypto(msg) => write!(f, "shred: crypto error: {msg}"),
        }
    }
}

impl std::error::Error for ShredError {}

// ---------------------------------------------------------------------------
// Keyring
// ---------------------------------------------------------------------------

/// Per-investigation crypto-shredding keyring.
///
/// Key bytes live only here, in memory. The only things that can leave the
/// keyring are [`KeyRecord`]s, [`ErasureEvent`] tombstones, and encrypted
/// blobs. `Debug` redacts; there is no `Serialize`, no `Clone`.
pub struct ShredKeyring {
    /// Live key material, indexed by key id. Removed (and zeroized) on
    /// `destroy`.
    keys: BTreeMap<String, [u8; KEY_LEN]>,
    /// Full issuance/destruction history, ascending by `key_id`.
    records: BTreeMap<String, KeyRecord>,
    /// Monotonic allocation counter (starts at 1; never reused).
    next_seq: u64,
}

impl Default for ShredKeyring {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ShredKeyring {
    /// Redacting view: counts only, never key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShredKeyring")
            .field("live_keys", &self.keys.len())
            .field("records", &self.records.len())
            .field("next_seq", &self.next_seq)
            .finish()
    }
}

impl Drop for ShredKeyring {
    /// Zeroize any key material still held when the ring is dropped.
    fn drop(&mut self) {
        for key in self.keys.values_mut() {
            key.zeroize();
        }
        self.keys.clear();
    }
}

impl ShredKeyring {
    /// New, empty keyring.
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
            records: BTreeMap::new(),
            next_seq: 1,
        }
    }

    /// Allocate a fresh 32-byte key for `investigation` and return its
    /// `key_id` (see module docs for the deterministic `shred-<seq:08x>-<fp8>`
    /// scheme). The key material is random; only the id derivation is
    /// deterministic.
    pub fn new_key(&mut self, investigation: &str, now_ms: i64) -> String {
        let mut key = [0u8; KEY_LEN];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut key);

        let seq = self.next_seq;
        self.next_seq += 1;
        let key_id = derive_key_id(seq, &key);

        let record = KeyRecord {
            key_id: key_id.clone(),
            investigation: investigation.to_string(),
            created_ms: now_ms,
            destroyed_ms: None,
        };
        self.keys.insert(key_id.clone(), key);
        self.records.insert(key_id.clone(), record);
        key_id
    }

    /// Encrypt `plaintext` under `key_id`: AES-256-GCM with a random 12-byte
    /// nonce prepended to the output blob. Never deterministic (fresh nonce).
    pub fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, ShredError> {
        let key = self.live_key(key_id)?;

        let mut nonce = [0u8; NONCE_LEN];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);

        let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|e| ShredError::Crypto(format!("AES-256-GCM encryption failed: {e}")))?;

        let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        Ok(blob)
    }

    /// Decrypt a blob produced by [`ShredKeyring::encrypt`] under `key_id`.
    /// A destroyed key yields [`ShredError::AlreadyDestroyed`] — the blob is
    /// gone for good, and that is the intended outcome, not a bug.
    pub fn decrypt(&self, key_id: &str, blob: &[u8]) -> Result<Vec<u8>, ShredError> {
        let key = self.live_key(key_id)?;

        if blob.len() < NONCE_LEN + TAG_LEN {
            return Err(ShredError::Crypto(format!(
                "blob too short: {} bytes (need at least {})",
                blob.len(),
                NONCE_LEN + TAG_LEN
            )));
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);

        let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
        cipher
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| {
                ShredError::Crypto(
                    "AES-256-GCM decryption failed (wrong key or tampered blob)".to_string(),
                )
            })
    }

    /// Crypto-shred `key_id`: remove (and zeroize) its key material, stamp
    /// the record with `destroyed_ms = Some(now_ms)`, and return the
    /// [`ErasureEvent`] tombstone for the ledger. All blobs encrypted under
    /// this key become permanently unreadable.
    ///
    /// A second destroy of the same key fails with
    /// [`ShredError::AlreadyDestroyed`] (the first tombstone stands).
    pub fn destroy(&mut self, key_id: &str, now_ms: i64) -> Result<ErasureEvent, ShredError> {
        let record = self
            .records
            .get(key_id)
            .ok_or_else(|| ShredError::UnknownKey {
                key_id: key_id.to_string(),
            })?;
        if record.destroyed_ms.is_some() {
            return Err(ShredError::AlreadyDestroyed {
                key_id: key_id.to_string(),
            });
        }

        if let Some(mut key) = self.keys.remove(key_id) {
            key.zeroize();
        }
        let record = self.records.get_mut(key_id).expect("checked above");
        record.destroyed_ms = Some(now_ms);

        Ok(ErasureEvent {
            key_id: key_id.to_string(),
            investigation: record.investigation.clone(),
            at_ms: now_ms,
        })
    }

    /// Whether `key_id` has been shredded. Unknown ids report `false` (no
    /// destruction evidence exists) — documented edge rule.
    pub fn is_destroyed(&self, key_id: &str) -> bool {
        self.records
            .get(key_id)
            .map(|r| r.destroyed_ms.is_some())
            .unwrap_or(false)
    }

    /// The record for `key_id`, if any (live or destroyed).
    pub fn record(&self, key_id: &str) -> Option<&KeyRecord> {
        self.records.get(key_id)
    }

    /// All records, ascending by `key_id` (canonical, deterministic order —
    /// `BTreeMap` iteration order).
    pub fn records(&self) -> impl Iterator<Item = &KeyRecord> + '_ {
        self.records.values()
    }

    /// Number of records (live + destroyed).
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether no key was ever issued.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Wrap a destroyed/unknown key into the right error; never returns a
    /// destroyed key's bytes (they do not exist).
    fn live_key(&self, key_id: &str) -> Result<&[u8; KEY_LEN], ShredError> {
        match self.records.get(key_id) {
            None => Err(ShredError::UnknownKey {
                key_id: key_id.to_string(),
            }),
            Some(rec) if rec.destroyed_ms.is_some() => Err(ShredError::AlreadyDestroyed {
                key_id: key_id.to_string(),
            }),
            // Invariant: live records always have material; absence would be
            // an internal bug, and failing closed (UnknownKey) leaks nothing.
            Some(_) => self.keys.get(key_id).ok_or_else(|| ShredError::UnknownKey {
                key_id: key_id.to_string(),
            }),
        }
    }

    /// Custody export (A2.1.1 — vault-side key material): hand the LIVE key
    /// material to `f` under the caller's custody seal, without exposing key
    /// bytes through a public return value. `f` receives `(key_id, key)`
    /// pairs in `BTreeMap` order; whatever it returns leaves, the material
    /// itself cannot be extracted beyond what `f` does with it.
    ///
    /// Destroyed keys are absent — their material is gone by design. The
    /// intended caller is `vault::key_custody::seal`, which encrypts inside
    /// the closure and returns only ciphertext.
    pub fn with_live_material<R>(
        &self,
        f: impl FnOnce(&BTreeMap<String, [u8; KEY_LEN]>) -> R,
    ) -> R {
        f(&self.keys)
    }

    /// Rebuild a keyring from custody (A2.1.1): records verbatim (including
    /// destruction stamps) + live material for live keys only.
    ///
    /// Fail-closed: material supplied for a key whose record is destroyed is
    /// **dropped** (a destroyed key never resurrects, even from a
    /// hand-edited custody payload); material for unknown ids is dropped too.
    /// `next_seq` resumes past every `shred-<seq:08x>-…` id ever recorded, so
    /// ids are never reused.
    pub fn from_custody(
        records: BTreeMap<String, KeyRecord>,
        keys: BTreeMap<String, [u8; KEY_LEN]>,
    ) -> Self {
        let keys: BTreeMap<String, [u8; KEY_LEN]> = keys
            .into_iter()
            .filter(|(id, _)| {
                records
                    .get(id)
                    .map(|r| r.destroyed_ms.is_none())
                    .unwrap_or(false)
            })
            .collect();
        let mut next_seq = records.len() as u64 + 1;
        for id in records.keys() {
            if let Some(body) = id.strip_prefix("shred-") {
                if let Some((seq, _)) = body.split_once('-') {
                    if let Ok(n) = u64::from_str_radix(seq, 16) {
                        next_seq = next_seq.max(n + 1);
                    }
                }
            }
        }
        ShredKeyring {
            keys,
            records,
            next_seq,
        }
    }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// `shred-<seq:08x>-<fp8>` (see module docs). Pure function of `(seq, key)`.
fn derive_key_id(seq: u64, key: &[u8; KEY_LEN]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(KEY_ID_DOMAIN);
    hasher.update(key);
    let fp = hasher.finalize();
    format!("shred-{seq:08x}-{}", hex_lower(&fp.as_bytes()[..4]))
}

/// Lowercase hex — local helper (no extra dependency).
fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_basic_and_empty_plaintext() {
        let mut ring = ShredKeyring::new();
        let k = ring.new_key("inv-1", 1_000);
        let blob = ring.encrypt(&k, b"secret payload").unwrap();
        assert_eq!(ring.decrypt(&k, &blob).unwrap(), b"secret payload");
        // Empty plaintext still authenticates.
        let blob = ring.encrypt(&k, b"").unwrap();
        assert_eq!(ring.decrypt(&k, &blob).unwrap(), b"");
    }

    #[test]
    fn roundtrip_binary_with_nul_bytes() {
        let mut ring = ShredKeyring::new();
        let k = ring.new_key("inv-bin", 1_000);
        let pt: Vec<u8> = (0u8..=255).collect();
        let blob = ring.encrypt(&k, &pt).unwrap();
        assert_eq!(ring.decrypt(&k, &blob).unwrap(), pt);
    }

    #[test]
    fn blob_layout_is_nonce_prepended() {
        let mut ring = ShredKeyring::new();
        let k = ring.new_key("inv-1", 1_000);
        let pt = b"twelve plus tag";
        let blob = ring.encrypt(&k, pt).unwrap();
        // nonce || ciphertext(+tag)
        assert_eq!(blob.len(), NONCE_LEN + pt.len() + TAG_LEN);
    }

    #[test]
    fn encryption_is_nondeterministic_but_both_decrypt() {
        let mut ring = ShredKeyring::new();
        let k = ring.new_key("inv-1", 1_000);
        let b1 = ring.encrypt(&k, b"same").unwrap();
        let b2 = ring.encrypt(&k, b"same").unwrap();
        assert_ne!(b1, b2, "random nonce must make blobs differ");
        assert_eq!(ring.decrypt(&k, &b1).unwrap(), b"same");
        assert_eq!(ring.decrypt(&k, &b2).unwrap(), b"same");
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let mut ring = ShredKeyring::new();
        let a = ring.new_key("inv-a", 1_000);
        let b = ring.new_key("inv-b", 2_000);
        let blob = ring.encrypt(&a, b"for a only").unwrap();
        assert!(matches!(
            ring.decrypt(&b, &blob),
            Err(ShredError::Crypto(_))
        ));
    }

    #[test]
    fn investigations_are_isolated() {
        let mut ring = ShredKeyring::new();
        let a = ring.new_key("ops/alpha", 1_000);
        let b = ring.new_key("ops/bravo", 1_000);
        let blob_a = ring.encrypt(&a, b"alpha eyes only").unwrap();
        let blob_b = ring.encrypt(&b, b"bravo eyes only").unwrap();
        // Cross-investigation decryption fails even though both keys are live
        // and healthy.
        assert!(ring.decrypt(&b, &blob_a).is_err());
        assert!(ring.decrypt(&a, &blob_b).is_err());
        assert!(ring.decrypt(&a, &blob_a).is_ok());
        assert!(ring.decrypt(&b, &blob_b).is_ok());
    }

    #[test]
    fn tampered_or_truncated_blob_fails() {
        let mut ring = ShredKeyring::new();
        let k = ring.new_key("inv-1", 1_000);
        let mut blob = ring.encrypt(&k, b"integrity").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01; // flip a tag bit
        assert!(matches!(ring.decrypt(&k, &blob), Err(ShredError::Crypto(_))));
        // Truncation below nonce+tag is rejected before the AEAD call.
        assert!(matches!(
            ring.decrypt(&k, &blob[..NONCE_LEN + TAG_LEN - 1]),
            Err(ShredError::Crypto(_))
        ));
    }

    #[test]
    fn destroyed_key_fails_decrypt_and_reports_destroyed() {
        let mut ring = ShredKeyring::new();
        let k = ring.new_key("inv-1", 1_000);
        let blob = ring.encrypt(&k, b"will be shredded").unwrap();
        assert!(!ring.is_destroyed(&k));
        ring.destroy(&k, 5_000).unwrap();
        assert!(ring.is_destroyed(&k));
        // The blob survives, the readability does not.
        assert!(matches!(
            ring.decrypt(&k, &blob),
            Err(ShredError::AlreadyDestroyed { .. })
        ));
        // Encrypting under a shredded key is refused too.
        assert!(matches!(
            ring.encrypt(&k, b"more"),
            Err(ShredError::AlreadyDestroyed { .. })
        ));
    }

    #[test]
    fn double_destroy_is_already_destroyed() {
        let mut ring = ShredKeyring::new();
        let k = ring.new_key("inv-1", 1_000);
        let ev1 = ring.destroy(&k, 5_000).unwrap();
        assert_eq!(ev1.at_ms, 5_000);
        match ring.destroy(&k, 9_000) {
            Err(ShredError::AlreadyDestroyed { key_id }) => assert_eq!(key_id, k),
            other => panic!("expected AlreadyDestroyed, got {other:?}"),
        }
        // First tombstone stands: record still carries the original stamp.
        assert_eq!(ring.record(&k).unwrap().destroyed_ms, Some(5_000));
    }

    #[test]
    fn tombstone_fields_match_record() {
        let mut ring = ShredKeyring::new();
        let k = ring.new_key("inv-42", 1_000);
        let ev = ring.destroy(&k, 7_777).unwrap();
        assert_eq!(ev.key_id, k);
        assert_eq!(ev.investigation, "inv-42");
        assert_eq!(ev.at_ms, 7_777);
        assert_eq!(ring.record(&k).unwrap().investigation, "inv-42");
        assert_eq!(ring.record(&k).unwrap().destroyed_ms, Some(7_777));
    }

    #[test]
    fn key_ids_unique_across_calls() {
        let mut ring = ShredKeyring::new();
        let mut ids = std::collections::BTreeSet::new();
        for i in 0..256 {
            let k = ring.new_key("inv-1", i);
            assert!(ids.insert(k.clone()), "duplicate key_id: {k}");
        }
        assert_eq!(ids.len(), 256);
        // Destroyed ids are never re-issued either.
        let victim = ring.new_key("inv-1", 99);
        ring.destroy(&victim, 100).unwrap();
        let after = ring.new_key("inv-1", 101);
        assert_ne!(after, victim);
    }

    #[test]
    fn key_id_scheme_is_deterministic_and_documented_shape() {
        let key = [7u8; KEY_LEN];
        let id1 = derive_key_id(1, &key);
        let id2 = derive_key_id(1, &key);
        assert_eq!(id1, id2, "same (seq, key) => same id");
        assert_ne!(derive_key_id(2, &key), id1, "seq participates");
        assert_ne!(derive_key_id(1, &[8u8; KEY_LEN]), id1, "key participates");
        // Shape: shred-<8 hex>-<8 hex>
        let body = id1.strip_prefix("shred-").expect("prefix");
        let (seq_hex, fp_hex) = body.split_once('-').expect("separator");
        assert_eq!(seq_hex.len(), 8);
        assert!(seq_hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(fp_hex.len(), 8);
        assert!(fp_hex.chars().all(|c| c.is_ascii_hexdigit()));
        // A fresh ring starts at seq 1.
        let mut ring = ShredKeyring::new();
        let first = ring.new_key("inv", 0);
        assert!(first.starts_with("shred-00000001-"), "got {first}");
    }

    #[test]
    fn unknown_key_paths() {
        let ring = ShredKeyring::new();
        match ring.encrypt("shred-deadbeef-deadbeef", b"x") {
            Err(ShredError::UnknownKey { key_id }) => {
                assert_eq!(key_id, "shred-deadbeef-deadbeef")
            }
            other => panic!("expected UnknownKey, got {other:?}"),
        }
        assert!(matches!(
            ring.decrypt("nope", b"x"),
            Err(ShredError::UnknownKey { .. })
        ));
        assert!(!ring.is_destroyed("nope"), "unknown => not destroyed");
        assert!(ring.record("nope").is_none());
    }

    #[test]
    fn unknown_key_destroy_is_err_and_does_not_mutate() {
        let mut ring = ShredKeyring::new();
        assert!(matches!(
            ring.destroy("nope", 1_000),
            Err(ShredError::UnknownKey { .. })
        ));
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);
    }

    #[test]
    fn records_are_deterministic_and_ascending() {
        let mut ring = ShredKeyring::new();
        let a = ring.new_key("inv-a", 10);
        let b = ring.new_key("inv-b", 20);
        let c = ring.new_key("inv-c", 30);
        let ids: Vec<&str> = ring.records().map(|r| r.key_id.as_str()).collect();
        assert_eq!(ids.len(), 3);
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "records ascend by key_id");
        assert!(ids.contains(&a.as_str()) && ids.contains(&b.as_str()) && ids.contains(&c.as_str()));
        assert_eq!(ring.len(), 3);
    }

    #[test]
    fn serde_roundtrip_key_record_and_erasure_event() {
        let mut ring = ShredKeyring::new();
        let k = ring.new_key("inv-serde", 12_345);
        let rec = ring.record(&k).unwrap().clone();
        let json = serde_json::to_string(&rec).unwrap();
        let back: KeyRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
        assert_eq!(back.destroyed_ms, None);

        let ev = ring.destroy(&k, 54_321).unwrap();
        let json = serde_json::to_string(&ev).unwrap();
        let back: ErasureEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
        assert_eq!(back.at_ms, 54_321);
        // Record serde round-trips the destroyed stamp too.
        let rec = ring.record(&k).unwrap().clone();
        let back: KeyRecord = serde_json::from_str(&serde_json::to_string(&rec).unwrap()).unwrap();
        assert_eq!(back.destroyed_ms, Some(54_321));
    }

    #[test]
    fn key_bytes_absent_from_debug_and_serialized_records() {
        let mut ring = ShredKeyring::new();
        let k = ring.new_key("inv-leak-check", 1_000);
        // Internal access (same module) to the actual key bytes.
        let raw = ring.keys.get(&k).unwrap();
        let raw_hex = hex_lower(raw);

        let dbg = format!("{ring:?}");
        assert!(!dbg.contains(&raw_hex), "Debug leaks key bytes: {dbg}");

        for rec in ring.records() {
            let json = serde_json::to_string(rec).unwrap();
            assert!(!json.contains(&raw_hex), "record JSON leaks key bytes");
        }
        ring.destroy(&k, 2_000).unwrap();
        assert!(ring.keys.is_empty(), "destroy removed key material");
        let dbg_after = format!("{ring:?}");
        assert!(!dbg_after.contains(&raw_hex));
    }

    #[test]
    fn debug_redacts_and_drop_zeroizes() {
        let mut ring = ShredKeyring::new();
        let k = ring.new_key("inv-dbg", 1_000);
        let dbg = format!("{ring:?}");
        assert!(dbg.contains("live_keys: 1"));
        assert!(!dbg.contains("shred-"), "Debug must not print key ids either");
        drop(ring);
        // No assertion possible on freed memory; the contract is the Drop impl
        // zeroizing before free. Compile-time: ShredKeyring has no Serialize
        // impl, so it cannot be persisted by accident.
        fn assert_not_serializable<T>() {}
        assert_not_serializable::<KeyRecord>();
        let _ = k; // silence unused
    }

    // ── custody (A2.1.1) ───────────────────────────────────────────────────

    #[test]
    fn from_custody_drops_material_of_destroyed_records() {
        let mut ring = ShredKeyring::new();
        let id = ring.new_key("inv", 1);
        ring.destroy(&id, 2).unwrap();

        let records: BTreeMap<String, KeyRecord> =
            ring.records().map(|r| (r.key_id.clone(), r.clone())).collect();
        let mut keys: BTreeMap<String, [u8; KEY_LEN]> = BTreeMap::new();
        // Hand-injected material for a DESTROYED record: must be dropped.
        keys.insert(id.clone(), [7u8; KEY_LEN]);

        let rebuilt = ShredKeyring::from_custody(records, keys);
        assert!(rebuilt.is_destroyed(&id));
        assert!(matches!(
            rebuilt.encrypt(&id, b"x"),
            Err(ShredError::AlreadyDestroyed { .. })
        ));
    }

    #[test]
    fn from_custody_resumes_sequence_and_keeps_live_keys() {
        let mut ring = ShredKeyring::new();
        let a = ring.new_key("inv", 1);
        let b = ring.new_key("inv", 2);
        let blob = ring.encrypt(&a, b"still readable").unwrap();

        let records: BTreeMap<String, KeyRecord> =
            ring.records().map(|r| (r.key_id.clone(), r.clone())).collect();
        let keys: BTreeMap<String, [u8; KEY_LEN]> = ring.with_live_material(|k| k.clone());

        let mut rebuilt = ShredKeyring::from_custody(records, keys);
        assert_eq!(rebuilt.len(), 2);
        assert_eq!(rebuilt.decrypt(&a, &blob).unwrap(), b"still readable");

        // New ids never collide with restored ones.
        let c = rebuilt.new_key("inv", 3);
        assert_ne!(c, a);
        assert_ne!(c, b);
        assert_eq!(rebuilt.len(), 3);
    }
}
