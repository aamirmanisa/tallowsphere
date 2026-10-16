//! Integration test — derived-layer recompute on a pipeline/model bump
//! (task A1.2.4, frozen interface §4).
//!
//! What this proves, end to end through the crate's public API only:
//!
//! 1. Raw bytes land once in `tallow::raw_store::RawStore` under their sha256
//!    content address; identical bytes dedupe to the same object.
//! 2. A first derivation stores an `extract/v1` layer keyed by
//!    `sha256(source_hash + '\n' + pipeline_version)`;
//!    `DerivedStore::derive_required` flips to `false`.
//! 3. Simulating a pipeline/model bump (`extract/v1` -> `extract/v2`):
//!    re-deriving mints a NEW key for the new version, the v1 layer stays
//!    byte-identical under its old key, and the raw layer is untouched
//!    (re-`put_bytes` returns the same hash, `get` returns the same bytes,
//!    `verify` still holds, the object file is not rewritten on disk).
//! 4. `DerivedStore::list_for_source` reports both versions for the source —
//!    and skips the raw-store sidecar sharing the same `<root>/meta/` dir.
//! 5. Recomputation from raw under the SAME version is idempotent: same key,
//!    byte-identical artifact, no file rewritten (mtimes frozen), and a fresh
//!    store handle over the same root gives the same answer.
//!
//! Both stores intentionally share ONE root (the intel-pipeline shape):
//! raw objects at `<root>/<ab>/<cd>/<hash>`, derived bytes at
//! `<root>/derived/<key>`, metadata at `<root>/meta/`. The two sidecar JSON
//! shapes are disjoint, so sharing a root must degrade nothing.
//!
//! Run with: `cargo test --test derived_recompute`

use std::fs;
use std::time::Duration;

use tallow::derived_store::DerivedStore;
use tallow::raw_store::RawStore;

#[test]
fn pipeline_bump_rederives_new_layer_without_touching_raw() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("intel_root");
    let raw = RawStore::open(root.clone()).expect("open raw store");
    let derived = DerivedStore::open(root.clone()).expect("open derived store");

    // (1) Raw bytes: stored once, content-addressed (sha256 hex id).
    let raw_bytes: &[u8] = b"<html><body>captured page for extract</body></html>";
    let raw_hash = raw.put_bytes(raw_bytes).expect("put_bytes");
    assert_eq!(raw_hash.len(), 64, "content address is a sha256 hex id");
    assert!(raw.exists(&raw_hash));
    // Pipeline shape: provenance is recorded via a fetch. Identical bytes must
    // dedupe to the same raw object — this also drops a raw-store sidecar into
    // the shared <root>/meta/ dir that `list_for_source` must ignore below.
    assert_eq!(
        raw.put_fetch("https://example.org/page", "text/html", raw_bytes)
            .expect("put_fetch"),
        raw_hash,
        "identical bytes must dedupe to the same raw object"
    );

    // (2) First derivation: extract/v1.
    let v1_bytes: &[u8] = b"extract/v1 output: captured page text";
    let k1 = derived
        .put_derived(&raw_hash, "extract/v1", v1_bytes)
        .expect("put_derived extract/v1");
    assert_eq!(k1.len(), 64, "derived key is a sha256 hex id");
    assert!(
        !derived.derive_required(&raw_hash, "extract/v1"),
        "a freshly derived version must report derive_required == false"
    );

    // (3) Pipeline/model bump: same source re-derived under extract/v2.
    assert!(
        derived.derive_required(&raw_hash, "extract/v2"),
        "a version never derived before must report derive_required == true"
    );
    let v2_bytes: &[u8] = b"extract/v2 output: better text, model=m2 fields";
    let k2 = derived
        .put_derived(&raw_hash, "extract/v2", v2_bytes)
        .expect("put_derived extract/v2");

    // (4) The bump mints a NEW key; the old layer is untouched.
    assert_ne!(k1, k2, "a version bump must mint a new derived key");
    assert_eq!(
        derived.get_derived(&k1).expect("get v1"),
        v1_bytes,
        "v1 bytes must remain byte-identical after the bump"
    );
    assert_eq!(derived.get_derived(&k2).expect("get v2"), v2_bytes);
    assert!(!derived.derive_required(&raw_hash, "extract/v2"));

    // Both versions listed for the source — and ONLY they are: the raw-store
    // sidecar sharing <root>/meta/ (same 64-hex filename shape, foreign JSON)
    // must be skipped.
    let listed = derived
        .list_for_source(&raw_hash)
        .expect("list_for_source");
    assert_eq!(
        listed,
        vec![
            (k1.clone(), "extract/v1".to_string()),
            (k2.clone(), "extract/v2".to_string()),
        ],
        "both versions listed, sorted by pipeline_version; raw sidecar ignored"
    );
    for (key, _version) in &listed {
        assert!(
            derived.get_derived(key).is_ok(),
            "every listed key must resolve to bytes"
        );
    }

    // Raw layer untouched: same hash, same bytes, fixity holds, and the object
    // file on disk (documented layout <root>/<ab>/<cd>/<hash>) was not
    // rewritten by either derivation.
    let raw_obj = root
        .join(&raw_hash[..2])
        .join(&raw_hash[2..4])
        .join(&raw_hash);
    assert!(
        raw_obj.is_file(),
        "raw object missing at {}",
        raw_obj.display()
    );
    let m_before = fs::metadata(&raw_obj)
        .expect("raw object metadata")
        .modified()
        .expect("mtime");
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(
        raw.put_bytes(raw_bytes).expect("re-put_bytes"),
        raw_hash,
        "re-storing the same bytes must return the same content address"
    );
    assert_eq!(
        raw.get(&raw_hash).expect("get raw"),
        raw_bytes,
        "raw bytes must be unchanged after derivations"
    );
    assert!(
        raw.verify(&raw_hash).expect("verify raw"),
        "raw object must still hash to its address"
    );
    let m_after = fs::metadata(&raw_obj)
        .expect("raw object metadata")
        .modified()
        .expect("mtime");
    assert_eq!(
        m_before, m_after,
        "a pipeline bump must not rewrite the raw object"
    );
}

#[test]
fn recompute_from_raw_is_idempotent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("intel_root");
    let raw = RawStore::open(root.clone()).expect("open raw store");
    let derived = DerivedStore::open(root.clone()).expect("open derived store");

    let raw_bytes: &[u8] = b"captured artifact for recompute";
    let raw_hash = raw.put_bytes(raw_bytes).expect("put_bytes");

    // First derivation under the bumped version.
    let v2_bytes: &[u8] = b"extract/v2 output (deterministic)";
    let k2 = derived
        .put_derived(&raw_hash, "extract/v2", v2_bytes)
        .expect("first derive");
    assert!(!derived.derive_required(&raw_hash, "extract/v2"));

    // Snapshot the derived artifact + sidecar + raw object so "no rewrite" is
    // falsifiable rather than assumed.
    let key_path = root.join("derived").join(&k2);
    let side_path = root.join("meta").join(format!("{k2}.json"));
    assert!(key_path.is_file(), "derived bytes at {}", key_path.display());
    assert!(side_path.is_file(), "sidecar at {}", side_path.display());
    let key_m1 = fs::metadata(&key_path).unwrap().modified().unwrap();
    let side_m1 = fs::metadata(&side_path).unwrap().modified().unwrap();
    let raw_obj = root
        .join(&raw_hash[..2])
        .join(&raw_hash[2..4])
        .join(&raw_hash);
    let raw_m1 = fs::metadata(&raw_obj).unwrap().modified().unwrap();

    std::thread::sleep(Duration::from_millis(20));

    // Recompute-from-raw: re-read the raw bytes (must be identical for a
    // deterministic pipeline) and re-derive the same version.
    let raw_again = raw.get(&raw_hash).expect("re-read raw");
    assert_eq!(
        raw_again.as_slice(),
        raw_bytes,
        "recompute input must be the identical raw bytes"
    );
    let k2_again = derived
        .put_derived(&raw_hash, "extract/v2", v2_bytes)
        .expect("recompute derive");
    assert_eq!(k2_again, k2, "recompute must resolve to the same key");

    // Idempotence: same key, byte-identical artifact, nothing rewritten.
    assert_eq!(derived.get_derived(&k2).expect("get"), v2_bytes);
    assert!(!derived.derive_required(&raw_hash, "extract/v2"));
    assert_eq!(
        fs::metadata(&key_path).unwrap().modified().unwrap(),
        key_m1,
        "derived bytes must not be rewritten on recompute"
    );
    assert_eq!(
        fs::metadata(&side_path).unwrap().modified().unwrap(),
        side_m1,
        "derived sidecar must not be rewritten on recompute"
    );
    assert_eq!(
        fs::metadata(&raw_obj).unwrap().modified().unwrap(),
        raw_m1,
        "raw object must not be touched by recompute"
    );
    assert!(raw.verify(&raw_hash).expect("verify"), "raw fixity holds");

    // A fresh handle over the same root (new process / restart) sees the same
    // state: the key is a pure function of (source_hash, pipeline_version).
    let derived2 = DerivedStore::open(root.clone()).expect("reopen derived store");
    assert!(
        !derived2.derive_required(&raw_hash, "extract/v2"),
        "recompute not required across restarts"
    );
    assert_eq!(
        derived2.get_derived(&k2).expect("get via fresh handle"),
        v2_bytes
    );
    assert_eq!(
        derived2.list_for_source(&raw_hash).expect("list"),
        vec![(k2.clone(), "extract/v2".to_string())]
    );
}
