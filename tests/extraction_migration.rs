//! A1.2.3 adoption — extraction outputs on the derived layer.
//!
//! Migrates the current extraction-output convention (a flat byte blob per
//! output) onto [`DerivedStore`]'s versioned layers, pinning byte
//! compatibility end to end: the bytes read back are exactly the bytes the
//! extractor produced, the raw layer is never touched, and a pipeline-version
//! bump mints a new layer without touching the old one.

use tallow::derived_store::DerivedStore;
use tallow::raw_store::RawStore;

/// A stand-in extractor: deterministic, and deliberately not a JSON
/// round-trip (the migration must not re-encode anything).
fn extract_v1(raw: &[u8]) -> Vec<u8> {
    let mut out = b"{\"extract\":\"v1\",\"len\":".to_vec();
    out.extend_from_slice(format!("{}", raw.len()).as_bytes());
    out.extend_from_slice(b",\"head\":\"");
    out.extend_from_slice(&raw[..raw.len().min(8)]);
    out.extend_from_slice(b"\"}");
    out
}

#[test]
fn extraction_outputs_migrate_byte_compatibly_and_idempotently() {
    let dir = tempfile::tempdir().unwrap();
    let raw = RawStore::open(dir.path()).unwrap();
    let derived = DerivedStore::open(dir.path()).unwrap();

    // 1. Capture raw (immutable), then extract from it.
    let html = b"<html><body><h1>Target</h1>text</body></html>";
    let source_hash = raw.put_bytes(html).unwrap();
    let output_v1 = extract_v1(html);

    // 2. Migrate the extraction output onto the derived layer.
    let out = derived
        .store_extraction(&source_hash, "extract/v1", &output_v1)
        .unwrap();
    assert!(out.stored);
    assert_eq!(
        derived.get_derived(&out.key).unwrap(),
        output_v1,
        "read-back must be byte-identical to the extraction output"
    );

    // 3. Re-running the same pipeline version replays (idempotent), the
    //    existing bytes win, and the raw layer is untouched.
    let again = derived
        .store_extraction(&source_hash, "extract/v1", b"different")
        .unwrap();
    assert!(again.replayed());
    assert_eq!(again.key, out.key);
    assert_eq!(derived.get_derived(&again.key).unwrap(), output_v1);
    assert_eq!(raw.get(&source_hash).unwrap(), html);

    // 4. A pipeline bump mints a NEW layer; both are listable.
    let out_v2 = derived
        .store_extraction(&source_hash, "extract/v2", &output_v1)
        .unwrap();
    assert!(out_v2.stored);
    assert_ne!(out_v2.key, out.key);
    assert_eq!(derived.list_for_source(&source_hash).unwrap().len(), 2);
    assert!(!derived.derive_required(&source_hash, "extract/v1"));
    assert!(!derived.derive_required(&source_hash, "extract/v2"));
    assert!(derived.derive_required(&source_hash, "extract/v3"));
}

#[test]
fn migrated_outputs_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let source_hash = {
        let raw = RawStore::open(dir.path()).unwrap();
        raw.put_bytes(b"payload").unwrap()
    };
    let output = extract_v1(b"payload");
    {
        let derived = DerivedStore::open(dir.path()).unwrap();
        let out = derived
            .store_extraction(&source_hash, "extract/v1", &output)
            .unwrap();
        assert!(out.stored);
    }
    let derived = DerivedStore::open(dir.path()).unwrap();
    let keys = derived.list_for_source(&source_hash).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(derived.get_derived(&keys[0].0).unwrap(), output);
}

#[test]
fn migration_bytes_are_never_rewritten() {
    let dir = tempfile::tempdir().unwrap();
    let derived = DerivedStore::open(dir.path()).unwrap();
    let src = "aa".repeat(32);
    let first = derived
        .store_extraction(&src, "extract/v1", b"first")
        .unwrap();
    let second = derived
        .store_extraction(&src, "extract/v1", b"second")
        .unwrap();
    assert_eq!(first.key, second.key);
    assert!(second.replayed());
    assert_eq!(derived.get_derived(&second.key).unwrap(), b"first");
}
