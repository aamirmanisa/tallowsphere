//! A2.1.1 — call-site artifact sealing with per-investigation keys.
//!
//! Pins the end-to-end adoption path: artifact payloads are encrypted under
//! an investigation key (`shred_ledger::encrypt_artifact`), the CIPHERTEXT
//! is what gets stored (raw store / replication payloads), erasure appends a
//! hash-chained tombstone, and after the key is destroyed the stored blob is
//! permanently unreadable while the ciphertext itself survives.
//!
//! The second test pins vault-side custody (`vault::key_custody`): a live
//! keyring survives a simulated process restart via a sealed custody file,
//! so sealed artifacts remain readable across restarts — until the key is
//! destroyed.

use tallow::raw_store::RawStore;
use tallow::shred::ShredKeyring;
use tallow::shred_ledger::{decrypt_artifact, encrypt_artifact, erasure_to_event, verify_chain};

#[test]
fn artifact_sealed_under_investigation_key_becomes_unreadable_after_shred() {
    let dir = tempfile::tempdir().unwrap();
    let store = RawStore::open(dir.path()).unwrap();
    let mut ring = ShredKeyring::new();
    let key_id = ring.new_key("inv-42", 1_700_000_000_000);

    // 1. Seal the artifact payload under the investigation key; store the
    //    CIPHERTEXT (content-addressed as always).
    let artifact = b"<html>collected artifact body</html>";
    let sealed = encrypt_artifact(&ring, &key_id, artifact).unwrap();
    assert_ne!(&sealed[..], &artifact[..], "stored form must not be plaintext");
    let hash = store.put_bytes(&sealed).unwrap();

    // 2. It reads back — but only through the key.
    let blob = store.get(&hash).unwrap();
    assert_eq!(decrypt_artifact(&ring, &key_id, &blob).unwrap(), artifact);

    // 3. Crypto-shred: destroy the key; emit the ledger tombstone.
    let event = ring.destroy(&key_id, 1_800_000_000_000).unwrap();
    let chain = vec![erasure_to_event(&event)];
    assert!(verify_chain(&chain), "erasure tombstone must chain-verify");

    // 4. The ciphertext survives at rest; readability is gone for good.
    assert!(store.exists(&hash));
    let still = store.get(&hash).unwrap();
    let err = decrypt_artifact(&ring, &key_id, &still).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("destroyed"), "must refuse as destroyed: {msg}");
}

#[test]
fn custody_restores_live_keys_so_sealed_artifacts_stay_readable_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let store = RawStore::open(dir.path()).unwrap();
    let custody_path = dir.path().join("custody.json");

    // Process 1: key + sealed artifact + sealed custody file.
    let (key_id, hash) = {
        let mut ring = ShredKeyring::new();
        let key_id = ring.new_key("inv-77", 1_000);
        let sealed = encrypt_artifact(&ring, &key_id, b"payload").unwrap();
        let hash = store.put_bytes(&sealed).unwrap();
        let custody = tallow::vault::key_custody::seal(&ring, "vault-pw").unwrap();
        tallow::vault::key_custody::save(&custody_path, &custody).unwrap();
        (key_id, hash)
    };

    // Process 2 (simulated restart): unseal the custody file, keep reading.
    let custody = tallow::vault::key_custody::load(&custody_path).unwrap();
    let restored = tallow::vault::key_custody::unseal(&custody, "vault-pw").unwrap();
    let blob = store.get(&hash).unwrap();
    assert_eq!(
        decrypt_artifact(&restored, &key_id, &blob).unwrap(),
        b"payload"
    );
}
