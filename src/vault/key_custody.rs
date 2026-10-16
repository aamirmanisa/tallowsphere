//! Vault-side custody of crypto-shredding key material (A2.1.1).
//!
//! The shred ring (`crate::shred`) keeps per-investigation key bytes **in
//! memory only**; the keyring store (`crate::keyring_store`) persists
//! identity metadata, "never key bytes" by design. This module closes the
//! gap between the two: `seal` exports the live material + full records and
//! wraps them under the vault password with the same hybrid construction the
//! v2 vault container uses (`pqc.rs`: inner AES-256-GCM keyed by
//! Argon2id(password), outer authenticated AEAD keyed by an ML-KEM-768
//! shared secret, ephemeral decapsulation key wrapped under
//! `Argon2id(password, BLAKE3(EK))`).
//!
//! **A destroyed key can never resurrect**: sealing exports live material
//! only, and [`ShredKeyring::from_custody`] additionally drops material whose
//! record is destroyed (fail-closed against hand-edited payloads).
//!
//! Sealed file format (JSON, versioned):
//! ```text
//! { "version": 1,
//!   "blob": <pqc::PQCEncryptedBlob as JSON>,   // sealed custody payload
//!   "dk_nonce": "<24 hex chars>",
//!   "wrapped_dk": "<hex>" }
//! ```
//! The custody file is written mode 0600; pair it with
//! `keyring_store`'s metadata: metadata is the audit index, this file is the
//! material custody.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::pqc;
use crate::shred::{KEY_LEN, KeyRecord, ShredKeyring};

/// Custody-file format version this module writes and reads.
pub const CUSTODY_VERSION: u32 = 1;

/// A sealed keyring custody file (see module docs).
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedKeyring {
    /// Format version ([`CUSTODY_VERSION`]).
    pub version: u32,
    /// Sealed custody payload (hybrid double-encrypted).
    pub blob: pqc::PQCEncryptedBlob,
    /// Hex-encoded 12-byte nonce wrapping the ML-KEM decapsulation key.
    pub dk_nonce: String,
    /// Hex-encoded ML-KEM decapsulation key, wrapped under the password.
    pub wrapped_dk: String,
}

/// Seal `keyring` (live material + full records) under `password`.
///
/// The plaintext custody payload exists only inside this call: it is built,
/// wrapped and zeroized before returning; `Err` carries no key material.
pub fn seal(keyring: &ShredKeyring, password: &str) -> Result<SealedKeyring, String> {
    keyring.with_live_material(|keys| {
        // Records travel verbatim (including destruction stamps) so a
        // restored ring keeps its full audit identity.
        let records: Vec<&KeyRecord> = keyring.records().collect();
        let material: Vec<(&str, String)> = keys
            .iter()
            .map(|(id, key)| (id.as_str(), to_hex(key)))
            .collect();
        let payload = serde_json::json!({ "records": records, "keys": material });
        let plaintext = Zeroizing::new(payload.to_string());

        let (blob, dk_hex) = pqc::pqc_hybrid_encrypt(plaintext.as_bytes(), password)?;
        let (dk_nonce, wrapped_dk) =
            pqc::pqc_wrap_dk(password, &blob.pqc_encapsulation_key, &dk_hex)?;
        Ok(SealedKeyring {
            version: CUSTODY_VERSION,
            blob,
            dk_nonce: to_hex(&dk_nonce),
            wrapped_dk: to_hex(&wrapped_dk),
        })
    })
}

/// Rebuild a [`ShredKeyring`] from a sealed custody file.
///
/// Refusals (all fail-closed, none leak material): unsupported version,
/// wrong password (KEM/AEAD authentication fails), malformed payload, or
/// malformed key material. Destroyed keys never resurrect (see module docs).
pub fn unseal(sealed: &SealedKeyring, password: &str) -> Result<ShredKeyring, String> {
    if sealed.version != CUSTODY_VERSION {
        return Err(format!(
            "custody: unsupported version {} (expected {CUSTODY_VERSION})",
            sealed.version
        ));
    }
    let dk_nonce: [u8; 12] = hex_decode(&sealed.dk_nonce)?
        .try_into()
        .map_err(|_| "custody: invalid dk nonce length".to_string())?;
    let wrapped_dk = hex_decode(&sealed.wrapped_dk)?;
    let dk_hex = pqc::pqc_unwrap_dk(
        password,
        &sealed.blob.pqc_encapsulation_key,
        &dk_nonce,
        &wrapped_dk,
    )?;
    let plaintext = Zeroizing::new(pqc::pqc_hybrid_decrypt(&sealed.blob, password, &dk_hex)?);

    let v: serde_json::Value = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("custody: corrupt sealed payload: {e}"))?;
    let records: BTreeMap<String, KeyRecord> = v
        .get("records")
        .map(|r| serde_json::from_value::<Vec<KeyRecord>>(r.clone()))
        .transpose()
        .map_err(|e| format!("custody: corrupt records: {e}"))?
        .unwrap_or_default()
        .into_iter()
        .map(|r| (r.key_id.clone(), r))
        .collect();
    let mut keys: BTreeMap<String, [u8; KEY_LEN]> = BTreeMap::new();
    if let Some(arr) = v.get("keys").and_then(|k| k.as_array()) {
        for pair in arr {
            let id = pair
                .get(0)
                .and_then(|x| x.as_str())
                .ok_or_else(|| "custody: malformed key entry".to_string())?;
            let hex = pair
                .get(1)
                .and_then(|x| x.as_str())
                .ok_or_else(|| "custody: malformed key entry".to_string())?;
            let bytes = hex_decode(hex)?;
            let key: [u8; KEY_LEN] = bytes
                .try_into()
                .map_err(|_| format!("custody: key {id} has wrong length"))?;
            keys.insert(id.to_string(), key);
        }
    }
    Ok(ShredKeyring::from_custody(records, keys))
}

/// Write a sealed custody file to `path` (new files are mode 0600).
pub fn save(path: &Path, sealed: &SealedKeyring) -> Result<(), String> {
    let json =
        serde_json::to_string_pretty(sealed).map_err(|e| format!("custody: encode: {e}"))?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("custody: write '{}': {e}", path.display()))?;
    f.write_all(json.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("custody: write '{}': {e}", path.display()))
}

/// Read a sealed custody file from `path`.
pub fn load(path: &Path) -> Result<SealedKeyring, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("custody: read '{}': {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("custody: parse '{}': {e}", path.display()))
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("custody: odd-length hex".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "custody: invalid hex".to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring_with_keys() -> (ShredKeyring, String, String) {
        let mut ring = ShredKeyring::new();
        let live = ring.new_key("inv-1", 1_000);
        let doomed = ring.new_key("inv-1", 1_000);
        (ring, live, doomed)
    }

    #[test]
    fn seal_unseal_round_trips_live_material() {
        let (mut ring, live, _doomed) = ring_with_keys();
        let blob = ring.encrypt(&live, b"artifact bytes").unwrap();

        let sealed = seal(&ring, "pw-1").unwrap();
        let mut restored = unseal(&sealed, "pw-1").unwrap();

        assert_eq!(restored.len(), 2);
        assert_eq!(restored.decrypt(&live, &blob).unwrap(), b"artifact bytes");
        // The restored ring keeps operating and shredding.
        let fresh = restored.new_key("inv-2", 2_000);
        assert!(restored.record(&fresh).is_some());
        restored.destroy(&fresh, 2_500).unwrap();
        assert!(restored.is_destroyed(&fresh));
    }

    #[test]
    fn destroyed_keys_never_resurrect_through_custody() {
        let (mut ring, live, doomed) = ring_with_keys();
        let live_blob = ring.encrypt(&live, b"live").unwrap();
        let doomed_blob = ring.encrypt(&doomed, b"gone").unwrap();
        ring.destroy(&doomed, 1_500).unwrap();

        let sealed = seal(&ring, "pw").unwrap();
        let restored = unseal(&sealed, "pw").unwrap();
        assert!(restored.is_destroyed(&doomed));
        let err = restored.decrypt(&doomed, &doomed_blob).unwrap_err();
        assert!(
            format!("{err}").contains("destroyed"),
            "destroyed key must refuse: {err}"
        );
        assert_eq!(restored.decrypt(&live, &live_blob).unwrap(), b"live");
    }

    #[test]
    fn wrong_password_and_version_are_refused() {
        let (ring, _l, _d) = ring_with_keys();
        let sealed = seal(&ring, "right").unwrap();
        assert!(unseal(&sealed, "wrong").is_err());

        let mut bogus = sealed.clone();
        bogus.version = 99;
        let err = unseal(&bogus, "right").unwrap_err();
        assert!(err.contains("unsupported version"), "{err}");
    }

    #[test]
    fn save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custody.json");
        let (ring, live, _d) = ring_with_keys();
        let sealed = seal(&ring, "pw").unwrap();
        save(&path, &sealed).unwrap();

        let loaded = load(&path).unwrap();
        assert_eq!(loaded.version, sealed.version);
        assert_eq!(loaded.dk_nonce, sealed.dk_nonce);
        assert_eq!(loaded.wrapped_dk, sealed.wrapped_dk);
        let restored = unseal(&loaded, "pw").unwrap();
        assert!(restored.record(&live).is_some());
    }
}
