//! Volatile in-process credential cache — real AEAD backing for the
//! `CredentialVault` `.tl` surface (cycle-02/07 §D3, FIX-9).
//!
//! # Honest label (CHARTER §3)
//!
//! **Volatile in-process credential cache; not persisted, not at-rest
//! encryption. Use `tallow vault` ([`super::db`] — Argon2id + AES-256-GCM,
//! header-versioned `.twv`) for persistence.**
//!
//! # What this is
//!
//! - AEAD = ChaCha20-Poly1305 (IETF, 96-bit nonce) over a random **per-process
//!   key** generated on first use ([`IN_PROCESS`]); the key never leaves
//!   process memory and dies with the process.
//! - AAD = `b"tallow-credential-vault-v1" || name`, so a ciphertext can never be
//!   relabelled to another credential name and still decrypt.
//! - Ciphertext, nonce and key are zeroized on drop / delete / rotate.
//!
//! This replaces the former `(std::process::id() & 0xFF)` XOR "encryption",
//! which provided **no confidentiality at all** (the PID is public) and is
//! deleted with this change. Any AEAD under a process-local key is strictly
//! stronger; this module does not claim operator-passphrase custody.
//!
//! # Routing note (D3 step 7 / OQ-7)
//!
//! `CredentialVault.store` stays a **session cache** in V1. When the vault
//! database ([`super::db::VaultDatabase`]) is unlocked, persistent credential
//! storage belongs there; the follow-up (P1) is to back `store()` with the
//! unlocked vault DB (persistence-with-fallback, OQ-7). No `.tl` contract
//! change is needed for that: the [`store`]/[`get`]/[`delete`]/[`list`]/
//! [`rotate`] seam is this module.
//!
//! # Threat model (measured)
//!
//! Raises the bar for casual heap inspection: a dump of the stored map alone
//! does not disclose passwords (ciphertext only, key in a separate
//! zeroizing allocation). It does **not** protect against a same-process
//! attacker, a debugger, or a memory dump while a password is being returned
//! by [`get`] — the plaintext is inherently in memory at that point.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core_06::RngCore;
use zeroize::Zeroizing;

/// AAD domain prefix (stable; versioned).
pub const AAD_DOMAIN: &[u8] = b"tallow-credential-vault-v1";

/// AEAD nonce length in bytes (IETF ChaCha20-Poly1305).
pub const NONCE_LEN: usize = 12;

/// Errors from the credential cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialVaultError {
    /// No credential stored under that name.
    NotFound(String),
    /// AEAD authentication failed — tampered ciphertext/nonce/AAD, or wrong key.
    Integrity(String),
}

impl std::fmt::Display for CredentialVaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialVaultError::NotFound(name) => write!(f, "credential '{name}' not found"),
            CredentialVaultError::Integrity(msg) => {
                write!(f, "credential vault integrity check failed: {msg}")
            }
        }
    }
}

impl std::error::Error for CredentialVaultError {}

/// One stored credential: plaintext username + AEAD-sealed password.
///
/// The ciphertext/nonce are private and zero-wiped on drop, so no removal path
/// can leave sealed material behind.
pub struct CredentialEntry {
    /// Username (not secret; stored in clear, as on the `.tl` surface).
    pub username: String,
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl CredentialEntry {
    /// Zero-wipe the sealed material in place.
    fn wipe(&mut self) {
        self.nonce = [0u8; NONCE_LEN];
        for b in self.ciphertext.iter_mut() {
            *b = 0;
        }
    }
}

impl Drop for CredentialEntry {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl Clone for CredentialEntry {
    fn clone(&self) -> Self {
        CredentialEntry {
            username: self.username.clone(),
            nonce: self.nonce,
            ciphertext: self.ciphertext.clone(),
        }
    }
}

/// A decrypted credential, as returned by [`CredentialVault::get`].
///
/// The password is zeroized on drop.
pub struct Credential {
    /// Credential name (cache key).
    pub name: String,
    /// Username.
    pub username: String,
    /// Decrypted password — zeroized on drop.
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print secret material.
        f.debug_struct("Credential")
            .field("name", &self.name)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Volatile in-process credential cache: ChaCha20-Poly1305 over a random
/// per-process key. See the module docs for the honest label and threat model.
pub struct CredentialVault {
    key: Zeroizing<[u8; 32]>,
    entries: HashMap<String, CredentialEntry>,
}

impl std::fmt::Debug for CredentialVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialVault")
            .field("entries", &self.entries.len())
            .field("key", &"<redacted>")
            .finish()
    }
}

impl Default for CredentialVault {
    fn default() -> Self {
        Self::new()
    }
}

/// AAD for one credential: domain || name (name is bound, never stored in the
/// clear alongside the ciphertext in a way that would allow relabelling).
fn aad_for(name: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + name.len());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(name.as_bytes());
    aad
}

impl CredentialVault {
    /// New cache with a fresh random per-process key from the OS CSPRNG.
    pub fn new() -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut key[..]);
        CredentialVault {
            key,
            entries: HashMap::new(),
        }
    }

    /// Cache with an explicit key — for tests and key-rotation drills only.
    ///
    /// Prefer [`CredentialVault::new`]: an explicit key must never be derived
    /// from anything guessable (see the deleted PID derivation).
    pub fn with_key(key: [u8; 32]) -> Self {
        CredentialVault {
            key: Zeroizing::new(key),
            entries: HashMap::new(),
        }
    }

    /// Number of stored credentials.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Seal `password` under the per-process key and store it (replacing any
    /// previous entry for `name`, whose ciphertext is zero-wiped).
    pub fn store(
        &mut self,
        name: &str,
        username: &str,
        password: &str,
    ) -> Result<(), CredentialVaultError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key[..]));
        let nonce_ga = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&nonce_ga);

        let aad = aad_for(name);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: password.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| {
                CredentialVaultError::Integrity(format!("sealing failed for credential '{name}'"))
            })?;

        // Displaced entry (if any) is zero-wiped by its Drop impl.
        self.entries.insert(
            name.to_string(),
            CredentialEntry {
                username: username.to_string(),
                nonce,
                ciphertext,
            },
        );
        Ok(())
    }

    /// Decrypt the credential stored under `name`.
    ///
    /// On authentication failure this returns [`CredentialVaultError::Integrity`]
    /// — never a mangled string.
    pub fn get(&self, name: &str) -> Result<Credential, CredentialVaultError> {
        let entry = self
            .entries
            .get(name)
            .ok_or_else(|| CredentialVaultError::NotFound(name.to_string()))?;

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key[..]));
        let aad = aad_for(name);
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&entry.nonce),
                Payload {
                    msg: &entry.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                CredentialVaultError::Integrity(format!(
                    "authentication failed for credential '{name}' — tampered store or wrong key"
                ))
            })?;

        // The plaintext buffer is moved into the String, then into Zeroizing:
        // no extra copy of the secret is left unmanaged.
        let password = String::from_utf8(plaintext).map_err(|_| {
            CredentialVaultError::Integrity(format!(
                "decrypted credential '{name}' is not valid UTF-8"
            ))
        })?;

        Ok(Credential {
            name: name.to_string(),
            username: entry.username.clone(),
            password: Zeroizing::new(password),
        })
    }

    /// Remove a credential, zero-wiping its sealed material. Returns whether it
    /// existed.
    pub fn delete(&mut self, name: &str) -> bool {
        match self.entries.remove(name) {
            Some(mut entry) => {
                entry.wipe();
                true
            }
            None => false,
        }
    }

    /// Names of stored credentials (sorted; never password material).
    pub fn list(&self) -> Vec<String> {
        let mut names: Vec<String> = self.entries.keys().cloned().collect();
        names.sort();
        names
    }

    /// Re-seal `name` with `new_password` under a **fresh nonce**; the old
    /// ciphertext is zero-wiped first.
    pub fn rotate(&mut self, name: &str, new_password: &str) -> Result<(), CredentialVaultError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key[..]));
        let nonce_ga = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&nonce_ga);

        let aad = aad_for(name);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: new_password.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| {
                CredentialVaultError::Integrity(format!("re-sealing failed for credential '{name}'"))
            })?;

        let entry = self
            .entries
            .get_mut(name)
            .ok_or_else(|| CredentialVaultError::NotFound(name.to_string()))?;

        // Old sealed material is wiped before the new one is installed.
        entry.wipe();
        entry.nonce = nonce;
        entry.ciphertext = ciphertext;
        Ok(())
    }
}

/// The per-process credential cache (created on first use with a random key).
///
/// This is the `.tl` `CredentialVault` backing store.
pub static IN_PROCESS: LazyLock<Mutex<CredentialVault>> =
    LazyLock::new(|| Mutex::new(CredentialVault::new()));

/// Run `f` against the per-process cache (poison-tolerant).
fn with_vault<T>(f: impl FnOnce(&mut CredentialVault) -> T) -> T {
    let mut guard = IN_PROCESS.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut guard)
}

/// Store a credential in the per-process cache (see [`CredentialVault::store`]).
pub fn store(name: &str, username: &str, password: &str) -> Result<(), CredentialVaultError> {
    with_vault(|v| v.store(name, username, password))
}

/// Read a credential from the per-process cache (see [`CredentialVault::get`]).
pub fn get(name: &str) -> Result<Credential, CredentialVaultError> {
    with_vault(|v| v.get(name))
}

/// Delete a credential from the per-process cache; `true` if it existed.
pub fn delete(name: &str) -> bool {
    with_vault(|v| v.delete(name))
}

/// List credential names in the per-process cache (sorted).
pub fn list() -> Vec<String> {
    with_vault(|v| v.list())
}

/// Rotate a credential in the per-process cache (see [`CredentialVault::rotate`]).
pub fn rotate(name: &str, new_password: &str) -> Result<(), CredentialVaultError> {
    with_vault(|v| v.rotate(name, new_password))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault() -> CredentialVault {
        CredentialVault::new()
    }

    #[test]
    fn test_store_get_roundtrip() {
        let mut v = vault();
        v.store("acct", "admin", "s3cret!").unwrap();
        let c = v.get("acct").unwrap();
        assert_eq!(c.name, "acct");
        assert_eq!(c.username, "admin");
        assert_eq!(&*c.password, "s3cret!");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn test_get_missing_is_not_found() {
        let v = vault();
        let err = v.get("nope").unwrap_err();
        assert_eq!(err, CredentialVaultError::NotFound("nope".to_string()));
        assert_eq!(err.to_string(), "credential 'nope' not found");
    }

    #[test]
    fn test_ciphertext_does_not_contain_plaintext() {
        let mut v = vault();
        let marker = "MARKER-plaintext-should-not-appear";
        v.store("marker", "u", marker).unwrap();
        let entry = v.entries.get("marker").unwrap();
        assert!(
            !entry
                .ciphertext
                .windows(marker.len())
                .any(|w| w == marker.as_bytes()),
            "plaintext password bytes appear in the stored ciphertext"
        );
        // Nonce is random and 96-bit.
        assert_eq!(entry.nonce.len(), NONCE_LEN);
    }

    #[test]
    fn test_tampered_ciphertext_fails_closed() {
        let mut v = vault();
        v.store("t", "u", "pw").unwrap();
        v.entries.get_mut("t").unwrap().ciphertext[0] ^= 0x01;
        let err = v.get("t").unwrap_err();
        match err {
            CredentialVaultError::Integrity(_) => {}
            other => panic!("expected Integrity error, got {other:?}"),
        }
    }

    #[test]
    fn test_tampered_nonce_fails_closed() {
        let mut v = vault();
        v.store("t2", "u", "pw").unwrap();
        v.entries.get_mut("t2").unwrap().nonce[0] ^= 0xFF;
        assert!(matches!(
            v.get("t2").unwrap_err(),
            CredentialVaultError::Integrity(_)
        ));
    }

    #[test]
    fn test_wrong_key_fails_closed() {
        let mut a = CredentialVault::with_key([1u8; 32]);
        a.store("k", "u", "pw").unwrap();
        // Same sealed entry, different per-process key → authentication failure.
        let mut b = CredentialVault::with_key([2u8; 32]);
        b.entries = a.entries.clone();
        assert!(matches!(
            b.get("k").unwrap_err(),
            CredentialVaultError::Integrity(_)
        ));
    }

    #[test]
    fn test_aad_binds_credential_name() {
        let mut v = vault();
        v.store("real-name", "u", "pw").unwrap();
        // Relabel the sealed entry under another name: AAD mismatch → fail.
        let entry = v.entries.remove("real-name").unwrap();
        v.entries.insert("other-name".to_string(), entry);
        assert!(matches!(
            v.get("other-name").unwrap_err(),
            CredentialVaultError::Integrity(_)
        ));
    }

    #[test]
    fn test_delete_removes_and_zero_wipes() {
        let mut v = vault();
        v.store("d", "u", "pw").unwrap();
        assert!(!v.entries.get("d").unwrap().ciphertext.is_empty());

        assert!(v.delete("d"));
        assert!(!v.delete("d"), "second delete must report non-existence");
        assert!(!v.entries.contains_key("d"));
        assert!(matches!(
            v.get("d").unwrap_err(),
            CredentialVaultError::NotFound(_)
        ));

        // Observable wipe: the allocation that held the ciphertext is zeroed.
        let mut v2 = vault();
        v2.store("d2", "u", "pw").unwrap();
        let mut entry = v2.entries.remove("d2").unwrap();
        let ct_before = entry.ciphertext.clone();
        assert!(ct_before.iter().any(|b| *b != 0), "ciphertext must not be all-zero before wipe");
        entry.wipe();
        let wiped = std::mem::take(&mut entry.ciphertext);
        assert!(wiped.iter().all(|b| *b == 0), "ciphertext not zero-wiped");
        assert_eq!(entry.nonce, [0u8; NONCE_LEN], "nonce not zero-wiped");
    }

    #[test]
    fn test_rotate_reencrypts_with_fresh_nonce_and_new_password() {
        let mut v = vault();
        v.store("r", "admin", "oldpass").unwrap();
        let (old_nonce, old_ct) = {
            let e = v.entries.get("r").unwrap();
            (e.nonce, e.ciphertext.clone())
        };

        v.rotate("r", "newpass").unwrap();

        let e = v.entries.get("r").unwrap();
        assert_ne!(e.nonce, old_nonce, "rotate must use a fresh nonce");
        assert_ne!(e.ciphertext, old_ct, "rotate must re-seal the ciphertext");
        assert_eq!(&*v.get("r").unwrap().password, "newpass");
        assert_eq!(v.get("r").unwrap().username, "admin");
    }

    #[test]
    fn test_rotate_missing_is_not_found() {
        let mut v = vault();
        assert!(matches!(
            v.rotate("ghost", "pw").unwrap_err(),
            CredentialVaultError::NotFound(_)
        ));
    }

    #[test]
    fn test_list_is_sorted_and_leaks_nothing() {
        let mut v = vault();
        v.store("zeta", "u", "pw-one").unwrap();
        v.store("alpha", "u", "pw-two").unwrap();
        let names = v.list();
        assert_eq!(names, vec!["alpha".to_string(), "zeta".to_string()]);
        assert!(!names.iter().any(|n| n.contains("pw-")));
    }

    #[test]
    fn test_instances_have_distinct_random_keys() {
        let a = CredentialVault::new();
        let b = CredentialVault::new();
        assert_ne!(&a.key[..], &b.key[..], "per-process keys must be random");
        assert_ne!(&a.key[..], &[0u8; 32][..], "key must not be a constant");
    }

    #[test]
    fn test_module_source_has_no_pid_derivation() {
        // Regression gate for FIX-9: the old construction derived "encryption"
        // from `(std::process::id() & 0xFF)`. It must never come back here.
        // The check is comment-aware: prose may *name* the removed construction;
        // production code may not reference it.
        let src = include_str!("credential.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        let code: String = prod
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains("process::id()"),
            "credential.rs production code must not reference the process id"
        );
        assert!(prod.contains("ChaCha20Poly1305"));
        assert!(prod.contains("tallow-credential-vault-v1"));
    }

    #[test]
    fn test_global_helpers_roundtrip() {
        // The seam the `.tl` CredentialVault surface calls into.
        assert!(store("w2_cred_global", "u", "pw").is_ok());
        let c = get("w2_cred_global").unwrap();
        assert_eq!(&*c.password, "pw");
        assert!(list().contains(&"w2_cred_global".to_string()));
        assert!(rotate("w2_cred_global", "pw2").is_ok());
        assert_eq!(&*get("w2_cred_global").unwrap().password, "pw2");
        assert!(delete("w2_cred_global"));
        assert!(matches!(
            get("w2_cred_global").unwrap_err(),
            CredentialVaultError::NotFound(_)
        ));
    }

    #[test]
    fn test_store_is_not_deterministic_across_nonces() {
        // Fresh nonce per store: sealing the same secret twice must not repeat
        // the ciphertext (would be the XOR-with-PID signature).
        let mut v = vault();
        v.store("n1", "u", "same-pw").unwrap();
        v.store("n2", "u", "same-pw").unwrap();
        let c1 = v.entries.get("n1").unwrap().ciphertext.clone();
        let c2 = v.entries.get("n2").unwrap().ciphertext.clone();
        assert_ne!(c1, c2, "same plaintext must not seal to identical bytes");
    }
}
