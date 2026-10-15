//! SSH Agent — load Ed25519/RSA keys from vault, serve for SSH authentication.
//! Implements a subset of the SSH agent protocol (RFC 4253).

use super::entry::{EntryData, SSHKeyData, VaultEntry};
use serde::{Deserialize, Serialize};

// ── Hex Utilities ───────────────────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex string must have even length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at position {i}: {e}"))
        })
        .collect()
}

// ── SSH Key Blob Encoding ───────────────────────────────────────────────────

/// Encode an SSH string/bytes as length-prefixed (u32 big-endian + payload).
fn ssh_string(data: &[u8]) -> Vec<u8> {
    let len = (data.len() as u32).to_be_bytes();
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&len);
    out.extend_from_slice(data);
    out
}

/// Build the SSH public key blob for Ed25519: length-prefixed "ssh-ed25519" + length-prefixed pk.
fn ed25519_public_key_blob(public_key_bytes: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(&ssh_string(b"ssh-ed25519"));
    blob.extend_from_slice(&ssh_string(public_key_bytes));
    blob
}

// ── Public API Types ────────────────────────────────────────────────────────

/// SSH key loaded into the agent.
#[derive(Clone, Serialize, Deserialize)]
pub struct AgentKey {
    pub id: String,
    pub name: String,
    pub key_type: String,
    pub fingerprint: String,
    pub public_key: String,
    pub private_key: String, // Only held in memory while agent is running
    pub require_confirmation: bool,
    pub lifetime_seconds: Option<u32>,
    pub loaded_at: String,
}
impl std::fmt::Debug for AgentKey {
    /// Hand-written: `private_key` is redacted (A6.1.1 sweep).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentKey")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("key_type", &self.key_type)
            .field("fingerprint", &self.fingerprint)
            .field("public_key", &self.public_key)
            .field("private_key", &"[redacted]")
            .field("require_confirmation", &self.require_confirmation)
            .field("lifetime_seconds", &self.lifetime_seconds)
            .field("loaded_at", &self.loaded_at)
            .finish()
    }
}

impl Drop for AgentKey {
    /// Zeroize-on-drop (A6.1.1 sweep): the private key is wiped.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.private_key.zeroize();
    }
}

/// Agent state.
pub struct SSHAgent {
    pub keys: Vec<AgentKey>,
    pub locked: bool,
    /// Fingerprints whose `require_confirmation` keys have been explicitly
    /// approved for this agent session (see `approve_key`).
    pub approved_fingerprints: Vec<String>,
}

// ── SSHAgent Implementation ─────────────────────────────────────────────────

impl SSHAgent {
    /// Create an empty agent.
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            locked: false,
            approved_fingerprints: Vec::new(),
        }
    }

    /// Scan vault entries for SSHKey entries and load them into a new agent.
    pub fn load_from_vault(entries: &[VaultEntry]) -> Self {
        let mut agent = Self::new();
        for entry in entries {
            if let EntryData::SSHKey(ssh) = &entry.data {
                let key = AgentKey {
                    id: entry.id.clone(),
                    name: entry.name.clone(),
                    key_type: ssh.key_type.clone(),
                    fingerprint: ssh.fingerprint.clone(),
                    public_key: ssh.public_key.clone(),
                    private_key: ssh.private_key.clone(),
                    require_confirmation: false,
                    lifetime_seconds: None,
                    loaded_at: chrono::Utc::now().to_rfc3339(),
                };
                agent.keys.push(key);
            }
        }
        agent
    }

    /// Add a key to the agent.
    pub fn add_key(&mut self, key: AgentKey) {
        self.keys.push(key);
    }

    /// Remove a key by ID. Returns true if a key was removed.
    pub fn remove_key(&mut self, id: &str) -> bool {
        let before = self.keys.len();
        self.keys.retain(|k| k.id != id);
        self.keys.len() < before
    }

    /// List all loaded keys.
    pub fn list_keys(&self) -> Vec<&AgentKey> {
        self.keys.iter().collect()
    }

    /// Find a key by fingerprint.
    pub fn find_key(&self, fingerprint: &str) -> Option<&AgentKey> {
        self.keys.iter().find(|k| k.fingerprint == fingerprint)
    }

    /// Lock the agent — refuse signing until unlocked.
    pub fn lock(&mut self) {
        self.locked = true;
    }

    /// Unlock the agent.
    pub fn unlock(&mut self) {
        self.locked = false;
    }

    /// Mark a `require_confirmation` key as approved for this agent session.
    /// Without this, `sign_data` refuses to sign with confirmation-required keys.
    pub fn approve_key(&mut self, fingerprint: &str) {
        if !self.approved_fingerprints.iter().any(|f| f == fingerprint) {
            self.approved_fingerprints.push(fingerprint.to_string());
        }
    }

    /// Revoke a previously approved key (next `sign_data` requires re-approval).
    pub fn revoke_approval(&mut self, fingerprint: &str) {
        self.approved_fingerprints.retain(|f| f != fingerprint);
    }

    /// Enable or disable per-sign confirmation for a loaded key.
    pub fn set_confirmation(&mut self, fingerprint: &str, require: bool) -> Result<(), String> {
        let key = self
            .keys
            .iter_mut()
            .find(|k| k.fingerprint == fingerprint)
            .ok_or_else(|| format!("no key with fingerprint {fingerprint}"))?;
        key.require_confirmation = require;
        if !require {
            self.revoke_approval(fingerprint);
        }
        Ok(())
    }

    /// Set (or clear, with `None`) the signing lifetime for a loaded key.
    pub fn set_lifetime(&mut self, fingerprint: &str, lifetime_seconds: Option<u32>) -> Result<(), String> {
        let key = self
            .keys
            .iter_mut()
            .find(|k| k.fingerprint == fingerprint)
            .ok_or_else(|| format!("no key with fingerprint {fingerprint}"))?;
        key.lifetime_seconds = lifetime_seconds;
        key.loaded_at = chrono::Utc::now().to_rfc3339(); // lifetime counts from now
        Ok(())
    }

    /// Sign data with a loaded key identified by fingerprint.
    /// Returns the raw signature bytes.
    ///
    /// ENFORCEMENT (previously stored-but-ignored):
    ///   * If the key has `require_confirmation` set, signing is refused
    ///     unless the key was explicitly approved via `approve_key` in this
    ///     agent session.
    ///   * If the key has a `lifetime_seconds`, signing is refused once the
    ///     lifetime has elapsed since `loaded_at`.
    pub fn sign_data(&self, fingerprint: &str, data: &[u8]) -> Result<Vec<u8>, String> {
        if self.locked {
            return Err("agent is locked".into());
        }
        let key = self
            .find_key(fingerprint)
            .ok_or_else(|| format!("no key with fingerprint {fingerprint}"))?;

        // Enforce require_confirmation: no signing without explicit approval.
        if key.require_confirmation && !self.approved_fingerprints.iter().any(|f| f == fingerprint) {
            return Err(format!(
                "key {fingerprint} requires confirmation — call approve_key() before signing"
            ));
        }

        // Enforce lifetime: refuse to sign with an expired key.
        if let Some(lifetime) = key.lifetime_seconds {
            if let Ok(loaded) = chrono::DateTime::parse_from_rfc3339(&key.loaded_at) {
                let expiry = loaded + chrono::Duration::seconds(lifetime as i64);
                if chrono::Utc::now() > expiry {
                    return Err(format!(
                        "key {fingerprint} has expired (lifetime {lifetime}s elapsed since {} — revoke and re-add the key to reset)",
                        key.loaded_at
                    ));
                }
            }
        }

        match key.key_type.as_str() {
            "ssh-ed25519" | "ed25519" => {
                use ed25519_dalek::{Signer, SigningKey};

                let sk_bytes_vec = hex_decode(&key.private_key)?;
                if sk_bytes_vec.len() != 32 {
                    return Err(format!(
                        "ed25519 private key must be 32 bytes, got {}",
                        sk_bytes_vec.len()
                    ));
                }
                let mut sk_bytes = [0u8; 32];
                sk_bytes.copy_from_slice(&sk_bytes_vec);
                let sk = SigningKey::from_bytes(&sk_bytes);
                let sig = sk.sign(data);
                Ok(sig.to_bytes().to_vec())
            }
            other => Err(format!(
                "unsupported key type for signing: {other} (only ed25519 supported)"
            )),
        }
    }
}

// ── Standalone Functions ────────────────────────────────────────────────────

/// Generate a new Ed25519 SSH key pair. Returns SSHKeyData ready for vault storage.
pub fn generate_ed25519_keypair() -> Result<SSHKeyData, String> {
    use ed25519_dalek::SigningKey;

    let sk = SigningKey::generate(&mut rand_core_06::OsRng);
    let pk = sk.verifying_key();

    let pk_bytes = pk.as_bytes();
    let fingerprint = ssh_fingerprint(pk_bytes);
    let public_key_hex = hex_encode(pk_bytes);
    let private_key_hex = hex_encode(&sk.to_bytes());

    Ok(SSHKeyData {
        private_key: private_key_hex,
        public_key: public_key_hex,
        fingerprint,
        key_type: "ssh-ed25519".to_string(),
        comment: None,
    })
}

/// Generate a new Ed25519 key pair and return the raw bytes.
///
/// Returns `(secret_key_bytes, public_key_bytes)` where both are 32-byte
/// little-endian representations used by `ed25519-dalek`.
///
/// Use this when you need raw key material rather than a full `SSHKeyData`
/// struct — for example, when building custom key exchange or signing
/// protocols.
///
/// # Example
/// ```rust,no_run
/// let (secret, public) = generate_ed25519_key().unwrap();
/// assert_eq!(secret.len(), 32);
/// assert_eq!(public.len(), 32);
/// ```
pub fn generate_ed25519_key() -> Result<(Vec<u8>, Vec<u8>), String> {
    use ed25519_dalek::SigningKey;

    let signing_key = SigningKey::generate(&mut rand_core_06::OsRng);
    let secret = signing_key.to_bytes().to_vec();
    let public = signing_key.verifying_key().to_bytes().to_vec();
    Ok((secret, public))
}

/// Compute the SHA-256 fingerprint of an SSH public key in the standard format.
/// Input: raw public key bytes (32 bytes for Ed25519).
/// Output: "SHA256:<base64-no-pad>" (matches `ssh-keygen -l` output).
pub fn ssh_fingerprint(public_key_bytes: &[u8]) -> String {
    use sha2::Digest;
    // Build the SSH public key blob (key-type-string + key-data)
    let blob = ed25519_public_key_blob(public_key_bytes);
    let hash = sha2::Sha256::digest(&blob);
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        hash,
    );
    format!("SHA256:{encoded}")
}

/// Format a public key in OpenSSH authorized_keys format.
/// Example: `ssh-ed25519 AAAA...base64... user@host`
pub fn format_public_key_openssh(key_type: &str, public_key_bytes: &[u8], comment: &str) -> String {
    let blob = ed25519_public_key_blob(public_key_bytes);
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &blob,
    );
    format!("{key_type} {encoded} {comment}")
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::entry::VaultEntry;

    /// Generate a keypair and verify the SSHKeyData fields are well-formed.
    #[test]
    fn test_keygen() {
        let kd = generate_ed25519_keypair().unwrap();
        assert_eq!(kd.key_type, "ssh-ed25519");
        assert!(kd.fingerprint.starts_with("SHA256:"));
        // Ed25519 private key = 32 bytes = 64 hex chars
        assert_eq!(kd.private_key.len(), 64);
        // Ed25519 public key = 32 bytes = 64 hex chars
        assert_eq!(kd.public_key.len(), 64);
    }

    /// Load SSH keys from vault entries; non-SSH entries are ignored.
    #[test]
    fn test_load_from_vault() {
        let kd = generate_ed25519_keypair().unwrap();
        let ssh_entry = VaultEntry::new_ssh_key(
            "my-server",
            &kd.private_key,
            &kd.public_key,
            &kd.fingerprint,
            &kd.key_type,
        );
        let login_entry = VaultEntry::new_login("GitHub", "user", "pass", vec![]);

        let agent = SSHAgent::load_from_vault(&[ssh_entry.clone(), login_entry]);
        assert_eq!(agent.keys.len(), 1);
        assert_eq!(agent.keys[0].name, "my-server");
        assert_eq!(agent.keys[0].fingerprint, kd.fingerprint);
    }

    /// Sign data and verify with ed25519-dalek.
    #[test]
    fn test_sign_and_verify() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let kd = generate_ed25519_keypair().unwrap();
        let entry = VaultEntry::new_ssh_key(
            "sign-test",
            &kd.private_key,
            &kd.public_key,
            &kd.fingerprint,
            &kd.key_type,
        );
        let agent = SSHAgent::load_from_vault(&[entry]);

        let data = b"hello, SSH agent!";
        let sig_bytes = agent.sign_data(&kd.fingerprint, data).unwrap();
        assert_eq!(sig_bytes.len(), 64); // Ed25519 signature = 64 bytes

        // Verify with the public key
        let pk_bytes = hex_decode(&kd.public_key).unwrap();
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);
        let vk = VerifyingKey::from_bytes(&pk_arr).unwrap();
        let sig = Signature::from_bytes(&sig_bytes.try_into().unwrap());
        assert!(vk.verify(data, &sig).is_ok());
    }

    /// Fingerprint is deterministic for the same key bytes.
    #[test]
    fn test_fingerprint_deterministic() {
        let pk_bytes = [0xABu8; 32];
        let fp1 = ssh_fingerprint(&pk_bytes);
        let fp2 = ssh_fingerprint(&pk_bytes);
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("SHA256:"));
    }

    /// Lock prevents signing; unlock restores it.
    #[test]
    fn test_lock_unlock() {
        let kd = generate_ed25519_keypair().unwrap();
        let entry = VaultEntry::new_ssh_key(
            "lock-test",
            &kd.private_key,
            &kd.public_key,
            &kd.fingerprint,
            &kd.key_type,
        );
        let mut agent = SSHAgent::load_from_vault(&[entry]);

        // Signing works while unlocked
        assert!(agent.sign_data(&kd.fingerprint, b"data").is_ok());

        // Lock -> signing fails
        agent.lock();
        assert!(agent.locked);
        let err = agent.sign_data(&kd.fingerprint, b"data").unwrap_err();
        assert!(err.contains("locked"));

        // Unlock -> signing works again
        agent.unlock();
        assert!(!agent.locked);
        assert!(agent.sign_data(&kd.fingerprint, b"data").is_ok());
    }

    /// List, add, remove, and find keys.
    #[test]
    fn test_list_add_remove_find() {
        let mut agent = SSHAgent::new();
        assert!(agent.list_keys().is_empty());

        let kd1 = generate_ed25519_keypair().unwrap();
        let kd2 = generate_ed25519_keypair().unwrap();

        agent.add_key(AgentKey {
            id: "key-1".into(),
            name: "first".into(),
            key_type: kd1.key_type.clone(),
            fingerprint: kd1.fingerprint.clone(),
            public_key: kd1.public_key.clone(),
            private_key: kd1.private_key.clone(),
            require_confirmation: false,
            lifetime_seconds: None,
            loaded_at: chrono::Utc::now().to_rfc3339(),
        });
        agent.add_key(AgentKey {
            id: "key-2".into(),
            name: "second".into(),
            key_type: kd2.key_type.clone(),
            fingerprint: kd2.fingerprint.clone(),
            public_key: kd2.public_key.clone(),
            private_key: kd2.private_key.clone(),
            require_confirmation: false,
            lifetime_seconds: Some(3600),
            loaded_at: chrono::Utc::now().to_rfc3339(),
        });

        assert_eq!(agent.list_keys().len(), 2);

        // Find by fingerprint
        let found = agent.find_key(&kd1.fingerprint);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "first");

        // Remove by ID
        assert!(agent.remove_key("key-1"));
        assert_eq!(agent.list_keys().len(), 1);
        assert!(agent.find_key(&kd1.fingerprint).is_none());

        // Removing non-existent returns false
        assert!(!agent.remove_key("key-999"));
    }

    /// OpenSSH public key format contains key type and base64 blob.
    #[test]
    fn test_format_public_key_openssh() {
        let kd = generate_ed25519_keypair().unwrap();
        let pk_bytes = hex_decode(&kd.public_key).unwrap();
        let line = format_public_key_openssh("ssh-ed25519", &pk_bytes, "test@host");
        assert!(line.starts_with("ssh-ed25519 "));
        assert!(line.ends_with(" test@host"));
        // The middle part is valid base64
        let parts: Vec<&str> = line.split(' ').collect();
        assert_eq!(parts.len(), 3);
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            parts[1],
        );
        assert!(decoded.is_ok());
    }

    /// require_confirmation keys refuse to sign until explicitly approved.
    #[test]
    fn test_confirmation_required_enforced() {
        let kd = generate_ed25519_keypair().unwrap();
        let entry = VaultEntry::new_ssh_key(
            "confirm-test",
            &kd.private_key,
            &kd.public_key,
            &kd.fingerprint,
            &kd.key_type,
        );
        let mut agent = SSHAgent::load_from_vault(&[entry]);
        agent.set_confirmation(&kd.fingerprint, true).unwrap();

        // Without approval -> refusal (previously this signed silently)
        let err = agent.sign_data(&kd.fingerprint, b"data").unwrap_err();
        assert!(
            err.contains("confirmation"),
            "error should mention confirmation: {err}"
        );

        // After approval -> signing works
        agent.approve_key(&kd.fingerprint);
        assert!(agent.sign_data(&kd.fingerprint, b"data").is_ok());

        // Revoking approval blocks again
        agent.revoke_approval(&kd.fingerprint);
        let err = agent.sign_data(&kd.fingerprint, b"data").unwrap_err();
        assert!(err.contains("confirmation"));
    }

    /// lifetime_seconds keys refuse to sign after the lifetime elapses.
    #[test]
    fn test_lifetime_expiry_enforced() {
        let kd = generate_ed25519_keypair().unwrap();
        let entry = VaultEntry::new_ssh_key(
            "lifetime-test",
            &kd.private_key,
            &kd.public_key,
            &kd.fingerprint,
            &kd.key_type,
        );
        let mut agent = SSHAgent::load_from_vault(&[entry]);
        agent.set_lifetime(&kd.fingerprint, Some(3600)).unwrap();

        // Fresh key signs fine
        assert!(agent.sign_data(&kd.fingerprint, b"data").is_ok());

        // Backdate loaded_at to force expiry -> signing must refuse
        let key = agent
            .keys
            .iter_mut()
            .find(|k| k.fingerprint == kd.fingerprint)
            .unwrap();
        key.loaded_at = "2020-01-01T00:00:00Z".to_string();
        let err = agent.sign_data(&kd.fingerprint, b"data").unwrap_err();
        assert!(err.contains("expired"), "error should mention expired: {err}");
    }

    /// Keys without confirmation or lifetime keep signing (unchanged behavior).
    #[test]
    fn test_no_confirmation_no_lifetime_still_signs() {
        let kd = generate_ed25519_keypair().unwrap();
        let entry = VaultEntry::new_ssh_key(
            "plain-test",
            &kd.private_key,
            &kd.public_key,
            &kd.fingerprint,
            &kd.key_type,
        );
        let agent = SSHAgent::load_from_vault(&[entry]);
        assert!(agent.sign_data(&kd.fingerprint, b"data").is_ok());
    }

    #[test]
    fn agent_key_debug_redacts_private_key() {
        let key = AgentKey {
            id: "k1".to_string(),
            name: "prod".to_string(),
            key_type: "ed25519".to_string(),
            fingerprint: "SHA256:x".to_string(),
            public_key: "ssh-ed25519 AAAA".to_string(),
            private_key: "PRIVKEY-SUPERSECRET".to_string(),
            require_confirmation: false,
            lifetime_seconds: None,
            loaded_at: "2026-09-11T00:00:00Z".to_string(),
        };
        let dbg = format!("{key:?}");
        assert!(dbg.contains("[redacted]"), "{dbg}");
        assert!(!dbg.contains("PRIVKEY-SUPERSECRET"), "{dbg}");
    }
}
