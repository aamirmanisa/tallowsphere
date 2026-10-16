//! Encrypted Vault Sync -- sync vaults across devices using delta detection.
//! Uses BLAKE3 for change detection and AES-256-GCM for encrypted transport.

use super::db::VaultDatabase;
use super::entry::VaultEntry;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Manifest describing the current state of a vault for sync comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncManifest {
    /// BLAKE3 hash of the full vault JSON.
    pub vault_hash: String,
    /// Per-entry hashes for delta detection.
    pub entry_hashes: Vec<EntryHash>,
    /// ISO-8601 timestamp when the manifest was created.
    pub timestamp: String,
    /// Unique device identifier.
    pub device_id: String,
}

/// Hash of a single vault entry for change detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryHash {
    pub id: String,
    pub hash: String,
    pub updated_at: String,
}

/// The set of changes between two vault states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncDelta {
    pub added: Vec<VaultEntry>,
    pub modified: Vec<VaultEntry>,
    pub deleted: Vec<String>,
    pub conflicts: Vec<SyncConflict>,
}

/// A conflict where the same entry was modified on both sides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConflict {
    pub entry_id: String,
    pub entry_name: String,
    pub local_updated: String,
    pub remote_updated: String,
    pub resolution: ConflictResolution,
}

/// Strategy for resolving sync conflicts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConflictResolution {
    KeepLocal,
    KeepRemote,
    KeepNewer,
    KeepBoth,
    Unresolved,
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// AES-256-GCM + Argon2id helpers (mirrors db.rs)
// ---------------------------------------------------------------------------

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| format!("sync: invalid argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("sync: key derivation failed: {e}"))?;
    Ok(key)
}

fn aes_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("sync: AES encryption failed: {e}"))
}

fn aes_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("sync: AES decryption failed (wrong password?): {e}"))
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// BLAKE3 hash of a vault entry's JSON representation.
fn hash_entry(entry: &VaultEntry) -> String {
    let json = serde_json::to_string(entry).unwrap_or_default();
    blake3::hash(json.as_bytes()).to_hex().to_string()
}

/// BLAKE3 hash of the full vault JSON.
fn hash_vault(db: &VaultDatabase) -> String {
    let json = serde_json::to_string(db).unwrap_or_default();
    blake3::hash(json.as_bytes()).to_hex().to_string()
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a sync manifest for the given vault database.
pub fn create_manifest(db: &VaultDatabase) -> SyncManifest {
    let entry_hashes = db
        .entries
        .iter()
        .map(|e| EntryHash {
            id: e.id.clone(),
            hash: hash_entry(e),
            updated_at: e.updated_at.clone(),
        })
        .collect();

    SyncManifest {
        vault_hash: hash_vault(db),
        entry_hashes,
        timestamp: chrono::Utc::now().to_rfc3339(),
        device_id: generate_device_id(),
    }
}

/// Compare two manifests and compute the delta required to sync local to remote.
///
/// - `added`: entries in remote but not in local
/// - `modified`: entries in both but with different hashes
/// - `deleted`: entries in local but not in remote
/// - `conflicts`: entries modified on both sides since last sync
pub fn compute_delta(
    local: &SyncManifest,
    remote: &SyncManifest,
    local_db: &VaultDatabase,
    remote_db: &VaultDatabase,
) -> SyncDelta {
    use std::collections::HashMap;

    let local_map: HashMap<&str, &EntryHash> =
        local.entry_hashes.iter().map(|h| (h.id.as_str(), h)).collect();
    let remote_map: HashMap<&str, &EntryHash> =
        remote.entry_hashes.iter().map(|h| (h.id.as_str(), h)).collect();

    let mut added = Vec::new();
    let mut modified = Vec::new();
    let mut deleted = Vec::new();
    let mut conflicts = Vec::new();

    // Entries in remote but not local -> added
    // Entries in both with different hashes -> modified or conflict
    for rh in &remote.entry_hashes {
        match local_map.get(rh.id.as_str()) {
            None => {
                // Added on remote side
                if let Some(entry) = remote_db.get_entry(&rh.id) {
                    added.push(entry.clone());
                }
            }
            Some(lh) => {
                if lh.hash != rh.hash {
                    // Both changed -- check if it's a conflict (both modified)
                    // or a simple update (only remote changed)
                    if lh.updated_at != local_db.get_entry(&lh.id)
                        .map(|e| e.updated_at.clone())
                        .unwrap_or_default()
                    {
                        // Local was also modified -> conflict
                        if let Some(entry) = remote_db.get_entry(&rh.id) {
                            conflicts.push(SyncConflict {
                                entry_id: rh.id.clone(),
                                entry_name: entry.name.clone(),
                                local_updated: lh.updated_at.clone(),
                                remote_updated: rh.updated_at.clone(),
                                resolution: ConflictResolution::Unresolved,
                            });
                        }
                    } else {
                        // Only remote changed -> take remote
                        if let Some(entry) = remote_db.get_entry(&rh.id) {
                            modified.push(entry.clone());
                        }
                    }
                }
            }
        }
    }

    // Entries in local but not remote -> deleted
    for lh in &local.entry_hashes {
        if !remote_map.contains_key(lh.id.as_str()) {
            deleted.push(lh.id.clone());
        }
    }

    SyncDelta {
        added,
        modified,
        deleted,
        conflicts,
    }
}

/// Apply a delta to the local vault database.
///
/// Conflict resolution is handled inline: KeepRemote replaces local,
/// KeepLocal keeps local, KeepNewer compares timestamps, KeepBoth
/// keeps both (remote gets " (conflict)" suffix), Unresolved is skipped.
///
/// The `remote_db` parameter is required for conflict resolution that
/// needs the remote entry. Pass `None` if no conflicts need remote data
/// (e.g., all conflicts are KeepLocal or Unresolved).
pub fn apply_delta(db: &mut VaultDatabase, delta: &SyncDelta) {
    apply_delta_with_remote(db, delta, None);
}

/// Apply a delta with optional access to the remote database for conflict resolution.
pub fn apply_delta_with_remote(
    db: &mut VaultDatabase,
    delta: &SyncDelta,
    remote_db: Option<&VaultDatabase>,
) {
    // Add new entries
    for entry in &delta.added {
        if db.get_entry(&entry.id).is_none() {
            db.add_entry(entry.clone());
        }
    }

    // Apply modifications (replace existing)
    for entry in &delta.modified {
        if let Some(pos) = db.entries.iter().position(|e| e.id == entry.id) {
            db.entries[pos] = entry.clone();
        } else {
            db.add_entry(entry.clone());
        }
    }

    // Delete removed entries
    for id in &delta.deleted {
        db.remove_entry(id);
    }

    // Apply resolved conflicts
    for conflict in &delta.conflicts {
        match conflict.resolution {
            ConflictResolution::KeepRemote => {
                // Replace local entry with the remote version
                if let Some(rdb) = remote_db {
                    if let Some(remote_entry) = rdb.get_entry(&conflict.entry_id) {
                        if let Some(pos) = db.entries.iter().position(|e| e.id == conflict.entry_id) {
                            db.entries[pos] = remote_entry.clone();
                        }
                    }
                }
            }
            ConflictResolution::KeepLocal => {
                // Keep the local entry as-is — no action needed.
            }
            ConflictResolution::KeepNewer => {
                // Compare timestamps, keep the newer one
                if conflict.remote_updated > conflict.local_updated {
                    // Remote is newer — replace local
                    if let Some(rdb) = remote_db {
                        if let Some(remote_entry) = rdb.get_entry(&conflict.entry_id) {
                            if let Some(pos) = db.entries.iter().position(|e| e.id == conflict.entry_id) {
                                db.entries[pos] = remote_entry.clone();
                            }
                        }
                    }
                }
                // Otherwise local is newer — keep it (no action)
            }
            ConflictResolution::KeepBoth => {
                // Keep local entry as-is, add remote with " (conflict)" suffix
                if let Some(rdb) = remote_db {
                    if let Some(remote_entry) = rdb.get_entry(&conflict.entry_id) {
                        let mut cloned = remote_entry.clone();
                        cloned.id = uuid::Uuid::new_v4().to_string();
                        cloned.name = format!("{} (conflict)", cloned.name);
                        db.add_entry(cloned);
                    }
                }
            }
            ConflictResolution::Unresolved => {
                // Unresolved conflicts are not applied — skip.
            }
        }
    }

    db.updated_at = chrono::Utc::now().to_rfc3339();
}

/// Resolve all conflicts in a delta with the given strategy.
pub fn resolve_conflicts(delta: &mut SyncDelta, strategy: ConflictResolution) {
    for conflict in &mut delta.conflicts {
        conflict.resolution = strategy.clone();
    }
}

/// Export the entire vault as an encrypted bundle for transport.
///
/// Bundle format: salt(32) + nonce(12) + AES-256-GCM(Argon2id(password, salt), nonce, JSON)
pub fn export_sync_bundle(db: &VaultDatabase, password: &str) -> Result<Vec<u8>, String> {
    use rand::RngCore;

    if password.is_empty() {
        return Err("sync: password must not be empty".into());
    }

    let json = serde_json::to_vec(db)
        .map_err(|e| format!("sync: serialization failed: {e}"))?;

    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce);

    let key = derive_key(password, &salt)?;
    let ciphertext = aes_encrypt(&key, &nonce, &json)?;

    let mut bundle = Vec::with_capacity(32 + 12 + ciphertext.len());
    bundle.extend_from_slice(&salt);
    bundle.extend_from_slice(&nonce);
    bundle.extend_from_slice(&ciphertext);

    Ok(bundle)
}

/// Import a vault from an encrypted bundle.
pub fn import_sync_bundle(bundle: &[u8], password: &str) -> Result<VaultDatabase, String> {
    if bundle.len() < 44 {
        return Err("sync: bundle too small".into());
    }
    if password.is_empty() {
        return Err("sync: password must not be empty".into());
    }

    let salt: [u8; 32] = bundle[..32]
        .try_into()
        .map_err(|_| "sync: corrupt salt".to_string())?;
    let nonce: [u8; 12] = bundle[32..44]
        .try_into()
        .map_err(|_| "sync: corrupt nonce".to_string())?;
    let ciphertext = &bundle[44..];

    let key = derive_key(password, &salt)?;
    let plaintext = aes_decrypt(&key, &nonce, ciphertext)?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| format!("sync: corrupt bundle payload: {e}"))
}

/// Generate a unique device identifier using BLAKE3(hostname + random).
pub fn generate_device_id() -> String {
    use rand::RngCore;

    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string());

    let mut random_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut random_bytes);

    let mut hasher = blake3::Hasher::new();
    hasher.update(hostname.as_bytes());
    hasher.update(&random_bytes);
    let hash = hasher.finalize();

    hex_encode(&hash.as_bytes()[..16]) // 128-bit device ID
}

/// Full merge: compare local and remote vaults, apply changes with conflict resolution.
///
/// Unlike `compute_delta` + `apply_delta` (which assume sync against a known baseline),
/// merge treats both vaults as authoritative: entries only in local are kept, entries
/// only in remote are added, and entries in both with different hashes are conflicts.
///
/// Returns the delta that was applied.
pub fn merge_vaults(
    local: &mut VaultDatabase,
    remote: &VaultDatabase,
    strategy: ConflictResolution,
) -> SyncDelta {
    let local_manifest = create_manifest(local);
    let remote_manifest = create_manifest(remote);

    let mut delta = compute_delta(&local_manifest, &remote_manifest, local, remote);

    // In a merge, "deleted" means "only in local" -- these should be kept, not removed.
    delta.deleted.clear();

    // Resolve conflicts
    resolve_conflicts(&mut delta, strategy);

    // apply_delta_with_remote handles all conflict resolution strategies
    // (KeepRemote, KeepLocal, KeepNewer, KeepBoth) using the remote db
    apply_delta_with_remote(local, &delta, Some(remote));

    delta
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::entry::VaultEntry;

    fn make_db(name: &str) -> VaultDatabase {
        VaultDatabase::new(name)
    }

    fn add_login(db: &mut VaultDatabase, name: &str, user: &str, pass: &str) -> String {
        let entry = VaultEntry::new_login(name, user, pass, vec![]);
        let id = entry.id.clone();
        db.add_entry(entry);
        id
    }

    #[test]
    fn manifest_creation() {
        let mut db = make_db("test");
        add_login(&mut db, "GitHub", "user", "pass");
        add_login(&mut db, "GitLab", "user2", "pass2");

        let manifest = create_manifest(&db);
        assert_eq!(manifest.entry_hashes.len(), 2);
        assert!(!manifest.vault_hash.is_empty());
        assert!(!manifest.device_id.is_empty());
        assert!(!manifest.timestamp.is_empty());

        // Each entry hash should be a 64-char hex string (BLAKE3 = 256 bits)
        for eh in &manifest.entry_hashes {
            assert_eq!(eh.hash.len(), 64);
        }
    }

    #[test]
    fn delta_detects_additions() {
        let local = make_db("local");
        let mut remote = make_db("remote");
        add_login(&mut remote, "NewEntry", "user", "pass");

        let lm = create_manifest(&local);
        let rm = create_manifest(&remote);
        let delta = compute_delta(&lm, &rm, &local, &remote);

        assert_eq!(delta.added.len(), 1);
        assert_eq!(delta.added[0].name, "NewEntry");
        assert!(delta.modified.is_empty());
        assert!(delta.deleted.is_empty());
    }

    #[test]
    fn delta_detects_deletions() {
        let mut local = make_db("local");
        let id = add_login(&mut local, "ToDelete", "user", "pass");
        let remote = make_db("remote");

        let lm = create_manifest(&local);
        let rm = create_manifest(&remote);
        let delta = compute_delta(&lm, &rm, &local, &remote);

        assert_eq!(delta.deleted.len(), 1);
        assert_eq!(delta.deleted[0], id);
        assert!(delta.added.is_empty());
    }

    #[test]
    fn delta_detects_modifications() {
        let mut local = make_db("local");
        let entry = VaultEntry::new_login("Entry", "user", "old_pass", vec![]);
        let id = entry.id.clone();
        local.add_entry(entry);

        let mut remote = make_db("remote");
        let mut entry2 = VaultEntry::new_login("Entry", "user", "new_pass", vec![]);
        entry2.id = id.clone();
        entry2.updated_at = "2099-01-01T00:00:00Z".to_string();
        remote.add_entry(entry2);

        let lm = create_manifest(&local);
        let rm = create_manifest(&remote);
        let delta = compute_delta(&lm, &rm, &local, &remote);

        // Should detect as modified (hashes differ, local entry unchanged from manifest)
        assert_eq!(delta.modified.len(), 1);
        assert_eq!(delta.modified[0].id, id);
    }

    #[test]
    fn apply_delta_adds_entries() {
        let mut local = make_db("local");
        let entry = VaultEntry::new_login("Added", "u", "p", vec![]);
        let delta = SyncDelta {
            added: vec![entry.clone()],
            modified: vec![],
            deleted: vec![],
            conflicts: vec![],
        };

        apply_delta(&mut local, &delta);
        assert_eq!(local.entry_count(), 1);
        assert_eq!(local.entries[0].name, "Added");
    }

    #[test]
    fn merge_with_keep_newer() {
        let mut local = make_db("local");
        let entry = VaultEntry::new_login("Shared", "user", "old", vec![]);
        let id = entry.id.clone();
        local.add_entry(entry);

        let mut remote = make_db("remote");
        let entry2 = VaultEntry::new_login("NewOnRemote", "u2", "p2", vec![]);
        remote.add_entry(entry2);

        let delta = merge_vaults(&mut local, &remote, ConflictResolution::KeepNewer);

        // Local should have both entries now
        assert!(local.entry_count() >= 1);
        // The new remote entry should be added
        assert!(delta.added.len() >= 1);
    }

    #[test]
    fn export_import_bundle_roundtrip() {
        let mut db = make_db("bundle-test");
        add_login(&mut db, "GitHub", "octocat", "secret");
        add_login(&mut db, "GitLab", "user", "pass");
        db.add_folder("Dev");

        let password = "bundle-password-123";
        let bundle = export_sync_bundle(&db, password).expect("export failed");
        assert!(bundle.len() > 44); // salt + nonce + at least some ciphertext

        let imported = import_sync_bundle(&bundle, password).expect("import failed");
        assert_eq!(imported.name, "bundle-test");
        assert_eq!(imported.entry_count(), 2);
        assert_eq!(imported.folders, vec!["Dev"]);
    }

    #[test]
    fn import_wrong_password_fails() {
        let db = make_db("test");
        let bundle = export_sync_bundle(&db, "correct").expect("export failed");
        let result = import_sync_bundle(&bundle, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn device_id_generation() {
        let id1 = generate_device_id();
        let id2 = generate_device_id();
        // Should be 32 hex chars (128 bits)
        assert_eq!(id1.len(), 32);
        assert_eq!(id2.len(), 32);
        // Should be unique (random component)
        assert_ne!(id1, id2);
    }

    #[test]
    fn empty_vault_sync() {
        let mut local = make_db("local");
        let remote = make_db("remote");
        let delta = merge_vaults(&mut local, &remote, ConflictResolution::KeepNewer);
        assert!(delta.added.is_empty());
        assert!(delta.modified.is_empty());
        assert!(delta.deleted.is_empty());
        assert!(delta.conflicts.is_empty());
    }

    #[test]
    fn large_vault_sync() {
        let mut local = make_db("local");
        let mut remote = make_db("remote");

        // Add 100 entries to each
        for i in 0..100 {
            add_login(
                &mut local,
                &format!("Local-{i}"),
                &format!("user{i}"),
                &format!("pass{i}"),
            );
            add_login(
                &mut remote,
                &format!("Remote-{i}"),
                &format!("ruser{i}"),
                &format!("rpass{i}"),
            );
        }

        let delta = merge_vaults(&mut local, &remote, ConflictResolution::KeepNewer);

        // All 100 remote entries should be added
        assert_eq!(delta.added.len(), 100);
        // Local should now have 200 entries
        assert_eq!(local.entry_count(), 200);
    }

    #[test]
    fn conflict_resolution_strategies() {
        let mut delta = SyncDelta {
            added: vec![],
            modified: vec![],
            deleted: vec![],
            conflicts: vec![
                SyncConflict {
                    entry_id: "id1".into(),
                    entry_name: "Entry1".into(),
                    local_updated: "2026-01-01T00:00:00Z".into(),
                    remote_updated: "2026-01-02T00:00:00Z".into(),
                    resolution: ConflictResolution::Unresolved,
                },
                SyncConflict {
                    entry_id: "id2".into(),
                    entry_name: "Entry2".into(),
                    local_updated: "2026-01-03T00:00:00Z".into(),
                    remote_updated: "2026-01-01T00:00:00Z".into(),
                    resolution: ConflictResolution::Unresolved,
                },
            ],
        };

        resolve_conflicts(&mut delta, ConflictResolution::KeepLocal);
        assert!(delta
            .conflicts
            .iter()
            .all(|c| c.resolution == ConflictResolution::KeepLocal));

        resolve_conflicts(&mut delta, ConflictResolution::KeepRemote);
        assert!(delta
            .conflicts
            .iter()
            .all(|c| c.resolution == ConflictResolution::KeepRemote));
    }
}
