//! Tamper-evident Merkle tree audit log with BLAKE3 hash chains.
//!
//! Provides append-only audit logging where each entry includes the hash
//! of the previous entry, forming a hash chain. A Merkle tree over all
//! entry hashes enables efficient inclusion proofs.
//!
//! Key operations:
//! - `append()` — add entry with BLAKE3 hash chain linking
//! - `verify_chain()` — detect any tampering in the log
//! - `prove_inclusion()` — generate Merkle proof for an entry
//! - `verify_proof()` — verify a Merkle inclusion proof

use blake3;
use serde_json;

/// A single audit log entry with hash chain linking.
#[derive(Clone, Debug)]
pub struct AuditEntry {
    pub timestamp: String,
    pub function: String,
    pub event_type: String,
    pub metadata: serde_json::Value,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

/// Append-only audit log with BLAKE3 hash chain and Merkle tree.
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    hashes: Vec<[u8; 32]>,
    genesis_hash: [u8; 32],
    root: Option<[u8; 32]>,
}

/// Merkle inclusion proof: sibling hashes from leaf to root.
pub struct MerkleProof {
    pub leaf_hash: [u8; 32],
    /// Each element is (is_right_sibling, hash).
    pub siblings: Vec<(bool, [u8; 32])>,
}

/// Hash data concatenated with the previous entry's hash.
fn hash_entry(data: &[u8], prev: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(data.len() + 32);
    input.extend_from_slice(data);
    input.extend_from_slice(prev);
    *blake3::hash(&input).as_bytes()
}

/// Compute Merkle root from a list of leaf hashes (bottom-up).
/// Duplicates last hash if count is odd at any level.
fn compute_merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    if hashes.len() == 1 {
        return hashes[0];
    }

    let mut level: Vec<[u8; 32]> = hashes.to_vec();
    while level.len() > 1 {
        let mut next_level = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            let left = &level[i];
            let right = if i + 1 < level.len() {
                &level[i + 1]
            } else {
                &level[i] // duplicate last if odd
            };
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(left);
            combined[32..].copy_from_slice(right);
            next_level.push(*blake3::hash(&combined).as_bytes());
            i += 2;
        }
        level = next_level;
    }
    level[0]
}

impl AuditLog {
    /// Create a new empty audit log with a genesis hash.
    pub fn new() -> Self {
        let genesis_hash = *blake3::hash(b"GENESIS").as_bytes();
        AuditLog {
            entries: Vec::new(),
            hashes: Vec::new(),
            genesis_hash,
            root: None,
        }
    }

    /// Append an entry to the log. The entry's hash includes the previous entry's hash.
    pub fn append(&mut self, function: &str, event_type: &str, metadata: serde_json::Value) {
        let prev_hash = self.hashes.last().copied().unwrap_or(self.genesis_hash);

        // Serialize the entry data for hashing
        let data = format!(
            "{}:{}:{}",
            function,
            event_type,
            serde_json::to_string(&metadata).unwrap_or_default()
        );

        let entry_hash = hash_entry(data.as_bytes(), &prev_hash);

        let timestamp = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            format!("{}s", now.as_secs())
        };

        self.entries.push(AuditEntry {
            timestamp,
            function: function.to_string(),
            event_type: event_type.to_string(),
            metadata,
            prev_hash,
            entry_hash,
        });
        self.hashes.push(entry_hash);

        // Recompute Merkle root
        self.root = Some(compute_merkle_root(&self.hashes));
    }

    /// Verify the hash chain is intact. Returns false if any entry was tampered with.
    pub fn verify_chain(&self) -> bool {
        if self.entries.is_empty() {
            return true;
        }

        let mut prev = self.genesis_hash;
        for (i, entry) in self.entries.iter().enumerate() {
            // Check prev_hash linkage
            if entry.prev_hash != prev {
                return false;
            }

            // Recompute hash from data
            let data = format!(
                "{}:{}:{}",
                entry.function,
                entry.event_type,
                serde_json::to_string(&entry.metadata).unwrap_or_default()
            );
            let expected = hash_entry(data.as_bytes(), &prev);
            if entry.entry_hash != expected {
                return false;
            }

            // Check stored hash matches
            if i < self.hashes.len() && self.hashes[i] != entry.entry_hash {
                return false;
            }

            prev = entry.entry_hash;
        }
        true
    }

    /// Return the cached Merkle root, if any entries exist.
    pub fn merkle_root(&self) -> Option<[u8; 32]> {
        self.root
    }

    /// Generate a Merkle inclusion proof for the entry at `index`.
    pub fn prove_inclusion(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.hashes.len() || self.hashes.is_empty() {
            return None;
        }

        let leaf_hash = self.hashes[index];
        let mut siblings = Vec::new();

        // Build bottom-up levels to find sibling at each level
        let mut level: Vec<[u8; 32]> = self.hashes.clone();
        let mut idx = index;

        while level.len() > 1 {
            // If idx is even, sibling is idx+1 (or duplicate of idx if last)
            // If idx is odd, sibling is idx-1
            let sibling_idx;
            let is_right;
            if idx % 2 == 0 {
                sibling_idx = if idx + 1 < level.len() { idx + 1 } else { idx };
                is_right = true;
            } else {
                sibling_idx = idx - 1;
                is_right = false;
            }
            siblings.push((is_right, level[sibling_idx]));

            // Compute next level
            let mut next_level = Vec::with_capacity((level.len() + 1) / 2);
            let mut i = 0;
            while i < level.len() {
                let left = &level[i];
                let right = if i + 1 < level.len() {
                    &level[i + 1]
                } else {
                    &level[i]
                };
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(left);
                combined[32..].copy_from_slice(right);
                next_level.push(*blake3::hash(&combined).as_bytes());
                i += 2;
            }
            level = next_level;
            idx /= 2;
        }

        Some(MerkleProof {
            leaf_hash,
            siblings,
        })
    }

    /// Verify a Merkle inclusion proof against an expected root.
    pub fn verify_proof(entry_hash: &[u8; 32], proof: &MerkleProof, root: &[u8; 32]) -> bool {
        let mut current = *entry_hash;

        for (is_right, sibling) in &proof.siblings {
            let mut combined = [0u8; 64];
            if *is_right {
                // sibling is on the right
                combined[..32].copy_from_slice(&current);
                combined[32..].copy_from_slice(sibling);
            } else {
                // sibling is on the left
                combined[..32].copy_from_slice(sibling);
                combined[32..].copy_from_slice(&current);
            }
            current = *blake3::hash(&combined).as_bytes();
        }

        current == *root
    }

    /// Serialize the audit log to JSON.
    pub fn to_json(&self) -> serde_json::Value {
        let entries: Vec<serde_json::Value> = self
            .entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "timestamp": e.timestamp,
                    "function": e.function,
                    "event_type": e.event_type,
                    "metadata": e.metadata,
                    "prev_hash": hex::encode(e.prev_hash),
                    "entry_hash": hex::encode(e.entry_hash),
                })
            })
            .collect();

        serde_json::json!({
            "entries": entries,
            "count": self.entries.len(),
            "merkle_root": self.root.map(|r| hex::encode(r)),
        })
    }

    /// Number of entries in the log.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Minimal hex encoding (avoid pulling in the `hex` crate just for display).
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

// ══════════════════════════════════════════════════════════════════
// External audit anchoring (tamper-PROOF, not just tamper-evidence)
// ══════════════════════════════════════════════════════════════════

/// A signed snapshot of the Merkle root at a point in time.
///
/// The chain alone is only tamper-EVIDENT: a writer who can rewrite the log
/// can also rewrite the chain. To make rewrite provable, the root must be
/// committed to by a party OUTSIDE the writer's control. This record binds a
/// Merkle root to an Ed25519 signing key + timestamp, so once an external
/// holder sees it, a later chain rewrite can be shown inconsistent with the
/// previously-anchored root. Deploy: publish each `SignedAnchor` to a
/// transparency log / TSA / offline cosigner so the trusted anchor is held
/// apart from the log writer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAnchor {
    /// The Merkle root hash (BLAKE3) that was committed.
    pub root: [u8; 32],
    /// RFC-3339 UTC timestamp of the anchor.
    pub timestamp: String,
    /// Base58/hex public key of the anchor signer (external witness identity).
    pub signer: String,
    /// Ed25519 signature over (root || timestamp).
    pub signature: Vec<u8>,
}

impl AuditLog {
    /// Produce a SignedAnchor for the current Merkle root, signed with `key`.
    ///
    /// Returns None if the log has no entries (nothing to anchor) or if the
    /// root is the zero-value empty-tree root.
    pub fn anchor(&self, key: &ed25519_dalek::SigningKey) -> Option<SignedAnchor> {
        let root = self.merkle_root()?;
        let timestamp = {
            let now = chrono::Utc::now();
            now.to_rfc3339()
        };
        let signer = hex::encode(key.verifying_key().as_bytes());
        let signature = sign_anchor_root(&root, &timestamp, key);
        Some(SignedAnchor {
            root,
            timestamp,
            signer,
            signature,
        })
    }

    /// Verify a SignedAnchor against a known verifier public key.
    ///
    /// Returns true iff the key matches `signer`, the signature verifies, and
    /// the anchored root equals the log's current root.
    pub fn verify_anchor(&self, anchor: &SignedAnchor, verifier: &ed25519_dalek::VerifyingKey) -> bool {
        // The signer identity must match the verifier we trust.
        if hex::encode(verifier.as_bytes()) != anchor.signer {
            return false;
        }
        // The signature must be valid for (root || timestamp).
        if !verify_anchor_root(anchor, verifier) {
            return false;
        }
        // The anchored root must equal the current root (no rewrite since).
        Some(anchor.root) == self.merkle_root()
    }
}

/// Serialize (root || timestamp) as the canonical bytes to sign.
fn anchor_payload(root: &[u8; 32], timestamp: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(32 + timestamp.len());
    payload.extend_from_slice(root);
    payload.extend_from_slice(timestamp.as_bytes());
    payload
}

/// Sign a Merkle root + timestamp with an Ed25519 key.
fn sign_anchor_root(
    root: &[u8; 32],
    timestamp: &str,
    key: &ed25519_dalek::SigningKey,
) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let payload = anchor_payload(root, timestamp);
    key.sign(&payload).to_bytes().to_vec()
}

/// Verify a SignedAnchor's signature against a verifier key.
fn verify_anchor_root(
    anchor: &SignedAnchor,
    verifier: &ed25519_dalek::VerifyingKey,
) -> bool {
    use ed25519_dalek::Verifier;
    let payload = anchor_payload(&anchor.root, &anchor.timestamp);
    let sig: ed25519_dalek::Signature = match ed25519_dalek::Signature::from_slice(&anchor.signature)
    {
        Ok(s) => s,
        Err(_) => return false,
    };
    verifier.verify(&payload, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_creates_empty_log_with_genesis() {
        let log = AuditLog::new();
        assert_eq!(log.len(), 0);
        assert!(log.is_empty());
        // Genesis hash is BLAKE3("GENESIS")
        let expected = *blake3::hash(b"GENESIS").as_bytes();
        assert_eq!(log.genesis_hash, expected);
    }

    #[test]
    fn test_append_chains_hashes() {
        let mut log = AuditLog::new();
        log.append("fn_a", "call", serde_json::json!({"key": "val"}));
        assert_eq!(log.len(), 1);

        // First entry's prev_hash should be genesis
        let genesis = *blake3::hash(b"GENESIS").as_bytes();
        assert_eq!(log.entries[0].prev_hash, genesis);

        // Second entry's prev_hash should be first entry's hash
        log.append("fn_b", "return", serde_json::json!({}));
        assert_eq!(log.entries[1].prev_hash, log.entries[0].entry_hash);
    }

    #[test]
    fn test_verify_chain_untampered() {
        let mut log = AuditLog::new();
        log.append("fn_a", "call", serde_json::json!({"x": 1}));
        log.append("fn_b", "call", serde_json::json!({"x": 2}));
        log.append("fn_c", "call", serde_json::json!({"x": 3}));
        assert!(log.verify_chain());
    }

    #[test]
    fn test_verify_chain_detects_data_tamper() {
        let mut log = AuditLog::new();
        log.append("fn_a", "call", serde_json::json!({"x": 1}));
        log.append("fn_b", "call", serde_json::json!({"x": 2}));
        log.append("fn_c", "call", serde_json::json!({"x": 3}));

        // Tamper with middle entry's data
        log.entries[1].function = "TAMPERED".to_string();
        assert!(!log.verify_chain());
    }

    #[test]
    fn test_verify_chain_detects_removal() {
        let mut log = AuditLog::new();
        log.append("fn_a", "call", serde_json::json!({}));
        log.append("fn_b", "call", serde_json::json!({}));
        log.append("fn_c", "call", serde_json::json!({}));

        // Remove middle entry
        log.entries.remove(1);
        log.hashes.remove(1);
        assert!(!log.verify_chain());
    }

    #[test]
    fn test_merkle_root_computed() {
        let mut log = AuditLog::new();
        assert!(log.merkle_root().is_none());

        log.append("fn_a", "call", serde_json::json!({}));
        assert!(log.merkle_root().is_some());

        // Root should be the single hash for 1 entry
        assert_eq!(log.merkle_root().unwrap(), log.hashes[0]);

        log.append("fn_b", "call", serde_json::json!({}));
        // Root should now be BLAKE3(hash_a || hash_b)
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&log.hashes[0]);
        combined[32..].copy_from_slice(&log.hashes[1]);
        let expected_root = *blake3::hash(&combined).as_bytes();
        assert_eq!(log.merkle_root().unwrap(), expected_root);
    }

    #[test]
    fn test_prove_inclusion_returns_proof() {
        let mut log = AuditLog::new();
        log.append("fn_a", "call", serde_json::json!({}));
        log.append("fn_b", "call", serde_json::json!({}));
        log.append("fn_c", "call", serde_json::json!({}));

        let proof = log.prove_inclusion(1);
        assert!(proof.is_some());
        let proof = proof.unwrap();
        assert_eq!(proof.leaf_hash, log.hashes[1]);
        assert!(!proof.siblings.is_empty());
    }

    #[test]
    fn test_verify_proof_valid() {
        let mut log = AuditLog::new();
        for i in 0..5 {
            log.append(&format!("fn_{i}"), "call", serde_json::json!({"i": i}));
        }
        let root = log.merkle_root().unwrap();

        // Verify each entry's proof
        for i in 0..5 {
            let proof = log.prove_inclusion(i).unwrap();
            assert!(
                AuditLog::verify_proof(&log.hashes[i], &proof, &root),
                "proof failed for index {i}"
            );
        }
    }

    #[test]
    fn test_verify_proof_invalid() {
        let mut log = AuditLog::new();
        log.append("fn_a", "call", serde_json::json!({}));
        log.append("fn_b", "call", serde_json::json!({}));

        let root = log.merkle_root().unwrap();
        let proof = log.prove_inclusion(0).unwrap();

        // Use wrong hash -- should fail
        let wrong_hash = [0xFFu8; 32];
        assert!(!AuditLog::verify_proof(&wrong_hash, &proof, &root));

        // Use wrong root -- should fail
        let wrong_root = [0x00u8; 32];
        assert!(!AuditLog::verify_proof(&log.hashes[0], &proof, &wrong_root));
    }

    #[test]
    fn test_to_json_serializes() {
        let mut log = AuditLog::new();
        log.append("scrape_prices", "network_call", serde_json::json!({"url": "example.com"}));

        let json = log.to_json();
        assert_eq!(json["count"], 1);
        assert!(json["entries"].is_array());
        assert!(json["merkle_root"].is_string());

        let entry = &json["entries"][0];
        assert_eq!(entry["function"], "scrape_prices");
        assert_eq!(entry["event_type"], "network_call");
        assert!(entry["entry_hash"].is_string());
        assert!(entry["prev_hash"].is_string());
    }

    #[test]
    fn test_anchor_signed_and_verifies() {
        use ed25519_dalek::SigningKey;
        let mut log = AuditLog::new();
        log.append("fn_a", "call", serde_json::json!({"x": 1}));
        log.append("fn_b", "call", serde_json::json!({"x": 2}));

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let verifier = key.verifying_key();
        let anchor = log.anchor(&key).expect("log with entries should anchor");
        assert!(log.verify_anchor(&anchor, &verifier), "valid anchor should verify");
        assert_eq!(anchor.root, log.merkle_root().unwrap());
    }

    #[test]
    fn test_anchor_detects_rewrite_after_tamper() {
        use ed25519_dalek::SigningKey;
        let mut log = AuditLog::new();
        log.append("fn_a", "call", serde_json::json!({"x": 1}));
        log.append("fn_b", "call", serde_json::json!({"x": 2}));

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let verifier = key.verifying_key();
        let anchor = log.anchor(&key).unwrap();

        // Rewrite the log (tamper + same count, so chain recomputes cleanly but
        // differs from the anchored root). A writer who controls the log cannot
        // fake the previously-anchored root because the anchor signature is
        // bound to the old root.
        log.entries[1].metadata = serde_json::json!({"x": 999});
        log.hashes[1] = hash_entry(
            format!(
                "fn_b:call:{}",
                serde_json::to_string(&log.entries[1].metadata).unwrap()
            )
            .as_bytes(),
            &log.entries[1].prev_hash,
        );
        log.root = Some(compute_merkle_root(&log.hashes));

        assert!(!log.verify_anchor(&anchor, &verifier), "rewritten log must not verify against old anchor");
        // The signature is still cryptographically valid for the OLD root, but
        // the current root diverges -> the tamper is now provable.
        assert!(!log.verify_chain(), "chain should also detect the tamper");
    }

    #[test]
    fn test_anchor_wrong_key_rejected() {
        use ed25519_dalek::SigningKey;
        let mut log = AuditLog::new();
        log.append("fn_a", "call", serde_json::json!({}));

        let sign_key = SigningKey::from_bytes(&[1u8; 32]);
        let other_key = SigningKey::from_bytes(&[2u8; 32]);
        let anchor = log.anchor(&sign_key).unwrap();
        assert!(
            !log.verify_anchor(&anchor, &other_key.verifying_key()),
            "a different verifier key must reject the anchor"
        );
    }

    #[test]
    fn test_anchor_empty_log_none() {
        use ed25519_dalek::SigningKey;
        let log = AuditLog::new();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        assert!(log.anchor(&key).is_none(), "empty log has no root to anchor");
    }

    #[test]
    fn test_chain_is_not_anchor_possibly_reordering() {
        // Guard: reordering entries WITHOUT changing their hashes must be
        // caught by verify_chain (prev_hash linkage) — no false pass.
        let mut log = AuditLog::new();
        log.append("fn_a", "call", serde_json::json!({"i": 0}));
        log.append("fn_b", "call", serde_json::json!({"i": 1}));
        log.append("fn_c", "call", serde_json::json!({"i": 2}));
        log.entries.swap(0, 2);
        log.hashes.swap(0, 2);
        assert!(!log.verify_chain(), "reordering must break the hash chain");
    }
}
