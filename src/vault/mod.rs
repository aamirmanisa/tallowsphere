//! Tallow Vault — Bitwarden/KeePass-class encrypted password manager.
//!
//! **16 modules across 5 tiers:**
//!
//! Tier 1 — Core Vault:
//!   - `entry` — Entry types (Login, Card, Identity, Note, SSH, API, TOTP)
//!   - `db` — Encrypted database (`.twv` v1 AES-256-GCM / v2 ML-KEM-768 hybrid
//!     / v3 XChaCha20-Poly1305 at-rest, + Argon2id)
//!   - `credential` — Volatile in-process credential cache (real AEAD; the
//!     `CredentialVault` `.tl` surface; NOT persistence — use `db` for that)
//!   - `generate` — Password/passphrase/username generator with entropy estimation
//!   - `totp` — TOTP authenticator (RFC 6238, SHA-1/256/512, Steam Guard)
//!
//! Tier 2 — Security & Health:
//!   - `health` — Health reports (weak/reused/exposed passwords, HIBP breach check)
//!
//! Tier 3 — Sharing & Access:
//!   - `share` — Ed25519 encrypted sharing, ephemeral send, Shamir recovery
//!   - `recovery` — dual-control custody recovery + root-rotation ceremony
//!     (row #114 · R-5.12: k≥2 distinct custody shares, KT-logged,
//!     honest-unrecoverable)
//!
//! Tier 4 — Integration:
//!   - `import_export` — Bitwarden/KeePass/Chrome/Firefox/LastPass import/export
//!   - `ssh_agent` — SSH agent (Ed25519 key loading, signing, fingerprints)
//!   - `autotype` — Auto-type engine (sequences, window matching, anti-keylogger)
//!
//! Tier 5 — PQC & Enterprise:
//!   - `pqc` — Post-quantum hybrid encryption (ML-KEM-768 + AES-256-GCM)
//!   - `key_custody` — Sealed custody of shred key material (A2.1.1)
//!   - `persona_store` — Sealed persona-registry custody + open-bundle support (A5.1.2)
//!   - `sync` — Encrypted vault sync (BLAKE3 delta detection, conflict resolution)
//!   - `audit` — Compliance audit (GDPR Art.32, NIST 800-63B, PCI-DSS, ISO 27001)

// Tier 1: Core
pub mod entry;
pub mod db;
pub mod access;
pub mod credential;
pub mod generate;
pub mod totp;

// Tier 2: Security
pub mod health;
pub mod identity_keys;

// Tier 3: Sharing
pub mod share;
pub mod recovery;

// Tier 4: Integration
pub mod import_export;
pub mod ssh_agent;
pub mod persona_store;
pub mod autotype;

// Tier 5: PQC & Enterprise
pub mod pqc;
pub mod key_custody;
pub mod sync;
pub mod audit;

// Re-exports
pub use entry::*;
pub use db::VaultDatabase;

#[cfg(test)]
mod tests {
    /// §D7 / FIX-11 ratchet: Argon2id cost parameters live in **one** module
    /// (`tallow_crypto::kdf::argon2`) with two named profiles. This gate keeps
    /// literal-cost `Params::new(<digit>…)` from creeping back into `src/vault/`.
    ///
    /// The two recorded write-side sites (`pqc.rs`, `sync.rs`) predate the
    /// single-source change and are staged in
    /// `research/tallow-v1/exec/W2-02-03-crypto-closeouts.md` §OPEN P-4/P-5
    /// (blocked on the root `tallow-crypto` dependency, P-2). The count may
    /// only go **down**: once those patches land, drop the constant to 0.
    const RECORDED_LITERAL_SITES: usize = 2;

    #[test]
    fn test_no_new_literal_argon2_cost_sites_in_vault() {
        let mut offenders: Vec<String> = Vec::new();
        for (name, src) in [
            ("db.rs", include_str!("db.rs")),
            ("pqc.rs", include_str!("pqc.rs")),
            ("sync.rs", include_str!("sync.rs")),
            ("import_export.rs", include_str!("import_export.rs")),
            ("share.rs", include_str!("share.rs")),
            ("credential.rs", include_str!("credential.rs")),
        ] {
            for (i, line) in src.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if let Some(pos) = trimmed.find("Params::new(") {
                    let rest = &trimmed[pos + "Params::new(".len()..];
                    if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                        offenders.push(format!("{name}:{}", i + 1));
                    }
                }
            }
        }
        assert!(
            offenders.len() <= RECORDED_LITERAL_SITES,
            "new literal-cost Argon2 params in src/vault (use tallow_crypto::kdf::argon2::Profile): {offenders:?}"
        );
    }
}
