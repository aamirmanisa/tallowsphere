//! Argon2id password hashing — **single parameter source** (cycle-02/07 §D7, FIX-11).
//!
//! This module is the only place in the workspace where Argon2id **cost
//! parameters** are declared. Two named profiles cover every consumer:
//!
//! | profile | memory | iterations | lanes | used by |
//! |---|---|---|---|---|
//! | [`Profile::Interactive`] | 256 MiB | 3 | 4 | `keys/storage`, stdlib crypto, PHC hashes |
//! | [`Profile::Vault`] | 64 MiB | 3 | 4 | `src/vault` containers (writer), encrypted exports |
//! | [`Profile::Room`] | 64 MiB | 3 | 1 | room-id derivation v2 (`tallow-protocol::room::code`) |
//!
//! Three values in **one** module with one owner is the policy
//! (`policy.oneParamsSource`); four values in four modules was not. Containers
//! that store their own costs in a header (vault `.twv`, export `TVX1`) keep
//! **header precedence on read** through [`derive_key_with_stored_params`]; the
//! writer path uses [`derive_key_with_profile`] with [`Profile::Vault`].
//!
//! PHC-encoded hashes ([`hash_password`]/[`verify_password`]) embed their own
//! parameters, so previously written hashes keep verifying — only new hashes
//! change if a profile value ever changes.

use crate::error::{CryptoError, Result};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use rand_core::OsRng;
use zeroize::Zeroizing;

/// Memory cost in KiB for [`Profile::Interactive`] (256 MiB = 262144 KiB)
pub const MEMORY_COST: u32 = 262_144;

/// Number of iterations for [`Profile::Interactive`]
pub const TIME_COST: u32 = 3;

/// Degree of parallelism for [`Profile::Interactive`]
pub const PARALLELISM: u32 = 4;

/// Memory cost in KiB for [`Profile::Vault`] (64 MiB = 65536 KiB).
///
/// Matches the historical `src/vault` defaults (`db.rs` DEFAULT_M_COST), so
/// existing vault containers open byte-for-byte and new writes are unchanged.
pub const VAULT_MEMORY_COST: u32 = 65_536;

/// Number of iterations for [`Profile::Vault`]
pub const VAULT_TIME_COST: u32 = 3;

/// Degree of parallelism for [`Profile::Vault`]
pub const VAULT_PARALLELISM: u32 = 4;

/// Memory cost in KiB for [`Profile::Room`] (64 MiB = 65536 KiB).
///
/// Sizing rationale (2026-09-20, room-id v2): the derivation runs once per
/// join — including inside wasm on phones — so it stays at the Vault memory
/// class with a single lane (wasm has no thread parallelism; extra lanes only
/// add variance across environments). Raises the offline cost of guessing a
/// room code by ~5-6 orders of magnitude versus a single fast hash.
pub const ROOM_MEMORY_COST: u32 = 65_536;

/// Number of iterations for [`Profile::Room`]
pub const ROOM_TIME_COST: u32 = 3;

/// Degree of parallelism for [`Profile::Room`]
pub const ROOM_PARALLELISM: u32 = 1;

/// Named Argon2id parameter profile — the three sanctioned cost classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// 256 MiB / t=3 / p=4 — interactive key derivation and password hashing.
    Interactive,
    /// 64 MiB / t=3 / p=4 — vault containers and encrypted exports; the
    /// container header carries the costs it was written with.
    Vault,
    /// 64 MiB / t=3 / p=1 — room-id derivation v2 (network-facing, wasm-safe).
    Room,
}

impl Profile {
    /// `(memory_cost_KiB, time_cost, parallelism)` for this profile.
    pub const fn costs(self) -> (u32, u32, u32) {
        match self {
            Profile::Interactive => (MEMORY_COST, TIME_COST, PARALLELISM),
            Profile::Vault => (VAULT_MEMORY_COST, VAULT_TIME_COST, VAULT_PARALLELISM),
            Profile::Room => (ROOM_MEMORY_COST, ROOM_TIME_COST, ROOM_PARALLELISM),
        }
    }

    /// Memory cost in KiB for this profile.
    pub const fn memory_cost(self) -> u32 {
        self.costs().0
    }

    /// Number of iterations for this profile.
    pub const fn time_cost(self) -> u32 {
        self.costs().1
    }

    /// Degree of parallelism for this profile.
    pub const fn parallelism(self) -> u32 {
        self.costs().2
    }

    /// Stable numeric identifier as persisted in versioned containers (the
    /// v2 keyring envelope). Never renumber — the value is stored on disk.
    pub const fn id(self) -> u8 {
        match self {
            Profile::Interactive => 0,
            Profile::Vault => 1,
            Profile::Room => 2,
        }
    }

    /// Parse a profile identifier previously written by [`Profile::id`].
    ///
    /// Unknown ids return `None` (no silent fallback to a default profile).
    pub const fn from_id(id: u8) -> Option<Profile> {
        match id {
            0 => Some(Profile::Interactive),
            1 => Some(Profile::Vault),
            2 => Some(Profile::Room),
            _ => None,
        }
    }
}

/// Build `argon2::Params` for a named profile.
///
/// This is the parameter entry point every Argon2id consumer should use.
pub fn params(profile: Profile, output_len: Option<usize>) -> Result<Params> {
    let (m_cost, t_cost, p_cost) = profile.costs();
    Params::new(m_cost, t_cost, p_cost, output_len)
        .map_err(|e| CryptoError::KeyGeneration(format!("Invalid Argon2 params: {}", e)))
}

/// Build `argon2::Params` from cost values **read out of a container header**.
///
/// Only for readers: the stored values take precedence over any profile so
/// legacy containers keep opening. Writers must use [`params`].
pub fn params_with_stored_costs(
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    output_len: Option<usize>,
) -> Result<Params> {
    Params::new(memory_cost, time_cost, parallelism, output_len)
        .map_err(|e| CryptoError::KeyGeneration(format!("Invalid Argon2 params: {}", e)))
}

/// [`Argon2`] instance for explicit params (Argon2id, version 0x13).
fn argon2_with(params: Params) -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Create an Argon2 instance with [`Profile::Interactive`] parameters.
///
/// Kept for compatibility with the pre-§D7 call sites; new code should prefer
/// [`params`]/[`derive_key_with_profile`].
fn production_argon2(output_len: Option<usize>) -> Result<Argon2<'static>> {
    Ok(argon2_with(params(Profile::Interactive, output_len)?))
}

/// Create an Argon2 instance for testing (fast, reduced parameters)
#[cfg(test)]
fn test_argon2(output_len: Option<usize>) -> Argon2<'static> {
    let params = Params::new(
        16_384, // 16 MiB — fast enough for tests
        1,      // 1 iteration
        1,      // 1 thread
        output_len,
    )
    .expect("test Argon2 params are valid");

    argon2_with(params)
}

/// Derive a key with explicit params, into a `Zeroizing` buffer.
fn derive_with_params(
    params: Params,
    password: &[u8],
    salt: &[u8],
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let argon2 = argon2_with(params);

    let mut output = Zeroizing::new(vec![0u8; output_len]);
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| CryptoError::KeyGeneration(format!("Argon2 key derivation failed: {}", e)))?;

    Ok(output)
}

/// Derive a key from a password using Argon2id under a **named profile**.
///
/// This is the profile-parameterized form of [`derive_key`] (kept as a
/// separate name because the flat 3-argument `derive_key` is retained for
/// existing callers — Rust has no overloading).
///
/// # Arguments
///
/// * `profile` - [`Profile::Interactive`] or [`Profile::Vault`]
/// * `password` - The password to derive from
/// * `salt` - Salt bytes (16 bytes is conventional; length is not enforced)
/// * `output_len` - Desired output length in bytes
///
/// # Returns
///
/// Derived key material, zeroized on drop
pub fn derive_key_with_profile(
    profile: Profile,
    password: &[u8],
    salt: &[u8],
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    derive_with_params(
        params(profile, Some(output_len))?,
        password,
        salt,
        output_len,
    )
}

/// Derive a key with the cost values **stored in a container header**.
///
/// Reader path (header precedence): `src/vault` `.twv` v1 files and `TVX1`
/// encrypted exports carry `m/t/p`; those values are used verbatim so
/// legacy containers keep opening. Prefer [`derive_key_with_profile`] for
/// every new derivation.
pub fn derive_key_with_stored_params(
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    password: &[u8],
    salt: &[u8],
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    derive_with_params(
        params_with_stored_costs(memory_cost, time_cost, parallelism, Some(output_len))?,
        password,
        salt,
        output_len,
    )
}

/// Hash a password using Argon2id
///
/// Uses [`Profile::Interactive`] parameters (256 MiB, t=3, p=4). The PHC
/// string embeds the parameters used, so existing hashes verify independently
/// of this module's current values.
///
/// # Arguments
///
/// * `password` - The password to hash
/// * `salt` - Optional salt (if None, a random salt is generated)
///
/// # Returns
///
/// PHC-encoded password hash string
///
/// # Example
///
/// ```ignore
/// let hash = hash_password(b"my_password", None)?;
/// ```
pub fn hash_password(password: &[u8], salt: Option<&SaltString>) -> Result<Vec<u8>> {
    let argon2 = production_argon2(None)?;

    let salt = match salt {
        Some(s) => s.clone(),
        None => SaltString::generate(&mut OsRng),
    };

    let hash = argon2
        .hash_password(password, &salt)
        .map_err(|e| CryptoError::KeyGeneration(format!("Argon2 hashing failed: {}", e)))?;

    Ok(hash.to_string().into_bytes())
}

/// Verify a password against an Argon2 hash
///
/// # Arguments
///
/// * `password` - The password to verify
/// * `hash` - The PHC-encoded hash to verify against
///
/// # Returns
///
/// `Ok(true)` if the password matches, `Ok(false)` if it doesn't,
/// or `Err` if the hash is malformed
pub fn verify_password(password: &[u8], hash: &[u8]) -> Result<bool> {
    let hash_str = std::str::from_utf8(hash)
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid hash encoding: {}", e)))?;

    let parsed_hash = PasswordHash::new(hash_str)
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid hash format: {}", e)))?;

    // Verify uses the parameters embedded in the PHC string itself,
    // so we only need a default Argon2 instance for the algorithm ID.
    // The actual memory/time/parallelism come from the hash, not from here.
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::DEFAULT);

    match argon2.verify_password(password, &parsed_hash) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Derive a key from a password using Argon2id
///
/// Legacy flat-signature form (kept for existing callers). Delegates to
/// [`derive_key_with_profile`] with [`Profile::Interactive`] — the historical
/// production parameters, so existing derived keys are unchanged:
/// 256 MiB memory, 3 iterations, 4 parallel lanes.
///
/// # Arguments
///
/// * `password` - The password to derive from
/// * `salt` - 16-byte salt
/// * `output_len` - Desired output length in bytes
///
/// # Returns
///
/// Derived key material
pub fn derive_key(
    password: &[u8],
    salt: &[u8; 16],
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    derive_key_with_profile(Profile::Interactive, password, salt, output_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only hash function with reduced Argon2 parameters for speed
    fn test_hash_password(password: &[u8], salt: Option<&SaltString>) -> Result<Vec<u8>> {
        let argon2 = test_argon2(None);

        let salt = match salt {
            Some(s) => s.clone(),
            None => SaltString::generate(&mut OsRng),
        };

        let hash = argon2
            .hash_password(password, &salt)
            .map_err(|e| CryptoError::KeyGeneration(format!("Argon2 hashing failed: {}", e)))?;

        Ok(hash.to_string().into_bytes())
    }

    /// Test-only key derivation with reduced Argon2 parameters
    fn test_derive_key(password: &[u8], salt: &[u8; 16], output_len: usize) -> Result<Vec<u8>> {
        let argon2 = test_argon2(Some(output_len));

        let mut output = vec![0u8; output_len];
        argon2
            .hash_password_into(password, salt, &mut output)
            .map_err(|e| {
                CryptoError::KeyGeneration(format!("Argon2 key derivation failed: {}", e))
            })?;

        Ok(output)
    }

    #[test]
    fn test_hash_and_verify() {
        let password = b"my_secure_password";
        let hash = test_hash_password(password, None).unwrap();

        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password(b"wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_verify_wrong_password() {
        let password = b"correct";
        let hash = test_hash_password(password, None).unwrap();

        assert!(!verify_password(b"incorrect", &hash).unwrap());
    }

    #[test]
    fn test_derive_key_deterministic() {
        let password = b"password";
        let salt = [0u8; 16];

        let key1 = test_derive_key(password, &salt, 32).unwrap();
        let key2 = test_derive_key(password, &salt, 32).unwrap();

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_derive_key_different_salt() {
        let password = b"password";
        let salt1 = [0u8; 16];
        let salt2 = [1u8; 16];

        let key1 = test_derive_key(password, &salt1, 32).unwrap();
        let key2 = test_derive_key(password, &salt2, 32).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_production_params_are_valid() {
        // Verify that production params construction succeeds
        let result = production_argon2(Some(32));
        assert!(result.is_ok());
    }

    // ── §D7 single-source profile tests ─────────────────────────────────────

    #[test]
    fn test_profile_costs_are_the_documented_values() {
        assert_eq!(Profile::Interactive.costs(), (262_144, 3, 4));
        assert_eq!(Profile::Vault.costs(), (65_536, 3, 4));
        // Named accessors agree with the tuple.
        assert_eq!(Profile::Vault.memory_cost(), VAULT_MEMORY_COST);
        assert_eq!(Profile::Vault.time_cost(), VAULT_TIME_COST);
        assert_eq!(Profile::Vault.parallelism(), VAULT_PARALLELISM);
    }

    #[test]
    fn test_profile_params_construct_with_expected_costs() {
        for profile in [Profile::Interactive, Profile::Vault] {
            let p = params(profile, Some(32)).unwrap();
            let (m, t, par) = profile.costs();
            assert_eq!(p.m_cost(), m);
            assert_eq!(p.t_cost(), t);
            assert_eq!(p.p_cost(), par);
            assert_eq!(p.output_len(), Some(32));
        }
    }

    #[test]
    fn test_legacy_derive_key_and_interactive_profile_agree() {
        // 256 MiB profile — the point is that the legacy flat function and the
        // named profile are the same derivation (2 derivations total).
        let password = b"legacy-compat";
        let salt = [7u8; 16];

        let legacy = derive_key(password, &salt, 32).unwrap();
        let profiled = derive_key_with_profile(Profile::Interactive, password, &salt, 32).unwrap();

        assert_eq!(&legacy[..], &profiled[..]);
        assert_eq!(legacy.len(), 32);
    }

    #[test]
    fn test_vault_profile_and_stored_params_agree() {
        // The writer (Profile::Vault) and the reader (stored header values) must
        // produce the same key for the same costs — this is the header-precedence
        // contract for `src/vault`.
        let password = b"vault-class";
        let salt = [9u8; 16];

        let writer = derive_key_with_profile(Profile::Vault, password, &salt, 32).unwrap();
        let reader = derive_key_with_stored_params(
            Profile::Vault.memory_cost(),
            Profile::Vault.time_cost(),
            Profile::Vault.parallelism(),
            password,
            &salt,
            32,
        )
        .unwrap();

        assert_eq!(&writer[..], &reader[..]);
    }

    #[test]
    fn test_stored_params_actually_control_the_derivation() {
        // Cheap costs prove the stored m/t/p feed the KDF (no silent fallback
        // to a profile): same password+salt, different stored costs → different key.
        let password = b"stored-costs";
        let salt = [3u8; 16];

        let fast = derive_key_with_stored_params(8_192, 1, 1, password, &salt, 32).unwrap();
        let different = derive_key_with_stored_params(16_384, 1, 1, password, &salt, 32).unwrap();

        assert_ne!(&fast[..], &different[..]);
    }

    #[test]
    fn test_output_len_is_honored_per_profile() {
        // Argon2 requires salt >= 8 bytes; use a 16-byte salt.
        let salt = [5u8; 16];
        let key16 = derive_key_with_stored_params(8_192, 1, 1, b"pw", &salt, 16).unwrap();
        let key64 = derive_key_with_stored_params(8_192, 1, 1, b"pw", &salt, 64).unwrap();
        assert_eq!(key16.len(), 16);
        assert_eq!(key64.len(), 64);
        assert_ne!(&key16[..], &key64[..16]);
    }

    #[test]
    fn test_profile_ids_are_stable_and_roundtrip() {
        // Persisted ids: 0 = Interactive, 1 = Vault, 2 = Room. These values
        // may never change — they live inside written keyring envelopes.
        assert_eq!(Profile::Interactive.id(), 0);
        assert_eq!(Profile::Vault.id(), 1);
        assert_eq!(Profile::Room.id(), 2);
        assert_eq!(Profile::from_id(0), Some(Profile::Interactive));
        assert_eq!(Profile::from_id(1), Some(Profile::Vault));
        assert_eq!(Profile::from_id(2), Some(Profile::Room));
        // Unknown ids are rejected outright (no default fallback).
        assert_eq!(Profile::from_id(3), None);
        assert_eq!(Profile::from_id(u8::MAX), None);

        // The Room profile is the wasm-safe single-lane class.
        assert_eq!(Profile::Room.costs(), (65_536, 3, 1));
    }

    #[test]
    fn test_blanket_duplication_gate_none_in_this_module_by_construction() {
        // The §D7 acceptance gate is `rg -n 'Params::new\(\s*[0-9]' src/` → 0
        // outside tallow-crypto. Inside this module the two cost tables are the
        // named profiles; no bare numeric `Params::new` may creep back in.
        let src = include_str!("argon2.rs");
        let code = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(
            !code.contains("Params::new(\n        16_384"),
            "test params must not leak into production code paths"
        );
        // Exactly the three named profiles own the costs.
        assert!(code.contains("pub const MEMORY_COST: u32 = 262_144;"));
        assert!(code.contains("pub const VAULT_MEMORY_COST: u32 = 65_536;"));
        assert!(code.contains("pub const ROOM_MEMORY_COST: u32 = 65_536;"));
    }
}
