//! Encrypted vault sharing + Shamir threshold recovery.
//!
//! - `encrypt_for_recipient` / `decrypt_shared_entry` — Ed25519-to-X25519 ECDH,
//!   AES-256-GCM envelope encryption for sending a single entry to a known peer.
//! - `create_ephemeral_send` / `access_ephemeral_send` — time-limited, access-
//!   counted encrypted payloads (like Bitwarden Send).
//! - `split_master_key` / `recover_master_key` — Shamir secret sharing over GF(256).

use serde::{Deserialize, Serialize};

use super::entry::VaultEntry;

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

// ── Data Structures ─────────────────────────────────────────────────────────

/// A vault entry encrypted for a specific recipient via ECDH + AES-256-GCM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedEntry {
    /// AES-256-GCM ciphertext of the JSON-serialised VaultEntry (hex).
    pub encrypted_data: String,
    /// AES-256-GCM-encrypted random key, keyed by the ECDH shared secret (hex).
    pub encrypted_key: String,
    /// Nonce used for data encryption (hex).
    pub data_nonce: String,
    /// Nonce used for key encryption (hex).
    pub key_nonce: String,
    /// Sender Ed25519 public key (hex).
    pub sender_pk: String,
    /// Recipient Ed25519 public key (hex).
    pub recipient_pk: String,
    /// ISO-8601 timestamp.
    pub timestamp: String,
}

/// A time-limited, access-counted encrypted payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralSend {
    /// Random identifier (hex).
    pub id: String,
    /// AES-256-GCM ciphertext (hex).
    pub encrypted_data: String,
    /// Argon2id salt (hex) — only meaningful when password-protected.
    pub salt: String,
    /// AES-256-GCM nonce (hex).
    pub nonce: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// ISO-8601 expiration timestamp.
    pub expire_at: String,
    /// Maximum number of accesses allowed.
    pub max_access: u32,
    /// Current access count (mutable on access).
    pub access_count: u32,
    /// Whether a password is required for decryption.
    pub password_protected: bool,
}

/// One share produced by Shamir secret splitting.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyShare {
    /// Share index (1-based, corresponds to GF(256) evaluation point).
    pub index: u8,
    /// Share data (hex-encoded byte vector, same length as the secret).
    pub data: String,
    /// Minimum shares required for reconstruction.
    pub threshold: u8,
    /// Total shares generated.
    pub total_shares: u8,
}

impl std::fmt::Debug for KeyShare {
    /// Hand-written: share material is redacted (A6.1.1 sweep).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyShare")
            .field("index", &self.index)
            .field("data", &"[redacted]")
            .field("threshold", &self.threshold)
            .field("total_shares", &self.total_shares)
            .finish()
    }
}

impl Drop for KeyShare {
    /// Zeroize-on-drop (A6.1.1 sweep): share material is wiped.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.data.zeroize();
    }
}

// ── ECDH Sharing ────────────────────────────────────────────────────────────

/// Encrypt a vault entry for a specific recipient.
///
/// 1. Convert sender/recipient Ed25519 keys to X25519 (via clamped SHA-512).
/// 2. Perform X25519 ECDH to derive a shared secret.
/// 3. Generate a random 32-byte AES key, encrypt the entry JSON with AES-256-GCM.
/// 4. Encrypt the random key with another AES-256-GCM using the ECDH shared secret.
pub fn encrypt_for_recipient(
    entry: &VaultEntry,
    recipient_pk_hex: &str,
) -> Result<SharedEntry, String> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};

    // --- sender keypair (ephemeral for each share) ---
    let sender_secret = x25519_dalek::StaticSecret::random_from_rng(rand_core_06::OsRng);
    let sender_x_public = x25519_dalek::PublicKey::from(&sender_secret);

    // --- recipient X25519 public key from hex ---
    let recipient_pk_bytes = hex_decode(recipient_pk_hex)?;
    if recipient_pk_bytes.len() != 32 {
        return Err(format!(
            "recipient public key must be 32 bytes, got {}",
            recipient_pk_bytes.len()
        ));
    }
    let mut rpk = [0u8; 32];
    rpk.copy_from_slice(&recipient_pk_bytes);
    let recipient_x_pk = x25519_dalek::PublicKey::from(rpk);

    // --- ECDH shared secret, stretched through BLAKE3 ---
    let shared_raw = sender_secret.diffie_hellman(&recipient_x_pk);
    let shared_key_hash = blake3::hash(shared_raw.as_bytes());
    let shared_key = shared_key_hash.as_bytes(); // 32 bytes

    // --- encrypt entry JSON with random AES key ---
    let entry_json =
        serde_json::to_string(entry).map_err(|e| format!("failed to serialise entry: {e}"))?;

    let mut random_key = [0u8; 32];
    rand::Rng::fill(&mut rand::rng(), &mut random_key);

    let data_nonce: Vec<u8> = (0..12).map(|_| rand::random::<u8>()).collect();
    let data_cipher = Aes256Gcm::new(GenericArray::from_slice(&random_key));
    let ciphertext = data_cipher
        .encrypt(
            GenericArray::from_slice(&data_nonce),
            entry_json.as_bytes(),
        )
        .map_err(|e| format!("data encryption failed: {e}"))?;

    // --- encrypt random key with ECDH shared key ---
    let key_nonce: Vec<u8> = (0..12).map(|_| rand::random::<u8>()).collect();
    let key_cipher = Aes256Gcm::new(GenericArray::from_slice(shared_key));
    let encrypted_key = key_cipher
        .encrypt(
            GenericArray::from_slice(&key_nonce),
            random_key.as_ref(),
        )
        .map_err(|e| format!("key encryption failed: {e}"))?;

    Ok(SharedEntry {
        encrypted_data: hex_encode(&ciphertext),
        encrypted_key: hex_encode(&encrypted_key),
        data_nonce: hex_encode(&data_nonce),
        key_nonce: hex_encode(&key_nonce),
        sender_pk: hex_encode(sender_x_public.as_bytes()),
        recipient_pk: recipient_pk_hex.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

/// Decrypt a shared entry using your X25519 private key (hex-encoded, 32 bytes).
pub fn decrypt_shared_entry(
    shared: &SharedEntry,
    sk_hex: &str,
) -> Result<VaultEntry, String> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};

    let sk_bytes = hex_decode(sk_hex)?;
    if sk_bytes.len() != 32 {
        return Err(format!(
            "private key must be 32 bytes, got {}",
            sk_bytes.len()
        ));
    }
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&sk_bytes);
    let recipient_secret = x25519_dalek::StaticSecret::from(sk_arr);

    let sender_pk_bytes = hex_decode(&shared.sender_pk)?;
    if sender_pk_bytes.len() != 32 {
        return Err(format!(
            "sender public key must be 32 bytes, got {}",
            sender_pk_bytes.len()
        ));
    }
    let mut spk = [0u8; 32];
    spk.copy_from_slice(&sender_pk_bytes);
    let sender_x_pk = x25519_dalek::PublicKey::from(spk);

    // --- reproduce ECDH shared secret ---
    let shared_raw = recipient_secret.diffie_hellman(&sender_x_pk);
    let shared_key_hash = blake3::hash(shared_raw.as_bytes());
    let shared_key = shared_key_hash.as_bytes();

    // --- decrypt the random AES key ---
    let encrypted_key_bytes = hex_decode(&shared.encrypted_key)?;
    let key_nonce = hex_decode(&shared.key_nonce)?;
    if key_nonce.len() != 12 {
        return Err(format!(
            "key nonce must be 12 bytes, got {}",
            key_nonce.len()
        ));
    }
    let key_cipher = Aes256Gcm::new(GenericArray::from_slice(shared_key));
    let random_key = key_cipher
        .decrypt(
            GenericArray::from_slice(&key_nonce),
            encrypted_key_bytes.as_ref(),
        )
        .map_err(|e| format!("key decryption failed: {e}"))?;

    if random_key.len() != 32 {
        return Err(format!(
            "decrypted key must be 32 bytes, got {}",
            random_key.len()
        ));
    }

    // --- decrypt entry JSON ---
    let ciphertext = hex_decode(&shared.encrypted_data)?;
    let data_nonce = hex_decode(&shared.data_nonce)?;
    if data_nonce.len() != 12 {
        return Err(format!(
            "data nonce must be 12 bytes, got {}",
            data_nonce.len()
        ));
    }
    let data_cipher = Aes256Gcm::new(GenericArray::from_slice(&random_key));
    let plaintext = data_cipher
        .decrypt(
            GenericArray::from_slice(&data_nonce),
            ciphertext.as_ref(),
        )
        .map_err(|e| format!("data decryption failed: {e}"))?;

    let json_str = String::from_utf8(plaintext)
        .map_err(|e| format!("decrypted data is not valid UTF-8: {e}"))?;

    serde_json::from_str(&json_str).map_err(|e| format!("failed to parse entry JSON: {e}"))
}

// ── Ephemeral Send ──────────────────────────────────────────────────────────

/// Create an encrypted, time-limited, access-counted payload.
///
/// A password is REQUIRED: the encryption key is derived from the password
/// via Argon2id with a fresh random salt. Passwordless sends are deliberately
/// NOT supported — a key deterministically derived from the stored salt would
/// be obfuscation, not encryption (anyone holding the struct could decrypt
/// without a secret).
pub fn create_ephemeral_send(
    data: &str,
    password: Option<&str>,
    expire_hours: u32,
    max_access: u32,
) -> Result<EphemeralSend, String> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};

    let pw = password.ok_or_else(|| {
        "ephemeral send requires a password — no-password sends are not supported \
         (a key derived from the public salt would be obfuscation, not encryption)"
            .to_string()
    })?;
    if pw.is_empty() {
        return Err("ephemeral send password must not be empty".into());
    }

    let id: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();
    let salt: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();
    let nonce: Vec<u8> = (0..12).map(|_| rand::random::<u8>()).collect();

    // Derive the key from the password via Argon2id (real KDF)
    let mut key = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(pw.as_bytes(), &salt, &mut key)
        .map_err(|e| format!("key derivation failed: {e}"))?;

    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let ciphertext = cipher
        .encrypt(GenericArray::from_slice(&nonce), data.as_bytes())
        .map_err(|e| format!("encryption failed: {e}"))?;

    let now = chrono::Utc::now();
    let expire = now + chrono::Duration::hours(expire_hours as i64);

    Ok(EphemeralSend {
        id: hex_encode(&id),
        encrypted_data: hex_encode(&ciphertext),
        salt: hex_encode(&salt),
        nonce: hex_encode(&nonce),
        created_at: now.to_rfc3339(),
        expire_at: expire.to_rfc3339(),
        max_access,
        access_count: 0,
        password_protected: true, // always password-protected (see above)
    })
}

/// Decrypt an ephemeral send, enforcing expiry and access-count limits.
///
/// On success the `access_count` on the provided send IS incremented (the
/// struct is borrowed mutably) — the caller should persist the updated count.
/// Returns the decrypted payload.
pub fn access_ephemeral_send(
    send: &mut EphemeralSend,
    password: Option<&str>,
) -> Result<String, String> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};

    // --- expiry check ---
    let now = chrono::Utc::now();
    if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(&send.expire_at) {
        if now > exp {
            return Err("ephemeral send has expired".into());
        }
    }

    // --- access-count check ---
    if send.access_count >= send.max_access {
        return Err(format!(
            "maximum access count reached ({}/{})",
            send.access_count, send.max_access
        ));
    }

    // --- password check (all sends are password-protected) ---
    let pw = password.ok_or_else(|| "this send requires a password".to_string())?;

    let salt = hex_decode(&send.salt)?;
    let nonce = hex_decode(&send.nonce)?;
    let ciphertext = hex_decode(&send.encrypted_data)?;

    if nonce.len() != 12 {
        return Err(format!("nonce must be 12 bytes, got {}", nonce.len()));
    }

    // Derive the key from the password via Argon2id (must match creation)
    let mut key = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(pw.as_bytes(), &salt, &mut key)
        .map_err(|e| format!("key derivation failed: {e}"))?;

    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let plaintext = cipher
        .decrypt(GenericArray::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|e| format!("decryption failed (wrong password?): {e}"))?;

    // Increment the access count on success (previously checked but never
    // incremented — the enforcement was silently ineffective).
    send.access_count = send.access_count.saturating_add(1);

    String::from_utf8(plaintext).map_err(|e| format!("decrypted data is not valid UTF-8: {e}"))
}

// ── Shamir Secret Sharing — GF(256) ────────────────────────────────────────

/// GF(256) multiplication using the Russian peasant algorithm with the
/// irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    while b > 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    result
}

/// GF(256) multiplicative inverse via Fermat's little theorem: a^254 = a^(-1).
fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let mut result = a;
    for _ in 0..6 {
        result = gf256_mul(result, result);
        result = gf256_mul(result, a);
    }
    result = gf256_mul(result, result);
    result
}

/// Evaluate a polynomial at `x` in GF(256).
///
/// `coeffs[0]` is the constant term (the secret byte).
fn gf256_eval(coeffs: &[u8], x: u8) -> u8 {
    let mut result: u8 = 0;
    let mut x_pow: u8 = 1;
    for &c in coeffs {
        result ^= gf256_mul(c, x_pow);
        x_pow = gf256_mul(x_pow, x);
    }
    result
}

/// Split `master_key` into `shares` shares with a reconstruction `threshold`.
///
/// Uses real Shamir secret sharing over GF(256): for each byte of the key a
/// random polynomial of degree `threshold - 1` is generated with the byte as
/// the constant term.
pub fn split_master_key(
    master_key: &[u8],
    threshold: u8,
    shares: u8,
) -> Result<Vec<KeyShare>, String> {
    if threshold < 1 {
        return Err("threshold must be >= 1".into());
    }
    if threshold > shares {
        return Err(format!(
            "threshold ({threshold}) must be <= shares ({shares})"
        ));
    }
    if shares < 2 {
        return Err("shares must be >= 2".into());
    }
    if master_key.is_empty() {
        return Err("master key must not be empty".into());
    }

    let n = shares as usize;
    let t = threshold as usize;
    let mut share_data: Vec<Vec<u8>> = vec![Vec::with_capacity(master_key.len()); n];

    for &byte in master_key {
        // Build random polynomial: coeffs[0] = byte, coeffs[1..t] = random
        let mut coeffs = vec![byte];
        for _ in 1..t {
            coeffs.push(rand::random::<u8>());
        }
        for i in 0..n {
            let x = (i + 1) as u8; // evaluation points 1..n
            let y = gf256_eval(&coeffs, x);
            share_data[i].push(y);
        }
    }

    let result: Vec<KeyShare> = share_data
        .into_iter()
        .enumerate()
        .map(|(i, data)| KeyShare {
            index: (i + 1) as u8,
            data: hex_encode(&data),
            threshold,
            total_shares: shares,
        })
        .collect();

    Ok(result)
}

/// Reconstruct the master key from at least `threshold` shares via Lagrange
/// interpolation in GF(256).
pub fn recover_master_key(shares: &[KeyShare]) -> Result<Vec<u8>, String> {
    if shares.is_empty() {
        return Err("need at least one share".into());
    }

    let threshold = shares[0].threshold as usize;
    if shares.len() < threshold {
        return Err(format!(
            "need at least {threshold} shares, got {}",
            shares.len()
        ));
    }

    // Decode hex data for each share.
    let decoded: Vec<(u8, Vec<u8>)> = shares
        .iter()
        .take(threshold)
        .map(|s| {
            let data = hex_decode(&s.data)?;
            Ok((s.index, data))
        })
        .collect::<Result<Vec<_>, String>>()?;

    let secret_len = decoded[0].1.len();
    for (_, d) in &decoded {
        if d.len() != secret_len {
            return Err("all shares must have the same length".into());
        }
    }

    let mut secret = Vec::with_capacity(secret_len);

    for byte_idx in 0..secret_len {
        let mut result: u8 = 0;

        for (i, (xi, data_i)) in decoded.iter().enumerate() {
            let yi = data_i[byte_idx];
            let mut basis: u8 = 1;

            for (j, (xj, _)) in decoded.iter().enumerate() {
                if i == j {
                    continue;
                }
                // basis *= (0 - xj) / (xi - xj)  in GF(256)
                // 0 - xj = xj  (additive inverse is identity in GF(2^k))
                let num = *xj;
                let den = *xi ^ *xj;
                if den == 0 {
                    return Err("duplicate share indices".into());
                }
                basis = gf256_mul(basis, gf256_mul(num, gf256_inv(den)));
            }

            result ^= gf256_mul(yi, basis);
        }

        secret.push(result);
    }

    Ok(secret)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::entry::VaultEntry;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let entry = VaultEntry::new_login("test", "user", "pw", vec!["https://x.com".into()]);

        // Generate a recipient X25519 keypair.
        let recipient_secret = x25519_dalek::StaticSecret::random_from_rng(rand_core_06::OsRng);
        let recipient_public = x25519_dalek::PublicKey::from(&recipient_secret);

        let shared = encrypt_for_recipient(&entry, &hex_encode(recipient_public.as_bytes()))
            .expect("encrypt");

        let decrypted =
            decrypt_shared_entry(&shared, &hex_encode(recipient_secret.as_ref()))
                .expect("decrypt");

        assert_eq!(decrypted.name, "test");
    }

    #[test]
    fn ephemeral_send_with_password() {
        let mut send = create_ephemeral_send("secret data", Some("hunter2"), 24, 3).expect("create");
        assert!(send.password_protected);

        let plain = access_ephemeral_send(&mut send, Some("hunter2")).expect("access");
        assert_eq!(plain, "secret data");
        // access_count is incremented by the access call itself
        assert_eq!(send.access_count, 1);
    }

    #[test]
    fn ephemeral_send_wrong_password() {
        let mut send = create_ephemeral_send("secret data", Some("hunter2"), 24, 3).expect("create");
        let result = access_ephemeral_send(&mut send, Some("wrong"));
        assert!(result.is_err());
        assert_eq!(send.access_count, 0, "failed access must not increment the count");
    }

    #[test]
    fn ephemeral_send_requires_password() {
        // No-password sends are obfuscation, not encryption — they must be
        // rejected outright (previously a deterministic key was derived from
        // the stored salt, decryptable by anyone holding the struct).
        let err = create_ephemeral_send("hello", None, 1, 5).unwrap_err();
        assert!(
            err.contains("password"),
            "error should mention password: {err}"
        );
    }

    #[test]
    fn ephemeral_send_expired() {
        let mut send = create_ephemeral_send("x", Some("pw"), 1, 5).expect("create");
        send.expire_at = "2020-01-01T00:00:00Z".to_string();
        let result = access_ephemeral_send(&mut send, Some("pw"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }

    #[test]
    fn ephemeral_send_access_exhausted() {
        let mut send = create_ephemeral_send("x", Some("pw"), 1, 2).expect("create");
        send.access_count = 2;
        let result = access_ephemeral_send(&mut send, Some("pw"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("maximum access count"));
    }

    #[test]
    fn shamir_split_recover_roundtrip() {
        let key = b"this is a 32-byte master key!!!";
        let shares = split_master_key(key, 3, 5).expect("split");
        assert_eq!(shares.len(), 5);

        // Use shares 1, 3, 5 (any 3 of 5).
        let subset = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = recover_master_key(&subset).expect("recover");
        assert_eq!(recovered, key);
    }

    #[test]
    fn shamir_insufficient_shares_fails() {
        let key = b"secret";
        let shares = split_master_key(key, 3, 5).expect("split");
        let subset = vec![shares[0].clone(), shares[1].clone()];
        let result = recover_master_key(&subset);
        assert!(result.is_err());
    }

    #[test]
    fn shamir_threshold_1() {
        let key = b"open secret";
        let shares = split_master_key(key, 1, 3).expect("split");
        // Any single share should recover the key.
        let recovered = recover_master_key(&[shares[2].clone()]).expect("recover");
        assert_eq!(recovered, key);
    }

    #[test]
    fn shamir_all_shares() {
        let key = b"full set";
        let shares = split_master_key(key, 4, 4).expect("split");
        let recovered = recover_master_key(&shares).expect("recover");
        assert_eq!(recovered, key);
    }

    #[test]
    fn shamir_invalid_params() {
        assert!(split_master_key(b"x", 3, 2).is_err()); // threshold > shares
        assert!(split_master_key(b"x", 0, 3).is_err()); // threshold 0
        assert!(split_master_key(b"x", 2, 1).is_err()); // shares < 2
        assert!(split_master_key(b"", 2, 3).is_err()); // empty key
    }

    #[test]
    fn key_share_debug_redacts_share_material() {
        let share = KeyShare {
            index: 1,
            data: "deadbeefcafebabe".to_string(),
            threshold: 3,
            total_shares: 5,
        };
        let dbg = format!("{share:?}");
        assert!(dbg.contains("[redacted]"), "{dbg}");
        assert!(!dbg.contains("deadbeefcafebabe"), "{dbg}");
    }
}
