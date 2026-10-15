//! REALITY-style TLS authentication for proxy tunnels.
//!
//! Implements covert proxy authentication inspired by the REALITY protocol
//! (XTLS/Xray-core). The proxy connection is indistinguishable from a genuine
//! TLS handshake to the impersonated server because the authentication material
//! is embedded inside the TLS ClientHello SessionId field -- a 32-byte opaque
//! blob that middleboxes and passive observers cannot distinguish from random.
//!
//! # Protocol overview
//!
//! 1. Client generates an ephemeral X25519 keypair.
//! 2. ECDH with the server's static public key produces a shared secret.
//! 3. The shared secret is expanded via HKDF-SHA256 (info = `"REALITY"`).
//! 4. A 32-byte SessionId is constructed:
//!    - bytes  0..3  : version + reserved
//!    - bytes  4..8  : Unix timestamp (big-endian u32)
//!    - bytes  8..16 : short_id (client identifier)
//!    - bytes 16..32 : HMAC-SHA256(derived_key, client_hello_prefix) truncated
//! 5. The server can verify the SessionId using the same derivation.
//! 6. Once authenticated, a symmetric tunnel key is derived and traffic is
//!    encrypted with ChaCha20-Poly1305.

use chacha20poly1305::aead::{Aead, KeyInit as AeadKeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

/// Helper: create an HMAC-SHA256 instance from a key slice.
///
/// Works around trait ambiguity between `KeyInit::new_from_slice` and
/// `Mac::new_from_slice` that arises when both are in scope.
fn hmac_from_key(key: &[u8]) -> HmacSha256 {
    <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length")
}

// ---------------------------------------------------------------------------
// RealityConfig
// ---------------------------------------------------------------------------

/// Configuration for a REALITY proxy tunnel.
#[derive(Clone, Debug)]
pub struct RealityConfig {
    /// Proxy server address (host:port).
    pub server_addr: String,
    /// Server's static X25519 public key (32 bytes).
    pub server_public_key: [u8; 32],
    /// 8-byte short identifier assigned to this client.
    pub short_id: [u8; 8],
    /// TLS SNI value to impersonate (e.g. `"www.microsoft.com"`).
    pub server_name: String,
}

// ---------------------------------------------------------------------------
// RealityAuth
// ---------------------------------------------------------------------------

/// Handles the authentication handshake for REALITY tunnels.
///
/// Generates authenticated TLS SessionId values and verifies server responses.
pub struct RealityAuth {
    config: RealityConfig,
    /// Ephemeral X25519 secret kept for the lifetime of the handshake.
    /// Stored as raw bytes so the struct remains `Send + Sync`.
    ephemeral_secret_bytes: [u8; 32],
    /// Our ephemeral public key (sent to the server out-of-band or embedded).
    pub ephemeral_public: [u8; 32],
}

impl RealityAuth {
    /// Create a new authenticator, generating a fresh ephemeral keypair.
    pub fn new(config: RealityConfig) -> Self {
        // Generate 32 random bytes and construct the secret from raw bytes
        // to avoid rand_core version conflicts between rand 0.9 and x25519-dalek.
        let mut secret_bytes = [0u8; 32];
        rand::fill(&mut secret_bytes);
        let static_secret = StaticSecret::from(secret_bytes);
        let static_public = PublicKey::from(&static_secret);

        Self {
            config,
            ephemeral_secret_bytes: static_secret.to_bytes(),
            ephemeral_public: *static_public.as_bytes(),
        }
    }

    // -- key derivation ------------------------------------------------------

    /// Perform X25519 ECDH with the server's public key and expand via
    /// HKDF-SHA256 with info string `"REALITY"`.
    pub fn derive_shared_secret(&self) -> [u8; 32] {
        let secret = StaticSecret::from(self.ephemeral_secret_bytes);
        let server_pk = PublicKey::from(self.config.server_public_key);
        let dh_output = secret.diffie_hellman(&server_pk);

        // HKDF extract + expand
        let hk = Hkdf::<Sha256>::new(None, dh_output.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(b"REALITY", &mut okm)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        okm
    }

    // -- session id generation -----------------------------------------------

    /// Build a 32-byte authenticated TLS SessionId.
    ///
    /// Layout:
    /// ```text
    /// [0]  version major  = 0
    /// [1]  version minor  = 1
    /// [2]  version patch  = 0
    /// [3]  reserved       = 0x00
    /// [4..8]  Unix timestamp (big-endian u32)
    /// [8..16] short_id
    /// [16..32] HMAC-SHA256(shared_secret, bytes[0..16]) truncated to 16 bytes
    /// ```
    pub fn generate_auth_session_id(&self) -> [u8; 32] {
        let shared = self.derive_shared_secret();

        let mut id = [0u8; 32];

        // Version
        id[0] = 0; // major
        id[1] = 1; // minor
        id[2] = 0; // patch
        id[3] = 0x00; // reserved

        // Timestamp
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        id[4..8].copy_from_slice(&ts.to_be_bytes());

        // Short ID
        id[8..16].copy_from_slice(&self.config.short_id);

        // HMAC over the first 16 bytes (the "client hello prefix")
        let mut mac = hmac_from_key(&shared);
        mac.update(&id[..16]);
        let tag = mac.finalize().into_bytes();
        id[16..32].copy_from_slice(&tag[..16]);

        id
    }

    // -- server verification -------------------------------------------------

    /// Verify a SessionId received from the server.
    ///
    /// The server constructs its response SessionId with the same layout; we
    /// recompute the HMAC over `session_id[0..16]` using our shared secret and
    /// compare the trailing 16 bytes in constant time.
    pub fn verify_server_response(&self, session_id: &[u8; 32]) -> bool {
        let shared = self.derive_shared_secret();

        let mut mac = hmac_from_key(&shared);
        mac.update(&session_id[..16]);

        // `verify_truncated_left` performs a constant-time comparison.
        mac.verify_truncated_left(&session_id[16..32]).is_ok()
    }
}

// ---------------------------------------------------------------------------
// RealityTunnel
// ---------------------------------------------------------------------------

/// An established REALITY tunnel providing ChaCha20-Poly1305 encryption.
pub struct RealityTunnel {
    pub config: RealityConfig,
    /// Symmetric key derived from the REALITY handshake.
    shared_key: [u8; 32],
}

impl RealityTunnel {
    /// Create a tunnel from a completed handshake.
    pub fn new(config: RealityConfig, shared_key: [u8; 32]) -> Self {
        Self { config, shared_key }
    }

    /// Derive a `RealityTunnel` directly from a `RealityAuth` after successful
    /// handshake verification.
    pub fn from_auth(auth: &RealityAuth) -> Self {
        let shared = auth.derive_shared_secret();

        // Derive a separate tunnel key so the authentication key and the
        // encryption key are never the same.
        let hk = Hkdf::<Sha256>::new(None, &shared);
        let mut tunnel_key = [0u8; 32];
        hk.expand(b"REALITY-TUNNEL", &mut tunnel_key)
            .expect("32 bytes is valid HKDF-SHA256 output length");

        Self {
            config: auth.config.clone(),
            shared_key: tunnel_key,
        }
    }

    /// Encrypt `plaintext` with ChaCha20-Poly1305.
    ///
    /// Returns ciphertext including the 16-byte Poly1305 authentication tag.
    pub fn encrypt_payload(&self, plaintext: &[u8], nonce: &[u8; 12]) -> Vec<u8> {
        let cipher = <ChaCha20Poly1305 as AeadKeyInit>::new_from_slice(&self.shared_key)
            .expect("key is 32 bytes");
        let nonce = Nonce::from_slice(nonce);
        cipher
            .encrypt(nonce, plaintext)
            .expect("ChaCha20-Poly1305 encryption should not fail")
    }

    /// Decrypt `ciphertext` (which must include the trailing auth tag).
    pub fn decrypt_payload(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>, String> {
        let cipher = <ChaCha20Poly1305 as AeadKeyInit>::new_from_slice(&self.shared_key)
            .expect("key is 32 bytes");
        let nonce = Nonce::from_slice(nonce);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("REALITY tunnel decryption failed: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> (RealityConfig, StaticSecret) {
        let mut secret_bytes = [0u8; 32];
        rand::fill(&mut secret_bytes);
        let server_secret = StaticSecret::from(secret_bytes);
        let server_public = PublicKey::from(&server_secret);

        let config = RealityConfig {
            server_addr: "127.0.0.1:443".into(),
            server_public_key: *server_public.as_bytes(),
            short_id: [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE],
            server_name: "www.microsoft.com".into(),
        };
        (config, server_secret)
    }

    #[test]
    fn session_id_layout() {
        let (config, _) = test_config();
        let auth = RealityAuth::new(config);
        let sid = auth.generate_auth_session_id();

        // Version bytes
        assert_eq!(sid[0], 0);
        assert_eq!(sid[1], 1);
        assert_eq!(sid[2], 0);
        assert_eq!(sid[3], 0x00);

        // Short ID
        assert_eq!(
            &sid[8..16],
            &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]
        );
    }

    #[test]
    fn self_verify() {
        let (config, _) = test_config();
        let auth = RealityAuth::new(config);
        let sid = auth.generate_auth_session_id();
        assert!(auth.verify_server_response(&sid));
    }

    #[test]
    fn tampered_session_id_rejected() {
        let (config, _) = test_config();
        let auth = RealityAuth::new(config);
        let mut sid = auth.generate_auth_session_id();
        sid[20] ^= 0xFF; // flip a byte in the HMAC region
        assert!(!auth.verify_server_response(&sid));
    }

    #[test]
    fn tunnel_round_trip() {
        let (config, _) = test_config();
        let auth = RealityAuth::new(config);
        let tunnel = RealityTunnel::from_auth(&auth);

        let plaintext = b"hello from the REALITY tunnel";
        let nonce: [u8; 12] = [1u8; 12];

        let ct = tunnel.encrypt_payload(plaintext, &nonce);
        let pt = tunnel.decrypt_payload(&ct, &nonce).expect("decrypt ok");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_nonce_fails() {
        let (config, _) = test_config();
        let auth = RealityAuth::new(config);
        let tunnel = RealityTunnel::from_auth(&auth);

        let ct = tunnel.encrypt_payload(b"secret", &[0u8; 12]);
        let result = tunnel.decrypt_payload(&ct, &[1u8; 12]);
        assert!(result.is_err());
    }
}
