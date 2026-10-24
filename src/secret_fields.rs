//! Fields that must never be rendered by `print()` or any display path.
//!
//! A struct returned by the crypto surface carries both public and secret
//! material — `AgeKeypair.recipient` is public, `.identity` is the private key.
//! `print(kp)` therefore used to write the secret key to stdout, which is the
//! "no secret in Display" rule failing on a surface the standard library
//! actually exposes.
//!
//! This table is the single source of truth for both planes. Adding a field
//! here redacts it everywhere; it never changes the value a caller can read
//! through field access, only what a display path is willing to show.

/// `(struct name, field name)` pairs whose values are secret material.
pub const SECRET_FIELDS: &[(&str, &str)] = &[
    // age (C2SP)
    ("AgeKeypair", "identity"),
    // OPAQUE (RFC 9807)
    ("OpaqueRegistration", "state"),
    ("OpaqueRegistrationUpload", "export_key"),
    ("OpaqueLoginRequest", "state"),
    ("OpaqueLoginResponse", "state"),
    ("OpaqueLoginResult", "session_key"),
    ("OpaqueLoginResult", "export_key"),
    // Signature / KEM keypairs returned by crypto.generate_keypair and the
    // post-quantum generators. These were dumping raw private keys.
    ("KeyPair", "private_key"),
    ("MlDsaKeyPair", "secret_key"),
    ("SlhDsaKeyPair", "secret_key"),
    ("FalconKeyPair", "secret_key"),
    ("FrodoKemKeyPair", "secret_key"),
    ("McElieceKeyPair", "secret_key"),
    ("HpkeKeypair", "secret_key"),
    ("VrfKeyPair", "secret_key"),
    ("BlsKeyPair", "secret_key"),
];

/// Text substituted for a redacted field.
pub const REDACTED: &str = "<redacted>";

pub fn is_secret(struct_name: &str, field: &str) -> bool {
    SECRET_FIELDS
        .iter()
        .any(|(s, f)| *s == struct_name && *f == field)
}
