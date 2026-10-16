//! Cryptographic key management

pub mod ephemeral;
pub mod identity;
pub mod prekeys;
pub mod rotation;
pub mod storage;

pub use ephemeral::EphemeralKeyPair;
pub use identity::{id_for_public_key, IdentityKeyPair};
pub use prekeys::{OneTimePreKey, PreKeyBundle, SignedPreKey};
pub use rotation::KeyRotationRecord;
pub use storage::{
    decrypt_keyring, decrypt_keyring_v2, decrypt_opened_keyring, encrypt_keyring,
    encrypt_keyring_v2, open_keyring, EncryptedKeyring, EncryptedKeyringV2, OpenedKeyring,
    KEYRING_V2_MAGIC, KEYRING_V2_VERSION,
};
