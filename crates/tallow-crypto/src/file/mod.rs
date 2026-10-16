//! File encryption and decryption

pub mod decrypt;
pub mod encrypt;

pub use decrypt::{decrypt_chunk, decrypt_chunk_scoped, FileDecryptor};
pub use encrypt::{
    derive_transfer_subkey, encrypt_chunk, encrypt_chunk_scoped, EncryptedChunk, FileEncryptor,
    TRANSFER_NONCE_DOMAIN, TRANSFER_SUBKEY_DOMAIN,
};
