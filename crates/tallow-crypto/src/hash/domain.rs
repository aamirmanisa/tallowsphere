//! Domain separation constants for cryptographic operations
//!
//! These constants ensure that cryptographic operations in different contexts
//! produce different outputs, even with the same inputs.

/// Domain separator for file encryption operations
pub const DOMAIN_FILE_ENC: &str = "tallow.file.encryption.v1";

/// Domain separator for chat message encryption
pub const DOMAIN_CHAT_ENC: &str = "tallow.chat.encryption.v1";

/// Domain separator for authentication
pub const DOMAIN_AUTH: &str = "tallow.authentication.v1";

/// Domain separator for key derivation functions
pub const DOMAIN_KDF: &str = "tallow.kdf.v1";

/// Domain separator for key encapsulation
pub const DOMAIN_KEM: &str = "tallow.kem.v1";

/// Domain separator for signatures
pub const DOMAIN_SIG: &str = "tallow.signature.v1";

/// Domain separator for PAKE protocols
pub const DOMAIN_PAKE: &str = "tallow.pake.v1";

/// Domain separator for ratcheting operations
pub const DOMAIN_RATCHET: &str = "tallow.ratchet.v1";

/// Domain separator for metadata encryption
pub const DOMAIN_METADATA: &str = "tallow.metadata.v1";

/// Domain separator for chunk encryption
pub const DOMAIN_CHUNK: &str = "tallow.chunk.v1";

/// Domain separator for header encryption
pub const DOMAIN_HEADER: &str = "tallow.header.v1";

/// Domain separator for nonce derivation
pub const DOMAIN_NONCE: &str = "tallow.nonce.v1";

/// Domain separator for key confirmation
pub const DOMAIN_KEY_CONFIRM: &str = "tallow.key_confirmation.v1";

/// Domain separator for pre-key signing
pub const DOMAIN_PREKEY_SIG: &str = "tallow.prekey.signature.v1";

/// Domain separator for ephemeral key derivation
pub const DOMAIN_EPHEMERAL: &str = "tallow.ephemeral.v1";

/// Domain separator for room key derivation
pub const DOMAIN_ROOM: &str = "tallow.room.v1";

/// Domain separator for hybrid key combination
pub const DOMAIN_HYBRID_COMBINE: &str = "tallow.hybrid.combine.v1";

/// Domain separator for password hashing
pub const DOMAIN_PASSWORD: &str = "tallow.password.v1";

/// Domain separator for SAS (Short Authentication String) generation
pub const DOMAIN_SAS: &str = "tallow.sas.v1";

/// Domain separator for handshake transcript hashing
pub const DOMAIN_HANDSHAKE_TRANSCRIPT: &str = "tallow.handshake.transcript.v1";

/// Domain separator for the v5+ handshake identity signature
/// (`HandshakeSigned`): the signed input binds the signer role and the
/// completed transcript hash.
pub const DOMAIN_HANDSHAKE_SIGNED: &str = "tallow.handshake.signed.v1";

/// Domain separator for session key derivation from KEM + PAKE
pub const DOMAIN_SESSION_KEY_KEM_PAKE: &str = "tallow.session_key.kem_pake.v3";

/// Domain separator for sender key confirmation tag
pub const DOMAIN_KEY_CONFIRM_SENDER: &str = "tallow.key_confirm.sender.v1";

/// Domain separator for receiver key confirmation tag
pub const DOMAIN_KEY_CONFIRM_RECEIVER: &str = "tallow.key_confirm.receiver.v1";

/// Domain separator for safety number generation (iterated BLAKE3)
pub const DOMAIN_SAFETY_NUMBER: &str = "tallow.safety_number.v1";

/// Domain separator for sealed sender envelope encryption
pub const DOMAIN_SEALED_SENDER: &str = "tallow.sealed_sender.v1";

/// Domain separator for the send chain key in the double ratchet
pub const DOMAIN_RATCHET_SEND_CHAIN: &str = "tallow.ratchet.send_chain.v1";

/// Domain separator for the receive chain key in the double ratchet
pub const DOMAIN_RATCHET_RECV_CHAIN: &str = "tallow.ratchet.recv_chain.v1";
