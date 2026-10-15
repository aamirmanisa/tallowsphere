//! Chat message types

use serde::{Deserialize, Serialize};

/// Chat message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Message ID
    pub id: String,
    /// Sender ID
    pub sender: String,
    /// Message text
    pub text: String,
    /// Timestamp (Unix seconds)
    pub timestamp: u64,
    /// Encrypted flag
    pub encrypted: bool,
}

impl ChatMessage {
    /// Create a new plaintext chat message
    pub fn new(sender: String, text: String) -> Self {
        Self {
            id: generate_message_id(),
            sender,
            text,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            encrypted: false,
        }
    }

    /// Create an encrypted chat message
    ///
    /// The `ciphertext` parameter should contain the hex-encoded encrypted bytes.
    pub fn new_encrypted(sender: String, ciphertext: String) -> Self {
        Self {
            id: generate_message_id(),
            sender,
            text: ciphertext,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            encrypted: true,
        }
    }
}

/// Generate a random message ID (hex-encoded 16 random bytes)
fn generate_message_id() -> String {
    let bytes: [u8; 16] = rand::random();
    bytes.iter().fold(String::with_capacity(32), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}
