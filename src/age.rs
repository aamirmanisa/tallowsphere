//! age (C2SP) container operations, shared by the interpreter stdlib and the
//! native FFI so both planes run the same code.
//!
//! The container is produced by the `age` crate: X25519 recipient stanzas,
//! HKDF-SHA-256, ChaCha20-Poly1305 in 64 KiB chunks, header MAC. Verified
//! against the reference `age(1)` binary in `tests/age_container.rs`.

use std::io::{Read, Write};

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let t = s.trim();
    if t.len() % 2 != 0 {
        return Err("crypto: hex input has an odd length".into());
    }
    let b = t.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char)
            .to_digit(16)
            .ok_or_else(|| "crypto: invalid hex digit".to_string())?;
        let lo = (b[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| "crypto: invalid hex digit".to_string())?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

pub fn keygen() -> (String, String) {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();
    let id = {
        use secrecy::ExposeSecret;
        identity.to_string().expose_secret().to_string()
    };
    (recipient.to_string(), id)
}

pub fn encrypt(recipient: &str, plaintext_hex: &str) -> Result<String, String> {
    let recipient: age::x25519::Recipient = recipient
        .parse()
        .map_err(|e| format!("crypto.age_encrypt: invalid recipient: {e}"))?;
    let pt = hex_decode(plaintext_hex)?;

    let encryptor = age::Encryptor::with_recipients(std::iter::once(&recipient as _))
        .map_err(|e| format!("crypto.age_encrypt: {e}"))?;
    let mut out = Vec::new();
    {
        let mut writer = encryptor
            .wrap_output(&mut out)
            .map_err(|e| format!("crypto.age_encrypt: {e}"))?;
        writer
            .write_all(&pt)
            .map_err(|e| format!("crypto.age_encrypt: {e}"))?;
        writer
            .finish()
            .map_err(|e| format!("crypto.age_encrypt: {e}"))?;
    }
    Ok(hex_encode(&out))
}

pub fn decrypt(identity: &str, ciphertext_hex: &str) -> Result<String, String> {
    let identity: age::x25519::Identity = identity
        .parse()
        .map_err(|e| format!("crypto.age_decrypt: invalid identity: {e}"))?;
    let ct = hex_decode(ciphertext_hex)?;

    let decryptor =
        age::Decryptor::new(&ct[..]).map_err(|e| format!("crypto.age_decrypt: {e}"))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as _))
        .map_err(|e| format!("crypto.age_decrypt: {e}"))?;
    let mut pt = Vec::new();
    reader
        .read_to_end(&mut pt)
        .map_err(|e| format!("crypto.age_decrypt: {e}"))?;
    Ok(hex_encode(&pt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let (recipient, identity) = keygen();
        let ct = encrypt(&recipient, "00ff10").expect("encrypt");
        assert_eq!(decrypt(&identity, &ct).expect("decrypt"), "00ff10");
    }

    #[test]
    fn tamper_is_rejected() {
        let (recipient, identity) = keygen();
        let ct = encrypt(&recipient, "01").expect("encrypt");
        let mut bytes = hex_decode(&ct).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(decrypt(&identity, &hex_encode(&bytes)).is_err());
    }
}
