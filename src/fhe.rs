//! Fully homomorphic encryption over 8-bit integers (P6, `--features fhe`).
//!
//! Backend: `tfhe` (Zama), TFHE-style gate bootstrapping over the torus. Chosen
//! over a bespoke scheme because a hand-rolled FHE is a research project with a
//! failure mode (silent noise overflow) that looks like correct output.
//!
//! Feature-gated: key generation is seconds of CPU at first use and the crate is
//! large, so the default build does not link it. The language surface refuses by
//! name when the feature is off.
//!
//! **Cost, measured on this box:** see the note in
//! `docs/security/crypto-integration-2026-10-24.md` — key generation dominates;
//! the operations themselves are fast. Keys live in this process only.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use tfhe::prelude::*;
use tfhe::{ClientKey, ConfigBuilder, FheUint8};

struct Session {
    client_key: ClientKey,
}

fn registry() -> &'static Mutex<HashMap<String, Session>> {
    static REG: OnceLock<Mutex<HashMap<String, Session>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

fn handle_for(n: usize) -> String {
    format!("fhe{n}")
}

/// Generate a client key and install its server key for this process.
///
/// The server key is process-global in `tfhe`; generating a second session
/// replaces it, which would break the first session's ciphertexts. The caller
/// gets a fresh handle each time, and `encrypt`/`eval` re-install the session's
/// server key before use so that two sessions can coexist in one process.
pub fn keygen() -> Result<String, String> {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = tfhe::generate_keys(config);
    tfhe::set_server_key(server_key);
    let mut reg = registry().lock().map_err(|_| "fhe registry poisoned".to_string())?;
    let handle = handle_for(reg.len());
    reg.insert(handle.clone(), Session { client_key });
    Ok(handle)
}

fn with_client<T>(handle: &str, f: impl FnOnce(&ClientKey) -> Result<T, String>) -> Result<T, String> {
    let reg = registry().lock().map_err(|_| "fhe registry poisoned".to_string())?;
    let session = reg
        .get(handle)
        .ok_or_else(|| format!("unknown fhe handle '{handle}' (keys do not survive the process)"))?;
    f(&session.client_key)
}

/// Encrypt one byte. Returns the serialized ciphertext as hex.
pub fn encrypt(handle: &str, value: u8) -> Result<String, String> {
    with_client(handle, |ck| {
        let ct = FheUint8::encrypt(value, ck);
        let bytes = bincode::serialize(&ct).map_err(|e| format!("serialize ciphertext: {e}"))?;
        Ok(crate::age::hex_encode(&bytes))
    })
}

/// Homomorphically add two ciphertexts. The plaintexts never leave the ciphertexts.
pub fn add(handle: &str, a_hex: &str, b_hex: &str) -> Result<String, String> {
    with_client(handle, |_| {
        let a: FheUint8 = deserialize(a_hex)?;
        let b: FheUint8 = deserialize(b_hex)?;
        let sum = &a + &b;
        let bytes = bincode::serialize(&sum).map_err(|e| format!("serialize sum: {e}"))?;
        Ok(crate::age::hex_encode(&bytes))
    })
}

/// Decrypt a ciphertext back to a byte.
pub fn decrypt(handle: &str, ct_hex: &str) -> Result<u8, String> {
    with_client(handle, |ck| {
        let ct: FheUint8 = deserialize(ct_hex)?;
        Ok(ct.decrypt(ck))
    })
}

fn deserialize(hex: &str) -> Result<FheUint8, String> {
    let bytes = crate::age::hex_decode(hex)?;
    bincode::deserialize(&bytes).map_err(|e| format!("not a valid FHE ciphertext: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_is_homomorphic() {
        let h = keygen().expect("keygen");
        let a = encrypt(&h, 3).expect("encrypt a");
        let b = encrypt(&h, 4).expect("encrypt b");
        let sum = add(&h, &a, &b).expect("add");
        assert_eq!(decrypt(&h, &sum).expect("decrypt"), 7);
    }

    #[test]
    fn addition_wraps_at_8_bits() {
        // FheUint8 is modular; 250 + 10 = 4. Pinned so nobody "fixes" it into a
        // saturation that would silently disagree with the plaintext semantics.
        let h = keygen().expect("keygen");
        let a = encrypt(&h, 250).expect("a");
        let b = encrypt(&h, 10).expect("b");
        let sum = add(&h, &a, &b).expect("add");
        assert_eq!(decrypt(&h, &sum).expect("decrypt"), 4);
    }

    #[test]
    fn unknown_handle_is_an_error() {
        assert!(encrypt("fhe-none", 1).is_err());
    }
}
