//! C ABI for `crypto.generate_keypair`, so the native plane can lower it.
//!
//! Supports the two algorithms the interpreter implements inline: ed25519 and
//! x25519. Anything else fails with a message naming what is available — the
//! interpreter's ML-KEM arm already refuses with the same style, and a silent
//! substitute key type would be worse than either.
//!
//! The record layout mirrors `%struct.KeyPair` in `src/codegen.rs`:
//! algorithm @0, public_key @8, private_key @16 (all `*mut c_char`).

use std::ffi::{c_char, CString};

#[repr(C)]
pub struct KeyPairRaw {
    pub algorithm: *mut c_char,
    pub public_key: *mut c_char,
    pub private_key: *mut c_char,
}

fn cstring(s: String) -> *mut c_char {
    CString::new(s)
        .map(|c| c.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn hex(bytes: &[u8]) -> String {
    crate::opaque::hex(bytes)
}

fn fail(msg: String) -> *mut KeyPairRaw {
    crate::runtime::set_last_error(msg);
    std::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_generate_keypair(algo: *const c_char) -> *mut KeyPairRaw {
    let algo = if algo.is_null() {
        "ed25519".to_string()
    } else {
        match unsafe { std::ffi::CStr::from_ptr(algo) }.to_str() {
            Ok(s) if !s.is_empty() => s.to_string(),
            Ok(_) => "ed25519".to_string(),
            Err(_) => return fail("crypto.generate_keypair: algorithm is not valid UTF-8".into()),
        }
    };

    let (name, public, private) = match algo.as_str() {
        "ed25519" => {
            use ed25519_dalek::SigningKey;
            let sk = SigningKey::generate(&mut rand_core_06::OsRng);
            let pk = sk.verifying_key();
            ("ed25519", hex(pk.as_bytes()), hex(&sk.to_bytes()))
        }
        "x25519" => {
            use x25519_dalek::{PublicKey, StaticSecret};
            let secret = StaticSecret::random_from_rng(rand_core_06::OsRng);
            let public = PublicKey::from(&secret);
            ("x25519", hex(public.as_bytes()), hex(&secret.to_bytes()))
        }
        other => {
            return fail(format!(
                "crypto.generate_keypair: '{other}' has no native lowering; this build \
                 implements ed25519 and x25519. Use the interpreter for the post-quantum \
                 generators."
            ))
        }
    };

    let rec = KeyPairRaw {
        algorithm: cstring(name.to_string()),
        public_key: cstring(public),
        private_key: cstring(private),
    };
    if rec.algorithm.is_null() || rec.public_key.is_null() || rec.private_key.is_null() {
        return std::ptr::null_mut();
    }
    Box::into_raw(Box::new(rec))
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn s(p: *mut c_char) -> String {
        assert!(!p.is_null());
        std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
    }

    #[test]
    fn ed25519_produces_a_conventional_pair() {
        let algo = CString::new("ed25519").unwrap();
        let rec = tallow_generate_keypair(algo.as_ptr());
        assert!(!rec.is_null());
        unsafe {
            assert_eq!(s((*rec).algorithm), "ed25519");
            assert_eq!(s((*rec).public_key).len(), 64, "32-byte key in hex");
            assert_eq!(s((*rec).private_key).len(), 64);
            assert_ne!(s((*rec).public_key), s((*rec).private_key));
        }
    }

    #[test]
    fn an_unsupported_algorithm_refuses_by_name() {
        let algo = CString::new("ml-kem-1024").unwrap();
        assert!(tallow_generate_keypair(algo.as_ptr()).is_null());
    }
}
