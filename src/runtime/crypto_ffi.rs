//! FFI wrappers for Tallow crypto operations.
//!
//! Compiled binaries call these via LLVM IR `call` instructions.
//! Each function follows the C convention: null/negative on error,
//! set_last_error for details. Memory allocated by FFI functions
//! is freed by `tallow_free_string` or `tallow_free_bytes`.

use std::os::raw::c_char;

use super::{cstr_to_str, set_last_error, string_to_cstr};

// ── Hex helper (no external crate) ─────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── BLAKE3 ─────────────────────────────────────────────────────────────────

/// Hash a null-terminated C string with BLAKE3. Returns hex-encoded hash.
/// Caller must free the result with `tallow_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_blake3_hash(data: *const c_char) -> *mut c_char {
    let s = match unsafe { cstr_to_str(data) } {
        Some(s) => s,
        None => {
            set_last_error("null input".into());
            return std::ptr::null_mut();
        }
    };
    let hash = blake3::hash(s.as_bytes()).to_hex().to_string();
    string_to_cstr(&hash)
}

/// Hash raw bytes with BLAKE3. Returns hex-encoded hash.
/// Caller must free the result with `tallow_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_blake3_hash_bytes(data: *const u8, len: usize) -> *mut c_char {
    if data.is_null() {
        set_last_error("null data".into());
        return std::ptr::null_mut();
    }
    let slice = unsafe { std::slice::from_raw_parts(data, len) };
    let hash = blake3::hash(slice).to_hex().to_string();
    string_to_cstr(&hash)
}

// ── AES-256-GCM ────────────────────────────────────────────────────────────

/// Encrypt with AES-256-GCM.
/// - `key`: 32 bytes
/// - `nonce`: 12 bytes
/// - `plaintext` + `plaintext_len`: input data
/// - `out_len`: receives ciphertext length (plaintext + 16-byte auth tag)
///
/// Returns heap-allocated ciphertext. Free with `tallow_free_bytes`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_aes256_gcm_encrypt(
    key: *const u8,
    nonce: *const u8,
    plaintext: *const u8,
    plaintext_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    if key.is_null() || nonce.is_null() || plaintext.is_null() || out_len.is_null() {
        set_last_error("null argument".into());
        return std::ptr::null_mut();
    }
    let key_slice = unsafe { std::slice::from_raw_parts(key, 32) };
    let nonce_slice = unsafe { std::slice::from_raw_parts(nonce, 12) };
    let pt = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };

    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key_slice));
    let nonce_ga = GenericArray::from_slice(nonce_slice);

    match cipher.encrypt(nonce_ga, pt) {
        Ok(ct) => {
            unsafe {
                *out_len = ct.len();
            }
            let boxed = ct.into_boxed_slice();
            Box::into_raw(boxed) as *mut u8
        }
        Err(e) => {
            set_last_error(format!("encrypt failed: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Decrypt with AES-256-GCM.
/// - `key`: 32 bytes
/// - `nonce`: 12 bytes
/// - `ciphertext` + `ciphertext_len`: input (ciphertext + 16-byte auth tag)
/// - `out_len`: receives plaintext length
///
/// Returns heap-allocated plaintext. Free with `tallow_free_bytes`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_aes256_gcm_decrypt(
    key: *const u8,
    nonce: *const u8,
    ciphertext: *const u8,
    ciphertext_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    if key.is_null() || nonce.is_null() || ciphertext.is_null() || out_len.is_null() {
        set_last_error("null argument".into());
        return std::ptr::null_mut();
    }
    let key_slice = unsafe { std::slice::from_raw_parts(key, 32) };
    let nonce_slice = unsafe { std::slice::from_raw_parts(nonce, 12) };
    let ct = unsafe { std::slice::from_raw_parts(ciphertext, ciphertext_len) };

    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key_slice));
    let nonce_ga = GenericArray::from_slice(nonce_slice);

    match cipher.decrypt(nonce_ga, ct) {
        Ok(pt) => {
            unsafe {
                *out_len = pt.len();
            }
            let boxed = pt.into_boxed_slice();
            Box::into_raw(boxed) as *mut u8
        }
        Err(_) => {
            set_last_error("decrypt failed".into());
            std::ptr::null_mut()
        }
    }
}

// ── Argon2id ───────────────────────────────────────────────────────────────

/// Hash a password with Argon2id.
/// - `password`: null-terminated C string
/// - `salt`: salt bytes (minimum 8 bytes for Argon2)
/// - `salt_len`: salt length
/// - `out_key`: 32-byte output buffer for the derived key
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_argon2id_hash(
    password: *const c_char,
    salt: *const u8,
    salt_len: usize,
    out_key: *mut u8,
) -> i32 {
    let pw = match unsafe { cstr_to_str(password) } {
        Some(s) => s,
        None => {
            set_last_error("null password".into());
            return -1;
        }
    };
    if out_key.is_null() {
        set_last_error("null output buffer".into());
        return -1;
    }
    // Argon2 requires salt >= 8 bytes
    let salt_slice = if salt.is_null() || salt_len < 8 {
        &[0x4eu8, 0x69, 0x78, 0x65, 0x53, 0x61, 0x6c, 0x74, // "TallowSalt"
          0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x21][..] // "Default!"
    } else {
        unsafe { std::slice::from_raw_parts(salt, salt_len) }
    };

    let mut key = [0u8; 32];
    match argon2::Argon2::default().hash_password_into(pw.as_bytes(), salt_slice, &mut key) {
        Ok(()) => {
            unsafe {
                std::ptr::copy_nonoverlapping(key.as_ptr(), out_key, 32);
            }
            0
        }
        Err(e) => {
            set_last_error(format!("argon2: {e}"));
            -1
        }
    }
}

// ── SHA-2 family ───────────────────────────────────────────────────────────

/// SHA-256 hash of a null-terminated string. Returns hex-encoded hash.
/// Caller must free with `tallow_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_sha256(data: *const c_char) -> *mut c_char {
    let s = match unsafe { cstr_to_str(data) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    use sha2::Digest;
    let hash = sha2::Sha256::digest(s.as_bytes());
    string_to_cstr(&hex_encode(&hash))
}

/// SHA-384 hash of a null-terminated string. Returns hex-encoded hash.
/// Caller must free with `tallow_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_sha384(data: *const c_char) -> *mut c_char {
    let s = match unsafe { cstr_to_str(data) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    use sha2::Digest;
    let hash = sha2::Sha384::digest(s.as_bytes());
    string_to_cstr(&hex_encode(&hash))
}

/// SHA-512 hash of a null-terminated string. Returns hex-encoded hash.
/// Caller must free with `tallow_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_sha512(data: *const c_char) -> *mut c_char {
    let s = match unsafe { cstr_to_str(data) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    use sha2::Digest;
    let hash = sha2::Sha512::digest(s.as_bytes());
    string_to_cstr(&hex_encode(&hash))
}

// ── SHA-3 ──────────────────────────────────────────────────────────────────

/// SHA3-256 hash of a null-terminated string. Returns hex-encoded hash.
/// Caller must free with `tallow_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_sha3_256(data: *const c_char) -> *mut c_char {
    let s = match unsafe { cstr_to_str(data) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    use sha3::Digest;
    let hash = sha3::Sha3_256::digest(s.as_bytes());
    string_to_cstr(&hex_encode(&hash))
}

// ── HMAC-SHA-256 ───────────────────────────────────────────────────────────

/// HMAC-SHA-256. Returns hex-encoded MAC.
/// Caller must free with `tallow_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_hmac_sha256(key: *const c_char, data: *const c_char) -> *mut c_char {
    let k = match unsafe { cstr_to_str(key) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let d = match unsafe { cstr_to_str(data) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;
    let mut mac = match HmacSha256::new_from_slice(k.as_bytes()) {
        Ok(m) => m,
        Err(e) => {
            set_last_error(format!("hmac init: {e}"));
            return std::ptr::null_mut();
        }
    };
    mac.update(d.as_bytes());
    string_to_cstr(&hex_encode(&mac.finalize().into_bytes()))
}

// ── HKDF-SHA-256 ───────────────────────────────────────────────────────────

/// HKDF-SHA-256 key derivation.
/// - `ikm` + `ikm_len`: input keying material
/// - `salt` + `salt_len`: optional salt (can be null)
/// - `info` + `info_len`: optional info (can be null)
/// - `out` + `out_len`: output buffer for derived key material
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_hkdf_sha256(
    ikm: *const u8,
    ikm_len: usize,
    salt: *const u8,
    salt_len: usize,
    info: *const u8,
    info_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if out.is_null() {
        set_last_error("null output buffer".into());
        return -1;
    }
    let ikm_s = if ikm.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(ikm, ikm_len) }
    };
    let salt_s = if salt.is_null() {
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts(salt, salt_len) })
    };
    let info_s = if info.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(info, info_len) }
    };

    let hk = hkdf::Hkdf::<sha2::Sha256>::new(salt_s, ikm_s);
    let mut okm = vec![0u8; out_len];
    match hk.expand(info_s, &mut okm) {
        Ok(()) => {
            unsafe {
                std::ptr::copy_nonoverlapping(okm.as_ptr(), out, out_len);
            }
            0
        }
        Err(e) => {
            set_last_error(format!("hkdf: {e}"));
            -1
        }
    }
}

// ── Ed25519 Sign/Verify ────────────────────────────────────────────────────

/// Ed25519 sign a message.
/// - `secret_key`: 32-byte secret key
/// - `message` + `message_len`: message to sign
/// - `signature_out`: 64-byte buffer for the signature
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_ed25519_sign(
    secret_key: *const u8,
    message: *const u8,
    message_len: usize,
    signature_out: *mut u8,
) -> i32 {
    if secret_key.is_null() || message.is_null() || signature_out.is_null() {
        set_last_error("null argument".into());
        return -1;
    }
    let sk_bytes = unsafe { std::slice::from_raw_parts(secret_key, 32) };
    let msg = unsafe { std::slice::from_raw_parts(message, message_len) };

    let sk_arr: [u8; 32] = match sk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            set_last_error("invalid key length".into());
            return -1;
        }
    };
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&sk_arr);
    use ed25519_dalek::Signer;
    let sig = signing_key.sign(msg);
    unsafe {
        std::ptr::copy_nonoverlapping(sig.to_bytes().as_ptr(), signature_out, 64);
    }
    0
}

/// Ed25519 verify a signature.
/// - `public_key`: 32-byte public key
/// - `message` + `message_len`: original message
/// - `signature`: 64-byte signature
///
/// Returns 0 if valid, -1 if invalid or error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_ed25519_verify(
    public_key: *const u8,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
) -> i32 {
    if public_key.is_null() || message.is_null() || signature.is_null() {
        set_last_error("null argument".into());
        return -1;
    }
    let pk_bytes: [u8; 32] = match unsafe { std::slice::from_raw_parts(public_key, 32) }.try_into()
    {
        Ok(a) => a,
        Err(_) => return -1,
    };
    let msg = unsafe { std::slice::from_raw_parts(message, message_len) };
    let sig_bytes: [u8; 64] = match unsafe { std::slice::from_raw_parts(signature, 64) }.try_into()
    {
        Ok(a) => a,
        Err(_) => return -1,
    };

    let vk = match ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes) {
        Ok(vk) => vk,
        Err(_) => return -1,
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    use ed25519_dalek::Verifier;
    if vk.verify(msg, &sig).is_ok() {
        0
    } else {
        -1
    }
}

// ── Hex-string crypto (interpreter parity: src/stdlib/crypto.rs) ───────────

/// Hash `data` with the named algorithm ("blake3", "sha256", "sha384",
/// "sha512", "sha3_256"). Shared implementation with the interpreter
/// (`stdlib::crypto::hash_by_algo`). Returns hex-encoded digest; null on
/// error (see tallow_last_error). Caller frees with `tallow_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_crypto_hash_alg(
    data: *const c_char,
    algo: *const c_char,
) -> *mut c_char {
    let d = match unsafe { cstr_to_str(data) } {
        Some(s) => s,
        None => {
            set_last_error("null data".into());
            return std::ptr::null_mut();
        }
    };
    let a = match unsafe { cstr_to_str(algo) } {
        Some(s) => s,
        None => {
            set_last_error("null algo".into());
            return std::ptr::null_mut();
        }
    };
    match crate::stdlib::crypto::hash_by_algo(d, a) {
        Ok(h) => string_to_cstr(&h),
        Err(e) => {
            set_last_error(e);
            std::ptr::null_mut()
        }
    }
}

/// Ed25519 verify with hex-encoded inputs (public key 32B, message,
/// signature 64B — all hex). Returns 1 = valid, 0 = invalid,
/// -1 = error (fail-closed: callers must treat only 1 as verified).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_hacl_ed25519_verify(
    public_key_hex: *const c_char,
    message_hex: *const c_char,
    signature_hex: *const c_char,
) -> i32 {
    let (Some(pk), Some(msg), Some(sig)) = (
        unsafe { cstr_to_str(public_key_hex) },
        unsafe { cstr_to_str(message_hex) },
        unsafe { cstr_to_str(signature_hex) },
    ) else {
        set_last_error("null argument".into());
        return -1;
    };
    match crate::stdlib::crypto::hacl_ed25519_verify_hex(pk, msg, sig) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => {
            set_last_error(e);
            -1
        }
    }
}

/// Ed25519 sign with hex-encoded inputs (secret key 32B, message — both
/// hex). Returns hex signature; null on error. Caller frees with
/// `tallow_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_hacl_ed25519_sign(
    secret_key_hex: *const c_char,
    message_hex: *const c_char,
) -> *mut c_char {
    let (Some(sk), Some(msg)) = (
        unsafe { cstr_to_str(secret_key_hex) },
        unsafe { cstr_to_str(message_hex) },
    ) else {
        set_last_error("null argument".into());
        return std::ptr::null_mut();
    };
    match crate::stdlib::crypto::hacl_ed25519_sign_hex(sk, msg) {
        Ok(s) => string_to_cstr(&s),
        Err(e) => {
            set_last_error(e);
            std::ptr::null_mut()
        }
    }
}

/// SHA-256 over hex-decoded input, returned as hex (HACL-shaped binding;
/// interpreter parity: `crypto.hacl_sha256`). Caller frees with
/// `tallow_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_hacl_sha256(data_hex: *const c_char) -> *mut c_char {
    let d = match unsafe { cstr_to_str(data_hex) } {
        Some(s) => s,
        None => {
            set_last_error("null argument".into());
            return std::ptr::null_mut();
        }
    };
    match crate::stdlib::crypto::hacl_sha256_hex(d) {
        Ok(h) => string_to_cstr(&h),
        Err(e) => {
            set_last_error(e);
            std::ptr::null_mut()
        }
    }
}

/// Compiled-mode guard for string-returning crypto FFI calls: if `s` is NULL,
/// print the runtime error (tallow_last_error) to stderr and exit(1) — a
/// cryptographic primitive must never silently continue with a NULL result
/// (fail-closed). Never returns when NULL; a no-op otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_check_string(s: *const c_char) {
    if s.is_null() {
        let err_ptr = super::tallow_last_error();
        let err = if err_ptr.is_null() {
            "unknown error".to_string()
        } else {
            unsafe { std::ffi::CStr::from_ptr(err_ptr) }
                .to_string_lossy()
                .into_owned()
        };
        eprintln!("runtime error: {err}");
        std::process::exit(1);
    }
}

// ── X25519 Diffie-Hellman ──────────────────────────────────────────────────

/// X25519 Diffie-Hellman key exchange.
/// - `secret_key`: 32-byte secret key
/// - `public_key`: 32-byte public key
/// - `shared_secret_out`: 32-byte buffer for the shared secret
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_x25519(
    secret_key: *const u8,
    public_key: *const u8,
    shared_secret_out: *mut u8,
) -> i32 {
    if secret_key.is_null() || public_key.is_null() || shared_secret_out.is_null() {
        set_last_error("null argument".into());
        return -1;
    }
    let sk: [u8; 32] = match unsafe { std::slice::from_raw_parts(secret_key, 32) }.try_into() {
        Ok(a) => a,
        Err(_) => return -1,
    };
    let pk: [u8; 32] = match unsafe { std::slice::from_raw_parts(public_key, 32) }.try_into() {
        Ok(a) => a,
        Err(_) => return -1,
    };
    let shared = x25519_dalek::x25519(sk, pk);
    unsafe {
        std::ptr::copy_nonoverlapping(shared.as_ptr(), shared_secret_out, 32);
    }
    0
}

// ── Random ─────────────────────────────────────────────────────────────────

/// Fill a buffer with cryptographically secure random bytes.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_random_bytes(out: *mut u8, len: usize) {
    if out.is_null() {
        return;
    }
    let random: Vec<u8> = (0..len).map(|_| rand::random::<u8>()).collect();
    unsafe {
        std::ptr::copy_nonoverlapping(random.as_ptr(), out, len);
    }
}

// ── Zstd Compression ──────────────────────────────────────────────────────

/// Compress data with Zstd at the given level.
/// - `data` + `data_len`: input
/// - `level`: compression level (1-22, typically 3)
/// - `out_len`: receives compressed data length
///
/// Returns heap-allocated compressed data. Free with `tallow_free_bytes`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_zstd_compress(
    data: *const u8,
    data_len: usize,
    level: i32,
    out_len: *mut usize,
) -> *mut u8 {
    if data.is_null() || out_len.is_null() {
        set_last_error("null argument".into());
        return std::ptr::null_mut();
    }
    let input = unsafe { std::slice::from_raw_parts(data, data_len) };
    match zstd::encode_all(std::io::Cursor::new(input), level) {
        Ok(compressed) => {
            unsafe {
                *out_len = compressed.len();
            }
            let boxed = compressed.into_boxed_slice();
            Box::into_raw(boxed) as *mut u8
        }
        Err(e) => {
            set_last_error(format!("zstd compress: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Decompress Zstd-compressed data.
/// - `data` + `data_len`: compressed input
/// - `out_len`: receives decompressed data length
///
/// Returns heap-allocated decompressed data. Free with `tallow_free_bytes`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_zstd_decompress(
    data: *const u8,
    data_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    if data.is_null() || out_len.is_null() {
        set_last_error("null argument".into());
        return std::ptr::null_mut();
    }
    let input = unsafe { std::slice::from_raw_parts(data, data_len) };
    match zstd::decode_all(std::io::Cursor::new(input)) {
        Ok(decompressed) => {
            unsafe {
                *out_len = decompressed.len();
            }
            let boxed = decompressed.into_boxed_slice();
            Box::into_raw(boxed) as *mut u8
        }
        Err(e) => {
            set_last_error(format!("zstd decompress: {e}"));
            std::ptr::null_mut()
        }
    }
}

// ── LZ4 ────────────────────────────────────────────────────────────────────

/// Compress data with LZ4 (prepends size header for decompression).
/// - `data` + `data_len`: input
/// - `out_len`: receives compressed data length
///
/// Returns heap-allocated compressed data. Free with `tallow_free_bytes`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_lz4_compress(
    data: *const u8,
    data_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    if data.is_null() || out_len.is_null() {
        set_last_error("null argument".into());
        return std::ptr::null_mut();
    }
    let input = unsafe { std::slice::from_raw_parts(data, data_len) };
    let compressed = lz4_flex::compress_prepend_size(input);
    unsafe {
        *out_len = compressed.len();
    }
    let boxed = compressed.into_boxed_slice();
    Box::into_raw(boxed) as *mut u8
}

/// Decompress LZ4-compressed data (expects size header from `compress_prepend_size`).
/// - `data` + `data_len`: compressed input
/// - `out_len`: receives decompressed data length
///
/// Returns heap-allocated decompressed data. Free with `tallow_free_bytes`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_lz4_decompress(
    data: *const u8,
    data_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    if data.is_null() || out_len.is_null() {
        set_last_error("null argument".into());
        return std::ptr::null_mut();
    }
    let input = unsafe { std::slice::from_raw_parts(data, data_len) };
    match lz4_flex::decompress_size_prepended(input) {
        Ok(decompressed) => {
            unsafe {
                *out_len = decompressed.len();
            }
            let boxed = decompressed.into_boxed_slice();
            Box::into_raw(boxed) as *mut u8
        }
        Err(e) => {
            set_last_error(format!("lz4 decompress: {e}"));
            std::ptr::null_mut()
        }
    }
}

// ── ChaCha20-Poly1305 ─────────────────────────────────────────────────────

/// Encrypt with ChaCha20-Poly1305.
/// - `key`: 32 bytes
/// - `nonce`: 12 bytes
/// - `plaintext` + `plaintext_len`: input data
/// - `out_len`: receives ciphertext length (plaintext + 16-byte tag)
///
/// Returns heap-allocated ciphertext. Free with `tallow_free_bytes`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_chacha20_poly1305_encrypt(
    key: *const u8,
    nonce: *const u8,
    plaintext: *const u8,
    plaintext_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    if key.is_null() || nonce.is_null() || plaintext.is_null() || out_len.is_null() {
        set_last_error("null argument".into());
        return std::ptr::null_mut();
    }
    let key_slice = unsafe { std::slice::from_raw_parts(key, 32) };
    let nonce_slice = unsafe { std::slice::from_raw_parts(nonce, 12) };
    let pt = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };

    use chacha20poly1305::aead::generic_array::GenericArray;
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key_slice));
    let nonce_ga = GenericArray::from_slice(nonce_slice);

    match cipher.encrypt(nonce_ga, pt) {
        Ok(ct) => {
            unsafe {
                *out_len = ct.len();
            }
            let boxed = ct.into_boxed_slice();
            Box::into_raw(boxed) as *mut u8
        }
        Err(e) => {
            set_last_error(format!("chacha20 encrypt: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Decrypt with ChaCha20-Poly1305.
/// - `key`: 32 bytes
/// - `nonce`: 12 bytes
/// - `ciphertext` + `ciphertext_len`: input (ciphertext + 16-byte tag)
/// - `out_len`: receives plaintext length
///
/// Returns heap-allocated plaintext. Free with `tallow_free_bytes`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_chacha20_poly1305_decrypt(
    key: *const u8,
    nonce: *const u8,
    ciphertext: *const u8,
    ciphertext_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    if key.is_null() || nonce.is_null() || ciphertext.is_null() || out_len.is_null() {
        set_last_error("null argument".into());
        return std::ptr::null_mut();
    }
    let key_slice = unsafe { std::slice::from_raw_parts(key, 32) };
    let nonce_slice = unsafe { std::slice::from_raw_parts(nonce, 12) };
    let ct = unsafe { std::slice::from_raw_parts(ciphertext, ciphertext_len) };

    use chacha20poly1305::aead::generic_array::GenericArray;
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key_slice));
    let nonce_ga = GenericArray::from_slice(nonce_slice);

    match cipher.decrypt(nonce_ga, ct) {
        Ok(pt) => {
            unsafe {
                *out_len = pt.len();
            }
            let boxed = pt.into_boxed_slice();
            Box::into_raw(boxed) as *mut u8
        }
        Err(_) => {
            set_last_error("chacha20 decrypt failed".into());
            std::ptr::null_mut()
        }
    }
}

// ── Reed-Solomon Erasure Coding ────────────────────────────────────────────

/// Reed-Solomon encode data into data + recovery shards.
/// - `data` + `data_len`: input data
/// - `data_shards`: number of data shards
/// - `recovery_shards`: number of recovery shards
/// - `out_len`: receives total output length (all shards concatenated)
///
/// Returns heap-allocated buffer of all shards. Free with `tallow_free_bytes`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_reed_solomon_encode(
    data: *const u8,
    data_len: usize,
    data_shards: usize,
    recovery_shards: usize,
    out_len: *mut usize,
) -> *mut u8 {
    if data.is_null() || out_len.is_null() || data_shards == 0 || recovery_shards == 0 {
        set_last_error("invalid arguments".into());
        return std::ptr::null_mut();
    }
    let input = unsafe { std::slice::from_raw_parts(data, data_len) };

    // reed-solomon-simd requires shard_size to be a multiple of 2
    let raw_shard_size =
        std::cmp::max(1, (input.len() + data_shards - 1) / data_shards);
    let shard_size = std::cmp::max(2, if raw_shard_size % 2 != 0 { raw_shard_size + 1 } else { raw_shard_size });
    let mut padded = input.to_vec();
    padded.resize(shard_size * data_shards, 0);

    // Split into shard slices (reed-solomon-simd needs Vec<&[u8]>)
    let shard_slices: Vec<&[u8]> = padded.chunks(shard_size).collect();

    match reed_solomon_simd::encode(data_shards, recovery_shards, shard_slices) {
        Ok(recovery) => {
            let mut all = padded;
            for shard in recovery.iter() {
                all.extend_from_slice(shard);
            }
            unsafe {
                *out_len = all.len();
            }
            let boxed = all.into_boxed_slice();
            Box::into_raw(boxed) as *mut u8
        }
        Err(e) => {
            set_last_error(format!("rs encode: {e}"));
            std::ptr::null_mut()
        }
    }
}

// ── Free allocated byte buffers ────────────────────────────────────────────

/// Free a byte buffer previously returned by a runtime FFI function.
/// Safe to call with null.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_free_bytes(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            let _ = Box::from_raw(std::slice::from_raw_parts_mut(ptr, len));
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    #[test]
    fn test_blake3_hash_ffi() {
        let input = CString::new("hello").unwrap();
        let result = tallow_blake3_hash(input.as_ptr());
        assert!(!result.is_null());
        let hash = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        assert_eq!(hash.len(), 64); // 32 bytes = 64 hex chars
        // Verify against known BLAKE3 hash of "hello"
        let expected = blake3::hash(b"hello").to_hex().to_string();
        assert_eq!(hash, expected);
        super::super::tallow_free_string(result);
    }

    #[test]
    fn test_blake3_hash_null() {
        let result = tallow_blake3_hash(std::ptr::null());
        assert!(result.is_null());
    }

    #[test]
    fn test_blake3_hash_bytes_ffi() {
        let data = b"hello world";
        let result = tallow_blake3_hash_bytes(data.as_ptr(), data.len());
        assert!(!result.is_null());
        let hash = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        assert_eq!(hash.len(), 64);
        super::super::tallow_free_string(result);
    }

    #[test]
    fn test_sha256_ffi() {
        let input = CString::new("hello").unwrap();
        let result = tallow_sha256(input.as_ptr());
        assert!(!result.is_null());
        let hash = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        // SHA-256 of "hello" = 2cf24dba...
        assert!(hash.starts_with("2cf24dba"));
        assert_eq!(hash.len(), 64);
        super::super::tallow_free_string(result);
    }

    #[test]
    fn test_crypto_hash_alg_sha256_vector() {
        let data = CString::new("abc").unwrap();
        let algo = CString::new("sha256").unwrap();
        let result = tallow_crypto_hash_alg(data.as_ptr(), algo.as_ptr());
        assert!(!result.is_null());
        let digest = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        super::super::tallow_free_string(result);
    }

    #[test]
    fn test_crypto_hash_alg_rejects_unknown_label() {
        let data = CString::new("abc").unwrap();
        let algo = CString::new("not-a-hash").unwrap();
        let result = tallow_crypto_hash_alg(data.as_ptr(), algo.as_ptr());
        assert!(
            result.is_null(),
            "unknown algo labels must be errors, never a silent fallback"
        );
    }

    #[test]
    fn test_hacl_ed25519_ffi_roundtrip_and_fail_closed() {
        let sk_bytes = [0x42u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
        let sk_hex: String = sk_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let vk_hex: String = sk
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let msg_hex: String = b"the quick brown fox"
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        let sk_s = CString::new(sk_hex).unwrap();
        let msg_s = CString::new(msg_hex).unwrap();
        let sig_ptr = tallow_hacl_ed25519_sign(sk_s.as_ptr(), msg_s.as_ptr());
        assert!(!sig_ptr.is_null(), "sign must succeed");
        let sig_hex = unsafe { CStr::from_ptr(sig_ptr).to_str().unwrap().to_string() };
        super::super::tallow_free_string(sig_ptr);

        let vk_s = CString::new(vk_hex).unwrap();
        let sig_s = CString::new(sig_hex).unwrap();
        assert_eq!(
            tallow_hacl_ed25519_verify(vk_s.as_ptr(), msg_s.as_ptr(), sig_s.as_ptr()),
            1,
            "valid signature must verify"
        );

        // Valid-hex but wrong signature value: must return 0 (reject).
        let mut tampered: Vec<u8> = sig_s.as_bytes().to_vec();
        tampered[0] = if tampered[0] == b'0' { b'1' } else { b'0' };
        let tampered_s = CString::new(tampered).unwrap();
        assert_eq!(
            tallow_hacl_ed25519_verify(vk_s.as_ptr(), msg_s.as_ptr(), tampered_s.as_ptr()),
            0,
            "tampered signature must NOT verify"
        );

        // Malformed hex: hard error (-1) — fail-closed, never a silent pass.
        let bad = CString::new("zz").unwrap();
        assert_eq!(
            tallow_hacl_ed25519_verify(vk_s.as_ptr(), msg_s.as_ptr(), bad.as_ptr()),
            -1,
            "malformed hex must be an error"
        );
    }

    #[test]
    fn test_sha384_ffi() {
        let input = CString::new("hello").unwrap();
        let result = tallow_sha384(input.as_ptr());
        assert!(!result.is_null());
        let hash = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        assert_eq!(hash.len(), 96); // 48 bytes = 96 hex chars
        super::super::tallow_free_string(result);
    }

    #[test]
    fn test_sha512_ffi() {
        let input = CString::new("hello").unwrap();
        let result = tallow_sha512(input.as_ptr());
        assert!(!result.is_null());
        let hash = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        assert_eq!(hash.len(), 128); // 64 bytes = 128 hex chars
        super::super::tallow_free_string(result);
    }

    #[test]
    fn test_sha3_256_ffi() {
        let input = CString::new("hello").unwrap();
        let result = tallow_sha3_256(input.as_ptr());
        assert!(!result.is_null());
        let hash = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        assert_eq!(hash.len(), 64);
        super::super::tallow_free_string(result);
    }

    #[test]
    fn test_hmac_sha256_ffi() {
        let key = CString::new("secret-key").unwrap();
        let data = CString::new("message").unwrap();
        let result = tallow_hmac_sha256(key.as_ptr(), data.as_ptr());
        assert!(!result.is_null());
        let mac = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        assert_eq!(mac.len(), 64); // 32 bytes = 64 hex chars
        super::super::tallow_free_string(result);
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"hello world";
        let mut ct_len: usize = 0;
        let ct = tallow_aes256_gcm_encrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            plaintext.as_ptr(),
            plaintext.len(),
            &mut ct_len,
        );
        assert!(!ct.is_null());
        assert!(ct_len > plaintext.len()); // ciphertext + 16-byte tag

        let mut pt_len: usize = 0;
        let pt =
            tallow_aes256_gcm_decrypt(key.as_ptr(), nonce.as_ptr(), ct, ct_len, &mut pt_len);
        assert!(!pt.is_null());
        assert_eq!(pt_len, plaintext.len());
        let recovered = unsafe { std::slice::from_raw_parts(pt, pt_len) };
        assert_eq!(recovered, plaintext);

        tallow_free_bytes(ct, ct_len);
        tallow_free_bytes(pt, pt_len);
    }

    #[test]
    fn test_aes_gcm_wrong_key() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"secret";
        let mut ct_len: usize = 0;
        let ct = tallow_aes256_gcm_encrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            plaintext.as_ptr(),
            plaintext.len(),
            &mut ct_len,
        );
        assert!(!ct.is_null());

        let mut pt_len: usize = 0;
        let pt = tallow_aes256_gcm_decrypt(
            wrong_key.as_ptr(),
            nonce.as_ptr(),
            ct,
            ct_len,
            &mut pt_len,
        );
        assert!(pt.is_null()); // decryption should fail

        tallow_free_bytes(ct, ct_len);
    }

    #[test]
    fn test_chacha20_poly1305_roundtrip() {
        let key = [0x55u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"chacha test data";
        let mut ct_len: usize = 0;
        let ct = tallow_chacha20_poly1305_encrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            plaintext.as_ptr(),
            plaintext.len(),
            &mut ct_len,
        );
        assert!(!ct.is_null());
        assert!(ct_len > plaintext.len());

        let mut pt_len: usize = 0;
        let pt = tallow_chacha20_poly1305_decrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            ct,
            ct_len,
            &mut pt_len,
        );
        assert!(!pt.is_null());
        assert_eq!(pt_len, plaintext.len());
        let recovered = unsafe { std::slice::from_raw_parts(pt, pt_len) };
        assert_eq!(recovered, plaintext);

        tallow_free_bytes(ct, ct_len);
        tallow_free_bytes(pt, pt_len);
    }

    #[test]
    fn test_argon2id_hash_ffi() {
        let pw = CString::new("password123").unwrap();
        let salt = b"TallowSaltDflt!";
        let mut out = [0u8; 32];
        let ret = tallow_argon2id_hash(pw.as_ptr(), salt.as_ptr(), salt.len(), out.as_mut_ptr());
        assert_eq!(ret, 0);
        // Key should not be all zeros after hashing
        assert!(out.iter().any(|&b| b != 0));

        // Same password + salt should produce same key
        let mut out2 = [0u8; 32];
        let ret2 = tallow_argon2id_hash(pw.as_ptr(), salt.as_ptr(), salt.len(), out2.as_mut_ptr());
        assert_eq!(ret2, 0);
        assert_eq!(out, out2);
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let sk = [0x42u8; 32];
        let msg = b"sign this message";
        let mut sig = [0u8; 64];
        assert_eq!(
            tallow_ed25519_sign(sk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr()),
            0
        );

        // Derive the public key from the secret key
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&sk);
        let pk = signing_key.verifying_key().to_bytes();
        assert_eq!(
            tallow_ed25519_verify(pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()),
            0
        );

        // Tamper with the message — verification should fail
        let wrong_msg = b"tampered message!";
        assert_eq!(
            tallow_ed25519_verify(pk.as_ptr(), wrong_msg.as_ptr(), wrong_msg.len(), sig.as_ptr()),
            -1
        );
    }

    #[test]
    fn test_x25519_dh() {
        // Alice and Bob each have secret keys
        let alice_sk = [0x41u8; 32];
        let bob_sk = [0x42u8; 32];

        // Derive public keys using x25519 with the base point
        let base_point = [
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ];
        let mut alice_pk = [0u8; 32];
        let mut bob_pk = [0u8; 32];
        assert_eq!(tallow_x25519(alice_sk.as_ptr(), base_point.as_ptr(), alice_pk.as_mut_ptr()), 0);
        assert_eq!(tallow_x25519(bob_sk.as_ptr(), base_point.as_ptr(), bob_pk.as_mut_ptr()), 0);

        // Compute shared secrets
        let mut alice_shared = [0u8; 32];
        let mut bob_shared = [0u8; 32];
        assert_eq!(tallow_x25519(alice_sk.as_ptr(), bob_pk.as_ptr(), alice_shared.as_mut_ptr()), 0);
        assert_eq!(tallow_x25519(bob_sk.as_ptr(), alice_pk.as_ptr(), bob_shared.as_mut_ptr()), 0);

        // Both should agree on the same shared secret
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_random_bytes_ffi() {
        let mut buf = [0u8; 32];
        tallow_random_bytes(buf.as_mut_ptr(), 32);
        // Very unlikely all zeros after random fill
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_zstd_roundtrip_ffi() {
        let data = b"hello world hello world hello world";
        let mut ct_len: usize = 0;
        let ct = tallow_zstd_compress(data.as_ptr(), data.len(), 3, &mut ct_len);
        assert!(!ct.is_null());

        let mut pt_len: usize = 0;
        let pt = tallow_zstd_decompress(ct, ct_len, &mut pt_len);
        assert!(!pt.is_null());
        assert_eq!(pt_len, data.len());
        let recovered = unsafe { std::slice::from_raw_parts(pt, pt_len) };
        assert_eq!(recovered, data);

        tallow_free_bytes(ct, ct_len);
        tallow_free_bytes(pt, pt_len);
    }

    #[test]
    fn test_lz4_roundtrip_ffi() {
        let data = b"lz4 compression test data repeated repeated repeated";
        let mut ct_len: usize = 0;
        let ct = tallow_lz4_compress(data.as_ptr(), data.len(), &mut ct_len);
        assert!(!ct.is_null());

        let mut pt_len: usize = 0;
        let pt = tallow_lz4_decompress(ct, ct_len, &mut pt_len);
        assert!(!pt.is_null());
        assert_eq!(pt_len, data.len());
        let recovered = unsafe { std::slice::from_raw_parts(pt, pt_len) };
        assert_eq!(recovered, data);

        tallow_free_bytes(ct, ct_len);
        tallow_free_bytes(pt, pt_len);
    }

    #[test]
    fn test_hkdf_sha256_ffi() {
        let ikm = b"input keying material";
        let salt = b"salt value";
        let info = b"context info";
        let mut out = [0u8; 32];

        let ret = tallow_hkdf_sha256(
            ikm.as_ptr(),
            ikm.len(),
            salt.as_ptr(),
            salt.len(),
            info.as_ptr(),
            info.len(),
            out.as_mut_ptr(),
            32,
        );
        assert_eq!(ret, 0);
        assert!(out.iter().any(|&b| b != 0));

        // Same inputs produce same output (deterministic)
        let mut out2 = [0u8; 32];
        let ret2 = tallow_hkdf_sha256(
            ikm.as_ptr(),
            ikm.len(),
            salt.as_ptr(),
            salt.len(),
            info.as_ptr(),
            info.len(),
            out2.as_mut_ptr(),
            32,
        );
        assert_eq!(ret2, 0);
        assert_eq!(out, out2);
    }

    #[test]
    fn test_reed_solomon_encode_ffi() {
        let data = b"reed solomon test data for erasure coding ffi";
        let mut out_len: usize = 0;
        let result = tallow_reed_solomon_encode(data.as_ptr(), data.len(), 4, 2, &mut out_len);
        assert!(!result.is_null());
        // Output should be larger: 4 data shards + 2 recovery shards
        assert!(out_len > data.len());
        tallow_free_bytes(result, out_len);
    }

    #[test]
    fn test_free_bytes_null() {
        // Should not panic or crash
        tallow_free_bytes(std::ptr::null_mut(), 0);
        tallow_free_bytes(std::ptr::null_mut(), 100);
    }
}
