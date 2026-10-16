//! FFI wrappers for TallowTransfer file operations.
//!
//! Provides file hashing, encryption/decryption, copy, and delta scanning
//! for compiled Tallow binaries via the runtime FFI system.

use std::os::raw::c_char;

use super::{cstr_to_str, set_last_error, string_to_cstr};

// ── File Hashing ───────────────────────────────────────────────────────────

/// BLAKE3-hash the contents of a file at `path`.
/// Returns hex-encoded hash string. Caller must free with `tallow_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_file_hash(path: *const c_char) -> *mut c_char {
    let p = match unsafe { cstr_to_str(path) } {
        Some(s) => s,
        None => {
            set_last_error("null path".into());
            return std::ptr::null_mut();
        }
    };
    match std::fs::read(p) {
        Ok(data) => string_to_cstr(&blake3::hash(&data).to_hex().to_string()),
        Err(e) => {
            set_last_error(format!("read: {e}"));
            std::ptr::null_mut()
        }
    }
}

// ── File Encryption ────────────────────────────────────────────────────────

/// Encrypt a file with AES-256-GCM using an Argon2id-derived key.
///
/// Writes a NIXV-format encrypted file:
///   `NIXV` (4 bytes) | version (1 byte) | salt (16 bytes) | nonce (12 bytes) | ciphertext
///
/// Returns 0 on success, -1 on error (check `tallow_last_error`).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_encrypt_file(
    input_path: *const c_char,
    output_path: *const c_char,
    password: *const c_char,
) -> i32 {
    let inp = match unsafe { cstr_to_str(input_path) } {
        Some(s) => s,
        None => {
            set_last_error("null input path".into());
            return -1;
        }
    };
    let outp = match unsafe { cstr_to_str(output_path) } {
        Some(s) => s,
        None => {
            set_last_error("null output path".into());
            return -1;
        }
    };
    let pw = match unsafe { cstr_to_str(password) } {
        Some(s) => s,
        None => {
            set_last_error("null password".into());
            return -1;
        }
    };

    let data = match std::fs::read(inp) {
        Ok(d) => d,
        Err(e) => {
            set_last_error(format!("read {inp}: {e}"));
            return -1;
        }
    };

    // Generate random salt and nonce
    let salt: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();
    let nonce: Vec<u8> = (0..12).map(|_| rand::random::<u8>()).collect();

    // Derive key with Argon2id
    let mut key = [0u8; 32];
    if argon2::Argon2::default()
        .hash_password_into(pw.as_bytes(), &salt, &mut key)
        .is_err()
    {
        set_last_error("key derivation failed".into());
        return -1;
    }

    // Encrypt with AES-256-GCM
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let ct = match cipher.encrypt(GenericArray::from_slice(&nonce), data.as_ref()) {
        Ok(ct) => ct,
        Err(_) => {
            set_last_error("encrypt failed".into());
            return -1;
        }
    };

    // Build NIXV format: header + salt + nonce + ciphertext
    let mut output = Vec::with_capacity(4 + 1 + 16 + 12 + ct.len());
    output.extend_from_slice(b"NIXV");
    output.push(1); // version
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ct);

    match std::fs::write(outp, &output) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!("write {outp}: {e}"));
            -1
        }
    }
}

/// Decrypt a NIXV-format encrypted file.
///
/// Returns 0 on success, -1 on error (check `tallow_last_error`).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_decrypt_file(
    input_path: *const c_char,
    output_path: *const c_char,
    password: *const c_char,
) -> i32 {
    let inp = match unsafe { cstr_to_str(input_path) } {
        Some(s) => s,
        None => {
            set_last_error("null input path".into());
            return -1;
        }
    };
    let outp = match unsafe { cstr_to_str(output_path) } {
        Some(s) => s,
        None => {
            set_last_error("null output path".into());
            return -1;
        }
    };
    let pw = match unsafe { cstr_to_str(password) } {
        Some(s) => s,
        None => {
            set_last_error("null password".into());
            return -1;
        }
    };

    let data = match std::fs::read(inp) {
        Ok(d) => d,
        Err(e) => {
            set_last_error(format!("read {inp}: {e}"));
            return -1;
        }
    };

    // Validate NIXV header: "NIXV" + version + 16 salt + 12 nonce = 33 bytes minimum
    if data.len() < 33 || &data[..4] != b"NIXV" {
        set_last_error("invalid NIXV file".into());
        return -1;
    }

    let salt = &data[5..21];
    let nonce = &data[21..33];
    let ct = &data[33..];

    // Derive key with Argon2id (same params as encryption)
    let mut key = [0u8; 32];
    if argon2::Argon2::default()
        .hash_password_into(pw.as_bytes(), salt, &mut key)
        .is_err()
    {
        set_last_error("key derivation failed".into());
        return -1;
    }

    // Decrypt with AES-256-GCM
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let pt = match cipher.decrypt(GenericArray::from_slice(nonce), ct) {
        Ok(pt) => pt,
        Err(_) => {
            set_last_error("decrypt failed (wrong password?)".into());
            return -1;
        }
    };

    match std::fs::write(outp, &pt) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!("write {outp}: {e}"));
            -1
        }
    }
}

// ── Fast File Copy ─────────────────────────────────────────────────────────

/// Copy a file from `src` to `dst`. Returns bytes copied, or -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_copy_file(src: *const c_char, dst: *const c_char) -> i64 {
    let s = match unsafe { cstr_to_str(src) } {
        Some(s) => s,
        None => {
            set_last_error("null src".into());
            return -1;
        }
    };
    let d = match unsafe { cstr_to_str(dst) } {
        Some(s) => s,
        None => {
            set_last_error("null dst".into());
            return -1;
        }
    };
    match std::fs::copy(s, d) {
        Ok(n) => n as i64,
        Err(e) => {
            set_last_error(format!("copy: {e}"));
            -1
        }
    }
}

// ── Delta Scan ─────────────────────────────────────────────────────────────

/// Scan a directory and return newline-separated "path:blake3_hash" entries.
/// Only includes regular files (not subdirectories).
///
/// Caller must free the result with `tallow_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_delta_scan(dir: *const c_char) -> *mut c_char {
    let d = match unsafe { cstr_to_str(dir) } {
        Some(s) => s,
        None => {
            set_last_error("null dir".into());
            return std::ptr::null_mut();
        }
    };
    let mut entries = Vec::new();
    if let Ok(read) = std::fs::read_dir(d) {
        for entry in read.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(data) = std::fs::read(&path) {
                    let hash = blake3::hash(&data).to_hex().to_string();
                    entries.push(format!("{}:{}", path.display(), hash));
                }
            }
        }
    }
    string_to_cstr(&entries.join("\n"))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    #[test]
    fn test_file_hash_ffi() {
        let tmp = std::env::temp_dir().join("tallow_ffi_hash_test.txt");
        std::fs::write(&tmp, "hash me").unwrap();
        let path = CString::new(tmp.to_str().unwrap()).unwrap();
        let result = tallow_file_hash(path.as_ptr());
        assert!(!result.is_null());
        let hash = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        assert_eq!(hash.len(), 64);
        // Verify against direct BLAKE3
        let expected = blake3::hash(b"hash me").to_hex().to_string();
        assert_eq!(hash, expected);
        super::super::tallow_free_string(result);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_file_hash_nonexistent() {
        let path = CString::new("/nonexistent/file/path.txt").unwrap();
        let result = tallow_file_hash(path.as_ptr());
        assert!(result.is_null());
    }

    #[test]
    fn test_encrypt_decrypt_file() {
        let tmp = std::env::temp_dir();
        let input = tmp.join("tallow_ffi_test_input.txt");
        let encrypted = tmp.join("tallow_ffi_test_encrypted.nixv");
        let decrypted = tmp.join("tallow_ffi_test_decrypted.txt");

        std::fs::write(&input, "secret data for FFI test").unwrap();

        let inp = CString::new(input.to_str().unwrap()).unwrap();
        let enc = CString::new(encrypted.to_str().unwrap()).unwrap();
        let dec = CString::new(decrypted.to_str().unwrap()).unwrap();
        let pw = CString::new("test-password").unwrap();

        assert_eq!(tallow_encrypt_file(inp.as_ptr(), enc.as_ptr(), pw.as_ptr()), 0);

        // Verify the encrypted file has NIXV header
        let enc_data = std::fs::read(&encrypted).unwrap();
        assert_eq!(&enc_data[..4], b"NIXV");
        assert_eq!(enc_data[4], 1); // version

        assert_eq!(tallow_decrypt_file(enc.as_ptr(), dec.as_ptr(), pw.as_ptr()), 0);

        let original = std::fs::read_to_string(&input).unwrap();
        let recovered = std::fs::read_to_string(&decrypted).unwrap();
        assert_eq!(original, recovered);

        let _ = std::fs::remove_file(&input);
        let _ = std::fs::remove_file(&encrypted);
        let _ = std::fs::remove_file(&decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_wrong_password() {
        let tmp = std::env::temp_dir();
        let input = tmp.join("tallow_ffi_wrong_pw_input.txt");
        let encrypted = tmp.join("tallow_ffi_wrong_pw_enc.nixv");
        let decrypted = tmp.join("tallow_ffi_wrong_pw_dec.txt");

        std::fs::write(&input, "sensitive data").unwrap();

        let inp = CString::new(input.to_str().unwrap()).unwrap();
        let enc = CString::new(encrypted.to_str().unwrap()).unwrap();
        let dec = CString::new(decrypted.to_str().unwrap()).unwrap();
        let pw = CString::new("correct-password").unwrap();
        let wrong_pw = CString::new("wrong-password").unwrap();

        assert_eq!(tallow_encrypt_file(inp.as_ptr(), enc.as_ptr(), pw.as_ptr()), 0);
        assert_eq!(
            tallow_decrypt_file(enc.as_ptr(), dec.as_ptr(), wrong_pw.as_ptr()),
            -1
        );

        let _ = std::fs::remove_file(&input);
        let _ = std::fs::remove_file(&encrypted);
        let _ = std::fs::remove_file(&decrypted);
    }

    #[test]
    fn test_copy_file_ffi() {
        let tmp = std::env::temp_dir();
        let src = tmp.join("tallow_ffi_copy_src.txt");
        let dst = tmp.join("tallow_ffi_copy_dst.txt");
        std::fs::write(&src, "copy me").unwrap();
        let s = CString::new(src.to_str().unwrap()).unwrap();
        let d = CString::new(dst.to_str().unwrap()).unwrap();
        let bytes = tallow_copy_file(s.as_ptr(), d.as_ptr());
        assert!(bytes > 0);
        assert_eq!(std::fs::read_to_string(&dst).unwrap(), "copy me");
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&dst);
    }

    #[test]
    fn test_copy_file_nonexistent() {
        let s = CString::new("/nonexistent/source.txt").unwrap();
        let d = CString::new("/tmp/tallow_copy_dst.txt").unwrap();
        let bytes = tallow_copy_file(s.as_ptr(), d.as_ptr());
        assert_eq!(bytes, -1);
    }

    #[test]
    fn test_delta_scan_ffi() {
        let tmp = std::env::temp_dir().join("tallow_ffi_delta_scan_test");
        let _ = std::fs::create_dir_all(&tmp);
        std::fs::write(tmp.join("a.txt"), "file a").unwrap();
        std::fs::write(tmp.join("b.txt"), "file b").unwrap();

        let dir = CString::new(tmp.to_str().unwrap()).unwrap();
        let result = tallow_delta_scan(dir.as_ptr());
        assert!(!result.is_null());
        let scan = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        // Should contain entries for both files
        assert!(scan.contains("a.txt:"));
        assert!(scan.contains("b.txt:"));
        // Each entry ends with ":64-char-hex-hash"
        for line in scan.lines() {
            // On Windows paths contain "C:\...", so split from the right
            let colon_pos = line.rfind(':').expect("should have colon separator");
            let hash_part = &line[colon_pos + 1..];
            assert_eq!(hash_part.len(), 64, "hash should be 64 hex chars, got: {hash_part}");
        }
        super::super::tallow_free_string(result);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_delta_scan_empty_dir() {
        let tmp = std::env::temp_dir().join("tallow_ffi_delta_scan_empty");
        let _ = std::fs::create_dir_all(&tmp);
        // Remove any leftover files
        if let Ok(entries) = std::fs::read_dir(&tmp) {
            for entry in entries.flatten() {
                let _ = std::fs::remove_file(entry.path());
            }
        }

        let dir = CString::new(tmp.to_str().unwrap()).unwrap();
        let result = tallow_delta_scan(dir.as_ptr());
        assert!(!result.is_null());
        let scan = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        assert_eq!(scan, ""); // empty directory = empty result
        super::super::tallow_free_string(result);

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
