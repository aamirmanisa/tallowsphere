//! FFI wrappers for gzip compression (compiled binaries).
//!
//! Compiled Tallow programs calling `compress.gzip` / `compress.gunzip` emit
//! calls to these symbols. Backed by flate2 (pure-Rust gzip).
//!
//! Memory convention: results are heap buffers returned as `*mut c_char` with
//! a NUL terminator appended so the codegen's `strlen`-based string model
//! round-trips; the real payload length is written to `out_len`.

use std::io::{Read, Write};
use std::os::raw::c_char;

use super::set_last_error;

/// Tracks the payload length of every buffer returned by `tallow_gzip_compress`.
///
/// Gzip streams contain interior NUL bytes (the header mtime field alone has
/// six), so the compressed length CANNOT be recovered with strlen/CStr — the
/// codegen passes only the buffer pointer to `tallow_gzip_decompress`, and
/// truncating at the first NUL produces a corrupt stream and a null result.
/// Compress therefore records `(buffer_ptr -> payload_len)` here and
/// decompress looks the exact length up. Entries live for the process
/// lifetime (the codegen FFI surface has no per-buffer free hook for these
/// strings); growth is bounded by the number of gzip compressions performed.
static COMPRESSED_LENS: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<usize, usize>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Gzip-compress `data_len` bytes of `data`. Returns a NUL-terminated heap
/// buffer containing the gzip stream; `out_len` receives the payload length.
/// Null on error (check `tallow_last_error`).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_gzip_compress(
    data: *const c_char,
    data_len: i64,
    out_len: *mut i64,
) -> *mut c_char {
    if data.is_null() || out_len.is_null() {
        set_last_error("gzip.compress: null argument".to_string());
        return std::ptr::null_mut();
    }
    let input = unsafe { std::slice::from_raw_parts(data as *const u8, data_len as usize) };
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    if let Err(e) = encoder.write_all(input) {
        set_last_error(format!("gzip.compress: {e}"));
        return std::ptr::null_mut();
    }
    let compressed = match encoder.finish() {
        Ok(v) => v,
        Err(e) => {
            set_last_error(format!("gzip.compress: {e}"));
            return std::ptr::null_mut();
        }
    };
    unsafe {
        *out_len = compressed.len() as i64;
    }
    let payload_len = compressed.len();
    // NUL-terminate so the codegen's strlen-based string model sees the whole
    // payload. `orig_len` from the caller is not needed for gzip framing.
    let mut terminated = compressed;
    terminated.push(0);
    let boxed = terminated.into_boxed_slice();
    let ptr = Box::into_raw(boxed) as *mut c_char;
    // Record the exact payload length so tallow_gzip_decompress can recover it
    // (strlen would truncate at the first interior NUL in the gzip stream).
    if let Ok(mut reg) = COMPRESSED_LENS.lock() {
        reg.insert(ptr as usize, payload_len);
    }
    ptr
}

/// Gzip-decompress `data` (a gzip stream passed as a C string).
/// `orig_len` is accepted for API compatibility with the codegen emission;
/// the decoder derives the real size from the gzip trailer.
/// Returns a NUL-terminated heap buffer with the decompressed payload;
/// `out_len` receives the payload length. Null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_gzip_decompress(
    data: *const c_char,
    orig_len: i64,
    out_len: *mut i64,
) -> *mut c_char {
    let _ = orig_len; // gzip framing carries the size; kept for ABI compatibility
    if data.is_null() || out_len.is_null() {
        set_last_error("gzip.decompress: null argument".to_string());
        return std::ptr::null_mut();
    }
    let input: &[u8] = match COMPRESSED_LENS.lock() {
        Ok(reg) => match reg.get(&(data as usize)).copied() {
            // Exact length known from a matching tallow_gzip_compress call.
            Some(len) => unsafe { std::slice::from_raw_parts(data as *const u8, len) },
            // Unknown buffer (e.g. from a different source): fall back to the
            // C-string length. This truncates at the first interior NUL of a
            // gzip stream, so decompression of foreign buffers will fail with
            // an explicit error rather than corrupt data.
            None => unsafe { std::ffi::CStr::from_ptr(data).to_bytes() },
        },
        Err(_) => unsafe { std::ffi::CStr::from_ptr(data).to_bytes() },
    };
    let mut decoder = flate2::read::GzDecoder::new(input);
    let mut decompressed = Vec::new();
    if let Err(e) = decoder.read_to_end(&mut decompressed) {
        set_last_error(format!("gzip.decompress: {e}"));
        return std::ptr::null_mut();
    }
    unsafe {
        *out_len = decompressed.len() as i64;
    }
    let mut terminated = decompressed;
    terminated.push(0);
    let boxed = terminated.into_boxed_slice();
    Box::into_raw(boxed) as *mut c_char
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn gzip_roundtrip_via_ffi() {
        let payload = "hello tallow gzip roundtrip";
        let data = CString::new(payload).unwrap();
        let mut out_len: i64 = 0;
        let compressed = tallow_gzip_compress(data.as_ptr(), payload.len() as i64, &mut out_len);
        assert!(!compressed.is_null());
        assert!(out_len > 0);

        let mut dec_len: i64 = 0;
        let decompressed = tallow_gzip_decompress(compressed, out_len, &mut dec_len);
        assert!(!decompressed.is_null(), "decompress failed");
        assert_eq!(dec_len as usize, payload.len());
        let text = unsafe { std::ffi::CStr::from_ptr(decompressed).to_str().unwrap() };
        assert_eq!(text, payload);

        // Free the NUL-terminated heap buffers (payload len + trailing NUL).
        unsafe {
            let comp_slice = std::ptr::slice_from_raw_parts_mut(compressed as *mut u8, out_len as usize + 1);
            drop(Box::from_raw(comp_slice));
            let dec_slice =
                std::ptr::slice_from_raw_parts_mut(decompressed as *mut u8, dec_len as usize + 1);
            drop(Box::from_raw(dec_slice));
        }
    }
}
