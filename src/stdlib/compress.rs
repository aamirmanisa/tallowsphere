//! Standard library: `tallow.compress` -- gzip/zstd/brotli compression.

use super::StdlibResult;
use crate::interp::Value;

use base64::Engine;
use std::io::{Read as IoRead, Write as IoWrite};

/// Dispatch a `tallow.compress.*` function call.
///
/// Intercepts ALL compress functions with real implementations.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "gzip" | "deflate" => Some(compress_gzip(args)),
        "gunzip" | "inflate" => Some(decompress_gzip(args)),
        "zstd" => Some(compress_zstd(args)),
        "unzstd" => Some(decompress_zstd(args)),
        "brotli" => Some(compress_brotli(args)),
        "unbrotli" => Some(decompress_brotli(args)),

        // Declared in stdlib/compress.tl with empty `// native:` bodies and
        // previously absent from every dispatcher. Implemented 2026-10-12.
        // Contract: `Bytes` is base64 at runtime (this module's existing
        // convention), so both are base64 in -> base64 out, and
        // `decompress_with(compress_with(x, algo, level), algo) == x`.
        "compress_with" => Some(compress_with(args)),
        "decompress_with" => Some(decompress_with(args)),

        _ => None,
    }
}

/// Dispatch a method call on a `tallow.compress` object.
pub fn dispatch_method(_object: &Value, _method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    None
}

pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub(crate) fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|e| format!("compress: base64 decode error: {e}"))
}

fn extract_string_arg(args: &[Value], fn_name: &str) -> Result<String, String> {
    args.first()
        .map(|v| v.as_string())
        .ok_or_else(|| format!("{fn_name} requires a string argument"))
}

// ── gzip ──

fn compress_gzip(args: Vec<Value>) -> StdlibResult {
    let data = extract_string_arg(&args, "compress.gzip")?;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(data.as_bytes())
        .map_err(|e| format!("compress.gzip: {e}"))?;
    let compressed = encoder.finish().map_err(|e| format!("compress.gzip: {e}"))?;
    Ok(Value::String(b64_encode(&compressed)))
}

fn decompress_gzip(args: Vec<Value>) -> StdlibResult {
    let encoded = extract_string_arg(&args, "compress.gunzip")?;
    let compressed = b64_decode(&encoded)?;
    let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
    let mut result = String::new();
    decoder
        .read_to_string(&mut result)
        .map_err(|e| format!("compress.gunzip: {e}"))?;
    Ok(Value::String(result))
}

// ── zstd ──

fn compress_zstd(args: Vec<Value>) -> StdlibResult {
    let data = extract_string_arg(&args, "compress.zstd")?;
    let compressed =
        zstd::encode_all(data.as_bytes(), 3).map_err(|e| format!("compress.zstd: {e}"))?;
    Ok(Value::String(b64_encode(&compressed)))
}

fn decompress_zstd(args: Vec<Value>) -> StdlibResult {
    let encoded = extract_string_arg(&args, "compress.unzstd")?;
    let compressed = b64_decode(&encoded)?;
    let decompressed = zstd::decode_all(std::io::Cursor::new(compressed))
        .map_err(|e| format!("compress.unzstd: {e}"))?;
    String::from_utf8(decompressed)
        .map(Value::String)
        .map_err(|e| format!("compress.unzstd: invalid UTF-8: {e}"))
}

// ── brotli ──

fn compress_brotli(args: Vec<Value>) -> StdlibResult {
    let data = extract_string_arg(&args, "compress.brotli")?;
    let mut compressed = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 6, 22);
        writer
            .write_all(data.as_bytes())
            .map_err(|e| format!("compress.brotli: {e}"))?;
        // flush on drop
    }
    Ok(Value::String(b64_encode(&compressed)))
}

fn decompress_brotli(args: Vec<Value>) -> StdlibResult {
    let encoded = extract_string_arg(&args, "compress.unbrotli")?;
    let compressed = b64_decode(&encoded)?;
    let mut decompressed = Vec::new();
    let mut reader = brotli::Decompressor::new(&compressed[..], 4096);
    reader
        .read_to_end(&mut decompressed)
        .map_err(|e| format!("compress.unbrotli: {e}"))?;
    String::from_utf8(decompressed)
        .map(Value::String)
        .map_err(|e| format!("compress.unbrotli: invalid UTF-8: {e}"))
}

// ── Algorithm-parameterised variants ─────────────────────────────────────────

/// Accept an `Algorithm` supplied either as a string (`"zstd"`) or as an enum
/// value (`Algorithm.Zstd`) — the `.tl` declares an enum, but callers written
/// against the string form should not break.
fn extract_algo(args: &[Value], idx: usize, fn_name: &str) -> Result<String, String> {
    match args.get(idx) {
        Some(Value::String(s)) => Ok(s.to_ascii_lowercase()),
        Some(Value::Enum { variant, .. }) => Ok(variant.to_ascii_lowercase()),
        _ => Err(format!(
            "{fn_name} expects an Algorithm (string or enum) as argument {}",
            idx + 1
        )),
    }
}

pub(crate) fn default_level(algo: &str) -> i32 {
    match algo {
        "brotli" => 6,
        _ => 3,
    }
}

pub(crate) fn compress_bytes(raw: &[u8], algo: &str, level: i32) -> Result<Vec<u8>, String> {
    match algo {
        "zstd" => zstd::encode_all(raw, level).map_err(|e| format!("compress_with(zstd): {e}")),
        "gzip" | "deflate" => {
            let mut encoder = flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::new(level.max(0) as u32),
            );
            encoder
                .write_all(raw)
                .map_err(|e| format!("compress_with(gzip): {e}"))?;
            encoder
                .finish()
                .map_err(|e| format!("compress_with(gzip): {e}"))
        }
        "brotli" => {
            let mut out = Vec::new();
            {
                // level 0..=11 is brotli's valid range; clamp rather than error
                // so an out-of-range level degrades instead of failing the call.
                let mut writer =
                    brotli::CompressorWriter::new(&mut out, 4096, level.clamp(0, 11) as u32, 22);
                writer
                    .write_all(raw)
                    .map_err(|e| format!("compress_with(brotli): {e}"))?;
            }
            Ok(out)
        }
        other => Err(format!(
            "compress_with: unsupported algorithm '{other}' (expected zstd, gzip, deflate or brotli)"
        )),
    }
}

pub(crate) fn decompress_bytes(raw: &[u8], algo: &str) -> Result<Vec<u8>, String> {
    match algo {
        "zstd" => zstd::decode_all(std::io::Cursor::new(raw))
            .map_err(|e| format!("decompress_with(zstd): {e}")),
        "gzip" | "deflate" => {
            let mut decoder = flate2::read::GzDecoder::new(raw);
            let mut out = Vec::new();
            decoder
                .read_to_end(&mut out)
                .map_err(|e| format!("decompress_with(gzip): {e}"))?;
            Ok(out)
        }
        "brotli" => {
            let mut out = Vec::new();
            let mut reader = brotli::Decompressor::new(raw, 4096);
            reader
                .read_to_end(&mut out)
                .map_err(|e| format!("decompress_with(brotli): {e}"))?;
            Ok(out)
        }
        other => Err(format!(
            "decompress_with: unsupported algorithm '{other}' (expected zstd, gzip, deflate or brotli)"
        )),
    }
}

/// `compress_with(data: Bytes, algo: Algorithm, level: i32) -> Bytes`
fn compress_with(args: Vec<Value>) -> StdlibResult {
    let encoded = extract_string_arg(&args, "compress.compress_with")?;
    let raw = b64_decode(&encoded)?;
    let algo = extract_algo(&args, 1, "compress.compress_with")?;
    let level = match args.get(2) {
        Some(Value::Int(n)) => *n as i32,
        _ => default_level(&algo),
    };
    let out = compress_bytes(&raw, &algo, level)?;
    Ok(Value::String(b64_encode(&out)))
}

/// `decompress_with(data: Bytes, algo: Algorithm) -> Result<Bytes>`
fn decompress_with(args: Vec<Value>) -> StdlibResult {
    let encoded = extract_string_arg(&args, "compress.decompress_with")?;
    let raw = b64_decode(&encoded)?;
    let algo = extract_algo(&args, 1, "compress.decompress_with")?;
    let out = decompress_bytes(&raw, &algo)?;
    Ok(Value::String(b64_encode(&out)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of the pair: what goes in comes back out.
    #[test]
    fn compress_with_round_trips_through_decompress_with() {
        for algo in ["zstd", "gzip", "brotli"] {
            let payload = "the quick brown fox jumps over the lazy dog";
            let input = b64_encode(payload.as_bytes());
            let compressed = compress_with(vec![
                Value::String(input),
                Value::String(algo.into()),
                Value::Int(3),
            ])
            .unwrap_or_else(|e| panic!("{algo}: compress failed: {e}"));
            let compressed_b64 = match compressed {
                Value::String(s) => s,
                other => panic!("{algo}: expected String, got {other:?}"),
            };
            let restored = decompress_with(vec![
                Value::String(compressed_b64),
                Value::String(algo.into()),
            ])
            .unwrap_or_else(|e| panic!("{algo}: decompress failed: {e}"));
            let restored_raw = match restored {
                Value::String(s) => b64_decode(&s).expect("restored must be base64"),
                other => panic!("{algo}: expected String, got {other:?}"),
            };
            assert_eq!(String::from_utf8(restored_raw).unwrap(), payload, "{algo}");
        }
    }

    #[test]
    fn compress_with_accepts_enum_algorithms_too() {
        let input = Value::String(b64_encode(b"hello"));
        let r = compress_with(vec![
            input,
            Value::Enum {
                enum_name: "Algorithm".into(),
                variant: "zstd".into(),
                // Synthetic value with no enum declaration behind it.
                discriminant: -1,
                fields: vec![],
            },
        ]);
        assert!(r.is_ok(), "enum algorithm form should be accepted");
    }

    #[test]
    fn compress_with_rejects_unknown_algorithm() {
        let r = compress_with(vec![
            Value::String(b64_encode(b"x")),
            Value::String("lzma".into()),
        ]);
        assert!(r.is_err());
    }

    #[test]
    fn compress_with_rejects_missing_or_non_string_args() {
        assert!(compress_with(vec![]).is_err());
        assert!(compress_with(vec![Value::Int(1), Value::String("zstd".into())]).is_err());
    }
}
