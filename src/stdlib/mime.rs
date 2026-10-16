//! Standard library: `tallow.mime` — MIME type detection.
//!
//! Real implementation of the `tallow.mime` module backed by a static
//! extension table and magic-byte sniffing, mirroring the declarations in
//! `stdlib/mime.tl`. Dispatch returns `None` for unrecognized functions so
//! callers can fall through to other dispatch mechanisms.

use super::StdlibResult;
use crate::interp::Value;

/// Contract-level dispatch for `tallow.mime.*` functions.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "from_extension" => {
            let ext = match args.first() {
                Some(Value::String(s)) => s.clone(),
                _ => {
                    return Some(Err(
                        "mime.from_extension: expected a String extension".into()
                    ))
                }
            };
            Some(Ok(Value::String(from_extension(&ext))))
        }
        "from_path" => {
            let path = match args.first() {
                Some(Value::String(s)) => s.clone(),
                _ => {
                    return Some(Err(
                        "mime.from_path: expected a String path".into()
                    ))
                }
            };
            Some(Ok(Value::String(from_path(&path))))
        }
        "from_bytes" => {
            let bytes = match args.first() {
                Some(Value::Bytes(b)) => b.clone(),
                Some(Value::String(s)) => s.as_bytes().to_vec(),
                _ => {
                    return Some(Err(
                        "mime.from_bytes: expected a Bytes (or String) argument".into()
                    ))
                }
            };
            Some(Ok(Value::String(from_bytes(&bytes))))
        }
        "is_text" => {
            let mime = match args.first() {
                Some(Value::String(s)) => s.clone(),
                _ => {
                    return Some(Err("mime.is_text: expected a String MIME type".into()))
                }
            };
            Some(Ok(Value::Bool(is_text(&mime))))
        }
        "is_image" => {
            let mime = match args.first() {
                Some(Value::String(s)) => s.clone(),
                _ => {
                    return Some(Err("mime.is_image: expected a String MIME type".into()))
                }
            };
            Some(Ok(Value::Bool(is_image(&mime))))
        }
        _ => None,
    }
}

/// Contract-level dispatch for `tallow.mime.*` struct methods.
pub fn dispatch_method(_object: &Value, _method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    None
}

/// Detect MIME type from a file extension (no leading dot).
pub fn from_extension(ext: &str) -> String {
    let e = ext.to_lowercase();
    let e = e.strip_prefix('.').unwrap_or(&e);
    match e {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "ico" => "image/x-icon",
        "avif" => "image/avif",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "tar" => "application/x-tar",
        "7z" => "application/x-7z-compressed",
        "txt" => "text/plain",
        "md" => "text/markdown",
        "csv" => "text/csv",
        "tsv" => "text/tab-separated-values",
        "rtf" => "application/rtf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mkv" => "video/x-matroska",
        "mov" => "video/quicktime",
        "avi" => "video/x-msvideo",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "flac" => "audio/flac",
        "m4a" => "audio/mp4",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "eot" => "application/vnd.ms-fontobject",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "apk" => "application/vnd.android.package-archive",
        "bin" | "exe" | "dll" | "so" | "dylib" => "application/octet-stream",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Detect MIME type from a file path by its extension.
pub fn from_path(path: &str) -> String {
    match path.rsplit('.').next() {
        Some(ext) if !ext.is_empty() && path.contains('.') => from_extension(ext),
        _ => "application/octet-stream".to_string(),
    }
}

/// Detect MIME type from file content via magic-byte sniffing.
pub fn from_bytes(data: &[u8]) -> String {
    if data.len() >= 8 && &data[0..4] == b"\x89PNG" {
        return "image/png".to_string();
    }
    if data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
        return "image/jpeg".to_string();
    }
    if data.len() >= 4 && &data[0..4] == b"GIF8" {
        return "image/gif".to_string();
    }
    if data.len() >= 4 && &data[0..4] == b"RIFF" && data.len() >= 12 && &data[8..12] == b"WEBP" {
        return "image/webp".to_string();
    }
    if data.len() >= 4 && &data[0..4] == b"\x00\x00\x01\x00" {
        return "image/x-icon".to_string();
    }
    if data.len() >= 2 && &data[0..2] == b"BM" {
        return "image/bmp".to_string();
    }
    if data.len() >= 4 && &data[0..4] == b"%PDF" {
        return "application/pdf".to_string();
    }
    if data.len() >= 4 && &data[0..4] == b"PK\x03\x04" {
        return "application/zip".to_string();
    }
    if data.len() >= 2 && data[0] == 0x1F && data[1] == 0x8B {
        return "application/gzip".to_string();
    }
    if data.len() >= 4 && &data[0..4] == b"\x00asm" {
        return "application/wasm".to_string();
    }
    if data.len() >= 8 && &data[0..8] == b"\x89JFIF\x00" {
        return "image/jpeg".to_string();
    }
    if data.len() >= 4 && &data[0..4] == b"OggS" {
        return "audio/ogg".to_string();
    }
    if data.len() >= 4 && &data[0..4] == b"fLaC" {
        return "audio/flac".to_string();
    }
    // Text sniffing: UTF-8 without NUL bytes in the first 512 bytes is text.
    let probe = &data[..data.len().min(512)];
    if !probe.contains(&0) && std::str::from_utf8(probe).is_ok() {
        return "text/plain".to_string();
    }
    "application/octet-stream".to_string()
}

/// Check whether a MIME type is text-based.
pub fn is_text(mime: &str) -> bool {
    mime.starts_with("text/")
        || matches!(
            mime,
            "application/json" | "application/xml" | "application/javascript"
        )
}

/// Check whether a MIME type is an image.
pub fn is_image(mime: &str) -> bool {
    mime.starts_with("image/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_lookup() {
        assert_eq!(from_extension("html"), "text/html");
        assert_eq!(from_extension("PNG"), "image/png");
        assert_eq!(from_extension(".pdf"), "application/pdf");
        assert_eq!(from_extension("unknown_thing"), "application/octet-stream");
    }

    #[test]
    fn path_lookup() {
        assert_eq!(from_path("foo/bar/baz.json"), "application/json");
        assert_eq!(from_path("archive.tar.gz"), "application/gzip");
        assert_eq!(from_path("noextension"), "application/octet-stream");
    }

    #[test]
    fn magic_bytes() {
        assert_eq!(from_bytes(b"\x89PNG\r\n\x1a\n"), "image/png");
        assert_eq!(from_bytes(b"\xFF\xD8\xFF\xE0"), "image/jpeg");
        assert_eq!(from_bytes(b"%PDF-1.7"), "application/pdf");
        assert_eq!(from_bytes(b"PK\x03\x04..."), "application/zip");
        assert_eq!(from_bytes(b"\x1f\x8b\x08\x00"), "application/gzip");
        assert_eq!(from_bytes(b"\x00asm\x01\x00\x00\x00"), "application/wasm");
        assert_eq!(from_bytes(b"hello plain text"), "text/plain");
        assert_eq!(from_bytes(&[0u8, 1, 2, 3]), "application/octet-stream");
    }

    #[test]
    fn classification() {
        assert!(is_text("text/html"));
        assert!(is_text("application/json"));
        assert!(!is_text("image/png"));
        assert!(is_image("image/png"));
        assert!(!is_image("application/pdf"));
    }

    #[test]
    fn dispatch_routing() {
        assert!(dispatch("from_extension", vec![Value::String("gif".into())])
            .is_some());
        assert!(dispatch("from_extension", vec![]).is_some()); // error, but recognized
        assert!(dispatch("nonsense", vec![]).is_none());
    }
}
