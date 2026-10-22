// tallow.mime — MIME type detection

/// Detect MIME type from file extension
fn from_extension(ext: String) -> String {
    match ext {
        "html" -> "text/html"
        "css"  -> "text/css"
        "js"   -> "application/javascript"
        "json" -> "application/json"
        "xml"  -> "application/xml"
        "png"  -> "image/png"
        "jpg"  -> "image/jpeg"
        "jpeg" -> "image/jpeg"
        "gif"  -> "image/gif"
        "svg"  -> "image/svg+xml"
        "pdf"  -> "application/pdf"
        "zip"  -> "application/zip"
        "gz"   -> "application/gzip"
        "txt"  -> "text/plain"
        "csv"  -> "text/csv"
        "mp4"  -> "video/mp4"
        "mp3"  -> "audio/mpeg"
        "wasm" -> "application/wasm"
        _      -> "application/octet-stream"
    }
}

/// Detect MIME type from file path
fn from_path(path: String) -> String {
    let parts = path.split(".")
    if parts.len > 1 {
        from_extension(parts[parts.len - 1])
    } else {
        "application/octet-stream"
    }
}

/// Detect MIME type from file content (magic bytes)
// native: inspects magic bytes to detect type
native fn from_bytes(data: Bytes) -> String

/// Check if MIME type is text-based
fn is_text(mime: String) -> bool {
    mime.starts_with("text/") || mime == "application/json" || mime == "application/xml"
}

/// Check if MIME type is image
fn is_image(mime: String) -> bool {
    mime.starts_with("image/")
}
