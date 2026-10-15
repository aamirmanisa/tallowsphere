//! Cover bytes — the byte-constant "ordinary 404" that every unauthenticated
//! outcome maps to. Byte-identical to the veil v0 reference core so the
//! battery's cover-equality acceptance transfers across the port.

use std::sync::OnceLock;

/// ASCII body of the cover response.
pub const COVER_BODY: &str = "<!doctype html><html><head><title>404 Not Found</title></head>\
<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>";

/// Total cover length in bytes (asserted).
pub const COVER_LEN: usize = 260;

/// sha256 of the full cover response (fidelity anchor across the port).
pub const COVER_SHA256_HEX: &str =
    "f23589f6bd9efe13270d9eea72e0c1d94a1c4cbf61d2491682bbfdfea7158bfe";

static COVER_CELL: OnceLock<Vec<u8>> = OnceLock::new();

/// The full cover response (`HTTP/1.1 404` + body), built once.
pub fn cover() -> &'static [u8] {
    COVER_CELL.get_or_init(|| {
        let out = format!(
            "HTTP/1.1 404 Not Found\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n{}",
            COVER_BODY.len(),
            COVER_BODY
        );
        let bytes = out.into_bytes();
        debug_assert_eq!(bytes.len(), COVER_LEN);
        bytes
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn cover_is_fidelity_anchored() {
        let c = cover();
        assert_eq!(c.len(), COVER_LEN, "cover length drifted");
        let sha = hex::encode(Sha256::digest(c));
        assert_eq!(
            sha, COVER_SHA256_HEX,
            "cover sha256 drifted from the reference"
        );
    }
}
