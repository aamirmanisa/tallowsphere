// tallow.tls_profile — TLS/JA4 fingerprint profiles for browser impersonation.
//
// Pre-built TLS handshake profiles matching real Chrome, Firefox, Safari,
// and Edge configurations for TLS fingerprint evasion.

struct TLSProfile {
    name: String,
    ja4: String,
    user_agent: String,
    tls_version: String,
    cipher_count: Int,
    supports_h2: Bool,
    grease: Bool,
}

// List all available TLS profiles
native fn TLSProfile.list() -> []TLSProfile

// Get a specific profile by name (chrome_131, firefox_132, safari_18, edge_131)
native fn TLSProfile.get(name: String) -> TLSProfile

// Generate curl-impersonate compatible arguments
native fn TLSProfile.to_curl_args(self) -> String

// Generate matching HTTP headers
native fn TLSProfile.to_headers(self) -> Map<String, String>
