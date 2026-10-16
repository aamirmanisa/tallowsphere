// tallow.csrf — CSRF token auto-extraction and request signing
//
// CSRF tokens are security tokens embedded in web pages that must be
// included in subsequent requests. This module extracts them from a
// landing page and signs follow-up requests.
//
// Extraction sources (in priority order):
//   - <meta name="csrf-token" content="...">
//   - <meta name="csrf-param" content="...">
//   - <input type="hidden" name="__RequestVerificationToken" value="...">
//   - <input type="hidden" name="authenticity_token" value="...">
//   - Cookie: XSRF-TOKEN
//   - Cookie: csrf_token
//   - Header: X-CSRF-Token

struct CsrfToken {
    token:      String,
    field_name: String,
    source:     String,  // "meta", "input", "cookie", "header"
}

struct CsrfSession {
    landing_url: String,
    tokens:      []CsrfToken,
    cookies:     Map<String, String>,
}

struct CsrfRequest {
    url:     String,
    method:  String,
    headers: Map<String, String>,
    body:    String?,
}

impl CsrfSession {
    /// Extract CSRF tokens from a URL.
    /// Visits the page in browser mode and detects all known token patterns.
    fn extract(url: String) -> CsrfSession {
        // native: launches browser, visits landing page, extracts tokens
    }

    /// Sign a request with extracted CSRF tokens.
    /// Returns a new CsrfRequest with CSRF headers/fields injected.
    fn sign_request(session: CsrfSession, request: CsrfRequest) -> CsrfRequest {
        // native: copies request with added CSRF token headers/body fields
    }
}
