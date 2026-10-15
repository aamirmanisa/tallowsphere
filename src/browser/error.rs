//! Browser error types for the Tallow browser automation module.
//!
//! Provides typed error variants for all browser operations including
//! navigation, CDP protocol errors, process crashes, and timeouts.

use thiserror::Error;

/// Top-level error type for all browser operations.
#[derive(Debug, Error)]
pub enum BrowserError {
    /// WebSocket connection to browser failed.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// Navigation to a URL failed with a specific cause.
    #[error("navigation failed: {0}")]
    NavigationFailed(#[from] NavigationError),

    /// An operation exceeded its configured timeout.
    #[error("timeout: {operation} ({detail})")]
    Timeout {
        operation: &'static str,
        detail: String,
    },

    /// CSS/XPath selector returned no matching elements.
    #[error("element not found: {selector}")]
    ElementNotFound { selector: String },

    /// The browser context was disposed or closed.
    #[error("browser context closed")]
    ContextClosed,

    /// Chromium process exited unexpectedly.
    #[error("browser process crashed: {0}")]
    ProcessCrashed(String),

    /// CDP protocol-level error returned by the browser.
    #[error("CDP protocol error: {code} {message}")]
    CdpError { code: i64, message: String },

    /// Browser binary download failed.
    #[error("download failed: {0}")]
    DownloadFailed(String),

    /// Navigation blocked by robots.txt rules.
    #[error("robots.txt disallowed: {0}")]
    RobotsTxtDisallowed(String),

    /// Rate limit for a domain was exceeded.
    #[error("rate limit exceeded for domain: {0}")]
    RateLimitExceeded(String),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    JsonError(String),

    /// File not found (e.g., for file upload).
    #[error("file not found: {0}")]
    FileNotFound(String),

    /// Shadow root not found on an element where one was expected.
    #[error("shadow root not found")]
    ShadowRootNotFound,

    /// Iframe access denied (e.g., cross-origin restriction).
    #[error("iframe access denied: {selector}")]
    IframeAccessDenied { selector: String },

    /// Network interception error (Fetch domain).
    #[error("network interception error: {0}")]
    InterceptError(String),

    /// Fetch domain error for a specific request.
    #[error("fetch domain error for request {request_id}: {detail}")]
    FetchDomainError { request_id: String, detail: String },

    /// Pool operation failure.
    #[error("pool error: {0}")]
    PoolError(String),

    /// All pool instances are busy and at max capacity.
    #[error("pool exhausted: all instances busy")]
    PoolExhausted,

    /// Session operation failure (save, load, capture, restore).
    #[error("session error: {0}")]
    SessionError(String),

    /// DOM storage access failure.
    #[error("storage error: {0}")]
    StorageError(String),

    /// PQC encryption or decryption failure.
    #[error("encryption error: {0}")]
    EncryptionError(String),

    /// Authentication operation failure (login persistence, TOTP, OAuth).
    #[error("auth error: {0}")]
    AuthError(String),

    /// CAPTCHA operation failure.
    #[error("captcha error: {0}")]
    CaptchaError(String),

    /// External CAPTCHA solver took too long.
    #[error("captcha solve timeout")]
    CaptchaSolveTimeout,

    /// No CAPTCHA detected on the page.
    #[error("captcha not found on page")]
    CaptchaNotFound,

    /// A browser action failed (e.g., DOM snapshot, batch extraction).
    #[error("action failed: {0}")]
    ActionFailed(String),

    /// Downloaded file checksum does not match the expected value.
    #[error("checksum mismatch for {file}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        expected: String,
        actual: String,
        file: String,
    },

    /// No in-repo SHA-256 pin exists for this Chrome-for-Testing artifact
    /// and the audited `TALLOW_CFT_ALLOW_UNPINNED=1` override is not set.
    /// Refused on principle (audit-05 F-3): an unverified browser binary is
    /// a supply-chain risk, not a skipped nicety.
    #[error(
        "no SHA-256 pin for {variant} {version} ({platform}) — refusing an unverified install; \
         re-pin in src/browser/cft_pins.rs, or set TALLOW_CFT_ALLOW_UNPINNED=1 for an audited override"
    )]
    UnpinnedArtifact {
        version: String,
        platform: String,
        variant: String,
    },
}

/// Typed navigation error variants mapping Chrome net:: errors.
#[derive(Debug, Error)]
pub enum NavigationError {
    /// DNS resolution failed (net::ERR_NAME_NOT_RESOLVED).
    #[error("DNS resolution failed: {0}")]
    DnsFailure(String),

    /// SSL/TLS handshake or certificate error (net::ERR_SSL_PROTOCOL_ERROR).
    #[error("SSL/TLS error: {0}")]
    SslError(String),

    /// Connection timed out (net::ERR_CONNECTION_TIMED_OUT).
    #[error("connection timed out")]
    Timeout,

    /// HTTP error status code.
    #[error("HTTP error: {0}")]
    HttpError(u16),

    /// Connection refused (net::ERR_CONNECTION_REFUSED).
    #[error("connection refused")]
    ConnectionRefused,

    /// Other Chrome net:: error not specifically categorized.
    #[error("Chrome net error: {0}")]
    ChromeNetError(String),
}

impl From<tokio_tungstenite::tungstenite::Error> for BrowserError {
    fn from(err: tokio_tungstenite::tungstenite::Error) -> Self {
        BrowserError::ConnectionFailed(err.to_string())
    }
}

impl From<serde_json::Error> for BrowserError {
    fn from(err: serde_json::Error) -> Self {
        BrowserError::JsonError(err.to_string())
    }
}

/// Maps a Chrome net:: error string from CDP to a typed NavigationError.
pub fn map_chrome_net_error(error_text: &str) -> NavigationError {
    match error_text {
        s if s.contains("ERR_NAME_NOT_RESOLVED") => {
            NavigationError::DnsFailure(error_text.to_string())
        }
        s if s.contains("ERR_SSL_PROTOCOL_ERROR")
            || s.contains("ERR_SSL_VERSION_OR_CIPHER_MISMATCH")
            || s.contains("ERR_CERT") =>
        {
            NavigationError::SslError(error_text.to_string())
        }
        s if s.contains("ERR_CONNECTION_TIMED_OUT") || s.contains("ERR_TIMED_OUT") => {
            NavigationError::Timeout
        }
        s if s.contains("ERR_CONNECTION_REFUSED") => NavigationError::ConnectionRefused,
        _ => NavigationError::ChromeNetError(error_text.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_error_display_connection_failed() {
        let err = BrowserError::ConnectionFailed("ws refused".to_string());
        assert_eq!(err.to_string(), "connection failed: ws refused");
    }

    #[test]
    fn test_browser_error_display_timeout() {
        let err = BrowserError::Timeout {
            operation: "navigate",
            detail: "waiting for load".to_string(),
        };
        assert_eq!(err.to_string(), "timeout: navigate (waiting for load)");
    }

    #[test]
    fn test_browser_error_display_element_not_found() {
        let err = BrowserError::ElementNotFound {
            selector: "div.missing".to_string(),
        };
        assert_eq!(err.to_string(), "element not found: div.missing");
    }

    #[test]
    fn test_browser_error_display_context_closed() {
        let err = BrowserError::ContextClosed;
        assert_eq!(err.to_string(), "browser context closed");
    }

    #[test]
    fn test_browser_error_display_process_crashed() {
        let err = BrowserError::ProcessCrashed("signal 11".to_string());
        assert_eq!(err.to_string(), "browser process crashed: signal 11");
    }

    #[test]
    fn test_browser_error_display_cdp_error() {
        let err = BrowserError::CdpError {
            code: -32601,
            message: "method not found".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "CDP protocol error: -32601 method not found"
        );
    }

    #[test]
    fn test_browser_error_display_download_failed() {
        let err = BrowserError::DownloadFailed("404 not found".to_string());
        assert_eq!(err.to_string(), "download failed: 404 not found");
    }

    #[test]
    fn test_browser_error_display_robots_txt() {
        let err = BrowserError::RobotsTxtDisallowed("/private".to_string());
        assert_eq!(err.to_string(), "robots.txt disallowed: /private");
    }

    #[test]
    fn test_browser_error_display_rate_limit() {
        let err = BrowserError::RateLimitExceeded("example.com".to_string());
        assert_eq!(
            err.to_string(),
            "rate limit exceeded for domain: example.com"
        );
    }

    #[test]
    fn test_browser_error_display_json_error() {
        let err = BrowserError::JsonError("unexpected token".to_string());
        assert_eq!(err.to_string(), "JSON error: unexpected token");
    }

    #[test]
    fn test_browser_error_display_file_not_found() {
        let err = BrowserError::FileNotFound("/path/to/missing.pdf".to_string());
        assert_eq!(err.to_string(), "file not found: /path/to/missing.pdf");
    }

    #[test]
    fn test_navigation_error_display() {
        let err = NavigationError::DnsFailure("example.invalid".to_string());
        assert_eq!(err.to_string(), "DNS resolution failed: example.invalid");

        let err = NavigationError::SslError("cert expired".to_string());
        assert_eq!(err.to_string(), "SSL/TLS error: cert expired");

        let err = NavigationError::Timeout;
        assert_eq!(err.to_string(), "connection timed out");

        let err = NavigationError::HttpError(404);
        assert_eq!(err.to_string(), "HTTP error: 404");

        let err = NavigationError::ConnectionRefused;
        assert_eq!(err.to_string(), "connection refused");

        let err = NavigationError::ChromeNetError("ERR_ABORTED".to_string());
        assert_eq!(err.to_string(), "Chrome net error: ERR_ABORTED");
    }

    #[test]
    fn test_navigation_error_from_browser_error() {
        let nav_err = NavigationError::Timeout;
        let browser_err: BrowserError = nav_err.into();
        assert!(matches!(browser_err, BrowserError::NavigationFailed(_)));
        assert!(browser_err.to_string().contains("connection timed out"));
    }

    #[test]
    fn test_from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let browser_err: BrowserError = json_err.into();
        assert!(matches!(browser_err, BrowserError::JsonError(_)));
    }

    #[test]
    fn test_map_chrome_net_error_dns() {
        let err = map_chrome_net_error("net::ERR_NAME_NOT_RESOLVED");
        assert!(matches!(err, NavigationError::DnsFailure(_)));
    }

    #[test]
    fn test_map_chrome_net_error_ssl() {
        let err = map_chrome_net_error("net::ERR_SSL_PROTOCOL_ERROR");
        assert!(matches!(err, NavigationError::SslError(_)));

        let err = map_chrome_net_error("net::ERR_CERT_AUTHORITY_INVALID");
        assert!(matches!(err, NavigationError::SslError(_)));
    }

    #[test]
    fn test_map_chrome_net_error_timeout() {
        let err = map_chrome_net_error("net::ERR_CONNECTION_TIMED_OUT");
        assert!(matches!(err, NavigationError::Timeout));

        let err = map_chrome_net_error("net::ERR_TIMED_OUT");
        assert!(matches!(err, NavigationError::Timeout));
    }

    #[test]
    fn test_map_chrome_net_error_refused() {
        let err = map_chrome_net_error("net::ERR_CONNECTION_REFUSED");
        assert!(matches!(err, NavigationError::ConnectionRefused));
    }

    #[test]
    fn test_map_chrome_net_error_other() {
        let err = map_chrome_net_error("net::ERR_ABORTED");
        assert!(matches!(err, NavigationError::ChromeNetError(_)));
    }

    #[test]
    fn test_browser_error_display_shadow_root_not_found() {
        let err = BrowserError::ShadowRootNotFound;
        assert_eq!(err.to_string(), "shadow root not found");
    }

    #[test]
    fn test_browser_error_display_iframe_access_denied() {
        let err = BrowserError::IframeAccessDenied {
            selector: "iframe.embedded".to_string(),
        };
        assert_eq!(err.to_string(), "iframe access denied: iframe.embedded");
    }

    #[test]
    fn test_browser_error_display_intercept_error() {
        let err = BrowserError::InterceptError("handler panic".to_string());
        assert_eq!(
            err.to_string(),
            "network interception error: handler panic"
        );
    }

    #[test]
    fn test_browser_error_display_fetch_domain_error() {
        let err = BrowserError::FetchDomainError {
            request_id: "req-42".to_string(),
            detail: "body too large".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "fetch domain error for request req-42: body too large"
        );
    }

    #[test]
    fn test_browser_error_display_checksum_mismatch() {
        let err = BrowserError::ChecksumMismatch {
            expected: "aabb".to_string(),
            actual: "ccdd".to_string(),
            file: "chrome.zip".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "checksum mismatch for chrome.zip: expected aabb, got ccdd"
        );
    }
}
