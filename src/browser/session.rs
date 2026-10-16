//! Browser session persistence for Tallow.
//!
//! Provides cookie import/export via CDP, localStorage/sessionStorage access
//! via the DOMStorage domain, and AEAD-encrypted (AES-256-GCM) SQLite save/restore of
//! complete session state.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::cdp::CdpClient;
use super::error::BrowserError;

// ── Cookie types ─────────────────────────────────────────────────────

/// A browser cookie as returned/consumed by the CDP Network domain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CdpCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    /// Unix timestamp in seconds. Values <= 0 indicate a session cookie.
    #[serde(default)]
    pub expires: f64,
    #[serde(default)]
    pub http_only: bool,
    #[serde(default)]
    pub secure: bool,
    #[serde(default)]
    pub same_site: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<i32>,
}

// ── Cookie operations (BRSS-01) ──────────────────────────────────────

/// Retrieve all cookies from the browser context.
pub async fn get_cookies(
    client: &CdpClient,
    session_id: &str,
) -> Result<Vec<CdpCookie>, BrowserError> {
    let result = client
        .send_command_with_session("Network.getCookies", None, session_id)
        .await?;

    let cookies_val = result
        .get("cookies")
        .cloned()
        .unwrap_or(Value::Array(vec![]));

    let cookies: Vec<CdpCookie> = serde_json::from_value(cookies_val)?;
    Ok(cookies)
}

/// Set cookies in the browser context.
///
/// For session cookies (expires <= 0), the `expires` field is omitted
/// from the CDP command to avoid creating persistent cookies from
/// session cookies (CDP pitfall #1).
pub async fn set_cookies(
    client: &CdpClient,
    session_id: &str,
    cookies: &[CdpCookie],
) -> Result<(), BrowserError> {
    for cookie in cookies {
        let mut params = json!({
            "name": cookie.name,
            "value": cookie.value,
            "domain": cookie.domain,
            "path": cookie.path,
            "httpOnly": cookie.http_only,
            "secure": cookie.secure,
        });

        // Only set expires for persistent cookies (> 0 means real expiry)
        if cookie.expires > 0.0 {
            params["expires"] = json!(cookie.expires);
        }

        if !cookie.same_site.is_empty() {
            params["sameSite"] = json!(cookie.same_site);
        }

        client
            .send_command_with_session("Network.setCookie", Some(params), session_id)
            .await?;
    }
    Ok(())
}

/// Clear all cookies from the browser context.
pub async fn clear_cookies(
    client: &CdpClient,
    session_id: &str,
) -> Result<(), BrowserError> {
    client
        .send_command_with_session("Network.clearBrowserCookies", None, session_id)
        .await?;
    Ok(())
}

/// Delete only the cookies whose name starts with any of `prefixes` (case-sensitive),
/// leaving every other cookie intact. Used to reset Cxense meter counters (cX_P,
/// cX_C, _cX_…) before a fresh navigation so the paywall quota never accumulates
/// across pooled-browser reuse. Returns the number of cookies deleted.
pub async fn delete_cookies_by_prefix(
    client: &CdpClient,
    session_id: &str,
    prefixes: &[&str],
) -> Result<usize, BrowserError> {
    let cookies = get_cookies(client, session_id).await?;
    let mut deleted = 0usize;
    for cookie in cookies {
        let matched = prefixes.iter().any(|p| cookie.name.starts_with(p));
        if !matched {
            continue;
        }
        let params = json!({
            "name": cookie.name,
            "domain": cookie.domain,
            "path": cookie.path,
        });
        let r = client
            .send_command_with_session("Network.deleteCookies", Some(params), session_id)
            .await;
        if r.is_ok() {
            deleted += 1;
        }
    }
    Ok(deleted)
}

// ── DOM Storage operations (BRSS-04) ─────────────────────────────────

/// Build the DOMStorage `storageId` parameter.
fn storage_id(security_origin: &str, is_local_storage: bool) -> Value {
    json!({
        "storageId": {
            "securityOrigin": security_origin,
            "isLocalStorage": is_local_storage
        }
    })
}

/// Enable the DOMStorage domain (idempotent).
async fn enable_dom_storage(
    client: &CdpClient,
    session_id: &str,
) -> Result<(), BrowserError> {
    client
        .send_command_with_session("DOMStorage.enable", None, session_id)
        .await?;
    Ok(())
}

/// Retrieve all localStorage items for a given security origin.
pub async fn get_local_storage(
    client: &CdpClient,
    session_id: &str,
    security_origin: &str,
) -> Result<Vec<(String, String)>, BrowserError> {
    get_storage_items(client, session_id, security_origin, true).await
}

/// Retrieve all sessionStorage items for a given security origin.
pub async fn get_session_storage(
    client: &CdpClient,
    session_id: &str,
    security_origin: &str,
) -> Result<Vec<(String, String)>, BrowserError> {
    get_storage_items(client, session_id, security_origin, false).await
}

/// Internal helper: get storage items for either localStorage or sessionStorage.
async fn get_storage_items(
    client: &CdpClient,
    session_id: &str,
    security_origin: &str,
    is_local_storage: bool,
) -> Result<Vec<(String, String)>, BrowserError> {
    enable_dom_storage(client, session_id).await?;

    let params = storage_id(security_origin, is_local_storage);
    let result = client
        .send_command_with_session("DOMStorage.getDOMStorageItems", Some(params), session_id)
        .await?;

    let entries = result
        .get("entries")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut items = Vec::new();
    for entry in entries {
        // CDP returns entries as array of [key, value] arrays
        if let Some(pair) = entry.as_array() {
            if pair.len() >= 2 {
                let key = pair[0].as_str().unwrap_or("").to_string();
                let val = pair[1].as_str().unwrap_or("").to_string();
                items.push((key, val));
            }
        }
    }
    Ok(items)
}

/// Set a single localStorage item.
pub async fn set_local_storage_item(
    client: &CdpClient,
    session_id: &str,
    security_origin: &str,
    key: &str,
    value: &str,
) -> Result<(), BrowserError> {
    set_storage_item(client, session_id, security_origin, key, value, true).await
}

/// Set a single sessionStorage item.
pub async fn set_session_storage_item(
    client: &CdpClient,
    session_id: &str,
    security_origin: &str,
    key: &str,
    value: &str,
) -> Result<(), BrowserError> {
    set_storage_item(client, session_id, security_origin, key, value, false).await
}

/// Internal helper: set a storage item.
async fn set_storage_item(
    client: &CdpClient,
    session_id: &str,
    security_origin: &str,
    key: &str,
    value: &str,
    is_local_storage: bool,
) -> Result<(), BrowserError> {
    enable_dom_storage(client, session_id).await?;

    let params = json!({
        "storageId": {
            "securityOrigin": security_origin,
            "isLocalStorage": is_local_storage
        },
        "key": key,
        "value": value
    });
    client
        .send_command_with_session("DOMStorage.setDOMStorageItem", Some(params), session_id)
        .await?;
    Ok(())
}

/// Clear all localStorage items for a given security origin.
pub async fn clear_local_storage(
    client: &CdpClient,
    session_id: &str,
    security_origin: &str,
) -> Result<(), BrowserError> {
    clear_storage(client, session_id, security_origin, true).await
}

/// Clear all sessionStorage items for a given security origin.
pub async fn clear_session_storage(
    client: &CdpClient,
    session_id: &str,
    security_origin: &str,
) -> Result<(), BrowserError> {
    clear_storage(client, session_id, security_origin, false).await
}

/// Internal helper: clear storage.
async fn clear_storage(
    client: &CdpClient,
    session_id: &str,
    security_origin: &str,
    is_local_storage: bool,
) -> Result<(), BrowserError> {
    enable_dom_storage(client, session_id).await?;

    let params = storage_id(security_origin, is_local_storage);
    client
        .send_command_with_session("DOMStorage.clear", Some(params), session_id)
        .await?;
    Ok(())
}

// ── URL helpers ──────────────────────────────────────────────────────

/// Extract the security origin from a page URL.
///
/// Returns the scheme + host + port (e.g., `https://example.com`).
/// Errors on invalid URLs.
pub fn extract_security_origin(page_url: &str) -> Result<String, BrowserError> {
    let parsed = url::Url::parse(page_url).map_err(|e| {
        BrowserError::SessionError(format!("invalid URL '{}': {}", page_url, e))
    })?;
    let origin = parsed.origin();
    match origin {
        url::Origin::Tuple(scheme, host, port) => {
            let default_port = match scheme.as_str() {
                "http" => 80,
                "https" => 443,
                _ => 0,
            };
            if port == default_port {
                Ok(format!("{}://{}", scheme, host))
            } else {
                Ok(format!("{}://{}:{}", scheme, host, port))
            }
        }
        url::Origin::Opaque(_) => Err(BrowserError::SessionError(format!(
            "opaque origin for URL '{}'",
            page_url
        ))),
    }
}

// ── BrowserSession struct ────────────────────────────────────────────

/// Complete browser session state: cookies + local/session storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserSession {
    /// Session identifier (user-chosen name).
    pub id: String,
    /// All cookies from the browser context.
    pub cookies: Vec<CdpCookie>,
    /// localStorage items keyed by security origin.
    pub local_storage: HashMap<String, Vec<(String, String)>>,
    /// sessionStorage items keyed by security origin.
    pub session_storage: HashMap<String, Vec<(String, String)>>,
    /// Unix timestamp when the session was captured.
    pub created_at: i64,
    /// Optional user-agent string that was active during capture.
    pub user_agent: Option<String>,
    /// Optional persona seed — deterministic per-session behavioral identity
    /// (coherence-aware; stable across sessions for the same persona).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persona_seed: Option<u64>,
    /// Optional fingerprint identity id (device profile) this session is bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint_id: Option<String>,
    /// Optional proxy geolocation descriptor this session is bound to (e.g. "US-Texas-Houston").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_geo: Option<String>,
    /// Optional IANA timezone this session is bound to (e.g. "America/Chicago").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    /// Optional campaign/tenant id for per-campaign compartmentation (G8 §1).
    ///
    /// Sessions sharing the same `campaign_id` belong to the same campaign;
    /// a recovered artifact attributes to a *campaign* but never to other
    /// campaigns that use distinct ids. By convention it mirrors the compile
    /// time `@opsec(profile:"X")` namespace: a function tagged `profile:"X"`
    /// must produce/consume only sessions with `campaign_id == Some("X")`,
    /// giving Tallow one identity namespace from the static call-graph (E0900)
    /// through to the persisted state store. Optional + serde default keeps
    /// every previously persisted session and every existing construction
    /// site backward compatible (old records deserialize as `None`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub campaign_id: Option<String>,
}

impl BrowserSession {
    /// Create a coherence-aware session bound to a seeded persona, fingerprint
    /// identity, proxy geolocation, and timezone.
    ///
    /// All bindings are optional so this remains fully backward compatible with
    /// plain captures (which leave them `None`). The stored context lets
    /// downstream code keep timezone/locale/IP/fingerprint co-varying as one
    /// seeded unit. Pair with [`bind_session_emulation`] to also apply the
    /// matching timezone/locale/geolocation/UA to the live browser context.
    pub fn with_context(
        id: String,
        persona_seed: Option<u64>,
        fingerprint_id: Option<String>,
        proxy_geo: Option<String>,
        timezone: Option<String>,
    ) -> Self {
        Self {
            id,
            cookies: Vec::new(),
            local_storage: HashMap::new(),
            session_storage: HashMap::new(),
            created_at: chrono::Utc::now().timestamp(),
            user_agent: None,
            persona_seed,
            fingerprint_id,
            proxy_geo,
            timezone,
            campaign_id: None,
        }
    }

    /// Bind this session to a campaign/tenant id (per-campaign
    /// compartmentation). Identity-neutral builder: returns the same session
    /// with the campaign stamp applied, so it composes with
    /// [`BrowserSession::with_context`]. See the `campaign_id` field docs for
    /// how this maps to the compile-time `@opsec(profile:"X")` namespace.
    pub fn with_campaign(mut self, campaign_id: Option<String>) -> Self {
        self.campaign_id = campaign_id;
        self
    }

    /// Stamp this session with its coherence binding (persona seed, fingerprint
    /// identity, proxy geolocation, timezone) so the binding is persisted and
    /// restored with the session.
    ///
    /// Identity-neutral builder: composes with [`BrowserSession::with_campaign`]
    /// and [`BrowserSession::with_context`]. When the session is later persisted
    /// via [`save_session`] the full coherence binding is written with it (the
    /// AEAD-encrypted JSON blob already carries every `BrowserSession` field) and
    /// restored by [`load_session`], so loading by the stable `id` lookup key
    /// re-binds the same seeded behavior. All bindings are optional — `None`
    /// leaves a plain (coherence-free) session, keeping old records backward
    /// compatible.
    pub fn with_coherence(
        mut self,
        persona_seed: Option<u64>,
        fingerprint_id: Option<String>,
        proxy_geo: Option<String>,
        timezone: Option<String>,
    ) -> Self {
        self.persona_seed = persona_seed;
        self.fingerprint_id = fingerprint_id;
        self.proxy_geo = proxy_geo;
        self.timezone = timezone;
        self
    }
}

// ── AEAD-encrypted SQLite persistence (BRSS-02, BRSS-03) ─────────────

/// HKDF info string for session-key derivation (domain separation).
const SESSION_KDF_INFO: &[u8] = b"tallow-browser-session-aead-v1";

/// Derive a 256-bit AEAD key from a shared secret using HKDF-SHA256 with a
/// random per-record salt.
///
/// The salt is stored alongside the ciphertext so every record derives an
/// independent key (no KDF re-use across records, no fixed salt).
fn derive_key(
    shared_secret: &[u8],
    salt: &[u8],
) -> Result<[u8; 32], BrowserError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut key = [0u8; 32];
    hk.expand(SESSION_KDF_INFO, &mut key).map_err(|e| {
        BrowserError::EncryptionError(format!("session key derivation failed: {e}"))
    })?;
    Ok(key)
}

/// Encrypt session data with AES-256-GCM (a real AEAD).
///
/// Format: salt (16 bytes, random) || nonce (12 bytes, random) || ciphertext + 16-byte tag.
///
/// This is a standard symmetric AEAD — NOT post-quantum encryption. Older
/// comments called this path "PQC"; it is not. The key is derived from the
/// shared secret via HKDF-SHA256 with a fresh random salt per record, and
/// AES-GCM provides authenticated encryption (confidentiality + integrity)
/// in one pass, replacing the previous homebrew SHA-256-CTR stream cipher
/// with a raw-hash MAC (which was length-extension susceptible and had no
/// KDF salt).
///
/// BREAKING: the on-disk format changed (old: nonce||ct||sha256-mac;
/// new: salt||nonce||ct+tag). Records written by the old cipher can no
/// longer be decrypted and will fail with `MAC verification failed` —
/// they must be re-saved.
fn encrypt_session_data(
    plaintext: &[u8],
    shared_secret: &[u8],
) -> Result<Vec<u8>, BrowserError> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use rand::Rng;

    // Random salt for HKDF + random 96-bit nonce for AES-GCM.
    let mut salt = [0u8; 16];
    rand::rng().fill(&mut salt);
    let key = derive_key(shared_secret, &salt)?;

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| {
        BrowserError::EncryptionError(format!("failed to init AES-256-GCM: {e}"))
    })?;

    let mut nonce = [0u8; 12];
    rand::rng().fill(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| BrowserError::EncryptionError("AES-256-GCM encryption failed".to_string()))?;

    let mut output = Vec::with_capacity(salt.len() + nonce.len() + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt session data encrypted by [`encrypt_session_data`].
///
/// Extracts the salt (first 16 bytes) and nonce (next 12 bytes), re-derives
/// the key, and lets AES-GCM authenticate-and-decrypt. The 16-byte tag is
/// verified internally (constant-time) — any corruption, truncation, or
/// wrong key fails here.
fn decrypt_session_data(
    data: &[u8],
    shared_secret: &[u8],
) -> Result<Vec<u8>, BrowserError> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};

    // Minimum: 16 (salt) + 12 (nonce) + 16 (tag) = 44 bytes.
    if data.len() < 44 {
        return Err(BrowserError::EncryptionError(
            "encrypted data too short".to_string(),
        ));
    }

    let salt = &data[..16];
    let nonce = &data[16..28];
    let ciphertext = &data[28..];

    let key = derive_key(shared_secret, salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| {
        BrowserError::EncryptionError(format!("failed to init AES-256-GCM: {e}"))
    })?;

    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| {
            BrowserError::EncryptionError(
                "MAC verification failed: wrong key or corrupted data".to_string(),
            )
        })
}

/// Initialize (or open) the session SQLite database.
///
/// Creates the `sessions` table if it does not exist.
pub fn init_session_db(
    path: &std::path::Path,
) -> Result<rusqlite::Connection, BrowserError> {
    let conn = rusqlite::Connection::open(path).map_err(|e| {
        BrowserError::SessionError(format!("failed to open session DB: {}", e))
    })?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sessions (
            id         TEXT PRIMARY KEY,
            data       BLOB NOT NULL,
            created_at INTEGER NOT NULL
        );",
    )
    .map_err(|e| {
        BrowserError::SessionError(format!("failed to create sessions table: {}", e))
    })?;

    Ok(conn)
}

/// Save a browser session to the database with AEAD (AES-256-GCM) encryption.
pub fn save_session(
    conn: &rusqlite::Connection,
    session: &BrowserSession,
    shared_secret: &[u8],
) -> Result<(), BrowserError> {
    let json_bytes = serde_json::to_vec(session)?;
    let encrypted = encrypt_session_data(&json_bytes, shared_secret)?;

    conn.execute(
        "INSERT OR REPLACE INTO sessions (id, data, created_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![session.id, encrypted, session.created_at],
    )
    .map_err(|e| {
        BrowserError::SessionError(format!("failed to save session: {}", e))
    })?;

    Ok(())
}

/// Load a browser session from the database, decrypting with the shared secret.
pub fn load_session(
    conn: &rusqlite::Connection,
    session_id: &str,
    shared_secret: &[u8],
) -> Result<BrowserSession, BrowserError> {
    let encrypted: Vec<u8> = conn
        .query_row(
            "SELECT data FROM sessions WHERE id = ?1",
            rusqlite::params![session_id],
            |row| row.get(0),
        )
        .map_err(|e| {
            BrowserError::SessionError(format!(
                "session '{}' not found: {}",
                session_id, e
            ))
        })?;

    let decrypted = decrypt_session_data(&encrypted, shared_secret)?;
    let session: BrowserSession = serde_json::from_slice(&decrypted)?;
    Ok(session)
}

/// List all sessions in the database as (id, created_at) pairs.
pub fn list_sessions(
    conn: &rusqlite::Connection,
) -> Result<Vec<(String, i64)>, BrowserError> {
    let mut stmt = conn
        .prepare("SELECT id, created_at FROM sessions ORDER BY created_at DESC")
        .map_err(|e| {
            BrowserError::SessionError(format!("failed to list sessions: {}", e))
        })?;

    let rows = stmt
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))
        .map_err(|e| {
            BrowserError::SessionError(format!("failed to query sessions: {}", e))
        })?;

    let mut sessions = Vec::new();
    for row in rows {
        sessions.push(row.map_err(|e| {
            BrowserError::SessionError(format!("failed to read session row: {}", e))
        })?);
    }
    Ok(sessions)
}

/// Delete a session from the database by ID.
pub fn delete_session(
    conn: &rusqlite::Connection,
    session_id: &str,
) -> Result<(), BrowserError> {
    conn.execute(
        "DELETE FROM sessions WHERE id = ?1",
        rusqlite::params![session_id],
    )
    .map_err(|e| {
        BrowserError::SessionError(format!("failed to delete session: {}", e))
    })?;
    Ok(())
}

// ── Capture / Restore helpers ────────────────────────────────────────

/// Capture a complete browser session: cookies + storage for all origins.
pub async fn capture_session(
    client: &CdpClient,
    session_id_cdp: &str,
    session_name: &str,
    origins: &[&str],
) -> Result<BrowserSession, BrowserError> {
    let cookies = get_cookies(client, session_id_cdp).await?;

    let mut local_storage = HashMap::new();
    let mut session_storage = HashMap::new();

    for origin in origins {
        let ls = get_local_storage(client, session_id_cdp, origin).await?;
        if !ls.is_empty() {
            local_storage.insert(origin.to_string(), ls);
        }
        let ss = get_session_storage(client, session_id_cdp, origin).await?;
        if !ss.is_empty() {
            session_storage.insert(origin.to_string(), ss);
        }
    }

    Ok(BrowserSession {
        id: session_name.to_string(),
        cookies,
        local_storage,
        session_storage,
        created_at: chrono::Utc::now().timestamp(),
        user_agent: None,
        persona_seed: None,
        fingerprint_id: None,
        proxy_geo: None,
        timezone: None,
        campaign_id: None,
    })
}

/// Restore a complete browser session: clear + set cookies, set storage items.
pub async fn restore_session(
    client: &CdpClient,
    session_id_cdp: &str,
    session: &BrowserSession,
) -> Result<(), BrowserError> {
    // Clear existing cookies and set saved ones
    clear_cookies(client, session_id_cdp).await?;
    set_cookies(client, session_id_cdp, &session.cookies).await?;

    // Restore localStorage for each origin
    for (origin, items) in &session.local_storage {
        for (key, value) in items {
            set_local_storage_item(client, session_id_cdp, origin, key, value).await?;
        }
    }

    // Restore sessionStorage for each origin
    for (origin, items) in &session.session_storage {
        for (key, value) in items {
            set_session_storage_item(client, session_id_cdp, origin, key, value).await?;
        }
    }

    Ok(())
}

/// Bind a live browser context to a session's geo identity.
///
/// Convenience that applies the timezone, locale, geolocation, and (optionally)
/// User-Agent derived from a `GeoContext` to the given CDP browser context so
/// the session's browser environment co-varies with its fingerprint/proxy
/// identity (session–fingerprint–proxy coherence). Pair with
/// [`BrowserSession::with_context`] to record the same context on the session.
pub async fn bind_session_emulation(
    client: &CdpClient,
    session_id_cdp: &str,
    geo: &super::fingerprint_coherence::GeoContext,
    user_agent: Option<&str>,
) -> Result<(), BrowserError> {
    super::emulation::configure_geo_context(client, session_id_cdp, geo, user_agent).await
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_security_origin_https() {
        let origin = extract_security_origin("https://example.com/path/to/page").unwrap();
        assert_eq!(origin, "https://example.com");
    }

    #[test]
    fn test_extract_security_origin_http() {
        let origin = extract_security_origin("http://example.com:8080/page").unwrap();
        assert_eq!(origin, "http://example.com:8080");
    }

    #[test]
    fn test_extract_security_origin_https_default_port() {
        let origin = extract_security_origin("https://example.com:443/page").unwrap();
        assert_eq!(origin, "https://example.com");
    }

    #[test]
    fn test_extract_security_origin_http_default_port() {
        let origin = extract_security_origin("http://example.com:80/page").unwrap();
        assert_eq!(origin, "http://example.com");
    }

    #[test]
    fn test_extract_security_origin_non_default_port() {
        let origin = extract_security_origin("https://example.com:9443/api").unwrap();
        assert_eq!(origin, "https://example.com:9443");
    }

    #[test]
    fn test_extract_security_origin_invalid_url() {
        let result = extract_security_origin("not a url at all");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid URL"), "got: {}", err);
    }

    #[test]
    fn test_cdp_cookie_serde_roundtrip() {
        let cookie = CdpCookie {
            name: "session_id".to_string(),
            value: "abc123".to_string(),
            domain: ".example.com".to_string(),
            path: "/".to_string(),
            expires: 1700000000.0,
            http_only: true,
            secure: true,
            same_site: "Lax".to_string(),
            size: Some(42),
        };

        let json = serde_json::to_string(&cookie).unwrap();
        let deserialized: CdpCookie = serde_json::from_str(&json).unwrap();

        assert_eq!(cookie, deserialized);
    }

    #[test]
    fn test_cdp_cookie_session_cookie_no_expires() {
        // Session cookie: expires <= 0 means no expiry in CDP
        let cookie = CdpCookie {
            name: "temp".to_string(),
            value: "val".to_string(),
            domain: ".example.com".to_string(),
            path: "/".to_string(),
            expires: -1.0,
            http_only: false,
            secure: false,
            same_site: String::new(),
            size: None,
        };

        // When building CDP params, expires <= 0 should be treated as session cookie
        assert!(cookie.expires <= 0.0);

        // Serde round-trip still works for storage
        let json = serde_json::to_string(&cookie).unwrap();
        let deser: CdpCookie = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.expires, -1.0);
    }

    #[test]
    fn test_cdp_cookie_camel_case_serde() {
        // Verify CDP-style JSON (camelCase) deserializes correctly
        let json = r#"{
            "name": "auth",
            "value": "token123",
            "domain": ".example.com",
            "path": "/",
            "expires": 1700000000.0,
            "httpOnly": true,
            "secure": true,
            "sameSite": "Strict",
            "size": 128
        }"#;

        let cookie: CdpCookie = serde_json::from_str(json).unwrap();
        assert_eq!(cookie.name, "auth");
        assert!(cookie.http_only);
        assert!(cookie.secure);
        assert_eq!(cookie.same_site, "Strict");
        assert_eq!(cookie.size, Some(128));
    }

    #[test]
    fn test_cdp_cookie_minimal_json() {
        // CDP may return cookies with only required fields
        let json = r#"{
            "name": "simple",
            "value": "v",
            "domain": "example.com",
            "path": "/"
        }"#;

        let cookie: CdpCookie = serde_json::from_str(json).unwrap();
        assert_eq!(cookie.name, "simple");
        assert_eq!(cookie.expires, 0.0);
        assert!(!cookie.http_only);
        assert!(!cookie.secure);
        assert_eq!(cookie.same_site, "");
        assert_eq!(cookie.size, None);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"hello world, this is session data";
        let secret = b"shared-secret-from-mlkem-768";

        let encrypted = encrypt_session_data(plaintext, secret).unwrap();
        // Must be: 16 salt + 12 nonce + plaintext.len() ciphertext + 16 tag
        assert_eq!(encrypted.len(), 44 + plaintext.len());

        let decrypted = decrypt_session_data(&encrypted, secret).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let plaintext = b"";
        let secret = b"key";

        let encrypted = encrypt_session_data(plaintext, secret).unwrap();
        assert_eq!(encrypted.len(), 44);

        let decrypted = decrypt_session_data(&encrypted, secret).unwrap();
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_encrypt_decrypt_large() {
        let plaintext: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
        let secret = b"large-data-secret";

        let encrypted = encrypt_session_data(&plaintext, secret).unwrap();
        let decrypted = decrypt_session_data(&encrypted, secret).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let plaintext = b"secret session";
        let right_key = b"correct-key";
        let wrong_key = b"wrong-key-!!";

        let encrypted = encrypt_session_data(plaintext, right_key).unwrap();
        let result = decrypt_session_data(&encrypted, wrong_key);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("MAC verification failed"),
            "expected MAC failure, got: {}",
            err
        );
    }

    #[test]
    fn test_decrypt_corrupted_data_fails() {
        let plaintext = b"session data";
        let secret = b"key";

        let mut encrypted = encrypt_session_data(plaintext, secret).unwrap();
        // Corrupt one byte in the ciphertext
        if encrypted.len() > 20 {
            encrypted[15] ^= 0xFF;
        }

        let result = decrypt_session_data(&encrypted, secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_too_short_fails() {
        let result = decrypt_session_data(&[0u8; 10], b"key");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too short"), "got: {}", err);
    }

    #[test]
    fn test_init_session_db() {
        let dir = std::env::temp_dir().join("tallow_test_session_db_init");
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("sessions.db");
        let _ = std::fs::remove_file(&db_path);

        let conn = init_session_db(&db_path).unwrap();

        // Verify table exists by inserting a row
        conn.execute(
            "INSERT INTO sessions (id, data, created_at) VALUES ('test', X'00', 0)",
            [],
        )
        .unwrap();

        // Cleanup
        drop(conn);
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_save_load_session_roundtrip() {
        let dir = std::env::temp_dir().join("tallow_test_session_save_load");
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("sessions.db");
        let _ = std::fs::remove_file(&db_path);

        let conn = init_session_db(&db_path).unwrap();
        let secret = b"test-shared-secret-for-sessions";

        let mut local_storage = HashMap::new();
        local_storage.insert(
            "https://example.com".to_string(),
            vec![
                ("theme".to_string(), "dark".to_string()),
                ("lang".to_string(), "en".to_string()),
            ],
        );

        let session = BrowserSession {
            id: "my-session".to_string(),
            cookies: vec![
                CdpCookie {
                    name: "sid".to_string(),
                    value: "abc".to_string(),
                    domain: ".example.com".to_string(),
                    path: "/".to_string(),
                    expires: 1700000000.0,
                    http_only: true,
                    secure: true,
                    same_site: "Lax".to_string(),
                    size: None,
                },
            ],
            local_storage,
            session_storage: HashMap::new(),
            created_at: 1700000000,
            user_agent: Some("Tallow/0.1".to_string()),
            persona_seed: None,
            fingerprint_id: None,
            proxy_geo: None,
            timezone: None,
            campaign_id: None,
        };

        save_session(&conn, &session, secret).unwrap();
        let loaded = load_session(&conn, "my-session", secret).unwrap();

        assert_eq!(loaded.id, "my-session");
        assert_eq!(loaded.cookies.len(), 1);
        assert_eq!(loaded.cookies[0].name, "sid");
        assert_eq!(loaded.local_storage.len(), 1);
        assert_eq!(loaded.created_at, 1700000000);
        assert_eq!(loaded.user_agent, Some("Tallow/0.1".to_string()));

        // Cleanup
        drop(conn);
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_save_load_roundtrip_coherence() {
        // Durable session-store persistence of the coherence binding: a session
        // carrying persona_seed/fingerprint_id/proxy_geo/timezone must survive a
        // AEAD-encrypted save -> load round-trip, keyed by the stable `id`.
        let dir = std::env::temp_dir().join("tallow_test_session_coherence");
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("sessions.db");
        let _ = std::fs::remove_file(&db_path);

        let conn = init_session_db(&db_path).unwrap();
        let secret = b"coherence-shared-secret";

        // Build via with_context (I12 path) then stamp via with_coherence (I20
        // path) — the same binding a captured session carries end-to-end.
        let session = BrowserSession::with_context(
            "coherent-session".to_string(),
            Some(0xCAFEBABE),
            Some("ipad-pro-chrome-131".to_string()),
            Some("US-Texas-Houston".to_string()),
            Some("America/Chicago".to_string()),
        )
        .with_coherence(
            Some(0xCAFEBABE),
            Some("ipad-pro-chrome-131".to_string()),
            Some("US-Texas-Houston".to_string()),
            Some("America/Chicago".to_string()),
        );

        save_session(&conn, &session, secret).unwrap();
        let loaded = load_session(&conn, "coherent-session", secret).unwrap();

        // session_id is the stable lookup key -> coherence re-binds on load.
        assert_eq!(loaded.id, "coherent-session");
        assert_eq!(loaded.persona_seed, Some(0xCAFEBABE));
        assert_eq!(loaded.fingerprint_id, Some("ipad-pro-chrome-131".to_string()));
        assert_eq!(loaded.proxy_geo, Some("US-Texas-Houston".to_string()));
        assert_eq!(loaded.timezone, Some("America/Chicago".to_string()));

        // Backward compatible: a session persisted without a coherence binding
        // round-trips with all four coherence fields defaulting to None.
        let plain = BrowserSession::with_context("legacy".to_string(), None, None, None, None);
        save_session(&conn, &plain, secret).unwrap();
        let plain_loaded = load_session(&conn, "legacy", secret).unwrap();
        assert_eq!(plain_loaded.persona_seed, None);
        assert_eq!(plain_loaded.fingerprint_id, None);
        assert_eq!(plain_loaded.proxy_geo, None);
        assert_eq!(plain_loaded.timezone, None);

        // Cleanup
        drop(conn);
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_load_session_wrong_key() {
        let dir = std::env::temp_dir().join("tallow_test_session_wrong_key");
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("sessions.db");
        let _ = std::fs::remove_file(&db_path);

        let conn = init_session_db(&db_path).unwrap();

        let session = BrowserSession {
            id: "encrypted-sess".to_string(),
            cookies: vec![],
            local_storage: HashMap::new(),
            session_storage: HashMap::new(),
            created_at: 0,
            user_agent: None,
            persona_seed: None,
            fingerprint_id: None,
            proxy_geo: None,
            timezone: None,
            campaign_id: None,
        };

        save_session(&conn, &session, b"right-key").unwrap();
        let result = load_session(&conn, "encrypted-sess", b"wrong-key");

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("MAC verification failed"),
            "expected MAC failure, got: {}",
            err
        );

        // Cleanup
        drop(conn);
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_list_sessions() {
        let dir = std::env::temp_dir().join("tallow_test_session_list");
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("sessions.db");
        let _ = std::fs::remove_file(&db_path);

        let conn = init_session_db(&db_path).unwrap();
        let secret = b"list-test-key";

        for i in 0..3 {
            let session = BrowserSession {
                id: format!("session-{}", i),
                cookies: vec![],
                local_storage: HashMap::new(),
                session_storage: HashMap::new(),
                created_at: 1000 + i as i64,
                user_agent: None,
                persona_seed: None,
                fingerprint_id: None,
                proxy_geo: None,
                timezone: None,
                campaign_id: None,
            };
            save_session(&conn, &session, secret).unwrap();
        }

        let sessions = list_sessions(&conn).unwrap();
        assert_eq!(sessions.len(), 3);

        // Ordered by created_at DESC
        assert_eq!(sessions[0].0, "session-2");
        assert_eq!(sessions[1].0, "session-1");
        assert_eq!(sessions[2].0, "session-0");

        // Cleanup
        drop(conn);
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_delete_session() {
        let dir = std::env::temp_dir().join("tallow_test_session_delete");
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("sessions.db");
        let _ = std::fs::remove_file(&db_path);

        let conn = init_session_db(&db_path).unwrap();
        let secret = b"delete-test-key";

        let session = BrowserSession {
            id: "to-delete".to_string(),
            cookies: vec![],
            local_storage: HashMap::new(),
            session_storage: HashMap::new(),
            created_at: 5000,
            user_agent: None,
            persona_seed: None,
            fingerprint_id: None,
            proxy_geo: None,
            timezone: None,
            campaign_id: None,
        };

        save_session(&conn, &session, secret).unwrap();

        let before = list_sessions(&conn).unwrap();
        assert_eq!(before.len(), 1);

        delete_session(&conn, "to-delete").unwrap();

        let after = list_sessions(&conn).unwrap();
        assert_eq!(after.len(), 0);

        // Cleanup
        drop(conn);
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_browser_session_serde_roundtrip() {
        let mut ls = HashMap::new();
        ls.insert(
            "https://example.com".to_string(),
            vec![("key".to_string(), "val".to_string())],
        );
        let mut ss = HashMap::new();
        ss.insert(
            "https://app.example.com".to_string(),
            vec![("tab".to_string(), "home".to_string())],
        );

        let session = BrowserSession {
            id: "test".to_string(),
            cookies: vec![CdpCookie {
                name: "c".to_string(),
                value: "v".to_string(),
                domain: "example.com".to_string(),
                path: "/".to_string(),
                expires: 0.0,
                http_only: false,
                secure: false,
                same_site: String::new(),
                size: None,
            }],
            local_storage: ls,
            session_storage: ss,
            created_at: 12345,
            user_agent: None,
            persona_seed: None,
            fingerprint_id: None,
            proxy_geo: None,
            timezone: None,
            campaign_id: None,
        };

        let json = serde_json::to_string(&session).unwrap();
        let deser: BrowserSession = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.id, "test");
        assert_eq!(deser.cookies.len(), 1);
        assert_eq!(deser.local_storage.len(), 1);
        assert_eq!(deser.session_storage.len(), 1);
        assert_eq!(deser.created_at, 12345);
    }

    #[test]
    fn test_with_context_binds_coherence() {
        // Coherence-aware session constructor stores persona/fingerprint/geo/tz.
        let session = BrowserSession::with_context(
            "ctx-1".to_string(),
            Some(0xDEADBEEF),
            Some("ipad-pro-chrome-131".to_string()),
            Some("US-Texas-Houston".to_string()),
            Some("America/Chicago".to_string()),
        );

        assert_eq!(session.id, "ctx-1");
        assert_eq!(session.persona_seed, Some(0xDEADBEEF));
        assert_eq!(session.fingerprint_id, Some("ipad-pro-chrome-131".to_string()));
        assert_eq!(session.proxy_geo, Some("US-Texas-Houston".to_string()));
        assert_eq!(session.timezone, Some("America/Chicago".to_string()));

        // Serde round-trip preserves the bindings.
        let json = serde_json::to_string(&session).unwrap();
        let deser: BrowserSession = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.persona_seed, Some(0xDEADBEEF));
        assert_eq!(deser.timezone, Some("America/Chicago".to_string()));
    }

    #[test]
    fn test_with_context_defaults_backward_compatible() {
        // with_context with all-None bindings stays compatible with plain sessions.
        let session = BrowserSession::with_context("plain".to_string(), None, None, None, None);
        assert_eq!(session.id, "plain");
        assert_eq!(session.persona_seed, None);
        assert_eq!(session.fingerprint_id, None);
        assert_eq!(session.proxy_geo, None);
        assert_eq!(session.timezone, None);

        // Old serialized session (no new fields) still deserializes via serde default.
        let old_json = r#"{"id":"legacy","cookies":[],"local_storage":{},"session_storage":{},"created_at":0}"#;
        let deser: BrowserSession = serde_json::from_str(old_json).unwrap();
        assert_eq!(deser.id, "legacy");
        assert_eq!(deser.persona_seed, None);
        assert_eq!(deser.timezone, None);
    }
}
