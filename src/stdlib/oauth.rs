//! Standard library: `tallow.oauth` — OAuth 2.0 / OIDC authorization flows.
//!
//! Automates: authorization code + PKCE, client credentials, device code,
//! and OIDC discovery. Returns tokens ready for HTTP injection.
//!
//! # API
//! - `OAuth.authorization_url(config)` — build authorization URL with PKCE
//! - `OAuth.exchange_code(config, code, code_verifier)` — exchange code for tokens
//! - `OAuth.client_credentials(config)` — machine-to-machine token
//! - `OAuth.refresh_token(config, refresh_token)` — refresh access token
//! - `OAuth.discover(issuer_url)` — OIDC discovery (.well-known/openid-configuration)
//! - `Token.to_header()` — generate Authorization header

use super::StdlibResult;
use crate::interp::{type_name, Value};

use base64::Engine;
use sha2::{Sha256, Digest};

/// Generate a PKCE code verifier (cryptographically random)
fn generate_code_verifier() -> String {
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom").and_then(|mut f| std::io::Read::read_exact(&mut f, &mut bytes)).ok();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
}

/// Derive PKCE code challenge from verifier (S256)
fn generate_code_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

/// OAuth token response fields.
///
/// Zeroization sweep (2026-09-11, zer. MEDIUM): no derived `Debug` (it would
/// print live tokens into logs and panic messages) — hand-written redacted
/// form below — and the token buffers are wiped on drop (`zeroize`).
///
/// Limit: the `Token` struct handed to the script by [`token_to_value`] is a
/// deliberate, owned copy of the access token (the point of the flow); this
/// wipe covers only `TokenData`'s own buffers before drop.
struct TokenData {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    token_type: String,
    expires_in: Option<i64>,
    scope: Option<String>,
}

impl std::fmt::Debug for TokenData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenData")
            .field("access_token", &"[redacted]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .field("id_token", &self.id_token.as_ref().map(|_| "[redacted]"))
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

impl Drop for TokenData {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.access_token.zeroize();
        if let Some(s) = self.refresh_token.as_mut() {
            s.zeroize();
        }
        if let Some(s) = self.id_token.as_mut() {
            s.zeroize();
        }
    }
}

fn token_to_value(t: &TokenData) -> Value {
    let mut fields = vec![
        ("access_token".into(), Value::String(t.access_token.clone())),
        ("token_type".into(), Value::String(t.token_type.clone())),
    ];
    if let Some(ref rt) = t.refresh_token {
        fields.push(("refresh_token".into(), Value::String(rt.clone())));
    }
    if let Some(ref id) = t.id_token {
        fields.push(("id_token".into(), Value::String(id.clone())));
    }
    if let Some(exp) = t.expires_in {
        fields.push(("expires_in".into(), Value::Int(exp as i128)));
    }
    if let Some(ref sc) = t.scope {
        fields.push(("scope".into(), Value::String(sc.clone())));
    }
    Value::Struct { name: "Token".into(), fields }
}

fn parse_token_response(body: &str) -> Result<TokenData, String> {
    let json: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| format!("parse JSON: {e}"))?;
    Ok(TokenData {
        access_token: json["access_token"].as_str().unwrap_or("").to_string(),
        refresh_token: json["refresh_token"].as_str().map(|s| s.to_string()),
        id_token: json["id_token"].as_str().map(|s| s.to_string()),
        token_type: json["token_type"].as_str().unwrap_or("Bearer").to_string(),
        expires_in: json["expires_in"].as_i64(),
        scope: json["scope"].as_str().map(|s| s.to_string()),
    })
}

fn parse_discovery(body: &str) -> Result<Value, String> {
    let json: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| format!("parse JSON: {e}"))?;
    Ok(json_to_value(&json))
}

fn json_to_value(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() { Value::Int(i as i128) }
            else if let Some(f) = n.as_f64() { Value::Float(f) }
            else { Value::String(n.to_string()) }
        }
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(a) => Value::Array(a.iter().map(json_to_value).collect()),
        serde_json::Value::Object(o) => {
            let entries: Vec<(Value, Value)> = o.iter()
                .map(|(k, v)| (Value::String(k.clone()), json_to_value(v)))
                .collect();
            Value::Map(entries)
        }
    }
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "authorization_url" => Some(oauth_auth_url(args)),
        "exchange_code" => Some(oauth_exchange_code(args)),
        "client_credentials" => Some(oauth_client_credentials(args)),
        "refresh_token" => Some(oauth_refresh(args)),
        "discover" => Some(oauth_discover(args)),
        "generate_pkce" => Some(oauth_generate_pkce(args)),
        "attack_redirect_uri" => Some(oauth_attack_redirect_uri(args)),
        "attack_pkce_downgrade" => Some(oauth_attack_pkce(args)),
        _ => None,
    }
}

pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    if !matches!(object, Value::Struct { name, .. } if name == "Token") {
        return None;
    }
    match method {
        "to_header" => Some(token_to_header(object)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "authorization_url" | "exchange_code" | "client_credentials"
        | "refresh_token" | "discover" | "generate_pkce"
        | "attack_redirect_uri" | "attack_pkce_downgrade")
}

// ── OAuth.authorization_url(config) ──

fn oauth_auth_url(args: Vec<Value>) -> StdlibResult {
    if args.len() < 3 {
        return Err("OAuth.authorization_url: requires (auth_endpoint, client_id, redirect_uri, scope?, state?)".into());
    }
    let endpoint = expect_str(&args[0], "auth_endpoint")?;
    let client_id = expect_str(&args[1], "client_id")?;
    let redirect_uri = expect_str(&args[2], "redirect_uri")?;
    let scope = args.get(3).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None }).unwrap_or("openid");
    let state = args.get(4).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None }).unwrap_or("");

    let verifier = generate_code_verifier();
    let challenge = generate_code_challenge(&verifier);

    let mut url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&code_challenge={}&code_challenge_method=S256",
        endpoint, client_id, redirect_uri, scope, challenge
    );
    if !state.is_empty() {
        url.push_str(&format!("&state={}", state));
    }

    Ok(Value::Struct {
        name: "OAuthConfig".into(),
        fields: vec![
            ("url".into(), Value::String(url)),
            ("code_verifier".into(), Value::String(verifier)),
        ],
    })
}

// ── OAuth.exchange_code(config) ──

fn oauth_exchange_code(args: Vec<Value>) -> StdlibResult {
    if args.len() < 5 {
        return Err("OAuth.exchange_code: requires (token_endpoint, client_id, client_secret?, redirect_uri, code, code_verifier)".into());
    }
    let endpoint = expect_str(&args[0], "token_endpoint")?;
    let client_id = expect_str(&args[1], "client_id")?;
    let client_secret = args.get(2).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None }).unwrap_or("");
    let redirect_uri = expect_str(&args[3], "redirect_uri")?;
    let code = expect_str(&args[4], "code")?;
    let verifier = args.get(5).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None }).unwrap_or("");

    let mut body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        code, redirect_uri, client_id, verifier
    );
    if !client_secret.is_empty() {
        body.push_str(&format!("&client_secret={}", client_secret));
    }

    let resp = crate::runtime::egress_http::post(endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .send(body.as_bytes())
        .map_err(|e| format!("token request: {e}"))?;

    let resp_body = resp.into_body().read_to_string()
        .map_err(|e| format!("read: {e}"))?;

    let token = parse_token_response(&resp_body)?;
    Ok(token_to_value(&token))
}

// ── OAuth.client_credentials(config) ──

fn oauth_client_credentials(args: Vec<Value>) -> StdlibResult {
    if args.len() < 3 {
        return Err("OAuth.client_credentials: requires (token_endpoint, client_id, client_secret, scope?)".into());
    }
    let endpoint = expect_str(&args[0], "token_endpoint")?;
    let client_id = expect_str(&args[1], "client_id")?;
    let client_secret = expect_str(&args[2], "client_secret")?;
    let scope = args.get(3).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None });

    let mut body = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}",
        client_id, client_secret
    );
    if let Some(sc) = scope {
        body.push_str(&format!("&scope={}", sc));
    }

    let resp = crate::runtime::egress_http::post(endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .send(body.as_bytes())
        .map_err(|e| format!("token request: {e}"))?;

    let resp_body = resp.into_body().read_to_string()
        .map_err(|e| format!("read: {e}"))?;

    let token = parse_token_response(&resp_body)?;
    Ok(token_to_value(&token))
}

// ── OAuth.refresh_token(config) ──

fn oauth_refresh(args: Vec<Value>) -> StdlibResult {
    if args.len() < 3 {
        return Err("OAuth.refresh_token: requires (token_endpoint, client_id, refresh_token)".into());
    }
    let endpoint = expect_str(&args[0], "token_endpoint")?;
    let client_id = expect_str(&args[1], "client_id")?;
    let refresh = expect_str(&args[2], "refresh_token")?;

    let body = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}",
        refresh, client_id
    );

    let resp = crate::runtime::egress_http::post(endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .send(body.as_bytes())
        .map_err(|e| format!("token request: {e}"))?;

    let resp_body = resp.into_body().read_to_string()
        .map_err(|e| format!("read: {e}"))?;

    let token = parse_token_response(&resp_body)?;
    Ok(token_to_value(&token))
}

// ── OAuth.discover(issuer_url) ──

fn oauth_discover(args: Vec<Value>) -> StdlibResult {
    let issuer = expect_first_str(&args, "issuer_url")?;
    let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));

    let resp = crate::runtime::egress_http::get(&url)
        .header("Accept", "application/json")
        .call()
        .map_err(|e| format!("discovery request: {e}"))?;

    let body = resp.into_body().read_to_string()
        .map_err(|e| format!("read: {e}"))?;

    parse_discovery(&body)
}

// ── OAuth.generate_pkce() ──

fn oauth_generate_pkce(_args: Vec<Value>) -> StdlibResult {
    let verifier = generate_code_verifier();
    let challenge = generate_code_challenge(&verifier);
    Ok(Value::Struct {
        name: "PKCE".into(),
        fields: vec![
            ("code_verifier".into(), Value::String(verifier)),
            ("code_challenge".into(), Value::String(challenge)),
        ],
    })
}

// ── token.to_header() ──

fn token_to_header(object: &Value) -> StdlibResult {
    let fields = match object {
        Value::Struct { name, fields } if name == "Token" => fields,
        _ => return Err(format!("Expected Token struct, got {}", type_name(object))),
    };
    let access_token = field_str(fields, "access_token");
    let token_type = field_str(fields, "token_type");
    Ok(Value::String(format!("{} {}", token_type, access_token)))
}

fn field_str(fields: &[(String, Value)], name: &str) -> String {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| if let Value::String(s) = v { Some(s.clone()) } else { None })
        .unwrap_or_default()
}

fn expect_str<'a>(val: &'a Value, name: &str) -> Result<&'a String, String> {
    match val { Value::String(s) => Ok(s), _ => Err(format!("Expected String for {name}, got {}", type_name(val))) }
}

fn expect_first_str<'a>(args: &'a [Value], name: &str) -> Result<&'a String, String> {
    match args.first() {
        Some(Value::String(s)) => Ok(s),
        Some(o) => Err(format!("Expected String {name}, got {}", type_name(o))),
        None => Err(format!("Missing {name} argument")),
    }
}

// ── OAuth.attack_redirect_uri(auth_endpoint, client_id, redirect_uri, scope?, state?) ──
// Generates authorization URLs with manipulated redirect_uri values to test
// if the OAuth server properly validates redirect URIs.

fn oauth_attack_redirect_uri(args: Vec<Value>) -> StdlibResult {
    if args.len() < 3 {
        return Err("OAuth.attack_redirect_uri: requires (auth_endpoint, client_id, redirect_uri, scope?, state?)".into());
    }
    let endpoint = expect_str(&args[0], "auth_endpoint")?;
    let client_id = expect_str(&args[1], "client_id")?;
    let redirect_uri = expect_str(&args[2], "redirect_uri")?;
    let scope = args.get(3).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None }).unwrap_or("openid");
    let state = args.get(4).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None }).unwrap_or("attacker");

    let verifier = generate_code_verifier();
    let challenge = generate_code_challenge(&verifier);

    // Parse the base redirect URI to extract the host
    let parsed_base = redirect_uri;
    let base_host = parsed_base
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/').next().unwrap_or("");

    // Build attack URLs with manipulated redirect URIs
    let attacks = [
        ("wildcard", format!("https://{}.evil.com/callback", base_host),
         "Wildcard: redirect_uri to evil.com subdomain matching base host"),
        ("open_redirect", format!("https://{}/redirect?url=https://evil.com/cb", base_host),
         "Open redirect: uses legitimate host with redirect parameter"),
        ("path_traversal", format!("https://{}/../../evil.com/callback", base_host),
         "Path traversal: directory traversal in redirect path"),
        ("no_tld", format!("https://{}.evil/callback", base_host),
         "No TLD: redirect_uri matching host prefix without proper TLD"),
        ("subdomain", format!("https://evil.{}/callback", base_host),
         "Subdomain takeover: attacker controls evil.{base_host}"),
        ("double_encoded", format!("https%3A%2F%2Fevil.com%2Fcallback", ),
         "Double-encoded: URL-encoded redirect_uri to evil.com"),
        ("null_byte", format!("https://{}/%00.evil.com/callback", base_host),
         "Null byte injection: legitimate host with null byte + attacker path"),
    ];

    let mut results = Vec::new();
    for (attack_type, uri, desc) in &attacks {
        let url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&code_challenge={}&code_challenge_method=S256&state={}",
            endpoint, client_id, urlencoding::encode(uri), scope, challenge, state
        );
        results.push(Value::Struct {
            name: "OAuthAttack".into(),
            fields: vec![
                ("attack_type".into(), Value::String(attack_type.to_string())),
                ("description".into(), Value::String(desc.to_string())),
                ("auth_url".into(), Value::String(url)),
                ("redirect_uri".into(), Value::String(uri.to_string())),
            ],
        });
    }

    // Also add the code_verifier for exchanging after successful redirect
    results.push(Value::Struct {
        name: "OAuthAttack".into(),
        fields: vec![
            ("attack_type".into(), Value::String("code_verifier".into())),
            ("description".into(), Value::String("Use this code_verifier with OAuth.exchange_code()".into())),
            ("code_verifier".into(), Value::String(verifier)),
        ],
    });

    Ok(Value::Array(results))
}

// ── OAuth.attack_pkce_downgrade(auth_endpoint, client_id, redirect_uri, scope?, state?) ──
// Builds an authorization URL without PKCE (no code_challenge), downgrading
// to the implicit flow. Tests if the server enforces PKCE.

fn oauth_attack_pkce(args: Vec<Value>) -> StdlibResult {
    if args.len() < 3 {
        return Err("OAuth.attack_pkce_downgrade: requires (auth_endpoint, client_id, redirect_uri, scope?, state?)".into());
    }
    let endpoint = expect_str(&args[0], "auth_endpoint")?;
    let client_id = expect_str(&args[1], "client_id")?;
    let redirect_uri = expect_str(&args[2], "redirect_uri")?;
    let scope = args.get(3).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None }).unwrap_or("openid");
    let state = args.get(4).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None }).unwrap_or("pkce_downgrade_test");

    // Standard authorization URL with PKCE
    let verifier = generate_code_verifier();
    let challenge = generate_code_challenge(&verifier);
    let pkce_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&code_challenge={}&code_challenge_method=S256&state={}",
        endpoint, client_id, urlencoding::encode(redirect_uri), scope, challenge, state
    );

    // Downgraded URL without PKCE
    let no_pkce_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
        endpoint, client_id, urlencoding::encode(redirect_uri), scope, state
    );

    // Implicit flow URL (response_type=token, no PKCE possible)
    let implicit_url = format!(
        "{}?response_type=token&client_id={}&redirect_uri={}&scope={}&state={}",
        endpoint, client_id, urlencoding::encode(redirect_uri), scope, state
    );

    // Hybrid flow (response_type=code+token+id_token)
    let hybrid_url = format!(
        "{}?response_type=code%20token%20id_token&client_id={}&redirect_uri={}&scope={}&state={}",
        endpoint, client_id, urlencoding::encode(redirect_uri), scope, state
    );

    Ok(Value::Struct {
        name: "PKCEAttack".into(),
        fields: vec![
            ("pkce_url".into(), Value::String(pkce_url)),
            ("no_pkce_url".into(), Value::String(no_pkce_url)),
            ("implicit_url".into(), Value::String(implicit_url)),
            ("hybrid_url".into(), Value::String(hybrid_url)),
            ("code_verifier".into(), Value::String(verifier)),
            ("note".into(), Value::String(
                "If no_pkce_url or implicit_url returns a code/token, PKCE is not enforced. The original authorization code flow allows code injection attacks.".into()
            )),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_token() -> TokenData {
        TokenData {
            access_token: "at-0123456789-secret".to_string(),
            refresh_token: Some("rt-0123456789-secret".to_string()),
            id_token: Some("idt-0123456789-secret".to_string()),
            token_type: "Bearer".to_string(),
            expires_in: Some(3600),
            scope: Some("openid profile".to_string()),
        }
    }

    #[test]
    fn token_data_debug_redacts_token_material() {
        let token = sample_token();
        let d = format!("{token:?}");
        assert!(d.contains("[redacted]"), "redaction marker missing: {d}");
        assert!(!d.contains("at-0123456789-secret"));
        assert!(!d.contains("rt-0123456789-secret"));
        assert!(!d.contains("idt-0123456789-secret"));
        // Non-secret metadata stays visible for debugging.
        assert!(d.contains("Bearer"));
    }

    #[test]
    fn token_data_debug_marks_absent_optional_tokens() {
        let token = TokenData {
            access_token: "only-access".to_string(),
            refresh_token: None,
            id_token: None,
            token_type: "Bearer".to_string(),
            expires_in: None,
            scope: None,
        };
        let d = format!("{token:?}");
        assert!(d.contains("refresh_token: None"), "got: {d}");
        assert!(d.contains("id_token: None"), "got: {d}");
        assert!(!d.contains("only-access"));
    }
}
