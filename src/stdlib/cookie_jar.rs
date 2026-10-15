//! Standard library: `tallow.cookie_jar` — HTTP cookie storage and management.
//!
//! Stores cookies from HTTP Set-Cookie headers, injects them into requests,
//! and loads cookies from browser profiles (Chromium, Chrome).
//!
//! # API
//! - `CookieJar.new()` — create an empty jar
//! - `CookieJar.load_browser(browser_name, domain)` — load cookies from a browser profile
//! - `CookieJar.add(name, value, domain, path)` — add a cookie manually
//! - `CookieJar.get(domain, name)` — get a cookie value
//! - `CookieJar.to_header(domain)` — generate Cookie header string for a domain
//! - `CookieJar.save(path)` — save jar to file (JSON)
//! - `CookieJar.load_file(path)` — load jar from file (JSON)
//! - `CookieJar.cookies()` — list all cookies as an array of Cookie structs

use super::StdlibResult;
use crate::interp::{type_name, Value};

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// A single cookie entry.
#[derive(Debug, Clone)]
struct CookieEntry {
    name: String,
    value: String,
    domain: String,
    path: String,
    secure: bool,
    http_only: bool,
    expires: Option<i64>,
}

/// Cookie jar — stores cookies keyed by (domain, name).
struct CookieJar {
    cookies: HashMap<(String, String), CookieEntry>,
}

impl CookieJar {
    fn new() -> Self {
        CookieJar { cookies: HashMap::new() }
    }

    fn add(&mut self, name: &str, value: &str, domain: &str, path: &str,
           secure: bool, http_only: bool, expires: Option<i64>) {
        let dn = normalize_domain(domain);
        let pn = if path.is_empty() { "/".to_string() } else { path.to_string() };
        self.cookies.insert((dn.clone(), name.to_string()), CookieEntry {
            name: name.to_string(), value: value.to_string(), domain: dn,
            path: pn, secure, http_only, expires,
        });
    }

    fn get(&self, domain: &str, name: &str) -> Option<String> {
        let dn = normalize_domain(domain);
        self.cookies.get(&(dn, name.to_string())).map(|c| c.value.clone())
    }

    fn to_header(&self, domain: &str) -> String {
        let dn = normalize_domain(domain);
        self.cookies.iter()
            .filter(|((cd, _), _)| domain_matches(&dn, cd))
            .map(|(_, c)| format!("{}={}", c.name, c.value))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn list(&self) -> Vec<Value> {
        self.cookies.values().map(|c| {
            let mut fields = vec![
                ("name".to_string(), Value::String(c.name.clone())),
                ("value".to_string(), Value::String(c.value.clone())),
                ("domain".to_string(), Value::String(c.domain.clone())),
                ("path".to_string(), Value::String(c.path.clone())),
                ("secure".to_string(), Value::Bool(c.secure)),
                ("http_only".to_string(), Value::Bool(c.http_only)),
            ];
            if let Some(exp) = c.expires {
                fields.push(("expires".to_string(), Value::Int(exp as i128)));
            }
            Value::Struct { name: "Cookie".to_string(), fields }
        }).collect()
    }

    fn save_to_file(&self, path: &str) -> Result<(), String> {
        let arr: Vec<serde_json::Value> = self.cookies.values().map(|c| {
            let mut obj = serde_json::json!({
                "name": c.name, "value": c.value, "domain": c.domain,
                "path": c.path, "secure": c.secure, "http_only": c.http_only,
            });
            if let Some(exp) = c.expires {
                obj["expires"] = serde_json::Value::Number(serde_json::Number::from(exp));
            }
            obj
        }).collect();
        let json = serde_json::to_string_pretty(&arr)
            .map_err(|e| format!("serialize: {e}"))?;
        fs::write(path, json).map_err(|e| format!("write: {e}"))?;
        Ok(())
    }

    fn load_from_file(path: &str) -> Result<Self, String> {
        let data = fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
        let arr: Vec<serde_json::Value> = serde_json::from_str(&data)
            .map_err(|e| format!("parse: {e}"))?;
        let mut jar = CookieJar::new();
        for c in &arr {
            let name = c["name"].as_str().unwrap_or("");
            let value = c["value"].as_str().unwrap_or("");
            let domain = c["domain"].as_str().unwrap_or("");
            let path = c["path"].as_str().unwrap_or("/");
            let secure = c["secure"].as_bool().unwrap_or(false);
            let http_only = c["http_only"].as_bool().unwrap_or(false);
            let expires = c["expires"].as_i64();
            jar.add(name, value, domain, path, secure, http_only, expires);
        }
        Ok(jar)
    }
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "new" => Some(cj_new(args)),
        "load_browser" => Some(cj_load_browser(args)),
        "load_file" => Some(cj_load_file(args)),
        _ => None,
    }
}

pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    if !matches_struct(object, "CookieJar") { return None; }
    match method {
        "add" => Some(cj_add(object, args)),
        "get" => Some(cj_get(object, args)),
        "to_header" => Some(cj_to_header(object, args)),
        "save" => Some(cj_save(object, args)),
        "cookies" => Some(cj_list(object, args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "new" | "load_browser" | "load_file")
}

// ── Function implementations ──

fn cj_new(_args: Vec<Value>) -> StdlibResult { Ok(jar_to_value(CookieJar::new())) }

fn cj_load_browser(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("CookieJar.load_browser: requires (browser_name, domain)".into());
    }
    let browser = expect_string(&args[0], "browser_name")?.to_lowercase();
    let domain = expect_string(&args[1], "domain")?.clone();
    let db_path = find_browser_cookies_db(&browser)?;
    let jar = load_chromium_cookies(&db_path, &domain)?;
    Ok(jar_to_value(jar))
}

fn cj_load_file(args: Vec<Value>) -> StdlibResult {
    let path = expect_first_string(&args, "path")?;
    Ok(jar_to_value(CookieJar::load_from_file(path)?))
}

fn cj_add(object: &Value, args: Vec<Value>) -> StdlibResult {
    let mut jar = extract_jar(object)?;
    if args.len() < 3 {
        return Err("CookieJar.add: requires (name, value, domain)".into());
    }
    let name = expect_string(&args[0], "name")?;
    let value = expect_string(&args[1], "value")?;
    let domain = expect_string(&args[2], "domain")?;
    let path = args.get(3).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None }).unwrap_or("/");
    let secure = args.get(4).and_then(|v| if let Value::Bool(b) = v { Some(*b) } else { None }).unwrap_or(false);
    let http_only = args.get(5).and_then(|v| if let Value::Bool(b) = v { Some(*b) } else { None }).unwrap_or(false);
    let expires = args.get(6).and_then(|v| if let Value::Int(i) = v { Some(*i) } else { None });
    jar.add(name, value, domain, path, secure, http_only, expires.map(|i| i as i64));
    Ok(jar_to_value(jar))
}

fn cj_get(object: &Value, args: Vec<Value>) -> StdlibResult {
    let jar = extract_jar(object)?;
    if args.len() < 2 { return Err("CookieJar.get: requires (domain, name)".into()); }
    let domain = expect_string(&args[0], "domain")?;
    let name = expect_string(&args[1], "name")?;
    match jar.get(domain, name) {
        Some(v) => Ok(Value::String(v)),
        None => Ok(Value::Nil),
    }
}

fn cj_to_header(object: &Value, args: Vec<Value>) -> StdlibResult {
    let jar = extract_jar(object)?;
    let domain = expect_first_string(&args, "domain")?;
    Ok(Value::String(jar.to_header(domain)))
}

fn cj_save(object: &Value, args: Vec<Value>) -> StdlibResult {
    let jar = extract_jar(object)?;
    let path = expect_first_string(&args, "path")?;
    jar.save_to_file(path)?;
    Ok(Value::Nil)
}

fn cj_list(object: &Value, _args: Vec<Value>) -> StdlibResult {
    Ok(Value::Array(extract_jar(object)?.list()))
}

// ── Helpers ──

fn jar_to_value(jar: CookieJar) -> Value {
    Value::Struct {
        name: "CookieJar".into(),
        fields: vec![("cookies".into(), Value::Array(jar.list()))],
    }
}

fn extract_jar(value: &Value) -> Result<CookieJar, String> {
    let fields = get_struct_fields(value, "CookieJar")?;
    let mut jar = CookieJar::new();
    if let Some(cookies_val) = fields.iter().find(|(n, _)| n == "cookies").map(|(_, v)| v) {
        if let Value::Array(arr) = cookies_val {
            for cv in arr {
                if let Value::Struct { fields: cf, .. } = cv {
                    let name = field_str(cf, "name");
                    let value = field_str(cf, "value");
                    let domain = field_str(cf, "domain");
                    let path = field_str(cf, "path");
                    let secure = field_bool(cf, "secure");
                    let http_only = field_bool(cf, "http_only");
                    let expires = field_int(cf, "expires");
                    jar.add(&name, &value, &domain, &path, secure, http_only, expires.map(|i| i as i64));
                }
            }
        }
    }
    Ok(jar)
}

fn matches_struct(value: &Value, name: &str) -> bool {
    matches!(value, Value::Struct { name: n, .. } if n == name)
}

fn get_struct_fields<'a>(value: &'a Value, expected: &str) -> Result<&'a [(String, Value)], String> {
    match value {
        Value::Struct { name, fields } if name == expected => Ok(fields),
        _ => Err(format!("Expected {} struct, got {}", expected, type_name(value))),
    }
}

fn field_str(fields: &[(String, Value)], name: &str) -> String {
    fields.iter().find(|(n, _)| n == name)
        .and_then(|(_, v)| if let Value::String(s) = v { Some(s.clone()) } else { None })
        .unwrap_or_default()
}
fn field_bool(fields: &[(String, Value)], name: &str) -> bool {
    fields.iter().find(|(n, _)| n == name)
        .and_then(|(_, v)| if let Value::Bool(b) = v { Some(*b) } else { None })
        .unwrap_or(false)
}
fn field_int(fields: &[(String, Value)], name: &str) -> Option<i128> {
    fields.iter().find(|(n, _)| n == name)
        .and_then(|(_, v)| if let Value::Int(i) = v { Some(*i) } else { None })
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

// ── Domain matching ──

fn normalize_domain(domain: &str) -> String {
    domain.trim_start_matches('.').to_lowercase()
}
fn domain_matches(request: &str, cookie: &str) -> bool {
    request == cookie || request.ends_with(&format!(".{}", cookie))
}

// ── Browser cookie loading ──

fn find_browser_cookies_db(browser: &str) -> Result<PathBuf, String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "~".into());
    let candidates: Vec<PathBuf> = match browser {
        "chromium" => vec![
            PathBuf::from(format!("{home}/.config/chromium/Default/Cookies")),
            PathBuf::from(format!("{home}/snap/chromium/common/chromium/Default/Cookies")),
        ],
        "chrome" | "google-chrome" => vec![
            PathBuf::from(format!("{home}/.config/google-chrome/Default/Cookies")),
            PathBuf::from(format!("{home}/.config/google-chrome-stable/Default/Cookies")),
        ],
        "brave" => vec![
            PathBuf::from(format!("{home}/.config/BraveSoftware/Brave-Browser/Default/Cookies")),
        ],
        "edge" | "microsoft-edge" => vec![
            PathBuf::from(format!("{home}/.config/microsoft-edge/Default/Cookies")),
        ],
        _ => return Err(format!("Unknown browser: {browser}. Supported: chromium, chrome, brave, edge")),
    };
    for p in &candidates {
        if p.exists() { return Ok(p.clone()); }
    }
    Err(format!("Cookies db not found for {browser}. Tried: {:?}", candidates))
}

fn load_chromium_cookies(db_path: &PathBuf, domain: &str) -> Result<CookieJar, String> {
    let conn = rusqlite::Connection::open(db_path)
        .map_err(|e| format!("open sqlite: {e}"))?;
    let domain_filter = format!("%{}%", domain);
    let mut jar = CookieJar::new();

    let mut stmt = conn.prepare(
        "SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly
         FROM cookies WHERE host_key LIKE ?1"
    ).map_err(|e| format!("prepare: {e}"))?;

    let rows = stmt.query_map([&domain_filter], |row| {
        Ok((
            row.get::<_, String>(0)?, row.get::<_, String>(1)?,
            row.get::<_, Vec<u8>>(2)?, row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?, row.get::<_, bool>(5)?,
            row.get::<_, bool>(6)?,
        ))
    }).map_err(|e| format!("query: {e}"))?;

    for row in rows {
        if let Ok((host, name, enc_val, path, expires_utc, is_secure, is_httponly)) = row {
            let value = decrypt_chromium_value(&enc_val);
            let exp = if expires_utc > 0 && expires_utc < 9_999_999_999 { Some(expires_utc) } else { None };
            jar.add(&name, &value, &host, &path, is_secure, is_httponly, exp);
        }
    }
    Ok(jar)
}

fn decrypt_chromium_value(encrypted: &[u8]) -> String {
    if encrypted.is_empty() { return String::new(); }
    // v10/v11 format: first 3 bytes are version, rest may be plaintext (common on Linux)
    if encrypted.len() > 3 && (&encrypted[0..3] == b"v10" || &encrypted[0..3] == b"v11") {
        let payload = &encrypted[3..];
        let plain = String::from_utf8_lossy(payload).to_string();
        if plain.chars().all(|c| c.is_ascii_graphic() || c == ' ' || c == '=' || c == '-' || c == '_' || c == '.' || c == '@') {
            return plain;
        }
        // Encrypted — try simple XOR with space (some Linux builds use this)
        if let Some(dec) = try_xor_decrypt(payload) { return dec; }
    }
    // Raw — try as-is
    let raw = String::from_utf8_lossy(encrypted).to_string();
    if raw.chars().all(|c| c.is_ascii_graphic() || c == ' ') { return raw; }
    String::new()
}

fn try_xor_decrypt(data: &[u8]) -> Option<String> {
    // Some Linux Chromium builds XOR with a space character (0x20)
    let dec: Vec<u8> = data.iter().map(|b| b ^ 0x20).collect();
    let s = String::from_utf8_lossy(&dec).to_string();
    if s.chars().all(|c| c.is_ascii_graphic() || c == ' ' || c == '=' || c == '-') {
        return Some(s);
    }
    None
}
