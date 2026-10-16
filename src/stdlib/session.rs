//! Standard library: `tallow.session` — browser session persistence.
//!
//! Save and restore authenticated browser sessions including cookies,
//! localStorage, and sessionStorage. Enables reusing logged-in state
//! across multiple Tallow runs without re-authenticating.
//!
//! # API
//! - `Session.capture(url, domain)` — capture current session from browser
//! - `Session.save(path)` — save session to disk
//! - `Session.load(path)` — load session from disk
//! - `Session.cookies()` — get all cookies
//! - `Session.local_storage()` — get all localStorage keys
//! - `Session.to_cookie_jar()` — convert to CookieJar for HTTP injection
//! - `Session.inject_into_page(page)` — inject cookies/storage into a live page

use super::StdlibResult;
use crate::interp::{type_name, Value};

use std::collections::HashMap;
use std::fs;

/// A persisted browser session
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Session {
    domain: String,
    url: String,
    cookies: Vec<CookieData>,
    local_storage: HashMap<String, String>,
    session_storage: HashMap<String, String>,
    user_agent: String,
    captured_at: u64, // unix timestamp
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CookieData {
    name: String,
    value: String,
    domain: String,
    path: String,
    secure: bool,
    http_only: bool,
    same_site: String,
    expires: Option<i64>,
}

impl Session {
    fn new(domain: &str, url: &str) -> Self {
        Session {
            domain: domain.to_string(),
            url: url.to_string(),
            cookies: Vec::new(),
            local_storage: HashMap::new(),
            session_storage: HashMap::new(),
            user_agent: String::new(),
            captured_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    fn add_cookie(&mut self, name: &str, value: &str, domain: &str, path: &str,
                  secure: bool, http_only: bool, same_site: &str, expires: Option<i64>) {
        self.cookies.push(CookieData {
            name: name.to_string(),
            value: value.to_string(),
            domain: domain.to_string(),
            path: path.to_string(),
            secure,
            http_only,
            same_site: same_site.to_string(),
            expires,
        });
    }

    fn to_cookie_jar_value(&self) -> Value {
        let cookies: Vec<Value> = self.cookies.iter().map(|c| {
            let mut fields = vec![
                ("name".into(), Value::String(c.name.clone())),
                ("value".into(), Value::String(c.value.clone())),
                ("domain".into(), Value::String(c.domain.clone())),
                ("path".into(), Value::String(c.path.clone())),
                ("secure".into(), Value::Bool(c.secure)),
                ("http_only".into(), Value::Bool(c.http_only)),
            ];
            if let Some(exp) = c.expires {
                fields.push(("expires".into(), Value::Int(exp as i128)));
            }
            Value::Struct { name: "Cookie".into(), fields }
        }).collect();

        Value::Struct {
            name: "CookieJar".into(),
            fields: vec![("cookies".into(), Value::Array(cookies))],
        }
    }

    fn to_value(&self) -> Value {
        let cookies_val: Vec<Value> = self.cookies.iter().map(|c| {
            let mut fields = vec![
                ("name".into(), Value::String(c.name.clone())),
                ("value".into(), Value::String(c.value.clone())),
                ("domain".into(), Value::String(c.domain.clone())),
                ("path".into(), Value::String(c.path.clone())),
                ("secure".into(), Value::Bool(c.secure)),
                ("http_only".into(), Value::Bool(c.http_only)),
                ("same_site".into(), Value::String(c.same_site.clone())),
            ];
            if let Some(exp) = c.expires {
                fields.push(("expires".into(), Value::Int(exp as i128)));
            }
            Value::Struct { name: "SessionCookie".into(), fields }
        }).collect();

        let ls_entries: Vec<(Value, Value)> = self.local_storage.iter()
            .map(|(k, v)| (Value::String(k.clone()), Value::String(v.clone())))
            .collect();
        let ss_entries: Vec<(Value, Value)> = self.session_storage.iter()
            .map(|(k, v)| (Value::String(k.clone()), Value::String(v.clone())))
            .collect();

        Value::Struct {
            name: "Session".into(),
            fields: vec![
                ("domain".into(), Value::String(self.domain.clone())),
                ("url".into(), Value::String(self.url.clone())),
                ("cookies".into(), Value::Array(cookies_val)),
                ("local_storage".into(), Value::Map(ls_entries)),
                ("session_storage".into(), Value::Map(ss_entries)),
                ("user_agent".into(), Value::String(self.user_agent.clone())),
                ("captured_at".into(), Value::Int(self.captured_at as i128)),
            ],
        }
    }

    fn save_to_file(&self, path: &str) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("serialize: {e}"))?;
        fs::write(path, json).map_err(|e| format!("write: {e}"))?;
        Ok(())
    }

    fn load_from_file(path: &str) -> Result<Self, String> {
        let data = fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
        serde_json::from_str(&data).map_err(|e| format!("parse: {e}"))
    }

    fn cookie_header(&self) -> String {
        self.cookies.iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Generate JavaScript to inject this session into a page
    fn inject_js(&self) -> String {
        let mut js = String::new();

        // Inject localStorage
        for (key, value) in &self.local_storage {
            let escaped_val = value.replace('\\', "\\\\").replace('\'', "\\'");
            js.push_str(&format!(
                "try{{localStorage.setItem('{}','{}');}}catch(e){{}}\n",
                key, escaped_val
            ));
        }

        // Inject sessionStorage
        for (key, value) in &self.session_storage {
            let escaped_val = value.replace('\\', "\\\\").replace('\'', "\\'");
            js.push_str(&format!(
                "try{{sessionStorage.setItem('{}','{}');}}catch(e){{}}\n",
                key, escaped_val
            ));
        }

        // Inject cookies
        for c in &self.cookies {
            let escaped_val = c.value.replace('\\', "\\\\").replace('\'', "\\'");
            let secure_flag = if c.secure { "; secure" } else { "" };
            js.push_str(&format!(
                "try{{document.cookie='{}={};path={};domain={}{}';}}catch(e){{}}\n",
                c.name, escaped_val, c.path, c.domain, secure_flag
            ));
        }

        js
    }
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "capture" => Some(session_capture(args)),
        "load" => Some(session_load(args)),
        _ => None,
    }
}

pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    if !matches!(object, Value::Struct { name, .. } if name == "Session") {
        return None;
    }
    match method {
        "save" => Some(session_save(object, args)),
        "cookies" => Some(session_cookies(object)),
        "local_storage" => Some(session_local_storage(object)),
        "to_cookie_jar" => Some(session_to_cookie_jar(object)),
        "cookie_header" => Some(session_cookie_header(object)),
        "inject_js" => Some(session_inject_js(object)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "capture" | "load")
}

// ── Session.capture(domain, url, cookies?, localStorage?, sessionStorage?) ──

fn session_capture(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("Session.capture: requires (domain, url, cookies?, localStorage?, sessionStorage?)".into());
    }
    let domain = expect_str(&args[0], "domain")?;
    let url = expect_str(&args[1], "url")?;
    let mut session = Session::new(domain, url);

    // Parse cookies from args[2] if provided — array of Cookie structs
    if let Some(cookies_val) = args.get(2) {
        if let Value::Array(arr) = cookies_val {
            for cv in arr {
                if let Value::Struct { fields, .. } = cv {
                    let name = field_str(fields, "name");
                    let value = field_str(fields, "value");
                    let c_domain = field_str(fields, "domain");
                    let path = field_str(fields, "path");
                    let secure = field_bool(fields, "secure");
                    let http_only = field_bool(fields, "http_only");
                    let same_site = field_str(fields, "same_site");
                    let expires = field_int(fields, "expires");
                    if !name.is_empty() {
                        session.add_cookie(&name, &value, &c_domain, &path,
                            secure, http_only, &same_site, expires.map(|i| i as i64));
                    }
                }
            }
        }
    }

    // Parse localStorage from args[3] — Map<String, String>
    if let Some(ls_val) = args.get(3) {
        if let Value::Map(entries) = ls_val {
            for (k, v) in entries {
                if let (Value::String(key), Value::String(val)) = (k, v) {
                    session.local_storage.insert(key.clone(), val.clone());
                }
            }
        }
    }

    // Parse sessionStorage from args[4]
    if let Some(ss_val) = args.get(4) {
        if let Value::Map(entries) = ss_val {
            for (k, v) in entries {
                if let (Value::String(key), Value::String(val)) = (k, v) {
                    session.session_storage.insert(key.clone(), val.clone());
                }
            }
        }
    }

    Ok(session.to_value())
}

// ── Session.load(path) ──

fn session_load(args: Vec<Value>) -> StdlibResult {
    let path = expect_first_str(&args, "path")?;
    let session = Session::load_from_file(path)?;
    Ok(session.to_value())
}

// ── session.save(path) ──

fn session_save(object: &Value, args: Vec<Value>) -> StdlibResult {
    let session = extract_session(object)?;
    let path = expect_first_str(&args, "path")?;
    session.save_to_file(path)?;
    Ok(Value::Nil)
}

// ── session.cookies() ──

fn session_cookies(object: &Value) -> StdlibResult {
    let session = extract_session(object)?;
    let cookies: Vec<Value> = session.cookies.iter().map(|c| {
        let mut fields = vec![
            ("name".into(), Value::String(c.name.clone())),
            ("value".into(), Value::String(c.value.clone())),
            ("domain".into(), Value::String(c.domain.clone())),
            ("path".into(), Value::String(c.path.clone())),
            ("secure".into(), Value::Bool(c.secure)),
            ("http_only".into(), Value::Bool(c.http_only)),
            ("same_site".into(), Value::String(c.same_site.clone())),
        ];
        if let Some(exp) = c.expires {
            fields.push(("expires".into(), Value::Int(exp as i128)));
        }
        Value::Struct { name: "SessionCookie".into(), fields }
    }).collect();
    Ok(Value::Array(cookies))
}

// ── session.local_storage() ──

fn session_local_storage(object: &Value) -> StdlibResult {
    let session = extract_session(object)?;
    let entries: Vec<(Value, Value)> = session.local_storage.iter()
        .map(|(k, v)| (Value::String(k.clone()), Value::String(v.clone())))
        .collect();
    Ok(Value::Map(entries))
}

// ── session.to_cookie_jar() ──

fn session_to_cookie_jar(object: &Value) -> StdlibResult {
    let session = extract_session(object)?;
    Ok(session.to_cookie_jar_value())
}

// ── session.cookie_header() ──

fn session_cookie_header(object: &Value) -> StdlibResult {
    let session = extract_session(object)?;
    Ok(Value::String(session.cookie_header()))
}

// ── session.inject_js() ──

fn session_inject_js(object: &Value) -> StdlibResult {
    let session = extract_session(object)?;
    Ok(Value::String(session.inject_js()))
}

// ── Helpers ──

fn extract_session(value: &Value) -> Result<Session, String> {
    let fields = match value {
        Value::Struct { name, fields } if name == "Session" => fields,
        _ => return Err(format!("Expected Session struct, got {}", type_name(value))),
    };
    let domain = field_str(fields, "domain");
    let url = field_str(fields, "url");
    let mut session = Session::new(&domain, &url);

    // Reconstruct cookies
    if let Some(Value::Array(cookies)) = fields.iter().find(|(n,_)| n == "cookies").map(|(_,v)| v) {
        for cv in cookies {
            if let Value::Struct { fields: cf, .. } = cv {
                session.add_cookie(
                    &field_str(cf, "name"), &field_str(cf, "value"),
                    &field_str(cf, "domain"), &field_str(cf, "path"),
                    field_bool(cf, "secure"), field_bool(cf, "http_only"),
                    &field_str(cf, "same_site"),
                    field_int(cf, "expires").map(|i| i as i64),
                );
            }
        }
    }

    // Reconstruct localStorage
    if let Some(Value::Map(entries)) = fields.iter().find(|(n,_)| n == "local_storage").map(|(_,v)| v) {
        for (k, v) in entries {
            if let (Value::String(key), Value::String(val)) = (k, v) {
                session.local_storage.insert(key.clone(), val.clone());
            }
        }
    }

    // Reconstruct sessionStorage
    if let Some(Value::Map(entries)) = fields.iter().find(|(n,_)| n == "session_storage").map(|(_,v)| v) {
        for (k, v) in entries {
            if let (Value::String(key), Value::String(val)) = (k, v) {
                session.session_storage.insert(key.clone(), val.clone());
            }
        }
    }

    Ok(session)
}

fn field_str(fields: &[(String, Value)], name: &str) -> String {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| if let Value::String(s) = v { Some(s.clone()) } else { None })
        .unwrap_or_default()
}

fn field_bool(fields: &[(String, Value)], name: &str) -> bool {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| if let Value::Bool(b) = v { Some(*b) } else { None })
        .unwrap_or(false)
}

fn field_int(fields: &[(String, Value)], name: &str) -> Option<i128> {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| if let Value::Int(i) = v { Some(*i) } else { None })
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
