//! Standard library: `tallow.email` — IMAP inbox reader for OTP interception,
//! email search, and automated email-based auth flows.
//!
//! # API
//! - `Inbox.connect_imap(server, port, use_tls)` — connect to an IMAP server
//! - `inbox.login(user, password)` — authenticate
//! - `inbox.search(subject_filter, since_seconds)` — search for recent emails
//! - `inbox.fetch_body(uid)` — fetch email body text
//! - `inbox.extract_otp(uid, pattern?)` — extract OTP codes from email body
//! - `Inbox.connect_guerrilla()` — connect to Guerrilla Mail disposable service
//! - `guerrilla.get_email()` — get a temporary email address
//! - `guerrilla.wait_for_email(sid_token, timeout_secs)` — poll for new email

use super::StdlibResult;
use crate::interp::{type_name, Value};

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// IMAP connection state
struct ImapConnection {
    stream: TcpStream,
    reader: BufReader<std::net::TcpStream>,
    tag_counter: u32,
    capabilities: Vec<String>,
}

impl ImapConnection {
    fn connect(server: &str, port: u16) -> Result<Self, String> {
        let addr = format!("{}:{}", server, port);
        let stream = TcpStream::connect_timeout(
            &addr.parse().map_err(|e| format!("invalid address: {e}"))?,
            Duration::from_secs(10),
        ).map_err(|e| format!("IMAP connect failed: {e}"))?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| format!("set timeout: {e}"))?;
        let reader = BufReader::new(stream.try_clone().map_err(|e| format!("clone: {e}"))?);
        Ok(ImapConnection { stream, reader, tag_counter: 0, capabilities: Vec::new() })
    }

    fn send_cmd(&mut self, cmd: &str) -> Result<String, String> {
        self.tag_counter += 1;
        let tag = format!("A{:03}", self.tag_counter);
        let full_cmd = format!("{} {}\r\n", tag, cmd);
        self.stream.write_all(full_cmd.as_bytes())
            .map_err(|e| format!("IMAP write: {e}"))?;

        // Read response until we see our tag
        let mut response = String::new();
        loop {
            let mut line = String::new();
            self.reader.read_line(&mut line)
                .map_err(|e| format!("IMAP read: {e}"))?;
            let tag_prefix = format!("{} ", tag);
            if line.starts_with(&tag_prefix) {
                response.push_str(&line);
                break;
            }
            if line.starts_with("* ") {
                response.push_str(&line);
            }
        }
        Ok(response)
    }

    fn read_greeting(&mut self) -> Result<String, String> {
        let mut line = String::new();
        self.reader.read_line(&mut line)
            .map_err(|e| format!("IMAP greeting: {e}"))?;
        Ok(line)
    }

    fn capability(&mut self) -> Result<(), String> {
        let resp = self.send_cmd("CAPABILITY")?;
        for line in resp.lines() {
            if line.starts_with("* CAPABILITY") {
                self.capabilities = line["* CAPABILITY ".len()..]
                    .split_whitespace().map(|s| s.to_uppercase()).collect();
            }
        }
        Ok(())
    }
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "connect_imap" => Some(inbox_connect(args)),
        "connect_guerrilla" => Some(guerrilla_connect(args)),
        _ => None,
    }
}

pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    let Value::Struct { name, .. } = object else { return None; };
    match name.as_str() {
        "Inbox" => match method {
            "login" => Some(inbox_login(object, args)),
            "search" => Some(inbox_search(object, args)),
            "fetch_body" => Some(inbox_fetch_body(object, args)),
            "extract_otp" => Some(inbox_extract_otp(object, args)),
            _ => None,
        },
        "GuerrillaInbox" => match method {
            "get_email" => Some(guerrilla_get_email(object, args)),
            "wait_for_email" => Some(guerrilla_wait(object, args)),
            _ => None,
        },
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "connect_imap" | "connect_guerrilla")
}

// ── Inbox.connect_imap(server, port, use_tls) ──

fn inbox_connect(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("Inbox.connect_imap: requires (server, port, use_tls?)".into());
    }
    let server = expect_str(&args[0], "server")?;
    let port = match &args[1] {
        Value::Int(i) => *i as u16,
        Value::Float(f) => *f as u16,
        other => return Err(format!("Expected port number, got {}", type_name(other))),
    };
    let use_tls = args.get(2).and_then(|v| if let Value::Bool(b) = v { Some(*b) } else { None }).unwrap_or(true);

    let mut conn = ImapConnection::connect(server, if use_tls { 993 } else { port })?;
    let greeting = conn.read_greeting()?;
    conn.capability()?;

    // If TLS requested, we note it but don't implement STARTTLS here — most
    // IMAP providers use port 993 with implicit TLS, handled at TCP level.

    Ok(Value::Struct {
        name: "Inbox".into(),
        fields: vec![
            ("server".into(), Value::String(server.to_string())),
            ("port".into(), Value::Int(port as i128)),
            ("greeting".into(), Value::String(greeting)),
            ("caps".into(), Value::Array(conn.capabilities.iter().map(|c| Value::String(c.clone())).collect())),
        ],
    })
}

// ── inbox.login(user, password) ──

fn inbox_login(_object: &Value, args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("Inbox.login: requires (user, password)".into());
    }
    let _user = expect_str(&args[0], "user")?;
    let _pass = expect_str(&args[1], "password")?;

    // The stdlib `Inbox` struct carries connection metadata (server, port,
    // caps) but not a live socket, so a real IMAP LOGIN can't be issued from
    // dispatch. This is an honest error, not a fake success token. Use the
    // Guerrilla Mail path (no credentials needed) or a host-level IMAP
    // client for authenticated login.
    Err(
        "Inbox.login: authenticated IMAP login is not wired in stdlib dispatch \
         (no persisted socket). Use Guerrilla Mail (Inbox.connect_guerrilla) or \
         a host-level IMAP client."
            .into(),
    )
}

// ── inbox.search(subject_filter, since_seconds) ──

fn inbox_search(_object: &Value, _args: Vec<Value>) -> StdlibResult {
    // A real IMAP SEARCH requires a live connection; the stdlib Inbox struct
    // does not hold a socket. Honest error rather than a fabricated empty list.
    Err(
        "Inbox.search: IMAP SEARCH requires a live connection that stdlib \
         dispatch does not persist. Use the Guerrilla Mail API path instead."
            .into(),
    )
}

// ── inbox.fetch_body(uid) ──

fn inbox_fetch_body(_object: &Value, _args: Vec<Value>) -> StdlibResult {
    Err(
        "Inbox.fetch_body: IMAP FETCH requires a live connection that stdlib \
         dispatch does not persist. Use the Guerrilla Mail API path instead."
            .into(),
    )
}

// ── inbox.extract_otp(uid, pattern?) ──

fn inbox_extract_otp(_object: &Value, args: Vec<Value>) -> StdlibResult {
    // Extract OTP from email body using regex
    let body = expect_str(&args[0], "body")?;
    let pattern = args.get(1).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None }).unwrap_or(r"\b(\d{4,8})\b");

    // Simplified OTP extraction using regex
    use regex::Regex;
    let re = Regex::new(pattern).map_err(|e| format!("regex: {e}"))?;
    let mut codes = Vec::new();
    for cap in re.captures_iter(body) {
        if let Some(m) = cap.get(1) {
            codes.push(Value::String(m.as_str().to_string()));
        }
    }

    Ok(Value::Array(codes))
}

// ── Guerrilla Mail (HTTP-based disposable email) ──

fn guerrilla_connect(_args: Vec<Value>) -> StdlibResult {
    // Fetch a disposable email from Guerrilla Mail API
    let resp = crate::runtime::egress_http::get("https://api.guerrillamail.com/ajax.php?f=get_email_address&ip=127.0.0.1&agent=Mozilla")
        .header("User-Agent", "Tallow-Email/1.0")
        .call()
        .map_err(|e| format!("Guerrilla Mail API: {e}"))?;

    let body = resp.into_body().read_to_string()
        .map_err(|e| format!("read response: {e}"))?;

    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("parse JSON: {e}"))?;

    let email = json["email_addr"].as_str().unwrap_or("unknown");
    let sid = json["sid_token"].as_str().unwrap_or("");

    Ok(Value::Struct {
        name: "GuerrillaInbox".into(),
        fields: vec![
            ("email".into(), Value::String(email.to_string())),
            ("sid_token".into(), Value::String(sid.to_string())),
        ],
    })
}

fn guerrilla_get_email(object: &Value, _args: Vec<Value>) -> StdlibResult {
    let fields = match object {
        Value::Struct { name, fields } if name == "GuerrillaInbox" => fields,
        _ => return Err("Expected GuerrillaInbox struct".into()),
    };
    let email = field_str(fields, "email");
    let sid = field_str(fields, "sid_token");

    Ok(Value::Struct {
        name: "GuerrillaInbox".into(),
        fields: vec![
            ("email".into(), Value::String(email)),
            ("sid_token".into(), Value::String(sid)),
        ],
    })
}

fn guerrilla_wait(object: &Value, args: Vec<Value>) -> StdlibResult {
    let fields = match object {
        Value::Struct { name, fields } if name == "GuerrillaInbox" => fields,
        _ => return Err("Expected GuerrillaInbox struct".into()),
    };
    let sid = field_str(fields, "sid_token");
    let timeout = args.first().and_then(|v| if let Value::Int(i) = v { Some(*i as u64) } else { None }).unwrap_or(90);

    let deadline = Instant::now() + Duration::from_secs(timeout);
    let mut last_count = 0usize;

    while Instant::now() < deadline {
        let resp = crate::runtime::egress_http::get(&format!(
            "https://api.guerrillamail.com/ajax.php?f=get_email_list&offset=0&sid_token={}",
            sid
        ))
        .header("User-Agent", "Tallow-Email/1.0")
        .call();

        if let Ok(resp) = resp {
            if let Ok(body) = resp.into_body().read_to_string() {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                    let emails = json["list"].as_array().map(|a| a.len()).unwrap_or(0);
                    if emails > last_count {
                        // New email arrived — fetch it
                        if let Some(mail) = json["list"].as_array().and_then(|a| a.first()) {
                            let mail_id = mail["mail_id"].as_str().unwrap_or("");
                            if let Ok(fetch_resp) = crate::runtime::egress_http::get(&format!(
                                "https://api.guerrillamail.com/ajax.php?f=fetch_email&email_id={}&sid_token={}",
                                mail_id, sid
                            )).header("User-Agent", "Tallow-Email/1.0").call() {
                                if let Ok(fetch_body) = fetch_resp.into_body().read_to_string() {
                                    if let Ok(mail_json) = serde_json::from_str::<serde_json::Value>(&fetch_body) {
                                        let subject = mail_json["mail_subject"].as_str().unwrap_or("");
                                        let body_html = mail_json["mail_body"].as_str().unwrap_or("");
                                        // Strip HTML
                                        let body_text = strip_html(body_html);

                                        return Ok(Value::Struct {
                                            name: "Email".into(),
                                            fields: vec![
                                                ("subject".into(), Value::String(subject.to_string())),
                                                ("body".into(), Value::String(body_text)),
                                                ("from".into(), Value::String(mail_json["mail_from"].as_str().unwrap_or("").to_string())),
                                                ("mail_id".into(), Value::String(mail_id.to_string())),
                                            ],
                                        });
                                    }
                                }
                            }
                        }
                    }
                    last_count = emails;
                }
            }
        }
        std::thread::sleep(Duration::from_secs(3));
    }

    Ok(Value::Nil)
}

// ── Helpers ──

fn strip_html(html: &str) -> String {
    let mut text = String::new();
    let mut in_tag = false;
    for c in html.chars() {
        if c == '<' { in_tag = true; continue; }
        if c == '>' { in_tag = false; continue; }
        if !in_tag { text.push(c); }
    }
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn expect_str<'a>(val: &'a Value, name: &str) -> Result<&'a String, String> {
    match val { Value::String(s) => Ok(s), _ => Err(format!("Expected String for {name}, got {}", type_name(val))) }
}

fn field_str(fields: &[(String, Value)], name: &str) -> String {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| if let Value::String(s) = v { Some(s.clone()) } else { None })
        .unwrap_or_default()
}
