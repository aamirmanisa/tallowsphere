//! Standard library: `tallow.otp` — OTP automation across email, SMS, voice.
//!
//! Automates OTP extraction and auto-submission for MFA bypass workflows.
//! Works with `tallow.email` for email OTPs and Guerrilla Mail for disposable inboxes.
//!
//! # API
//! - `OTP.from_email(html_or_body)` — extract OTP from email body
//! - `OTP.from_sms(body)` — extract OTP from SMS text
//! - `OTP.auto_submit(otp, form_url, field_name)` — auto-submit OTP to form
//! - `OTP.guerrilla_inbox(sid_token, pattern?)` — poll Guerrilla Mail for OTP

use super::StdlibResult;
use crate::interp::{type_name, Value};
use regex::Regex;

fn extract_otp_from_text(text: &str) -> Value {
    let patterns = [
        // Common OTP patterns
        (r"(?i)(?:one.?time\s*(?:passcode|password|pin|code)|otp|verification\s*code|login\s*code|security\s*code)[\s:]*(\d{4,8})", "otp_explicit"),
        // 6-digit code (most common)
        (r"\b(\d{6})\b", "6_digit"),
        // 4-digit code
        (r"\b(\d{4})\b", "4_digit"),
        // 8-digit code
        (r"\b(\d{8})\b", "8_digit"),
        // "Your code is XXXX" pattern
        (r"(?i)code\s*(?:is|:)\s*(\d{4,8})", "code_is"),
        // "XXXXXX is your" pattern
        (r"(\d{4,8})\s+is\s+your\s+(?:one.?time|verification|login|security)", "is_your"),
        // Verification code pattern
        (r"(?i)verification\s*code[\s:]*(\d{4,8})", "verification_code"),
    ];

    let mut codes = Vec::new();
    for (pattern, ptype) in &patterns {
        if let Ok(re) = Regex::new(pattern) {
            for caps in re.captures_iter(text) {
                if let Some(m) = caps.get(1) {
                    codes.push(Value::Struct {
                        name: "OTPEntry".into(),
                        fields: vec![
                            ("code".into(), Value::String(m.as_str().to_string())),
                            ("type".into(), Value::String(ptype.to_string())),
                        ],
                    });
                }
            }
        }
    }

    if codes.is_empty() {
        Value::Nil
    } else if codes.len() == 1 {
        codes.remove(0)
    } else {
        Value::Array(codes)
    }
}

fn guerrilla_check(sid_token: &str, _code_pattern: Option<&str>) -> StdlibResult {
    let url = format!(
        "https://api.guerrillamail.com/ajax.php?f=get_email_list&offset=0&sid_token={}",
        sid_token
    );

    let resp = crate::runtime::egress_http::get(&url)
        .call()
        .map_err(|e| format!("Guerrilla Mail request: {e}"))?;

    let body = resp.into_body()
        .read_to_string()
        .map_err(|e| format!("read: {e}"))?;

    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("JSON parse: {e}"))?;

    let mut all_otps = Vec::new();
    if let Some(list) = json["list"].as_array() {
        for email in list {
            let mail_id = email["mail_id"].as_i64().unwrap_or(0);
            let subject = email["mail_subject"].as_str().unwrap_or("");
            let from = email["mail_from"].as_str().unwrap_or("");

            // Fetch email body
            let fetch_url = format!(
                "https://api.guerrillamail.com/ajax.php?f=fetch_email&email_id={}&sid_token={}",
                mail_id, sid_token
            );
            if let Ok(resp2) = crate::runtime::egress_http::get(&fetch_url).call() {
                if let Ok(body2) = resp2.into_body().read_to_string() {
                    if let Ok(json2) = serde_json::from_str::<serde_json::Value>(&body2) {
                        let email_body = json2["mail_body"].as_str().unwrap_or("");
                        // Clean HTML from email body
                        let clean = strip_html(email_body);
                        let otps = extract_otp_from_text(&clean);
                        match otps {
                            Value::Nil => continue,
                            Value::Array(ref arr) if arr.is_empty() => continue,
                            _ => {
                                all_otps.push(Value::Struct {
                                    name: "OTPMessage".into(),
                                    fields: vec![
                                        ("from".into(), Value::String(from.to_string())),
                                        ("subject".into(), Value::String(subject.to_string())),
                                        ("mail_id".into(), Value::Int(mail_id as i128)),
                                        ("otps".into(), otps),
                                    ],
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    if all_otps.is_empty() {
        Ok(Value::Nil)
    } else {
        Ok(Value::Array(all_otps))
    }
}

fn strip_html(html: &str) -> String {
    let re = Regex::new(r"<[^>]+>").unwrap();
    re.replace_all(html, " ")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn auto_submit(otp: &str, form_url: &str, field_name: &str) -> StdlibResult {
    let body = format!("{}={}", urlencoding::encode(field_name), urlencoding::encode(otp));

    let resp = crate::runtime::egress_http::post(form_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(body.as_bytes())
        .map_err(|e| format!("submit request: {e}"))?;

    let status = resp.status();
    let resp_body = resp.into_body()
        .read_to_string()
        .unwrap_or_default();

    Ok(Value::Struct {
        name: "OTPResult".into(),
        fields: vec![
            ("status".into(), Value::Int(status.as_u16() as i128)),
            ("success".into(), Value::Bool(status == 200 || status == 302)),
            ("response".into(), Value::String(
                if resp_body.len() > 500 { resp_body[..500].to_string() } else { resp_body }
            )),
        ],
    })
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "from_email" => Some(otp_from_email(args)),
        "from_sms" => Some(otp_from_sms(args)),
        "guerrilla_inbox" => Some(otp_guerrilla(args)),
        "auto_submit" => Some(otp_auto_submit(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "from_email" | "from_sms" | "guerrilla_inbox" | "auto_submit")
}

fn otp_from_email(args: Vec<Value>) -> StdlibResult {
    let text = expect_first_str(&args, "html_or_body")?;
    Ok(extract_otp_from_text(text))
}

fn otp_from_sms(args: Vec<Value>) -> StdlibResult {
    let text = expect_first_str(&args, "body")?;
    Ok(extract_otp_from_text(text))
}

fn otp_guerrilla(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("OTP.guerrilla_inbox: requires (sid_token, pattern?)".into());
    }
    let sid_token = expect_first_str(&args, "sid_token")?;
    let pattern = args.get(1).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None });
    guerrilla_check(sid_token, pattern)
}

fn otp_auto_submit(args: Vec<Value>) -> StdlibResult {
    if args.len() < 3 {
        return Err("OTP.auto_submit: requires (otp, form_url, field_name)".into());
    }
    let otp = expect_first_str(&args, "otp")?;
    let form_url = expect_string(&args[1], "form_url")?;
    let field_name = expect_string(&args[2], "field_name")?;
    auto_submit(otp, form_url, field_name)
}

fn expect_first_str<'a>(args: &'a [Value], name: &str) -> Result<&'a String, String> {
    match args.first() {
        Some(Value::String(s)) => Ok(s),
        Some(o) => Err(format!("Expected String {name}, got {}", type_name(o))),
        None => Err(format!("Missing {name} argument")),
    }
}

fn expect_string<'a>(val: &'a Value, name: &str) -> Result<&'a String, String> {
    match val {
        Value::String(s) => Ok(s),
        _ => Err(format!("Expected String for {name}, got {}", type_name(val))),
    }
}
