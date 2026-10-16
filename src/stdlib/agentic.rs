//! Standard library: `tallow.agentic` — AI agent integration and MCP protocol.
//!
//! Implements MCP (Model Context Protocol) tool spec export and natural language
//! to Tallow script generation.
//!
//! # API
//! - `Agent.mcp_tools()` — export Tallow capabilities as MCP tool definitions
//! - `Agent.mcp_resources()` — export available resources (files, browsers, proxies)
//! - `Agent.nl_to_script(prompt)` — generate .tl script from natural language

use super::StdlibResult;
use crate::interp::Value;

fn mcp_tool_definitions() -> Value {
    let tools = vec![
        tool_def("tallow.browser.navigate", "Navigate to a URL using the browser pool",
            r#"{"url": "string", "fingerprint": "string?", "proxy": "string?"}"#,
            r#"{"html": "string", "screenshot": "string?"}"#),
        tool_def("tallow.browser.click", "Click an element on the page",
            r#"{"selector": "string", "page_index": "number?"}"#,
            r#"{"success": "boolean"}"#),
        tool_def("tallow.browser.extract", "Extract text/html from the current page",
            r#"{"selector": "string?", "attribute": "string?"}"#,
            r#"{"content": "string"}"#),
        tool_def("tallow.http.fetch", "Make an HTTP request",
            r#"{"url": "string", "method": "string?", "headers": "object?", "body": "string?", "proxy": "string?"}"#,
            r#"{"status": "number", "body": "string", "headers": "object"}"#),
        tool_def("tallow.jwt.parse", "Parse and analyze a JWT token",
            r#"{"token": "string"}"#,
            r#"{"header": "object", "payload": "object", "algorithm": "string"}"#),
        tool_def("tallow.jwt.attack_none", "Try JWT alg:none bypass",
            r#"{"token": "string"}"#,
            r#"{"forged_token": "string", "success": "boolean"}"#),
        tool_def("tallow.oauth.discover", "OIDC discovery on issuer URL",
            r#"{"issuer_url": "string"}"#,
            r#"{"authorization_endpoint": "string", "token_endpoint": "string"}"#),
        tool_def("tallow.cookie_jar.load_browser", "Load cookies from browser database",
            r#"{"browser_path": "string?"}"#,
            r#"{"cookie_count": "number", "domains": ["string"]}"#),
        tool_def("tallow.email.inbox", "Get Guerrilla Mail disposable inbox",
            r#"{}"#,
            r#"{"email": "string", "sid_token": "string"}"#),
        tool_def("tallow.captcha.detect", "Detect CAPTCHA/WAF on page",
            r#"{"html": "string"}"#,
            r#"{"provider": "string", "challenge_type": "string"}"#),
        tool_def("tallow.escalation.fetch", "Auto-escalated page fetch",
            r#"{"url": "string", "max_level": "string?"}"#,
            r#"{"html": "string", "status": "number", "level_used": "string"}"#),
        tool_def("tallow.extract.all", "Extract all structured data from page",
            r#"{"html": "string"}"#,
            r#"{"product": "object?", "article": "object?", "profile": "object?"}"#),
        tool_def("tallow.markdown.convert", "Convert HTML to clean Markdown",
            r#"{"html": "string"}"#,
            r#"{"markdown": "string"}"#),
        tool_def("tallow.fingerprint.generate", "Generate random browser fingerprint",
            r#"{}"#,
            r#"{"user_agent": "string", "platform": "string"}"#),
    ];

    Value::Array(tools)
}

fn tool_def(name: &str, description: &str, input_schema: &str, _output_schema: &str) -> Value {
    Value::Struct {
        name: "MCPTool".into(),
        fields: vec![
            ("name".into(), Value::String(name.to_string())),
            ("description".into(), Value::String(description.to_string())),
            ("inputSchema".into(), Value::String(input_schema.to_string())),
        ],
    }
}

fn mcp_resources() -> Value {
    Value::Struct {
        name: "MCPResources".into(),
        fields: vec![
            ("browsers".into(), Value::String("chrome, chromium, brave-browser".into())),
            ("proxies".into(), Value::String("7-layer: TorPool, ProxyPool, static, direct".into())),
            ("modules".into(), Value::Int(65)), // approximate
        ],
    }
}

fn nl_to_script(prompt: &str) -> Value {
    // Template-based NL→TL conversion
    let prompt_lower = prompt.to_lowercase();

    let template = if prompt_lower.contains("login") || prompt_lower.contains("sign in") {
        r#"
// Auto-generated login script
let browser = Browser.launch()
let page = browser.navigate(url)
page.wait_for("input[type='email']")
page.type_text("input[type='email']", email)
page.type_text("input[type='password']", password)
page.click("button[type='submit']")
page.wait_for_navigation()
let html = page.content()
return html
"#
    } else if prompt_lower.contains("scrape") && prompt_lower.contains("product") {
        r#"
// Auto-generated product scraper
let result = escalation.fetch(url, "browser_render")
let data = Extract.schema(result.html, "product")
return data
"#
    } else if prompt_lower.contains("bypass") && prompt_lower.contains("auth") {
        r#"
// Auto-generated auth bypass
let email = Email.inbox()
let login = HTTP.post(auth_url, {"email": email.email})
let otp = Email.wait_for(email.sid_token, 60)
let verify = HTTP.post(verify_url, {"email": email.email, "code": otp.code})
let token = verify.cookies
return token
"#
    } else {
        r#"
// Auto-generated extract script
let result = escalation.fetch(url, "browser_cdp")
let html = result.html
let md = Markdown.convert(html)
let data = Extract.all(md)
return data
"#
    };

    Value::Struct {
        name: "AgentScript".into(),
        fields: vec![
            ("script".into(), Value::String(template.trim().to_string())),
            ("prompt".into(), Value::String(prompt.to_string())),
        ],
    }
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "mcp_tools" => Some(Ok(mcp_tool_definitions())),
        "mcp_resources" => Some(Ok(mcp_resources())),
        "nl_to_script" => Some(ag_nl_to_script(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "mcp_tools" | "mcp_resources" | "nl_to_script")
}

fn ag_nl_to_script(args: Vec<Value>) -> StdlibResult {
    let prompt = args.first().and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None })
        .unwrap_or("scrape page");
    Ok(nl_to_script(prompt))
}
