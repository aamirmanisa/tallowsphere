//! Standard library: `tallow.llm` — provider-agnostic model access.
//!
//! Design constraints, in the order they shaped the code:
//!
//! 1. **Credentials never enter the language.** A provider entry names an
//!    environment variable or a key file; an inline `key = "..."` in the config is
//!    refused with an explanation rather than accepted and quietly used. Errors
//!    are redacted, so a failed request cannot leak the key into a log.
//! 2. **No hardcoded model lists.** Models come from the provider's own
//!    `/models` endpoint at call time. The registry carries *providers* (protocol,
//!    base URL, auth style), not models.
//! 3. **Protocols, not twenty clients.** Sixteen of the listed providers speak one
//!    of four wire protocols (OpenAI chat completions, Anthropic messages, Google
//!    generateContent, Cohere v2); the registry records which. Providers with no
//!    public inference API are listed with `unavailable` and the reason, because a
//!    silently missing provider is harder to diagnose than an honest refusal.
//! 4. **Config is user data, not code.** `~/.config/tallow/llm.toml` (or
//!    `TALLOW_LLM_CONFIG`) adds or overrides providers; a self-hosted endpoint is
//!    just a provider with `protocol = "openai"` and a base URL.

use super::StdlibResult;
use crate::interp::{type_name, Value};
use serde_json::{json, Value as J};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Protocol {
    OpenAi,
    Anthropic,
    Google,
    AzureOpenAi,
    Cohere,
    /// Listed, but not reachable without a step this build does not implement.
    Unavailable,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::OpenAi => "openai",
            Protocol::Anthropic => "anthropic",
            Protocol::Google => "google",
            Protocol::AzureOpenAi => "azure-openai",
            Protocol::Cohere => "cohere",
            Protocol::Unavailable => "unavailable",
        }
    }

    fn parse(s: &str) -> Option<Protocol> {
        match s {
            "openai" => Some(Protocol::OpenAi),
            "anthropic" => Some(Protocol::Anthropic),
            "google" => Some(Protocol::Google),
            "azure-openai" => Some(Protocol::AzureOpenAi),
            "cohere" => Some(Protocol::Cohere),
            "unavailable" => Some(Protocol::Unavailable),
            _ => None,
        }
    }
}

pub struct ProviderSpec {
    pub id: &'static str,
    pub label: &'static str,
    pub protocol: Protocol,
    pub base_url: &'static str,
    pub key_env: &'static str,
    pub docs: &'static str,
    /// Why a provider is not usable through this build. Empty when usable.
    pub unavailable: &'static str,
}

const fn p(
    id: &'static str,
    label: &'static str,
    protocol: Protocol,
    base_url: &'static str,
    key_env: &'static str,
    docs: &'static str,
) -> ProviderSpec {
    ProviderSpec {
        id,
        label,
        protocol,
        base_url,
        key_env,
        docs,
        unavailable: "",
    }
}

const fn unavailable(
    id: &'static str,
    label: &'static str,
    key_env: &'static str,
    reason: &'static str,
) -> ProviderSpec {
    ProviderSpec {
        id,
        label,
        protocol: Protocol::Unavailable,
        base_url: "",
        key_env,
        docs: "",
        unavailable: reason,
    }
}

/// The twenty listed providers. Sixteen map onto a protocol this build speaks.
pub const REGISTRY: &[ProviderSpec] = &[
    p("openai", "OpenAI", Protocol::OpenAi, "https://api.openai.com/v1", "OPENAI_API_KEY", "platform.openai.com/docs"),
    p("anthropic", "Anthropic", Protocol::Anthropic, "https://api.anthropic.com/v1", "ANTHROPIC_API_KEY", "docs.anthropic.com"),
    p("google", "Google DeepMind (Gemini)", Protocol::Google, "https://generativelanguage.googleapis.com/v1beta", "GEMINI_API_KEY", "ai.google.dev/docs"),
    unavailable("meta", "Meta AI (Llama)", "META_API_KEY", "Meta publishes Llama weights but no general inference API; serve it locally and point a custom provider at it (protocol = \"openai\")"),
    p("xai", "xAI", Protocol::OpenAi, "https://api.x.ai/v1", "XAI_API_KEY", "docs.x.ai"),
    p("deepseek", "DeepSeek", Protocol::OpenAi, "https://api.deepseek.com/v1", "DEEPSEEK_API_KEY", "api-docs.deepseek.com"),
    p("alibaba", "Alibaba Cloud (DashScope)", Protocol::OpenAi, "https://dashscope-intl.aliyuncs.com/compatible-mode/v1", "DASHSCOPE_API_KEY", "help.aliyun.com/zh/model-studio"),
    p("mistral", "Mistral AI", Protocol::OpenAi, "https://api.mistral.ai/v1", "MISTRAL_API_KEY", "docs.mistral.ai"),
    p("moonshot", "Moonshot AI (Kimi)", Protocol::OpenAi, "https://api.moonshot.ai/v1", "MOONSHOT_API_KEY", "platform.moonshot.ai/docs"),
    p("zai", "Z.ai", Protocol::OpenAi, "https://api.z.ai/api/paas/v4", "ZAI_API_KEY", "docs.z.ai"),
    p("minimax", "MiniMax", Protocol::OpenAi, "https://api.minimax.io/v1", "MINIMAX_API_KEY", "platform.minimax.io/docs"),
    p("microsoft", "Microsoft (Azure OpenAI)", Protocol::AzureOpenAi, "", "AZURE_OPENAI_API_KEY", "learn.microsoft.com/azure/ai-services/openai"),
    unavailable("amazon", "Amazon (Bedrock)", "AWS_ACCESS_KEY_ID", "Bedrock requires SigV4 request signing, which this build does not implement; use Bedrock's OpenAI-compatible gateway or a proxy and register it as a custom provider"),
    p("nvidia", "NVIDIA (NIM)", Protocol::OpenAi, "https://integrate.api.nvidia.com/v1", "NVIDIA_API_KEY", "docs.nvidia.com/nim"),
    p("cohere", "Cohere", Protocol::Cohere, "https://api.cohere.com/v2", "COHERE_API_KEY", "docs.cohere.com"),
    p("bytedance", "ByteDance (Volcengine Ark)", Protocol::OpenAi, "https://ark.cn-beijing.volces.com/api/v3", "ARK_API_KEY", "www.volcengine.com/docs/82379"),
    p("tencent", "Tencent (Hunyuan)", Protocol::OpenAi, "https://api.hunyuan.cloud.tencent.com/v1", "HUNYUAN_API_KEY", "cloud.tencent.com/document/product/1729"),
    p("baidu", "Baidu (Qianfan)", Protocol::OpenAi, "https://qianfan.baidubce.com/v2", "QIANFAN_API_KEY", "cloud.baidu.com/doc/WENXINWORKSHOP"),
    unavailable("ibm", "IBM (watsonx)", "WATSONX_API_KEY", "watsonx needs an IAM token exchange (API key -> bearer) that this build does not implement; exchange the token yourself and register the gateway as a custom provider"),
    unavailable("xiaomi", "Xiaomi (MiLM)", "XIAOMI_API_KEY", "Xiaomi publishes no general-purpose inference API; there is nothing to authenticate against"),
];

// ── Config ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct ProviderConfig {
    pub protocol: Option<Protocol>,
    pub base_url: Option<String>,
    pub key_env: Option<String>,
    pub key_file: Option<String>,
    pub model_path: Option<String>,
    pub chat_path: Option<String>,
}

pub fn config_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("TALLOW_LLM_CONFIG") {
        return std::path::PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home).join(".config/tallow/llm.toml")
}

/// Load provider overrides. A missing file is not an error: the registry works
/// without it, and the file only exists to add or redirect providers.
/// True when `url` points at this machine: `127.0.0.0/8`, `::1`, or `localhost`.
///
/// Used to decide whether a provider may omit a credential: a key sent to a
/// loopback socket is not a secret, it is ceremony.
pub fn is_loopback_url(url: &str) -> bool {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host_port = rest.split('/').next().unwrap_or("");
    let host = match host_port.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host_port,
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host == "::1"
        || host
            .parse::<std::net::Ipv4Addr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

// ══════════════════════════════════════════════════════════════════
// Call capture (mesh `llm`-class tasks)
// ══════════════════════════════════════════════════════════════════

/// One completion that crossed the wire, in a `Send` form: the mesh worker
/// thread that made the call hands this back to the coordinator so the journal
/// can record what the model was asked and what it answered without storing the
/// `Value` types that cannot leave the thread.
#[derive(Clone, Debug)]
pub struct LlmCall {
    pub model: String,
    pub prompt_hash: String,
    pub response_hash: String,
    pub response: String,
}

thread_local! {
    static LLM_CAPTURE: std::cell::RefCell<Option<Vec<LlmCall>>> =
        const { std::cell::RefCell::new(None) };
}

/// Start recording completions on this thread. Nested calls are not a thing:
/// a second `begin_capture` replaces whatever was pending.
pub fn begin_capture() {
    LLM_CAPTURE.with(|c| *c.borrow_mut() = Some(Vec::new()));
}

/// Stop recording and return what was recorded on this thread.
pub fn take_capture() -> Vec<LlmCall> {
    LLM_CAPTURE.with(|c| c.borrow_mut().take().unwrap_or_default())
}

fn record_call(call: LlmCall) {
    LLM_CAPTURE.with(|c| {
        if let Some(v) = c.borrow_mut().as_mut() {
            v.push(call);
        }
    });
}

pub fn load_config() -> Result<BTreeMap<String, ProviderConfig>, String> {
    load_config_from(&config_path())
}

/// The loader, with the path passed in so tests do not have to mutate the
/// process environment (which is global, racy, and `unsafe` in recent Rust).
pub fn load_config_from(path: &std::path::Path) -> Result<BTreeMap<String, ProviderConfig>, String> {
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(format!("llm config {}: {e}", path.display())),
    };
    let parsed: toml::Value = toml::from_str(&text)
        .map_err(|e| format!("llm config {}: {e}", path.display()))?;
    let mut out = BTreeMap::new();
    let Some(table) = parsed.get("providers").and_then(|v| v.as_table()) else {
        return Ok(out);
    };
    for (id, value) in table {
        if value.get("key").is_some() {
            return Err(format!(
                "llm config: provider `{id}` sets `key` inline. Keys do not belong in config files — \
                 use `key_env = \"VAR_NAME\"` or `key_file = \"/path/with/0600\"` instead."
            ));
        }
        let mut cfg = ProviderConfig::default();
        if let Some(v) = value.get("protocol").and_then(|v| v.as_str()) {
            cfg.protocol = Some(
                Protocol::parse(v)
                    .ok_or_else(|| format!("llm config: provider `{id}`: unknown protocol `{v}`"))?,
            );
        }
        cfg.base_url = value.get("base_url").and_then(|v| v.as_str()).map(str::to_string);
        cfg.key_env = value.get("key_env").and_then(|v| v.as_str()).map(str::to_string);
        cfg.key_file = value.get("key_file").and_then(|v| v.as_str()).map(str::to_string);
        cfg.model_path = value.get("model_path").and_then(|v| v.as_str()).map(str::to_string);
        cfg.chat_path = value.get("chat_path").and_then(|v| v.as_str()).map(str::to_string);
        out.insert(id.clone(), cfg);
    }
    Ok(out)
}

/// A provider after config overrides are applied.
#[derive(Debug)]
pub struct Resolved {
    pub id: String,
    pub label: String,
    pub protocol: Protocol,
    pub base_url: String,
    pub key_env: String,
    pub key_file: Option<String>,
    pub model_path: String,
    pub chat_path: String,
    pub docs: String,
    pub unavailable: String,
}

fn default_paths(protocol: Protocol) -> (&'static str, &'static str) {
    match protocol {
        Protocol::OpenAi | Protocol::AzureOpenAi => ("/models", "/chat/completions"),
        Protocol::Anthropic => ("/models", "/messages"),
        Protocol::Google => ("/models", "/models/{model}:generateContent"),
        Protocol::Cohere => ("/models", "/chat"),
        Protocol::Unavailable => ("", ""),
    }
}

pub fn resolve(id: &str) -> Result<Resolved, String> {
    let cfg_map = load_config()?;
    let cfg = cfg_map.get(id);
    let spec = REGISTRY.iter().find(|s| s.id == id);
    let (protocol, base_url, key_env, docs, unavailable) = match (spec, cfg) {
        (Some(s), _) => (
            cfg.and_then(|c| c.protocol).unwrap_or(s.protocol),
            cfg.and_then(|c| c.base_url.as_deref()).unwrap_or(s.base_url),
            cfg.and_then(|c| c.key_env.clone()).unwrap_or_else(|| s.key_env.to_string()),
            s.docs.to_string(),
            s.unavailable.to_string(),
        ),
        (None, Some(c)) => {
            let protocol = c.protocol.ok_or_else(|| {
                format!("llm: provider `{id}` is not in the registry and sets no `protocol`")
            })?;
            (
                protocol,
                c.base_url.as_deref().unwrap_or(""),
                c.key_env.clone().unwrap_or_default(),
                String::new(),
                String::new(),
            )
        }
        (None, None) => {
            return Err(format!(
                "llm: unknown provider `{id}`. Run llm.providers() for the registry, or add it to {}",
                config_path().display()
            ))
        }
    };
    if !unavailable.is_empty() || protocol == Protocol::Unavailable {
        return Err(format!(
            "llm: provider `{id}` is not reachable from this build: {unavailable}"
        ));
    }
    if base_url.trim().is_empty() {
        return Err(format!("llm: provider `{id}` has no base_url; set it in {}", config_path().display()));
    }
    // A loopback endpoint has nothing to authenticate against: a local
    // llama.cpp / Ollama server takes no key, and demanding one forced callers
    // to invent a fake credential env var. Anything off-loopback still must name
    // a credential source.
    if key_env.trim().is_empty()
        && cfg.and_then(|c| c.key_file.as_ref()).is_none()
        && !is_loopback_url(base_url)
    {
        return Err(format!(
            "llm: provider `{id}` has no credential source; set key_env or key_file in {} \
             (only a loopback base_url may omit one)",
            config_path().display()
        ));
    }
    let (dm, dc) = default_paths(protocol);
    Ok(Resolved {
        id: id.to_string(),
        label: spec.map(|s| s.label).unwrap_or(id).to_string(),
        protocol,
        base_url: base_url.trim_end_matches('/').to_string(),
        key_env,
        key_file: cfg.and_then(|c| c.key_file.clone()),
        model_path: cfg.and_then(|c| c.model_path.clone()).unwrap_or_else(|| dm.to_string()),
        chat_path: cfg.and_then(|c| c.chat_path.clone()).unwrap_or_else(|| dc.to_string()),
        docs,
        unavailable,
    })
}

/// Resolve the credential. Never returned in an error message.
fn secret(r: &Resolved) -> Result<String, String> {
    if let Some(path) = &r.key_file {
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("llm: {} key_file {path}: {e}", r.id))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(format!(
                    "llm: {} key_file {path} is mode {mode:o}; it must not be group/world readable \
                     (chmod 600)",
                    r.id
                ));
            }
        }
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("llm: {} key_file {path}: {e}", r.id))?;
        let key = raw.trim().to_string();
        if key.is_empty() {
            return Err(format!("llm: {} key_file {path} is empty", r.id));
        }
        return Ok(key);
    }
    if r.key_env.trim().is_empty() && is_loopback_url(&r.base_url) {
        // Loopback takes no key. Returning an empty string here means "send no
        // Authorization header", which is what a local server expects.
        return Ok(String::new());
    }
    match std::env::var(&r.key_env) {
        Ok(v) if !v.trim().is_empty() => Ok(v.trim().to_string()),
        _ => Err(format!(
            "llm: {} has no credential: set {} or a key_file in {}",
            r.id,
            r.key_env,
            config_path().display()
        )),
    }
}

// ── HTTP ────────────────────────────────────────────────────────────────────

fn url_join(base: &str, path: &str) -> String {
    if path.starts_with("http") {
        path.to_string()
    } else if base.ends_with('/') {
        format!("{}{}", base, path.trim_start_matches('/'))
    } else {
        // `path` almost always starts with '/', so joining naively produced
        // `/v1//models`. Trim both sides exactly once.
        format!("{}/{}", base.trim_end_matches('/'), path.trim_start_matches('/'))
    }
}

fn auth_headers(r: &Resolved, key: &str) -> Vec<(&'static str, String)> {
    if key.is_empty() {
        // Loopback provider with no credential: send nothing rather than an
        // empty `Bearer `. Some local servers reject a blank scheme.
        return Vec::new();
    }
    match r.protocol {
        Protocol::Anthropic => vec![
            ("x-api-key", key.to_string()),
            ("anthropic-version", "2023-06-01".to_string()),
        ],
        Protocol::Google => vec![("x-goog-api-key", key.to_string())],
        Protocol::AzureOpenAi => vec![("api-key", key.to_string())],
        _ => vec![("Authorization", format!("Bearer {key}"))],
    }
}

/// Model traffic uses its own agent, not the browsing egress plane.
///
/// The egress plane is deny-by-default and Tor-routed because browsing must not
/// carry the box's identity. A model call is different: the credential travelling
/// in the header *is* an identity, so routing it through Tor provides no
/// anonymity, breaks providers that block exits, and hides the attribution the
/// provider's own billing and abuse policy depend on. This agent therefore
/// connects directly unless `TALLOW_LLM_PROXY` names a proxy explicitly.
fn llm_agent() -> Result<ureq::Agent, String> {
    let mut b = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(120)))
        .timeout_per_call(Some(Duration::from_secs(120)));
    match std::env::var("TALLOW_LLM_PROXY") {
        Ok(raw) if !raw.trim().is_empty() => {
            let proxy = ureq::Proxy::new(raw.trim())
                .map_err(|e| format!("llm: TALLOW_LLM_PROXY is not a valid proxy: {e}"))?;
            b = b.proxy(Some(proxy));
        }
        _ => {
            b = b.proxy(None);
        }
    }
    Ok(b.build().new_agent())
}

fn send(method: &str, url: &str, headers: &[(&str, String)], body: Option<&J>) -> Result<J, String> {
    let agent = llm_agent()?;
    let sent = if method == "GET" {
        let mut req = agent.get(url);
        for (k, v) in headers {
            req = req.header(*k, v);
        }
        req.call()
    } else {
        let mut req = agent.post(url).header("Content-Type", "application/json");
        for (k, v) in headers {
            req = req.header(*k, v);
        }
        let payload = body.cloned().unwrap_or_else(|| json!({}));
        req.send(payload.to_string().as_bytes())
    };
    match sent {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.into_body().read_to_string().unwrap_or_default();
            let parsed: J = serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }));
            if (200..300).contains(&status) {
                Ok(parsed)
            } else {
                let msg = parsed["error"]["message"]
                    .as_str()
                    .or_else(|| parsed["message"].as_str())
                    .unwrap_or("no message");
                Err(format!("http {status}: {msg}"))
            }
        }
        Err(e) => Err(format!("transport: {e}")),
    }
}

// ── Model discovery ─────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ModelInfo {
    pub id: String,
    pub owned_by: String,
}

pub fn list_models(r: &Resolved) -> Result<Vec<ModelInfo>, String> {
    let key = secret(r)?;
    let headers = auth_headers(r, &key);
    let mut url = url_join(&r.base_url, &r.model_path);
    if r.protocol == Protocol::Google {
        url = format!("{url}?pageSize=1000");
    }
    let body = send("GET", &url, &headers, None)?;
    let mut out = Vec::new();
    // OpenAI-style: { data: [ { id, owned_by } ] }
    if let Some(items) = body["data"].as_array() {
        for m in items {
            if let Some(id) = m["id"].as_str() {
                out.push(ModelInfo {
                    id: id.to_string(),
                    owned_by: m["owned_by"].as_str().unwrap_or("").to_string(),
                });
            }
        }
    }
    // Google-style: { models: [ { name: "models/gemini-…" } ] }
    if let Some(items) = body["models"].as_array() {
        for m in items {
            let raw = m["name"].as_str().or_else(|| m["id"].as_str()).unwrap_or("");
            if !raw.is_empty() {
                out.push(ModelInfo {
                    id: raw.trim_start_matches("models/").to_string(),
                    owned_by: m["publisher"].as_str().or_else(|| m["owner"].as_str()).unwrap_or("").to_string(),
                });
            }
        }
    }
    if out.is_empty() {
        return Err(format!(
            "llm: {} returned no models (endpoint {url}); check base_url/model_path",
            r.id
        ));
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out.dedup_by(|a, b| a.id == b.id);
    Ok(out)
}

// ── Completion ──────────────────────────────────────────────────────────────

pub struct Completion {
    pub text: String,
    pub model: String,
    pub tokens_in: i64,
    pub tokens_out: i64,
}

pub fn complete(r: &Resolved, model: &str, prompt: &str, max_tokens: u32) -> Result<Completion, String> {
    let key = secret(r)?;
    let headers = auth_headers(r, &key);
    let path = r.chat_path.replace("{model}", model);
    let url = url_join(&r.base_url, &path);
    let (body, text_path, tin, tout) = match r.protocol {
        Protocol::OpenAi | Protocol::AzureOpenAi => (
            json!({
                "model": model,
                "max_tokens": max_tokens,
                "messages": [{ "role": "user", "content": prompt }]
            }),
            json_pointer(&["choices", "0", "message", "content"]),
            json_pointer(&["usage", "prompt_tokens"]),
            json_pointer(&["usage", "completion_tokens"]),
        ),
        Protocol::Anthropic => (
            json!({
                "model": model,
                "max_tokens": max_tokens,
                "messages": [{ "role": "user", "content": prompt }]
            }),
            json_pointer(&["content", "0", "text"]),
            json_pointer(&["usage", "input_tokens"]),
            json_pointer(&["usage", "output_tokens"]),
        ),
        Protocol::Google => (
            json!({ "contents": [{ "parts": [{ "text": prompt }] }] }),
            json_pointer(&["candidates", "0", "content", "parts", "0", "text"]),
            json_pointer(&["usageMetadata", "promptTokenCount"]),
            json_pointer(&["usageMetadata", "candidatesTokenCount"]),
        ),
        Protocol::Cohere => (
            json!({
                "model": model,
                "messages": [{ "role": "user", "content": prompt }]
            }),
            json_pointer(&["message", "content", "0", "text"]),
            json_pointer(&["usage", "tokens", "input_tokens"]),
            json_pointer(&["usage", "tokens", "output_tokens"]),
        ),
        Protocol::Unavailable => return Err(format!("llm: {} is unavailable", r.id)),
    };
    let resp = send("POST", &url, &headers, Some(&body))?;
    let mut text = resp
        .pointer(text_path)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if text.trim().is_empty() {
        // Reasoning models (MiniCPM, DeepSeek-R1-style servers, some llama.cpp
        // builds) put the answer in `reasoning_content` and leave `content`
        // empty when the token budget ends inside the reasoning. Reading only
        // `content` made a live local model look like it had answered nothing.
        if matches!(r.protocol, Protocol::OpenAi | Protocol::AzureOpenAi) {
            if let Some(alt) = resp
                .pointer("/choices/0/message/reasoning_content")
                .and_then(|v| v.as_str())
            {
                if !alt.trim().is_empty() {
                    text = alt.to_string();
                }
            }
        }
    }
    if text.is_empty() {
        return Err(format!(
            "llm: {} returned no text (model {model}); response keys were {}",
            r.id,
            top_keys(&resp)
        ));
    }
    Ok(Completion {
        text,
        model: model.to_string(),
        tokens_in: resp.pointer(tin).and_then(|v| v.as_i64()).unwrap_or(0),
        tokens_out: resp.pointer(tout).and_then(|v| v.as_i64()).unwrap_or(0),
    })
}

fn json_pointer(parts: &[&str]) -> &'static str {
    // Pointers are static; this helper keeps the match arms readable.
    match parts {
        ["choices", "0", "message", "content"] => "/choices/0/message/content",
        ["usage", "prompt_tokens"] => "/usage/prompt_tokens",
        ["usage", "completion_tokens"] => "/usage/completion_tokens",
        ["content", "0", "text"] => "/content/0/text",
        ["usage", "input_tokens"] => "/usage/input_tokens",
        ["usage", "output_tokens"] => "/usage/output_tokens",
        ["candidates", "0", "content", "parts", "0", "text"] => "/candidates/0/content/parts/0/text",
        ["usageMetadata", "promptTokenCount"] => "/usageMetadata/promptTokenCount",
        ["usageMetadata", "candidatesTokenCount"] => "/usageMetadata/candidatesTokenCount",
        ["message", "content", "0", "text"] => "/message/content/0/text",
        ["usage", "tokens", "input_tokens"] => "/usage/tokens/input_tokens",
        ["usage", "tokens", "output_tokens"] => "/usage/tokens/output_tokens",
        _ => "",
    }
}

fn top_keys(v: &J) -> String {
    match v {
        J::Object(m) => m.keys().cloned().collect::<Vec<_>>().join(","),
        other => type_name_json(other).to_string(),
    }
}

fn type_name_json(v: &J) -> &'static str {
    match v {
        J::Null => "null",
        J::Bool(_) => "bool",
        J::Number(_) => "number",
        J::String(_) => "string",
        J::Array(_) => "array",
        J::Object(_) => "object",
    }
}

// ── Value marshalling ───────────────────────────────────────────────────────

fn arg_str(args: &[Value], i: usize) -> String {
    args.get(i).map(|v| v.as_string()).unwrap_or_default()
}

fn field<'a>(fields: &'a [(String, Value)], name: &str) -> Option<&'a Value> {
    fields.iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "providers" => Some(do_providers()),
        "models" => Some(do_models(args)),
        "complete" => Some(do_complete(args)),
        "verify" => Some(do_verify(args)),
        _ => None,
    }
}

fn do_providers() -> StdlibResult {
    let cfg = load_config()?;
    let mut out = Vec::new();
    let mut seen: Vec<String> = REGISTRY.iter().map(|s| s.id.to_string()).collect();
    for spec in REGISTRY {
        let overridden = cfg.get(spec.id).and_then(|c| c.base_url.clone());
        let status = if !spec.unavailable.is_empty() {
            "unavailable"
        } else if overridden.is_some() {
            "configured"
        } else {
            "registry"
        };
        out.push(Value::Struct {
            name: "ProviderInfo".to_string(),
            fields: vec![
                ("id".into(), Value::String(spec.id.to_string())),
                ("label".into(), Value::String(spec.label.to_string())),
                ("protocol".into(), Value::String(spec.protocol.as_str().to_string())),
                (
                    "base_url".into(),
                    Value::String(overridden.unwrap_or_else(|| spec.base_url.to_string())),
                ),
                ("key_env".into(), Value::String(spec.key_env.to_string())),
                ("status".into(), Value::String(status.to_string())),
                ("docs".into(), Value::String(spec.docs.to_string())),
                ("unavailable_reason".into(), Value::String(spec.unavailable.to_string())),
            ],
        });
    }
    for id in cfg.keys() {
        if !seen.contains(id) {
            let r = resolve(id)?;
            out.push(Value::Struct {
                name: "ProviderInfo".to_string(),
                fields: vec![
                    ("id".into(), Value::String(r.id.clone())),
                    ("label".into(), Value::String(r.label.clone())),
                    ("protocol".into(), Value::String(r.protocol.as_str().to_string())),
                    ("base_url".into(), Value::String(r.base_url.clone())),
                    ("key_env".into(), Value::String(r.key_env.clone())),
                    ("status".into(), Value::String("custom".to_string())),
                    ("docs".into(), Value::String(String::new())),
                    ("unavailable_reason".into(), Value::String(String::new())),
                ],
            });
        }
    }
    Ok(Value::Array(out))
}

fn do_models(args: Vec<Value>) -> StdlibResult {
    let id = arg_str(&args, 0);
    let r = resolve(&id)?;
    let models = list_models(&r)?;
    Ok(Value::Array(
        models
            .into_iter()
            .map(|m| Value::Struct {
                name: "ModelInfo".to_string(),
                fields: vec![
                    ("id".into(), Value::String(m.id)),
                    ("owned_by".into(), Value::String(m.owned_by)),
                ],
            })
            .collect(),
    ))
}

fn do_complete(args: Vec<Value>) -> StdlibResult {
    let id = arg_str(&args, 0);
    let model = arg_str(&args, 1);
    let prompt = arg_str(&args, 2);
    let max_tokens = match args.get(3) {
        Some(Value::Int(n)) if *n > 0 => *n as u32,
        _ => 1024,
    };
    if prompt.trim().is_empty() {
        return Err("llm.complete: prompt is empty".to_string());
    }
    let r = resolve(&id)?;
    let started = Instant::now();
    let c = complete(&r, &model, &prompt, max_tokens)?;
    record_call(LlmCall {
        model: c.model.clone(),
        prompt_hash: blake3::hash(prompt.as_bytes()).to_hex().to_string(),
        response_hash: blake3::hash(c.text.as_bytes()).to_hex().to_string(),
        response: c.text.clone(),
    });
    Ok(Value::Struct {
        name: "Completion".to_string(),
        fields: vec![
            ("text".into(), Value::String(c.text.clone())),
            ("model".into(), Value::String(c.model)),
            ("provider".into(), Value::String(r.id)),
            ("prompt_hash".into(), Value::String(blake3::hash(prompt.as_bytes()).to_hex().to_string())),
            ("response_hash".into(), Value::String(blake3::hash(c.text.as_bytes()).to_hex().to_string())),
            ("tokens_in".into(), Value::Int(c.tokens_in as i128)),
            ("tokens_out".into(), Value::Int(c.tokens_out as i128)),
            ("elapsed_ms".into(), Value::Int(started.elapsed().as_millis() as i128)),
        ],
    })
}

fn do_verify(args: Vec<Value>) -> StdlibResult {
    let id = arg_str(&args, 0);
    let started = Instant::now();
    let (ok, detail, count) = match resolve(&id) {
        Ok(r) => match list_models(&r) {
            Ok(models) => (true, format!("{} reachable", r.protocol.as_str()), models.len()),
            Err(e) => (false, e, 0),
        },
        Err(e) => (false, e, 0),
    };
    Ok(Value::Struct {
        name: "VerifyReport".to_string(),
        fields: vec![
            ("provider".into(), Value::String(id)),
            ("ok".into(), Value::Bool(ok)),
            ("models".into(), Value::Int(count as i128)),
            ("elapsed_ms".into(), Value::Int(started.elapsed().as_millis() as i128)),
            ("detail".into(), Value::String(detail)),
        ],
    })
}

#[allow(dead_code)]
fn _unused(fields: &[(String, Value)]) -> Option<&Value> {
    field(fields, "x")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_covers_every_listed_provider() {
        let listed = [
            "openai", "anthropic", "google", "meta", "xai", "deepseek", "alibaba", "mistral",
            "moonshot", "zai", "minimax", "microsoft", "amazon", "nvidia", "cohere", "bytedance",
            "tencent", "baidu", "ibm", "xiaomi",
        ];
        for id in listed {
            assert!(REGISTRY.iter().any(|p| p.id == id), "missing provider {id}");
        }
        assert_eq!(REGISTRY.len(), 20);
    }

    #[test]
    fn unusable_providers_say_why() {
        for id in ["meta", "amazon", "ibm", "xiaomi"] {
            let spec = REGISTRY.iter().find(|p| p.id == id).unwrap();
            assert_eq!(spec.protocol, Protocol::Unavailable);
            assert!(!spec.unavailable.is_empty(), "{id} must explain itself");
        }
        for id in ["openai", "anthropic", "google", "cohere", "microsoft"] {
            let spec = REGISTRY.iter().find(|p| p.id == id).unwrap();
            assert_ne!(spec.protocol, Protocol::Unavailable, "{id} must be usable");
        }
    }

    #[test]
    fn an_inline_key_is_refused_by_name() {
        let dir = std::env::temp_dir().join(format!("llm-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("llm.toml");
        std::fs::write(
            &path,
            "[providers.openai]\nbase_url = \"https://example.invalid/v1\"\nkey = \"sk-secret\"\n",
        )
        .unwrap();
        let err = load_config_from(&path).unwrap_err();
        assert!(err.contains("key_env"), "{err}");
        assert!(!err.contains("sk-secret"), "the error must not echo the key: {err}");
    }

    #[test]
    fn unknown_providers_are_refused_with_the_config_path() {
        let err = resolve("definitely-not-a-provider").unwrap_err();
        assert!(err.contains("unknown provider"), "{err}");
    }

    #[test]
    fn a_loopback_endpoint_may_omit_a_credential_but_a_remote_one_may_not() {
        assert!(is_loopback_url("http://127.0.0.1:27759/v1"));
        assert!(is_loopback_url("http://localhost:8080/v1"));
        assert!(is_loopback_url("http://[::1]:1234/v1"));
        assert!(!is_loopback_url("https://api.openai.com/v1"));
        // 127.0.0.2 is loopback too (127.0.0.0/8), while 128.0.0.1 is not.
        assert!(is_loopback_url("http://127.0.0.2:1/v1"));
        assert!(!is_loopback_url("http://128.0.0.1:1/v1"));

        let dir = std::env::temp_dir().join(format!("llm-loop-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("llm.toml");
        std::fs::write(
            &path,
            "[providers.local]\nprotocol = \"openai\"\nbase_url = \"http://127.0.0.1:27759/v1\"\n",
        )
        .unwrap();
        let cfg = load_config_from(&path).unwrap();
        let c = cfg.get("local").expect("parsed");
        assert!(c.key_env.is_none() || c.key_env.as_deref() == Some(""));
        assert_eq!(c.protocol, Some(Protocol::OpenAi));

        // The same shape pointing off-box is refused at resolve time.
        let remote = dir.join("remote.toml");
        std::fs::write(
            &remote,
            "[providers.local]\nprotocol = \"openai\"\nbase_url = \"https://api.example.com/v1\"\n",
        )
        .unwrap();
        let cfg = load_config_from(&remote).unwrap();
        let c = cfg.get("local").unwrap();
        assert!(c.key_env.is_none());
        assert!(!is_loopback_url("https://api.example.com/v1"));
    }
}
