//! Agent Reasoning Engine -- pluggable backends for cognitive reasoning.
//!
//! Three backend modes:
//! - **CloudLLM**: OpenAI-compatible API via HTTP POST (GPT-4, Claude, etc.)
//! - **LocalLLM**: Ollama API via HTTP POST (llama3, mistral, etc.)
//! - **RuleEngine**: Condition-action rules evaluated against working memory
//!
//! Tiered inference routing:
//! - Secret data -> local-only backends (never sent to cloud APIs)
//! - Private data -> depends on LlmPolicy (local_only, redact_private, allow_cloud)
//! - Public data -> any backend
//!
//! All reasoning steps are logged in an auditable chain.

use std::time::Duration;

// ── LlmPolicy ─────────────────────────────────────────────────────────────

/// Policy controlling which inference backends an agent may use.
/// Parsed from `llm_policy:` field in @agent_task annotations.
#[derive(Debug, Clone, PartialEq)]
pub enum LlmPolicy {
    /// Only local inference backends (LocalLLM, RuleEngine). No cloud API calls.
    LocalOnly,
    /// Redact private fields before sending to cloud. Secret still blocked.
    RedactPrivate,
    /// Requires trusted execution environment. Treated as LocalOnly for now.
    TeeRequired,
    /// Any backend is acceptable (default for public data).
    AllowCloud,
}

impl LlmPolicy {
    /// Parse from annotation string value (e.g., ".local_only").
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "local_only" => Some(LlmPolicy::LocalOnly),
            "redact_private" => Some(LlmPolicy::RedactPrivate),
            "tee_required" => Some(LlmPolicy::TeeRequired),
            "allow_cloud" => Some(LlmPolicy::AllowCloud),
            _ => None,
        }
    }
}

// ── DataSensitivity ────────────────────────────────────────────────────────

/// Sensitivity level of data being processed, determines routing constraints.
#[derive(Debug, Clone, PartialEq)]
pub enum DataSensitivity {
    /// Secret data -- must use local-only inference, never cloud.
    Secret,
    /// Private data -- depends on LlmPolicy.
    Private,
    /// Public data -- any backend is fine.
    Public,
}

// ── Tiered Routing ─────────────────────────────────────────────────────────

/// Check if a backend is acceptable for the given data sensitivity and policy.
///
/// Returns `Ok(true)` if the backend is acceptable.
/// Returns `Err(message)` if the backend is NOT acceptable for this sensitivity+policy.
pub fn route_inference(
    sensitivity: &DataSensitivity,
    policy: &LlmPolicy,
    backend: &ReasoningBackend,
) -> Result<bool, String> {
    let is_local = matches!(backend, ReasoningBackend::LocalLLM { .. } | ReasoningBackend::RuleEngine { .. });

    match sensitivity {
        DataSensitivity::Secret => {
            if is_local {
                Ok(true)
            } else {
                Err("secret data requires local inference -- cannot send to cloud API".to_string())
            }
        }
        DataSensitivity::Private => {
            match policy {
                LlmPolicy::LocalOnly | LlmPolicy::TeeRequired => {
                    if is_local {
                        Ok(true)
                    } else {
                        Err("llm_policy: .local_only requires local inference for private data".to_string())
                    }
                }
                LlmPolicy::RedactPrivate => {
                    // Caller must redact private fields before sending, but backend is OK
                    Ok(true)
                }
                LlmPolicy::AllowCloud => {
                    Ok(true)
                }
            }
        }
        DataSensitivity::Public => {
            Ok(true)
        }
    }
}

// ── Cloud Provider Detection ───────────────────────────────────────────────

/// Detected cloud API provider for format selection.
#[derive(Debug, Clone, PartialEq)]
pub enum CloudProvider {
    OpenAI,
    Anthropic,
}

/// Detect provider from API URL.
fn detect_provider(api_url: &str) -> CloudProvider {
    let url_lower = api_url.to_lowercase();
    if url_lower.contains("anthropic.com") || url_lower.contains("claude") {
        CloudProvider::Anthropic
    } else {
        CloudProvider::OpenAI
    }
}

// ── ReasoningBackend ─────────────────────────────────────────────────────────

/// Pluggable reasoning backend for the Brain.
#[derive(Debug, Clone)]
pub enum ReasoningBackend {
    CloudLLM {
        api_url: String,
        api_key: String,
        model: String,
    },
    LocalLLM {
        url: String,
        model: String,
    },
    RuleEngine {
        rules: Vec<Rule>,
    },
}

impl ReasoningBackend {
    /// Construct a ReasoningBackend from string configuration values.
    pub fn from_config(
        backend_type: &str,
        model: &str,
        api_key: &str,
        api_url: &str,
        url: &str,
    ) -> Self {
        match backend_type {
            "cloud_llm" => ReasoningBackend::CloudLLM {
                api_url: if api_url.is_empty() {
                    "https://api.openai.com/v1/chat/completions".to_string()
                } else {
                    api_url.to_string()
                },
                api_key: api_key.to_string(),
                model: if model.is_empty() {
                    "gpt-4".to_string()
                } else {
                    model.to_string()
                },
            },
            "local_llm" => ReasoningBackend::LocalLLM {
                url: if url.is_empty() {
                    "http://localhost:11434".to_string()
                } else {
                    url.to_string()
                },
                model: if model.is_empty() {
                    "llama3.2".to_string()
                } else {
                    model.to_string()
                },
            },
            // Default to rule engine for "rule_engine", "rule", or unknown values
            _ => ReasoningBackend::RuleEngine { rules: Vec::new() },
        }
    }

    /// Human-readable name for this backend type.
    pub fn name(&self) -> &str {
        match self {
            ReasoningBackend::CloudLLM { .. } => "cloud_llm",
            ReasoningBackend::LocalLLM { .. } => "local_llm",
            ReasoningBackend::RuleEngine { .. } => "rule_engine",
        }
    }

    /// Resolve a concrete model name for a given tier.
    ///
    /// A backend that carries only a single model returns that model for both
    /// tiers; backends configured with a `CloudTier`/`LocalTier` pair can map
    /// Fast/Strong to distinct models (see `CloudTier`/`LocalTier`). Returns
    /// `None` for rule engines, which have no model.
    pub fn model_for_tier(&self, _tier: ModelTier) -> Option<&str> {
        match self {
            ReasoningBackend::CloudLLM { model, .. } => Some(model.as_str()),
            ReasoningBackend::LocalLLM { model, .. } => Some(model.as_str()),
            ReasoningBackend::RuleEngine { .. } => None,
        }
    }
}

// ── Model Tier Selection ────────────────────────────────────────────────────

/// Which model tier to use for a reasoning step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelTier {
    /// Lower-cost, faster model for simple/public steps.
    Fast,
    /// Higher-capability model for hard steps.
    Strong,
}

/// Prompt length (in characters) above which the strong tier is selected.
pub const STRONG_PROMPT_LEN_THRESHOLD: usize = 4096;
/// Working-memory item count at or above which the strong tier is selected.
pub const STRONG_WORKING_MEM_THRESHOLD: usize = 32;
/// Uncertainty (0..=1) at or above which the strong tier is selected.
pub const STRONG_UNCERTAINTY_THRESHOLD: f64 = 0.65;
/// 3.0: how many independent samples the strong tier runs and reduces via
/// consensus. Set to 1 to disable (single-pass critique/revise instead).
pub const STRONG_TIER_CONSENSUS_SAMPLES: usize = 3;

/// Choose a `ModelTier` based on prompt length, working-memory size, and
/// uncertainty.
///
/// The strong tier is selected when the prompt is long, the working memory is
/// large, or uncertainty is high; otherwise the fast tier is used. This keeps
/// most steps cheap while reserving the expensive strong model for genuinely
/// hard problems.
pub fn select_model_tier(prompt_len: usize, working_mem_items: usize, uncertainty: f64) -> ModelTier {
    if prompt_len >= STRONG_PROMPT_LEN_THRESHOLD
        || working_mem_items >= STRONG_WORKING_MEM_THRESHOLD
        || uncertainty >= STRONG_UNCERTAINTY_THRESHOLD
    {
        ModelTier::Strong
    } else {
        ModelTier::Fast
    }
}

/// A pair of cloud model names, one for each tier.
#[derive(Debug, Clone, PartialEq)]
pub struct CloudTier {
    pub fast: String,
    pub strong: String,
}

/// A pair of local model names, one for each tier.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalTier {
    pub fast: String,
    pub strong: String,
}

// ── Few-shot prior outcomes ─────────────────────────────────────────────────

/// Snippet cap: only this many characters of each outcome are included, and
/// newlines are collapsed so each past attempt stays on a single line.
pub const PRIOR_OUTCOME_SNIPPET_LEN: usize = 120;

/// Build a prompt that appends a compact history of prior attempts.
///
/// Each entry in `prior_outcomes` is `(success, snippet)`. Successes are marked
/// `SUCCESS` and failures `FAILURE`, with a one-line snippet (newlines collapsed,
/// capped at `PRIOR_OUTCOME_SNIPPET_LEN`). Returns the base prompt unchanged when
/// there is no history. Pure string assembly -- no LLM involved, so it is cheap.
pub fn build_prompt_with_history(base_prompt: &str, prior_outcomes: &[(bool, String)]) -> String {
    if prior_outcomes.is_empty() {
        return base_prompt.to_string();
    }

    let mut out = String::with_capacity(base_prompt.len() + prior_outcomes.len() * 96);
    out.push_str(base_prompt);
    out.push_str("\n\nPast attempts:");

    for (success, snippet) in prior_outcomes {
        let status = if *success { "SUCCESS" } else { "FAILURE" };
        let collapsed: String = snippet
            .chars()
            .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
            .collect();
        let snippet = collapsed.trim();
        let snippet = if snippet.chars().count() > PRIOR_OUTCOME_SNIPPET_LEN {
            let mut clipped: String = snippet.chars().take(PRIOR_OUTCOME_SNIPPET_LEN).collect();
            clipped.push_str("...");
            clipped
        } else {
            snippet.to_string()
        };
        out.push_str(&format!("\n- {status}: {snippet}"));
    }

    out
}

// ── Retry / backoff ───────────────────────────────────────────────────────────

/// Default number of attempts used by [`with_retry`] when the caller does not
/// want to think about retry policy.
pub const DEFAULT_RETRY_ATTEMPTS: u32 = 3;

/// Default exponential backoff base (in milliseconds) for [`with_retry`].
pub const DEFAULT_BACKOFF_BASE_MS: u64 = 250;

/// Run `f`, retrying on `Err` with exponential backoff until `attempts` total
/// calls have been made.
///
/// `attempts` is the total number of times `f` is invoked (the first call, plus
/// `attempts - 1` retries). After the first failure the delay is
/// `base_delay_ms * 2^n` where `n` is the 0-based retry index, so the
/// sequence is `base`, `base * 2`, `base * 4`, ... A `base_delay_ms` of `0`
/// yields no blocking sleep, which keeps tests fast. Returns the last error on
/// exhaustion. Pure apart from the optional `std::thread::sleep` between
/// attempts.
pub fn with_retry<T, F: Fn() -> Result<T, String>>(attempts: u32, base_delay_ms: u64, f: F) -> Result<T, String> {
    let attempts = attempts.max(1);
    let mut last_err = String::new();
    for attempt in 0..attempts {
        match f() {
            Ok(value) => return Ok(value),
            Err(err) => {
                last_err = err;
                if attempt + 1 < attempts {
                    // Saturating shift guards against attempt overflow; delay
                    // computed with saturating mul so it never panics.
                    let backoff = 2u64.saturating_pow(attempt.min(62));
                    let delay_ms = base_delay_ms.saturating_mul(backoff);
                    if delay_ms > 0 {
                        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                    }
                }
            }
        }
    }
    Err(last_err)
}

// ── Best-of-N sampling / self-consistency ─────────────────────────────────────

/// Run `n` samples (indexed `0..n`) and apply a `pick` aggregator over them.
///
/// A general self-consistency primitive: `sample` produces one outcome per
/// index (e.g. one LLM completion, possibly randomised by temperature), and
/// `pick` reduces the `n` outcomes to a single result (e.g. majority vote via
/// [`majority_pick`], or a scoring function). The caller supplies both the
/// sampling and the selection, so this stays a pure, generic shape.
pub fn best_of_n<R>(n: usize, sample: impl Fn(usize) -> R, pick: impl Fn(&[R]) -> R) -> R {
    let samples: Vec<R> = (0..n).map(sample).collect();
    pick(&samples)
}

/// Return the most frequently occurring element of `items` (the mode).
///
/// Returns `None` for an empty slice. Ties are broken by the first element
/// encountered that reached the maximum count. Requires `Clone + Eq + Hash`
/// because elements are counted in a HashMap.
pub fn majority_pick<T: Clone + Eq + std::hash::Hash>(items: &[T]) -> Option<T> {
    let mut counts: std::collections::HashMap<&T, usize> = std::collections::HashMap::new();
    for item in items {
        *counts.entry(item).or_insert(0) += 1;
    }
    let mut best: Option<&T> = None;
    let mut best_count = 0usize;
    for (value, count) in &counts {
        if *count > best_count {
            best_count = *count;
            best = Some(*value);
        }
    }
    best.cloned()
}

/// 2.4 reducer: reduce N independent candidate answers to the modal
/// (majority-consistent) one. Ties break toward the first-encountered candidate.
/// Returns None only when there are no candidates.
pub fn reduce_consensus(candidates: &[String]) -> Option<String> {
    majority_pick(candidates)
}

/// 2.4 deep reasoning: sample N independent answers to the same prompt and reduce
/// them to the majority-consensus response. Cost scales linearly with N — intended
/// for the strong tier only (escalate-on-difficulty). If no sample succeeds,
/// returns the last sample's failure.
pub fn reason_with_consensus(
    backend: &ReasoningBackend,
    prompt: &str,
    working_memory_items: &[(String, String)],
    timeout_secs: u64,
    n: usize,
) -> ReasoningResult {
    let num = n.max(1);
    let mut samples = Vec::with_capacity(num);
    for _ in 0..num {
        samples.push(reason_with_backend(backend, prompt, working_memory_items, timeout_secs));
    }
    let candidates: Vec<String> = samples
        .iter()
        .filter(|r| r.success)
        .map(|r| r.response.clone())
        .collect();
    if let Some(pick) = reduce_consensus(&candidates) {
        let meta = samples
            .iter()
            .find(|r| r.success)
            .unwrap_or_else(|| &samples[0]);
        return ReasoningResult {
            response: pick,
            duration_ms: meta.duration_ms,
            backend_name: format!("{}_consensus", meta.backend_name),
            tokens_used: meta.tokens_used,
            input_tokens: meta.input_tokens,
            output_tokens: meta.output_tokens,
            success: true,
        };
    }
    samples.into_iter().next_back().unwrap_or(ReasoningResult {
        response: "consensus: no sample produced an answer".to_string(),
        duration_ms: 0,
        backend_name: "consensus".to_string(),
        tokens_used: None,
        input_tokens: None,
        output_tokens: None,
        success: false,
    })
}

/// 1.8: consult a rules store before hitting an LLM. Returns the fired action
/// (highest-priority rule whose conditions all match prompt/working-memory) as a
/// short-circuit override, or None to proceed to the LLM. Decouples rules from
/// the backend so an LLM-configured agent still short-circuits cheap answers.
pub fn rules_short_circuit(
    rules: &[Rule],
    prompt: &str,
    working_memory_items: &[(String, String)],
) -> Option<String> {
    if rules.is_empty() {
        return None;
    }
    let mut sorted: Vec<&Rule> = rules.iter().collect();
    sorted.sort_by(|a, b| b.priority.cmp(&a.priority));
    let mut match_items: Vec<(String, String)> = working_memory_items
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
        .collect();
    match_items.push(("__prompt".to_string(), prompt.to_lowercase()));
    for rule in sorted {
        // All conditions must match against a key OR a value.
        let all_match = rule.conditions.iter().all(|cond| {
            let c = cond.to_lowercase();
            match_items.iter().any(|(k, v)| k.contains(&c) || v.contains(&c))
        });
        if all_match {
            return Some(rule.action.clone());
        }
    }
    None
}

/// 1.8: reason with rules-first short-circuiting. If a rule fires, return it
/// immediately (no LLM cost); otherwise fall through to the backend.
pub fn reason_short_circuit_first(
    backend: &ReasoningBackend,
    rules: &[Rule],
    prompt: &str,
    working_memory_items: &[(String, String)],
    timeout_secs: u64,
) -> ReasoningResult {
    match rules_short_circuit(rules, prompt, working_memory_items) {
        Some(action) => ReasoningResult {
            response: action,
            duration_ms: 0,
            backend_name: "rule_short_circuit".to_string(),
            tokens_used: None,
            input_tokens: None,
            output_tokens: None,
            success: true,
        },
        None => reason_with_backend(backend, prompt, working_memory_items, timeout_secs),
    }
}

// ── Rule ─────────────────────────────────────────────────────────────────────

/// A condition-action rule for the rule-based reasoning engine.
#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    /// Patterns to match against working memory items (case-insensitive).
    pub conditions: Vec<String>,
    /// Conclusion or response when all conditions match.
    pub action: String,
    /// Higher priority rules are evaluated first.
    pub priority: i32,
}

// ── ReasoningResult ──────────────────────────────────────────────────────────

/// Result of a single reasoning step.
#[derive(Debug, Clone)]
pub struct ReasoningResult {
    pub response: String,
    pub duration_ms: u64,
    pub backend_name: String,
    pub tokens_used: Option<u32>,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    pub success: bool,
}

// ── Main dispatch ────────────────────────────────────────────────────────────

/// Execute a reasoning step using the configured backend.
///
/// For CloudLLM/LocalLLM, makes HTTP calls with the given timeout.
/// For RuleEngine, evaluates conditions against working memory items.
pub fn reason_with_backend(
    backend: &ReasoningBackend,
    prompt: &str,
    working_memory_items: &[(String, String)],
    timeout_secs: u64,
) -> ReasoningResult {
    let start = std::time::Instant::now();
    let result = match backend {
        ReasoningBackend::CloudLLM { .. } => reason_cloud(backend, prompt, timeout_secs),
        ReasoningBackend::LocalLLM { .. } => reason_local(backend, prompt, timeout_secs),
        ReasoningBackend::RuleEngine { rules } => reason_rules(prompt, rules, working_memory_items),
    };
    let duration_ms = start.elapsed().as_millis() as u64;

    // Extract tokens from Ok result
    let (response, input_tokens, output_tokens, success) = match result {
        Ok((resp, inp, out)) => (resp, inp, out, true),
        Err(e) => (format!("reasoning error: {e}"), None, None, false),
    };

    let tokens_used = match (input_tokens, output_tokens) {
        (Some(i), Some(o)) => Some(i + o),
        (Some(i), None) => Some(i),
        (None, Some(o)) => Some(o),
        (None, None) => None,
    };

    ReasoningResult {
        response,
        duration_ms,
        backend_name: backend.name().to_string(),
        tokens_used,
        input_tokens,
        output_tokens,
        success,
    }
}

// ── Cloud LLM backend ────────────────────────────────────────────────────────

/// Send a prompt to an OpenAI-compatible or Anthropic API endpoint.
fn reason_cloud(
    backend: &ReasoningBackend,
    prompt: &str,
    timeout_secs: u64,
) -> Result<(String, Option<u32>, Option<u32>), String> {
    let ReasoningBackend::CloudLLM {
        api_url,
        api_key,
        model,
    } = backend
    else {
        return Err("reason_cloud called with non-cloud backend".to_string());
    };

    let provider = detect_provider(api_url);

    // Egress contract (audit-06 F-1): proxied-or-refuses. A configured but
    // malformed TALLOW_PROXY hard-refuses here instead of egressing direct.
    let agent = crate::runtime::egress_http::agent_with_timeouts(
        Some(Duration::from_secs(timeout_secs)),
        None,
    );

    match provider {
        CloudProvider::Anthropic => {
            let url = resolve_anthropic_url(api_url);
            let body = serde_json::json!({
                "model": model,
                "max_tokens": 4096,
                "messages": [{"role": "user", "content": prompt}]
            });

            let resp = agent
                .post(&url)
                .header("x-api-key", api_key)
                .header("anthropic-version", "2023-06-01")
                .header("Content-Type", "application/json")
                .send_json(&body)
                .map_err(|e| format!("Anthropic API request failed: {e}"))?;

            let body_str = resp
                .into_body()
                .read_to_string()
                .map_err(|e| format!("Anthropic API response read failed: {e}"))?;

            let json: serde_json::Value = serde_json::from_str(&body_str)
                .map_err(|e| format!("Anthropic API response parse failed: {e}"))?;

            parse_anthropic_response(&json)
        }
        CloudProvider::OpenAI => {
            let url = resolve_cloud_url(api_url);
            let body = serde_json::json!({
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1024
            });

            let resp = agent
                .post(&url)
                .header("Authorization", &format!("Bearer {api_key}"))
                .header("Content-Type", "application/json")
                .send_json(&body)
                .map_err(|e| format!("cloud LLM request failed: {e}"))?;

            let body_str = resp
                .into_body()
                .read_to_string()
                .map_err(|e| format!("cloud LLM response read failed: {e}"))?;

            let json: serde_json::Value = serde_json::from_str(&body_str)
                .map_err(|e| format!("cloud LLM response parse failed: {e}"))?;

            parse_cloud_response(&json)
        }
    }
}

/// Resolve the cloud API URL: if it already ends with a completions path, use as-is.
/// Otherwise, append `/v1/chat/completions`.
pub fn resolve_cloud_url(api_url: &str) -> String {
    if api_url.ends_with("/completions") || api_url.ends_with("/chat") {
        api_url.to_string()
    } else {
        let base = api_url.trim_end_matches('/');
        format!("{base}/v1/chat/completions")
    }
}

/// Resolve the Anthropic API URL: if it already ends with /messages, use as-is.
/// Otherwise, append `/v1/messages`.
pub fn resolve_anthropic_url(api_url: &str) -> String {
    if api_url.ends_with("/messages") {
        api_url.to_string()
    } else {
        let base = api_url.trim_end_matches('/');
        format!("{base}/v1/messages")
    }
}

/// Parse an OpenAI-compatible chat completion response.
/// Returns (text, input_tokens, output_tokens).
pub fn parse_cloud_response(json: &serde_json::Value) -> Result<(String, Option<u32>, Option<u32>), String> {
    let content = json
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .ok_or_else(|| {
            let err_msg = json
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("unexpected response format");
            format!("cloud LLM: {err_msg}")
        })?;

    let input_tokens = json
        .get("usage")
        .and_then(|u| u.get("prompt_tokens"))
        .and_then(|t| t.as_u64())
        .map(|t| t as u32);

    let output_tokens = json
        .get("usage")
        .and_then(|u| u.get("completion_tokens"))
        .and_then(|t| t.as_u64())
        .map(|t| t as u32);

    Ok((content.to_string(), input_tokens, output_tokens))
}

/// Parse an Anthropic Messages API response.
/// Returns (text, input_tokens, output_tokens).
pub fn parse_anthropic_response(json: &serde_json::Value) -> Result<(String, Option<u32>, Option<u32>), String> {
    let content = json
        .get("content")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("text"))
        .and_then(|t| t.as_str())
        .ok_or_else(|| {
            let err_msg = json
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("unexpected response format");
            format!("Anthropic API: {err_msg}")
        })?;

    let input_tokens = json
        .get("usage")
        .and_then(|u| u.get("input_tokens"))
        .and_then(|t| t.as_u64())
        .map(|t| t as u32);

    let output_tokens = json
        .get("usage")
        .and_then(|u| u.get("output_tokens"))
        .and_then(|t| t.as_u64())
        .map(|t| t as u32);

    Ok((content.to_string(), input_tokens, output_tokens))
}

// ── Local LLM backend (Ollama) ───────────────────────────────────────────────

/// Send a prompt to an Ollama API endpoint.
fn reason_local(
    backend: &ReasoningBackend,
    prompt: &str,
    timeout_secs: u64,
) -> Result<(String, Option<u32>, Option<u32>), String> {
    let ReasoningBackend::LocalLLM { url, model } = backend else {
        return Err("reason_local called with non-local backend".to_string());
    };

    let api_url = format!("{}/api/generate", url.trim_end_matches('/'));

    let body = serde_json::json!({
        "model": model,
        "prompt": prompt,
        "stream": false
    });

    // Egress contract (audit-06 F-1): proxied-or-refuses. A configured but
    // malformed TALLOW_PROXY hard-refuses here instead of egressing direct.
    let agent = crate::runtime::egress_http::agent_with_timeouts(
        Some(Duration::from_secs(timeout_secs)),
        None,
    );

    let resp = agent
        .post(&api_url)
        .header("Content-Type", "application/json")
        .send_json(&body)
        .map_err(|e| format!("local LLM request failed (is Ollama running?): {e}"))?;

    let body_str = resp
        .into_body()
        .read_to_string()
        .map_err(|e| format!("local LLM response read failed: {e}"))?;

    let json: serde_json::Value =
        serde_json::from_str(&body_str).map_err(|e| format!("local LLM response parse failed: {e}"))?;

    parse_local_response(&json)
}

/// Parse an Ollama generate response.
/// Returns (text, input_tokens, output_tokens).
pub fn parse_local_response(json: &serde_json::Value) -> Result<(String, Option<u32>, Option<u32>), String> {
    let response = json
        .get("response")
        .and_then(|r| r.as_str())
        .ok_or_else(|| {
            let err_msg = json
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("unexpected response format");
            format!("local LLM: {err_msg}")
        })?;

    let input_tokens = json
        .get("prompt_eval_count")
        .and_then(|t| t.as_u64())
        .map(|t| t as u32);

    let output_tokens = json
        .get("eval_count")
        .and_then(|t| t.as_u64())
        .map(|t| t as u32);

    Ok((response.to_string(), input_tokens, output_tokens))
}

// ── Rule-based backend ───────────────────────────────────────────────────────

/// Evaluate rules against working memory items.
///
/// Rules are sorted by priority (descending). A rule fires when ALL of its
/// conditions match at least one working memory item (key or value, case-insensitive).
fn reason_rules(
    prompt: &str,
    rules: &[Rule],
    working_memory_items: &[(String, String)],
) -> Result<(String, Option<u32>, Option<u32>), String> {
    if rules.is_empty() {
        return Ok((format!("No rules matched for: {prompt}"), None, None));
    }

    // Sort rules by priority descending
    let mut sorted_rules: Vec<&Rule> = rules.iter().collect();
    sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

    // Combine prompt with working memory for matching context
    let mut match_items: Vec<(String, String)> = working_memory_items
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
        .collect();
    // Also match against the prompt itself
    match_items.push(("__prompt".to_string(), prompt.to_lowercase()));

    let mut fired_actions = Vec::new();

    for rule in &sorted_rules {
        let all_match = rule.conditions.iter().all(|condition| {
            let cond_lower = condition.to_lowercase();
            match_items
                .iter()
                .any(|(k, v)| k.contains(&cond_lower) || v.contains(&cond_lower))
        });

        if all_match {
            fired_actions.push(rule.action.clone());
        }
    }

    if fired_actions.is_empty() {
        Ok((format!("No rules matched for: {prompt}"), None, None))
    } else {
        Ok((fired_actions.join("; "), None, None))
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── from_config tests ─────────────────────────────────────────────────

    #[test]
    fn from_config_cloud_llm() {
        let backend =
            ReasoningBackend::from_config("cloud_llm", "gpt-4", "sk-test", "https://api.openai.com/v1/chat/completions", "");
        match backend {
            ReasoningBackend::CloudLLM {
                api_url,
                api_key,
                model,
            } => {
                assert_eq!(api_url, "https://api.openai.com/v1/chat/completions");
                assert_eq!(api_key, "sk-test");
                assert_eq!(model, "gpt-4");
            }
            _ => panic!("expected CloudLLM"),
        }
    }

    #[test]
    fn from_config_cloud_llm_default_url() {
        let backend = ReasoningBackend::from_config("cloud_llm", "gpt-4o", "key", "", "");
        match backend {
            ReasoningBackend::CloudLLM { api_url, .. } => {
                assert_eq!(api_url, "https://api.openai.com/v1/chat/completions");
            }
            _ => panic!("expected CloudLLM"),
        }
    }

    #[test]
    fn from_config_local_llm() {
        let backend = ReasoningBackend::from_config("local_llm", "llama3.2", "", "", "http://localhost:11434");
        match backend {
            ReasoningBackend::LocalLLM { url, model } => {
                assert_eq!(url, "http://localhost:11434");
                assert_eq!(model, "llama3.2");
            }
            _ => panic!("expected LocalLLM"),
        }
    }

    #[test]
    fn from_config_local_llm_default_url() {
        let backend = ReasoningBackend::from_config("local_llm", "mistral", "", "", "");
        match backend {
            ReasoningBackend::LocalLLM { url, .. } => {
                assert_eq!(url, "http://localhost:11434");
            }
            _ => panic!("expected LocalLLM"),
        }
    }

    #[test]
    fn from_config_rule_engine() {
        let backend = ReasoningBackend::from_config("rule_engine", "", "", "", "");
        assert!(matches!(backend, ReasoningBackend::RuleEngine { .. }));
    }

    #[test]
    fn from_config_unknown_defaults_to_rule_engine() {
        let backend = ReasoningBackend::from_config("unknown_thing", "", "", "", "");
        assert!(matches!(backend, ReasoningBackend::RuleEngine { .. }));
    }

    // ── Backend name tests ────────────────────────────────────────────────

    #[test]
    fn backend_name_cloud() {
        let b = ReasoningBackend::CloudLLM {
            api_url: String::new(),
            api_key: String::new(),
            model: String::new(),
        };
        assert_eq!(b.name(), "cloud_llm");
    }

    #[test]
    fn backend_name_local() {
        let b = ReasoningBackend::LocalLLM {
            url: String::new(),
            model: String::new(),
        };
        assert_eq!(b.name(), "local_llm");
    }

    #[test]
    fn backend_name_rule() {
        let b = ReasoningBackend::RuleEngine { rules: Vec::new() };
        assert_eq!(b.name(), "rule_engine");
    }

    // ── Cloud URL resolution tests ────────────────────────────────────────

    #[test]
    fn resolve_cloud_url_already_has_completions() {
        let url = resolve_cloud_url("https://api.openai.com/v1/chat/completions");
        assert_eq!(url, "https://api.openai.com/v1/chat/completions");
    }

    #[test]
    fn resolve_cloud_url_base_only() {
        let url = resolve_cloud_url("https://api.openai.com");
        assert_eq!(url, "https://api.openai.com/v1/chat/completions");
    }

    #[test]
    fn resolve_cloud_url_trailing_slash() {
        let url = resolve_cloud_url("https://api.custom.com/");
        assert_eq!(url, "https://api.custom.com/v1/chat/completions");
    }

    // ── Cloud response parsing tests ──────────────────────────────────────

    #[test]
    fn parse_cloud_response_valid() {
        let json = serde_json::json!({
            "choices": [{
                "message": {
                    "content": "The answer is 42."
                }
            }],
            "usage": {
                "prompt_tokens": 50,
                "completion_tokens": 100,
                "total_tokens": 150
            }
        });
        let (content, inp, out) = parse_cloud_response(&json).unwrap();
        assert_eq!(content, "The answer is 42.");
        assert_eq!(inp, Some(50));
        assert_eq!(out, Some(100));
    }

    #[test]
    fn parse_cloud_response_no_usage() {
        let json = serde_json::json!({
            "choices": [{
                "message": {
                    "content": "hello"
                }
            }]
        });
        let (content, inp, out) = parse_cloud_response(&json).unwrap();
        assert_eq!(content, "hello");
        assert_eq!(inp, None);
        assert_eq!(out, None);
    }

    #[test]
    fn parse_cloud_response_error() {
        let json = serde_json::json!({
            "error": {
                "message": "invalid API key"
            }
        });
        let err = parse_cloud_response(&json).unwrap_err();
        assert!(err.contains("invalid API key"), "got: {err}");
    }

    #[test]
    fn parse_cloud_response_empty() {
        let json = serde_json::json!({});
        let err = parse_cloud_response(&json).unwrap_err();
        assert!(err.contains("unexpected response format"), "got: {err}");
    }

    // ── Anthropic response parsing tests ──────────────────────────────────

    #[test]
    fn parse_anthropic_response_valid() {
        let json = serde_json::json!({
            "content": [{
                "type": "text",
                "text": "Hello from Claude."
            }],
            "usage": {
                "input_tokens": 25,
                "output_tokens": 42
            }
        });
        let (text, inp, out) = parse_anthropic_response(&json).unwrap();
        assert_eq!(text, "Hello from Claude.");
        assert_eq!(inp, Some(25));
        assert_eq!(out, Some(42));
    }

    #[test]
    fn parse_anthropic_response_no_usage() {
        let json = serde_json::json!({
            "content": [{
                "type": "text",
                "text": "answer"
            }]
        });
        let (text, inp, out) = parse_anthropic_response(&json).unwrap();
        assert_eq!(text, "answer");
        assert_eq!(inp, None);
        assert_eq!(out, None);
    }

    #[test]
    fn parse_anthropic_response_error() {
        let json = serde_json::json!({
            "error": {
                "message": "invalid x-api-key"
            }
        });
        let err = parse_anthropic_response(&json).unwrap_err();
        assert!(err.contains("invalid x-api-key"), "got: {err}");
    }

    // ── Local response parsing tests ──────────────────────────────────────

    #[test]
    fn parse_local_response_valid() {
        let json = serde_json::json!({
            "response": "Local model says hello!"
        });
        let (content, inp, out) = parse_local_response(&json).unwrap();
        assert_eq!(content, "Local model says hello!");
        assert_eq!(inp, None);
        assert_eq!(out, None);
    }

    #[test]
    fn parse_local_response_with_tokens() {
        let json = serde_json::json!({
            "response": "Local answer",
            "prompt_eval_count": 30,
            "eval_count": 55
        });
        let (content, inp, out) = parse_local_response(&json).unwrap();
        assert_eq!(content, "Local answer");
        assert_eq!(inp, Some(30));
        assert_eq!(out, Some(55));
    }

    #[test]
    fn parse_local_response_error() {
        let json = serde_json::json!({
            "error": "model not found"
        });
        let err = parse_local_response(&json).unwrap_err();
        assert!(err.contains("model not found"), "got: {err}");
    }

    #[test]
    fn parse_local_response_empty() {
        let json = serde_json::json!({});
        let err = parse_local_response(&json).unwrap_err();
        assert!(err.contains("unexpected response format"), "got: {err}");
    }

    // ── Route inference tests ─────────────────────────────────────────────

    #[test]
    fn route_inference_secret_cloud_rejected() {
        let backend = ReasoningBackend::CloudLLM {
            api_url: "https://api.openai.com".to_string(),
            api_key: "sk-test".to_string(),
            model: "gpt-4".to_string(),
        };
        let result = route_inference(&DataSensitivity::Secret, &LlmPolicy::AllowCloud, &backend);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("secret data requires local inference"));
    }

    #[test]
    fn route_inference_secret_local_ok() {
        let backend = ReasoningBackend::LocalLLM {
            url: "http://localhost:11434".to_string(),
            model: "llama3".to_string(),
        };
        assert!(route_inference(&DataSensitivity::Secret, &LlmPolicy::AllowCloud, &backend).is_ok());
    }

    #[test]
    fn route_inference_secret_rule_engine_ok() {
        let backend = ReasoningBackend::RuleEngine { rules: vec![] };
        assert!(route_inference(&DataSensitivity::Secret, &LlmPolicy::AllowCloud, &backend).is_ok());
    }

    #[test]
    fn route_inference_public_cloud_ok() {
        let backend = ReasoningBackend::CloudLLM {
            api_url: "https://api.openai.com".to_string(),
            api_key: "sk-test".to_string(),
            model: "gpt-4".to_string(),
        };
        assert!(route_inference(&DataSensitivity::Public, &LlmPolicy::AllowCloud, &backend).is_ok());
    }

    #[test]
    fn route_inference_private_redact_private_cloud_ok() {
        let backend = ReasoningBackend::CloudLLM {
            api_url: "https://api.openai.com".to_string(),
            api_key: "sk-test".to_string(),
            model: "gpt-4".to_string(),
        };
        assert!(route_inference(&DataSensitivity::Private, &LlmPolicy::RedactPrivate, &backend).is_ok());
    }

    #[test]
    fn route_inference_private_local_only_cloud_rejected() {
        let backend = ReasoningBackend::CloudLLM {
            api_url: "https://api.openai.com".to_string(),
            api_key: "sk-test".to_string(),
            model: "gpt-4".to_string(),
        };
        let result = route_inference(&DataSensitivity::Private, &LlmPolicy::LocalOnly, &backend);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("local_only requires local inference"));
    }

    #[test]
    fn route_inference_private_local_only_local_ok() {
        let backend = ReasoningBackend::LocalLLM {
            url: "http://localhost:11434".to_string(),
            model: "llama3".to_string(),
        };
        assert!(route_inference(&DataSensitivity::Private, &LlmPolicy::LocalOnly, &backend).is_ok());
    }

    // ── Cloud provider detection tests ────────────────────────────────────

    #[test]
    fn detect_anthropic_from_url() {
        assert_eq!(detect_provider("https://api.anthropic.com/v1/messages"), CloudProvider::Anthropic);
        assert_eq!(detect_provider("https://claude.example.com/api"), CloudProvider::Anthropic);
    }

    #[test]
    fn detect_openai_from_url() {
        assert_eq!(detect_provider("https://api.openai.com/v1/chat/completions"), CloudProvider::OpenAI);
        assert_eq!(detect_provider("https://custom-llm.example.com"), CloudProvider::OpenAI);
    }

    // ── Anthropic URL resolution tests ────────────────────────────────────

    #[test]
    fn resolve_anthropic_url_already_has_messages() {
        let url = resolve_anthropic_url("https://api.anthropic.com/v1/messages");
        assert_eq!(url, "https://api.anthropic.com/v1/messages");
    }

    #[test]
    fn resolve_anthropic_url_base_only() {
        let url = resolve_anthropic_url("https://api.anthropic.com");
        assert_eq!(url, "https://api.anthropic.com/v1/messages");
    }

    // ── LlmPolicy parsing tests ──────────────────────────────────────────

    #[test]
    fn llm_policy_from_str_all_values() {
        assert_eq!(LlmPolicy::from_str("local_only"), Some(LlmPolicy::LocalOnly));
        assert_eq!(LlmPolicy::from_str("redact_private"), Some(LlmPolicy::RedactPrivate));
        assert_eq!(LlmPolicy::from_str("tee_required"), Some(LlmPolicy::TeeRequired));
        assert_eq!(LlmPolicy::from_str("allow_cloud"), Some(LlmPolicy::AllowCloud));
        assert_eq!(LlmPolicy::from_str("invalid"), None);
    }

    // ── Rule engine tests ─────────────────────────────────────────────────

    #[test]
    fn rule_engine_no_rules() {
        let result = reason_rules("test prompt", &[], &[]);
        let (resp, _, _) = result.unwrap();
        assert!(resp.contains("No rules matched"), "got: {resp}");
    }

    #[test]
    fn rule_engine_single_condition_match() {
        let rules = vec![Rule {
            name: "price_alert".to_string(),
            conditions: vec!["price".to_string()],
            action: "check pricing".to_string(),
            priority: 1,
        }];
        let wm = vec![("price".to_string(), "100".to_string())];
        let (resp, _, _) = reason_rules("what?", &rules, &wm).unwrap();
        assert_eq!(resp, "check pricing");
    }

    #[test]
    fn rule_engine_multiple_conditions_all_must_match() {
        let rules = vec![Rule {
            name: "high_price_alert".to_string(),
            conditions: vec!["price".to_string(), "high".to_string()],
            action: "negotiate".to_string(),
            priority: 1,
        }];

        // Only "price" in WM, not "high" -> should not match
        let wm_partial = vec![("price".to_string(), "100".to_string())];
        let (resp, _, _) = reason_rules("query", &rules, &wm_partial).unwrap();
        assert!(resp.contains("No rules matched"), "got: {resp}");

        // Both present -> should match
        let wm_full = vec![
            ("price".to_string(), "100".to_string()),
            ("level".to_string(), "high".to_string()),
        ];
        let (resp, _, _) = reason_rules("query", &rules, &wm_full).unwrap();
        assert_eq!(resp, "negotiate");
    }

    #[test]
    fn rule_engine_case_insensitive() {
        let rules = vec![Rule {
            name: "test".to_string(),
            conditions: vec!["URGENT".to_string()],
            action: "handle urgently".to_string(),
            priority: 1,
        }];
        let wm = vec![("status".to_string(), "urgent task".to_string())];
        let (resp, _, _) = reason_rules("check", &rules, &wm).unwrap();
        assert_eq!(resp, "handle urgently");
    }

    #[test]
    fn rule_engine_priority_ordering() {
        let rules = vec![
            Rule {
                name: "low".to_string(),
                conditions: vec!["task".to_string()],
                action: "low priority action".to_string(),
                priority: 1,
            },
            Rule {
                name: "high".to_string(),
                conditions: vec!["task".to_string()],
                action: "high priority action".to_string(),
                priority: 10,
            },
            Rule {
                name: "mid".to_string(),
                conditions: vec!["task".to_string()],
                action: "mid priority action".to_string(),
                priority: 5,
            },
        ];
        let wm = vec![("task".to_string(), "something".to_string())];
        let (resp, _, _) = reason_rules("go", &rules, &wm).unwrap();
        // Highest priority first
        assert!(resp.starts_with("high priority action"), "got: {resp}");
        assert!(resp.contains("mid priority action"));
        assert!(resp.ends_with("low priority action"), "got: {resp}");
    }

    #[test]
    fn rule_engine_multiple_rules_joined() {
        let rules = vec![
            Rule {
                name: "r1".to_string(),
                conditions: vec!["alpha".to_string()],
                action: "action_a".to_string(),
                priority: 2,
            },
            Rule {
                name: "r2".to_string(),
                conditions: vec!["beta".to_string()],
                action: "action_b".to_string(),
                priority: 1,
            },
        ];
        let wm = vec![
            ("alpha".to_string(), "yes".to_string()),
            ("beta".to_string(), "yes".to_string()),
        ];
        let (resp, _, _) = reason_rules("go", &rules, &wm).unwrap();
        assert_eq!(resp, "action_a; action_b");
    }

    #[test]
    fn rule_engine_condition_matches_key_or_value() {
        let rules = vec![Rule {
            name: "test".to_string(),
            conditions: vec!["temperature".to_string()],
            action: "adjust cooling".to_string(),
            priority: 1,
        }];

        // Condition matches the KEY
        let wm_key = vec![("temperature".to_string(), "72".to_string())];
        let (resp, _, _) = reason_rules("check", &rules, &wm_key).unwrap();
        assert_eq!(resp, "adjust cooling");

        // Condition matches the VALUE
        let wm_val = vec![("sensor".to_string(), "temperature_high".to_string())];
        let (resp, _, _) = reason_rules("check", &rules, &wm_val).unwrap();
        assert_eq!(resp, "adjust cooling");
    }

    // ── ReasoningResult construction test ──────────────────────────────────

    #[test]
    fn reasoning_result_construction() {
        let result = ReasoningResult {
            response: "test response".to_string(),
            duration_ms: 42,
            backend_name: "rule_engine".to_string(),
            tokens_used: Some(100),
            input_tokens: Some(40),
            output_tokens: Some(60),
            success: true,
        };
        assert_eq!(result.response, "test response");
        assert_eq!(result.duration_ms, 42);
        assert_eq!(result.backend_name, "rule_engine");
        assert_eq!(result.tokens_used, Some(100));
        assert_eq!(result.input_tokens, Some(40));
        assert_eq!(result.output_tokens, Some(60));
        assert!(result.success);
    }

    // ── reason_with_backend integration test (rule engine only, no network) ──

    #[test]
    fn reason_with_backend_rule_engine() {
        let backend = ReasoningBackend::RuleEngine {
            rules: vec![Rule {
                name: "greet".to_string(),
                conditions: vec!["hello".to_string()],
                action: "wave back".to_string(),
                priority: 1,
            }],
        };
        let wm = vec![("greeting".to_string(), "hello world".to_string())];
        let result = reason_with_backend(&backend, "respond", &wm, 30);
        assert!(result.success);
        assert_eq!(result.response, "wave back");
        assert_eq!(result.backend_name, "rule_engine");
        assert!(result.duration_ms < 1000); // should be nearly instant
    }

    #[test]
    fn reason_with_backend_rule_engine_no_match() {
        let backend = ReasoningBackend::RuleEngine { rules: Vec::new() };
        let result = reason_with_backend(&backend, "test prompt", &[], 30);
        assert!(result.success);
        assert!(result.response.contains("No rules matched"), "got: {}", result.response);
    }

    // ── ReasoningStep chain cap test ──────────────────────────────────────

    #[test]
    fn reasoning_chain_cap_at_1000() {
        use crate::agent_memory::{Brain, BrainConfig, ReasoningStep};

        let mut brain = Brain::new(BrainConfig {
            working_capacity: 5,
            persistence_path: ":memory:".to_string(),
            ..BrainConfig::default()
        })
        .unwrap();

        for i in 0..1050 {
            brain.record_reasoning_step(ReasoningStep {
                step_number: i,
                backend: "test".to_string(),
                prompt: format!("prompt {i}"),
                response: format!("response {i}"),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                duration_ms: 1,
                tokens_used: None,
            });
        }

        assert_eq!(brain.reasoning_chain.len(), 1000);
        // Oldest entries should have been dropped
        assert_eq!(brain.reasoning_chain[0].step_number, 50);
    }

    // ── Model tier selection tests ────────────────────────────────────────

    #[test]
    fn select_model_tier_strong_on_high_uncertainty() {
        assert_eq!(select_model_tier(100, 5, 0.9), ModelTier::Strong);
    }

    #[test]
    fn select_model_tier_strong_on_long_prompt() {
        assert_eq!(select_model_tier(5000, 5, 0.1), ModelTier::Strong);
    }

    #[test]
    fn select_model_tier_strong_on_large_working_memory() {
        assert_eq!(select_model_tier(100, 64, 0.1), ModelTier::Strong);
    }

    #[test]
    fn select_model_tier_fast_on_easy_step() {
        assert_eq!(select_model_tier(200, 10, 0.1), ModelTier::Fast);
    }

    #[test]
    fn select_model_tier_threshold_boundaries() {
        // Inclusive thresholds should trip to Strong at the exact boundary.
        assert_eq!(select_model_tier(STRONG_PROMPT_LEN_THRESHOLD, 0, 0.0), ModelTier::Strong);
        assert_eq!(select_model_tier(0, STRONG_WORKING_MEM_THRESHOLD, 0.0), ModelTier::Strong);
        assert_eq!(select_model_tier(0, 0, STRONG_UNCERTAINTY_THRESHOLD), ModelTier::Strong);
        // Just below each threshold should stay Fast.
        assert_eq!(select_model_tier(STRONG_PROMPT_LEN_THRESHOLD - 1, 0, 0.0), ModelTier::Fast);
    }

    #[test]
    fn model_for_tier_returns_configured_model_for_both_tiers() {
        let backend = ReasoningBackend::CloudLLM {
            api_url: "https://api.openai.com".to_string(),
            api_key: "sk-test".to_string(),
            model: "gpt-4".to_string(),
        };
        assert_eq!(backend.model_for_tier(ModelTier::Fast), Some("gpt-4"));
        assert_eq!(backend.model_for_tier(ModelTier::Strong), Some("gpt-4"));

        let local = ReasoningBackend::LocalLLM {
            url: "http://localhost:11434".to_string(),
            model: "llama3.2".to_string(),
        };
        assert_eq!(local.model_for_tier(ModelTier::Fast), Some("llama3.2"));

        let rule = ReasoningBackend::RuleEngine { rules: vec![] };
        assert_eq!(rule.model_for_tier(ModelTier::Strong), None);
    }

    #[test]
    fn model_tier_structs_hold_two_models() {
        let cloud = CloudTier {
            fast: "gpt-4o-mini".to_string(),
            strong: "gpt-4".to_string(),
        };
        assert_eq!(cloud.fast, "gpt-4o-mini");
        assert_eq!(cloud.strong, "gpt-4");

        let local = LocalTier {
            fast: "llama3.2:3b".to_string(),
            strong: "llama3.2:70b".to_string(),
        };
        assert_eq!(local.fast, "llama3.2:3b");
        assert_eq!(local.strong, "llama3.2:70b");
    }

    // ── Few-shot prior-outcomes prompt tests ──────────────────────────────

    #[test]
    fn build_prompt_with_history_includes_failure_snippet() {
        let prompt = build_prompt_with_history(
            "Solve the puzzle.",
            &[(false, "tried brute force, timed out".to_string())],
        );
        assert!(prompt.contains("Solve the puzzle."));
        assert!(prompt.contains("Past attempts:"));
        assert!(prompt.contains("- FAILURE: tried brute force, timed out"));
    }

    #[test]
    fn build_prompt_with_history_marks_success() {
        let prompt = build_prompt_with_history(
            "Go.",
            &[(true, "found answer via backtracking".to_string())],
        );
        assert!(prompt.contains("- SUCCESS: found answer via backtracking"));
    }

    #[test]
    fn build_prompt_with_history_empty_returns_base() {
        let prompt = build_prompt_with_history("Just the base.", &[]);
        assert_eq!(prompt, "Just the base.");
    }

    #[test]
    fn build_prompt_with_history_collapses_multiline_snippet() {
        let prompt = build_prompt_with_history(
            "Q",
            &[(false, "line one\nline two".to_string())],
        );
        // Each past attempt stays on one line; no embedded newline after the marker.
        assert!(prompt.contains("- FAILURE: line one line two"));
    }

    #[test]
    fn build_prompt_with_history_caps_long_snippet() {
        let long_snippet = "x".repeat(500);
        let prompt = build_prompt_with_history("Q", &[(false, long_snippet.clone())]);
        // Capped + ellipsis, not the full 500-char blob.
        assert!(prompt.contains("..."));
        assert!(!prompt.contains(&long_snippet));
    }

    // ── Retry / backoff tests ─────────────────────────────────────────────

    #[test]
    fn with_retry_succeeds_on_second_attempt() {
        use std::cell::Cell;
        let calls = Cell::new(0);
        let result = with_retry(3, 0, || {
            calls.set(calls.get() + 1);
            if calls.get() < 2 {
                Err("transient".to_string())
            } else {
                Ok("ok".to_string())
            }
        });
        assert_eq!(result, Ok("ok".to_string()));
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn with_retry_exhausts_and_returns_last_error() {
        use std::cell::Cell;
        let calls = Cell::new(0);
        let result = with_retry(3, 0, || -> Result<(), String> {
            calls.set(calls.get() + 1);
            Err(format!("failure {}", calls.get()))
        });
        assert_eq!(result, Err("failure 3".to_string()));
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn with_retry_backoff_caps_attempts() {
        use std::cell::Cell;
        let calls = Cell::new(0);
        // attempts = 1 -> no retries, single call only.
        let result = with_retry(1, 0, || -> Result<(), String> {
            calls.set(calls.get() + 1);
            Err("always".to_string())
        });
        assert_eq!(result, Err("always".to_string()));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn with_retry_attempts_zero_still_runs_once() {
        use std::cell::Cell;
        let calls = Cell::new(0);
        let result = with_retry(0, 0, || -> Result<(), String> {
            calls.set(calls.get() + 1);
            Err("forced".to_string())
        });
        assert_eq!(result, Err("forced".to_string()));
        assert_eq!(calls.get(), 1);
    }

    // ── 2.4 reducer / consensus tests ─────────────────────────────────────

    #[test]
    fn reduce_consensus_picks_modal_candidate() {
        let candidates = vec![
            "a".to_string(),
            "b".to_string(),
            "a".to_string(),
            "c".to_string(),
            "a".to_string(),
        ];
        assert_eq!(reduce_consensus(&candidates), Some("a".to_string()));
    }

    #[test]
    fn reduce_consensus_empty_returns_none() {
        assert_eq!(reduce_consensus(&[]), None);
    }

    #[test]
    fn reason_with_consensus_rule_engine_returns_consensus() {
        let rules = vec![Rule {
            name: "answer".to_string(),
            conditions: vec!["key".to_string()],
            action: "consensus-answer".to_string(),
            priority: 1,
        }];
        let backend = ReasoningBackend::RuleEngine { rules };
        let wm = vec![("key".to_string(), "value".to_string())];
        let result = reason_with_consensus(&backend, "what?", &wm, 5, 3);
        assert!(result.success, "expected success");
        assert_eq!(result.response, "consensus-answer");
        assert!(
            result.backend_name.ends_with("_consensus"),
            "backend_name should be suffixed: {}",
            result.backend_name
        );
    }

    // ── 1.8 rules short-circuit tests ─────────────────────────────────────

    #[test]
    fn rules_short_circuit_returns_highest_priority_action() {
        let rules = vec![
            Rule {
                name: "low".to_string(),
                conditions: vec!["price".to_string()],
                action: "low-action".to_string(),
                priority: 1,
            },
            Rule {
                name: "high".to_string(),
                conditions: vec!["price".to_string()],
                action: "high-action".to_string(),
                priority: 5,
            },
        ];
        let wm = vec![("price".to_string(), "100".to_string())];
        assert_eq!(
            rules_short_circuit(&rules, "what?", &wm),
            Some("high-action".to_string())
        );
    }

    #[test]
    fn rules_short_circuit_none_when_no_match() {
        let rules = vec![Rule {
            name: "r".to_string(),
            conditions: vec!["missing".to_string()],
            action: "x".to_string(),
            priority: 1,
        }];
        let wm = vec![("price".to_string(), "100".to_string())];
        assert_eq!(rules_short_circuit(&rules, "what?", &wm), None);
        assert_eq!(rules_short_circuit(&[], "what?", &wm), None);
    }

    #[test]
    fn reason_short_circuit_first_bypasses_backend_on_match() {
        // Backend has NO matching rule (would answer "No rules matched"); the
        // rules store DOES match, so it must short-circuit before the backend.
        let backend = ReasoningBackend::RuleEngine {
            rules: vec![Rule {
                name: "other".to_string(),
                conditions: vec!["nope".to_string()],
                action: "backend-action".to_string(),
                priority: 1,
            }],
        };
        let store = vec![Rule {
            name: "fire".to_string(),
            conditions: vec!["price".to_string()],
            action: "short-circuit-action".to_string(),
            priority: 1,
        }];
        let wm = vec![("price".to_string(), "100".to_string())];
        let result = reason_short_circuit_first(&backend, &store, "what?", &wm, 5);
        assert!(result.success);
        assert_eq!(result.response, "short-circuit-action");
        assert_eq!(result.backend_name, "rule_short_circuit");
    }

    #[test]
    fn retry_defaults_are_sane() {
        assert_eq!(DEFAULT_RETRY_ATTEMPTS, 3);
        assert_eq!(DEFAULT_BACKOFF_BASE_MS, 250);
    }

    // ── Best-of-N sampling tests ──────────────────────────────────────────

    #[test]
    fn best_of_n_runs_all_samples_and_applies_pick() {
        // sample returns its own index; pick selects the max value.
        let picked = best_of_n(5, |i| i, |items| items.iter().copied().max().unwrap());
        assert_eq!(picked, 4);
    }

    #[test]
    fn best_of_n_zero_samples_uses_pick_on_empty() {
        let picked = best_of_n(0, |i| i, |items| items.len());
        assert_eq!(picked, 0);
    }

    #[test]
    fn best_of_n_majority_consensus() {
        let picks: Vec<&str> = vec!["a", "a", "b", "a", "b"];
        let picked = best_of_n(picks.len(), |i| picks[i], |items| majority_pick(items).unwrap());
        assert_eq!(picked, "a");
    }

    // ── Majority pick tests ───────────────────────────────────────────────

    #[test]
    fn majority_pick_returns_modal_element() {
        let items = vec!["apple", "banana", "apple", "cherry", "apple"];
        assert_eq!(majority_pick(&items), Some("apple"));
    }

    #[test]
    fn majority_pick_empty_returns_none() {
        let items: Vec<&str> = vec![];
        assert_eq!(majority_pick(&items), None);
    }

    #[test]
    fn majority_pick_single_item() {
        let items = vec![42u32];
        assert_eq!(majority_pick(&items), Some(42));
    }
}
