// tallow.llm — provider-agnostic model access
//
// Credentials never enter the language: a provider names an environment variable
// (`key_env`) or a `key_file`, resolved at call time. An inline key in the config
// is refused by name.
//
// Providers are a registry of *protocols*, not of models: sixteen of the twenty
// listed providers speak one of four wire protocols (OpenAI chat completions,
// Anthropic messages, Google generateContent, Cohere v2), and models are
// discovered from each provider's own `/models` endpoint. Providers with no
// public inference API are listed with `unavailable_reason` rather than omitted.
//
// Configure `~/.config/tallow/llm.toml` (or `$TALLOW_LLM_CONFIG`):
//
//   [providers.deepseek]
//   key_env = "DEEPSEEK_API_KEY"
//
//   [providers.selfhosted]
//   protocol = "openai"
//   base_url = "http://127.0.0.1:8080/v1"
//   key_env  = "LOCAL_LLM_KEY"
//
// A custom entry is a first-class provider: any OpenAI-compatible server works.

/// One entry in the provider registry.
struct ProviderInfo {
    id:                String,
    label:             String,
    /// openai | anthropic | google | azure-openai | cohere | unavailable
    protocol:          String,
    base_url:          String,
    key_env:           String,
    /// registry | configured | custom | unavailable
    status:            String,
    docs:              String,
    /// Non-empty only when status is unavailable.
    unavailable_reason: String,
}

/// One model reported by a provider.
struct ModelInfo {
    id:       String,
    owned_by: String,
}

/// A completion, with the hashes a journal needs.
struct Completion {
    text:         String,
    model:        String,
    provider:     String,
    prompt_hash:  String,
    response_hash: String,
    tokens_in:    i64,
    tokens_out:   i64,
    elapsed_ms:   i64,
}

/// The result of a reachability check.
struct VerifyReport {
    provider:   String,
    ok:         bool,
    models:     i64,
    elapsed_ms: i64,
    detail:     String,
}

/// The registry plus any providers added in the config file.
native fn providers() -> []ProviderInfo

/// Discover the models a provider currently serves. Never cached: a model list
/// that is three months old is a bug report waiting to happen.
native fn models(provider: String) -> []ModelInfo

/// One completion. `max_tokens` defaults to 1024 when omitted or zero.
/// Errors are redacted: a failure never contains the credential.
native fn complete(provider: String, model: String, prompt: String, max_tokens: i64) -> Completion

/// Resolve credentials and list models, reporting latency. This is the check a
/// user runs after entering a key; it does not spend tokens.
native fn verify(provider: String) -> VerifyReport
