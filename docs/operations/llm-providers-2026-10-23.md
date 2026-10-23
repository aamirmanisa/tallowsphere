# LLM provider integration

Date: 2026-10-23. Surface: `llm` module, 4 functions (1,126 → 1,130 declarations;
86 → 87 modules).

## What it is

`tallow.llm` connects Tallow programs to a model provider without baking any
provider into the language:

```tallow
struct MeshTask { … }   // unrelated; see the directorate example

@legal(basis: .public_data, purpose: "summarise a public filing", personal_data: false)
fn main() {
    let models = llm.models("deepseek")
    let c = llm.complete("deepseek", models[0].id, "Summarise this filing…", 512)
    print(c.text)
}
```

Four functions:

| Function | What it does |
| --- | --- |
| `llm.providers()` | the registry plus any provider added in config |
| `llm.models(provider)` | the provider's *own* model list, fetched at call time |
| `llm.complete(provider, model, prompt, max_tokens)` | one completion, with hashes |
| `llm.verify(provider)` | resolve credentials + list models; spends no tokens |

## Providers

Twenty listed providers. Sixteen are reachable through four wire protocols; four
are declared `unavailable` with the reason, because a silently missing provider is
harder to diagnose than an honest refusal.

| Protocol | Providers |
| --- | --- |
| `openai` (chat completions) | OpenAI, xAI, DeepSeek, Alibaba DashScope, Mistral, Moonshot, Z.ai, MiniMax, NVIDIA NIM, ByteDance Ark, Tencent Hunyuan, Baidu Qianfan, any self-hosted OpenAI-compatible server |
| `anthropic` (messages) | Anthropic — `x-api-key` + `anthropic-version` |
| `google` (generateContent) | Google DeepMind — `x-goog-api-key` |
| `azure-openai` | Microsoft Azure OpenAI — deployment path + `api-key` |
| `cohere` (v2 chat) | Cohere |
| `unavailable` | Meta (weights only, no general API), Amazon Bedrock (SigV4 not implemented), IBM watsonx (IAM exchange not implemented), Xiaomi (no public API) |

Models are never hardcoded: `llm.models` calls the provider's `/models` endpoint
and parses the response for that protocol. A provider that changes its model line
does not require a Tallow release.

## Configuration

`~/.config/tallow/llm.toml` (or `$TALLOW_LLM_CONFIG`):

```toml
[providers.deepseek]
key_env = "DEEPSEEK_API_KEY"

[providers.openai]
base_url = "https://api.openai.com/v1"   # optional override

[providers.selfhosted]
protocol = "openai"
base_url = "http://127.0.0.1:8080/v1"
key_env  = "LOCAL_LLM_KEY"

[providers.azure]
protocol = "azure-openai"
base_url = "https://my-resource.openai.azure.com/openai"
key_env  = "AZURE_OPENAI_API_KEY"
chat_path = "/deployments/my-deployment/chat/completions?api-version=2024-10-21"
```

`tallow llm init` writes a starter file with mode `0600`. `tallow llm providers`
lists the registry; `tallow llm models <p>` and `tallow llm verify <p>` exercise a
configuration; `tallow llm complete <p> <model> <prompt>` runs one completion.

## Credential handling (the part that matters)

- **No key in the language, in a plan, or on the command line.** A provider names
  an environment variable or a key file. `tallow llm complete` deliberately has no
  `--key` flag: process arguments are world-readable and land in shell history.
- **Inline keys are refused.** `key = "sk-…"` in the config fails with a message
  naming the fix (`key_env`/`key_file`) and never echoes the value.
- **Key files must be `0600`.** A group- or world-readable file is refused rather
  than silently trusted.
- **Errors are redacted.** A 401 reports the status and the provider's message; the
  key never appears in an error, a log, or a `Completion`.
- **No request is sent without a credential.** `verify` fails locally when the
  variable is unset — the test asserts the mock server saw zero requests.

## Egress

Model traffic does **not** use the browsing egress plane. That plane is
deny-by-default and Tor-routed because browsing must not carry the box's identity.
A model call is the opposite: the credential in the header *is* an identity, so Tor
provides no anonymity, breaks providers that block exits, and hides the attribution
the provider's billing depends on. `llm` connects directly unless
`TALLOW_LLM_PROXY` names a proxy explicitly. This is a deliberate exception, and it
is stated here rather than left to be discovered.

## What is verified, and what is not

Verified by `tests/llm_providers.rs` (7 tests) against a local HTTP server that
enforces each protocol's authentication surface:

- OpenAI-style discovery + completion (Bearer), including token counts;
- Anthropic (`x-api-key` + `anthropic-version`) and Google (`x-goog-api-key`)
  request construction and response parsing;
- Azure (deployment path + `api-key`) and a **custom self-hosted** provider;
- a bad key fails without echoing it; a missing key names the variable and sends
  no request;
- the registry lists all twenty providers, four with reasons;
- an inline key in the config is refused, and the key is not echoed.

Not verified, and not claimed: that any specific vendor is reachable from this
machine *today*. That requires the user's own credential — `tallow llm verify
<p>` is the check, and it is a live request.

## Surface accounting

`stdlib/llm.tl` declares 4 functions and 4 structs. The gate moved 86 → 87
modules and 1,126 → 1,130 functions in the same commit, with the reason inline.
`llm` is registered in both interpreter tables (`is_stdlib_module` and the
module-sentinel match) — the omission that made `mesh` unreachable in 1.2.2 is
tested for here by running the module from Tallow, not by reading the registry.
