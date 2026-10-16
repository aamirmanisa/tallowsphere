# Tallow Scraper Troubleshooting Guide

This guide covers common failures seen in high-parallel scraper runs.

## Quick Triage

0. For the active Linux/CachyOS target, verify the Phase 1 substrate before debugging scraper behavior:
   - `./target/debug/tallow doctor`
   - `python3 scripts/phase1_smoke_ladder.py`
   - reports: `artifacts/doctor/tallow_doctor_report.json` and `artifacts/phase1/phase1_smoke_ladder_report.json`
1. Confirm the binary path actually used by the launcher.
2. Confirm the script requires only capabilities supported by that binary.
3. Validate target auth/session state before scaling concurrency.
4. Re-run a single target with debug logs before retrying a full parallel batch.

## Symptom -> Likely Cause -> Fix

| Symptom | Likely cause | Fix |
|---|---|---|
| `runtime error: undefined function: http.batch` | The script depends on a function not compiled into the current binary. | Run with a compatible binary that includes `http.batch`. Pin the binary path in your launcher so runs do not silently switch binaries. |
| `undefined function` warnings for `write_file`, `time`, `json`, or similar | Capability mismatch between script/runtime (older or different build). | Align script and runtime versions. Add a startup capability check that fails fast when required functions are missing. |
| `401 Unauthorized` | Missing/expired token, cookie, or signed header. | Refresh credentials, regenerate tokens, and verify auth headers/cookies are present on each request. |
| `403 Forbidden` | Bot protection/WAF block, missing browser-like headers, or region/IP restrictions. | Use proper header/profile parity, valid session state, and proxy strategy. Browser fallback is not a default production remedy until a later live/human-approved fallback gate proves it for the target. |
| GraphQL endpoint returns `404` | Endpoint path is incorrect, deprecated, or environment-specific. | Re-discover endpoint from live network traffic, update target config, and verify method/content-type match server expectations. |
| Frequent `429 Too Many Requests` | Per-host concurrency is too high; no throttling/backoff; bursty retries. | Add adaptive rate limiting, exponential backoff with jitter, per-host caps, and retry budgets. |
| Read/connect timeouts | Aggressive timeout values, saturated network, overloaded target, or blocked challenge flow. | Separate connect/read timeouts, raise limits moderately, add retry with jitter, and route JS-challenge/browser-fallback cases through the later live/human-approved browser-fallback gate instead of enabling fallback by default. |
| Works with one binary but fails with another | Capability mismatch between binaries (local build vs packaged build). | Standardize on one production binary, version-lock it, and print binary fingerprint/version at run start. |

## Detailed Fix Playbook

### 1) Missing Function Errors

When you see `undefined function: ...`, treat it as a runtime capability issue first, not a target-site issue.

Recommended actions:

1. Print and log the exact binary path used by the launcher.
2. Run a small script that validates required functions before launching large batches.
3. Keep a single pinned runtime in CI and production runners.

### 2) 401/403 Authentication and Access Blocks

`401` usually indicates invalid credentials. `403` usually indicates the request is understood but blocked.

Recommended actions:

1. Validate token freshness and cookie validity.
2. Check request headers against a known-good browser trace.
3. If target is protected, capture the evidence and route it through the Phase 3+ browser-fallback gate. Do not auto-enable live browser fallback in production from this troubleshooting playbook alone.

### 3) 404 GraphQL Endpoints

Do not assume `/graphql` is valid. Many sites use custom paths or gateway routing.

Recommended actions:

1. Discover endpoint from live app traffic.
2. Verify request method (`POST` usually), `content-type`, and host.
3. Externalize endpoint configs per environment/domain.

### 4) Rate Limits and Timeouts Under High Parallelism

High global concurrency without per-host controls causes `429` spikes and timeout storms.

Recommended actions:

1. Enforce per-host concurrency ceilings.
2. Implement token bucket or leaky bucket throttling.
3. Use exponential backoff with jitter and bounded retries.
4. Track timeout and `429` rates per host; auto-reduce concurrency when error budgets are exceeded.

### 5) Binary Capability Mismatch

If one `tallow.exe` succeeds and another fails on the same script, the problem is almost always binary feature parity.

Recommended actions:

1. Pin runtime path in scripts and CI.
2. Log binary version/fingerprint at startup.
3. Maintain a compatibility matrix: script version -> required runtime capabilities.

