# Tallow Target Config Templates

This folder provides JSON config templates for managing target URL lists and request behavior for current Tallow parallel scraper scripts.

Current script mapping:

- `targets` -> `target_urls`
- `headers` -> `headers`
- `retry.wave_concurrency[0..2]` -> `l1_concurrency`, `l2_concurrency`, `l3_concurrency`
- `retry.max_attempts` -> total waves you run
- `policy` -> pre-launch governance checked by `scripts/policy_manifest_validate.ps1`

These templates are designed to be practical for:

- `scripts/tallow_max_scraper_graphql_json_parallel.tl`
- `scripts/tallow_max_scraper_graphql_json_parallel_v2.tl`
- `scripts/tallow_max_stealth_parallel_graphql_json_scraper.tl`

## Files

- `targets.schema.json`: JSON Schema for validation.
- `targets.example.json`: practical starter config.

## Field Reference

| Field | Type | Required | Notes |
|---|---|---|---|
| `targets` | `string[]` (URLs) | Yes | Absolute `http`/`https` URLs to scrape. |
| `headers` | `object<string,string>` | No | Shared headers sent with each request. |
| `auth` | `object` | No | Optional auth profile (`none`, `bearer`, `basic`, `api_key`, `custom_headers`). |
| `retry` | `object` | No | Retry policy and per-wave concurrency settings. |
| `per_domain` | `object` | No | Hostname-keyed overrides for headers/auth/retry and extra targets. |
| `policy` | `object` | No | Governed-run policy for allowlist/denylist, robots mode, and rate limits. Required by `policy_manifest_validate.ps1`. |

### `auth` modes

- `none`: No auth.
- `bearer`: Requires `bearer_token`.
- `basic`: Requires `username` and `password`.
- `api_key`: Requires `api_key_name` and `api_key_value`.
- `custom_headers`: Requires `headers`.

### `retry` keys

- `max_attempts` (integer): total attempts/waves, usually `3`.
- `wave_concurrency` (integer array): parallelism per wave, for example `[200, 80, 30]`.
- `retry_on_status` (integer array): HTTP status codes that should retry.
- `retry_on_transport_errors` (boolean): retry timeout/connection errors.
- `backoff_ms` (integer array): delays between waves in milliseconds.

### `policy` keys

- `allowlist`: required by the policy validator. Include at least one `domains` or `url_patterns` selector.
- `denylist`: required by the policy validator. Can be empty, but denied selectors always override allowlisted selectors.
- `robots.mode`: one of `strict`, `advisory`, or `off`.
- `rate_limits.per_domain`: hostname-keyed or `default` request budget. Each target host must match a configured key.
- `rate_limits.per_ip_pool`: IP-pool keyed request budget. Use `default` when pool-specific routing is not configured yet.

Rate limit entries support:

- `requests_per_second` or `requests_per_minute`
- `burst`
- `concurrent`
- `cooldown_ms`

## Minimal Example

```json
{
  "targets": [
    "https://app.apollo.io/graphql",
    "https://api.apollo.io/graphql"
  ]
}
```

## Advanced Example

```json
{
  "targets": [
    "https://app.apollo.io/graphql",
    "https://app.apollo.io/api/graphql",
    "https://api.apollo.io/graphql"
  ],
  "headers": {
    "Accept": "application/json, text/plain, */*",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Referer": "https://app.apollo.io/"
  },
  "auth": {
    "mode": "bearer",
    "bearer_token": "${APOLLO_BEARER_TOKEN}"
  },
  "retry": {
    "max_attempts": 3,
    "wave_concurrency": [200, 80, 30],
    "retry_on_status": [408, 429, 500, 502, 503, 504],
    "retry_on_transport_errors": true,
    "backoff_ms": [250, 1000]
  },
  "per_domain": {
    "app.apollo.io": {
      "headers": {
        "Origin": "https://app.apollo.io"
      },
      "retry": {
        "wave_concurrency": [120, 40, 20]
      }
    },
    "api.apollo.io": {
      "retry": {
        "wave_concurrency": [100, 40, 20]
      },
      "extra_targets": [
        "https://api.apollo.io/status"
      ]
    }
  },
  "policy": {
    "allowlist": {
      "domains": ["apollo.io", "*.apollo.io"],
      "url_patterns": ["https://*.apollo.io/*"]
    },
    "denylist": {
      "url_patterns": [
        "https://*.apollo.io/admin/*",
        "https://*.apollo.io/private/*"
      ]
    },
    "robots": {
      "mode": "advisory"
    },
    "rate_limits": {
      "per_domain": {
        "app.apollo.io": {
          "requests_per_minute": 120,
          "burst": 20,
          "concurrent": 20,
          "cooldown_ms": 250
        },
        "api.apollo.io": {
          "requests_per_minute": 100,
          "burst": 20,
          "concurrent": 16,
          "cooldown_ms": 250
        }
      },
      "per_ip_pool": {
        "default": {
          "requests_per_minute": 500,
          "burst": 80,
          "concurrent": 50,
          "cooldown_ms": 100
        }
      }
    }
  }
}
```

## Validation Example

Use any Draft 2020-12 JSON Schema validator with:

- schema: `configs/tallow/targets.schema.json`
- data: `configs/tallow/targets.example.json`

Run the governed target policy gate with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\policy_manifest_validate.ps1 -ManifestPath configs\tallow\targets.example.json -ReportPath artifacts\policy_validation_report.json
```
