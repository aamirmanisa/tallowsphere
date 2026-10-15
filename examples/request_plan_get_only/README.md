# request_plan_get_only

Release-quality request-plan example for local/mock GET-only execution.

## Command

Terminal 1:

```bash
python3 examples/fixtures/mock_server.py --port 18080
```

Terminal 2:

```bash
rm -rf /tmp/tallow-examples/get-only
python3 -B scripts/run_tallow_request_plan.py \
  --plan examples/request_plan_get_only/request-plan.v1.json \
  --report-path /tmp/tallow-examples/get-only/execution_report.json \
  --output-dir /tmp/tallow-examples/get-only \
  --mock-base-url http://127.0.0.1:18080 \
  --timeout-seconds 5
python3 - <<'PY'
import json
r = json.load(open('/tmp/tallow-examples/get-only/execution_report.json'))
print({k: r['summary'][k] for k in ('planned', 'executed', 'succeeded', 'failed', 'blocked', 'unsupported')})
PY
```

## Expected output

```text
request plan execution report written: /tmp/tallow-examples/get-only/execution_report.json
{'planned': 2, 'executed': 2, 'succeeded': 2, 'failed': 0, 'blocked': 0, 'unsupported': 0}
```

## Fixtures

- `examples/fixtures/mock_server.py` serves local JSON for `/status` and `/api/products`.
- `target-manifest.v2.json` documents the public-source-style source policy.
- `request-plan.v1.json` uses external-looking `https://example.invalid/...` URLs that are rewritten to loopback by `--mock-base-url`.

## Non-claims

- No public internet access; all I/O is loopback.
- No secrets, cookies, auth headers, or vault resolution.
- No browser fallback.
- No live/external scraping or production compliance gate claim.
