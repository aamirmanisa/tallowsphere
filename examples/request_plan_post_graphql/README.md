# request_plan_post_graphql

Release-quality request-plan example for local/mock POST GraphQL query execution.

## Command

Terminal 1:

```bash
python3 examples/fixtures/mock_server.py --port 18080
```

Terminal 2:

```bash
rm -rf /tmp/tallow-examples/post-graphql
python3 -B scripts/run_tallow_request_plan.py \
  --plan examples/request_plan_post_graphql/request-plan.v1.json \
  --report-path /tmp/tallow-examples/post-graphql/execution_report.json \
  --output-dir /tmp/tallow-examples/post-graphql \
  --mock-base-url http://127.0.0.1:18080 \
  --timeout-seconds 5
python3 - <<'PY'
import json
r = json.load(open('/tmp/tallow-examples/post-graphql/execution_report.json'))
print({k: r['summary'][k] for k in ('planned', 'executed', 'succeeded', 'failed', 'blocked', 'unsupported')})
print(r['requests'][0]['method'], r['requests'][0]['graphql']['operation_name'])
PY
```

## Expected output

```text
request plan execution report written: /tmp/tallow-examples/post-graphql/execution_report.json
{'planned': 1, 'executed': 1, 'succeeded': 1, 'failed': 0, 'blocked': 0, 'unsupported': 0}
POST Products
```

## Fixtures

- `examples/fixtures/mock_server.py` accepts `POST /graphql` and returns deterministic product data.
- The body uses `kind=json` with inline `body.value.query`; no `query_ref` resolver is used.

## Non-claims

- No public internet access; all I/O is loopback.
- No GraphQL mutations or persisted-query/query-ref resolver support claim.
- No secrets or vault resolution.
- No browser fallback.
- No live/external scraping or production compliance gate claim.
