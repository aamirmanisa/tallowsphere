# extraction_schema_html

Release-quality local/mock example for schema-defined HTML extraction rows.

## Command

Terminal 1:

```bash
python3 examples/fixtures/mock_server.py --port 18080
```

Terminal 2:

```bash
rm -rf /tmp/tallow-examples/extraction
python3 -B scripts/run_tallow_request_plan.py \
  --plan examples/extraction_schema_html/request-plan.v1.json \
  --report-path /tmp/tallow-examples/extraction/execution_report.json \
  --output-dir /tmp/tallow-examples/extraction \
  --mock-base-url http://127.0.0.1:18080 \
  --timeout-seconds 5
python3 - <<'PY'
import json
r = json.load(open('/tmp/tallow-examples/extraction/execution_report.json'))
print({k: r['summary'][k] for k in ('planned', 'executed', 'succeeded', 'failed', 'blocked', 'unsupported', 'extraction_rows', 'extraction_quarantined')})
PY
```

## Expected output

```text
request plan execution report written: /tmp/tallow-examples/extraction/execution_report.json
{'planned': 1, 'executed': 1, 'succeeded': 1, 'failed': 0, 'blocked': 0, 'unsupported': 0, 'extraction_rows': 2, 'extraction_quarantined': 0}
```

Rows are written to:

```text
/tmp/tallow-examples/extraction/extraction/rows.jsonl
```

## Fixtures

- `examples/fixtures/mock_server.py` serves deterministic product HTML at `/products`.
- The request plan references `schemas/tallow/examples/product-listing.extraction.schema.json`.

## Non-claims

- No public internet access; all I/O is loopback.
- No browser rendering, screenshot, HAR, or DOM capture.
- No secrets or vault resolution.
- No live/external scraping or production compliance gate claim.
