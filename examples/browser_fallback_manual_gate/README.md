# browser_fallback_manual_gate

Release-quality example for the current safe browser-fallback boundary. It is a
manual/preflight gate example: `browser_fallback.mode=reasoned` is recognized and
then fails closed before any request is executed.

## Command

The fixture server is optional for this example because the runner blocks before
fetching, but start it to keep the command shape consistent with the other examples.

Terminal 1:

```bash
python3 examples/fixtures/mock_server.py --port 18080
```

Terminal 2:

```bash
rm -rf /tmp/tallow-examples/browser-gate
set +e
python3 -B scripts/run_tallow_request_plan.py \
  --plan examples/browser_fallback_manual_gate/request-plan.v1.json \
  --report-path /tmp/tallow-examples/browser-gate/execution_report.json \
  --output-dir /tmp/tallow-examples/browser-gate \
  --mock-base-url http://127.0.0.1:18080 \
  --timeout-seconds 5
echo "exit_code=$?"
set -e
python3 - <<'PY'
import json
r = json.load(open('/tmp/tallow-examples/browser-gate/execution_report.json'))
print({k: r['summary'][k] for k in ('planned', 'executed', 'succeeded', 'failed', 'blocked', 'unsupported')})
print(r['unsupported'][0]['code'])
PY
```

## Expected output

```text
request plan refused: unsupported runtime fields
- fixture_manual_browser_gate: browser_fallback.mode: reasoned browser fallback is recognized but fail-closed until WebSocket CDP execution, artifact capture, budget, and challenge-classification proofs are implemented
exit_code=2
{'planned': 1, 'executed': 0, 'succeeded': 0, 'failed': 0, 'blocked': 1, 'unsupported': 1}
live_browser_fallback_not_enabled
```

## Fixtures

- `examples/fixtures/mock_server.py` has a `/challenge` endpoint, but this example should not reach it.
- The report records `non_claims.browser_execution=false` and the fail-closed unsupported reason.

## Non-claims

- No browser execution.
- No stealth, CAPTCHA solving, or challenge bypass.
- No screenshot, HAR, or DOM capture.
- No public internet access.
- No secrets or vault resolution.
- No live/external scraping or production compliance gate claim.
