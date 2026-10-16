# Browser Fallback Service — Local/Non-Live Phase 4

Status: Phase 4 local planner proof only. This is not production/live browser fallback readiness.

## What exists

Phase 4 adds a deterministic local browser fallback planner under `src/browser/fallback.rs` and exposes non-live status through `browser_fallback_service_status` in `stdlib/browser.tl` / `src/stdlib/browser.rs`.

The planner consumes plain data:

- target id and URL/domain;
- fallback mode (`never`, `reasoned`, `always`);
- reason codes such as `requires_javascript` or `dom_state`;
- route fields used by the existing D/T route model;
- budget class and transport policy;
- artifact policy flags for response body, screenshot, HAR, and DOM snapshot.

The planner emits plain JSON-serializable decisions:

- selected route depth/transport and route observability tags;
- stable reason codes;
- budget cap/estimate/guardrail;
- artifact-policy hook statuses;
- explicit non-claims and side-effect booleans.

## Safety boundary

The Phase 4 planner always keeps these booleans false:

- `would_launch_browser`
- `performed_network_io`
- `captured_artifacts`
- `claims_live_browser_ready`
- `claims_production_fallback_ready`

It does not call:

- `BrowserProcess::launch`
- `CdpClient::connect` or `connect_pipe`
- `Page::navigate`, screenshot, PDF, DOM snapshot, recording, or HAR capture paths
- session/cookie capture or restore helpers
- request-plan live execution

CDP pipe remains `unsupported_fail_closed`.

## Local proof command

```bash
TALLOW_RUN_BROWSER_LIVE_TESTS=0 cargo test --test browser_fallback_service -- --nocapture
```

This generates the local proof bundle:

- `artifacts/phase4/browser-fallback-service-local/decision-report.json`
- `artifacts/phase4/browser-fallback-service-local/metrics.json`
- `artifacts/phase4/browser-fallback-service-local/hash-checks.json`
- `artifacts/phase4/browser-fallback-service-local/command-log.txt`
- `artifacts/phase4/browser-fallback-service-local/README.txt`
- `artifacts/phase4/browser-fallback-service-local/artifact_manifest.json`

## Required regression gates

For Phase 4 acceptance, run:

```bash
cargo check
cargo test --test browser_fallback_service -- --nocapture
TALLOW_RUN_BROWSER_LIVE_TESTS=0 cargo test --test browser_flow_runtime_integration -- --nocapture
TALLOW_RUN_BROWSER_LIVE_TESTS=0 cargo test --test browser_contracts -- --nocapture
python3 scripts/phase1_smoke_ladder.py --skip-build --skip-targeted-tests
```

## Non-claims / human gates

Still requires explicit the operator approval and later phase gates:

- live browser launch;
- live external scraping/crawling;
- screenshots/HAR/DOM capture against live targets;
- session reuse or cookie handoff with real credentials;
- real vault/secret configuration;
- production fallback budgets or compliance policy decisions;
- performance/benchmark claims;
- Windows support.
