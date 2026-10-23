# Pre-existing CI failures found while executing M1

Date: 2026-10-23. Found while running the remediation plan's M1 gates. None is caused by
M1: each reproduces on a commit that changed no code, or on the production gate's own
history.

## 1. SBOM drift gate — red since at least `fdc603a` (documentation-only commit)

Evidence: CI run 40016871000 for `fdc603a` has exactly one failing job, `SBOM drift gate`:
*"scripts/sbom.snapshot.json does not match the regenerated artifact; update the snapshot
in the same change"*. The commit touched two markdown files only.

Cause, in the gate's own terms: the snapshot was not regenerated when the workspace last
changed. The gate is correct; the snapshot is old.

Fix: regenerate with `python3 scripts/sbom-gen.py --write artifacts/sbom/` (see the
script's `--check` mode), review the diff for dependency changes, commit both together.
Owner: alden. Expiry: 2026-10-30.

## 2. Production CI Gates — red since at least `22c7b40`

Evidence: workflow `386117969` has failed on every run in the day's history —
`22c7b40`, `517fe82`, `9ef844f`, `55fa650`, `2d2a0cf`, `9cd968d`, `5067cb0`. Always the
same step: `[FAIL] cargo-test-browser-flow-runtime: command failed (exit 101)`.

The underlying suite, `tests/browser_flow_runtime_integration.rs`, fails on this host as
well:
- `cdp_navigate_without_response_uses_event_fallback` — "navigate should succeed even
  without Page.navigate response: Timeout { operation: \"navigate\", detail: \"waiting for
  DOMContentLoaded\" }"
- `cdp_new_page_navigate_title_flow_tracks_goto_path` and
  `cdp_wrapped_target_message_flow_handles_nested_responses` fail alongside it;
  `live_browser_launch_new_page_goto_title_data_url` passes, so the launch path works and
  the CDP event path does not.

This is not an environment artefact: it fails identically on GitHub's runner and here.
Either the navigation waits on `DOMContentLoaded` that the fixture page never emits, or
the event-fallback path is broken. Both are testable in one sitting.

Fix: reproduce with `RUST_BACKTRACE=1 cargo test --test browser_flow_runtime_integration
-- --nocapture`, decide whether the defect is in the test's fixture or in
`src/browser/cdp.rs`'s navigate wait. Owner: forge. Expiry: 2026-10-30.

## 3. Six browser suites that do not pass on the pinned CfT build

Registered in `ci-excluded-suites.txt` as `triage` with the failing assertion named:

| Suite | Observed |
| --- | --- |
| browser_array_parity_cookies | array parity at 0/1/3 elements |
| browser_array_parity_links | same class |
| browser_array_parity_n | same class |
| browser_flow_runtime_integration | DOMContentLoaded timeout (see §2) |
| egress_census | needs a network-capable fixture |
| transfer_transport | needs a network-capable fixture |

The three array-parity failures share a shape — correct at one size, wrong at another —
which is the signature of an off-by-one in the array marshalling between the interpreter
and the native plane, not a flaky test. Owner: forge. Expiry: 2026-11-06.

## What is *not* in this list

The 23 browser suites that now run in CI pass against the pinned build, both locally and
on the runner; the conformance job is green in CI; `Dependency Check` is green after the
`--all-features` correction. Those are M1 successes, recorded separately.
