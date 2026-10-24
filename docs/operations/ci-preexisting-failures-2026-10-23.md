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

## 2. Production CI Gates — red since at least `22c7b40` — **FIXED 2026-10-23**

Evidence: workflow `386117969` has failed on every run in the day's history —
`22c7b40`, `517fe82`, `9ef844f`, `55fa650`, `2d2a0cf`, `9cd968d`, `5067cb0`. Always the
same step: `[FAIL] cargo-test-browser-flow-runtime: command failed (exit 101)`.

Root cause, found by instrumenting the navigate loop: the three failures were the mock
server, not the engine. Since 2026-10-22 `Page::navigate` verifies completion against the
document — it reads `performance.timeOrigin` before navigating and again when the
lifecycle event lands, and accepts the event only when the value changed (a real browser
had reported success on `chrome-error://` without it). The mock answered every
`Runtime.evaluate` with `""`, so the probe parsed to `None`, `new_document` stayed false,
and the loop waited out its budget with the events correctly received. Instrumented
output showed `Page.frameStartedNavigating`, `Network.responseReceived` and
`Page.lifecycleEvent {name: DOMContentLoaded, frameId: frame-fallback}` all arriving and
matching.

Fix: the mock tracks the last navigated URL, returns a number for `performance.timeOrigin`
(1000.0 before, 2000.0 in the probe) and a JSON string with `u/s/o/e` for the
`JSON.stringify(...)` probes. No engine change. Result: `5 passed; 0 failed` locally
(previously 2/5).

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

---

## Status after the M1 fixes — 2026-10-23

Main CI **19/19 jobs green** at `919ca8e` (run 40039973842); Tallow Production CI Gates
green on the same commit. The three failures above are closed except §3, where the six
suites remain registered as triage with named assertions and a 2026-11-06 expiry — the
browser job runs the other 23.

A fourth defect was found by the contract suite once the browser job went green:
`mesh_workers::a_stalled_worker_does_not_extend_the_wave` measured a 5.0005 s wave on the
2-core runner. Speculation had fired, but the duplicate was dispatched by round-robin and
could land in the same worker queue as the task it was meant to replace. Fixed in
`919ca8e`: the duplicate now targets a worker other than the straggler's slot. Verified
under `taskset -c 0,1`: 3/3 passes (was 0/3).

## 5. `http.get` issues no request when its fields are read directly (2026-10-24)

Evidence, measured with a local fixture server that logs connections:

- `let a = http.get("http://127.0.0.1:28111/"); print(a.status)` prints `-1`,
  `print(a.url)` prints `(null)`, the server records **zero** connections, and an
  egress ledger watching the same run records nothing.
- The same URL consumed by `match a { Ok(r) -> ... }` **does** perform the
  request: the ledger records `{"status":200,...}` and the server serves it.

So the defect is specific to field access on the result value, not to HTTP. The
stdlib path (`http_get`) and the interpreter path (`interp.rs` http block) both
execute when reached; the field-access form reaches neither.

Impact: the egress-ledger integration tests (`tests/egress_ledger.rs`) are
`#[ignore]`d with this reason. The ledger itself is covered by its unit tests.

Owner: engine. Reproduction is the two-line program above.

### Update (2026-10-24, same day)

The ledger is now wired into the **native** batch path (`src/runtime/fetch.rs`),
which is the path a program actually takes for `http.batch`: the scope gate, the
request, and the status are all recorded, so the control no longer depends on
which engine ran the program. Two things follow from that work:

- A program's `http.batch` is refused before egress unless the host is in the
  scope register — the tests now write a register authorizing their loopback
  fixture, which is what a real target needs too.
- The native path had no ledger at all, so the same program was governed or not
  depending on whether the result's fields were read. That inconsistency is fixed.

`http.get` with direct field access remains broken as described above (no
request, empty value); `http.batch` is the working form and the one the
integration tests use.
