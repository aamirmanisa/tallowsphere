# Browser sentinels: the eleven that used to simulate

2026-10-24. These eleven structs were returned with `simulated: true` and a state
nothing underneath ever read. Each now drives the CDP domain for the field it
names, against the page the interpreter has bound (`current_page_handle()`),
through `src/browser/sentinels.rs`.

| Element | CDP method | Proof |
|---|---|---|
| `NetworkInterceptor.create` | `Fetch.enable` (pattern `*`, request stage) | `i.active == true` |
| `NetworkInterceptor.add_rule` | rule table consulted by the Fetch pump | blocked request fails `ERR_BLOCKED_BY_CLIENT` |
| `NetworkInterceptor.block_pattern` | same | fixture server records no request for the blocked path |
| `NetworkInterceptor.mock_response` | `Fetch.fulfillRequest` (base64 body) | response code/body from the rule |
| `NetworkInterceptor.clear` | `Fetch.disable` | rules emptied, `active == false` |
| `TraceRecorder.start` | `Tracing.start` (`ReportEvents`) | `recording == true` |
| `TraceRecorder.record_action` | `Runtime.evaluate` → `performance.mark` | mark present in the trace |
| `TraceRecorder.stop` | `Tracing.end` → wait `tracingComplete` | non-empty trace document under `.tallow-traces/` |
| `DeviceEmulator.set_viewport` | `Emulation.setVisibleSize` + `setDeviceMetricsOverride` | page reports `clientWidth == 800` |
| `DeviceEmulator.set_mobile` | same + `setUserAgentOverride` (named profile) | unknown profile refused |
| `DeviceEmulator.set_geolocation` / `set_timezone` / `set_locale` / `set_user_agent` / `clear` | `Emulation.*` | page reads back the value; `clear` restores |

## Two measurements worth keeping

**`window.innerWidth` is not the viewport under a persona.** With
`@fingerprint_policy(policy: .normalize)`, the stealth layer installs a getter on
`window.innerWidth` that keeps reporting the physical window: after an emulation
to 800×600, `document.documentElement.clientWidth` was **800** while
`innerWidth` stayed **1920**. A test asserting on `innerWidth` fails against
correct code. Assert on `clientWidth`. The conflict is real and unresolved:
normalization wins over emulation for that one property.

**A trace written to `/tmp` disappears.** The run sandbox gives the child its own
mount namespace, so a trace file under `/tmp` is invisible to the caller that
started the run. Traces are written under the run directory (`.tallow-traces/`)
for that reason.

## Failure modes are named, not silent

With no page bound, every one of these returns the reason and the way to get a
page — no struct, no `simulated` flag. An unknown device profile is refused
rather than mapped to a default: emulating "iPhone 15" as 1024×768 is worse than
saying the profile is unknown.
