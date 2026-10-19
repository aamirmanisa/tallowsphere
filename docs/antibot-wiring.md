# Antibot wiring — measured state and the exact work

Written after the surface registry was found to claim an implementation that does
not exist. Every claim below is a grep result, not a reading of comments.

## The measurement

```
grep -c "goto_antibot\|resolve_antibot" src/interp.rs   → 0
grep -c "goto_antibot\|resolve_antibot" src/codegen.rs  → 0
```

`src/stdlib/browser.rs:734` and `:743` declare the capability-surface entries
`Page.resolve_antibot` and `Page.goto_antibot (egress map)` with status
`"implemented_interp_routed"`. **There is no interpreter route.** The status is a
self-report, and it is wrong. Any tooling that reads that registry to decide what
is available will be misled in the optimistic direction — the worst direction.

This is the same failure class as the stdlib doc comments corrected in `c7215ab`,
one layer up: prose asserting work that was never done.

## What IS implemented (and where)

| Piece | Location | State |
|---|---|---|
| `AntiBotOrchestrator` | `src/browser/antibot.rs:33` | real |
| `AntiBotOrchestrator::resolve` | `src/browser/antibot.rs:212` | real |
| `apply_stealth_bootstrap` | `src/browser/antibot.rs:359` | real |
| `page_resolve_antibot(args)` | `src/stdlib/browser.rs:1328` | real, takes `(handle, url, opts?)` |
| `resolve_antibot` dispatch arm | `src/stdlib/browser.rs:562` | real, module shape `browser.resolve_antibot(page, url)` |
| `dispatch_method(...)` entry point | `src/stdlib/browser.rs:644` | real |

`resolve_antibot` is reachable, but NOT by the delegation this doc first proposed.
Two corrections, both measured after writing it:

1. `dispatch_method` (src/stdlib/browser.rs:644) matches only
   `Value::Struct { name, fields }` — surface-manifest field reads. It cannot
   accept a page handle at all.
2. The real entry point is `page_resolve_antibot(args)` via the module-level
   `dispatch` arm at :562, which reads `args[0]` as
   `Value::BrowserObject(bh)` with `bh.kind == "Page"` (`extract_page`, :876).

So an interp arm would build `Value::BrowserObject(bh.clone())` plus url/opts and
call that path. **Hazard:** `page_resolve_antibot` calls
`crate::runtime::get_runtime()` and `rt.block_on(...)` internally; an interp arm
runs inside the interpreter's own runtime drive, and a nested `block_on` on the
same runtime panics. Any wiring must either extract the async part
(`AntiBotOrchestrator::resolve`) and await it on the interpreter's existing drive,
or run it on a separate thread with its own runtime — not call the stdlib helper
from inside the arm.

`goto_antibot` has **no** Rust implementation at all: the surface entry is the
only place the name appears outside `stdlib/browser.tl`. The comment at
`src/stdlib/browser.rs:747` describes egress-map semantics
(`{proxy, tor, stealth, tier}`, relaunch via `BrowserConfig.proxy`, live relaunch
human-gated) that no code implements. That is a specification, not a feature.

## Order of work

1. **Interpreter `resolve_antibot`** — delegate to `dispatch_method`. Reference
   plane first; a native lowering of behaviour the interpreter does not have
   cannot be parity-tested.
2. **Native `resolve_antibot`** — a `("Page", "resolve_antibot")` arm. The return
   type is `Result<AntibotResolveReport>`, a struct of per-engine step reports;
   that needs a layout registration like `WaitResult`/`AuthenticatedResponse`,
   plus the report's nested step array (array-of-struct, which now exists — see
   `drain_events`/`get_cookies`).
3. **`goto_antibot`** — decide the egress-map semantics before either plane:
   either implement the relaunch path or remove the surface entry. Do not lower
   a method whose behaviour is undefined.
4. **Fix the registry** — `implemented_interp_routed` must not be used for a
   method with no interpreter route. Whatever status value means "declared, not
   wired", use it, so the surface stops over-reporting.

## Why this is in a doc and not in code

Steps 1–3 each need a build (~5 min) plus a two-plane probe. Writing an interp arm
that cannot be exercised in the same session would leave unverified code in a
tree whose whole value is that its claims are measured — the exact opposite of
what this session did everywhere else.

## Measured divergence — why the native lowering was withdrawn

A first native lowering (FFI returning a flat report struct whose `steps` slot is
a native array of step pointers) was built and run, then reverted. Same build,
same program, same loopback page:

```
interp: resolved=true  final_status=200  attempts=1  steps.len=5
        egress / captcha.detect / warmup / escalation / classify
native: resolved=true  final_status=200  attempts=1  steps.len=1
        egress
```

The native report claims success while carrying one fifth of the reasoning. That
is the dangerous shape: the summary fields agree, so a caller checking only
`resolved` would never notice the missing steps. Shipping it would have converted
a loud "no lowering" into a quiet wrong answer.

Unresolved, and the next thing to measure: whether the FFI-side orchestrator
produced one step, or whether the array never carried five. The runtime is the
prime suspect — the interpreter arm drives `get_browser_runtime()`, the FFI used
`get_runtime()`, and mixing them is the #105 reply-routing failure mode.

### Testing lesson

Every earlier array probe used exactly one element, where a broken length is
invisible. Measured afterwards with two console events:
`tests/browser_array_len.rs` → natives and interp both report `2`. So the array
plumbing is correct at N>1, and the one-step report above is the FFI-side
orchestrator's own output, not a truncated array. The runtime hypothesis stands:
`get_runtime()` vs `get_browser_runtime()`.

## Attempt 2 — browser runtime, and a new failure

Retried the lowering driving `get_browser_runtime()` (the interpreter arm's
runtime) instead of `get_runtime()`, with the FFI always returning a report and
marking failure in an `error` field — the first attempt's null-on-error returned
null and every field load dereferenced it (SIGSEGV, "native run crashed").

Result: `[ffi] resolve_antibot error: action failed: resolve: navigation timed
out for http://127.0.0.1:18118/`. So the earlier one-step report and this timeout
are the same fault seen twice: navigation inside the FFI's `block_on` does not
complete, while `page.goto` immediately before it does.

Diagnostic note worth keeping: without the `eprintln!` the whole failure looked
like a silent `exit 1`, because the Result-tag guard exits on Err before any
`print` runs. A failing FFI in this position reports nothing unless it prints.

## Attempt 3 — narrowing, without touching the tree

Cheapest discriminating probe first, using the committed binary (no rebuild):
navigate twice through the ordinary native path.

```
let a = page.goto(url)   → "first"
let b = page.goto(url)   → "second"      EXIT=0
```

So a second navigation is fine on the native plane. The fault is therefore not
"navigate inside an FFI" and not "renavigating the same URL". Inside `resolve`
the only differences are (a) the wait strategy — `WaitUntil::NetworkAlmostIdle`
rather than whatever `Page.goto` uses — and (b) the 30 s `tokio::time::timeout`
wrapper. Next probe should drive `navigate(url, NetworkAlmostIdle)` once through a
throwaway FFI, with no orchestrator, and report which of the two is responsible.

## Attempt 4 — the wait strategy is exonerated too

Temporarily switched `tests/nav_direct.rs`'s first case from
`WaitUntil::DomContentLoaded` to `WaitUntil::NetworkAlmostIdle` and ran it
(harness: pure Rust, multi_thread runtime, no interpreter, no FFI):

```
navigate ok in 37.817715ms: status=None
body after navigate: "RENDERED-BY-JS"
```

`NetworkAlmostIdle` is fine. Probe reverted immediately; the test file is
unchanged in the tree.

That leaves exactly one difference between the working and failing cases: the
FFI calls `get_browser_runtime().block_on(...)` from compiled code, while the
interpreter and this test both drive navigation on a runtime they own. The
failure is therefore a property of that block_on context, not of the navigation
code it runs.

## Attempt 4 — resolve is exonerated; the array length is not

Re-applied on `get_runtime()` (the runtime every other native browser FFI uses,
and the one that owns the CDP reader). Navigation no longer times out — attempt
2's 30 s failure was `get_browser_runtime()`, a foreign runtime, i.e. register
#105's exact shape: the command is written and the reader is never polled.

With the FFI printing the report it actually returns:

```
[ffi] resolve_antibot ok: resolved=true status=200 attempts=1
      steps=[("egress", false), ("captcha.detect", true), ("warmup", false),
             ("escalation", false), ("classify", true)]
```

The orchestrator produced **five** steps natively — identical to the interpreter
(egress, captcha.detect, warmup, escalation, classify). The compiled program then
printed `rep.steps.len` = **1**.

So the whole divergence is in the array crossing the FFI, not in `resolve`, not in
settings, not in the runtime. `drain_events` traverses the same `native_array`
helper at N=2 correctly, which is why the N=2 test passed and told us nothing
about this case; the difference between the two is the element kind (a struct that
appears only as a report payload) rather than a plain registered event struct.

Lowering reverted again; the interpreter arm remains the only wired plane.

## Attempt 5 — a `.len` arm that changed nothing

Hypothesis: `rep.steps.len` misses the native-array `len` arm (only
`ElementArray`/`HtmlElementArray`/`StringArray` were listed), falls through to the
generic path and returns a wrong number. Added `("AntibotStepArray", "len")`
alongside them and re-applied the lowering.

Result: unchanged. `resolved=true / 200 / attempts=1 / steps.len=1`, while the FFI
(measured in attempt 4) hands back five step pointers in a `[count][ptr...]` array.

Conclusion: `.len` on this expression is emitted somewhere other than the typed
array-method arm — the struct-field access path is the remaining candidate — so the
hypothesis was wrong and the arm alone is not the fix. Reverted; recorded so the
next attempt does not start by adding that arm again.
