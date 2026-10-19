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
