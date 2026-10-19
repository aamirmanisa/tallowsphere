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

So `resolve_antibot` is one delegation away on the interpreter: an arm in
`src/interp.rs` that calls

```rust
crate::stdlib::browser::dispatch_method(&Value::Handle(handle.clone()), "resolve_antibot", args)
```

with `args = [url]` or `[url, opts]` (the Rust side accepts the handle as
`args[0]`, url as `args[1]`, opts as an optional map at `args[2]` — see
`page_resolve_antibot`).

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
