# Browser native-plane gaps (Page)

Measured at HEAD `d65e3ba`+ by diffing `impl Page` in `stdlib/browser.tl` against the
`("Page", "<method>")` arms in `src/codegen.rs` — including the grouped form
`("Page", m @ ("on_console" | ...))`, which a literal-only diff misses:

**48 methods declared, 46 lowered, 2 without a native lowering.**

The 12 are not one problem. They fall into three groups, and only the first group
needs new machinery in the compiler.

The refusal contract for everything still unlowered is pinned by
`tests/browser_unlowered_gaps.rs`: exit non-zero, the method named in the
message, and the program body never runs. The body assertion is the one that
matters — a silent fallback would print plausible output.

## Group 1 — payload shapes not yet lowered (2)

| method | declared return | what is missing |
|---|---|---|
| `get_cookies` | `Result<[]CdpCookie>` | an **array of struct pointers**. Every array lowered so far holds scalars (`StringArray`) or opaque handles (`ElementArray`), and the index path knows how to `inttoptr` a slot but not how to view a slot as a struct and then resolve fields. |
| `drain_events` | `[]PageEvent` | the same array-of-struct shape, plus a bounded per-page event buffer filled by the CDP pump. |

Order for these two: array-of-struct first, since `drain_events` reuses it.

What "array of struct" requires, concretely:

1. A runtime FFI that allocates an array of pointers to `#[repr(C)]` structs and
   returns `(ptr, len)`.
2. A payload-kind registration (`CookieArray`, `EventArray`) alongside
   `StringArray` / `ElementArray`.
3. An index path that loads the slot as `ptr`, then resolves field access through
   `struct_layouts` rather than treating the slot as the field itself.
4. One parity test per shape: field values printed from an indexed element must be
   byte-identical across engines.

## Group 2 — JS bindings — lowered

`expose_binding` and `expose_function` went in with the callback work: same
registry and pump, plus `Runtime.addBinding` and a lookup by the binding name in
the event payload. Verified with a page calling both `note(...)` and
`note2(...)`, byte-identical across engines.

## Group 3 — bot-defence orchestration (2)

`goto_antibot`, `resolve_antibot`.

Both wrap `AntiBotOrchestrator` (`src/browser/antibot.rs`), which takes an egress
`Map`, escalates proxy tiers, and can relaunch the browser. Neither has an
interpreter arm today either — so this is a feature gap in **both** planes, not a
native-only gap. Lowering it means marshalling a `Map` through FFI and deciding
how a proxy-tier escalation is expressed in the compiled world; that decision is
the work.

## Guard

`tests/browser_page_methods.rs::unlowered_browser_methods_refuse_the_native_build`
holds the contract that an unlowered method fails the build **and names the
method**. Its canary target must move whenever a lowering lands — it has been
retargeted three times (`add_init_script` → `wait_for_function` →
`wait_for_selector` → `on_console`). Prefer deriving the target from this list on
the next retarget, so the next lowering does not require editing the test.

## The antibot pair — measured

`goto_antibot` and `resolve_antibot` are not missing features. `src/browser/antibot.rs`
holds the orchestrator, and `src/stdlib/browser.rs` calls it
(`AntiBotOrchestrator::with_settings` + `resolve`). What is missing is dispatch:
`grep -n antibot src/interp.rs` returns nothing, and codegen has no
`("Page", ...)` arm for either, so the native plane refuses loudly and the
interpreter answers `unknown browser method`.

The stdlib doc comments claimed an interpreter arm existed; they were wrong and
are corrected. Wiring these means calling the existing Rust path from both
planes — interpreter first (it is the reference), then codegen.
