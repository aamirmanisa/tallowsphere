# Browser native-plane gaps (Page)

Measured at HEAD `c1c2990`+ by diffing `impl Page` in `stdlib/browser.tl` against the
`("Page", "<method>")` arms in `src/codegen.rs` — including the grouped form
`("Page", m @ ("on_console" | ...))`, which a literal-only diff misses:

**48 methods declared, 42 lowered, 6 without a native lowering.**

The 12 are not one problem. They fall into three groups, and only the first group
needs new machinery in the compiler.

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

## Group 2 — JS bindings (2)

`expose_binding`, `expose_function`.

The six `on_*` handlers are lowered (see docs/browser-callback-abi.md) and share
one registry, one pump and one wrapper emitter, so a new kind is a match arm and
a parity probe. Bindings differ slightly: the binding NAME travels in the
`Runtime.bindingCalled` payload, so one drain serves every binding and the handler
must be selected per event rather than per kind.

These take a Tallow function value and expect the runtime to call it later. The
native plane has no callback plumbing: a compiled Tallow function is not a C
function pointer the CDP pump can invoke, and the pump runs on the runtime thread
while generated code is not re-entrant. These are **interpreter-only by design**;
the correct native behaviour is the loud refusal that exists today, naming the
method.

Making them native would need a callback ABI (a trampoline that re-enters compiled
code from the CDP loop) — a project, not a lowering. Do not start it without an
explicit decision, because it changes the runtime's threading contract.

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
