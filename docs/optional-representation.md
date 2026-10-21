# Optional representation in the native plane

Status: **the encoding is complete; the language around it is not.** Boxed
`T?` produce, print, `== nil` and field store/load work on both planes, and
implicit wrapping into an optional was fixed on 2026-10-21 (#135 — `return a`
from a `-> i64?` function used to be refused when the value was not a literal).
Two gaps remain open, both measured on 2026-10-21:

- **#134 — an optional cannot be unwrapped natively.** `match` on a `T?` is
  refused by codegen ("unsupported subject shape") and `??` is a type error on
  both planes. A program can hold a `T?` and never read it.
- **#136 — the type checker lets a `T?` bind to a `T`.** `let v: i64 = src(0)`
  passes `tallow check`, then the native plane refuses at codegen and the
  interpreter prints `nil` and fails on the next arithmetic.

Arithmetic on an optional is not a gap: the type checker rejects it on both
planes with `E0110 left operand of + must be numeric, got i64?`, so there is no
divergence to fix. Operator chose the boxed encoding (option 1 of three in
register #119) on 2026-10-18.

## The defect it fixes

`T?` had no representation of its own. `src/codegen.rs` mapped every optional
to `i64` (`Type::Optional(_) => LLType::I64`, `TypeExprKind::Optional(_) =>
LLType::I64`) and `ExprKind::Nil` to `i64 0`. Consequences:

- `bool?` cannot distinguish `false` from `nil` — both are `0`.
- A present `true` prints `1`; the interpreter prints `true`.
- Any `WaitResult` (nine optional fields) built natively reports invented values
  for fields the interpreter leaves absent.

This is why the five `wait_*` browser methods are not lowered.

## Encoding

`T?` is a **pointer to a boxed payload**:

```
%struct.Optional = type { i64 tag, i64 payload }
tag 0 = nil  (pointer may be null, or a box with tag 0 — see below)
tag 1 = present; payload holds the value
```

Rules:

- `nil` is a null pointer. Emitting a null `ptr` is one instruction and needs no
  allocation; a box with `tag 0` is accepted on load so a payload-less box is not
  a hard error.
- `some x` allocates a 16-byte box, stores `tag = 1` and the payload as `i64`
  (booleans zero-extended, floats bitcast, strings `ptrtoint`).
- Reading an optional (`x ?? default`, field access, `match` on presence) loads
  the tag; null means absent.
- Printing an optional renders `nil` when null, otherwise the payload rendered
  by the *inner* type — so `bool?` prints `true`/`false` and `String?` prints the
  string, matching the interpreter.

## Why not the alternatives

- **`i64::MIN` as nil** — cheaper, but it is a language-wide rule every optional
  consumer must honour forever, and it silently reinterprets an integer value
  that a program may legitimately produce.
- **Accepting integer rendering** — documents a divergence instead of removing
  it; `WaitResult` would still invent `false` for absent fields.

## Migration order (each step compiles and is tested before the next)

1. ~~Add the type and the box~~ **DONE** — `LLType::Optional`, `%struct.Optional
   { i64 kind, i64 payload }`, `box_optional`, `return nil` ⇒ `ret ptr null`,
   `return x` ⇒ boxed. Verified: a `bool?` program builds and runs natively;
   `cargo test --lib` 9133 passed.
2. ~~Printing~~ **DONE** — `tallow_print_optional` reads the box's kind and
   renders `true`/`false`/`%lld`/`%g`/`%s`, or `nil` for a null pointer.
   `tests/optional_parity.rs` holds both engines to `true`/`false`/`nil`.
   **Also done:** field store/load (both struct builders box an optional slot and
   load the pointer back), truthiness (`emit_optional_truthy_i1` reads the kind
   tag, so a present `false`/`0`/`""` is falsy *and* not absent — this replaced a
   catch-all that read "non-null pointer ⇒ true"), and `== nil` / `!= nil` /
   value equality (`emit_optional_eq`). The same test file's
   `optional_truthiness_and_nil_equality_agree` asserts all of it on both planes.
   Arithmetic on an optional is rejected by the type checker (E0110) before
   either engine runs — same error on both, so nothing is left open here.
3. **DONE** — the browser structs carry real optional fields, and the five wait
   arms fill only what the interpreter fills: `wait_for_event` writes `event`
   (not `received`/`method`), `wait_for_request` leaves `received` nil, and
   `wait_for_response` writes `received` as the observed bool. Before this they
   wrote the URL string into `received`, which is declared `bool?`.
4. **DONE** — all six `wait_*` arms (timeout, function, url, event, request,
   response) are lowered; `wait_url_parity` / `wait_net_parity` gate the value.
5. **DONE** — `tests/wait_url_parity.rs` now prints and compares every
   deterministic field (`result`, `matched`, `received`, `url`, `method`,
   `status`, `event`) on both engines, and `tests/wait_net_parity.rs` asserts the
   per-wait shape the interpreter defines: response sets `received`, request and
   event leave it absent, and the event wait puts the event *name* in `event`
   only. `elapsed_ms`/`waited_ms` are excluded from the comparison — they differ
   between runs by construction.

## Sites to change (inventory, `src/codegen.rs`)

Named so step 1 starts from facts rather than another search. This is the
original inventory; the migration order above records what has since landed.

| Site | Line | Today | Change |
|---|---|---|---|
| `Type::Optional(_)` mapping | 19137 | `LLType::I64` | `LLType::I8Ptr` |
| `TypeExprKind::Optional(_)` mapping | 21847 | `LLType::I64` | `LLType::I8Ptr` |
| `ExprKind::Nil` | 4382 | `i64 0` | null pointer in optional context, `i64 0` elsewhere |
| `coerce` | 18238 | no `I64 ⇄ I8Ptr` path; must not box implicitly | explicit boxing helper, coerce stays reinterpretation-only |
| `emit_print` | 10308 | dispatches on `LLType`; `I8Ptr` ⇒ `%s` | needs the optional's inner type, so print must consult the static type, not the LLType alone |
| equality (`BinOp::Eq`/`Neq`) | 5551, 5619 | integer compare | pointer compare for nils, tag compare otherwise |
| optional field store/load | — | none today (no native struct has an optional field) | box on store, tag on load |
| function return coercion | return path | `i64` value | box for `T?` returns |

Two facts worth carrying forward:

- There is no `??`, no `Some(..)`, and no `Option` value in the interpreter — `Value` has only `Nil` and plain values. So "present" never needs a distinct runtime tag from the language's point of view; the box exists only so `false` and `nil` stop being the same number.
- `print` is the hard part, not the storage: it dispatches on `LLType`, and an optional and a string are both `I8Ptr`. Either `print` learns the static type at its call site, or the box carries enough tag information to render itself. Step 1 must settle this before any browser arm uses the encoding, because `WaitResult` is normally printed or inspected field by field.

**Resolved 2026-10-18:** add `LLType::Optional` rather than reusing `I8Ptr`.
`I8Ptr` is already the string type, so an optional and a string would be
indistinguishable at every dispatch site, `print` above all. A separate variant
makes the distinction structural.

**Correction (measured):** the variant does *not* enumerate the work. Adding it
produced zero compile errors, because every `match` on `LLType` in this file has
a catch-all arm. The migration sites are silent, so step 1 closes the damage at
the conversion boundary instead: `coerce` refuses any conversion to or from
`LLType::Optional` with a message naming this document, which turns a wrong
program into a failed build rather than a wrong binary.

## Verification

- `cargo test --lib` must stay at 0 failures; any test that pinned `i64`-shaped
  optional behaviour is a real signal, not noise, and gets updated only after the
  encoding is confirmed correct.
- The parity test is the acceptance gate for steps 3–4.
