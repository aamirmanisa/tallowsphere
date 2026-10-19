# Optional representation in the native plane

Status: **decided, not yet implemented.** Operator chose the boxed encoding
(option 1 of three in register #119) on 2026-10-18.

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

1. Add `%struct.Optional` and a `lower_optional_some` / `lower_optional_load`
   pair in codegen; map `T?` to `I8Ptr`; `nil` becomes a null pointer.
2. Fix the fallout in field store/load (optional struct fields), function
   returns and parameters, `match` on optional values, and printing.
3. Convert the browser structs that carry optionals (`ScriptTag.script_hash`,
   `ScriptTag.injected`, `WaitResult.*`) to real optional fields — today they are
   filled with `null`/`false` placeholders.
4. Lower the five `wait_*` methods, which become possible only at step 3.
5. `tests/browser_native_parity.rs` gains a `WaitResult` assertion: the same
   wait on both engines must report the same `result`, `url` and absent fields.

## Verification

- `cargo test --lib` must stay at 0 failures; any test that pinned `i64`-shaped
  optional behaviour is a real signal, not noise, and gets updated only after the
  encoding is confirmed correct.
- The parity test is the acceptance gate for steps 3–4.
