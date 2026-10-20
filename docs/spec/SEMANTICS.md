# Tallow — Normative Semantics (v0)

**Status:** normative draft — sheet item **U-A01**. It states the rules the two engines must agree on.

**Enforcement rule:** this document is *not* the definition — the conformance corpus (`tests/conformance/`)
is. Where the corpus and this text disagree, **the corpus wins and this text is corrected** (sheet §8.2).

Every rule carries its basis:
- **[code]** — directly evidenced by the implementation named.
- **[decided]** — a normative decision of this spec, not yet proven by a conformance case.
- **[open]** — not yet decided; a named task.

This document exists because two independent implementations (`src/interp.rs`, `src/codegen.rs`) define
Tallow semantics today, and only one of them is currently tolerant enough to hide the disagreement
(§3). A guarantee is only as strong as the weaker engine.

---

## 1. Value model [code]

The runtime value is `interp::Value` (`src/interp.rs:153`), a tagged union. Principal constructors:

| Constructor | Payload | Notes |
|---|---|---|
| `Nil` | — | the absent value |
| `Bool` | `bool` | |
| `Int` | `i128` | 128-bit signed; the checker narrows via `IntSize` |
| `Float` | `f64` | IEEE-754 binary64 |
| `String` | `String` | UTF-8 |
| `Array` | `Vec<Value>` | |
| `Map` | `Vec<(Value, Value)>` | **keys are `Value`, not `String`** — insertion-ordered |
| `Ok` / `Err` | `Box<Value>` | user-level result (see §4) |
| `Private` / `Secret` | `Box<Value>` | privacy qualifiers, carried at runtime |
| `Consent` | `{ consent_id, inner }` | GDPR consent chain |
| `Erasable` | `{ erasure_id, inner }` | right-to-erasure tracking |
| `Function` | `{ name, params, body, captures }` | first-class; captures are a creation-time snapshot held in a shared cell |
| `Enum` | `{ enum_name, variant, discriminant, fields }` | `discriminant` is the variant's position in its declaration: enums are integer-backed, so `==`/`!=` against an integer and integer literal `match` arms compare it, and display prints it. A synthetic `Some(x)` has no declaration and carries `-1`, which keeps its constructor display. See register #122/#123 for the remaining plane divergences. |
| `Struct` | `{ name, fields }` | `name` drives `impl` dispatch |
| `Range` | `{ start, end, step }` | end-exclusive |
| `DbConnection`, `KeyPair` | opaque handles | |

(The enum continues beyond this excerpt — read `src/interp.rs` for the authoritative list.)

**V1 — value equality.** Two values are equal iff the same constructor with equal payloads, except
`Float`, which follows IEEE-754 (`NaN != NaN`, `-0.0 == 0.0`). *[decided]*

**V2 — map order.** `Map` is insertion-ordered; iteration yields insertion order, and re-inserting an
existing key preserves its original position. *[decided]*

## 2. Type model [code]

`typeck::Type` (`src/typeck.rs:18`):

`Void · Bool · Int(IntSize) · Float(FloatSize) · String · Bytes · Char · Private<T> · Secret<T> ·
Optional<T> · Result<T> · Array<T> · Tuple<…> · Map<K,V> · Set<T> · Chan<T> · Function{params, ret} ·
Consent<T> · Erasable<T> · Trusted<T> · Unverified<T> · Fresh<T, ttl_ms> · Boxed<T>`

**T1 — assignability (lattice).** `T ⊑ Optional<T>`; `T ⊑ Result<T>` (via `Ok`). Privacy qualifiers are
**contagious upward and never dropped implicitly**: the only direction is `Secret<T> → Private<T> → T`,
and each step is an explicit declassification site. *[decided; the contagion direction is [code] from
`as_string`'s explicit `Secret(_) => "[SECRET]"`, but the full assignability table is [open] and needs a
checker read.]*

## 3. Coercion — the root fix

**C1 (normative).** There is **no implicit coercion**. No value is implicitly converted to `String`, to a
numeric type, or across the privacy qualifier. Every conversion is an explicit, named operation, and a
conversion that can fail returns a `Result`.

**C2 (normative).** At the FFI / native boundary, an argument whose type does not match the declared
signature is a **compile-time error** on both engines. Neither engine may accept-then-coerce it.

### Current state — the measured divergence [code]

The interpreted leg violates C1 today. `Value::as_string()` (`src/interp.rs:577`) is a **total**
function — it maps *every* value to a `String`, including badly-typed ones (`Nil → "nil"`, `Int(n) →
n.to_string()`), and recursively unwraps a `Private(v)` with the comment *"unwrap for internal use"*,
rendering `Secret(_)` as `"[SECRET]"`. It has **653 call sites in `src/interp.rs` alone.** The compiled
(native) leg **refuses** the same call.

Consequence: a wrong-typed program can pass `tallow check`, run on the interpreter, and return a
plausible *wrong* answer, while the identical program is rejected natively. That asymmetry is the root
defect (sheet §3).

**Migration — U-A02, gated on this spec.** Replace each `as_string()` call site with a typed accessor
returning `Result<&str, TypeError>`, and require the site to handle the error explicitly. Gate:
`grep -c 'as_string()' src/interp.rs` = **0**.

## 4. Error propagation [code]

Two distinct planes that must never be conflated:

1. **`Value::Ok` / `Value::Err`** — a *user-level* result **value**. It flows as a value; `Err` is not a
   panic, and `match` on it is the ordinary handling path.
2. **`RuntimeError`** (`src/interp.rs:809`) — a *runtime fault*. Every evaluation function returns
   `Result<_, RuntimeError>` (`run` → `exec_stmt` → `eval_expr`); a `RuntimeError` propagates out of
   `run()` and fails the program. **It is not catchable from `.tl`.**

**E1.** A user-level `Err` reaching the top level of `main` aborts the program. Current mechanism
[code]: `run()` maps `Value::Err(e)` to `RuntimeError::UnhandledResult(e.as_string())` — which
**coerces through `as_string()`**, so it is itself a §3 violation site. *[decided: it must become a typed
render; tracked by U-A02.]*

**E2.** A `RuntimeError` is never observable as a value — there is no `.tl` construct that yields one.
*[code: `RuntimeError` has no corresponding `Value` constructor.]*

## 5. Evaluation order [open — named task]

The evaluator is a tree-walker: `run` → `exec_stmt` → `eval_expr`. `eval_binop` receives *already
evaluated* operands (`left, right`), so its caller decides the order; the order is therefore currently
**implicit in `eval_expr`'s call sites** and is not yet specified here.

**Closure task:** read `eval_expr`'s `Expr::Binary`, `Expr::Call` (argument list) and `Expr::Match` arms;
state the order (expected: strict left-to-right, arguments left-to-right); add one conformance case per
construct that observes order via a side effect.

## 6. Open sections [open]

- Numeric tower: the exact `Int(IntSize) ↔ Float(FloatSize)` promotion/coercion matrix.
- String indexing and the unicode model (shares the cross-engine parity notes).
- `Fresh<T, ttl_ms>` staleness semantics; `Trusted`/`Unverified` verification points.

---

## Conformance checklist

Per sheet §8.1–§8.2, **every rule above needs a runnable conformance case** under `tests/conformance/`,
and **both engines must pass it**. A rule with no conformance case is a proposal, not a guarantee. The
cases this spec commits to:

| Rule | Case (both engines) |
|---|---|
| V1 | `NaN != NaN`, `-0.0 == 0.0`, struct/enum/array equality |
| V2 | map insertion order preserved across re-insert and iteration |
| T1 | `Secret<T>` must not silently satisfy `T`; explicit declassification required |
| **C1** | a call site that coerces is **rejected** on both engines |
| **C2** | a wrong-typed FFI/native argument is a compile error on both engines |
| E1 | an unhandled user `Err` aborts with a typed render, not a coerced string |
| E2 | no `.tl` program can obtain a `RuntimeError` as a value |
| §5 | evaluation order observed by side effects matches the specified order |
