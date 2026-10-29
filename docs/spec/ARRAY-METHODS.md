# Array method resolution

Status: **normative for Tallow 2.0**. Blueprint gap BP21.

## The defect this replaces

Measured at `8dafa20`:

```
let a = [1]; let b = a.push(2)
--interpret        print(b) = [1, 2]        print(a) = [1]
--require-native   print(b) = raw 0x02      print(a) = [1]
tallow check       check passed: 1 items, 0 warning(s)
```

`push` is implemented in the interpreter, unknown to the type checker, and lowered by codegen into
something that yields a byte. Three components disagree about whether the method exists, and
`tallow check` — the command a user runs before shipping — says the program is fine.

The same holds for the whole method surface: the interpreter dispatches ~104 method names on
arrays, strings, numbers and `Result`, and the type checker has a signature for almost none of them.
A method call is therefore untyped, uncounted, and unchecked.

## Rule

**A method call is resolved at check time against a registry keyed by receiver type.**

1. The registry is the **interpreter's implemented set** for that receiver type — not a wish list.
   If the interpreter can execute it, the registry has it; if the registry has it and the interpreter
   cannot, that is a defect in the registry, caught by its own test.
2. For an `Array` receiver the registry covers the interpreter's array arms. The lane derives the
   list from `src/interp.rs` and records it in the registry as data, one row per method: name, arity,
   argument types, return type, and whether the native plane lowers it.
3. `arity` is checked. A wrong argument count is a named error, not a runtime surprise.
4. An **unknown method name** on a known receiver type is **E0625** at check time, on both planes,
   naming the receiver type and the method. This is the important half: it is what stops
   `a.push(2)` from being accepted and then doing nothing.
5. A method the registry declares but the native plane cannot lower is a **named build refusal** —
   `the native backend has no lowering for Array.<name>; run with --interpret` — never a call that
   silently yields a byte. This mirrors `print()`'s array refusal (BP19): refuse, do not fake.
6. Methods on `Unknown` receivers are left alone. No rule is invented for a type the checker cannot
   see; the interpreter remains the fallback plane for those programs.

## Semantics that must not drift

`push` is **functional**: it returns a new array and mutates nothing. A bare `a.push(2)` discards the
result on both planes. The registry records this, and the doc for the method says so — a method that
looks mutating and is not is the kind of trap a type checker exists to make visible.

## Gates

- `tests/array_methods.rs`, driving the real binary on both planes:
  - `a.push(2)` bound and unbound: interpreter result `[1, 2]`, native named refusal (no byte), and
    `a` unchanged on both;
  - `len`, `first`, `last` (lowered methods): identical values on both planes;
  - unknown method `a.frobnicate()`: **E0625** from `tallow check` and from both planes, naming
    `Array` and `frobnicate`;
  - wrong arity (`a.push(1, 2)`): named error, not accepted;
  - a method on an `Unknown` receiver still runs (no new refusal invented).
- `cargo test --lib typeck` green, since the registry lives in the checker.
- `scripts/check_test_coverage.py` reports 0 unaccounted.
