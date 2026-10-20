# `stdlib/*.tl` — declaration surface, not compilable source

These 85 files declare the standard library's **surface**: every `fn` (and every
`native fn`) that a program may call, with its parameter and return types. They are
read by `tallow doctor`, not by the compiler's parser:

```
tallow doctor --stdlib-drift     # every declaration vs the real resolution order
tallow doctor --crypto-surface   # every crypto declaration vs dispatch evidence
```

Both run clean on the current tree (`unreachable: []`, `offenders: []`, rc 0), which is
the invariant these files exist to protect: **a name a program can call is declared, and a
name declared is reachable.** The implementation lives in `src/stdlib/*.rs` and the
dispatch tables in `src/interp.rs`; nothing here is compiled or linked.

## Why they do not compile

They are written in a declaration dialect, not in the language:

| construct | example | language equivalent |
| --- | --- | --- |
| `native fn` without a body | `native fn read(path: String, has_headers: Bool) -> [[String]]` | none — the language has no extern declaration |
| nested slice types | `[[String]]` | none — one level of `[T]` only |
| `Int` / `Float` | `fn momentum(prices: [Float], lookback: Int) -> [Float]` | `i64` / `f64` |

So `tallow check stdlib/csv.tl` is *expected* to fail, and 11 of 85 files happen to be
written entirely in compilable syntax. This is a **self-hosting gap**, tracked as register
row #129: Tallow cannot yet express its own standard-library declarations. Until it can,
these files are documentation with a machine check, and the machine check is
`doctor --stdlib-drift`.

## Rules for editors

- A new runtime function that a program can call needs a declaration here, or
  `doctor --stdlib-drift` has nothing to verify it against.
- Do not "fix" these files to satisfy the parser by adding bodies — a body here would be
  a mock, and `--crypto-surface` flags single-literal bodies as exactly that.
- Do not move them: `tallow doctor` reads them at these paths.
