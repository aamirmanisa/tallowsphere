# Design sketches

`.tl` files kept for their intent, not as runnable programs. They are **not** part of
`examples/*.tl`, not in the benchmark corpus, and not typechecked by CI.

## `financial_e2e_test.tl`

Written in a dialect Tallow does not have, in four independent ways:

- top-level statements (Tallow is items-only; a program is `fn main() { … }`)
- Rust-style closures `|t| { … }`
- an `export { … }` block, which exists in no grammar version
- `|>` pipes and PascalCase namespace calls (`Yahoo.quote`, `Technical.rsi`) over an
  API surface (`to_map`, `each`, `enumerate`, tuple destructuring in closures) that
  the stdlib does not provide

It also needs live Yahoo Finance / SEC EDGAR data to mean anything. Making it runnable
is a rewrite against the real dialect, not a repair — so it lives here as a sketch of
what an end-to-end financial pipeline would look like, and register row #83 is closed
by this move rather than by pretending the file works.
