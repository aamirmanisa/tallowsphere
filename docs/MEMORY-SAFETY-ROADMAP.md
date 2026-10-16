# Tallow — Memory-Safety Roadmap

**Status:** roadmap (CISA-shaped). It states plainly which tier is safe **by construction** and which is
safe **by convention** — the distinction procurement and regulatory reviewers ask for.

## The three tiers

| Tier | What it is | Safe by |
|---|---|---|
| **1 — Rust implementation** | Every subsystem written in this repository is Rust. | **Construction** — the language forbids the memory-safety class outright. |
| **2 — Tallow default tier** | Programs compiled and run by Tallow without an escape hatch. Intended guarantee: no raw pointer arithmetic in the default surface, allocation through a checked arena, bounds-checked indexing. | **Construction, where proven.** This guarantee is currently **asserted, not proven** — the roadmap's first task is to state it precisely and back it with a conformance case. |
| **3 — `@unsafe` escape** | A named, gated escape hatch for the few operations the default tier forbids. | **Convention. NOT YET IMPLEMENTED** — the language has no `@unsafe` construct today (verified: no `unsafe` form in the lexer/parser/AST). When it lands, every use is named, gated by a pass, and recorded in emitted provenance **and** the SBOM. |

## What this roadmap commits to

1. **State the tier-2 guarantee precisely** and back it with a conformance case before it is claimed.
2. **Land tier 3 as a named, gated, recorded escape** — never an implicit one. A `@unsafe` use must be
   visible in a real artifact (SBOM + provenance), not only in source.
3. Keep tier 1 (the Rust implementation) the default answer: the safe path is the one you get without
   asking.

## Honest caveat

`@unsafe` does not exist yet. Until it does, tier 3 is a plan, not a surface — and no public material
should describe it as shipped. Tallow ships **no `fips` feature** and makes no CMVP claim (see
[`../SECURITY.md`](../SECURITY.md)); the same "state which is which" rule applies to the safe-by-construction
tiers above.
