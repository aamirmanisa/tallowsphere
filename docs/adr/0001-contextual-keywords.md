# ADR 0001 — Keywords are contextual in name positions

Status: accepted (2026-10-23). Applies to `src/parser.rs`, documented in
`tallow-language/spec/02-grammar.md` §2.2.

## Context

The shipped stdlib manifest — the published description of the language surface —
uses reserved words as ordinary names: `type: String` in struct fields across
net/orders/yahoo, `return: Float` in portfolio2, `fn await(self)` and
`fn cancel(self)` on agent handles. Real API shapes do the same, because `type`
and `return` are the natural names for a field and a result value.

The parser rejected all of them. `tallow check` therefore failed on 65 of 85
stdlib modules, and the only two ways out were to rename published fields or to
let a name slot accept a keyword.

## Decision

A keyword is still a keyword everywhere the grammar expects a construct. In a
*name* position — struct field, function/method name, parameter list — the
reserved word is accepted as an identifier.

`return 1` inside a body is a return statement. `return: Float` inside a struct
is a field named `return`. The parser knows which it is looking at because the
two positions are parsed by different functions; no lookahead heuristic is
involved.

## Alternatives considered

**Rename the fields (`type_`, `return_`).** Rejected: it changes the published
surface to suit the parser. Every consumer of `net.tls.config().type` would have
to change, and the language would be telling its users that ordinary words are
unavailable as field names — a cost paid forever to preserve a parser
limitation.

**Escape syntax (`r#type`).** Rejected: it puts punctuation in field names that
serialize to JSON keys, so every wire format would inherit the escape.

**Treat the corpus as documentation and stop checking it.** Rejected: it is the
published description of 1,124 functions. If it does not parse, nothing keeps it
honest against the engine — and the drift that motivated this work (declarations
with no implementation) had already gone unnoticed once.

## Consequences

- The corpus checks clean (85/85), so `tallow check` on `stdlib/` is a usable
  gate and is wired into CI.
- A negative test pins the boundary: `return` in expression position still
  starts a statement, so the widening cannot silently spread.
- The grammar has one more rule to state and keep consistent across the parser,
  the formatter and the LSP. The formatter already round-trips these
  declarations; the LSP's completion list should treat the same positions as
  names.
- A keyword accepted in a name position cannot be used as a bare identifier in
  expression position. That asymmetry is intentional and is the price of not
  reserving `type` and `return` forever.
