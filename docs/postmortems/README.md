# Postmortems

Operational-failure library for the Tallow fault-injection surface
(`src/fault_injection.rs`, driven by `scripts/fault_suite.sh`).

## When to file

File a postmortem for:

- **any fault-suite failure** — offline run (`cargo test --lib fault_injection`)
  or an operator-run checklist row in `scripts/fault_suite.sh` not behaving as
  `expected_handling` pins it;
- **any real misuse or near-miss** — a malformed proxy string that reached a
  SOCKS5 client, poisoned content that reached a consumer unquarantined, a
  partial response treated as complete, a secret exposed to logs, etc.

No stamp "it didn't happen again". One incident → one postmortem.

## How to file

1. Copy `TEMPLATE.md` to `YYYY-MM-DD-<slug>.md` (date = first detection, UTC;
   slug = short kebab-case title, e.g. `2026-09-11-kill-mid-headers-silent-retry`).
2. Fill every section; keep commands, error strings, and paths verbatim.
3. Land it with the fix (or immediately after mitigation if the fix is slow).
4. If the incident shows a policy gap, update the suite in the same change —
   a postmortem without a new refusal or a named follow-up is not closed.

## Naming convention

`YYYY-MM-DD-<slug>.md` — lexicographic order in this directory is
chronological order. Do not rename or delete filed postmortems; supersede
them with a new file and cross-link.

## Index

Starts empty; add one line per filed postmortem, newest last:
`- [YYYY-MM-DD — title](YYYY-MM-DD-slug.md) — scenario/trigger — status`
