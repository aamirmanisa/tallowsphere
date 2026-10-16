# tallow-registry

Fleet registry skeleton + **receipt format v1** for the Tallow mesh
(checklist task 2.2). Local by design: a file-backed device registry and an
append-only, hash-chained, Ed25519-signed receipts ledger, with a CLI as the
v1 "registry service" shape.

**Format spec:** `Nixe/artifacts/tallow-mega-mesh-2026-09-27/registry/RECEIPT-FORMAT-v1.md`.

## Layout

- `store` — `registry.json` device rows: `{id, role, status, ed_pub_hex,
  created_ms, updated_ms, notes}`; atomic writes (tmp + rename).
- `receipt` — receipt v1: canonical-JSON body (`v, seq, kind, ts_ms, actor,
  subject, data, prev`), `sha256` body digest, Ed25519 signature
  (`sig{alg,key_fp,sig_hex}`), `prev` chain. Strict parsing — unknown fields
  are rejected so nothing unsigned rides along.
- `ledger` — `receipts.jsonl`: `append` enforces seq + `prev` linkage against
  the head; `verify` re-checks the whole file (parse, seq, chain, signatures).
- `bridge` — registry row → `tallow_admission::DeviceEntry` (the mint → door
  path preview for item 2.4).

## CLI

```bash
target/debug/tallow-registry --registry registry.json --ledger receipts.jsonl init
target/debug/tallow-registry --registry registry.json --ledger receipts.jsonl \
  mint --id operator-1 --role owner --ed-pub-hex <64 hex>
target/debug/tallow-registry --registry registry.json --ledger receipts.jsonl \
  revoke --id guest-1
target/debug/tallow-registry --registry registry.json --ledger receipts.jsonl list --json
target/debug/tallow-registry --registry registry.json --ledger receipts.jsonl \
  receipts --kind device.mint --limit 5 --json
target/debug/tallow-registry --registry registry.json --ledger receipts.jsonl verify-ledger
```

- Default actor key = deterministic DEV material (`tallow-test/registry/actor`)
  with a loud warning; `--key <file>` loads `{"seed_hex": "<64 hex>"}`.
- `verify-ledger` exits `0` clean / `3` broken (tamper, chain break, bad sig).

## Receipt kinds (v1)

Implemented by the CLI: `device.mint`, `device.revoke`. Reserved for the
spine (door events, windows, jobs): `door.auth`, `window.open`,
`window.close`, `job.run`.

## Tests

- `cargo test` — canonical encoding (order independence, escaping), receipt
  sign/verify/tamper, strict-parse rejection, ledger chain enforcement +
  file-tamper detection, query filters, store roundtrip + validation,
  bridge mapping.
- `tests/cli_smoke.rs` — drives the real binary: init → mint ×2 → revoke →
  list → receipts (chain-linkage asserted) → verify (ok) → file tamper →
  verify exits 3.

## v1 limits (documented, not bugs)

Single actor key per ledger; no key rotation; no external anchoring
(RFC 3161 / SCITT-class is a later rung); payloads should stay
integer/short-string JSON (no floats in v1 conventions).
