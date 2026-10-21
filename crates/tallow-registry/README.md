<div align="center">

# tallow-registry

**Who is in the fleet, and a ledger of everything that happened to it — append-only, hash-chained, signed.**

![receipts](https://img.shields.io/badge/receipts-v1%20%C2%B7%20Ed25519%20%C2%B7%20SHA--256-1f6feb?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-black?style=flat-square)

</div>

---

A fleet that cannot prove what happened to it is a fleet you have to trust. This crate gives you two files: a registry of devices with their public keys, and a receipts ledger where every entry is signed, chained to the one before it, and verifiable by anyone holding the public key.

## What it is

| Module | Contents |
|---|---|
| `store` | `registry.json`: device rows `{id, role, status, ed_pub_hex, created_ms, updated_ms, notes}`; atomic writes (temp file + rename) so a crash cannot leave a half-written registry |
| `receipt` | Receipt v1: canonical-JSON body (`v, seq, kind, ts_ms, actor, subject, data, prev`), SHA-256 digest, Ed25519 signature, `prev` chain |
| `ledger` | `receipts.jsonl`: append enforces sequence and chain linkage against the head; verify re-checks parse, sequence, chain and every signature |
| `pins` | Peer pin registry (`pins.json`) — out-of-band identity/SPKI pins with fail-closed resolution, never trust-on-first-use |
| `bridge` | Registry row → `tallow_admission::server::DeviceEntry`, the mint → door path |
| `canonical` | Canonical JSON encoding — key order independent, deterministic escaping |

**Strict parsing is the point.** An unknown field in a receipt is rejected rather than ignored: anything that rides along unsigned is a place to hide a modification.

## What it is not

- **Not a database.** Two JSON files, read whole. A fleet large enough to need indexing needs a different store.
- **Not anchored.** The chain proves internal consistency and detects edits after the fact; it does not prove to a third party when an entry was written. RFC 3161 / SCITT-class anchoring is a later rung, and the README says so instead of implying it.
- **Not multi-writer.** One actor key per ledger.

## Quick start

```console
$ cargo build -p tallow-registry

# create the two files
$ ./target/debug/tallow-registry --registry registry.json --ledger receipts.jsonl init

# admit a device (its Ed25519 public key, hex)
$ ./target/debug/tallow-registry --registry registry.json --ledger receipts.jsonl \
    mint --id operator-1 --role owner --ed-pub-hex <64 hex chars>

# look at what the fleet contains
$ ./target/debug/tallow-registry --registry registry.json --ledger receipts.jsonl list --json
$ ./target/debug/tallow-registry --registry registry.json --ledger receipts.jsonl receipts --kind device.mint --limit 5 --json

# prove the ledger has not been edited
$ ./target/debug/tallow-registry --registry registry.json --ledger receipts.jsonl verify-ledger
```

`verify-ledger` exits `0` when the chain, sequence and signatures all check out, and `3` when anything is broken — a tampered line, a missing entry, a bad signature.

### As a library

```rust
use tallow_registry::Ledger;

let ledger = Ledger::new("receipts.jsonl");   // opens or creates on first append
let verdict = ledger.verify(&public_key);     // LedgerVerdict, same check as the CLI
```

The same verification the CLI performs is available in-process, so a service can refuse to start on a broken ledger rather than discovering it later.

## Configuration

| Flag | Meaning |
|---|---|
| `--registry <path>` | Device registry file |
| `--ledger <path>` | Receipts ledger (JSONL, append-only) |
| `--key <file>` | Actor signing key: `{"seed_hex": "<64 hex>"}` |
| `--actor <name>` | Actor label recorded in receipts |

Without `--key`, the CLI runs on deterministic **dev** key material (`tallow-test/registry/actor`) and prints a loud warning. That is fine for a demo and unacceptable for a real ledger: dev keys are public, so every receipt they signed is forgeable by anyone who reads this repository.

## Deploying it

The registry is a library plus a CLI; the "service" shape is a scheduled or on-demand invocation, not a daemon.

```ini
# /etc/systemd/system/tallow-registry-verify.service
[Unit]
Description=Verify the Tallow receipts ledger

[Service]
Type=oneshot
ExecStart=/usr/local/bin/tallow-registry \
  --registry /var/lib/tallow/registry.json \
  --ledger /var/lib/tallow/receipts.jsonl \
  --key /etc/tallow/registry-actor.json \
  verify-ledger
User=tallow
```

Pair it with a timer (`OnCalendar=daily`) and page on exit code `3`. A ledger nobody verifies is a log.

Operational rules learned from the format:

- **Back up the ledger by copying it, never by rewriting it.** Order is the chain.
- **Keep `--key` outside the repository and outside the backup of the ledger.** A stolen ledger plus a stolen key is a forgeable history.
- **Payloads stay integer/short-string JSON.** v1 conventions exclude floats, because canonical encoding of floats is a compatibility trap.

## Receipt kinds

| Kind | Written by |
|---|---|
| `device.mint` | `tallow-registry mint` |
| `device.revoke` | `tallow-registry revoke` |
| `job.run` | `tallow-jobs` |
| `locator.scorecard` / `locator.refusal` | `tallow-locator` |
| `door.auth`, `window.open`, `window.close` | reserved for the mesh spine |

## Verification

```console
$ cargo test -p tallow-registry
$ cargo test -p tallow-registry --test cli_smoke
```

7 test functions in the crate source [measured 2026-10-21], plus a CLI smoke test that drives the real binary through init → mint ×2 → revoke → list → receipts (asserting chain linkage) → verify → file tamper → verify exits `3`.

## Limits

| Limit | Detail |
|---|---|
| Single actor key | Rotation is not implemented; a new key starts a new ledger |
| No external anchoring | The chain is only as trustworthy as the file it lives in |
| No compaction | The ledger grows forever; that is the cost of an append-only record |
| No floats in payloads | v1 convention; use integers and strings |

## License

MIT — see the repository `LICENSE` and `NOTICE`.
