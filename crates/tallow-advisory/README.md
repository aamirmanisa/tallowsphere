<div align="center">

# tallow-advisory

**Reads your ledgers, tells you what looks wrong, and touches nothing.**

![mode](https://img.shields.io/badge/mode-read--only-2ea44f?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-black?style=flat-square)

</div>

---

Monitoring that can act is monitoring that can be wrong twice: once in the diagnosis, once in the response. This crate is the other kind. It opens files, computes findings with evidence attached, prints them, and exits with a severity code. It never writes, never opens a socket, and never takes an action.

## What it is

| Module | Responsibility |
|---|---|
| `ledger` | Load and verify a receipts ledger (`job.run` rows) |
| `detectors` | Fixed detectors over ledger and mesh snapshots — no ML, no model calls |
| `findings` | `Severity`, `Finding` with evidence, stable sort order |
| `advise` | `scan()` — the whole pass, printing a report and returning an exit code |
| `cli` | Argument parsing and the binary |

Detectors in v1 include ledger integrity (chain errors), an empty ledger, job failure rate over a lookback window, cadence violations against an expectation file, and mesh/peer anomalies from a snapshot. Same input ⇒ same findings: v1 has no randomness and no network.

## What it is not

- **Not a fixer.** There is no write path in the crate (`#![forbid(unsafe_code)]`, no `File::create`, no network stack).
- **Not an alerting service.** It prints and returns a code; paging is the supervisor's job.
- **Not an ML model.** Deliberately deterministic so a finding can be explained and re-derived.
- **Not a source of secrets.** Output carries fingerprints only, never key material.

## Quick start

```console
$ cargo build -p tallow-advisory

# scan a receipts ledger
$ ./target/debug/tallow-advisory scan --ledger receipts.jsonl

# include a mesh snapshot and a peer fingerprint list
$ ./target/debug/tallow-advisory scan \
    --ledger receipts.jsonl --mesh mesh.json --peers peers.json

# machine-readable, with a lookback window and an expected cadence file
$ ./target/debug/tallow-advisory scan --ledger receipts.jsonl \
    --expect cadence.json --days 7 --json
```

Exit codes: `0` clean or info-only · `4` warnings · `5` critical · `2` usage · `1` error.

That mapping is the contract: a CI step or a timer can gate on `>= 4` without parsing prose.

```
tallow-advisory scan --ledger <receipts.jsonl> [--mesh <mesh.json>]
                     [--peers <fps.json>] [--expect <cadence.json>]
                     [--days N] [--pubkey <hex64>] [--json]
tallow-advisory selftest
```

Pass `--pubkey` to verify the ledger's signatures as part of the scan; without it, integrity checks cover structure and chain only.

## Configuration

No environment variables. Every input is a flag, every default is documented in `--help`, and the lookback window is explicit (`--days`).

Cadence expectations are a JSON file:

```json
{ "recipe": { "every_minutes": 5 } }
```

A bare number is also accepted. A job that stops running is the failure mode nobody notices; a cadence expectation is what turns silence into a finding.

## Deploying it

Run it on a timer, let the exit code do the paging:

```ini
# /etc/systemd/system/tallow-advisory.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/tallow-advisory scan \
  --ledger /var/lib/tallow/receipts.jsonl \
  --mesh /var/lib/tallow/mesh.json \
  --expect /etc/tallow/cadence.json \
  --days 7 --pubkey <hex64>

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/tallow-advisory.timer
[Timer]
OnCalendar=hourly
Persistent=true
```

`Persistent=true` matters: a machine that was off should still run the missed scan once it is back.

Because the crate is read-only and network-free, it is safe to run as an unprivileged user with the ledger mounted read-only — and that is what the unit above should do.

## Design notes

**Why exit codes rather than just text.** An advisory that can only be read by a human is an advisory that is never read at 03:00. The severity-to-code mapping makes it a gate without making it automated remediation.

**Why deterministic detectors first.** An explainable rule with evidence can be argued with and corrected. A model that is right 90% of the time is not acceptable for "your ledger chain is broken".

**Why read-only is structural, not a policy.** The crate has no write path to disable. There is no configuration that turns action on, so there is no configuration mistake that turns it on by accident.

## Verification

```console
$ cargo test -p tallow-advisory
$ cargo test -p tallow-advisory detectors -- --nocapture
$ ./target/debug/tallow-advisory selftest
```

22 test functions in the crate source [measured 2026-10-21]: detector thresholds, evidence shape, severity ordering, exit-code mapping, and the strict "no writes, no network" properties.

## Limits

| Limit | Detail |
|---|---|
| Fixed detectors | Adding a detector is a code change, not a plugin |
| No historical baseline | Thresholds are configured, not learned from the fleet's own history |
| Snapshot inputs | Mesh and peer data must be produced by another tool |
| No paging integration | Exit code only |

## License

MIT — see the repository `LICENSE` and `NOTICE`.
