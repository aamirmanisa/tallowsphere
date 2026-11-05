# Egress configuration — every mechanism is optional

> **Docs truth label:** describes the egress controls and how to set each one. It is
> not a claim that any opt-out is safe for your situation, and not legal advice.

Tallow's egress behaviour is configured entirely by environment variables. **Nothing
is compiled in, nothing is unchangeable, and every gate has an explicit override.**
The defaults are the secure ones; opting out is always possible and always a single
variable.

The design rule: *optional* means "you can turn it off on purpose", not "it is off
until you turn it on". A control that is off by default is not a control.

## The decision order

`egress_proxy_url()` resolves in this order, first match wins:

1. `TALLOW_PROXY=<url>` — an explicit proxy. **Wins over everything.**
2. `TALLOW_ALLOW_DIRECT=1|true|yes` — deliberate opt-out, connects directly.
3. otherwise — Tor, at `TALLOW_TOR_SOCKS_PORT` (default 9050), with a per-run circuit
   identity bound into the SOCKS credentials.

An empty or whitespace-only `TALLOW_PROXY` counts as unset, so clearing the variable
in a shell does not silently mean "no proxy".

## Every variable

| Variable | Default | Effect |
|---|---|---|
| `TALLOW_PROXY` | unset | Explicit proxy URL (`http://`, `https://`, `socks5h://`). Highest precedence. |
| `TALLOW_ALLOW_DIRECT` | unset (fail-closed) | `1\|true\|yes` → connect directly, no proxy, no Tor. Also exempts plain DNS on `:53`. |
| `TALLOW_TOR_SOCKS_PORT` | `9050` | Tor SOCKS port. Set to `9150` for Tor Browser or a per-user `tor` unit. |
| `TALLOW_TOR_ISOLATE` | unset (isolated) | `0\|false\|no` → one shared Tor circuit instead of one per run. |
| `TALLOW_TOR_STREAM_ID` | minted per run | Runner-assigned circuit identity, `[A-Za-z0-9_-]{1,64}`. |
| `TALLOW_TOR` | n/a | Accepted, now redundant — Tor is the default. Kept to document intent. |

Junk values never open a leak: `TALLOW_ALLOW_DIRECT=lol` stays fail-closed, and
`TALLOW_TOR_SOCKS_PORT=abc` falls back to 9050 rather than disabling Tor.

## Common configurations

**Direct, no anonymity** — the "just fetch it" case:

```bash
TALLOW_ALLOW_DIRECT=1 tallow run-plan ...
```

**Tor Browser's port** — for a box where no system Tor daemon is running:

```bash
TALLOW_TOR_SOCKS_PORT=9150 tallow run-plan ...
```

**A specific proxy** (corporate, rotating pool, or your own Tor instance):

```bash
TALLOW_PROXY=socks5h://127.0.0.1:9150 tallow run-plan ...
```

**Several fetches, one circuit** — cheaper, less isolated:

```bash
TALLOW_TOR_ISOLATE=0 tallow run-plan ...
```

## What is still required, and why

These are *not* egress settings, and no variable switches them off:

- **`--approve-live` plus a compliance report bound to the manifest sha256** for
  `network-scope live`. Required so a live fetch is an explicit act with a record.
  The report must name the sha256 of the manifest you are actually running;
  approving one manifest cannot authorise another.
- **The scope register** (`configs/tallow/scope/authorized-hosts.toml`,
  deny-by-default). A host not listed is refused before a socket is opened. Adding
  a host is one TOML entry.
- **The egress refusal for a configured-but-broken proxy.** If you set
  `TALLOW_PROXY` to something unusable, Tallow refuses rather than falling back to
  the box IP. That is the point: a typo must not become an anonymity leak.

If you want a host reachable, add it to the register. That keeps the audit trail —
`run-plan` writes a hash-bound artifact set per run, and the register records who
authorised what and when.

## Failure symptoms and their real causes

- `Connection refused (os error 111)` on every target, with `policy_blocked: true`
  reported — almost always the Tor port. Nothing listening on 9050 while your Tor is
  on 9150. Set `TALLOW_TOR_SOCKS_PORT`.
- `compliance_gate_report_required` — pass `--compliance-gate-report`, or you are
  running `--network-scope live` without the report.
- `not-listed — refused` — the host is not in the scope register.
- `the compliance gate report is bound to a different source manifest` — the manifest
  changed after the report was generated. Re-generate the report.
