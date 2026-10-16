# Config Lock — governance + operator procedure

> status: active (2026-09-28). Runtime truth: `/usr/local/bin/tallow-config-lock*.sh`,
> `/opt/sendtallow/config-lock/`, and the commands below. This doc is what the
> lock scripts mean by "read docs/operations/config-lock.md first".

## What it is

The production box's stability-critical configuration is protected by three layers:

1. **Immutable attribute** (`chattr +i`) on every path in `files.list` (40 files as of 2026-09-28).
2. **sha256 manifest** (`manifest.sha256`) with superseded copies in `history/` — content drift detection.
3. **15-minute drift verifier** (`tallow-config-lock.timer` → `tallow-config-lock-verify.sh`): checks each path for `MISSING` / `CONTENT_CHANGED` / `UNLOCKED`; exit 1 pages via the relay alert path. An open maintenance window (`/run/tallow-config-unlocked`) suppresses paging and records `maintenance:true` in state.

## Scope rule — what is locked, and what is not

- **Locked:** local stability-critical config, units and ops scripts — relay (`relay.toml`, unit + drop-ins, `env`, `web-pass-hash`, cert-sync), `Caddyfile`, `turnserver.conf`, status-gen, `host-firewall.sh`, the lock/alert chain itself (self-protection), transfer + chat canaries, the ops-portal compartment (unit + canaries + `wg0.conf` + `wg-portal.conf`), core-dump protections (`LimitCORE=0`).
- **Not locked (by scope rule):** package-managed units (coturn, caddy — follow the package manager's integrity model); binaries/releases (versioned artifacts with their own rollback path); data (`/var/lib/...`), Hermes state.
- **The lock set is locked** (self-protection): editing `files.list` requires a window, otherwise the verifier would silently check fewer files.

## The maintenance window — the ONLY way to change locked files

Approved purposes only: hardware/software upgrades; new non-breaking features.
Preconditions: root, a reason string, and a backup of every file you will touch.

```bash
# 0) FRESH check + backup the files you will touch
tallow-config-lock-verify.sh; echo rc=$?     # expect rc=0
cp -a /etc/caddy/Caddyfile /root/backups/Caddyfile.$(date -u +%Y%m%dT%H%M%SZ)

# 1) OPEN the window (records WHO/WHY; verifier paging suspended)
tallow-config-unlock.sh --reason "<approved purpose>"

# 2) make the change; validate BEFORE any reload
caddy validate --config /etc/caddy/Caddyfile     # caddy
dnsmasq --test                                   # dnsmasq
systemctl daemon-reload                          # units (after install)
# (WireGuard: `wg-quick strip wg0 >/dev/null` for syntax)

# 3) reload/restart the affected service, then probe it (expect 200s; probe
#    paths on mesh doors expect the cover 404s — that is correct)

# 4) CLOSE the window — re-lock, new manifest, audit line, window flag removed
tallow-config-lock.sh apply --reason "<what changed>"

# 5) verify clean + evidence
tallow-config-lock-verify.sh; echo rc=$?     # expect rc=0
cat /opt/sendtallow/config-lock/state.json
```

Every window ends with a **receipt**: the audit log line(s), the manifest
history entry, and a committed receipt doc (repo artifacts, `TMM-<ID>` style).

## Reading state

- `state.json` — verifier output `{"ok":true,...,"maintenance":false}`; `state.drift.txt` exists only while drift is present.
- Audit: `/var/log/tallow-config-lock.log` — one line per unlock/relock, including reason, operator, and changed-file list.
- History: `/opt/sendtallow/config-lock/history/` — timestamped superseded manifests.
- Journal: `journalctl -u tallow-config-lock.service -n 50`.

## Failure modes

- **Drift page (`CONFIG LOCK DRIFT`)** — read `state.drift.txt`; restore the file to the manifest-known content or run an approved window for the intended change. Never `chattr -i` outside a window (that is exactly what the verifier catches).
- **Window left open** — `/run/tallow-config-unlocked` exists → verifier quiet. Re-lock anyway; `apply` removes the flag.
- **MISSING file** — restore before re-locking (`apply` aborts — never half-locks).

## Worked example

`artifacts/tallow-mega-mesh-2026-09-27/window-harness/W1-RUNBOOK.md` — a fully
staged window (pre-capture → unlock → backup/byte-proof → apply → validate →
reload → smoke + acceptance compare → re-lock → receipt) for the W1 mesh-DNS +
TLS-1.3 change. The same shape applies to any locked-file change.
