<div align="center">

# tallow-daemon

**A background service that keeps directories in sync, runs jobs, and tells you the truth about both over HTTP.**

![api](https://img.shields.io/badge/api-HTTP%20%C2%B7%20loopback%20by%20default-1f6feb?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-black?style=flat-square)

</div>

---

Sync tools usually fail in the same three ways: a conflict is resolved by whoever wrote last, a crash mid-transfer leaves an ambiguous state, and the UI shows a progress bar that means nothing. This daemon is built around the opposite assumptions — conflicts are recorded and wait for a decision, transfers resume from a journal, and health is a state you can query rather than a light that is on.

## What it is

| Area | Behaviour |
|---|---|
| **Sync pairs** | Create, list, inspect, pause, resume, delete; per-pair history |
| **Conflict handling** | Conflicts are detected and listed (`/sync/conflicts`); resolution is an explicit call, never "newest wins" |
| **Jobs** | Create, list, inspect, per-job history; execution delegated to `.tl` scripts |
| **Delta transfer** | Merkle trees over 4 KiB blocks; only changed blocks move |
| **Resume** | A journal records progress, so a restart continues instead of restarting |
| **Mesh** | Configure mesh peers, inspect status and peer list per mesh |
| **Events** | Server-sent events stream at `/events` |
| **Health** | `/health` reports process and subsystem state |
| **Admission** | `/auth/handshake` — the mesh-door handshake |
| **Revocation gate** | Refuses work for revoked identities, with `TALLOW_DAEMON_REVOCATION` selecting the mode |

## What it is not

- **Not a public API.** It binds an OS-assigned port on the local interface and writes that port to `<data-dir>/port`. Exposing it requires a deliberate front end.
- **Not a sync algorithm of its own.** Chunking, compression and wire messages come from `tallow-protocol`; this crate decides *when* and *whether*.
- **Not a scheduler with cron semantics.** Job timing belongs to `tallow-jobs`; the daemon dispatches and records.

## Quick start

```console
$ cargo build -p tallow-daemon
$ ./target/debug/tallow-daemon            # foreground; port written to the data dir
$ cat ~/.local/share/tallow/port
$ curl -s http://127.0.0.1:$(cat ~/.local/share/tallow/port)/health
```

As a service:

```console
$ tallow-daemon install     # writes and enables the systemd unit
$ tallow-daemon start
$ tallow-daemon status
$ tallow-daemon stop
$ tallow-daemon uninstall
```

### The API in practice

```console
$ PORT=$(cat ~/.local/share/tallow/port)

# a sync pair
$ curl -s -X POST http://127.0.0.1:$PORT/sync/pairs \
    -H "Authorization: Bearer $TALLOW_DAEMON_TOKEN" \
    -d '{"source":"/home/me/docs","target":"/mnt/nas/docs"}'

# what is happening
$ curl -s http://127.0.0.1:$PORT/sync/pairs/<id>/status

# a conflict, and a decision
$ curl -s http://127.0.0.1:$PORT/sync/conflicts
$ curl -s -X POST http://127.0.0.1:$PORT/sync/conflicts/resolve -d '{…}'
```

## Configuration

| Variable | Meaning | Default |
|---|---|---|
| `TALLOW_DAEMON_TOKEN` | Bearer token for the API. **Empty is a hard error**, never a silent default | required for authenticated calls |
| `TALLOW_DAEMON_REVOCATION` | Revocation gate mode | see `revocation_gate::GateMode` |
| `TALLOW_DAEMON_TALLOW_BIN` | Which `tallow` binary executes job scripts | resolved from the environment |
| `TALLOW_DAEMON_JOB_WORKSPACE` | Workspace root for job execution | data dir |
| `TALLOW_DAEMON_SCRIPT_SANDBOX` | Sandbox mode for scripts | documented in `executor.rs` |
| `TALLOW_DAEMON_SCRIPT_WRITE_ROOTS` | Allowed write roots for scripts | none |
| `RUST_LOG` | Log filter | `tallow_daemon=info` |

| Setting | Default | Note |
|---|---|---|
| Concurrency | 4 | Tested as a stable default |
| Retry base / max | 1000 ms / 60000 ms | Exponential with a ceiling |

Data lives in the platform data dir (`~/.local/share/tallow` on Linux): the database, the port file, and job state.

## Deploying it

`tallow-daemon install` writes a unit that runs as the invoking user. For a server, run it under a dedicated account and keep the data dir on a filesystem you back up:

```ini
[Service]
ExecStart=/usr/local/bin/tallow-daemon run
Environment=TALLOW_DAEMON_TOKEN=<read from a credential file, not inline>
Environment=RUST_LOG=tallow_daemon=info
User=tallow
Restart=always
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/tallow
```

Rules the code enforces, which your deployment must not defeat:

- **Never put the token on the command line.** It is read from the environment (or a credential source) precisely so it does not appear in `ps`.
- **An empty token is an error.** The daemon refuses rather than running unauthenticated.
- **Keep the port file.** Clients discover the service through it; hard-coding a port fights the design.
- **Put the data dir on real storage.** A journal on tmpfs is a resume that survives nothing.

## Design notes

**Why conflicts are explicit.** A sync engine that resolves silently is a sync engine that loses data politely. Detection is cheap; deciding is the user's call, so the API records the conflict and waits.

**Why a journal.** Resume without a record of what was already written is a guess that happens to look like progress.

**Why the port is assigned by the OS.** Two daemons on one host, or a port already taken, stop being failure modes; the port file is the contract.

## Verification

```console
$ cargo test -p tallow-daemon
$ cargo test -p tallow-daemon --lib -- --test-threads=2
```

184 test functions in the crate source [measured 2026-10-21], covering delta block computation, conflict detection, journal resume, token handling (including the empty-token error), revocation gate modes, and route behaviour.

## Limits

| Limit | Detail |
|---|---|
| Loopback only | Not designed to face a network directly |
| Single node | No clustering; mesh peers are peers, not replicas of the daemon |
| Conflict resolution is manual | By design, but it means unattended syncs can accumulate conflicts |
| SQLite-backed state | Fine for a workstation or small server; not a shared database |

## License

MIT — see the repository `LICENSE` and `NOTICE`.
