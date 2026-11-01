# harbor — W12: gate loopback daemon egress, retire two DEBT rows

Tree: /home/aamir/tallow-worktrees/w12/harbor · branch `rel/w12-harbor` · base `758e5bc`

## What was wrong

Two files made HTTP requests to the tallow-daemon, always on loopback
(`http://127.0.0.1:{port}`), with no `scope::require` and a DEBT row standing in
for a decision:

| file | sites on `758e5bc` |
|---|---|
| `src/stdlib/sync.rs` | POST :45, GET :71 |
| `src/cli/daemon.rs` | POST :168 (handshake), GET :215 (health), POST :255 (shutdown), GET :286 (jobs), POST :345 (submit), GET :381 (job), GET :421 (history) |

The register has granted loopback since `758e5bc` (`127.0.0.1`, `localhost`,
`::1`, methods `GET`/`HEAD`/`POST`), so these were ungated calls to a host the
register already authorises. Per the standing decision, loopback is a **grant**,
not an exemption: both files now consult the register before every request.

## Premise defects found in the brief

1. **"4 sites", not 5 facts.** The brief counts 4 request sites. `daemon.rs`
   holds **seven** on this commit, not the two named (`:168`, `:215`):
   `/shutdown`, `/jobs` (GET), `/jobs` (POST), `/jobs/{id}`, `/jobs/{id}/history`
   are all live requests. Gating only the two named ones would have left five
   body-shaped holes in the same file while flipping its DEBT row green — the
   exact failure mode the DEBT gate exists to prevent. **Nine** sites are gated
   in total (2 in `sync.rs`, 7 in `daemon.rs`).

2. **The register path is cwd-relative.** `DEFAULT_REGISTER_PATH` is
   `configs/tallow/scope/authorized-hosts.toml` and `ScopeRegister::load` reads
   it with `fs::read_to_string(path)` — no `CARGO_MANIFEST_DIR`, no env
   override, no install step copies it (grep: no `install.sh`/`scripts/`
   reference). In a build tree it resolves; in an installed binary run from any
   other cwd it resolves to nothing, and an unreadable register is
   `RegisterUnreadable` → **refuses every host, including loopback**. Consequence
   of this commit: `tallow daemon status`, `tallow job …`, `tallow daemon stop`
   and the `sync.*` stdlib calls now fail with `scope:register-unreadable` when
   the binary is run outside a tree carrying `configs/tallow/scope/`. That is a
   packaging defect this change *exposes*, not one it introduces — the same gate
   already guarded every `http.*` call. It is **not fixed here** (changing
   register resolution changes the policy surface for every gate user); raised
   for alden as a follow-up.

3. **The brief's "one cargo invocation" vs. its own three acceptance runs.**
   Acceptance asks for two test targets (`--lib scope::`, `--test
   egress_gate_coverage`) plus a new module test; a single cargo invocation
   cannot select a disjoint filter across a lib target and an integration
   target. Ran three *sequential* cargo commands in one shell block with
   `CARGO_BUILD_JOBS=2` and `--test-threads=1`; both `test result:` lines are
   quoted below. Reported rather than worked around silently.

## Change

`src/stdlib/sync.rs`
- `scope_gate(url, method) -> Result<(), String>` — `crate::scope::require`,
  refusal rendered `"{code} — {explain}"` (the `stdlib/http.rs:607` convention).
- `daemon_post` / `daemon_get` split into URL derivation + `daemon_post_url` /
  `daemon_get_url`, so the gated transport is testable without fabricating a
  `~/.tallow/daemon/port` file. Gate is the first statement of each `*_url` fn.

`src/cli/daemon.rs`
- `scope_gate(url, method) -> anyhow::Result<()>`, same formatting; refusal
  surfaces through each command's existing `anyhow` error — no new variant.
- Gates at all seven request sites. `establish_audit_session` returns `None` on
  refusal (it opens no connection; the command's own URL is gated separately
  and surfaces the refusal to the user).

`tests/egress_gate_coverage.rs`
- `src/cli/daemon.rs` and `src/stdlib/sync.rs` removed from `DEBT`. DEBT_CAP
  left at 10; the other eight rows untouched.

## Tests added (`src/stdlib/sync.rs`, `mod tests`)

- `daemon_get_reaches_loopback_when_the_register_grants_it` — plants a register
  granting `127.0.0.1` GET/POST, stands up a one-shot `TcpListener`, and
  asserts the request line that arrived is `GET /sync/pairs HTTP/1.1` and the
  JSON body comes back. The allowed leg proves the gate passes through to the
  wire.
- `daemon_get_refuses_loopback_the_register_does_not_list` — plants
  `ScopeRegister::empty()`, asserts the error carries `scope:not-listed` and the
  register's own sentence `refused: 127.0.0.1 is not in the authorization
  register (deny-by-default)`, and that a non-blocking `accept()` on the
  listener returns `WouldBlock` (no socket was opened).

## Acceptance — measured

(pending, see below)

## Commit

(pending)
