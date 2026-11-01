# Egress gate — dispositions for the four DEBT rows no lane owns

Measured on `758e5bc` (2026-11-01), production region only, by reading the
enclosing function in each file — not from a grep hit.

The wave-12 lanes own six of the ten DEBT rows (harbor: `stdlib/sync.rs`,
`cli/daemon.rs`; atlas: `signing.rs`; assay: `browser/process.rs`,
`browser/socks_shim.rs`, `cli/fingerprint_audit_cmd.rs`). These four are the
remainder.

| file | what it dials | gated? | disposition |
|---|---|---|---|
| `src/cli/request_plan_cmd.rs` | loopback HTTP GET, via a bespoke `is_loopback_url` check | no — private check, not the register | **GATE** (replace the private check) |
| `src/cli/veil_cmd.rs` | Tor SOCKS proxy (loopback), then an operator-supplied circuit target | no | **EXEMPT** (operator tooling), documented |
| `src/stdlib/mesh.rs` | operator-supplied overlay addresses, `TcpStream::connect` at :482 | no | **OPERATOR DECISION** — gating it locks mesh out |
| `src/stdlib/transfer_net.rs` | sendtallow boundary | no | **EXEMPT** — operator directive 2026-10-26, out of fleet scope |

## 1. `request_plan_cmd.rs` — GATE, and delete the second policy

`loopback_get` (:950) validates the URL with `is_loopback_url` (:932) and only
then dials `TcpStream::connect_timeout` (:972). Two consequences:

- The tree has **two independent loopback policies**: the register, and
  `is_loopback_url`. They agree today by coincidence and will drift. The gate
  should be the single chokepoint: `crate::scope::require(url, "GET")` now
  allows loopback and refuses everything else, so the private predicate is dead
  weight that reads as a control.
- `is_loopback_url` accepts the hostname `localhost` (:942) but `loopback_get`
  then does `addr.parse()` on `authority:port` (:973), which only accepts an IP
  literal — so `http://localhost:8080/` passes the policy check and fails as
  `bad loopback address`. No egress occurs; the refusal names the wrong reason.
  Drop the hostname arm or resolve it; do not leave a policy that says yes and
  a transport that says no.

Deliverable for a lane: `scope::require` before the dial, `is_loopback_url`
removed or narrowed to what the transport really accepts, one test for each
leg (loopback allowed, `10.0.0.1` refused with the register's sentence), and
the DEBT row deleted.

## 2. `veil_cmd.rs` — EXEMPT, but the boundary must be written down

`connect_tor` (:190) dials the SOCKS proxy with `TcpStream::connect_timeout`
(:195) — loopback, and the *destination* is dialed by the proxy through
`socks5_connect(&mut s, &target)` (:214). The target comes from
`--circuit-target`, then `TALLOW_VEIL_CIRCUIT_TARGET`, then the onion in
`ONION_FILE` (`resolve_circuit_target`, :245) — arbitrary, operator-supplied.

This is the same class as `browser/socks_shim.rs`: the process never opens a
socket to the destination. It is also a CLI verb, not a stdlib call, so no
Tallow program can reach it. **Exempt, with the reason stated in the register's
DEBT entry**: the verb's job is to assert a plane, and its target is operator
input by construction. The remaining requirement is that the verb keeps
announcing what it did (`egress: tor rung=… id=…`, `circuit: ok through …`), so
a probe leaves a trace of the plane it proved.

## 3. `stdlib/mesh.rs` — OPERATOR DECISION: gating it is a lockout

`TcpStream::connect(&addr)` at :482 to an operator-supplied overlay address.
The register's methods are HTTP verbs plus `CONNECT`, and `CONNECT` is
**grantable by nobody by default** — deliberately, so a raw socket needs its own
operator line. Gating mesh therefore breaks every mesh run until the operator
enumerates its peers, and mesh addresses are runtime topology, not a fixed host
list.

Two honest options, neither of which a fleet lane may pick alone:

- **A: named plane, not a register host.** Record mesh as its own plane with its
  own chokepoint (a `Mesh.connect` grant that names the overlay), and keep it
  out of the HTTP register.
- **B: gate on `CONNECT` and ship a documented grant step.** Requires the
  operator to add peer lines; a mesh that starts with none must fail with a
  sentence that tells them, not with a silent refusal.

Until the operator picks, the DEBT row stands and the reason in it should say
"awaiting the mesh plane decision", not "operator-supplied addrs" — the current
wording reads as a settled exemption.

## 4. `stdlib/transfer_net.rs` — EXEMPT by directive

Operator directive 2026-10-26 puts the sendtallow boundary out of the ten
agents' scope. Unchanged, not re-litigated here.

## What this changes in the numbers

If 1 lands and the six lane-owned rows land, DEBT goes 10 -> 3 (`veil_cmd`,
`mesh`, `transfer_net`), and `DEBT_CAP` should be lowered in the same commit
that empties the last of them — a cap that stays at 10 while the list is 3
invites the next lane to refill it.
