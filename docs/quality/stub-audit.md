# Stub audit — claims of implementation that the code does not back

Revision audited: `8f7a456` (`run/2.0-20261030-stub-audit`, clean worktree).
Auditor: probe. Read-only on source; no `cargo`, no build, no network.

**Hard limitation, stated up front.** There is no prebuilt `target/{debug,release}/tallow`
in this worktree and this task forbids building one. Every behavioural statement below is
a **static reading of the source at `8f7a456`**, not a program run by me. Where the tree
itself carries a test or fixture that exercises the path, I cite it; where it does not, I
say so. A claim in this report marked *static* has not been executed at this revision.

**Exclusions.** `target/`, `vendor/`, `patches/` (the already-applied commit series — it
quotes the same census strings and would double-count), `.git/`. Everything else was swept.

---

## 1. Raw sweep — counts and first five hits

`-F` fixed-string, case-insensitive for the prose patterns, whole tree minus the exclusions.
"prod" = `*.rs` + `*.tl` only, which still includes in-file `#[cfg(test)]` modules — those
inflate prod counts, so the substantive hits are the ones classified in §2–§5, not the totals.

| pattern | tree | prod | first five prod hits |
|---|---:|---:|---|
| `todo!()` | 10 | **0** | — |
| `unimplemented!()` | 9 | **0** | — |
| `unreachable!("not implemented` | 0 | 0 | — |
| `panic!("not implemented` | 0 | 0 | — |
| `simulated` | 203 | 128 | `stdlib/agent.tl:164`, `:169`, `:175`, `:179`, `:183` |
| `mock` | 761 | 316 | `stdlib/browser.tl:1087`, `:1097`, `:1098`, `:1104`, `:1108` |
| `stub` | 378 | 210 | `src/interp_browser_dispatch.rs:30`, `src/net/ip_pool.rs:176`, `:215`, `:219`, `:225` |
| `placeholder` | 177 | 85 | `src/vault/autotype.rs:111`, `:130`, `:137`, `:140`, `:143` |
| `fake` | 259 | 183 | `src/vault/autotype.rs:718`, `:1018`, `:1042`, `:1145`, `stdlib/jobs.tl:94` |
| `for now` | 46 | 34 | `stdlib/jobs.tl:6`, `src/retention.rs:414`, `src/decay_model.rs:500`, `src/agent_reasoning.rs:27`, `src/net/ip_pool.rs:275` |
| `TODO` | 44 | 3 | `tests/parity_runner.rs:5`, `src/stdlib/osint.rs:4821` (substring of `TODOS`), `crates/tallow-admission/src/lib.rs:42` |
| `FIXME` | 3 | **0** | — (all three are in `docs/`) |
| `XXX` | 37 | 28 | `tests/opsec_corpus_acceptance.rs:231` (`E5xxx`), `crates/tallow-daemon/src/mesh.rs:634`, `:639`, `src/interp.rs:43890`, `src/opsec_gates.rs:44` |

The four hard stub macros are **zero in all source**. All 10 `todo!()` and 9
`unimplemented!()` hits are prose in `docs/` — and every one of them is a *previous census
asserting zero*:

```
docs/operations/STUB-CENSUS-2026-10-16.md:15      - **`todo!()` 0 · `unimplemented!()` 0** across `src/`, ...
docs/operations/PLACEHOLDER-AUDIT-2026-10-15.md:20 | `todo!()` / `unimplemented!()` | **0** |
docs/operations/AUDIT-2026-10-21.md:132           | Zero `todo!()` / `unimplemented!()` | claimed | **confirmed** ...
docs/extraction-engine/RECONCILIATION-2026-10-12.md:111  `todo!()` — **0 files**...
docs/plans/2026-08-04-tallow-compiler-100x-completeness-upgrade.md:202   todo!("await not yet implemented in interpreter")   ← inside a code fence, illustrative
```

Structural flags `simulated: true` / `stub: true` / `placeholder: true` / `fake: true`:
**zero occurrences in Rust or `.tl`.** All 12 hits for that shape are prose. The real
honesty flag is built as a struct field tuple, e.g. `("simulated".to_string(),
Value::Bool(...))`, which appears exactly twice, both honest:

```
src/stdlib/mesh.rs:251   ("simulated".to_string(), Value::Bool(false))
src/stdlib/mesh.rs:582   ("simulated".to_string(), Value::Bool(!connected))
```

Also zero: `@mock` / `@unimplemented` annotations in `stdlib/*.tl`. The literal-mock-body
checker in `src/main.rs:19304-19370` therefore has no offenders **by construction, not by
virtue** — there is nothing annotated for it to find.

---

## 2. Category A — real stubs reachable from a user path

**A count = 4.** All four are reachable from any `.tl` program via `tallow run`, and all
four return success rather than refusing. Three of them contradict an explicit written
claim of a real implementation; the fourth contradicts its own declared return type.

### A1. WireGuard tunnel — simulated unconditionally; Cargo.toml claims the opposite

Claim (`Cargo.toml:191-202`):

> `# ── REAL network-layer backends (feature-gated) ──`
> `# These replace the previous SIMULATED implementations in src/stdlib/net.rs.`
> `# When the feature is OFF, the corresponding stdlib functions return an HONEST error
> rather than faking success (they never pretend a tunnel/circuit exists when one does not).`
> `# WireGuard tunnel (--features wireguard): the WireGuard handshake is the
> Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s pattern, implemented with the `snow` crate...`

Reality (`src/stdlib/net.rs`):
- `tunnel_handshake` (`:1509-1522`) — comment `// Simulated handshake -- transition to
  connected state`, then `state.status = "connected"` and `Ok("connected")`.
- `tunnel_send` (`:1525-1545`) — `// Simulated: return the data length as acknowledgement`,
  returns `data.len()`. No socket, no tunnel, no bytes.
- `tunnel_receive` (`:1548-1563`) — `// Simulated: no data available`, returns `Nil`.
- The `wireguard` feature is **empty** (`Cargo.toml:286  wireguard = []`) and
  `#[cfg(feature = "wireguard")]` occurs **nowhere** in `src/` or `crates/` (0 files).
  `src/stdlib/net.rs` contains no `snow` reference at all; `snow` is used only by
  `src/stdlib/crypto.rs:4919-4951`.
- There is no off-state honest error either: the same fake success runs with the feature
  on and off.

Command a user runs (spelling taken verbatim from the shipped fixture
`tests/fixtures/stealth_net.tl:3,17`):

```
tallow run prog.tl
```
```tl skip:records the removed stub shape; not valid source
fn main() with Net(tunnel_wireguard) {
    let t = net.tunnel_wireguard("vpn.example.com:51820", "base64pubkey==")
    print(t.handshake())     // "connected"      — no handshake happened
    print(t.send("secret"))  // 6                — no bytes left the box
    print(t.receive())       // nil
}
```

What the user sees: `connected`, a byte count, and `nil`. A script that checks
`t.status()` sees `"connected"` and will route real traffic through a tunnel that does not
exist. This is the worst class in the register's own taxonomy — a shape-correct fake
success, not a refusal. *(static; no build in this task)*

### A2. gRPC server/client — in-memory fakes; `tonic` declared and never used

Claim (`Cargo.toml:204-205,287-288`): optional deps `tonic = { version = "0.12",
optional = true, ... }` and `h2 = { version = "0.4", optional = true }`, with
`# Real HTTP/2 gRPC server/client via tonic + h2 — replaces simulated gRPC.` and
`grpc = ["dep:tonic", "dep:h2"]`.

Reality:
- `tonic::` appears **nowhere** in `src/` or `crates/` (0 hits; the `h2::` hits are all in
  the unrelated, genuinely real `src/browser/http2_fingerprint.rs`).
- `#[cfg(feature = "grpc")]` appears **nowhere**. Enabling `grpc` compiles two unused
  dependencies and changes no code path.
- `grpc_server_start` (`src/stdlib/net.rs:1672-1679`) — `/// Start a GrpcServer (simulated
  -- sets running=true)`, sets `state.running = true`, returns `true`. No listener is
  bound; `GrpcServerState.port` and `.routes` are never read outside the struct's own
  bookkeeping (`#[allow(dead_code)]` at `:1601`).
- `grpc_client_connect` (`:1711-1736`) — inserts `connected: true` and returns
  `connected: true` without opening a socket. The `.tl` doc
  (`stdlib/net.tl:246`) says only "Returns GrpcClient struct with connected=true", so the
  declaration is honest about the fake while the struct field is not.

Command: same `tallow run` program with `with Net(grpc_server_create, grpc_client_connect)`.
What the user sees: `server.start()` → `true`, `client = net.grpc_client_connect(url)` →
`connected: true`, for a server that never bound and a client that never dialed.
*(static)*

### A3. Pluggable transports (obfs4 / meek / snowflake) — no transport exists

Claim (`stdlib/net.tl:344-360`), in the declaration the user programs against:

> `// Establishes the transport connection.`
> `// For obfs4: performs obfuscation handshake with bridge`
> `// For meek: establishes domain-fronted HTTPS session`
> `// For snowflake: negotiates WebRTC connection through broker`
> `// Sends data through the transport, returns bytes sent.`
> `// Data is automatically obfuscated per the transport protocol.`
> `// Receives data from the transport. Automatically de-obfuscates received data.`

Reality (`src/stdlib/net.rs`):
- `transport_connect` (`:2032-2041`) — `/// Attempt to connect a transport. Returns
  simulated success.`, `// Simulated connection (real implementation would use ptrs crate /
  WebRTC)`, sets `connected = true`, returns `true`.
- `transport_send` (`:2044`) — increments a counter and returns `len`; nothing is sent.
- `transport_receive` (`:2060`) — `// Simulated receive`, returns `""` unconditionally.
- Constructors (`transport_obfs4_create` `:1952`, `transport_meek_create` `:1979`,
  `transport_snowflake_create` `:2006`) differ only in a type-name string.

Command: `tallow run` with `with Net(transport_obfs4)`, then
`t.connect()` / `t.send("x")` / `t.receive()`. What the user sees: `true`, `1`, `""` — a
censorship-resistance transport that does not connect, obfuscate, or carry bytes.
*(static)*

### A4. `ContainmentAction.*` — returns a struct whose declared honesty field does not exist

Claim (`stdlib/agent.tl:163-188`): `ContainmentResult` is declared with
`simulated: bool`, and the four functions are documented "Simulate host isolation" etc.

Reality (`src/interp.rs:8920-9043`, four arms): each returns `success: true` plus
`dry_run: true` and a message naming dry-run — e.g. `"Host isolation: dry-run mode (compile
and deploy for real containment)"` (`:8944`). The field the declaration promises,
**`simulated`, is never set**, and the field the runtime sets, **`dry_run`, is not
declared**. A caller reading the declared contract (`r.simulated`) gets `nil`; a caller
using the undeclared field gets `true` — and the in-tree test enshrines the latter
(`src/interp.rs:51763-51782` prints `result.dry_run` and asserts `"true"`).

So: the actions do nothing, report `success: true`, and the disclosure channel that the
declaration publishes is missing. The message does disclose dry-run, which is why this is
the mildest A — but it is still a stub returning success on a user path, and its declared
return type is wrong.

Command: `tallow run` on `let r = ContainmentAction.isolate_host("WORKSTATION-42")`.
What the user sees: `success` → `true`; `r.simulated` → `nil`.
*(behaviour confirmed by the in-tree test at `:51763`; `simulated → nil` is static)*

---

## 3. Category B — deliberate refusal with a message (not a defect)

Each of these refuses and says why. Cited verbatim.

| site | message |
|---|---|
| `src/interp.rs:27878`, `:27930` | `LightweightCrypto.encrypt: algorithm '{}' is not implemented in this build (supported: aes256gcm)` — ascon/photon/gift are refused by name, never aliased to AES-GCM |
| `src/stdlib/net.rs:2721` | `net.i2p_connect: I2P is not supported in this build (no SAMv3 bridge implementation)` |
| `src/stdlib/net.rs:240-242` (dispatch comment) | I2P pair refuses "precisely because returning a shape-correct struct would be a fake" |
| `crates/tallow-copy-engine/src/lib.rs:2025`, `:2031` | `metadata policy Security (SELinux contexts / POSIX ACLs) is not implemented in this build; select DataOnly, Timestamps, Attributes or All` (and the `Owner` companion) |
| `crates/tallow-net/src/signaling/client.rs:262` | `websocket signaling transport not implemented; use tcp://host:port or host:port` |
| `src/stdlib/agent.rs:290-293` | `Playbook.execute: step '…' uses action '…', which the stdlib playbook runner does not implement (supported actions: noop, record, fail). No simulated success.` |
| `src/browser/ml/embeddings.rs:65-75` | `real-ml is not shipped: the candle-based BGE-small-en-v1.5 loader is not implemented in this build. Use the default deterministic FNV-1a mock … it is NOT semantic, only reproducible.` |
| `src/net/ip_pool.rs:287-292` | `ip_pool: io_uring backend is not implemented in this build; using epoll. Throughput characteristics are epoll's, not io_uring's.` (warning, then a working fallback — disclosed, not silent) |
| `src/vault/recovery.rs:38-42` | SLIP-39 absence stated in module docs; no API claims it |

Near-misses worth recording because they are honest by construction and should not be
"fixed" into stubs:

- `net.tor_new_circuit` (`src/stdlib/net.rs:2685-2711`) is **real**: it probes the control
  port, issues a NEWNYM, and on failure returns `… — no rotation performed`.
- `HarRecorder` reports `recording: false` (`src/interp.rs:23996`); the mesh plane derives
  `simulated` from `!connected` (`stdlib/mesh.rs:582`). Both tell the truth in the value the
  caller reads.
- `Page.add_style_tag` / `emulate_media` / `emulate_vision` (`src/interp.rs:18832-18895`)
  now call real CDP and only set `applied: true` on a CDP `Ok`. The stale register text for
  row #52 ("descriptive-echo arms") understates these.

---

## 4. Category C — comment, test, doc or fixture text only (no behaviour claimed)

- **The bulk of the raw counts.** Of 761 `mock` hits, 172 are in `tests/`+`examples/` and
  309 in `docs/`; the `mock_status` / `mock_body` hits in `stdlib/browser.tl:1087-1108` are
  a *request-interception feature* (mocking HTTP responses on purpose), not a stub.
  `placeholder` in `src/vault/autotype.rs:111-176` is the autotype template syntax
  (`{USERNAME}`, `{TOTP}`) — the word is the feature.
- **`src/browser/affiliate.rs:57-67`** — eight default affiliate tags are placeholders
  (`tallow-20`, `tallow`); the comment states no affiliate account exists under that name
  and deployments must call `set_tag`. Disclosed in source and in the register; it is a
  documented default with no runtime error, so a wrapped link earns nothing silently. Keep
  as documented default (register convention explicitly allows this) — but a reader of the
  wrapped URL cannot tell.
- **`src/foresight_adapter.rs:24-106`** — three hand-written placeholder records, each
  summary string saying "placeholder … Not fetched data". Honest fixtures; no user path.
- **Stale comment that understates real code** (`crypto.rs:127`): the dispatch table is
  annotated `// HSM/PKCS#11 (KINF-01) -- simulated`, but `crypto_hsm_connect/sign/encrypt/
  list_keys` (`:3132-3255`) are a real `cryptoki` PKCS#11 implementation that opens a
  module, logs in, and calls `C_Sign`/`C_Encrypt`, refusing when no token is present. The
  label is wrong in the *conservative* direction — the inverse of the defect this audit
  hunts, and equally able to mislead a reader.
- **The census documents.** `docs/operations/STUB-CENSUS-2026-10-16.md`,
  `PLACEHOLDER-AUDIT-2026-10-15.md`, `AUDIT-2026-10-21.md` and
  `RECONCILIATION-2026-10-12.md` all assert 0 `todo!()`/`unimplemented!()`. That specific
  assertion **holds** at this revision (§6). They do not assert that no user path returns a
  fake success, and that is where the four A findings live.

---

## 5. Category D — dead code, unreachable from any user path

| site | why unreachable |
|---|---|
| `src/browser/compliance.rs:100-150` (`ComplianceManager`) | referenced only by its own unit tests (`:329-362`). It seeds `last_reviewed: 0` and ToS URLs on `.example` domains for Amazon/Walmart/Target/BestBuy/Costco/Kroger, and reports `public_data_allowed: true` — a compliance record backed by placeholders. Harmless only because no user path reaches it; the moment it is wired it becomes an A. |
| 17 root-`src` modules (`ach_matrix`, `unknowns`, `spawn_isolation`, … `bands`, register #69) | `pub mod` in `src/lib.rs`, no `.tl` surface, no cross-module callers. |
| `src/browser/ml/*` (`EmbeddingEngine` FNV-1a mock) | no dispatch in `src/stdlib/` or `src/interp_browser_dispatch.rs`; the only honest-by-documentation mock in the tree. |
| `src/net/ip_pool.rs:215-230` (`StubDpdkBackend`) | every method errors; named `Stub` on purpose; only reachable when `BackendType::Dpdk` is selected (register #68). |
| `src/finance_ir.rs` CUDA section | emits CUDA C text with no execution path; field renamed `cuda_offload_candidates` so it cannot be read as GPU execution (register #64). |

---

## 6. What I attacked and what held — evidence the surviving claims are real

Attacks that produced nothing are the evidence. Each was run at `8f7a456`.

1. **Hard-macro census.** `rg '\btodo!\(|unimplemented!\(|unreachable!\("not implemented|
   panic!\("not implemented'` over `*.rs` + `*.tl` → 0 hits. The "0 stubs" macro claim is
   true and is true for the right reason (the code exists), not because the string is
   spelled differently (`NotImplemented`, `not implemented` prose were swept separately —
   those hits are refusals, §3).
2. **Declaration vs implementation, whole stdlib.** Extracted all 731 unique
   `native fn` names from `stdlib/*.tl` and checked each against an identifier index of all
   862 `src/**/*.rs` + `crates/**/*.rs`. **0 declared names are absent** — including after
   allowing for prefix-stripped dispatch keys (`page_wp_login` → `"wp_login"`).
3. **Browser surface specifically.** 244 declarations in `stdlib/browser.tl`; 8 looked
   unwired under a naive string test and all 8 resolve under their qualified dispatch keys
   (`Mouse.dblclick` at `src/interp.rs:11077`, `Keyboard.press` `:10952`,
   `Keyboard.shortcut` `:11021`, `Mouse.drag` `:11185`, `Mouse.wheel` `:11168`,
   `AccessibilityAudit.check_contrast` `:24710`, `BrowserIsolation.check_isolation`
   `:30379`). Register row #88's three named failures (`browser.find_sitemaps`,
   `browser.check_contrast`, `browser.dblclick`) are namespace-spelling errors on the
   *caller* side — the method names exist.
4. **WordPress / Wordfence surface** (row #88's 23 declared-but-unwired functions). All
   seven `page_wp_*` / `page_*wordfence*` names are dispatched as
   `("Page", "wp_login")` … at `src/interp.rs:18083-18363`, backed by real implementations
   in `src/browser/wordpress_auth.rs` and `src/browser/wordfence_bypass.rs`. The row is
   stale.
5. **Literal-mock-body checker.** `@mock`/`@unimplemented` count in `stdlib/*.tl` = 0, so
   the checker at `src/main.rs:19454` has no input. Passing there is not evidence of
   correctness.
6. **Fabricated-state sweep.** `connected = true | running = true | status =
   "connected"` across `src/stdlib`, `src/browser`, `src/mesh` — every hit is either the
   A1–A3 cluster or a truthful scheduler/bookkeeping field (`src/browser/scheduler.rs`
   crash-recovery paths, which un-set `running` on the next daemon tick).

**Two false positives I discarded, recorded so the next auditor does not re-spend the
time:** (a) the seven `page_wp_*` functions, which my first "absent from Rust" test
flagged because dispatch keys are prefix-stripped; (b) the eight browser methods, which my
first "no quoted-string key" test flagged because the keys are `Kind.method`. Both were
method errors, not tree defects.

---

## 7. Verdict

**Category A count = 4** (A1 WireGuard tunnel, A2 gRPC, A3 pluggable transports,
A4 ContainmentAction). A1–A3 share one root cause: `Cargo.toml:191-205` describes a
feature-gated real-backend layer that was never written — two of the three features are
declared and gate nothing (`wireguard = []` empty; `grpc` pulls `tonic`/`h2` that no code
references), and the "honest error when the feature is OFF" that the manifest promises does
not exist in any state. A4 is a declared-vs-returned field mismatch on four functions that
return `success: true`.

Therefore **"no stubs remain" cannot be claimed at `8f7a456`.** The macro-level claim
(0 `todo!()` / 0 `unimplemented!()`) is true; the capability-level claim is false in the
networking surface and, more damagingly, the manifest *states* the opposite in writing.

Minimum work to reach A = 0:
- A1/A2/A3 — pick one per capability and state it in the value, not only in a comment:
  either implement the backend (the `snow` dependency is already present for A1), or make
  each of the fifteen entry points listed for A1–A3 (`tunnel_wireguard`,
  `Tunnel.{handshake,send,receive}`, `grpc_server_create`,
  `GrpcServer.{route,start,stop}`, `grpc_client_connect`,
  `transport_{obfs4,meek,snowflake}`, `Transport.{connect,send,receive}`) return the
  refusal shape used by `net.i2p_connect:2721` — and delete `Cargo.toml:191-205,282-288`.
- A4 — add `simulated: true` (or `dry_run`) to the `ContainmentResult` declaration in
  `stdlib/agent.tl:164`, or drop the undeclared field from the four arms at
  `src/interp.rs:8942,8970,9004,9032`.

---

## 8. Reproduce

```bash
cd /workspace/tallow-worktrees/probe            # 8f7a456

# §1 counts
rg -n -i -F 'todo!(' -g '*.rs' -g '*.tl' -g '!target' -g '!vendor'          # 0
rg -n -i -F 'stub'   -g '*.rs' -g '*.tl' -g '!target' -g '!vendor' | wc -l  # 210
rg -n '"simulated"\.to_string\(\)' src/                                     # 2, both mesh

# A1 the false manifest claim
sed -n '190,206p;282,289p' Cargo.toml
rg -n 'cfg\(feature *= *"wireguard"\)|cfg\(feature *= *"grpc"\)' src/ crates/  # 0
rg -n '\btonic::' src/ crates/                                                # 0

# A1-A3 the bodies
sed -n '1508,1563p;1671,1680p;1711,1736p;2032,2075p' src/stdlib/net.rs

# A4 the field mismatch
sed -n '164,188p' stdlib/agent.tl
sed -n '8920,9043p' src/interp.rs
sed -n '51763,51782p' src/interp.rs
```

Author: probe · 2026-10-28 · revision `8f7a456` · static analysis only, no build performed.

---

## 9. Resolution — A1–A4 closed

Branch `run/2.0-20261031-stubfix`, commit `baf9a20`. The mechanism everywhere is
the same: the capability refuses in its **return value**, in the shape already
used by `net.i2p_connect` (`src/stdlib/net.rs`), and no fake state registry
survives behind it. All four build/test commands were run at `baf9a20` and
exited 0; the dependency grep returned no output.

- **A1 RESOLVED — `baf9a20`.** `tunnel_wireguard`, `Tunnel.{handshake,send,receive,status,close}`
  return `Err("net.tunnel_wireguard: WireGuard is not supported in this build
  (no WireGuard/Noise_IKpsk2 transport backend)")` (method text names the method
  and the backend). `TunnelState`/`TUNNELS`, the `status = "connected"`
  transition and the byte-count acknowledgement were deleted. Cargo.toml: the
  "REAL network-layer backends" paragraph and the empty `wireguard = []` feature
  are gone. User path: `tallow run tests/fixtures/unsupported_net.tl` prints the
  refusal on stderr and exits **1**.
- **A2 RESOLVED — `baf9a20`.** `grpc_server_create`, `GrpcServer.{route,start,stop}`,
  `grpc_client_connect`, `GrpcClient.{call,close}` return the same refusal shape
  naming the missing HTTP/2 gRPC backend; `GRPC_SERVERS`/`GRPC_CLIENTS`, the
  `running = true` transition and the HTTP-POST "simulation" were deleted.
  `tonic` is removed from Cargo.toml (no code referenced it) and `grpc = [...]`
  is removed. `h2` remains only because `http2-fingerprint` uses it, and the
  dependency is annotated to say so.
- **A3 RESOLVED — `baf9a20`.** `transport_{obfs4,meek,snowflake}` and
  `Transport.{connect,send,receive,close}` refuse by name ("… pluggable
  transport is not supported in this build (no … bridge implementation)");
  `TRANSPORTS`/`TransportState` and the simulated connect/send/receive were
  deleted. The `stdlib/net.tl` comments no longer describe obfuscation, domain
  fronting or WebRTC negotiation that never happens.
- **A4 RESOLVED — `baf9a20`.** All four `ContainmentAction.*` arms now set
  `simulated: Bool(true)` (keeping `dry_run: true`), so the declared field at
  `stdlib/agent.tl:174` exists on the returned value. The in-tree test prints and
  asserts `result.simulated`, not only `result.dry_run`. The declaration comment
  states that `success: true` means the dry-run record was produced, not that
  containment happened.

Category A count at `baf9a20`: **0**.

Verification at `baf9a20`:

```
cargo check --lib                                  # exit 0
cargo test --test stdlib_bridge_returns            # 6 passed; 0 failed
cargo test --test api_parity_native                # 3 passed; 0 failed
cargo test --lib containment                       # 3 passed; 0 failed
grep -rn "wireguard\|tonic" Cargo.toml             # no output, exit 1
```

Not done here, by design: no WireGuard, gRPC or obfs4/meek/snowflake backend was
written. A refusal is the honest state until one is; the manifest no longer
claims otherwise.

