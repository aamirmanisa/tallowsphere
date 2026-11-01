# assay — W12 browser/CLI DEBT triage (3 rows)

Lane: triage, proposal only. Tree `/home/aamir/tallow-worktrees/w12/assay`,
branch `rel/w12-assay`, HEAD `758e5bc`. No source edited, no `cargo`
invocation run (the brief forbids it, so there is **no `test result:` line to
quote** — every claim below is a read of the code at `758e5bc`, not a run).

## Verdict table

| file | dials | gateable? | verdict | grant needed |
|---|---|---|---|---|
| `src/browser/process.rs` | `127.0.0.1:<own launch port>`, literal; issues a real `GET /json/version` | yes — the verb is `GET` and loopback already carries it | **GATE** | none (already shipped) |
| `src/browser/socks_shim.rs` | `upstream` = the SOCKS endpoint named in the per-run proxy URL (Tor `127.0.0.1:9050`); never the CONNECT destination | only by breaking per-run circuit isolation | **EXEMPT** | none |
| `src/cli/fingerprint_audit_cmd.rs` | the configured proxy endpoint (`TALLOW_PROXY`/`TALLOW_TOR`, default `127.0.0.1:9050`); zero bytes | expressible as `CONNECT`, but withholding it turns the probe into a lie | **EXEMPT** | none |

Net effect if the merge owner applies the earned patch: DEBT goes 10 → 9
(`DEBT_CAP` 10 → 9), and the one row that makes an actual HTTP request stops
being ungated.

## Premises in the brief that are wrong

1. **"there is no register verb for a bare TCP connect"** — false. `CONNECT`
   is a member of `GRANTABLE_METHODS` and is *defined* as exactly that verb:
   `docs/spec/scope-register.md:29-36` — "`CONNECT` is permission to open a raw
   TCP socket to the listed host — the verb `Scanner.scan` presents to the gate
   before `TcpStream::connect_timeout`". It is not HTTP CONNECT (RFC 9110).
   It is also already in production use for precisely this shape:
   `src/main.rs:2355` `tallow::scope::require(relay_addr, "CONNECT")`.
   So the question in each row is never "is there a verb", it is "does granting
   CONNECT here preserve the behaviour the dial exists for".
2. **"`devtools_probe` around :915-951"** — false. There is no symbol
   `devtools_probe` in the file. The function is
   `discover_ws_url_via_http`, declared at `src/browser/process.rs:913`; the
   connect is at `:936`.
3. **"socks_shim.rs — `upstream` is the local SOCKS listener"** — false in a
   way that matters. `upstream` is the *upstream* SOCKS endpoint (Tor), resolved
   from the credentialed proxy URL; the local listener is a different socket,
   bound at `127.0.0.1:0` (`src/browser/socks_shim.rs:104`). The relay accepts
   on the listener and dials `upstream`; the two are on opposite sides.
4. **"TCP liveness probe of local Tor SOCKS"** (`fingerprint_audit_cmd.rs`) —
   true only by default. The endpoint is derived from `TALLOW_PROXY` /
   `TALLOW_TOR` (`:1494`, `:1508-1511`) and is **not** constrained to loopback;
   `127.0.0.1:9050` is the fallback when no proxy URL resolves. The DEBT reason
   string understates what the code can dial (see row 3, finding F2).
5. Everything else in the brief held: all three files are DEBT rows
   (`tests/egress_gate_coverage.rs:78-119`), none of the three contains
   `scope::require` (grep, 0 hits, `758e5bc`), and loopback now grants
   `GET`/`HEAD`/`POST` but not `CONNECT`
   (`configs/tallow/scope/authorized-hosts.toml`, three loopback entries).

A note the merge owner needs before touching anything: the coverage test is
**per-file and binary** — a file is "gated" if `scope::require` appears anywhere
in its production region, and `debt_list_is_not_stale` (`:300`) fails if a
listed file *is* gated. So gating one row is a two-file change: add the call,
delete the DEBT entry, lower the cap. Adding the call alone turns the suite red.

---

## Row 1 — `src/browser/process.rs`, CDP control socket

### 1. What it dials; attacker-influenced?

`discover_ws_url_via_http`, `src/browser/process.rs:913`. The only call site is
`:695`, and it hardcodes the host:

```rust
let http_url = format!("http://127.0.0.1:{port}/json/version");
discover_ws_url_via_http(&http_url, config.timeout)?;
```

`port` is the port of the child this process just spawned
(`BrowserProcess.port`), i.e. our own launch, not a number read from the page.
The dial itself:

```rust
let path = "/json/version";                       // :933

loop {
    match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {   // :936
```

and then a genuine HTTP request over that socket:

```rust
let request = format!(
    "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
    path, addr
);
```

Destination: **fixed loopback literal**, ephemeral port of our own child. Not
attacker-influenced — a page cannot choose it. What *is* attacker-influenced is
what the browser on the far side of this socket then fetches; this socket is the
control channel to that browser.

### 2. Gateable through the register as it stands?

**Yes, and it needs no new grant.** This row is unlike the other two because it
makes an HTTP request, not a bare connect — and the verb it needs is `GET`,
which the shipped register already grants to `127.0.0.1`, `localhost` and `::1`.
`split_host_path` drops the port and validates it (`src/scope.rs:451-453`), so
`require("http://127.0.0.1:9222/json/version", "GET")` resolves to host key
`127.0.0.1`; `/json/version` matches no marker in `AUTH_PATH_MARKERS`
(`src/scope.rs:274-301`), so it is not an authentication surface. The decision
is `Allowed` on the register as it ships.

So the mapping question is not `CONNECT` — it is `GET`. Using `CONNECT` here
would be wrong twice: it names the wrong primitive (a request is made), and the
register grants `CONNECT` to no host, so it would refuse a path that is
authorised today.

Counter-argument, stated honestly: `src/main.rs:2342-2343` exempts *loopback* bare
TCP dials outright ("Loopback relay chat is a local control socket ... not
register-governed egress") and only gates non-loopback dials. That carve-out is
about raw control sockets with no request. This row is not that: it composes and
writes an HTTP request, which is the exact object the register governs. Where
the two conflict, the request wins.

### 3. Insertion point and grant

- Insert at **`src/browser/process.rs:934`**, in
  `discover_ws_url_via_http`, after `let path = "/json/version";` and **before**
  `loop {` — not inside the loop, because a refusal is permanent and retrying it
  would burn `config.timeout` before reporting the real reason. This is the same
  reasoning already recorded for `gate_relay_dial` (`src/main.rs:2348-2350`:
  "Fatal: the three connect sites ... swallow `Err`").
- TOML: **no line added.** `127.0.0.1` already carries `methods = ["GET", "HEAD", "POST"]`.
- Also required: delete the DEBT row at `tests/egress_gate_coverage.rs:79-82`
  and set `DEBT_CAP: usize = 9` at `:121`.

### 4. Verdict — GATE

```rust
    let path = "/json/version";
    // Authorization before the request. Loopback is granted GET in the shipped
    // register, so this passes today; a register edit that withdraws it fails
    // the launch instead of silently driving CDP.
    if let Err(r) = crate::scope::require(http_url, "GET") {
        return Err(BrowserError::ConnectionFailed(format!(
            "scope refused CDP control socket {http_url}: {} — {}", r.code(), r.explain()
        )));
    }
```

`Refusal::code()` and `::explain()` exist (`src/scope.rs:177`, `:191`), and
`BrowserError::ConnectionFailed` is already in scope in this file (`:929`), so
this compiles as written.

Verification the merge owner must run (this lane does not): the browser launch
tests still pass, because the decision is `Allowed`, and the coverage test's
`every_egress_site_consults_scope_require` and `debt_list_is_not_stale` both go
green only if the DEBT entry and cap move together with the call.

---

## Row 2 — `src/browser/socks_shim.rs`, loopback SOCKS upstream

### 1. What it dials; attacker-influenced?

`handle_conn`, `src/browser/socks_shim.rs:155`. The dial at `:196`:

```rust
let mut up = match TcpStream::connect_timeout(&upstream, UPSTREAM_CONNECT_TIMEOUT) {
```

`upstream` is not the listener. It is parsed out of the per-run proxy URL and
resolved once at spawn (`:101-105`):

```rust
let (upstream, user, pass) = parse_credentialed_proxy(proxy_url)?;
let upstream_addr: SocketAddr = upstream.to_socket_addrs()...
```

The listener is a separate socket bound to `127.0.0.1:0` (`:108`). So the dial
target is the **operator's configured SOCKS endpoint** — Tor at `127.0.0.1:9050`
by default, per `TOR_SOCKS_URL` (`src/runtime/fetch.rs:64`). Not
attacker-influenced.

What *is* attacker-influenced is the destination inside the CONNECT the relay
forwards — a page load can name any host. But that destination is never dialed by
this process: the relay reads the SOCKS header, re-emits it upstream, and from
then on splices bytes. The dial happened *before* the destination was known.

### 2. Gateable as it stands?

**Not without changing what the shim is for.** The only verb that describes a
bare connect is `CONNECT`, and the shipped register grants `CONNECT` to no host,
loopback included (`docs/spec/scope-register.md:51-53`). So
`require("127.0.0.1:9050", "CONNECT")` would refuse on a stock install. The
refusal lands exactly where the shim must not fail: circuit isolation is the
reason this module exists (module doc, `:1-14` — "restores per-run circuit
isolation for the Chromium engine"), and per-run isolation is a security
property, not a convenience.

Second, structural: even a grant would not gate the thing that matters. A gate on
the dial constrains `upstream`, which is constant for the run; the relayed
destination — the only value an attacker touches — appears after the dial and is
never a local decision. Gating this dial would be a gate that cannot see its own
subject.

### 3. Insertion point and grant

None recommended. If the fleet ever decides otherwise, the point would be
`src/browser/socks_shim.rs:196` in `handle_conn`, and the grant would be
`methods = ["CONNECT"]` added to the `127.0.0.1` entry — an operator line that
`docs/spec/scope-register.md:51-53` explicitly withholds by default and that
would also enable raw scanning from every other call path on loopback, which is
far more than this row needs. Do not take that trade for one relay.

### 4. Verdict — EXEMPT

The sentence that makes it permanent (it already exists in the tree at
`:186-195`; promote it to the DEBT reason and to the docs so it is not just a
comment):

> This dial is proxy transport, not a destination: the shim connects only to the
> operator-configured SOCKS endpoint named in the per-run proxy URL, and the
> CONNECT destination a page names is dialed by that proxy, never by this
> process — so a scope gate here would have no attacker-influenced input to
> decide on, while refusing it would silently disable per-run circuit isolation.

DEBT reason string is already adequate (`tests/egress_gate_coverage.rs:84-86`).

---

## Row 3 — `src/cli/fingerprint_audit_cmd.rs`, Tor SOCKS liveness probe

### 1. What it dials; attacker-influenced?

`build_egress`, `src/cli/fingerprint_audit_cmd.rs:1493`. Endpoint selection at
`:1508-1511` and the dial at `:1516`:

```rust
let endpoint = match resolved.as_deref() {
    Some(url) => proxy_endpoint(url),
    None => Some(("127.0.0.1".to_string(), 9050)),
};
...
    Ok(addr) => match TcpStream::connect_timeout(&addr, Duration::from_millis(400)) {
```

`resolved` is `crate::runtime::egress_http::proxy_url()` (`:1494`), which is
`TALLOW_PROXY` if set, else the default Tor URL unless direct egress is allowed
(`src/runtime/fetch.rs:39-55`). So the target is **operator configuration**, and
may be a remote host — loopback is only the fallback.

No bytes are written: the body is `Ok(_) =>` and `Err(e) =>`, nothing between.
And `target.parse::<std::net::SocketAddr>()` means a DNS name is refused, so the
probe never resolves a name either (`:1515`, and the note at `:1535`). The probe
is gated behind an explicit opt-in: `build_egress(args.tor_check)` at `:1607`.

Not attacker-influenced. It is the same value that governs every other egress in
the process.

### 2. Gateable as it stands?

Expressible — `CONNECT` on the endpoint — but it would make the audit lie. There
is no grant for `CONNECT` on any host, so on a stock register the probe would be
refused; the surrounding code has no "refused" arm and would fall into
`"unreachable"` with the note "the SOCKS port is not reachable from this host".
That is a fabricated measurement of a healthy proxy, which is the one failure
mode this fleet treats as worse than no test. The verb's whole job is
reachability (`DEBT` reason for `veil_cmd`, `:100-102`, is the same class and is
already exempt for the same reason).

Third point, and the reason an exemption is not a loophole: a liveness probe of
the proxy **cannot** be routed through the proxy — that is what it measures. Any
gate would be an off/on switch on the diagnostic, not a constraint on where
traffic goes.

### 3. Insertion point and grant

None recommended. (If it were gated: `:1514`, on `target`, before the parse;
grant `methods = ["CONNECT"]` on the resolved endpoint — impossible for an
env-set endpoint without a per-run register, which is itself an argument against.)

### 4. Verdict — EXEMPT, with a corrected reason string (finding F2)

> A zero-byte liveness probe of the proxy endpoint the process is configured to
> use: it writes nothing, resolves no name (the endpoint must parse as a literal
> `IP:port`), and by construction a probe of the proxy cannot be routed through
> the proxy — the endpoint is the same `TALLOW_PROXY`/`TALLOW_TOR` value that
> governs all egress, never attacker input.

**Finding F2 (needs an operator decision, not an assay patch).** The DEBT reason
at `tests/egress_gate_coverage.rs:92-94` says "local Tor SOCKS", but the code
dials whatever `TALLOW_PROXY` names — including a remote host, directly, from
the box IP. The probe is correct (it must reach the endpoint to test it), but if
the anonymity contract is "every dial goes through the proxy", this is the one
dial that structurally cannot honour it, and the reason string currently hides
that. Recommended replacement reason, no behaviour change:

```
"zero-byte liveness probe of the configured proxy endpoint (TALLOW_PROXY/TALLOW_TOR); the endpoint is dialed directly because probing the proxy cannot go through it"
```

That edit is inside the DEBT table, so it belongs to the merge owner, not this
lane.

---

## What the merge owner should apply

1. `src/browser/process.rs`: insert the 6-line gate at `:934`; delete DEBT entry
   `:79-82`; `DEBT_CAP` 10 → 9.
2. `src/cli/fingerprint_audit_cmd.rs`: nothing. Optionally replace the DEBT
   reason with the F2 text (reason string only, same row).
3. `src/browser/socks_shim.rs`: nothing. Consider promoting the `:186-195`
   comment into `docs/spec/scope-register.md` so the exemption is documented
   where the doctrine lives, not only in one function.

Nothing here was executed. Every line reference was read at `758e5bc`.
