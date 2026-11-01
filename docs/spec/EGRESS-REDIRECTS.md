# Egress: the register authorises every hop

Status: **normative for the egress gate**. Written 2026-11-01, wave 3.

## The defect this replaces

Measured on loopback, `tallow 1.6.0` (stamp `72751483db`, build 2026-11-01T01:56:01Z),
`TALLOW_ALLOW_DIRECT=1`, cwd `/workspace/tallowsphere`. Two servers: A at
`http://127.0.0.1:18081/` (in the register, basis `self-hosted`, methods `["GET","HEAD"]`)
answering `302 Location: http://127.0.0.2:18082/leak`; B at `http://127.0.0.2:18082/`
(**not** in the register) answering `200 LEAKED`.

```
http.get("http://127.0.0.1:18081/")
  landed_on=http://127.0.0.1:18081/     <- Response.url
  body_len=6                            <- "LEAKED", produced by the UNLISTED host
  server B received: ['/leak']

sitescan.scan("http://127.0.0.1:18081/", 1, opts)
  rc=0
  server B received: ['/leak']
```

The gate ran once, on the URL the caller typed, and passed. The client then followed the
redirect without asking the register, received bytes from a host the register refuses, and
reported the *original* URL as their origin.

Mechanism: `src/runtime/egress_http.rs:231` builds every shared agent with timeouts, proxy and
TLS and **no redirect policy**; `ureq 3.5.0` defaults to `max_redirects: 10`
(`ureq-3.5.0/src/config.rs:1075`). `src/runtime/fetch.rs:228` builds its agent through the same
function, so `fetch()` inherits it. Two modules deviate: `intel_api.rs:2455` sets `0` — with the
comment that states this spec's thesis — and `sitescan.rs:222` sets `8`, which still follows.

## Rule

**A request is authorised per hop.** The register is consulted for the host of every URL the
client actually sends to, not only the one the caller named. A follow that skips the gate is a
bypass; a client that follows without recording the final URL is a provenance defect on top of it.

## Requirements

1. **No implicit follow.** Every agent builder in the tree sets `max_redirects(0)`. A 3xx is a
   status to report, never a request the client makes on its own.
2. **One gated follow API.** `egress_http` exposes the only way to follow:
   issue with `max_redirects(0)`; on `301/302/303/307/308` read `Location`, resolve it against the
   current URL (RFC 3986 §5.2, including relative locations), `scope::require(next, method)`; on
   refusal the whole request is refused and the sentence names the **refusing** URL; otherwise
   issue again. Hard ceiling 8 hops, then refuse with `redirect-limit`.
3. **The method is re-authorised when it changes.** `303` (and `301`/`302` for the user-facing
   GET case) becomes `GET`; `307`/`308` preserve the method. A hop that changes the method is
   authorised under the method the next request will actually carry, so a `POST` grant cannot be
   walked into a `GET` on an unlisted host or the reverse.
4. **Scheme is part of the decision.** An **upgrade** `http:` → `https:` on the same host is permitted (it is the redirect that makes a plain-URL grant usable). A **downgrade** `https:` → `http:`, or a hop to any non-HTTP scheme (`file:`, `ftp:`, `data:`), is refused: downgrade is the shape that turns a granted read into a body someone else can rewrite, and a non-HTTP scheme is a different transport that the register says nothing about.
5. **Provenance.** The URL a `Response` reports is the URL that produced its body. `Response.url`
   is the final URL after any gated hops — never the requested one when they differ.
6. **Follow is opt-in per module, and named.** A module that must land on the final URL
   (`sitescan`'s fingerprint/page fetch) calls the gated API. A module that must not (`intel_api`,
   whose 3xx *is* its measurement) keeps `0`. Modules that only want a status keep `0` and pass
   the 3xx to their caller.
7. **The stealth plane answers the same question.** The `wreq`-based client is not exempt: either
   it is configured with the same policy, or its redirect behaviour is measured and recorded as a
   known deviation in this spec. An unmeasured client is not a compliant one.

## Status at `6bb094b` — what is implemented and measured, what is not

Written 2026-11-01, wave 3. Re-read against source and the suite on 2026-11-01 at
`6bb094b`, after a docs lane found the spec did not say which of its own requirements
had been delivered. **All seven requirements are implemented in the ureq plane and six
of the seven are measured by the `redirects_*` suite (five cases, all passing);
requirement 7 is the only one whose compliance rests on reading source rather than on
a test this repository runs.**

| # | Requirement | State | Where it lives / what measures it |
|---|---|---|---|
| 1 | No implicit follow — every builder sets `max_redirects(0)` | **implemented, measured** (ureq plane) | `egress_http.rs:239` (shared), `:480` (`agent_for_follow`), `fetch.rs:248`, `http.rs:192`, `sitescan.rs:144`, `intel_api.rs:2455`, `interp.rs:5293`. The five `redirects_*` cases exercise the gated path, which is only reachable because no builder follows. |
| 2 | One gated follow API; `Location` resolved RFC 3986 §5.2; `scope::require(next, method)`; ceiling 8 → `redirect-limit` | **implemented, measured** | `egress_http::follow` (`:576`), register call at `:671`, ceiling at `:659`, `MAX_FOLLOW_HOPS = 8` (`:361`). Cases `redirects_unlisted_target_is_refused` (unlisted host receives nothing, sentence names it) and `redirects_ceiling_is_eight` (5 hops pass, 9th refuses with `redirect-limit`). |
| 3 | Method re-authorised when it changes (303 → GET; 307/308 preserve) | **implemented, measured** | `method_after_redirect` (`:500`) applied before the register call (`:671`). Case `redirects_303_rewrites_method_to_get`. |
| 4 | Scheme is part of the decision: `http→https` permitted, downgrade and non-HTTP refused | **implemented, measured** | `is_forbidden_scheme_change` (`:542`), called at `:653`. Case `redirects_downgrade_and_non_http_are_refused`. |
| 5 | Provenance — `Response.url` is the URL that produced the body | **implemented, measured** | `Followed.final_url` returned at `:619`; consumed by `http.rs:693/716/1027/1086` and `fetch.rs:360/433`. Case `redirects_listed_target_is_followed` asserts the final URL. |
| 6 | Follow opt-in per module and named | **implemented, measured** | `sitescan` follows via `egress_http::follow` (`sitescan.rs:353`); `intel_api` keeps `0` with its reason recorded inline (`intel_api.rs:2453`); `http.get`/`post`/`request` follow through the gated loop. Covered indirectly — no test asserts that `intel_api` *does not* follow. |
| 7 | The stealth plane answers the same question (`wreq`) | **source-read only — NOT measured** | See below. |

### Requirement 7 — the honest statement

`src/stdlib/stealth_http.rs:43` builds the `wreq` client with
`.emulation(...)`, `.timeout(...)`, optional `.proxy(...)` and optional
`.tls_cert_store(...)`. It **never calls `.redirect(...)`**, and the module contains no
`scope::require` at all; its only entry gate is `stdlib/http.rs:639`, one call up, before
the client is built.

What that means, stated as measured and unmeasured separately:

- **Measured (library source).** `wreq` 6.0.0-rc.31 initialises
  `redirect_policy: redirect::Policy::none()` in the builder's config literal
  (`~/.cargo/registry/…/wreq-6.0.0-rc.31/src/client.rs:286`), so a `stealth_http` client
  **does not follow redirects**. It returns the 3xx to the caller with the status intact.
- **Not measured.** No test in this tree exercises the stealth client against a
  redirecting server, so nothing in CI would notice if that default changed on a `wreq`
  upgrade, or if a future edit added a `.redirect(Policy::limited(..))`. The compliance is
  a *coincidence of an upstream default*, not a rule this tree asserts.
- **Consequence, which is a deviation and not a pass.** `wreq`'s own
  `.redirect()` doc comment still reads "Default will follow redirects up to a maximum of
  10" (`client.rs:960`) while the code sets `Policy::none()`. A maintainer reading the doc
  would assume the opposite of the behaviour, which is precisely how the `ureq` bypass
  documented at the top of this file survived for four waves.
- **Not a bypass today**, because `Policy::none()` cannot make an unauthorised request.
  **Not compliant either**, because "an unmeasured client is not a compliant one" (req. 7).
  Closing it means one of: an explicit `.redirect(wreq::redirect::Policy::none())` in
  `stealth_http.rs` with a test asserting the policy, or routing the stealth plane through
  `egress_http::follow`. Neither is in this lane — it is a `src/` change.

The `stealth-http` feature is **on by default** (`Cargo.toml:254`), so this is the plane a
stock build uses for non-loopback `http.get`; it is not an optional corner.

## Gates

- `cargo test --lib redirects -- --test-threads=1` — a new in-crate suite (every case named `redirects_*`) over a loopback
  harness: (a) listed → unlisted 302 is refused, and the unlisted server receives nothing;
  (b) listed → listed 302 succeeds and `Response.url` is the final URL; (c) a 302 that downgrades
  https→http is refused; (d) 5 hops of listed hosts succeed, 9 refuse with `redirect-limit`;
  (e) a 303 from a POST is re-authorised as GET.
- `cargo test --lib -- --test-threads=1` — the suite is green on main as of `2ac6d23`
  (9,539 passed / 0 failed / 33 ignored). The three tests that were red while this spec was written
  (`osint` ×2 for the `CONNECT` verb, `sitescan` ×1 for `x.test`) were fixed by the test-only register
  seam (`bb77d21`) and the `CONNECT` vocabulary (`faa54fb`), and must stay green. The count may move only upward.
- The measurement above, re-run against the built binary: the unlisted server must receive
  **nothing** and the refusal must name `127.0.0.2`.

## Fail condition

If the gated follow cannot be expressed without changing every call site's request-building
signature, **stop and report** — do not ship `max_redirects(0)` alone as the fix. That closes the
hole by breaking every legitimate `http → https` redirect, which pushes the next operator to set
the ceiling back to 10 and restores the bypass with a commit that looks like a fix.
