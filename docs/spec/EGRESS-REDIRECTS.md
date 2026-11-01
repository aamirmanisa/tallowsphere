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

## Gates

- `cargo test --lib egress::redirects -- --test-threads=1` — a new in-crate suite over a loopback
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
