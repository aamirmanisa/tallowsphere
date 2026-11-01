# Egress surface outside the 25 gated modules

Measured 2026-11-01 on `e2d91ac`. Written because the wave-5 claim "25 modules gated,
0 ungated" was **true only for the predicate the coverage test uses**
(`src/stdlib/*.rs` containing an `egress_http::` request verb). A sweep over every
request primitive in every non-test region finds a much larger ungated surface.

**Re-measured 2026-11-01 at `6bb094b`.** Three rows in the HTTP table are now closed
(`9925c2b`, merged `6bb094b`); the rows are kept and marked rather than deleted, so the
delta stays auditable. Counts below are the `6bb094b` scan, with the `e2d91ac` value in
parentheses wherever it moved. The counting script that reproduces both columns is
`reports/inventory_scan.py`; it reproduces the original `e2d91ac` table exactly
(20 files / 32 sites, every row at the published line numbers).


## Method

- Walk `src/**/*.rs`; cut each file at its first `#[cfg(test)]` so test harnesses do
  not count as egress.
- A file is **gated** if its production region contains `scope::require`.
- Classify the rest by primitive: `egress_http::<verb>(`, `ureq::<verb>(`,
  `reqwest::Client::new|builder`, `reqwest::<verb>(` for HTTP egress;
  `TcpStream::connect`, `UdpSocket::connect`, `connect_timeout` for raw connects;
  `bind` / `Command::new` for the non-egress class.
- Two readings the script has to make explicit, because the prose above does not state them
  and a re-run that differs on either gets different numbers:
  - **`egress_http::agent_with_timeouts(` counts as an HTTP egress primitive.** It is the
    request-client factory — the module builds that agent and issues on it a few lines later
    (`agent.get(url)`), so a row that names only that line is still a request site. Four of
    the twenty rows below are that shape.
  - **`reqwest::blocking::Client::new|builder` counts too.** The document's shorthand says
    `reqwest::Client::…`; the `blocking::` module path is the same primitive.
  Comment lines (`// …`) are not counted as sites.

## Counts

At `6bb094b`, with the `e2d91ac` value in parentheses where it moved:

- files calling `scope::require` outside tests: **34** (31)
- HTTP egress with no register call: **17 files / 26 sites** (20 / 32)
- raw socket connect with no register call: **15 files / 36 sites** (unchanged)
- bind/listen/subprocess (not egress by itself): **38 files / 99 sites** (unchanged)

The earlier text of this section said 32 gated files and 32/77 for the last class; neither
reproduces from the predicate above, and both are corrected here rather than left to flatter
the delta. The three-class totals are unaffected by the `6bb094b` merge except in HTTP.

### HTTP egress, ungated — 17 files / 26 sites (was 20 / 32)

Rows marked **closed** are gated at `6bb094b` and no longer appear in the count; their
`e2d91ac` line numbers are kept so the original measurement can still be located.

| file | sites | lines (`e2d91ac`) | status |
|---|---|---|---|
| `src/agent_reasoning.rs` | 2 | 579, 748 | open |
| `src/browser/adaptive_crawler.rs` | 2 | 54, 69 | open |
| `src/browser/autonomous.rs` | 1 | 274 | open |
| `src/browser/captcha.rs` | 4 | 427, 478, 580, 621 | **closed** — `6bb094b`, gate `captcha.rs:418` (`gate_solver`) |
| `src/browser/download.rs` | 3 | 197, 305, 739 | open |
| `src/browser/dpi_bypass.rs` | 1 | 398 | open |
| `src/browser/dual_mode.rs` | 2 | 432, 551 | open |
| `src/browser/free_proxies.rs` | 2 | 35, 96 | open |
| `src/browser/llm_extract.rs` | 1 | 296 | open |
| `src/browser/perf_engine.rs` | 1 | 103 | open |
| `src/browser/proxy_intelligence.rs` | 2 | 152, 200 | open |
| `src/browser/robots.rs` | 1 | 79 | **closed** — `6bb094b`, gate `robots.rs:81` |
| `src/browser/sitemap.rs` | 1 | 184 | **closed** — `6bb094b`, gate `sitemap.rs:186` |
| `src/browser/typesense.rs` | 1 | 166 | open |
| `src/cli/daemon.rs` | 1 | 215 | open |
| `src/request_plan.rs` | 1 | 72 | open |
| `src/signing.rs` | 2 | 259, 307 | open |
| `src/stdlib/cnam_dip.rs` | 1 | 129 | open |
| `src/stdlib/lrn_dip.rs` | 1 | 129 | open |
| `src/stdlib/sync.rs` | 2 | 44, 69 | open |

The three closed rows were closed by one commit, `9925c2b`, and each is fatal rather than
returned — the deciding caller is named per site in `reports/vellum-egress-docs.md`. All
three modules now contain `scope::require`, so they also leave the ungated set entirely
rather than shrinking within it.


### Raw socket connect, ungated — 15 files / 36 sites

| file | sites | lines |
|---|---|---|
| `src/browser/ipv6_pool.rs` | 1 | 642 |
| `src/browser/network_stealth.rs` | 4 | 252, 257, 265, 268 |
| `src/browser/process.rs` | 1 | 936 |
| `src/browser/proxy.rs` | 1 | 642 |
| `src/browser/socks_shim.rs` | 1 | 187 |
| `src/cli/fingerprint_audit_cmd.rs` | 1 | 1516 |
| `src/cli/request_plan_cmd.rs` | 1 | 972 |
| `src/cli/veil_cmd.rs` | 4 | 195, 273, 289, 589 |
| `src/main.rs` | 7 | 2312, 2513, 2540, 2591, 5733, 6012 … |
| `src/mesh/remote.rs` | 1 | 602 |
| `src/stdlib/cnam_dip.rs` | 1 | 131 |
| `src/stdlib/lrn_dip.rs` | 1 | 131 |
| `src/stdlib/mesh.rs` | 1 | 482 |
| `src/stdlib/topology.rs` | 5 | 389, 481, 1595, 1765, 2092 |
| `src/stdlib/transfer_net.rs` | 6 | 1003, 1193, 1365, 3170, 3521, 3575 |

## Caveats that make this a work list, not a panic

- **Loopback-only sites are not a policy hole.** Several connect to 127.0.0.1 for the
  browser's own control socket, the CDP endpoint, or a local proxy. They appear here
  because the predicate cannot tell them apart; gating a loopback control socket buys
  nothing.
- **Hardcoded constant targets differ from caller-supplied URLs.** `src/browser/download.rs:197`
  fetches `CFT_LAST_KNOWN_GOOD_URL`; `src/main.rs:2312` connects to `8.8.8.8:80` to detect
  the public IP. Neither is attacker-influenced, but under the register's doctrine every
  host is granted or refused, so an operator reading the register would expect them there.
- **`src/stdlib/transfer_net.rs` and `src/stdlib/relay_room.rs` are the sendtallow boundary** —
  ruled out of scope for the fleet by the operator, so their sites are excluded from gate work.
- **`bind` / `Command::new` are not egress.** The third class is reported for completeness only.

## Consequence for `tests/egress_gate_coverage.rs`

Its predicate is `src/stdlib/*.rs` x `egress_http::`, which is why 30 files above never
failed it. The durable fix is to widen it to `ureq::`, `reqwest` and `TcpStream::connect`
across `src/`, with an explicit debt list that shrinks as gates land — not to add a gate
for every row here, and not to leave the predicate as it is and call the surface covered.

Status: **inventory only, nothing is gated by this document.** Three of the browser rows in
the first table were closed by `6bb094b`; the rest is a backlog with a measured size. The
counts above are re-derived from `6bb094b`, not carried forward: the script that produces
them is `reports/probes/inventory_scan.py`, and it reproduces the original `e2d91ac`
table exactly — run it against both revisions to see the six-site delta for yourself:

```bash
python3 reports/inventory_scan.py e2d91ac   # 20 files / 32 sites
python3 reports/inventory_scan.py 6bb094b   # 17 files / 26 sites
python3 reports/inventory_scan.py 758e5bc   #  3 files /  5 sites   (see the re-measure below)
```

## Re-measured at `758e5bc` (2026-11-01, wave 12)

The script moved into the tree (`reports/inventory_scan.py`) so the number the
coverage gate cites can be reproduced from the repository instead of from a
scratch directory.

| class | `6bb094b` | `758e5bc` |
|---|---|---|
| files calling `scope::require` in the production region | 34 | **53** |
| HTTP egress with no register call | 17 files / 26 sites | **3 files / 5 sites** |
| raw socket connect with no register call | 15 files / 36 sites | **7 files / 15 sites** |
| bind / listen / subprocess (not egress) | 38 files / 99 sites | 34 files / 71 sites |

The three ungated HTTP files are exactly the three HTTP rows on
`tests/egress_gate_coverage.rs`'s DEBT list: `src/cli/daemon.rs` (:215),
`src/signing.rs` (:259, :307), `src/stdlib/sync.rs` (:44, :69). The seven ungated
raw-connect files are exactly the seven raw DEBT rows (`browser/process.rs`,
`browser/socks_shim.rs`, `cli/fingerprint_audit_cmd.rs`, `cli/request_plan_cmd.rs`,
`cli/veil_cmd.rs` — 4 sites, `stdlib/mesh.rs`, `stdlib/transfer_net.rs` — 6 sites).

That agreement is the useful result, not the drop: **the DEBT list is complete
with respect to this predicate** — there is no ungated file outside it, and no
file on it that the scan cannot see. What the predicate still cannot see is the
class `quarry` is census-ing (QUIC, DNS resolution, child processes, browser
CDP), so this table is a claim about HTTP and raw TCP, not about every socket.

### Correction, same day: file-level completeness is not site-level coverage

`reports/quarry-w12.md` (§2) measures what this document's predicate cannot, and
it changes how the paragraph above should be read. Over 176 network-capable
sites in production regions:

- a `scope::require` earlier in the **same function**: **12**
- genuinely ungated: **164**
- invisible to the predicate: **135**, of which **61 sit in files the coverage
  gate reports as gated**
- of 87 sites inside files called gated, **75 have no `require` in their
  enclosing function**

`tests/egress_gate_coverage.rs` decides gating with `is_gated(text)` — one
`scope::require` anywhere in the production region marks the whole file
(verified: the test computes `egress_sites(text)` and then gates on the file).
So "0 ungated" is a file-granularity claim, and the debt list is complete only
in that sense. The durable fix is site-level gating: for each site, require a
`require` in its enclosing function, with a per-site debt list that shrinks.
Until that lands, any statement of the form "N gated / 0 ungated" carries this
caveat with it.
