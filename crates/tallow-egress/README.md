# tallow-egress

Throughput primitives for moving more bytes out of one host than a single TCP
flow allows. Three levers, measured rather than asserted.

| lever | module | what it buys |
|---|---|---|
| shard planning | `plan` | splits one transfer into N contiguous ranges; exact coverage, sizes within 1 byte |
| parallel streams | `pool` | N concurrent range connections; lifts *single-flow* wall time, because the per-flow ceiling is a bandwidth-delay product limit, not a link limit |
| exit fan-out | `node` | N independent egress nodes with per-node concurrency caps; raises the aggregate ceiling to `nodes × per-node` and spreads per-IP limits |

`probe` exists so the other three are not used to paper over a single uplink.

## Measured

`egress-bench`, release build, three runs, 64 MiB per run against a
range-capable public origin (`http://ipv4.download.thinkbroadband.com/100MB.zip`,
`206 Partial Content` confirmed). Median of three:

```
streams   elapsed ms    MB/s   Gbit/s   speedup
      1         1971    34.0     0.27     1.00x
      2          666   100.8     0.81     2.96x
      4         1016    66.1     0.53     1.94x
      8          589   113.9     0.91     3.35x
     16          480   139.7     1.12     4.11x
```

Run-to-run variance is large (single-stream landed between 29.2 and 81.1 MB/s
across the three runs), because the origin's own per-connection rate is
unstable. The direction is consistent in every run: 8 and 16 streams beat one
stream, and the gain comes from the origin capping each *connection* while
leaving the aggregate open. That is the case fan-out is for.

Do not read 4.11x as a property of the code. It is a property of
`concurrency × origin behaviour` and it moves with the target.

## Host capability verdict

`egress-bench --probe-only` on the Hetzner ARM box:

```
kernel                 6.8.0-147-generic
mptcp_enabled          true          (net.mptcp.enabled = 1)
mptcp_pm_type          0             (userspace path manager)
mptcp_scheduler        default
physical uplinks       1             (eth0)
bond interfaces        none
distinct_paths         1
```

- **MPTCP (lever 3)**: the kernel supports it and `IPPROTO_MPTCP` sockets
  create successfully here, so the local half is ready. It buys nothing until
  (a) the peer is MPTCP-capable and (b) this host has a second path to offer.
  One uplink means one path; MPTCP over one path is plain TCP with extra
  header bytes.
- **Link bonding (lever 4)**: nothing to bond. `wg0` is a tunnel over `eth0`
  and adds privacy, not capacity. A second independent path has to come from
  the provider; additional IPs on the same NIC are the same NIC.

Both of those are procurement facts, not code. The probes in `probe.rs` report
them so a run cannot silently pretend otherwise.

## CLI

```
egress-bench --url <URL> [--streams 1,2,4,8,16] [--bytes 67108864]
             [--retries 3] [--timeout 30] [--json <PATH>] [--probe-only]
```

Exit codes: `0` success, `2` bad arguments, `3` target does not support byte
ranges, `4` a run failed. `--probe-only` makes no network call.

## Library

```rust
let plan = plan_shards(total_len, 8, 1)?;          // 8 contiguous ranges
let report = fetch_plan(&plan, &HttpRangeFetcher::new(url), &PoolConfig {
    streams: 8,
    ..Default::default()
})?;
assert_eq!(report.total_bytes, total_len);
```

`Fetcher` is the seam: anything that returns exactly `end - start` bytes can be
driven by `fetch_plan`, including a test double.

## Not done

- `ProxiedFetcher` fans ranges across a `NodePool` and is covered by tests, but
  `egress-bench` has no `--nodes` flag yet, so the measured table above is the
  *stream* lever only. Fan-out cannot be measured on this host regardless: there
  is no second exit to fan across, and pointing it at Tor would measure Tor.
- No cross-node retry inside one `fetch_range`: a failed node is recorded and
  `fetch_plan`'s retry loop picks the next shard attempt, which re-leases. Doing
  both would multiply attempt counts and hide the real failure rate.
- Per-shard accounting reports wall time but not time-to-first-byte, so a slow
  start and a slow transfer are not distinguished in the JSON.
