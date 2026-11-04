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
             [--retries 3] [--timeout 30] [--nodes direct,socks5://h:p]
             [--json <PATH>] [--probe-only]
```

`--nodes` fans the ranges across egress exits; omit it to fetch every range over
the host's own route. A run with two nodes and four streams reports the split,
which is the evidence that the ranges actually spread rather than sticking:

```
egress exits (shards served per node):
  streams=1   node-0=1  node-1=0  failures=0  idle_nodes=1
  streams=4   node-0=2  node-1=2  failures=0  idle_nodes=0
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

## Measured across two genuinely distinct exits

`--nodes direct,socks5://127.0.0.1:9050` on this box: the direct leg leaves from
`204.168.219.219`, the SOCKS5 leg from Tor exit `185.220.101.21`. Two real
exits, 2 MiB per run:

```
streams   elapsed ms    MB/s   Gbit/s   speedup   exits
      1          404     5.2     0.04     1.00x   node-0=1  node-1=0
      2          867     2.4     0.02     0.46x   node-0=1  node-1=1
      4          866     2.4     0.02     0.46x   node-0=2  node-1=2
```

The shards spread exactly as designed — 1/1 at two streams, 2/2 at four, zero
failures — and throughput **halved**, because the transfer finishes only when
its slowest shard does and every shard is the same size. Fan-out across
asymmetric exits buys per-IP distribution, not aggregate bandwidth.

## Weighted shards fix the equal split

`--weights` allocates each path's bytes in proportion to its measured goodput
instead of splitting evenly. Same two exits, same 2 MiB, three runs:

```
run                              elapsed ms    MB/s
direct only, 2 streams                  341     6.2
equal shards, direct + tor             2023     1.0
weighted 10:1, direct + tor             382     5.5
```

`--weights 10,1` produced shards of 1,906,502 and 190,650 bytes (90.9% / 9.1%),
spread 1/1 across the exits with zero failures, and finished within 12% of
direct-only — **5.3x faster than the equal split**. The slow leg stops setting
the finish time because it is given proportionally less work.

## Auto-calibration, and what it does *not* fix

`--calibrate` measures each exit with a 2 MiB probe and derives the weights, so
the ratio does not have to be guessed. The probe size matters: a 256 KiB probe
reported the direct path at 0.98 MB/s while the same path moved 2 MiB at
5.3 MB/s — slow start was the measurement, not the path. At 2 MiB the probe
reads 5.30 MB/s, matching an independent direct-only run.

But calibrating correctly does not make a slow exit worth using here. At 4 MiB,
all on the same target:

```
connections                          elapsed ms    MB/s
1 stream, direct                           515     8.1
2 streams, direct (both fast)              394    10.6
2 streams, direct + tor (calibrated)       583     7.2
```

Adding the Tor exit lost to direct-only at both concurrency levels — 7.2 against
8.1 for a single direct stream and 10.6 for two. At 2 MiB the weighted split was
5.5 MB/s against 5.3 MB/s direct-only, i.e. break-even inside the noise.

Proportional allocation predicts the opposite: with rates 8.1 and 2.3 MB/s, a
correct 78/22 split puts the same wall time on both legs and should land near
`total / (r_fast + r_slow)` ≈ 10 MB/s. Measured: 7.2. The fast leg delivered
2.91 MB in those 583 ms — 5.0 MB/s, not the 8.1 it reaches alone. So the model's
assumption (each path keeps its standalone rate when running alongside another)
does not hold on this link, and I do not have data that explains why: candidates
are Tor circuit churn, the origin throttling when it sees parallel range
requests, or CPU contention in the client. This needs more runs than I have.

What stands regardless: **prefer another stream on the fast exit over adding a
slow exit.** Fan-out earns its keep only when the fast exit is already capped —
per-IP rate limits, connection limits, or a single account — because then the
extra connection buys nothing and the slow path is the only capacity left.




## Not done

- Fan-out is measurable only where a second exit exists. On this host the only
  candidate is Tor, so a `--nodes socks5://127.0.0.1:9050` run would measure Tor,
  not the scheduler. The two-direct-node run above proves the wiring, not a gain.
- No cross-node retry inside one `fetch_range`: a failed node is recorded and
  `fetch_plan`'s retry loop picks the next shard attempt, which re-leases. Doing
  both would multiply attempt counts and hide the real failure rate.
- Per-shard accounting reports wall time but not time-to-first-byte, so a slow
  start and a slow transfer are not distinguished in the JSON.
