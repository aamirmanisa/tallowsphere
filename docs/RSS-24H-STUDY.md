# The 24 h RSS study — protocol

Every resident-memory figure this repo published came from a benchmark run lasting seconds or minutes
(the current baseline row is `peak RSS 23.3 MB` from `benchmarks/run_compiler_parser.py`). A run that ends
in 12 s cannot tell a settled runtime from one that has not finished leaking. That is the whole of U-D05:
**measure RSS over 24 h, not over a run.**

Harness: `scripts/rss_24h.py`. Study of record: `/home/aamir/tallow-work/rss-24h-2026-10-16/`.
Stated once, plainly: **the raw data deliberately lives outside the repo** — 7 subjects × 1,440 ticks is
~2 MB of JSONL that is an input to a number, not a deliverable. The number goes in the repo; the JSONL
stays beside it in the work directory.

## Subjects

Six long-lived production services, sampled **read-only**, plus one process the harness owns and drives:

| Subject | Why it is in the study |
|---|---|
| `tallow-admissiond` | the mesh-door daemon — the process decision #5 (allocator) is actually about |
| `tallow-relay` | the largest resident set on the box (134 MB at study start) |
| `tallow-portal` | long uptime, Rust service |
| `tallow-admin` | console service |
| `tallow-reader` | reader lane |
| `tallow veil bridge serve` | the egress bridge |
| `driven-watch` (spawned) | `tallow watch` on a scratch dir — a subject the harness controls, so a restart or a crash is observable rather than inferred |

Subjects are resolved from the process table **every tick** by `--match <regex>` against the full command
line. That matters: a pid change is *observed* (and counted) rather than ending the study or being silently
followed. **Sampling never signals, restarts or reconfigures a subject** — production services are safe to
watch.

## What is recorded, per subject per tick

`/proc/<pid>/status`: `VmRSS`, `VmSize`, `Threads`. `/proc/<pid>/smaps_rollup`: `Rss`, `Pss`,
`Anonymous`, `Private_Dirty`, `Swap` — the Pss/Anonymous pair is the fragmentation evidence, and a status
read cannot provide it. Plus fd count, CPU seconds, and system context (`load1`, `MemAvailable`) so a
memory movement can be read against what else the box was doing.

## Verdicts

| Verdict | Meaning |
|---|---|
| `STABLE` | first-hour and last-hour medians differ by < 5% |
| `GROWING` | they differ by ≥ 5%, with the rate reported in MB/h |
| `TOO-SHORT-TO-TREND` | the run spans < 2 h, so those two windows are the same window |
| `NEVER-OBSERVED` | the subject was never seen alive — reported, not smoothed over |

The medians are over the first and last hour rather than the two endpoints, because an endpoint pair on a
jittery process is noise.

## Reproduce

```sh
M='tallow-admissiond --listen|tallow-relay serve|tallow-portal serve|/opt/tallow-admin/tallow-admin|/usr/local/bin/tallow-reader|tallow veil bridge serve'
python3 -u scripts/rss_24h.py --match "$M" \
    --spawn "driven-watch::/usr/local/bin/tallow watch <dir> --interval 1000" \
    --out <out>.jsonl --duration 24 --interval 60
python3 scripts/rss_24h.py --report <out>.jsonl          # the table
python3 scripts/rss_24h.py --self-test                   # the harness's own proof
```

## Defects this harness found in itself, before it measured anything

Recorded because each one would have produced a plausible wrong number rather than an error:

1. **A silent zero in the `smaps_rollup` parser.** The unit is the *last* token of `Rss:  1316 kB`; the
   parser tested token 1, matched nothing, and returned `{}` for every process **with no error** — and the
   caller then reported a perfectly readable file as "unreadable". Found by asserting that Pss is present
   rather than merely absent-with-an-excuse.
2. **The study matched its own command line.** A `--match` regex is tested against every command line on
   the box, and the harness's own line contains that regex — so its first smoke run carried itself, its
   supervisor shell and its `timeout` wrapper as three of ten "subjects". Fixed with an ancestor-plus-marker
   guard; the same self-match hazard as `pkill -f <pattern>`.
3. **A false green on short runs.** With a run shorter than the trend window, the first-hour and last-hour
   windows are *the same window*, so the delta is identically zero — and a 72 s smoke run reported
   `+0.00% STABLE` for all ten subjects. That reads as "measured, no growth" when nothing measurable about
   growth happened. Hence `TOO-SHORT-TO-TREND` and a 2 h floor.

All three are now pinned by `--self-test` (which PASSes: smaps parses, a flat trajectory is `STABLE`, a
climbing one is `GROWING`, a 70-second run is refused a verdict, an unobserved subject is flagged).

## Status

**RUNNING — started 2026-10-16 ~16:45 UTC, 24 h, ~1,440 ticks/subject.** Log:
`/home/aamir/tallow-work/rss-24h-2026-10-16/study.log`; data: `.../raw/study-2026-10-16.jsonl`.
The result table is **pending** and this section gets the real numbers when the run ends — the first-hour
medians only become meaningful an hour in, and the verdict only after two.
