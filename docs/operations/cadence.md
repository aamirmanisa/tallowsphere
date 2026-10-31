# Browser cadence — sleep audit (P1 C3)

Rule (from the reader fix): **never sleep a constant on a request cadence** —
a fixed interval is a timing fingerprint. Jittered helpers:

- `src/browser/cadence.rs` — `jitter(base_ms, frac)` / `sleep(base_ms, frac)`
  for cadence waits (±frac around the base).
- `src/browser/autonomous.rs::backoff_duration` — exponential ±25% (retries).
- `src/browser/warmup.rs` — dwell/scroll/click waits already randomised
  (`jit.dwell`, `300 + rand(500)`, `500 + rand(1000)`).
- `src/browser/behavior.rs` — `idle_jitter` / `micro_jitter` for human pauses.

## Audit result (`rg 'sleep\(' src/browser/`)

| site | class | action |
|---|---|---|
| `wordfence_bypass.rs` challenge auto-redirect wait (was fixed 2 s) | cadence | **replaced** → `cadence::sleep(2000, 0.35)` |
| `wordfence_bypass.rs` redirect poll (was fixed 500 ms) | cadence | **replaced** → `cadence::sleep(500, 0.4)` |
| `warmup.rs` dwell / scroll / click pauses | cadence | already randomised — keep |
| `autonomous.rs` retry sleeps | backoff | `backoff_duration` — keep |
| `network_stealth.rs` IPv6 race head start (250 ms) | structural | keep (race structure) |
| `network_stealth.rs` TLS fragment pacing | structural | keep (protocol pacing; micro-second scale) |
| `captcha.rs` solve polls (`config.poll_interval`) | poll | keep (operator-configured interval) |
| `cookie_farm.rs` session segment waits | structural | keep (segment accounting; revisit if farm cadence becomes a signal) |
| `ipv6_pool.rs` health-check waits | structural | keep (3/8/11 s health ladder) |
| `trace.rs`, `crawl_pipeline.rs` 1–10 ms sleeps | test/plumbing | keep |
| everything else | — | no constant request cadence found |

No `sleep(` in a request cadence path remains constant after this audit.
