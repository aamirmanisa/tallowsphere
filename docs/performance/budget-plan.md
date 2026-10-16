# Performance Budget Plan

Current realistic targets for the scraper tooling are operational targets, not language/runtime claims.

## Host Tiers

| Tier | CPU | RAM | Recommended workers | Connection hint |
|---|---:|---:|---:|---:|
| Local dev | 4-8 cores | 16 GB | 1-10 | 50-500 |
| Small runner | 8-16 cores | 32 GB | 10-25 | 500 |
| Production runner | 16-32 cores | 64 GB+ | 25-100 | 500-2000 |

## Guardrails

- Keep per-worker connection pressure below 100 unless a run-specific benchmark proves it is stable.
- Treat success rate, unresolved count, and retry rate as release gates.
- Use artifact bundle size and full JSON row count as early signals for memory pressure.
- Prefer bounded batches and resumable launch directories over a single unbounded run.

These targets complete the publishable performance budget. Lower-level parser and memory profiling remain separate implementation work.

