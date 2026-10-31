# Claims provenance gaps

These claims were registered from documents that have never been part of this
repository: `CLAUDE.md`, `tallow_1000x_upgrade_prompt.md` and
`docs/mega/tallow-2.0-spec.md` exist in no commit here and on no local copy.
Each row below records the original anchor verbatim so the register keeps its
history; the claim itself stays labeled in `docs/claims-ledger.yaml` (none of
these is `shipped`), and nothing here asserts the original text still exists.

| entry | original anchor | claim (truncated) |
|---|---|---|
| R-P1 | `CLAUDE.md:116` | single-request HTTP fetch ~50µs |
| R-P2 | `CLAUDE.md:119` | 100K concurrent reqs — io_uring + userspace TCP ✅ |
| R-P3 | `CLAUDE.md:106` | DPDK option for kernel bypass (10M+ connections) |
| R-P5 | `CLAUDE.md:115` | <1ms startup |
| R-P6 | `CLAUDE.md:117` | Parse 10K HTML pages ~40ms (SIMD tokenizer) |
| R-P7 | `CLAUDE.md:118` | Encrypt 1GB ~200ms (AES-NI) |
| R-P9 | `CLAUDE.md:105` | io_uring backend (Linux 5.1+) for async I/O |
| R-P10 | `CLAUDE.md:107` | SIMD string processing (32 bytes at once) |
| R-P11 | `CLAUDE.md:108` | Arena allocators, zero GC |
| R-C1 | `CLAUDE.md:105` | Scales from 10K (epoll) → 1M (io_uring) → 10M+ (DPDK) |
| R-C1 | `CLAUDE.md:150` | Scales from 10K (epoll) → 1M (io_uring) → 10M+ (DPDK) |
| R-C1 | `CLAUDE.md:762-763` | Scales from 10K (epoll) → 1M (io_uring) → 10M+ (DPDK) |
| R-B9 | `tallow_1000x_upgrade_prompt.md:23` | HtmlParser ~100x faster (no browser) |
| R-M3 | `CLAUDE.md:103-119` | Same perf table duplicated in agent-facing root file |
| R-M5 | `docs/mega/tallow-2.0-spec.md:1-8` | 'Tallow 2.0 — 1000x Language Specification' + provenance |
| R-M5 | `docs/mega/tallow-2.0-spec.md:147` | 'Tallow 2.0 — 1000x Language Specification' + provenance |
| R-M5 | `docs/mega/tallow-2.0-spec.md:160` | 'Tallow 2.0 — 1000x Language Specification' + provenance |
| R-M5 | `docs/mega/tallow-2.0-spec.md:212` | 'Tallow 2.0 — 1000x Language Specification' + provenance |
| R-M5 | `docs/mega/tallow-2.0-spec.md:216` | 'Tallow 2.0 — 1000x Language Specification' + provenance |
| R-M5 | `docs/mega/tallow-2.0-spec.md:251` | 'Tallow 2.0 — 1000x Language Specification' + provenance |
| R-M5 | `docs/mega/tallow-2.0-spec.md:252` | 'Tallow 2.0 — 1000x Language Specification' + provenance |
| R-M5 | `docs/mega/tallow-2.0-spec.md:379` | 'Tallow 2.0 — 1000x Language Specification' + provenance |
| R-M5 | `docs/mega/tallow-2.0-spec.md:421` | 'Tallow 2.0 — 1000x Language Specification' + provenance |

## Later finds (same class)

| entry | original anchor | claim (truncated) |
|---|---|---|
| R-M6 | `docs/mega/tallow-1000x-adversary-upgrade-plan.md:57-58` | 'Stdlib: 100 modules' + 'full PQC suite … HSM PKCS#11, sigstore' |
| R-M12 | `.planning/phases/36-supply-chain-integrity/36-01-DONE.md:6` | .planning phase-completion bookkeeping: DONE-stub 'all tests passing'  |
| R-M12 | `.planning/phases/47-codegen-parity/47-01-DONE.md:6` | .planning phase-completion bookkeeping: DONE-stub 'all tests passing'  |
| R-M12 | `.planning/phases/48a-browser-automation-upgrade-OLD/48-01-DONE.md:6` | .planning phase-completion bookkeeping: DONE-stub 'all tests passing'  |
| R-M12 | `.planning/ROADMAP.md:594` | .planning phase-completion bookkeeping: DONE-stub 'all tests passing'  |
| R-M12 | `.planning/ROADMAP.md:631` | .planning phase-completion bookkeeping: DONE-stub 'all tests passing'  |
| R-M12 | `.planning/ROADMAP.md:650` | .planning phase-completion bookkeeping: DONE-stub 'all tests passing'  |
| R-M12 | `.planning/ROADMAP.md:662` | .planning phase-completion bookkeeping: DONE-stub 'all tests passing'  |
| R-M12 | `.planning/STATE.md:29` | .planning phase-completion bookkeeping: DONE-stub 'all tests passing'  |
| R-M12 | `.planning/REQUIREMENTS.md:554` | .planning phase-completion bookkeeping: DONE-stub 'all tests passing'  |
