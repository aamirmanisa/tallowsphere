# Quiet windows — operator guide

Quiet windows rate-limit **intake** and **interrupts** so collection stays
steady and operator attention stays usable. Four policies share one config
(`src/quiet_window.rs` → `QuietConfig`). All evaluation is pure: same inputs,
same verdicts.

## Config fields

| Field | Meaning | Example |
|---|---|---|
| `windows: Vec<TimeWindow>` | Quiet spans `[start_ms, end_ms)` on your clock; ingest is refused inside any of them. Start instant is **inside**, end instant is **outside**. Empty/inverted spans (`start >= end`) match nothing. | `[{ start_ms: 7200000, end_ms: 9000000 }]` (02:00–02:30) |
| `consolidation_ms: i64` | Cooldown after the **last accepted ingest**: `[last, last + consolidation_ms)` refuses new intake, so fresh material settles before the next pull. Exactly `consolidation_ms` after the last ingest, intake resumes. `0` = no cooldown. | `600000` (10 min) |
| `digest_size: usize` | Items per digest batch. `0` is **invalid config** (`InvalidConfig`). | `5` |
| `interrupt_severity: u8` | Severity at or above which an alert may break silence. | `4` |

## What each policy does

- **Quiet windows** — call `ingest_allowed(cfg, last_ingest_ms, now_ms)` before
  accepting material. It returns `false` inside a window **or** during the
  consolidation cooldown; `true` only when both are clear. Use windows for
  scheduled silence (deconfliction, maintenance, shift handover).
- **Consolidation silence** — the same call. Pass the timestamp of the last
  accepted ingest; `None` means no cooldown is in force. Rejected attempts do
  **not** extend the cooldown — only accepted ingests reset it.
- **Digest batching** — below-interrupt findings accumulate. Flush when
  `should_digest(cfg, pending)` is true (`pending >= digest_size`), then call
  `digest_batches(cfg, &items)` to split them in order; the last batch may be
  partial and is kept (nothing may join it later). An empty input yields no
  batches.
- **Alert tiers** — `classify_alert(cfg, severity)`:
  - `Silent` — severity `0`; never emitted (checked first, even if the
    threshold is misconfigured to `0`).
  - `Immediate` — severity `>= interrupt_severity`; may break silence now.
  - `Digest` — everything else; held for the next flush.

## Why interrupts are rate-limited

An interrupt spends a scarce resource: the operator's attention. If every
finding prompts, the urgent and the routine blur together and important
signals get missed (alert fatigue). The threshold keeps `Immediate` for
events that genuinely warrant breaking silence; everything else rides the
digest, where it is still seen — batched, ordered, and without the cost of a
live break-in.

## Practical notes

- Set `interrupt_severity` so it fires rarely; page-class events only.
- Keep windows generous around sleeps/off-hours; consolidation only needs to
  cover one acquisition-to-analysis beat (minutes, not hours).
- Watch the digest cadence: if digests routinely fill before the next window,
  `digest_size` is too small for the current collection rate.
- `digest_size == 0` fails closed: `should_digest` never fires and
  `digest_batches`/`validate` return `InvalidConfig` — fix the config.
