# Structured logging

Status: **normative for Tallow 2.0**. Backlog row G52.

## What exists

`log.info(msg)` already emits, under `log.set_format("json")`:

```json
{"level":"INFO","ts":"2026-10-29T23:10:00Z","msg":"server started"}
```

There is no way to attach **fields**, and no **trace id**, so a log line cannot be joined to the run
that produced it. `log.set_level`, `set_format` and `set_output` exist; the level/format/sink state is
process-wide atomics in `src/stdlib/log.rs`.

## Additions

### `log.record(level, fields)`

`fields` is a Map of `String -> scalar` (string, int, float, bool). The record is emitted through the
same level filter and sink as `log.info`:

- **json format**: `{"level":…, "ts":…, "msg": <fields["msg"] or "">, "trace": <trace id or omitted>,
  …fields}` — fields are merged at the top level. A field named `level`, `ts` or `trace` is refused:
  the logger owns those keys.
- **text format**: `[LEVEL] [ts] [trace] k=v k=v …`, keys in insertion order.

A `Private` or `Secret` field value is replaced with `[REDACTED]` / `[SECRET]` exactly as `log.info`
does; an `Array`/`Map`/`Struct` value is refused with a named error rather than stringified, because a
nested value has no defined rendering here.

### `log.set_trace(id)` / `log.trace()`

`set_trace` sets a process-wide trace id (string, ≤64 chars); `log.trace()` returns it or `nil`.
`log.set_trace(nil)` clears it. Every record and every `log.*` line carries it while set.

The trace id is **process-wide, not task-local**, and the spec says so plainly: task-scope propagation
requires the concurrency model (G46) that does not exist yet. What this row delivers is the field, the
verb, and the rendering — not a propagation mechanism that would have to be reinvented when G46 lands.

## Gates

`tests/structured_logging.rs`, driving the real binary:

1. `log.record("info", {"msg": "x", "task": "t1", "n": 3})` under json format → parses as JSON, has
   `level`, `ts`, `msg`, `task`, `n` with the right types; no `trace` key when unset.
2. With `log.set_trace("run-7")` → every subsequent line carries `"trace":"run-7"`; `log.trace()`
   returns it; `set_trace(nil)` removes it from later lines.
3. Field name `level` / `ts` / `trace` in the map → named error, nothing emitted.
4. `Private` field → `[REDACTED]`; `Secret` → `[SECRET]`.
5. Text format renders `k=v` pairs in insertion order.
6. Level filtering still applies: `set_level("warn")` suppresses a `record("info", …)`.

## Out of scope

Task-scope propagation (needs G46 structured concurrency), sampling, and sink rotation.
