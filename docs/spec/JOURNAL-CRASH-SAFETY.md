# Journal crash-safety

Status: **normative for Tallow 2.0**. Backlog row G51.

## The defect this replaces

`src/mesh/journal.rs` appends one JSON object per line with `writeln!` + `flush`. `flush` moves
bytes into the kernel, not onto the platter, and nothing frames a record: a crash in the middle of a
write can leave a **partial line**. `replay()` then fails on it —

```
replay: line {N} is not JSON: {serde error}      (format string in replay(), src/mesh/journal.rs)
```

— which is correct behaviour for a corrupt file and useless behaviour for a journal, because the
whole run becomes unreplayable after a power loss. A journal exists to be trusted after a crash.

## Contract

A record is **one line** with a self-check, written in this order:

```
<blake3-hex-16> <json>\n
```

The digest covers the JSON text exactly as written, before the trailing newline. Records are
appended with `sync_data()` before `append` returns — a returned append is a durable append.

`open()` classifies what it finds, and the three outcomes are deliberately different:

| Found | Meaning | Action |
|---|---|---|
| complete line, digest matches | a good record | keep |
| complete line (ends `\n`), digest **differs** | corruption of committed data | **refuse**: open fails, naming the line |
| trailing bytes with no `\n`, or an incomplete digest/JSON | a torn tail from a crash | **truncate** to the last good record, report the number of bytes discarded |

Truncation is allowed **only** at the tail. A torn record in the middle of a file is corruption, not
a crash artifact, and must be refused — truncating there would silently discard committed history.

`replay()` keeps refusing anything it cannot parse; if `open()` has done its job the only unparseable
thing left is real corruption, and a replay that "mostly" matches is a failed replay.

## Scope

In scope: `src/mesh/journal.rs` (`Journal::open`, `Journal::append`) and every writer of a
replayable artifact under `src/mesh/`.

Out of scope: SQLite-backed state (`src/agent_ledger_sqlite.rs`) — SQLite has its own WAL contract —
and files that are regenerated rather than replayed (reports, SBOMs).

Snapshots that are rewritten rather than appended (the rotation report) are written
**temp file → `sync_data` → `rename` → `sync_dir`**, so a reader sees either the old file or the new
one and never a half-written one.

## Gates

`tests/journal_crash_safety.rs`:

1. **Torn tail** — write three records, truncate the file mid-way through the fourth, `open()` →
   truncates to three, `replay()` returns the three waves.
2. **Corrupt committed record** — flip a byte in a complete record, `open()` → error naming the line,
   file left untouched.
3. **Clean round-trip** — append N records, reopen, replay returns N waves, byte-identical file.
4. **Torn digest** — truncate inside the digest prefix only → tail rule applies (truncate), not
   corruption rule.
5. The existing `src/mesh/journal.rs` unit tests and `tests/mesh_*` suites stay green.

## Compatibility

A journal written by the previous version has no digest prefix. `open()` detects a line whose first
token is not a 16-hex digest and reads it as a legacy record **without** a self-check, reporting the
count of legacy records once. New appends use the framed form. Mixing is allowed; the checksum is
only claimed for records that carry one.
