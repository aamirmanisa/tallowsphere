# Vault autotype — backend requirements and security posture

Companion to `src/vault/autotype.rs` (the `vault auto-type` execution
backend). Read together with `docs/ops/vault_pqc_hybrid.md` (vault sealing)
and `docs/ops/zeroization.md` (secret hygiene sweep).

## What it does

Given a decrypted autotype request (username / password / TOTP values from a
vault item), `vault::autotype` builds an ordered keystroke plan
(`Ctrl+A` → `Delete` → text) and executes it through the platform backend.
The backend is the only component that touches the X server; the vault
module never logs, prints, or serializes the typed values (Debug is
redacted; values are held as ordinary strings and are not zeroized).

## Backend requirements

- Linux + X11. Execution shells out to `xdotool` (type / key subcommands)
  found on `PATH`; there is no bundled input stack.
- When `xdotool` is missing, the backend fails honestly: the executor
  refuses to inject and returns an `Err` naming the missing backend — it
  never silently degrades or falls back to another input method.
- Keystroke values are passed to the child process on **stdin**, never on
  argv (argv is world-readable via `/proc`); unit tests pin this property.

## Security posture

- **Redaction:** `Keystroke`/`AutoTypeResult` Debug impls print `[redacted]`
  in place of values; error messages never embed typed values.
- **Ordering is pinned:** the plan clears the target field before typing
  (`Ctrl+A`, `Delete`, then the value); tests assert the exact ordering and
  key mapping so a regression cannot silently interleave old/new text.
- **Clipboard paths:** `clipboard_paste` sets the X clipboard via `xclip`
  (falling back to `xsel`) and presses `Ctrl+V`; the previous clipboard
  content is not saved or restored. Tests cover the set order, the `xsel`
  fallback, and the requires-a-tool refusal.
- **Known limitation (pre-existing, outside this module):** the `vault
  auto-type` CLI arm in `src/main.rs` prints the keystroke plan — including
  raw values — to stderr as a user-requested preview. Treat that output as
  sensitive; do not run it in logged/instrumented terminals. Redacting the
  CLI preview (e.g. printing `Debug` now that it is redacted) is a
  follow-up product decision.

## Tests

26 unit tests in `src/vault/autotype.rs`: ordering/key-mapping, missing
backend, probe/execution errors, value redaction, clipboard set/fallback/
refusal, and the stdin-not-argv property. Full slice: `cargo test --lib -- vault::`.
