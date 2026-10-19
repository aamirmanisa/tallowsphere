# Typing `Result<T>` payloads (closes #120)

Status: **steps 1–2 landed (payload carried on the value and through `let`);
step 3 attempted and reverted — measured crash, see below.** Blocks the four remaining `wait_*` arms and any
native program that reads a field off a browser call's result.

## The defect, measured

`page.wait_for_url(...)` is statically `Result<WaitResult>`. Codegen carries that value as
`LLType::I8Ptr` (a pointer to the tagged result box), so when the program writes `r.url`:

1. the `Member` emitter cannot see the payload type — it only has an `I8Ptr`;
2. it falls back to guessing a struct layout by field name (guard added in `52b9f9e` refuses
   when more than one struct owns the field);
3. before that guard it picked the first match and loaded an unrelated offset, printing `0`
   where the interpreter raises `unknown method: .result() on Ok`.

So the *storage* is correct — the arm returns a real `Result` — and the *read* is untyped.

## Design

Carry the payload struct name alongside the value, and unwrap at the read.

- Add `result_payloads: HashMap<String, String>` keyed by the result-box register, or simpler:
  a `LLValue` field `payload_struct: Option<String>` set by the call arm that built the Result
  (`build_result_struct` already knows the struct name).
- In `Member`:
  - if the object is a `Result` with a known payload struct, emit a tag check first:
    `tag = load i64, ptr box` (offset 0 of the tagged box); `if tag != 0` → jump to an error
    block that prints the Err payload and calls `exit(1)`. Both engines then refuse the same
    program the same way rather than one printing `Ok(...)` and the other `0`.
  - then `payload = load ptr, ptr box+8` (offset of the payload) and resolve the field against
    `struct_layouts[payload_struct]`.
- Variables bound to such a value (`let r = ...`) must keep the payload name: store it in the
  same slot as the alloca/type pair, so the read path works after the assignment, not only on a
  temporary.

## Why not "return the bare payload"

It removes the tag, so a failing call cannot be distinguished from a successful one, and the
interpreter keeps returning `Ok(...)`. That is the divergence the parity harness exists to
catch — rejected.

## Order of work

1. `LLValue.payload_struct` + set it in `build_result_struct` (no behaviour change on its own).
2. Variable binding preserves it.
3. `Member` unwraps with tag check; unit test asserts the `icmp`/branch and the `getelementptr`
   into the payload.
4. `tests/optional_parity.rs` grows a `wait_for_url` case: both legs must print the same
   `result`/`url` values from a real page.
5. Only then: `wait_for_function`, `wait_for_event`, `wait_for_request`, `wait_for_response`
   arms — same out-parameter shape as `tallow_page_wait_for_url`.

## Measured attempt at step 3 (reverted)

The unwrap branch was written and run against `wait_native.tl` with
`--require-native`. It compiled and linked, and the native leg aborted:

```
panicked at src/runtime/mod.rs:132:17:
misaligned pointer dereference: address must be a multiple of 0x8 but is 0xa
```

`0xa` is an integer payload read where a box pointer belongs, so the field load
returned a value rather than a pointer: either the payload offset inside
`%struct.TallowResult` is not the one the unwrap used, or `WaitResult`'s stored
field list and the layout used to read it disagree. The next step is to dump the
generated `.ll` for this program and compare the `store` offsets in
`build_result_struct` with the `getelementptr` indices in the read path — do not
re-guess, diff the IR.

The unwrap branch is not in the tree; only the carrier (step 1) and the `let`
recording (step 2) are, so nothing half-working ships.
