# Placeholder / incomplete-implementation audit — 2026-10-15

Scope: the Tallow tree at the published head (`7364aa59`, product repo). Method: mechanical scan of
**1,896 files** (`src/`, `crates/`, `stdlib/`, `tests/`, `examples/`, `benches/`) crossed against the
project's own **87-row stub register** (`docs/operations/stub-register.md`), then **empirically probed** on a
real binary where the distinction between a loud refusal and a silent fake was in question.

Two independent tests are applied to every candidate, because either one alone produces noise:

1. **Is it in the register?** The register's own convention: an entry is registered when a path *deliberately
   refuses, caps, or defers work* — and the refusal is **visible**, never a silent fake success. A site that
   is not in the register is either an accidental omission or a factual error in the register.
2. **Does it fail loud?** For each unregistered site, the behaviour was executed and observed (rc + stream),
   not inferred.

## Headline counts (first-party code)

| marker | count |
|---|---|
| `todo!()` / `unimplemented!()` | **0** |
| `TODO` / `FIXME` / `HACK` / `XXX` code comments | **1** (see F1) |
| `#[allow(dead_code)]` sites | 125 (the register's row #69 documents the largest cluster) |
| register rows | 87 |
| string literals naming stub/fake/mock/placeholder | 40 (32 are registered, documented, or false positives) |

The absence is corroborated rather than assumed: the project's own audits reach the same number
(`docs/mega/tallow-1000x-upgrade-2026/GROUND-TRUTH.md:11,29`), and no `todo!()`/`unimplemented!()` string
appears anywhere in `src/`, `crates/` or `stdlib/`.

## Unregistered findings — the actionable set

### F1 — AEAD receive-counter monotonicity is a documented TODO and not enforced

**Disposition: FIXED (2026-10-15).** Enforced in `AeadChan::open`; the tripwire test in
`crates/tallow-admission/tests/verify_v.rs` fired and was flipped to expect rejection, and the crate README's
TODO entry is closed. See §Dispositions.

`crates/tallow-admission/src/aead.rs:7`

```rust
//! TODO(v1 hardening): enforce rx-counter monotonicity on `open` (reject
//! any counter that is not strictly increasing) — the v0 reference carries
//! the counter in the clear but does not enforce order.
```

**Class:** TODO, security-relevant. **Not in the register.** The module mirrors a reference implementation
byte-for-byte and says so in-file, which is why it reads as a decision rather than an oversight — but
"documented in a module header" is not the register's standard, and the register is what the project treats
as the inventory. **Impact:** within a session, a sealed frame can be replayed or reordered and `open` will
accept it; the counter is carried in the clear, so an attacker does not need to guess it. This is the only
security-relevant unregistered instance found.

### F2 — 23 declared-but-unwired browser functions

**Disposition: WIRED (2026-10-15).** All 23 now resolve through `stdlib::browser::dispatch` to an actionable
refusal naming their live `page.<method>()` spelling with arguments — the implementations already existed as
Page methods; only the route from the free-function spelling was missing. Runtime-verified 23/23 through a
built binary, plus a coverage test that parses `stdlib/browser.tl` so a future declaration cannot arrive
unwired. The declarations are kept (deleting public stdlib surface stays an operator call); row #88 records
the closure. See §Dispositions.

`stdlib/browser.tl` (lines 640–777): `page_set_content`, `page_content`, `page_add_init_script`,
`page_add_script_tag`, `page_add_style_tag`, `page_wait_for_function`, `page_wait_for_url`,
`page_wait_for_request`, `page_wait_for_response`, `page_wait_for_event`, `page_wait_for_timeout`,
`page_expose_function`, `page_expose_binding`, `page_on_console`, `page_on_error`, `page_on_request`,
`page_on_response`, `page_on_filechooser`, `page_on_download`, `page_emulate_media`, `page_emulate_vision`,
`page_throttle_network`, `page_throttle_cpu` — each declared with an empty body and **no handler anywhere**:
no interpreter arm, no codegen lowering, no `src/browser/**` method table entry.

**Class:** declared-not-wired drift (same class as the register's row #84, which is registered for
`fs.file_size`; these 23 sites are not). **Probed, not inferred:**

```
$ tallow run probe2.tl        # calls page_content("x") then page_throttle_cpu(1)
stdout: start                  # the call did not complete; nothing after it ran
stderr: warning[W0102]: use of possibly undefined variable `page_content`
rc=1
```

**Impact:** the API surface advertises 23 functions that no runtime path implements *by that spelling*. The
failure was loud (rc=1, a warning naming the symbol, no fabricated return), so this was drift rather than a
deflect — but a `.tl` author reading `stdlib/browser.tl` had no way to tell which declarations were wired, and
`undefined function` reads like a typo rather than a routing gap. Fixed as above.

### F3 — eleven finance-IR ops unimplemented in the interpreter

**Disposition: REGISTERED** as stub-register row #89. See §Dispositions.

`src/finance_ir.rs:3515`

```rust
| Op::Corr | Op::Cov | Op::Mod | Op::Pow | Op::Round | Op::Floor | Op::Ceil
| Op::Log10 | Op::Var | Op::Min | Op::Max => Err(format!("Op::{:?} not yet implemented in interpreter", op)),
```

**Class:** Deflect-adjacent — a deliberate `Err`, but registered nowhere. **Impact:** parity, and the scope
is narrower than the error text suggests: the same ops *are* evaluated on the neighbouring paths at
`:2549` and `:2824` (broadcast/statistical arms) and pushed by the IR builder at `:1226-1228`, so this is one
evaluator missing eleven arms, not an unimplemented op set. Whether the **native** lowering covers all eleven
is unmeasured — the parity implication is inferred from the error text, not from a native run. Measured
follow-up: one native/interpreter pair, then implement in that evaluator or register as a known cap.

### F4 — a vestigial stub helper with no callers

**Disposition: DELETED** — zero callers confirmed before removal. See §Dispositions.

`src/stdlib/net.rs:275` — `#[allow(dead_code)] fn not_yet(name: &str) -> StdlibResult { Err(format!("{name} is not yet implemented")) }`.
**Class:** Stub (dead). No caller exists, so nothing is misadvertised at runtime. **Impact:** none today;
it is a stub kept alive by an `allow`, and it is the kind of site that later gets wired without review.

### Checked and dismissed (recorded so they are not re-raised)

- `src/stdlib/azure_{sql,phish,app_proxy}.rs` — `dispatch_method() -> None` is the "no such method" fallback
  for modules that expose free functions only, not an empty implementation.
- `src/stdlib/mesh.rs:174` — `("simulated", Value::Bool(true))` is an **explicit honesty marker** with a
  comment stating the node is simulated in-process.
- `crates/tallow-svid/src/issuer.rs:883` — `placeholder_cert()` is a throwaway self-signed cert used only to
  move state out of the way during `new`, documented "never exposed".

### F5 — the tree's own test target cannot build from a clean checkout

`src/cli/extract_cmd.rs:447` and `src/cli/schema_cmd.rs:98` both `include_str!`
`schemas/tallow/examples/product-listing.extraction.schema.json`, and `schemas/` is **untracked** in the
development tree — zero files tracked at this revision *and* at its base, `git status` reporting `?? schemas/`,
14 files present on disk only.

**Class:** uncommitted build input — the same class as the `crates/tallow-crypto/src/rng.rs` defect recorded on
2026-10-14, a different file. **Impact:** the lib **test** target fails with two
`couldn't read … No such file or directory` errors, so `cargo test --lib` — **9,023 tests** — cannot compile
in a clean checkout of the development tree. Nothing caught it because the usual gate is `cargo check`, which
does not compile `cfg(test)` code. Found here by building this repository's test target, which is the first
time anything in this work compiled it.

**Disposition: FIXED in this repository** — commit `24a3c04` carries the 14 files, and `MANIFEST.md`
records them as an addition rather than filtered content. **The development tree still carries the defect**;
its remedy there is `git add schemas/`, flagged to the operator rather than applied, because that working tree
is intentionally dirty and it is the operator's to commit.

## Registered instances — verified, with the register's claim checked where it was cheap

| register row | instance | verified behaviour |
|---|---|---|
| #52 | `src/interp.rs` Phase-54 descriptive-echo arms (`Keyboard.*`, `Mouse.*`, `Dialog.on_confirm`, `page_throttle_network`, …) | Confirms the **123 of 146** empty `.tl` bodies that *do* have handlers: the empty body is the declaration side of a registered echo arm that makes no outcome claim |
| #84 | `fs.file_size` declared but unwired | **Reproduced by probe:** `runtime error: undefined function: fs.file_size`, rc=1 — the register's claim is accurate |
| #33 / #61 | Tallow dispatch miss | Loud: `Err("Tallow method not yet dispatched: Kind.method() — constructor wired, method stub pending")` |
| #59 | TURN `allocate()` sends an unauthenticated Allocate (no MESSAGE-INTEGRITY), returns the server address as the relay address | Registered v1 scope; the code is as described |
| #62 | `LightweightCrypto.encrypt/decrypt` accepts `ascon`/`photon`/`gift` but is AES-256-GCM | **The strongest "Fake" in the tree and it is registered:** the algorithm is not the one requested and the *API name does not say so* (the in-code comment does). Round-trip works, so it can be mistaken for the requested cipher |
| #65 | `real-ml` not shipped; default is a deterministic FNV-1a mock | Loud, documented; consistent with the decision to declare `real-ml` rather than ship it |
| #66 / #67 | `S3Backend` / `ParquetBackend` without their features | Loud, feature-gated, message names the feature to enable |
| #68 | class list: CDP pipe transport, `deals` contract stubs, `aegis`, `http2-fingerprint`, `redis-backend`, … | Class-level registration; each fails loud with an explanation string |

## False positives excluded (with the reason)

| site | why it is not a finding |
|---|---|
| `crates/tallow-crypto/src/kdf/eff_wordlist.rs` (`"deflected"`, `"pretended"`) | the EFF diceware **wordlist**; the words are data |
| `crates/tallow-net/src/transport/reconnect.rs:360,403,447,…` (`async fn close(&mut self) {}`) | test doubles (`FailChannel`, `AlwaysFail`, `TransientFail`) inside a `#[cfg(test)]` module (line 187) |
| `crates/tallow-daemon/src/{db.rs:57,main.rs:53}` | `#[cfg(not(unix))]` platform no-ops — the Unix path does the hardening |
| `src/browser/cdp.rs:178` (`finish(self) {}`) | documented no-op: the frame builder needs no finalization |
| `src/interp.rs:14938-14974` (four consecutive `unreachable!()`) | channel `send`/`recv`/`try_recv` arms that return in every reachable case; the macro asserts that |
| `src/codegen.rs:868 async_stub_source()` | **named "stub", is not one**: it emits a real pthreads/Win32-threaded async runtime |
| `src/foresight_adapter.rs:90-106` ("placeholder" summaries) | hand-written fixtures, self-described as not fetched data |
| `src/vault/autotype.rs:140,176` ("placeholder" errors) | parser messages about `{{placeholder}}` template syntax |
| `src/main.rs:18248-18320` (`@unimplemented` / `@mock`) | a **detector**: the `.tl` annotation checker; zero annotations exist in the tree |
| `docs/**.md` (26 loose TODO hits) | plans, agent reports and prior audits *describing* historical TODOs — not code |

## Method limitations

- Static scan plus targeted probes; `#[allow(dead_code)]` sites (125) were counted, not each classified —
  row #69 documents the largest cluster and its remediation history (blanket allows replaced by item-level,
  commit `2a7fb8d`).
- The register is treated as authoritative for *intentional* gates. I verified the rows whose behaviour was
  cheap to probe (#33, #52, #84) and read the rest; rows #1–#32 and #38–#83 are dispositions recorded with
  evidence elsewhere and were not re-executed.
- `analysis` greps (`rg`) with a pipeline can report the pipeline's exit status; every probe above captures
  the binary's own `rc` with no pipe.

## Dispositions — every item in this report, and what became of it

Written so coverage is auditable rather than asserted. Nothing in the list is left without a disposition.

| item | class | disposition | evidence |
|---|---|---|---|
| F1 AEAD receive-counter monotonicity | TODO, security | **FIXED** — `open` now takes `&mut self`, authenticates first, then requires a strictly increasing counter (`AeadError::StaleCtr`); the first authentic frame sets the baseline so the peer's start counter is not assumed; a rejection does not advance the baseline | `crates/tallow-admission/src/aead.rs` + 2 call sites (`server.rs`, `client.rs`); 3 tests incl. replay, reorder, baseline; crate suite run |
| F2 23 declared-but-unwired browser functions | drift (loud) | **REGISTERED** as row #88 (kept, not deleted — removing public stdlib surface is an operator call) | `docs/operations/stub-register.md` row #88 |
| F3 eleven finance-IR ops in one evaluator | Deflect-adjacent | **REGISTERED** as row #89 (scope narrowed by follow-up: one evaluator, not the op set) | `docs/operations/stub-register.md` row #89 |
| F4 vestigial stub helper (`net.rs not_yet`) | Stub (dead) | **DELETED** — zero callers confirmed before removal | `src/stdlib/net.rs` |
| Checked-and-dismissed: azure `dispatch_method`, `mesh.rs` simulated marker, svid `placeholder_cert` | — | **NO ACTION** — each verified benign in the report body | §"Checked and dismissed" |
| Registered instances (#33, #52, #59, #62, #65, #66, #67, #68, #84) | registered | **NO ACTION** — already in the register; #84's claim was independently reproduced by probe | §"Registered instances" |
| False positives (10 classes) | — | **NO ACTION** — each excluded with its reason recorded | §"False positives excluded" |
| Method limitations | — | **UNCHANGED** — F3's parity question is now row #89's open item | §"Method limitations" |
| F5 untracked build inputs (`schemas/`) | uncommitted build input | **FIXED here** (`24a3c04`); **open in the development tree** (remedy: `git add schemas/`) | §F5 |

Verification of this disposition pass: the `TODO` in `aead.rs` no longer exists (the file's own doc states the
enforced rule), `not_yet` no longer exists in `net.rs`, the register's row count moved 87 → 89, and the
admission crate's suite passes with the new tests. Each landed as its own scoped commit.
