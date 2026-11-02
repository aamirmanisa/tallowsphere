# Changelog

All notable changes to Tallow are recorded here.

Every version section MUST contain `### What was wrong` and `### What was fixed`.
`scripts/release_body.py` builds the GitHub release body from these sections and
the release workflow fails when either heading is missing — a release that does
not say what broke and what repaired it cannot be published.
Format: [Keep a Changelog](https://keepachangelog.com/) · versions: [SemVer](https://semver.org/).
Release identity for V1 is **local-only (R0)** — see `docs/release/versioning-policy.md`.

## [v1.7.0] — 2026-11-01 — Every egress path consults the register, and http.batch has a type

### What was wrong

The authorization register decided whether a request could be built, but only on the
paths that remembered to ask. Twenty-five stdlib modules consulted it; every other way
out of the engine did not, and the coverage test meant to catch that could only see
`src/stdlib/*.rs` and only an `egress_http::` verb — so a module reaching the network
through `ureq`, `reqwest` or a raw socket was invisible to it. Measured on the published
tree before this release: 68 ungated egress sites across 35 files, including the browser
plane and the engine's own startup path.

Two further defects, measured rather than inferred:

- A redirect was followed without asking the register again. A listed host answering
  `302` to an unlisted one made the engine fetch the unlisted host and return its body,
  while `Response.url` still reported the listed URL — `ureq`'s default of ten redirects
  applied because the shared agent set no policy.
- `http.batch` entries had no type on the compiled plane: reading `entry.response.status`
  could not be lowered, and an explicit `[]BatchResponse` annotation found no such struct.
  The same program was refused natively and ran on the interpreter.

### Added

- A gated follow loop: `max_redirects(0)` on every agent builder, and the only way to
  follow a redirect re-consults the register per hop, resolves `Location` against the
  current URL, refuses a downgrade or non-HTTP scheme, re-authorises under the method the
  next request will carry, stops at eight hops, and reports the URL that produced the body.
- Register gates on 48 modules across the stdlib, browser and engine planes — the verb
  the request uses, fatal where a caller would otherwise swallow the refusal.
- `tests/egress_gate_coverage.rs` scans all of `src/` for `egress_http::`, `ureq::`,
  `reqwest::` and raw connects and fails on an ungated site; twelve exemptions carry a
  one-line reason each.
- A typed `http.batch` entry on both planes: `#[repr(C)]` records plus a dedicated
  `tallow_http_batch_entries` entry point, `pool.map`'s ABI untouched, and a parity test
  that runs the same program under `--interpret` and `--require-native` with nothing
  ignored.
- A `#[cfg(test)]`-only thread-local register fixture, so gate behaviour is testable
  without depending on the shipped register, and `CONNECT` as a grantable verb that is
  never a default.

### Fixed

- The element of an array-of-arrays is not a string. `[10, 20].zip([30, 40])[0][1]` and the
  same shape from `chunk`/`enumerate` travelled the string index path because the inner
  slot is pointer-shaped: it read the inner count word as text and then failed with
  `runtime error: index 1 out of bounds`. The array lowering now asks whether the slot is
  an untagged inner array before asking whether it is a pointer.
- `https://host?q=1` was refused as the host `host?q=1`; the authority now ends at the
  first `/`, `?` or `#`, and a query-carried auth path is still refused.
- Mesh test fixtures took a cross-process lock, so concurrent worktrees no longer collide
  on fixed loopback ports.
- Privacy: a client street address and a live-format phone number used as demo data are
  replaced with reserved values (555-01XX and documentation addresses), and the seed
  record no longer borrows a real carrier's name.
- Internal working documents (agent notes, benchmark protocols, the publication manifest)
  are not part of this repository.
- `tallow doctor --capabilities` no longer under-reports crypto. Since 2026-10-27 the
  report read only `fn` declarations and skipped the 32 written in the canonical
  `native fn` form, so `hpke_seal`, `hpke_open` and the FROST/BBS+/age/opaque surface
  were missing from a report that claimed to enumerate them.
- **`.len` on a chained native-array call read the count slot as a C string.** A native
  array is `[count: i64][slot: i64]…`, and a chained call (`page.get_cookies()`,
  `env.args()`, `doc.select(…)`, `el.classes()`, `http.batch(…)`) has no bound variable
  for the let-tracker to record, so `expr_is_native_array`'s `MethodCall` arm consulted
  only the array-method registry and answered false even where `infer_kind` on the same
  expression already answered `CookieArray`. `.len` then took the string branch and ran
  `strlen` over the buffer, which reads the count's low byte and stops at the NUL of its
  second byte — 0 → 0, every count in 1..=255 → 1. Measured in
  `tests/browser_array_parity_cookies.rs`, both planes on the same program:
  `native=["0","1","1"]` against `interp=["0","1","3"]` for `page.get_cookies().len`
  before any cookie, after `set_cookies_from_header("a=1", …)`, and after
  `set_cookies_from_header("a=1; b=2; c=3", …)` — a three-element cookie array reported
  1. The array contents were always right; only the length collapsed, which is why the
  two-cookie case passed and three did not. The compiled plane now reads the count, the
  same value the interpreter reports, through a single `kind_is_native_array` predicate
  in `src/codegen.rs` shared by both call sites; no FFI or marshalling change.
  `tests/chained_native_array_len.rs` pins chained and bound forms at N = 0, 1 and 3 on
  both planes without a browser, and runs in CI.

### Known at tag time

Measured, not hedged — each line names what is still true when this tag ships:

- **Windows and macOS are CI verdicts, not locally measured ones.** The release was cut
  on aarch64 Linux. The unix-only topology, ICMP and probe paths now carry
  `cfg(unix)` guards with refusing stubs that name the missing capability, and a cfg
  census (`tests/egress_gate_coverage.rs`, 28 pinned sites) fails the tree if a new
  cfg-gated egress site appears without a row stating what the other platform does.
  Whether the Windows build and the macOS lib suite are green is answered by the tag's
  own CI run, and only by it.
- **`zstd 0.13.4` stays in the lock.** `wreq-util 3.0.0-rc.14` requires `zstd ^0.13.3`
  inside its default `emulation` feature, which also gates the `Profile` type the
  default stealth-http client is built from, so that copy cannot leave the graph
  without deleting a capability. RUSTSEC-2026-0391/-0398/-0403 are answered per
  affected function in `.cargo/audit.toml` — none of those three functions is called
  in this graph — under a review deadline of 2027-01-31, after which the gate fails
  again.
- **The perf gate compares like with like or not at all.** The corpus is pinned and the
  baseline is selected by architecture and build profile; a cross-architecture
  comparison is refused rather than reported as a regression.
- **`storage.googleapis.com` is now a register entry.** The CI browser jobs were failing
  because the scope gate refused it before the GET, not because the pinned Chrome for
  Testing artifact was wrong. The grant is exact-host, `public-read-only`, GET/HEAD,
  expiring 2027-11-02.
- **`Array.push` has no lowering on the compiled plane.** `tallow build` refuses a
  program that grows an array with `.push()` by name ("the native backend has no
  lowering for Array.push") and `tallow run` falls back to the interpreter, so the
  behaviour is correct and slow rather than wrong. The lowering used to SEGFAULT with no
  error text, which the fallback swallowed; a named refusal is the improvement, and the
  E1 parity table now records it as such instead of expecting a byte match.
- **A cookie array's length stopped at 1 on the compiled plane; that is fixed above, and
  the rest of the family is not.** Measured by `tests/browser_array_parity_cookies.rs`,
  both planes on the same program: `native=["0","1","1"]` against
  `interp=["0","1","3"]` for `page.get_cookies().len` before any cookie, after
  `set_cookies_from_header("a=1", …)`, and after
  `set_cookies_from_header("a=1; b=2; c=3", …)`. The chained-`.len` lowering named in
  `### Fixed` carries that case and is pinned at N = 0, 1 and 3 by
  `tests/chained_native_array_len.rs`; the browser-backed parity suite is still written
  in terms of the old gap at tag time and only its own run after the fix answers it.
  `Element.classes` is the same family and has no lowering at all; it stays pinned as a
  refusal in `tests/browser_unlowered_gaps.rs`.
- **The three browser suites had never run before this tag.** `browser_sentinels_live`,
  `browser_array_parity_cookies` and `browser_flow_runtime_integration` were not
  exercised on any earlier tag: the Chrome-for-Testing install step failed before them
  (the scope gate refusal recorded in the `storage.googleapis.com` entry above), so CI
  never reached their bodies. Their first real execution is this tag's own CI run
  (41389719617), where all three are red. Of the causes measured so far,
  `browser_sentinels_live` fails at `tests/browser_sentinels_live.rs:56`, which spawns
  the binary with `.current_dir(&dir)` while the register path it passes is relative;
  `browser_flow_runtime_integration`'s cause is not yet established. They are newly
  observed, not newly broken.

## [v1.6.0] — 2026-10-31 — Eight compiler defects closed, and the gates move into the binary

### Added

- `tallow gate <name>`: the nine repository gates (ffi-symbols, census-surface,
  census-page-methods, capability-registry, crypto-inventory, docs-examples,
  panic-policy, release-body, sbom) now run from the compiler binary instead of a
  pile of Python scripts, so the same claim can be checked on any checkout with
  one command. Unit tests live in `src/gate/`; `tests/gate_*_parity.rs` compares
  every gate against the script it replaces, on the live tree.
- Conformance cases 41–47: closure write capture, string index, logical
  short-circuit, map `len`, index assignment, block shadowing, and `nil` into a
  non-optional destination. The corpus is 27 cases / 54 files and its digest now
  covers every file under `cases/`.
- `tests/conformance_runner.rs`, which runs the whole corpus through
  `cargo test` on both planes, takes the compiler under test from `TALLOW_BIN`,
  and refuses to pin a case whose two planes disagree.
- `tests/async_await_idempotent.rs`: awaiting one handle twice, and awaiting the
  same handle twice inside a comparison, on both planes.
- `E0116`, the diagnostic that refuses `nil` where a non-optional type is
  required, with the optional-typed remedy in the help line.

### What was wrong

- **String indexing read a pointer as a character.** Strings and native arrays
  share the `i8*` type, so the index lowering treated the string's first bytes as
  an element count and loaded character data as an `i64` slot: `"hello"[0]`
  printed `281474234531448` on the native plane while the interpreter printed
  `h`. In-bounds access, not an edge case.
- **`map.len` was 1 for every non-empty map.** The field-read path fell through
  to `strlen` on the payload slot; the method-call spelling already guarded for
  maps, the field spelling did not.
- **Index assignment was dropped.** `a[1] = 20` never reached the element on the
  native plane, so a program that then printed `a[1]` printed the old value.
- **`&&` and `||` were not short-circuit.** Both operands were evaluated, so a
  side effect on the right-hand side ran even when the left decided the answer.
- **Block shadowing leaked.** A binding declared in an inner block stayed visible
  after the block on the native plane.
- **`spawn`/`await` returned 0 instead of the task's value.** The native await
  returned the raw wrapper pointer rather than the result payload, and even
  after the wrapper was unwrapped the value slot was loaded as `i64` for every
  payload kind: awaiting a `String` printed pointer bits that changed each run,
  and awaiting a `Map` printed pointer bits where the interpreter printed `nil`.
- **Awaiting one handle twice aborted the binary.** `let a = h.await; let
  b = h.await` died with `free(): double free detected in tcache 2`, exit 134,
  on 5 of 5 runs.
- **`defer` in a loop ran three times and all three bodies saw the final loop
  value**, so `defer { close(h) }` in a loop closed the last handle three times.
- **`let x: i64 = nil` passed the checker with zero diagnostics**, and the two
  planes then disagreed about what `x` held (interpreter `nil`, native `0`).
- **A refused `net.connect` was reported and then ignored.** The compiled plane
  printed the scope refusal, printed whatever came next and exited 0, while the
  interpreter aborted with exit 1 — the refusal was an ordinary value, not a
  gate.
- **A fetched 404 arrived as a transport error on the native plane.** `ureq`
  reports `4xx`/`5xx` as `Err`, so the interpreter returned a `Response` and the
  native path returned a failure, for the same URL.
- **The conformance digest covered 19 of 26 cases.** Seven cases shipped beside a
  manifest that did not include them, so the corpus could grow without its own
  digest noticing.

### What was fixed

- `src/runtime/fs_ffi.rs`, `src/codegen.rs` — `tallow_string_index` indexes a
  string by Unicode scalar, which is what the interpreter's `s.chars().nth(i)`
  already did, and returns null with `index N out of bounds` past the end; the
  index lowering routes that null through `tallow_check_string`, so both planes
  abort with the same sentence. `"αβ"[0]` is `α` on both planes, not the first
  UTF-8 byte.
- `src/codegen.rs` — a map receiver routes to the count slot before the string
  path, so `m.len` reads the entry count; the index-store path targets the
  element slot; `&&`/`||` lower to branches; scope restore is emitted at every
  block exit; the await arm unwraps the `TallowResult` value slot, carries the
  spawn handle's declared payload kind (`variable_spawn_payload`) so a `String`
  or `Map` payload is not loaded as `i64`, and refuses at compile time when the
  kind cannot be recovered instead of guessing; a `net.connect` handle that is
  null after the FFI call goes through `tallow_check_string`, so a scope refusal
  aborts the program; handle release happens once per handle rather than once
  per await; defer registrations capture the iteration's value at registration
  and drain LIFO.
- `src/stdlib/http.rs`, `src/interp.rs`, `src/codegen.rs`, `src/runtime/fetch.rs` —
  the authorization register is consulted by `http.get`, `http.post`,
  `http.put`, `http.delete` and `http.batch` before any socket on both planes,
  and a refusal is fatal on both. POST previously consulted nothing at all: it
  spent the connection attempt and returned a transport error as data, while the
  compiled plane printed `(null)` and exited 0. A literal loopback address no
  longer goes through the egress proxy, which is the branch the interpreter's
  agent has always taken.
- `src/interp.rs` — the recorded task result is kept in an idempotent cache, so a
  second await returns the same value instead of draining a single-shot channel;
  defer order and per-iteration capture match the native plane.
- `src/typeck.rs` — `E0116`: `nil` into a non-optional destination is refused
  instead of silently accepted.
- `src/stdlib/net.rs`, `stdlib/http.tl`, `stdlib/net.tl` — the fetch agent is
  built with `http_status_as_error(false)`, and `fetch`, `Client.get`,
  `Client.post`, `TorPool.fetch` and `ProxyChain.fetch` return `Response`
  instead of `Result<Response>`: a status the program can inspect is data, not a
  failure the runtime invents.
- `tests/defer_parity.rs` — the loop expectations are corrected to the language's
  per-registration, LIFO rule (the FIFO expectation was the test's bug), and each
  case gets a private temp directory so two parallel legs stop deleting each
  other's files.
- `conformance/run.py` is deleted in favour of `tests/conformance_runner.rs`; both
  workflows call it, and the release workflow points `TALLOW_BIN` at the unpacked
  artifact so the packaged binary is what gets proven.
- `conformance/README.md` — the count, the file count and the digest are
  regenerated over the whole corpus.

### Known at tag time

Measured on the tagged tree, recorded rather than hidden:

- **The egress register is a chokepoint on the paths this release tests, not on
  every path.** `net.connect`, `http.get`, `http.post`, `http.put`,
  `http.delete` and `http.batch` consult it on both planes and a refusal is
  fatal on both (measured 2026-10-31, tallow 1.5.8+4 merges: `http.post` to
  192.0.2.1 → `runtime error: … not in the authorization register`, exit 1, no
  socket). Still uncovered: an `atlas` census counts 18 stdlib modules holding
  socket primitives with no `crate::scope::` call (`http, ws, osint, transfer,
  transfer_net, mesh, email, llm, medium, substack, beehiiv, ghost, cxense,
  cnam_dip, lrn_dip, sitescan, sync, wordpress`) and 113 socket sites under
  `src/browser/` with none.
- **A transport failure aborts on the native plane where the interpreter returns
  a value.** Measured on a loopback GET to a closed port: `--interpret` →
  `Err("http.get: io: Connection refused (os error 111)")`, exit 0;
  `--require-native` → `runtime error: fetch: io: Connection refused`, exit 1.
  The compiled plane has no `Err` value for these calls, so the null handle is
  fatal rather than silently `(null)` — loud, but not parity, and a program that
  inspects the result cannot tell a transient failure from a refusal there.
- **`http.get` still disagrees on a 404 between the planes.** Measured by the
  merged `tests/http_status_as_data_parity.rs` (case
  `http_get_404_planes_agree`, `#[ignore]`d with the values):
  `--interpret` → `Err("http.get: http status: 404")`, `--require-native` →
  `status=404 body=missing-body`. `fetch()` and `Client.get` return statuses as
  data on both planes; the `http.*` verb path does not, on the interpreter side.
- **The native POST path is dead.** `http.post` returns a null handle on the
  native plane for every case measured (200 and 404), so with the fatal guard a
  native POST now fails loudly instead of silently; the per-call timeout argument
  to `http.get` is ignored there while the interpreter honours it.
- **Six of the nine gates cannot fail on today's tree** (`capability-registry`,
  `ffi-symbols`, `census-surface`, `docs-examples`, `census-page-methods`,
  `panic-policy`, and `release-body`'s substring-heading check): mutating a
  scratch copy turned every other check red and left these green. The parity
  suites prove binary-equals-script, which is not the same as proving the gate
  detects the defect it names.
- **`tallow gate --help` does not list the nine gates.** A bare `tallow gate`
  lists two; an unknown name refuses and lists ten, including `test-summary`.
- **The native POST path is dead.** `http.post` returns a null handle on the
  native plane for every case measured (200 and 404), and the per-call timeout
  argument to `http.get` is ignored there while the interpreter honours it.
- **The release gate is wider than the merge gate in one direction and narrower
  in another.** The tag path runs 113 fewer suites, never runs the SBOM drift
  check, and `tests/gate_release_parity.rs` does not carry `v1.6.0` in its
  version list, so the Rust `release-body` port is unproven on this release's
  body.
- `scripts/check_backlog_evidence.py` fails `G07` (the row points at
  `src/interp.rs:23659`, which does not mention `bind_binding_pattern`);
  pre-existing, not introduced here.

## [v1.5.8] — 2026-10-26 — UTF-8 literals, and two names the checker called undefined

### Added

- `TypeEnv.constants`, the set of top-level `const` names the checker now
  consults — the missing half of the name resolution described below.
- Regression tests: `lexer::tests::lex_string_keeps_multibyte_utf8`,
  `typeck::tests::const_use_does_not_warn_w0102`,
  `typeck::tests::filecopy_namespace_does_not_warn_w0102`.

### What was wrong

- **Every non-ASCII string literal was double-encoded.** The lexer decoded each
  byte of a UTF-8 scalar as a Latin-1 character, so `print("—")` wrote
  `c3 a2 c2 80 c2 94` and a program whose source said `—` printed `â€"`. Both
  planes, every release. Found from the outside: `tallowx --help` printed
  `tallowx â verified copy/move`.
- **Two classes of defined name were reported as undefined.** Top-level `const`
  declarations were never registered in the type environment, and the
  `FileCopy` runtime module was missing from the builtin list, so a program
  using either correctly warned `W0102 use of possibly undefined variable` on
  every use. `tallowx` printed three warnings on a clean run because of it.

### What was fixed

- `src/lexer.rs` — the four string scanners (`scan_string`,
  `scan_triple_quoted_string`, `scan_single_quote_string`,
  `scan_string_continuation`) now step by one scalar instead of one byte, via
  `push_char`; an invalid or bisected sequence appends U+FFFD and advances one
  byte so malformed input cannot stall the loop. Covered by
  `lexer::tests::lex_string_keeps_multibyte_utf8` and, end to end, by the
  `22-utf8-literals` conformance case in Tallow-Language.
- `src/typeck.rs` — `TypeEnv` gained a `constants` set populated from
  `Item::Const`, and `FileCopy` joined `is_builtin_name`. Verified:
  `tallow check tallowx.tl` went from `28 items, 3 warnings` to
  `28 items, 0 warnings`; `typeck::tests` 218 pass, including new tests that a
  const and `FileCopy` do not warn and that a genuinely undefined name still
  does.

## [v1.5.7] — 2026-10-25 — the audit pass: dependency refresh and a register that renders

### Added

- `docs/operations/dependency-exceptions-2026-10-25.md` — the eight advisories
  that survive this refresh, each with the code path it can reach and a
  2027-01-31 expiry, cross-referenced from `deny.toml` so the decision lives in
  one place and the gate re-opens the question on a date instead of forever.

### What was wrong

- **248 crates were behind their published versions.** Not one of them was a
  security fix we could take, but the tree had drifted enough that every future
  advisory would have needed a manual "is this reachable?" argument against a
  stale graph.
- **The stub register did not render.** Twenty-six rows were malformed — 22
  written with three columns, three missing a closing cell, two carrying
  unescaped `|` from pipe-operator examples — and ids 104 and 120 were absent.
  The guard that should have caught it asserted `1..=103` and had been failing
  since the register grew past that.
- **The advisory gate was red with no decision recorded.** `cargo deny
  --all-features` reported eight advisories and nothing in the tree said whether
  any of them mattered here.

### What was fixed

- **`?` kept the payload's kind.** `fn flag() -> Result<bool>` unwrapped with
  `?` came back as a bare `i64` on the native plane, so `b.to_string()` printed
  `1` where the interpreter printed `true`, and a `Result<String>` payload
  printed the pointer as a decimal. `collect_fn_return_kinds` now records
  primitive return kinds and the `?` lowering consults the callee's signature
  when inference is silent. Pinned by `tests/result_payload_typing.rs` on both
  planes. (Prepared as 1.5.6; that tag never published, so the fix ships here.)
- `cargo update`: 248 semver-compatible upgrades (lockfile 852 insertions /
  987 deletions), SBOM snapshot regenerated in the same change.
- Stub register normalised to five columns per row (surplus `|` → `│`, omitted
  columns padded with `—` and the header states what `—` means), the two gap ids
  recorded as gaps rather than renumbered, and the guard now derives N from the
  file.
- **`copy` treated "file onto itself" as whatever the OS thought.** Linux
  allows it, Windows returns a sharing violation (os error 32), and the verify
  path does exactly that to hash a file — so the Windows job failed on a green
  Linux tree. `copy_file_streaming` now canonicalises both sides and skips the
  write when they are the same file; a regression test pins the behaviour.
- Every advisory is now an explicit entry with a reachability argument:
  `crypto-bigint 0.5.5` (RUSTSEC-2026-0387) is reached only through HPKE's
  **ephemeral** P-256 keys and never through our OPAQUE, which is Ristretto255;
  the three `libcrux-*` advisories exist only behind `--features fhe` and are
  pinned by `tfhe 1.8.2`.

### Verified

- `cargo test --lib` → 9,267 passed / 0 failed / 33 ignored (153.88 s).
- Nineteen release-gate integration suites → 19/19 ok, 0 failures.
- `cargo deny --all-features check advisories` → advisories ok.
- `tests/test_docs_truth_maintenance.py` → 10 tests OK; `check_test_coverage.py`
  → 136 targets, 134 in CI, 2 registered debt, 0 unaccounted.

## [v1.5.6] — 2026-10-25 — `?` keeps the payload's kind

### Added

- `tests/result_payload_typing.rs` pins the `?` payload kind on both planes
  (`Result<bool>`, `Result<String>` printed and `.len()`'d, `Result<i64>`), and
  the target is registered in CI's contract suites and in the release gate's
  integration list. It was written for this fix and had to be wired into the
  gates before the ledger would accept it: an unrun test is debt, not a proof.

### What was wrong

- **A value unwrapped with `?` lost its type on the native plane, and printed
  the wrong thing.** `fn flag() -> Result<bool>` then `let b = flag()?;
  b.to_string()` printed `1` natively and `true` interpreted; a `Result<String>`
  payload printed the pointer as a decimal integer (`str=201890135739400`). Every
  exit code stayed 0 — the failure mode is a wrong value, not a crash, which is
  the worse of the two.

  Two gaps, both in `src/codegen.rs`. `collect_fn_return_kinds` recorded a
  callee's return kind only for `String`, `Bytes`, containers and registered
  structs, so a primitive payload had no kind at all. And the `?` lowering asked
  `infer_kind` for the payload kind, which has **no `Call` arm** — so for
  `let x = f()?` it always answered `None` and fell back to `LLType::I64`. The
  earlier inttoptr repair could therefore never fire for a call result.

### What was fixed

- `collect_fn_return_kinds` now also records `bool`, `i64` and `f64` return
  kinds.
- The `?` lowering falls back to the callee's signature when `infer_kind` is
  silent, and returns `i1` for a bool payload (`trunc i64 → i1`) and a pointer for
  handle payloads, instead of a bare i64.

### Verified

- New `tests/result_payload_typing.rs`: `Result<bool>` (printed), `Result<String>`
  (printed and `.len()`'d) and `Result<i64>` through `?`, asserted byte-identical
  between `--interpret` and `--require-native`, with the native leg required to
  have compiled rather than fallen back.
- The parity suites re-run green on this tree: `interp_codegen_parity`,
  `result_truthiness_parity` (4), `data_enum_print_parity` (4), `optional_parity`
  (2), `truthiness_parity`, `native_fn_decl` — 13 tests, 0 failed.

## [v1.5.5] — 2026-10-25 — Windows builds again

### Added

- Nothing user-facing.

### Fixed

- **The Windows build could not compile the library.** `tallow_time_monotonic_ns`
  called `libc::clock_gettime(CLOCK_MONOTONIC)`, which `libc` does not provide on
  Windows — the job failed with E0425 on both the function and the constant, so
  the 1.5.4 tag shipped without a windows-x86_64 asset (macOS was still building
  when the tag was cut). The clock now measures against a process-wide `Instant`,
  which is monotonic on every supported target and needs no platform binding.
- **SBOM drift after the version bump**: the snapshot is regenerated in the same
  change as the bump, which is what the byte-comparing gate requires.

### Verified

- `cargo check --lib` clean; the Linux and macOS release builds of 1.5.4 were
  green, so this is the only platform that changed for 1.5.5.

### Known red, not hidden

- **Security Audit / Dependency Check**, after the upgrade pass:
  * `sha3` 0.10.8 -> **0.10.9**, clearing RUSTSEC-2026-0374 (incremental SHAKE).
  * `crypto-bigint` RUSTSEC-2026-0387 **cannot be cleared from this tree yet**:
    the vulnerable 0.5.5 comes in through `elliptic-curve` 0.13 <- `p256` 0.13
    (via `age` 0.12.1 and `hpke`) and `opaque-ke` 4.0.1. The fix is 0.7.6, which
    `elliptic-curve` 0.14 requires — and no released `age` (0.12.1 is current)
    or `opaque-ke` (4.1 is a pre-release) pulls 0.14 yet. Upgrading means either
    waiting for those releases or vendoring/patching them here.
  * `basic-toml` (unmaintained, no vulnerability) arrives with `age`'s i18n
    stack; it goes away with the same age upgrade.
  * `proc-macro-error2` and `libcrux-aesgcm` appear only in the --all-features
    graph (`tfhe`, `openmls`) and are likewise upstream-pinned.

  So the audit job stays red until `age`/`opaque-ke` move. That is a measured
  blocker, not an unexamined one; clearing it needs a fork or a documented
  exception, and neither is in this release.

## [v1.5.4] — 2026-10-25 — the gates that judged 1.5.3 are green

### Added

- Nothing user-facing. This release exists because v1.5.3's own workflows failed
  and a tag is immutable, so the fix goes forward rather than into history.

### Fixed

- **The Release gate could not pass on any runner without `age(1)`**:
  `age_native_parity` and `age_container` decrypt with the reference
  implementation in both directions and panicked with `install age to run this
  test`. The workflows now install `age` before the suites. A missing dependency
  was being reported as a test failure.
- **`cargo check --all-targets` could not compile the tree**: `examples/mls_probe.rs`
  imported `tallow::mls` unconditionally, so Check and Clippy failed without the
  feature. The example now builds a stub that says which feature it needs.
- **The ZK CI job tested the wrong refusal**: it used `--require-native`, which
  fails on "no native lowering" before the feature message is reachable. It now
  uses `--interpret`, which is the path that exercises the gate.
- **Dependency Check rejected tfhe's licence** (`BSD-3-Clause-Clear`); allowed
  with the rationale in `deny.toml`.
- **SBOM and CBOM drift**: both artifacts regenerated for the new dependencies and
  the new crypto surface; both `--check` gates pass.
- **`a_tampered_container_is_refused` was flaky by construction**: it replaced the
  last hex nibble with `"0"`, a no-op whenever that nibble already was `"0"` (1 in
  16 runs). The mutation moved into Rust and is proven to differ.

### Verified

- 19 release-gate suites: 18 green, 1 (the flaky tamper test) now fixed and
  passing 3/3 on its own.
- `sbom-gen --check` and `crypto-inventory --check` pass; `cargo deny check
  licenses` passes.
- Default and `--features mls` builds both compile the example.

### Known red, not hidden

- **Security Audit**: 9 advisories, including `crypto-bigint` RUSTSEC-2026-0387
  (published 2026-10-23) and `libcrux-aesgcm` RUSTSEC-2026-0209. Both transitive
  and newer than the previous release. Clearing them is a dependency arc, and the
  repository's policy requires a documented exception for any ignore.

## [v1.5.3] — 2026-10-25 — crypto that does the thing, and says so when it cannot

### Added

- **age containers (C2SP)**, interoperable with `age(1)` in both directions —
  proven by decrypting each implementation's output with the other, not by a
  self round-trip.
- **OPAQUE (RFC 9807)** via `opaque-ke` (ristretto255, TripleDH/SHA-512), with a
  ten-call message-passing surface and a real registration/login flow.
- **MLS (RFC 9420)** via openmls 0.7.1, feature-gated behind `--features mls`.
  Group state lives in an in-process registry keyed by handle; a Welcome can only
  be processed by the provider that created the key package, so the handle is
  returned from `key_package_new`.
- **Chunked, resumable transfer**: a directory of ordinary age containers plus a
  manifest; resume re-encrypts only the missing parts. Measured on 2.5 MB / 1 MiB
  parts: 3 parts, native round-trip byte-identical.
- **Opt-in ZK** (`--features zk`): Bulletproofs range proofs,
  `crypto.zk_range_prove` / `zk_range_verify`, no trusted setup.
- **Opt-in FHE** (`--features fhe`): tfhe 1.8.2, `crypto.fhe_{keygen,encrypt,add,decrypt}`.
  Measured: keygen 1,436 ms, add 174 ms, 200+100 → 44 (modular, as an unsigned
  byte should be).
- **Native lowering** for age, OPAQUE, keypair generation, MLS and chunked
  transfer, each verified under `--require-native` against the interpreter.
- **A per-function capability report** (`tallow doctor --capabilities`): every
  declared crypto function with its status and a quoted reason for anything that
  is not `implemented`.
- **Assurance**: KATs (FIPS 180-4, BLAKE3, RFC 5869, RFC 8032), a deterministic
  mutation sweep (8,000 hostile inputs, zero panics), a dudect-style AEAD timing
  harness, and a `cargo-fuzz` harness whose two targets executed 2,358,971 and
  1,587,576 runs in 101 s each with no crashes.
- **MLS, ZK and FHE CI jobs**, so none of the opt-in paths is hand-verified only.

### Fixed

- **Nine crypto calls were approximations that returned plausible values** for
  algorithms they did not implement, and `opaque_register` was not OPAQUE at all.
  They now refuse and name what replaces them.
- **`print()` of a struct leaked private keys**: `print(crypto.age_keygen())`
  wrote an `AGE-SECRET-KEY-1…` to stdout, and the same hole exposed the secret
  half of nine key types. Redaction is table-driven and a gate fails any new
  struct with a secret-sounding field.
- **OPAQUE's native lowering segfaulted**: the C side returned a bare pointer
  where the language surface declared a record, so the generated IR read text
  bytes as a pointer. Every new FFI returns a `#[repr(C)]` record mirroring the
  codegen layout.
- **`print(<struct>)` on the native plane printed binary garbage**; it is now a
  named compile-time refusal that tells you to print a field.
- **`fs.delete` asked `stat` for `is_dir` through a missing extern**, and a
  result-carrying program could not run natively at all.
- **`copy` verification was unfalsifiable and memory-unbounded**; `copy.try_file`
  returns `Result<CopyStats>` and the engine copies in bounded chunks.
- **Feature refusals told the reader to `--interpret`**, which fails identically
  because the stdlib module is compiled into both planes. They now say which
  feature to rebuild with.

### Verified

- Library suite green; 135 test targets, 133 wired into CI, 2 registered debt
  (perf), 0 unaccounted.
- age/OPAQUE/MLS native paths byte-identical to the interpreter on the same
  program; chunked transfer round-trips 2,500,000 bytes as 3 parts.
- Default build refuses `crypto.mls_*`, `crypto.zk_*` and `crypto.fhe_*` by name
  with exit 1; feature builds run them.

## [v1.5.2] — 2026-10-24 — the release gate runs what CI judges the tree by

### Added

- **The release gate runs the integration suites.** `parity_runner`,
  `mesh_plan_tl`, `mesh_plan_parity`, `process_contract`, `stdlib_method_refusals`,
  `injection_redteam`, `egress_census` and `llm_native_parity` now run before any
  target is built, and `integration.log` travels with the run's artifacts. Before
  this, two v1.5.1 tags published from a tree whose lib suite and conformance
  corpus were green while those suites were red — the gate duplicated CI's cheap
  half and skipped the half that catches codegen regressions.

### Fixed

- **README version claims.** The badge, install transcript, `--version` block and
  `/opt` paths still named 1.5.0 and commit `0fdd5797ee`, four releases late. Every
  dated claim was re-measured against the published 1.5.1 artefact (checksum
  verified, installer probe passed, `schema check` exit 0, `extract` one row with
  an empty quarantine).
- **The `--version` transcript no longer pins a commit sha** it cannot know before
  the tag exists; it shows the version, platform, arch and build stamp, and says
  the `git:` line names the tagged commit.

### Verified

- v1.5.1's published linux-aarch64 tarball: sha256 `70748912…e492f9b` matches its
  sidecar; extracted binary prints `1.5.1`; `Mesh.replay` runs natively; the
  two-JSON-LD `.len` probe returns 2 interpreted and 2 compiled.
- Full library suite 9,250 passed / 0 failed / 33 ignored; 13 integration suites
  re-run green after the codegen fixes.

## [v1.5.1] — 2026-10-24 — llm and mesh compile natively

### Added

- **Native lowerings for all six `llm`/`Mesh` entry points.** `llm.complete`,
  `llm.models`, `llm.verify`, `llm.providers`, `Mesh.plan` and `Mesh.replay` now
  build with `--require-native` instead of falling back to the interpreter. The
  runtime builds the same records the interpreter builds (`Completion`,
  `ModelInfo`, `VerifyReport`, `ProviderInfo`, `MeshPlan`, `MeshReplay`) and the
  compiled path reads them through the ordinary struct/array GEP path.
- **`Mesh.plan` respects the program's own `struct MeshTask`.** The lowering reads
  that declaration, requires the five contract fields, verifies their types
  (`String, String, []String, String, String?`) and passes each field's byte
  offset to the FFI, so a reordered struct plans correctly and a declaration the
  backend cannot read (`deps: String`) is refused at compile time with the field
  named.

### Fixed

- **`infer_kind` ignored `variable_struct_types`**, so a struct binding had a type
  for field reads but not for the array test: `p.wave_sizes.len` strlen'd the
  buffer and answered 1 for a 3-element array.
- **A `[]T` struct field was not recognised as a native array**; that now comes
  from the declaration instead of a hard-coded name list.
- **Container field kinds were dropped when a program declared a struct with the
  same name** as a synthesized record (`struct MeshReplay`), because the struct
  scan registers that name first and every `or_insert_with` for it was a no-op.
- **`.len` on a struct-field array strung the count slot.** `expr_is_native_array`
  returned `false` whenever the owner type was not a program-declared struct, so
  `sd.json_ld.len` fell through to `strlen` over the native array's `[count][…]`
  header — and since a little-endian count is followed by NUL bytes, that answered
  **1 for every non-empty array**. The parity fixture caught it: `StructuredData.extract`
  on a page with two JSON-LD blocks printed 2 interpreted and 1 compiled. The check
  now falls back to the field's registered container kind and then to the
  expression's inferred kind.
- **`print(<struct>.<array field>)` printed one control byte.** The composite
  print route handled literals and bindings but not field access, so `print(p.wave_sizes)`
  fell to the string path and strlen'd the `[count][elem…]` header — printing
  `\u{3}` for a 3-element array instead of `[1, 2, 1]`. Field kinds now route to
  the array renderer.
- **Array-element field reads only worked for bindings**, not for struct fields —
  `r.checkpoints[0].wave` had no route to the element struct.
- **The release workflow's body gate grepped `^## Added`** while the generator
  emits `### Added`, which blocked every release since 1.3.0 after all five
  platform builds and checksums had succeeded.
- **The SBOM snapshot lagged the version bump**, failing the drift gate on the
  release commit; regenerated with the count unchanged at 716 packages.
- **README carried 1.1.5 claims** four releases late; every dated claim was
  re-measured against the released artifact.

### Verified

- Compiled and interpreted planes print byte-identical output for the six
  functions: `text`/`model`/`provider`/`tokens_in`/`tokens_out`, the model list,
  the verify report and the provider registry against a mock provider; and
  `Mesh.plan` (3 waves, sizes [2,1,1]) plus `Mesh.replay` of a journal written by
  a real `Mesh.run` (waves=2, ok=true, 2 checkpoints).
- Full library suite: 9,250 passed / 0 failed / 33 ignored.
- 119 test targets, 118 run in CI, 1 registered as debt (`compiler_bench`, which
  needs `--release` and a larger stack).

## [v1.5.0] — 2026-10-24 — the operator workflow, and native llm lowerings

### Added

- **Request-plan operator verbs.** `tallow run-plan` executes or preflights a
  `tallow.request_plan.v1` plan: `local` (default) evaluates policy and opens
  nothing, `live-preflight` runs every live gate and still opens nothing, `live`
  requires `--approve-live` plus a compliance gate report bound to the source
  manifest's sha256 and then performs one GET per request. Refusals are reported,
  never raised: stdout is a JSON run report with a stable `blocked_reason` code
  per request and the process exits 2. Gates, in order: shape validation, URL
  scheme, method, approval, compliance binding, header hygiene (a literal secret
  in a header is refused and the value is never echoed), output-dir isolation,
  source-manifest presence/sha, manifest allow/deny policy, browser fallback and
  artifact capture (declared but unwired is refused by name), and vault
  references (only `vault://local` resolves; the raw reference is never
  serialised, only its sha256).
- **Live artifacts.** A clean live run writes a redacted plan snapshot,
  `requests.jsonl`, `response_metadata.jsonl`, `source_index.csv`,
  `run_metrics.json`, `compliance_report.json`, per-request response files under
  `responses/`, and an `artifact_manifest.json` carrying size and sha256 for every
  file. Bodies — empty ones included — are stored as `<redacted:sha256:…>`.
- **`tallow validate-manifest`** — v2 shape checks (schema, unique v2-safe target
  ids, http(s) URLs, expressible methods, a complete compliance block), report to
  stdout and `--report-path` identically.
- **`tallow build-plan`** — manifest to plan, attaching the manifest's canonical
  path and sha256 so `run-plan` can prove the pair has not drifted.
- **`tallow package-report`** — recursive hash manifest of a run directory,
  excluding its own output by file identity rather than by string comparison.
- **`tallow fmt --check`** — verifies without rewriting, comparing against the
  formatted body because a generated file's `@generated_by` header is not
  reproduced by the formatter.
- **`tallow lint --profile scraper`** — `E-SCRAPER-IMPORT` and `E-SCRAPER-LEGAL`;
  an import alone is not HTTP work, so an import-only file passes.
- **Native lowerings for `llm.complete`, `llm.models`, `llm.verify` and
  `llm.providers`.** Compiled programs no longer fall back to the interpreter:
  the runtime builds the same `Completion`, `ModelInfo`, `VerifyReport` and
  `ProviderInfo` records the interpreter builds, and the compiled path reads them
  through the ordinary struct/array GEP path. Failure is loud — the redacted
  sentence and exit 1 — never a zero-filled struct.

### Fixed

- **Browser array calls returned `Ok(array)` interpreted and a bare array
  compiled**, so `page.query_selector_all(sel).len` was 1 natively and 0
  interpreted at a single result. The three calls now return the array on both
  planes, and field access on a `Result` refuses on both planes again
  (`http.get(url).status` must be bound first).
- **An `i32` concatenated into a string rendered `nil`** (`"code=" + o.exit_code`
  printed `code=nil` natively) — `coerce_to_string` had no i32 arm.
- **`test_speed_test_nonzero` raced on a fixed temp filename** across processes;
  the path is unique per call.
- **`fmt --check` exited 64 for unformatted source** — 64 is the usage code; it
  now exits 1.
- **The WordPress fixture probed readiness once**, so a cold CI runner failed
  before the container served; it now polls with a bounded timeout and prints the
  container's last log lines on failure.
- **The parity harness classified every non-zero interpreter exit as an error**,
  so the `*_refusal` fixtures could never pass; both planes are now required to
  refuse with the same sentence.

### Verified

- Full library suite: 9,250 passed / 0 failed / 33 ignored.
- 118 test targets, 117 run in CI, 1 registered as debt (`compiler_bench`, which
  needs `--release` and a larger stack; measured, not assumed).
- `llm` parity against a mock OpenAI-compatible provider: identical
  `text`/`model`/`provider`/`tokens_in`/`tokens_out`, model list, verify report
  and provider registry on both planes.
- Every CI job green on `71a8e8b`, including the new WordPress fixture job.

## [v1.4.0] — 2026-10-23 — model providers, without keys in the language

### Added

- **`llm` module** (`stdlib/llm.tl` + `src/stdlib/llm.rs`): `providers`, `models`,
  `complete`, `verify`. Twenty providers across five wire protocols — OpenAI chat
  completions (OpenAI, xAI, DeepSeek, Alibaba DashScope, Mistral, Moonshot, Z.ai,
  MiniMax, NVIDIA NIM, ByteDance Ark, Tencent Hunyuan, Baidu Qianfan, and any
  self-hosted OpenAI-compatible server), Anthropic messages, Google
  generateContent, Azure OpenAI, Cohere v2. Four providers are listed as
  `unavailable` with the reason and the route that does work (Meta has no
  inference API; Bedrock needs SigV4; watsonx needs IAM exchange; Xiaomi has no
  public API).
- **Model discovery.** `llm.models` calls the provider's own `/models` endpoint at
  call time and parses it per protocol, so a provider changing its line does not
  need a release.
- **Credential policy.** Config names `key_env` or `key_file`; an inline
  `key = "..."` is refused with a message naming the fix and never echoes the
  value; key files must be mode 0600; errors are redacted; no request is sent when
  the credential is missing.
- **CLI**: `tallow llm providers|models|verify|complete|init` (`init` writes the
  config at mode 600).
- **Documented egress rule**: model traffic does not use the Tor browsing plane —
  the credential in the header is an identity, so Tor buys no anonymity there and
  breaks providers that block exits. `llm` connects directly unless
  `TALLOW_LLM_PROXY` is set.

### Fixed

- **Interpreter: a lowercase module name shadowed a user variable.** With `llm`
  registered, `let llm = h.llm_calls` evaluated to `"__module_llm__"` instead of
  the field. Bound variables now take precedence over module sentinels; modules
  are a fallback, not a reserved word (spec §4.13).
- **Two advisories closed**: `ctutils` 0.4.2 → 0.4.5 (RUSTSEC-2026-0385) and
  `tokio` 1.53.1 → 1.54.1 (RUSTSEC-2026-0386), both published after v1.3.0.
  `cargo deny check advisories` reports advisories ok.

Counts: 86 → 87 modules; 1,126 → 1,130 function declarations.

Verified: `tests/llm_providers.rs` 7 passed against a local server enforcing each
protocol's authentication surface; full lib suite 9,212 passed / 0 failed / 33
ignored.

## [v1.3.0] — 2026-10-23 — the mesh crosses a socket

### Added

- `src/mesh/wire.rs` — 1 MiB length-prefixed frames, every frame Ed25519-signed
  over a fixed canonical string; replay refused by per-run nonce; oversized
  frames refused before allocation; `FrameReader` decodes only complete frames.
- `src/mesh/remote.rs` — `MeshServer` accepts joins against a node allowlist and
  refuses everyone else with a signed reason; `(task, epoch, deadline)` leases;
  reassignment on expiry at `epoch + 1`; per-class attempt caps that journal
  `TaskFailed`; stale-epoch results discarded.
- `tallow mesh worker --connect … --node … --key … --server-key … --run-id …`
  joins a coordinator and executes assignments.
- `simulated` flips **per node**, only after that node has joined and had one
  result committed.
- Control frames (`stop`, `inject`) over the wire accepted only from allowlisted
  operator keys.

### Fixed

- A task slower than its lease was reassigned forever; lease expiry is now
  bounded by the task class's attempt limit.
- Reassignment could return a task to the node that had just failed it;
  the expired holder is excluded when another peer exists.
- A reassigned `pure` task got a different seed, so a partitioned run committed a
  different checkpoint; pure seeds are now attempt-independent.
- A refused join looked like success; EOF before `welcome` is now an error and the
  server sends a signed refusal with the reason.
- `read_exact` under a read timeout could split a frame; decoding now buffers.

Not claimed: plaintext TCP, no NAT traversal, no TLS, no key rotation. The topology
plane (`src/stdlib/mesh.rs`) is still simulated; this release makes the execution
plane real.

Verified: `tests/mesh_remote.rs` 3 passed — two worker processes over TCP, one
frozen with SIGSTOP before the plan, six tasks, 300 ms leases: checkpoints equal a
local reference run, at least one reassignment, exactly one commit per task, and
thawing the frozen node adds none.

## [v1.2.2] — 2026-10-23 — the mesh gets a surface

### Added

- `Mesh.plan(tasks, seed)` and `Mesh.replay(journal_path)` published in
  `stdlib/mesh.tl`, answered by `src/stdlib/mesh_exec.rs`, with the four structs
  they return. Planning validates task classes, missing dependencies, duplicate
  ids and dependency cycles (the refusal names the path, e.g. `a -> b -> a`);
  replay recomputes every checkpoint and reports the first wave that disagrees.

### Fixed

- The `mesh` module was dispatched and routed but never registered in the
  interpreter's module tables, so `mesh.MeshNode.new(...)` died as "undefined
  variable: mesh". Both `mesh` and `Mesh` are registered now.

Counts: 85 → 86 modules; 1,124 → 1,126 functions.

`Mesh.run` is deliberately not declared: running a plan needs a worker pool
executing Tallow functions, and that executor does not exist.

Verified: `stdlib/mesh.tl` checks clean; the diamond plans to 3 waves `[1, 2, 1]`;
a cycle is refused with its path; an `io` task without an idempotency key is
refused — through the shipped binary (`tests/mesh_plan_tl.rs`, 3 passed).

## [v1.2.1] — 2026-10-23 — declared is what you get

### Added

- The six module-level browser helpers return the structs `stdlib/browser.tl`
  declares: `page_set_content` → `PageContentResult`, `page_throttle_cpu` →
  `CpuThrottle`, `page_emulate_media` → `MediaEmulation`, `page_wait_for_url` /
  `page_wait_for_function` → `WaitResult`, `page_add_script_tag` /
  `page_add_init_script` → `ScriptTag`, `page_add_style_tag` → `StyleTag`.
- Native lowering for those seven helpers on the current-page receiver, falling
  back to the interpreter by name when a match-arm binding's struct type cannot be
  inferred.
- Release bodies are generated from this file, and the build fails when a section
  lacks the required headings.

### Fixed

- Six helpers returned primitives where the declaration said struct:
  `page_throttle_cpu` echoed back its argument as a float, `page_wait_for_url`
  discarded the matched URL and elapsed time, and three others returned `Bool`,
  `String` or `Nil`. Declaration, interpreter and native arms now agree.
- The shared `WaitResult` builder produced 7 of the 9 declared fields since it was
  written; `status` and `event` now exist.
- A killed test run left an orphaned `chrome-headless` holding
  `/run/nixe-heavy-build.lock`, parking `cargo test` for 15 minutes. Killing the
  orphan let the build finish in 20 seconds.

Programs that printed the old primitive now print a struct, which is what the
declaration always said. Migration surface was measured before the change: five
of six helpers had zero call sites; the sixth had two, both tests from this work.

Verified: 6/6 browser tests, including one asserting all nine fields; full lib
suite 9,159 passed / 0 failed / 33 ignored.

## [v1.2.0] — 2026-10-23 — the surface stops lying

The counts were right and parts of the surface behind them were not. This release
makes the published surface executable and the manifest valid Tallow.

### Added
- **41 browser declarations now execute.** `page_extract_all_text/attrs`,
  `page_capture_dom_snapshot`, `page_structured_data`, `page_text_redacted`,
  `page_block_non_essential`, `page_wait_for_stable`, `page_detect_pagination`,
  `page_handle_cookie_consent`, ten delegations (`set_content`, `content`,
  `add_init_script`, `add_script_tag`, `add_style_tag`, `wait_for_function`,
  `wait_for_url`, `wait_for_timeout`, `throttle_cpu`, `emulate_media`), three
  event waiters, eight callback registrations, the WordPress/Wordfence set, and
  `browser_context_create`. A current-page registry in the interpreter is what
  lets a module-level helper reach a live tab.
- **Agent handles answer `status()`, `is_done()` and `cancel()`**, with
  cooperative cancellation at function-call boundaries and `spawn_await`
  reporting cancellation instead of `Ok(nil)`.
- **Grammar**: record types `{a: T}` / `{T, U}`, `fn()` without a return,
  contextual keywords in name positions, generic type aliases, and type-scoped
  function names `fn Type.member(...)`.
- WordPress fixture (`scripts/wordpress_fixture.sh`) and live-page tests that
  skip when Chrome is absent.

### Fixed
- `page.goto` reported success while the tab sat on Chromium's error page; it
  now returns a navigation failure.
- A `Page` outliving its `Browser` handle left a reaped browser and a hanging
  `Runtime.evaluate`; the interpreter retains the browser for the program's life.
- `Page.evaluate` returned every result as a string, double-quoting JS strings.
- `json.get` ignored its default argument, breaking `map.get(k, 0)`.
- `tallow check`: 85 of 85 stdlib modules now pass (was 20). 355 declarations
  moved to the spec's `native fn` form, 100 array types corrected to `[]T`, and
  the checker learned `Float`/`Int`/`Bool`/`str`.
- Native lowering for `math.asin/acos/atan/atan2/cbrt` and the integer helpers
  `abs_i/min_i/max_i/clamp_i`.
- The published function count is **1,124**; the six-function difference from
  1,118 is `timeseries.tl`'s `method … on TimeSeries` declarations, which no
  counter ever read.



## [v1.1.5] — 2026-10-22 — `String.parse()` compiles

One gap, and it was the kind that only shows up when you re-measure your own
claims instead of re-reading them.

`String.parse()` had no codegen lowering. The interpreter ran it, the native
backend refused the build by name, and `--require-native` therefore rejected
every program that converted a string to a number — including
`examples/error_handling.tl`. The README said "10 programs identical on both
planes"; the honest count was nine, and that is what it said for one release.

Now lowered: `tallow_str_parse_i64` (`src/runtime/string_ffi.rs`) parses with
the interpreter's own `str::parse::<i64>`, so the accepted spelling is identical
(optional sign, ASCII digits, no whitespace, no separators, no radix prefix).
Unparseable text exits 1 with the interpreter's exact sentence,
`runtime error: cannot parse '<s>' as number`. Float text is **refused by name**
— ``native plane cannot carry it through this integer ABI; use `.to_float()` ``
— rather than truncated, because a truncation would be the silent divergence
this codebase exists to avoid; the interpreter returns `Float` there and the two
planes deliberately differ, visibly.

Verified: `examples/error_handling.tl` now runs identically on both planes
(stdout byte-identical, both rc 0), `cargo test --lib string_ffi` 3 passed,
`tests/interp_codegen_parity.rs::string_parse_*` 2 passed.

## [v1.1.4] — 2026-10-21 — green on three platforms, and no advisory left open

Seven of the ten red CI jobs were arguing about code, not about policy. This
change settles the four that were genuinely broken in the dependency tree: two
platform builds, a test that could not pass on a host without softhsm, six
regression targets nothing ran, and thirteen RustSec advisories.

### Security
- **`libcrux-aesgcm` 0.0.8 → RustCrypto `aes-gcm` 0.10 (item 6.4 reversed).**
  libcrux 0.0.8 carries RUSTSEC-2026-0209 (no AAD length limit) and
  RUSTSEC-2026-0211 (non-constant-time tag comparison); 0.0.8 is the newest
  published release and the upstream fixes are unmerged. Wire format is
  byte-identical — `tests/aes_gcm_differential.rs` proves it against eight
  ciphertexts generated from the 1.1.x libcrux backend, NIST CAVS vectors, and a
  tamper case. Measured cost on aarch64: 128.3 MB/s vs 984.6 MB/s with `+aes`
  (7.7×) — recorded in `docs/CRYPTO-FASTPATH-AUDIT.md`.
- `rustls` 0.23.45 → 0.23.46, `rustls-webpki` 0.103.15 → 0.103.16,
  `webpki-roots` 1.0.6 → 1.0.10, `webpki-root-certs` 1.0.9 → 1.0.10.
- `zip` 2.4.2 → 9.0.0 (RUSTSEC-2026-0367/-0368/-0369). The upgrade also closed a
  zip-slip: `src/browser/trace.rs` extracted entries with `zip.join(entry.name())`
  and now uses `enclosed_name()`, which refuses absolute and `..` paths.
- `cargo audit`: 13 advisories → 0. `deny.toml` gains `bzip2-1.0.6` (zip 9's
  pure-Rust bzip2 decoder) and `Apache-2.0 WITH LLVM-exception` (the cranelift
  family, reached only with the optional JIT feature), and records the
  `mach`/RUSTSEC-2020-0168 acceptance that `region` forces on macOS. Verified
  the way CI runs it — `cargo deny --all-features check` — which is what caught
  both of those; the earlier plain `cargo deny check` never saw the optional
  dependency set.

### Fixed
- **The workspace did not build on macOS or Windows.** `landlock` (Linux LSM) was
  declared unconditionally in the root and `tallow-daemon`; `landlock-0.4.7`
  calls `libc::prctl`, absent off-Linux, so both crates failed at compile. Moved
  under `[target.'cfg(target_os = "linux")'.dependencies]`.
- **`crypto::test_hsm_list_slots` failed on every host without softhsm.** It
  unwrapped `Hsm.list_slots()`, which correctly returns "no PKCS#11 provider
  module found". Now skips on that environmental error and still fails on any
  other.
- **Six regression targets ran in no pipeline**: `exit_in_conditional`,
  `fs_read_file_native`, `native_fn_decl`, `optional_implicit_wrap`,
  `optional_match_unwrap`, `script_mode`. Added to the contract job;
  `check_test_coverage.py` now reports `103 targets: 66 in CI, 37 excluded with a
  reason, 0 unaccounted`.
- **Clippy job could not start**: the workflow installed clippy for `stable`
  while `rust-toolchain.toml` pins 1.98.1. Job now pins the same toolchain.

### Changed
- `scripts/sbom.snapshot.json`, `scripts/crypto-inventory.json` and
  `crates/CANONICAL-SYNC.sha256` regenerated (204 pinned files) — all three drift
  gates pass.
- `docs/PGO.md`, `scripts/pgo_ab.sh`, `benchmarks/cliff-probe` re-measured against
  `aes-gcm`; the old 111/973 MB/s figures described a backend that no longer ships.

### Fixed (cross-platform)
- **The crate did not compile for Windows.** Fifteen `std::os::unix` /
  `libc` uses sat outside any `cfg` gate. Each now has a real branch or an honest
  refusal, not a stub that pretends to work:
  - `sluice.rs` receipt-log lock: `libc::flock` → `File::try_lock`/`unlock`
    (flock on Unix, `LockFileEx` on Windows), same semantics, no `unsafe`.
  - `cli/secrets_cmd.rs` masked prompt: hand-rolled `termios` →
    `console::Term::read_secure_line` (already in the dependency graph); the
    0600 write is `cfg(unix)`-gated with a note that Windows inherits the
    directory ACL.
  - `stdlib/secrets.rs` store write: same 0600 gate.
  - `sandbox_runtime`: Unix implementation behind `cfg(unix)`; the non-Unix
    module exposes the same five entry points and returns `Err`, because a
    `run_sandboxed` that returned `Ok` would claim a confinement that is not
    there.
  - `browser/juggler.rs`: the `pre_exec` + fd 3/4 pipe launch is `cfg(unix)`;
    on Windows `launch` refuses and names the Chromium/CDP backend.
- **The crate did not compile for macOS.** `RlimitResource` was keyed on
  `not(target_env = "musl")`, so it selected glibc's `__rlimit_resource_t` on
  Apple targets too; now keyed on `target_env = "gnu"`. `sandbox_pass`'s seccomp
  call was a `cfg!()` runtime test around a `#[cfg(target_os = "linux")]`
  function — a `cfg!()` never removes the call site; it is now a real `cfg` split,
  and the syscall-table test is Linux-gated.

### Fixed (platform test parity — the rest of the red)

The first pass above made the crate *compile* off Linux. These are the failures
that were left once it ran there.

- **Accepted sockets inherited the listener's non-blocking mode.** A listener is
  set non-blocking so its accept loop can poll; on Windows and macOS the socket
  returned by `accept()` inherits that state (on Linux it does not). The first
  read returned `WouldBlock`, each server treated it as a closed client and
  dropped the connection unread, and the peer reported `EINVAL` (macOS) or
  `WSAECONNABORTED`/10053 (Windows). Three sites:
  - the two hand-rolled mock servers in `browser::crawl_pipeline` (7 Windows and
    2 macOS test failures) — `set_nonblocking(false)` on the accepted socket;
  - **`browser::observability::serve_metrics` — shipping code.** On macOS a
    Prometheus scrape of the metrics port got a zero-byte response. Same fix,
    with the reason at the call site.
- **`sluice`'s receipt log locked the data file, which Windows refuses to share.**
  `LockFileEx` is a mandatory lock, so every reader of the KT log got
  `os error 33` (11 Windows failures). The lock moved to a `<log>.lock` sidecar;
  the log itself is never held while being read.
- **Four macOS tests asserted platform assumptions, not product behaviour**:
  a 50 ms heartbeat interval that overshot to 157 ms on a loaded runner (now
  2 s), a hard-coded `linux-arm64` install directory (`BrowserPlatform::detect()`),
  Landlock paths compared uncanonicalised (`/var` vs `/private/var`), and JA4T
  expected to be `derived` on a platform where it is correctly `unavailable`.
- **Windows fixture failures**: `File::open()` then `set_modified` (Access
  denied), `PATH` joined with `:` instead of `;`, a TOML fixture carrying a
  backslash path, and provenance paths normalised with `\` instead of `/`.
- **`browser_install_dir` ignored `TALLOW_DATA_HOME`**, which is the only
  writable location macOS and Windows give an installed tool.

### Fixed (production gates)

- **`Tallow Production CI Gates` could never pass.** Its gate list invoked
  `scripts/phase1_smoke_ladder.py`, which existed only in the older Nixe
  workspace and was never carried into this repository, so `p2-006-phase1-smoke`
  exited 2 on every commit. The ladder is now part of the tree and passes
  (17 rungs, `pass=17 warn=0 fail=0`); its generated receipt is gitignored.

### Verified

- CI run `39655436215` on `1836329f`: **17 of 17 jobs green**.
- `Tallow Production CI Gates` run `39655436090` on the same tree: success.
- Tests: Linux 9,145 / macOS 9,140 / Windows 9,108 — zero failures on each.
  The 33 ignored tests are the same set everywhere (mesh-only and
  privileged-environment cases).
- `docs/operations/PLATFORM-PARITY.md` states, per platform, what builds, what
  runs, and what refuses on purpose.


## [v1.1.3] — 2026-10-21 — three defects a five-line script found

Two example scripts for the language repository turned over three codegen and
packaging defects in an hour. None was visible to the suite: no test in it read a
file, exited from a conditional, or passed an argument to a program.

### Added
- **A `.tl` file is a program.** `tallow app.tl` runs it; a `#!/usr/bin/env tallow`
  shebang is accepted (the line is blanked, not stripped, so spans still index the
  original source); arguments after the path belong to the program
  (`./wc.tl notes.txt` becomes `tallow run wc.tl -- notes.txt`).

### Fixed
- **`fs.read_file` had no native plane (#138).** The "could not open" report was
  emitted from the ok block using a buffer defined in the fail block — invalid IR,
  so clang 18 died in the register coalescer and every file-reading program fell
  back to the interpreter. The report now lives on the fail path; the ok path
  compares `fread()` against `st_size` and fails loudly on a short read.
- **`exit()` inside a conditional produced invalid IR (#139).** `process.exit(n)`
  emits `unreachable`, after which the enclosing `if` appended a dead `br`.
  `emit_line` now drops a branch when the current block already ends in a
  terminator.
- **`install.sh` advertised "latest" and installed 1.1.1 (#140).** `VERSION` was a
  literal, so it requested an asset that never existed. It now resolves
  `/releases/latest` after argument parsing and exits 2 with a usable message when
  it cannot.

## [v1.1.2] — 2026-10-21 — a Result cannot be dropped

### Fixed
- **A discarded `Result` was silent success (#133).** Both planes now run the same
  rule: a `Result`-valued call whose value nobody reads, in a non-final statement
  of a block, is checked — `Err` writes to stderr and exits 1.
- **`match` on a `T?` now compiles (#134).** The payload type comes from the
  callee's signature instead of being refused.
- **Returning a computed value from a `-> T?` function was refused on the native
  plane (#135).** `coerce` now boxes any non-optional value whose slot is optional;
  unwrapping (`T?` → `T`) is still refused, because it needs a check the compiler
  cannot invent.

### Changed
- Register rows #129, #130 and #132 were re-measured rather than restated; see
  `docs/operations/stub-register.md` for the corrected premises.

## [v1.1.1] — 2026-10-10 — the deployment's fix, landed (prepared on `v1`, local-only)

v1.1 released a gate whose deployment ran a fix the release did not contain. The installed binary had been
built from the live tree plus a patch binding a **read-only open** into `sluice verify`, and that patch — the
one that makes the anchor control deployable at all — existed in no commit. The release therefore could not
reproduce the binary its own deployment depended on.

### Fixed
- **`KtLog::open_read_only` is in the tree.** `verify` and `verify_segment_close` take a read handle on the
  receipt log instead of a write handle, so the account that checks the log is no longer an account that can
  rewrite it.

### Known gap, recorded rather than hidden
- The running deployment still describes its binary as built from a live patched tree, so it is not yet
  reproducible from a revision. Re-deploying from this tag closes that, and the deployment-provenance gate
  is the mechanism that will say so.

## [v1.1] — 2026-10-10 — the cross-domain release gate (prepared on `v1`, local-only)

Adds **Sluice**, a cross-domain release gate: one decision over whether material may cross a domain
boundary, with failures attributed to the BOUNDARY MODEL rather than to the material. Cross-domain transfer
failures are failures of the boundary, not of what is being transferred.

### The gate
- **Stage order is frozen**: plan+lineage → channel admit → channel obligations → class gate → caveat gate
  → release+receipt. `exit 0` = ALLOW, `exit 1` = DENY.
- **14 emittable deny codes**, each with a stable machine-readable form so a caller can tell a boundary
  refusal from an infrastructure failure.
- **Receipts are digest-only** and hash-chained into the existing KT log — no sidecar, no plaintext.
- **CLI**: `check` / `channels` / `explain` / `release` / `verify` / `rotate`.

### Verification
- A **30-gate regression battery** (`tools/regression_gates.sh`) runs over both the deliverable and the
  product: a clean-checkout build gate, a deployment-drift gate, and auditors that re-derive every count,
  citation and path the documents state rather than trusting them.
- **124 defects** found and recorded across 45 waves, each with its reproduction and severity.

### Deployment
- Installed and running on the reference host: daily rotation, hourly divergence monitoring, hourly anchor
  recording. Each is proven by a real run, not by its unit being enabled.

### Release identity
- Tag `v1.1` pairs with Cargo version `1.1.0`. Release identity remains **local-only (R0)** per R-03.
- This entry covers the gate and its verification. Other work on the `v1` line between the freeze and this
  tag is recorded in the commit history rather than summarised here.

## [v1.0] — 2026-09-14 — V1 freeze (prepared on `v1`, local-only)

The first V1 freeze candidate, assembled through the R-08 execution program
(batches 1–4) on branch `v1` (17 checkpoint commits B0–B16, tip `fea1029`),
verified by batteries 2–9. Not a public release; tag + archive mechanics per
`docs/release/` and decision R-03/D6.

### Identity fabric (W3)
- **SVID workload identity** — certs, issuer, relay mutual-auth, zero-trust policy
  pack (`W7201–W7203`), short-lived scope-bound workload tokens, sector pseudonyms.
- **Enrollment ceremony** — two-sided SAS-based enrollment with single-use
  SPKI-bound tokens and honest attestation (`src/enrollment.rs`, `pake/sas.rs`).
- **Revocation** — signed revocation lists with TTL-bounded staleness, checked at
  the daemon handshake seam (refuse new sessions; established sessions
  untouched per D-4); KT-logged.
- **Recovery** — offline custody shares (Shamir, k≥2 distinct custodians),
  dual-control recovery with root-commitment verification, root-rotation
  ceremony (Ed25519 approvals, no self-approval, re-verify-at-execute,
  retired roots never re-anchored); honest-unrecoverable doctrine; KT-logged.
- **Persona firewall** — enforcement layer with typed findings/refusals.

### Key transparency
- Append-only BLAKE3 KT log with signed tree heads, inclusion and consistency
  proofs; event payloads committed by hash (caller-held evidence). Wired into
  enrollment, recovery and revocation flows.

### Config kernel
- Layered scopes (KB-2), versioning/migrations (KB-3), signed config bundles
  (Ed25519; verify-before-load), secure-by-default lint pack.

### Crypto & supply chain
- AEAD upgrades (agent channel v2; CredentialVault), Argon2id single-source
  parameters, AEGIS gating, constant-time test harness + procurement rule,
  cargo-vet trust foundation, SBOM/CBOM drift gates.

### Transport, egress, measurement
- TallowTransfer relay end-to-end + delta-sync resume; transport fallback and
  bandwidth limits; fail-closed Tor egress (direct is an explicit opt-in);
  browser/measurement readiness for the D4 calibration run.

### Compliance
- Compliance report generator with CRA 24h / CERT-In 6h early-warning clocks
  and ZNISM self-assessment output.

### Gates & process
- `release_gate.sh` acceptance battery (`--twice`, `--quick`, evidence archive),
  `never_check.sh` (static + cargo + optional live egress), `kev_gate.sh`,
  claims-ledger gate; freeze chain F-01…F-08 defined.

### Known limitations (honest, per freeze review)
- Live calibration run **R-01** pending (windows A/B); cost/perf multipliers stay
  `[target-only]` until then.
- SLIP-39 mnemonic leg blocked (no offline crate/wordlist) — recorded, not built;
  FROST k-of-n authorizer dep-gated; mesh/swarm legs are W5 by design.
- Release identity is local-only (no remote, no CI execution); non-Linux targets
  not exercised on this host.
