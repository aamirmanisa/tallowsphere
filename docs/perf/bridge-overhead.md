# The generic stdlib bridge — pure marshalling overhead

The bridge spike answered "is the bridge usable?" with a comparison that
included the module's own work: 89.4 µs/call bridged against 105.2 µs/call
interpreted for `api.endpoints_json`, with the report stating plainly that
serializing two endpoints dominated both numbers. It also stated that a
pure-overhead number was still unmeasured.

This document is that number, measured on this box, with its conditions.

Reproduce it with:

```
cargo test --test bridge_overhead -- --nocapture
```

The test is the artifact; this document is the reading of what it printed.

---

## 1. The probe function

### 1.1 There is no identity/echo helper in the stdlib

The brief asked for a function that does almost nothing but marshal — a string
identity helper. **There is none.** All 92 `stdlib/*.tl` modules were searched
for a one-`String`-argument, one-`String`-result `native fn`. The candidates
either transform their input or are not reachable as native calls at all:

| candidate | why it is not the probe |
|---|---|
| `url.encode(s)` | Not reachable from the bridge at all — see §1.3. |
| `recordlink.normalize_name(s)`, `entity.name_key(s)`, `recordlink.name_key(s)` | Lowercase + split on non-alphanumerics into a `Vec<String>`, then join (and `name_key` sorts and dedups). Several allocations of *variable* count: the per-call cost would depend on the input text. |
| `geocode.zip5(s)` | Collects the whole input into `Vec<char>` before scanning it. Allocation proportional to input length. |
| `geocode.normalize_address`, `geocode.parse_address`, `geocode.address_key` | Word-level parsing of an address; tens of allocations. |
| `Manifest.to_url`, `QrCode.generate`, `hash_body` | Base64 / QR encoding / hashing — real work, and proportional to input. |

`url.encode` deserves its own note because it looks like the obvious choice:

```
$ TALLOW_ALLOW_DIRECT=1 tallow build p_url.tl          # prints url.encode("a b")
build failed: native backend has no lowering for method 'encode' at byte offset 41
  on this receiver (unknown method for any statically-known kind); failing loudly
  so the interpreter runs it
$ tallow run --interpret p_url.tl
a%20b
```

Two independent reasons it cannot be the probe: `url` is in the hand-written
module list in `emit_stdlib_module_call`'s caller (`src/codegen.rs`, the
`"url"` arm), so the generic-bridge arm is never reached for it; and even if it
were, `src/stdlib/url.rs` returns `None` from `dispatch` for `encode` ("already
implemented inline in interp.rs"), so `tallow_stdlib_call` would abort with *the
interpreter's router has no dispatch for url.encode*. **A function implemented
inline in `interp.rs` cannot be bridged** — the bridge reaches
`stdlib::dispatch` only. This is worth knowing before anyone assumes the bridge
covers "every module the interpreter knows": it covers every module the
*router* knows.

### 1.2 The probe: `geocode.state_from_name`

```
native fn state_from_name(name: String) -> String      # "Texas" -> "TX", "" if unknown
```

One `String` in, one `String` out, four bytes of output, no clock, no I/O, no
allocation proportional to the input.

**The work it also does** (this is the part the number must be corrected for,
and §4 corrects it): `trim()` then `to_lowercase()` (one allocation), a linear
scan of the 56-entry `STATE_NAMES` table comparing owned `String`s, and one more
allocation for the two-byte abbreviation. Constant per call, independent of the
argument text, so it is a stable floor under every measurement below.

`geocode` has no hand-written native emitter, so the compiled plane reaches it
through `tallow_stdlib_call`. That is asserted, not assumed: the test rebuilds
the same source with `TALLOW_GENERIC_STDLIB_BRIDGE=0` and requires the old
refusal —

```
build failed: native backend has no lowering for method 'state_from_name' at
  byte offset 101 on this receiver
```

— so if a hand-written emitter for `geocode` ever appears, the test fails
instead of quietly reporting emitter timings as bridge timings.

### 1.3 A premise in the brief that turned out to be wrong

The brief's method — "measure N calls in the compiled plane, differencing N and
N+2000 so process startup and JIT/loading cancels" — **does not work for the
compiled plane on this binary**, and not marginally.

`tallow run --require-native` codegens, links against a 1.1 GB static archive
and *then* executes, every invocation. Measured on the binary below, 5 runs
each, min of each side (the same two programs the test uses):

| harness | 200 calls | 2200 calls | per call |
|---|---|---|---|
| `tallow run --require-native` | 19767 ms | 19677 ms | **−45.0 µs** |
| the same programs, built once and executed | 9.2 ms | 18.85 ms | **+4.83 µs** |

The `tallow run` figure is *negative*: the 2000 extra calls measured as faster
than the 2000 fewer, because the signal is ~9 ms and the run-to-run spread of a
21 s build is ~1.9 s. Compiling dominates by three orders of magnitude and its
variance by two.

So the test builds each program once with `tallow build` (19.1 s and 19.4 s for
the two programs here) and times the **artifact**, 5 runs, minimum. Nothing
about the bridge changed; the compiler was simply removed from a measurement
about the bridge. The interpreter leg needs no such hoist — `tallow run
--interpret` parses and typechecks (~constant, cancels) but never compiles.

---

## 2. Conditions

| | |
|---|---|
| revision | `345f205` (`run/2.0-20261028-ember` worktree) + this test |
| binary | `/workspace/shared-target/debug/tallow` |
| sha256 | `7d21043b228cef163bc1c7048d736f86d906cf51efa2c46b3a306e1f01182bb7` |
| profile | **debug** (`dev`, unoptimized) for the compiler, the runtime archive and the test |
| counts | 200 vs 2200 calls, difference ÷ 2000 |
| runs | 5 per configuration, minimum reported |
| box | Hetzner ARM (aarch64), 15 GiB, shared with 8+ concurrent agent lanes; `/run/nixe-heavy-build.lock` queues `cargo` invocations |
| corpus | `geocode.state_from_name("Texas") -> "TX"`, 1 `String` arg, 1 `String` result |

### 2.1 Repeatability

The measurement was taken twice, on two builds of the same worktree. The second
binary has a different sha256 because the shared target dir had been relinked by
the lanes in between — which is exactly why the sha, not the revision, is the
identity of a measurement here.

| | run 1 (`7d21043b…82bb7`) | run 2 (`e5f1f7ca…2b777`) |
|---|---|---|
| bridged | 4.566 µs/call | 4.944 µs/call |
| interpreted | 38.498 µs/call | 36.212 µs/call |
| delta | −33.931 µs/call (0.12x) | −31.269 µs/call (0.14x) |
| work floor | 2.085 µs/call | 2.221 µs/call |

Same shape, ±8 % on the bridged figure and ±6 % on the interpreted one. That
spread — not the last digit of any single number — is the precision this box
supports while other lanes are building. §3 quotes run 1; §6's conclusions are
the ones both runs agree on.

Everything is debug-profile. That inflates the *interpreter* far more than a C
call boundary, whose own cost is a handful of instructions — read the numbers
below as debug numbers, not as what a release build would spend. Nothing here
was measured in release, and no release figure is claimed.

---

## 3. The three numbers

```
binary      /workspace/shared-target/debug/tallow sha256:7d21043b…82bb7
corpus      geocode.state_from_name("Texas") -> "TX"
counts      200 vs 2200 calls, min of 5 runs each, difference / 2000
bridged     4.566 µs/call   (10.151953 ms -> 19.284326 ms)
interpreted 38.498 µs/call   (31.370915 ms -> 108.365975 ms)
delta       -33.931 µs/call  (0.12x)
```

* **bridged** — 4.566 µs/call. `tallow_stdlib_call` decodes the argument into a
  `Value`, calls `stdlib::dispatch`, re-encodes the result as a C string and
  hands the pointer back to codegen.
* **interpreted** — 38.498 µs/call. The tree-walker reaches the *same*
  `stdlib::dispatch`; the difference is entirely in how it gets there.
* **delta** — −33.931 µs/call. The bridge is **8.4× cheaper** than the
  interpreter for this call.

The spike's 89.4 µs (bridged) was 20× this figure because `endpoints_json`
serializes a document. Here the module does ~2 µs of work, so what is left is
the call mechanism itself — which is the point of the exercise.

---

## 4. Overhead or work? The delta is neither, on its own

The honest decomposition needs the third measurement: `stdlib::dispatch` called
directly, in-process, no bridge and no interpreter.

```
── module work floor (20000 in-process dispatch calls) ──
dispatch    2.085 µs/call  (geocode.state_from_name)
```

That floor includes the argument `String` allocation (which the bridge also
makes), the module and function dispatch, the `trim().to_lowercase()`, the table
scan and the two-byte result. It excludes the bridge's result re-encode
(`Vec` + `CString`), the `extern "C"` boundary, and the ownership handoff.

So, per call:

| | total | module work (floor) | mechanism |
|---|---|---|---|
| bridged | 4.57 µs | 2.09 µs | **~2.5 µs** marshalling + boundary |
| interpreted | 38.50 µs | 2.09 µs | **~36.4 µs** interpreter call machinery |

Reading that:

1. **~46 % of the bridged per-call cost is the module's own work, not the
   bridge.** The correct statement of the bridge's overhead here is ~2.5 µs
   (debug), not 4.57 µs. Anyone quoting the raw bridged number as "bridge
   overhead" is overstating it roughly two-fold.
2. **The delta between the planes is not overhead at all.** Both planes pay the
   same 2.09 µs of module work, so the −33.9 µs difference is a comparison
   between two *call mechanisms*: the bridge's ~2.5 µs against the
   interpreter's ~36.4 µs. The delta is the interpreter's machinery, seen from
   the other side of a subtraction. It says nothing about marshalling being
   expensive — it says the tree-walker costs more than a C call.
3. The marshalling cost is dominated by what the ABI forces, not by JSON:
   `state_from_name` returns a `String`, and a `String` result is
   `text.as_bytes().to_vec()` plus a `CString::new` — two allocations and two
   copies of a result the runtime already owned. Non-`String` results pay a
   `serde_json` round trip on top; that is what the spike's 89.4 µs measured,
   and it is the class to optimise if the bridge ever becomes hot.

The comparison in row 2 is also why the closed loop back to §1.2 matters: the
floor is the *same* function in the *same* debug profile, so "2.09 µs of work in
both" is an estimate with a stated basis, not an assumption.

---

## 5. The bound the test asserts

```
bridged_per_call < 5 × interpreted_per_call      # measured ratio 0.12 → 50× headroom
bridged_per_call < 20 µs                          # measured 4.57 µs  → 4.4× headroom
```

Both are loose on purpose. A ~50× regression in the bridge, or a ~4× absolute
regression, still passes; anything an order of magnitude worse fails. The
ratio bound alone would not catch a regression that inflated *both* planes, and
the absolute bound alone would not catch a change in the relationship between
them — which is why both exist. Neither is tight enough to fire on a shared box
where another lane is linking, which is the box these were measured on.

Guards inside the same test, so it cannot pass while measuring something else:

* the compiled fixtures are built with `tallow build`, which has no interpreter
  fallback — a call the bridge does not lower fails the test at the build step;
* the same source is rebuilt with `TALLOW_GENERIC_STDLIB_BRIDGE=0` and must be
  refused by name, proving the timed program is bridged and not emitted;
* every timed run's stdout must equal the expected call count, so a fast run
  that did fewer calls fails instead of reporting a small delta;
* a non-positive delta fails the test rather than passing as "fast".

---

## 6. Findings, including the ones this brief did not ask for

1. **The `tallow run` harness cannot measure call overhead.** ~21 s of
   compile+link per invocation, with ~2 s of variance, against a signal of
   ~10 ms. Any "µs/call" figure produced by differencing `tallow run`
   invocations is measuring the compiler. The spike's numbers may not be
   affected (its method is not recorded in enough detail to tell), but this is
   the harness trap in this tree, and it cost a negative measurement to find.
   The new test therefore times built artifacts.
2. **`url.encode`/`url.parse`/`url.decode` are unreachable from native code** —
   declared `native fn` in `stdlib/url.tl`, implemented inline in `interp.rs`,
   and `stdlib::dispatch` returns `None` for them. `url` is also in the
   hand-written module list, so the bridge never gets the call. A program using
   them compiles natively today only because the refusal falls back to the
   interpreter under `tallow run`; under `--require-native` it refuses.
3. **No stdlib module offers a pure identity/echo function.** Anyone measuring
   "the cost of a call with no work" in this tree must pick a function with
   constant-but-nonzero work and subtract a measured floor, as done here. This
   is a gap worth closing with a deliberately trivial `probe.echo(s: String) ->
   String` if bridge overhead is to be tracked over time.
4. **A `String` result costs two allocations at the boundary** (`to_vec` +
   `CString::new`) and is never freed by the emitted code — 2000 calls leak
   2000 small allocations in the measured program. Irrelevant at 4.5 µs/call,
   relevant if a loop ever calls a bridged function a million times.
5. **The shared `CARGO_TARGET_DIR` makes the runtime archive a cross-lane
   artifact.** `find_runtime_lib_for_target` picks the newest
   `deps/libtallow-*.a` by mtime; with all lanes writing to
   `/workspace/shared-target`, the archive linked into a measured program may
   have been produced by another lane's tree. The numbers above were taken with
   the archive in place at the time and the binary's sha256 recorded; treat the
   sha as the identity of the measurement, not the git revision alone.
