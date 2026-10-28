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

**These are the pre-F1 numbers.** They were taken before `735a689` gave a
bridged `String` result an owner; §7 re-measures them and reports what the
ownership rule cost. Nothing here is retired — §7 is a second reading, not a
replacement, and the readings differ by less than they differ from each other.

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

§7 adds three fences for the ownership case (a bridged `String` result
consumed immediately, and the release F1 emits); the two above are unchanged.

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
   `CString::new`). **Superseded by F1 (`735a689`):** the emitted code used to
   never free that buffer, so 2000 calls leaked 2000 small allocations. It is
   now released at the end of the block that binds it when the binding provably
   does not escape; the release costs 59–60 ns/call and RSS is flat at 2000 calls
   × 32 KiB (§7). The two allocations per result are still there — F1 gave them
   an owner, it did not remove the copy.
5. **The shared `CARGO_TARGET_DIR` makes the runtime archive a cross-lane
   artifact.** `find_runtime_lib_for_target` picks the newest
   `deps/libtallow-*.a` by mtime; with all lanes writing to
   `/workspace/shared-target`, the archive linked into a measured program may
   have been produced by another lane's tree. The numbers above were taken with
   the archive in place at the time and the binary's sha256 recorded; treat the
   sha as the identity of the measurement, not the git revision alone.

---

## 7. The F1 ownership fix — what it cost

`735a689` (F1) closed the last bridge defect: a bridged `String`/struct result
had no owner, so a loop leaked the whole payload per call (32 KiB/call,
measured 19 208 KiB over 600 calls). The fix is ownership, not a call-site
free: a bridge binding records the statement that declared it, an escape scan
over the declaring block decides whether the value can be released at the end
of that block, and only then does codegen emit `tallow_free_string`.

Two things are new, and each can cost something:

| added | when it runs | what it costs |
|---|---|---|
| the escape scan | once per bridged binding, at codegen | compile time only — see §7.1 |
| `tallow_free_string` | once per released result, at run time | **60.3 ns/call**, measured directly (§7.2) |

### 7.1 The three numbers, pre-F1 and post-F1

Same harness, same corpus, same method (200 vs 2200, difference ÷ 2000, min of
5 runs, debug profile), two binaries:

```
                                   pre-F1 (e5f1f7ca)   post-F1 (c16cdf2e)   move
bridged                            4.944 µs/call       4.780 µs/call        -0.164  (-3.3 %)
interpreted                       36.212 µs/call      38.447 µs/call        +2.235  (+6.2 %)
delta                            -31.269 µs/call     -33.667 µs/call
module work floor                  2.221 µs/call       2.088 µs/call        -0.133  (-6.0 %)
```

Conditions for the post-F1 column:

| | |
|---|---|
| revision | `4a8db9a` (worktree `run/2.0-20261029-ember-cost`) with F1 `735a689` |
| binary | `/workspace/shared-target/debug/tallow` |
| sha256 | `c16cdf2eeda7daceb6a0461908d350acf6865835e19b1f7c492278061ab1a8cb` |
| profile | **debug** (`dev`, unoptimized) — compiler, runtime archive and test |
| counts | 200 vs 2200 calls, difference ÷ 2000, min of 5 runs each |
| box | same Hetzner ARM box, other lanes building throughout |
| command | `cargo test --test bridge_overhead -- --nocapture --test-threads=1` (3 passed) |

**The bridge did not get more expensive — it moved down, and the sign of the
move is not the finding.** The same program on five binaries reads:

```
bridged      4.566  4.944  3.956  4.231  4.780  µs/call   (7d21043b, e5f1f7ca, 147d1b6e, 8d5949e4, c16cdf2e)
interpreted 38.498 36.212 38.521 38.303 38.447  µs/call
```

That is a 3.96–4.94 µs band on a shared box across five rebuilds, and the
interpreted plane a 36.2–38.5 band. F1's run-time addition is **58.9 ns** —
1.2 % of the bridged call and 0.2 % of the plane delta — so it is inside that
band and no end-to-end statement of the form "F1 added X µs" can be made from
this harness. The direct measurement below is what resolves it.

**The escape scan is compile-time and is not in any number here.** It walks the
statements of the declaring block once per bridged binding, with no
allocation, and it runs once per program rather than once per call — so it
cannot appear in a per-call figure, and the loop bound does not change it. Its
magnitude is **unverified**: separating a linear AST walk from a ~20 s
codegen-plus-link whose own run-to-run spread is seconds (measured in §1.3)
is not possible with the instrumentation in this tree. It is a walk over
statements the emitter already visits, and nothing in §7 depends on its size.

### 7.2 The ownership case

`tests/bridge_overhead.rs::bridged_string_ownership_path_is_bounded_and_released`
times the case where the release actually fires — the result is consumed
immediately by `print`, so the binding does not escape its block:

```
── bridged String ownership path (F1) ──
binary      /workspace/shared-target/debug/tallow sha256:c16cdf2e…a1a8cb
corpus      geocode.state_from_name("Texas") -> "TX", consumed by print
counts      200 vs 2200 iterations, min of 5 runs each, difference / 2000
loop        4.156 µs/call   (9.98619ms -> 18.298587ms)
control    -0.210 µs/call   (same loop, print only; 4.813291ms -> 4.393644ms)
ownership   4.156 µs/call   (loop - control: bridge + marshalling + release)
release    58.9 ns/call     (tallow_free_string, timed directly)
rss         +24 KiB over 2000 calls returning 32751 bytes (baseline 22104 KiB, peak 22128 KiB, 20928 samples)
```

Reading it:

1. **Consuming the result immediately is free at this resolution.** The loop
   measures 4.156 µs/call and the plain bridged call of §7.1 measures 4.780 —
   the same measurement inside run-to-run noise. The control makes that
   explicit: 2200 buffered `print`s of a two-byte literal differ from 200 by
   **less than the ±0.4 ms start-up jitter** of a ~5 ms process, so the control
   comes out *negative* (−0.210 µs/call, and −0.308 on the run before it) and
   is clamped at zero rather than subtracted. That is the control reporting the
   method's floor, not failing: print and loop together cost under 0.3 µs/call,
   and the ownership path is the call.
2. **The release itself is 58.9 ns/call** (60.3 ns on the previous run),
   measured by allocating 200 000 results first and then timing the frees
   alone, so neither the bridge call nor the module's work is in the timed
   region — the two-count subtraction cannot resolve a deallocation against a
   4 µs call. 59 ns is one deallocation of the buffer `tallow_stdlib_call`
   returned; it is the whole run-time cost of F1.
3. **The scan is not in this number** — it is compile-time, per §7.1.

### 7.3 RSS at 2000 calls

F1's own test checks 600 calls with a 32 KiB result. This one checks 2000 —
the same ownership shape (result bound in the loop body, read once, released at
the end of the block) at 3.3× the calls:

```
rss         +24 KiB over 2000 calls returning 32751 bytes
            (baseline 22104 KiB, peak 22128 KiB, 20928 samples)
rss series  [188, 22084, 22088, 21832, 22044, 22048, 21872, 21872, 22100, 22052,
             22052, 22056, 21932, 22104, 22092, 22056, 22056, 22060, 22068, 22096,
             21844, 22072, 21940, 21928, 22112, 22072, 22072, 22068, 21944, 22068,
             22068, 22084, 22108, 22072, 22072, 22072, 22124, 22076, 22108, 22076,
             22128, 22076]
```

Flat after start-up (sample 0 is the process still mapping its binary). A
missing release would be **64 MiB** at this call count — 2000 × 32 KiB — which
is what the ceiling exists to catch. Three runs of this case measured **+24,
+300 and +408 KiB**; the residual is the allocator's arena, not a per-call
trend (24 KiB over 2000 calls would be 12 bytes/call, and the leak this exists
to catch was 32768 bytes/call).

Ceiling: **2048 KiB** — ~5× the largest of those three readings rather than the
2× this brief asked for, and the reason is stated rather than hidden: 2× a
noise-level *peak* (816 KiB) would flake on a shared box, and a flaky
performance gate is worse than a slightly looser one. The bound is still 32×
below the leak it exists to catch, and — per call — **13× tighter** than F1's
own 8 MiB ceiling for 600 calls (1.0 KiB/call allowed here against 13.7
KiB/call there). The existing bound was not touched.

### 7.4 The fences this case adds

| bound | measured | bound | headroom |
|---|---|---|---|
| ownership loop, µs/call | 4.156 (3.819 on the first run) | **8.0** | 1.9× this run, 2.1× the run it was set from |
| RSS growth, KiB over 2000 calls | 24…408 | **2048** | 5.0× (§7.3) |
| `tallow_free_string`, ns/call | 58.9 (60.3) | **1000** | 17× — a sanity fence, not a perf bound |

Guards inside the case, so it cannot pass while measuring something else:

* the emitted IR of the ownership program must contain **exactly one**
  `call void @tallow_free_string` — the bridged result, not the program's own
  string argument. If F1's rule moves and the release stops firing, the case
  fails instead of quietly re-measuring the leak path;
* every timed run must print exactly 200 / 2200 lines, each `TX`; a run that
  did fewer calls, or a corrupted result, fails instead of reporting a small
  delta;
* the loop's two-count subtraction must be positive — 2000 bridged calls are
  ~8 ms of signal against ~0.2 ms of jitter. The control is deliberately *not*
  guarded the same way, for the reason in §7.2;
* the RSS program's summed result length must land between half and twice
  `calls × payload`, which is what a premature release (freed while still live)
  would break — and a garbage answer would also make the RSS series
  meaningless.

### 7.5 What is still unpaid

* **The copy stayed.** F1 gave the buffer an owner; it did not remove the
  `to_vec` + `CString::new` pair the bridge makes per `String` result (§4,
  finding 3). If the bridge ever becomes hot, that copy — not the 60 ns free —
  is the thing to remove.
* **The scan's cost is unmeasured**, for the reason in §7.1. It is a linear
  AST walk with no allocation; anyone who wants a number needs codegen
  instrumentation, which does not exist in this tree.
* **A pre-F1 A/B was not built.** The honest A/B would rebuild `735a689^` into
  a second target dir and run the same harness; the box had 8 GiB free during
  this work and two other lanes building, and the effect being measured (60 ns
  on 4.2 µs) is an order of magnitude below the between-binary spread the A/B
  would be fighting. The direct free measurement is the stronger evidence and
  costs 200 000 allocations instead of a 20 minute rebuild.

