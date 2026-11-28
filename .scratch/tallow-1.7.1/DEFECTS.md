# Tallow 1.7.1 — defect list, reproduced at 1.7.0

Base: published `v1.7.0`, tag commit `24504a4`, binary reports `git: 24504a4b52`.
Every row was produced by running the same program on both planes of that
published binary — `tallow run --interpret` and `tallow run --require-native` —
not read from an older audit.

## The old audit list is mostly stale

The 2026-10-30 audit (at `97ed5d8`) listed nine compiler defects. Reproduced at
1.7.0, **eight of them now agree across planes**:

| claim | at 1.7.0 (both planes) |
|---|---|
| native in-bounds string index returns a heap pointer | `s[0]` prints `h` |
| `map.len` is 1 for every non-empty map | prints `3` for a 3-key map |
| `a[1] = 20` is dropped | prints `20` |
| `&&`/`\|\|` run side effects (no short-circuit) | `false && hit()` and `true \|\| hit()` print neither side effect |
| block shadowing leaks | inner `let x = 2` prints `2`, outer prints `1` |
| `defer` in a loop runs 3× seeing the final `i` | prints `2 1 0` — LIFO, each defer its own `i` |
| `let x: i64 = nil` passes with 0 warnings | refused: `E0116 cannot bind nil where i64 is required` |
| chained `.len` on a native array reads `strlen` over the count | `"a,b,c".split(",").len` prints `3` |

That is eight fixes landed by the waves between `97ed5d8` and 1.7.0, and it means
a 1.7.1 cut is not the list-of-nine job an older note implied.

## What is actually open

### 1. Closure write capture — RESOLVED as a spec correction (decision: code is right)

`spec/04-semantics.md:69` used to say mutation "is visible to closures that
captured them *(reference)*", while the implementation captures a snapshot
(`src/interp.rs:189-191`) and `closure_snapshot_semantics` pins that.

Measured on the published 1.7.0 binary, both planes identical:

```tallow
var n = 0
let bump = { -> n = n + 1; n }
print(bump())   // 1   the closure's own copy persists across calls
print(bump())   // 2
print(n)        // 0   the enclosing binding never changes
```

Operator decision 2026-11-03: the implementation is the contract; the spec is the
outlier. Tallow-Language `62a4251` rewrote 4.6 to state snapshot capture
normatively, explain the surprise, and point at `reduce` for accumulation.
Reference capture, if wanted, is a language change for 1.8 with its own migration
note — not a patch.

### 2. The element of a literal array-of-arrays indexes wrong on the compiled plane — a LOWERING GAP, not to be patched blind

```tallow
let m = [[10, 20], [30, 40]]
print(m[1][0])          // interpreter 30, native 0
```

Exit 0 on both. 1.7.0 fixed the FFI-produced shape (`zip`, `chunk`, cookie
arrays — the element of a `NonScalar` array is not a string); a literal nested
array is a different producer.

**RE-MEASURED 2026-11-26.** The three-site note that used to sit here was
written from reading code, not from running it. A ten-program two-plane probe
set (`scripts/parity-probe.sh`, interpreter vs compiled plane) found FIVE
divergences, not one, and two of them in producers the note never named. All
figures below are from `tallow 1.7.3` (tag `43a3ccf`):

| probe | program | at 1.7.3 |
|---|---|---|
| p01 | `let m = [[10,20],[30,40]]; print(m[1][0])` | DIFFER 30 vs 0 |
| p02 | `print([[10,20],[30,40]][1][0])` (no binding) | DIFFER 30 vs 0 |
| p03 | `m.len` on the nested literal | SAME |
| p04 | `print(m[1])` — print an inner array | NATIVE-REFUSED by name |
| p05 | `let s = [["a","b"],["c","d"]]; print(s[1][0])` | DIFFER `c` vs `0` |
| p06 | flat int array control | SAME |
| p07 | flat string array control | SAME |
| p08 | `Result` array control | NATIVE-REFUSED by name |
| p09 | `for row in g { print(row[0]) }` | DIFFER `1,3` vs `0,0` |
| p10 | `let m = {"a":[1,2],"b":[3,4]}; print(m["b"][1])` | DIFFER `4` vs `nil` |

So the note was wrong on two counts: the defect is **not literal-only**
(`p10` is the tagged-map producer at `emit_nested_index`, not `ExprKind::Array`),
and it **survives iteration and binding** (`p09`, `p01`), so a fix at the index
site alone does not close it. `p05` also rules out an integer-only cause.

**FIXED on branch `fix/nested-array-index` (local, unpushed, 2026-11-26):**
`p01`, `p02`, `p09`, `p10` are SAME on a build carrying `e8d49cb` +
`14ce0f6`; `p06`/`p07` unchanged SAME and `p04`/`p08` unchanged NATIVE-REFUSED.
Probe summary on that branch: `same=7 differ=1 native_refused=2`.

Two mechanisms, both now measured rather than inferred:

- **Literal shape.** The producer `ptrtoint`s a nested element but nothing
  records that the slot is pointer-shaped: `array_expr_elem_is_ptr` asked only
  `expr_is_string_like`, and an inner array literal is not string-like; and the
  binding never inserted `variable_array_elem_is_ptr`. Both fixed
  (`e8d49cb`), which is what closes `p01`/`p02`/`p09`.
- **Tagged-box contract.** `emit_nested_index`'s doc comment promised a tag-6
  (array) branch; the code had only the tag-5 map search and fell through to
  the nil default (`p10`). The contract, read out of the emitted IR:

  ```
  map literal layout  [count, k0, v0, k1, v1, ..., t0, t1, ...]
  array value         tag 6 in the trailing tag array
  tag-6 payload       ptrtoint of a [count, slot...] array buffer
  tagged-box tags     0=int  1=str (inttoptr'd)  2=float (bitcast)
                      3=bool  4=nil  5=map  6=array
  ```

  Writing tag 1 (string) for a scalar slot inttoptr'd the integer 4 into a
  pointer and crashed at rc=139; tag 0 is the integer tag (`14ce0f6`).

**Still open — `p05`.** A string matrix `s[1][0]` still prints `0` natively.
The outer slot `inttoptr`s correctly now, but the loaded inner value is then
classified as a string and indexed as one. A loaded `i8*` cannot say whether it
points at a string or at an array buffer, so this is a representation change,
not a flag: 1.8 work.

The three-site plan this note used to prescribe would not have fixed `p10` and
would not have fixed `p05`; deleting it in favour of the table above is the
point of this edit.

### 3. `tallow scope check` only works from a directory containing the register — FIXED (f90471f)

```
$ cd ~ && tallow scope check 192.0.2.1 --method CONNECT
scope:register-unreadable — refused: the register at
configs/tallow/scope/authorized-hosts.toml could not be read (os error 2)

$ cd <engine repo> && tallow scope check 192.0.2.1 --method CONNECT
scope:not-listed — refused: 192.0.2.1 is not in the authorization register
```

The refusal was correct and fail-closed, but the path was resolved against the
process cwd, so the operator tool was unusable anywhere but the repo root. The
same shape is what made four test suites report `register-unreadable` until they
were changed to run the binary from the workspace root.

Fixed in `f90471f`: `TALLOW_SCOPE_REGISTER` names the register, there is no
upward search (an attacker-planted register is the reason), the refusal names the
working directory and the variable, and the CLI now defaults through
`scope::register_path()` instead of the constant. Verified from /tmp: no override
gives `register-unreadable`; with it, `192.0.2.1` gives `not-listed` and
`127.0.0.1` + CONNECT gives `method-not-allowed`. `cargo test --lib scope`:
87 passed.

### 4. `Array.push` has no lowering on the compiled plane

`tallow build` refuses a program that grows an array with `.push()` by name, so
`tallowx` and every other array-growing program runs interpreted. Documented in
the 1.7.0 changelog's Known-at-tag block; a 1.7.1 candidate only if the lowering
is small, otherwise 1.8.

## Not defects, checked because memory said they were

- **`net.connect` bypassing the register** — false at 1.7.0.
  `net.connect("192.0.2.1:443")` is refused with
  `scope:not-listed — refused: 192.0.2.1 is not in the authorization register`
  and **zero `connect(2)` calls** are made (strace). The gate holds.
- **Native/interpreted agreement on the 1.7.0 test suite** — 24/24 CI jobs and
  the whole release gate passed on the tagged tree.
