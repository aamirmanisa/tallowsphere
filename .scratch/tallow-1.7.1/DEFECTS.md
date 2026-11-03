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

### 1. Closure write capture is lost — on BOTH planes (spec violation, not a split)

`spec/04-semantics.md:69` says mutation "is visible to closures that captured
them *(reference)*".

```tallow
fn main() {
    var n = 0
    let bump = { -> n = n + 1 }
    bump()
    bump()
    print(n)
}
```

Both planes print `0`. The closure mutates a copy, so the language does not do
what its own spec says. This is the worst kind of defect to leave in a patch
release: not a divergence a parity suite can catch, because both engines are
wrong together.

### 2. The element of a literal array-of-arrays indexes wrong on the compiled plane

```tallow
let m = [[10, 20], [30, 40]]
print(m[1][0])          // interpreter 30, native 0
```

Exit 0 on both. 1.7.0 fixed the FFI-produced shape (`zip`, `chunk`, cookie
arrays — the element of a `NonScalar` array is not a string); a literal nested
array is a different producer and still takes the string path. Recorded as
`Tallow-Language/conformance/findings/nested-array-index.tl`.

### 3. `tallow scope check` only works from a directory containing the register

```
$ cd ~ && tallow scope check 192.0.2.1 --method CONNECT
scope:register-unreadable — refused: the register at
configs/tallow/scope/authorized-hosts.toml could not be read (os error 2)

$ cd <engine repo> && tallow scope check 192.0.2.1 --method CONNECT
scope:not-listed — refused: 192.0.2.1 is not in the authorization register
```

The refusal is correct and fail-closed, but the path is resolved against the
process cwd, so the operator tool is unusable anywhere but the repo root. The
same shape is what made four test suites report `register-unreadable` until they
were changed to run the binary from the workspace root.

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
