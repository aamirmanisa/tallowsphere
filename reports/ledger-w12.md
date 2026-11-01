# ledger — W12 lane: the http.* compiled-plane defect (D3)

Tree: /home/aamir/tallow-worktrees/w12/ledger, branch `rel/w12-ledger`, cut from
tallowsphere main @ 758e5bc0d0a88015e0357f233b67af64ab635f50.

Verdict: **D3 is not reproducible at 758e5bc. No code was changed.** The
compiled plane already aborts with the register's refusal sentence and exits 1,
which is exactly what the interpreter does and exactly what `net.connect` does.
Three of the brief's premises are wrong; they are refuted below with commands.

## The binary every measurement in this report ran under

    $ target/debug/tallow --version
    tallow 1.7.0
      platform: linux
      arch: aarch64
      build: 2026-11-01T23:14:54Z
      git: 758e5bc0d0 (dirty)

    $ sha256sum target/debug/tallow
    60a7417f3563a8e302e87a4ec40236030cedf5ef7f17b4d7cc55969b6eedcba0

    $ ls -l --time-style=full-iso target/debug/tallow
    485438920  2026-11-01 23:19:00.305522014 +0000

`(dirty)` is the wave-prep `.gitignore` edit described at the end of this
report; nothing under `src/` differs from 758e5bc. Built with
`CARGO_BUILD_JOBS=2 cargo build --bin tallow`, once, before any measurement.
Every run below used that one binary, unmodified, throughout.

## Measurement 1 — the program as the brief writes it

    $ cat brief.tl
    print(http.post("https://1.1.1.1/x","body"))

    $ target/debug/tallow run --interpret brief.tl      → exit 1
    $ target/debug/tallow run --require-native brief.tl → exit 1

Both planes, identical, on stderr and nothing on stdout:

    error[1:1]: expected item (fn, struct, enum, impl, trait, const, type, import), found print

A bare top-level expression is not a Tallow program; it fails at the parser on
both planes. So the literal snippet in the brief cannot produce `(null)` on any
plane at this revision — it produces a parse error. Premise P3 below.

## Measurement 2 — the same call inside a program the checker accepts

The annotated form is the one `tests/egress_scope_gate.rs` uses (the checker
requires the annotation header before it will run a network program, and
`Budget(bytes: …)`/`Plane(egress)` do not parse, per D4 of the defects doc):

    @legal(basis: .research, purpose: "scope gate regression")
    @cra_class(.default)
    @persona("operator")
    @burn_plan("none - refusal happens before egress")
    @fingerprint_policy(policy: .none, bot_identity: "TallowTest/1.0 (+https://tallow.invalid/test)")
    fn main() with Net(post) {
        print(http.post("https://1.1.1.1/x", "body"))
    }

    $ target/debug/tallow run --interpret annot.tl
    exit=1
    stderr:
      * running in the interpreter (--interpret)
      runtime error: http.post: scope:not-listed — refused: 1.1.1.1 is not in
      the authorization register (deny-by-default) (at 7:5)

    $ target/debug/tallow run --require-native annot.tl
    exit=1
    stderr:
      runtime error: scope:not-listed — refused: 1.1.1.1 is not in the
      authorization register (deny-by-default)

Both planes print the register's refusal sentence and exit non-zero. Neither
prints `(null)`. The compiled run does **not** contain `running in the
interpreter`, so it did not fall back — this is the native plane's own output.
Stdout was empty on both planes, as it must be: the call aborts before `print`
is reached, on both planes, which is also the plane split for `net.connect`.

Remaining divergence, and it is decoration not semantics: the interpreter
prefixes `http.post: ` and appends `(at 7:5)`; the compiled plane prints the
bare `tallow_last_error`. The sentence itself is byte-identical.

### Sockets opened on the native plane

    $ strace -f -e trace=connect -o conn-native.log target/debug/tallow run --require-native annot.tl
    $ grep -c "connect(" conn-native.log
    0

Zero `connect()` syscalls: the refusal is decided in `crate::scope::require`
before any socket call, on the compiled plane as on the interpreted one.

## The premise checklist

### P1 — "net.connect got the null -> last_error treatment in cf41072"

**Wrong as stated: `cf41072` does not exist in this repository.**

    $ git cat-file -t cf41072
    fatal: Not a valid object name cf41072

The net.connect work does exist, under other hashes:

    $ git log --oneline --all --grep="net.connect"
    c30d0d1 fix(egress): a refused net.connect aborts instead of continuing
    747c88c fix(net): the scope gate holds on both planes, and a refusal is visible

The end state the brief describes is real: `tallow_net_connect` returns null
with the reason in `tallow_last_error`, and the lowering emits
`call void @tallow_check_string(ptr %r)`, which prints the reason to stderr and
`exit(1)`. Only the citation in the brief is unusable here.

### P2 — "the http.* lowering never got the null -> last_error treatment"

**Wrong. Both http paths already carry it at 758e5bc.**

src/codegen.rs `emit_stdlib_http`:

    line 30356 (get)      {resp} = call ptr @tallow_fetch(...)          → call void @tallow_check_string(ptr {resp})
    line 30393 (post/put/delete/patch/head)
                          {resp} = call ptr @tallow_fetch_method(...)   → call void @tallow_check_string(ptr {resp})

    $ git blame -L 30356,30356 src/codegen.rs
    5a31321f (Aamir Manisa 2026-10-31)  … call void @tallow_check_string(ptr {resp})
    $ git blame -L 30393,30393 src/codegen.rs
    5a31321f (Aamir Manisa 2026-10-31)  … call void @tallow_check_string(ptr {resp})

    $ git log -1 --format="%h %ad %s" --date=iso 5a31321
    5a31321 2026-10-31 06:37:40 +0000 fix(egress): the http verbs consult the register, and a refusal is fatal

`docs/egress-gate-open-defects.md` is dated 2026-10-30. The fix landed the next
morning and the document was never re-measured. D3 is a stale document, not an
open defect. (Re-measuring that document is the `probe` lane's assignment.)

### P3 — the literal snippet in the brief

**Wrong**: `print(http.post(...))` at top level is not a program. Both planes
reject it at the parser (measurement 1). Any measurement of this defect has to
be made on the annotated form in measurement 2.

### P4 — "1.1.1.1 is refused" holds

Confirmed by `configs/tallow/scope/authorized-hosts.toml` (116 lines) containing
no `1.1.1.1` entry, and by the refusal output itself.

## STEP 2 — the plane split, stated rather than invented

The question "does the compiled plane abort or return the value?" is already
answered by the tree, and the answer is **abort**, on both planes, for every
gated effect call:

* `net.connect` → `tallow_check_string` on null → stderr + `exit(1)`.
* `http.get` / `http.post` / `put` / `delete` / `patch` / `head` → same guard,
  same function, same exit.
* The interpreter's `http_post` returns `Err(format!("http.post: {reason}"))`,
  and the dispatch layer turns that into `runtime error:` plus a non-zero exit.

So a refusal is **fatal, not an inspectable value**, consistently. `http.batch`
is the documented exception and stays one: it refuses per entry
(`EntryOutcome::refused`, `http.batch[url]: scope:not-listed — …`) because the
batch contract is "N results, one per URL". That asymmetry is deliberate; making
batch fatal would be a new failure semantics, which this lane was told not to
invent. Nothing was changed.

## Tests named as affected

The brief's three constraints (one cargo invocation / a pre-edit build / a
quoted `test result:` line) cannot all hold: the build is one invocation and any
test is a second. I spent the first on the mandatory measurement and accepted
the second for the four lib cases that pin this lowering:

    $ CARGO_BUILD_JOBS=2 cargo test --lib codegen_stdlib_http -- --test-threads=1
    running 4 tests
    test codegen::tests::codegen_stdlib_http_get ... ok
    test codegen::tests::codegen_stdlib_http_post ... ok
    test codegen::tests::codegen_stdlib_http_post_forwards_body ... ok
    test codegen::tests::codegen_stdlib_http_put ... ok
    test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 9604 filtered out;
    finished in 0.04s

Green, and green because the source is unchanged, not because the change was
made to fit — the tree at HEAD is 758e5bc plus this report.

## A real gap this measurement exposes (not fixed — brief says stop)

`http_write_verbs_refuse_a_host_absent_from_the_register` in
tests/egress_scope_gate.rs loops over both planes and **silently skips** the
native plane when it detects a fallback (`continue`), where the net.connect case
hard-asserts no-fallback. That skip is what would let a re-broken http lowering
pass the test again. Work item: replace the `continue` with the same assert the
net.connect case uses. Then, and only then, is the test a regression test for
D3 rather than for "some plane refused".

## What I did not do

* No source change: `src/codegen.rs` and `src/runtime/` are untouched, because
  the defect the brief sent me to fix does not exist at 758e5bc.
* No new test target, so `.github/workflows/ci.yml` and
  `scripts/check_test_coverage.py` are untouched.
* No `cargo fmt` of any kind, no push, no tag.

## Tree hygiene note

`.gitignore` was modified in this worktree before I ran anything (the same
8-line change is present in `/home/aamir/tallow-worktrees/w12/probe` and
`…/vellum`), allowing `reports/*.md` to be tracked. It is not this lane's edit;
it is committed here because it is what makes this report citable.
