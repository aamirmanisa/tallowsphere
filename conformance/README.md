# Conformance suite (engine copy)

Vendored from `Tallow-Language/conformance` so CI can prove the *packaged* binary
behaves, not just that it links. Canonical copy: the language repo; sync by
copying `cases/` and updating the digest below.

The runner is a Rust test target, not a script — it runs through `cargo test`
like every other check, and it takes the compiler under test from the build this
tree produced rather than from `PATH`.

    cargo test --test conformance_runner

    # a specific binary (e.g. a release or packaged artifact)
    TALLOW_BIN=/path/to/tallow cargo test --test conformance_runner

    # rewrite expectations from both planes (a case whose planes disagree is
    # REFUSED, never pinned)
    TALLOW_REFRESH=1 cargo test --test conformance_runner -- --ignored

The binary under test is `$TALLOW_BIN` when set, else `target/debug/tallow`.
There is deliberately no `PATH` fallback: a `tallow` picked up from `PATH` is a
different compiler than the one this tree built, so proving the packaged binary
against it proves nothing. The suite runs against the debug build by default
because that is the archive the native plane links; a release binary needs
`TALLOW_BIN=target/release/tallow` *and* a `target/release/libtallow.a` built
from the same tree.

Each case runs on BOTH planes (`--interpret` and `--require-native`) and must
agree with its `.json` expectation, so a divergent plane fails instead of
silently shipping.

Cases: 27 · files: 54 ·
tree sha256: c8852d5dc5c9a6aa022c182e5ab243772fe994ad0cc22b165afa835b04bd00e0

The digest covers **every file** in `cases/`, computed as
`find cases -type f | sort | xargs sha256sum | sha256sum`. It is the whole tree,
so a case added without refreshing it is an unaccounted file — the failure mode
that let seven cases ship against a digest that did not include them.

`findings/` holds programs the suite cannot pin yet: they either diverge between
the planes or exercise a feature one plane lacks. A case lives in `cases/` only
when it passes on both.
