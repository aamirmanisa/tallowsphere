# Failure attribution — pre-existing, or caused by this change?

The house rule is that a failure predating a change is not that change's, and must not be reported as
though it were. Until now that rule lived in prose: a comment in `.github/workflows/ci.yml` explains the
pre-existing warning baseline, and plan documents hand-annotate individual cases ("this failure is NOT
from this work"). Prose does not survive a CI run. A red job printed a test name and left the reader to
work out whose it was.

`scripts/attribute_failure.py` makes the attribution explicit, and provable.

## The mechanism

For each failing test it runs **the same test at the base revision** — a detached `git worktree` at the
merge-base, with its own `CARGO_TARGET_DIR` so the current tree is never touched — and labels the result:

| Label | Meaning | What it tells you |
|---|---|---|
| `PRE-EXISTING` | fails at the base as well | not this change's; don't hold the PR for it |
| `CAUSED` | passed at the base, fails here | this change broke it; the PR is red on its own merits |
| `NOT-REPRODUCED` | passes when re-run here | the log is stale or the test is flaky — rerun before believing it |
| `UNKNOWN` | could not run at the base | says so; never guesses |

Exit status: `1` if any test is `CAUSED`, otherwise `0`. `UNKNOWN` is reported, not hidden — and does not
fail the run, because "we could not tell" is a different statement from "you broke it".

**The label comes from running the test, never from a heuristic.** It is not inferred from which files a
diff touched, who authored it, or how it smells. That is the whole point: attribution that can be argued
with is not attribution.

## Use

```sh
# from a CI log (the wired path)
cargo test --locked --lib 2>&1 | tee /tmp/test.log || \
    scripts/attribute_failure.py --log /tmp/test.log

# explicit names, against a chosen base
scripts/attribute_failure.py --test cli::pkg::tests::foo --base origin/main

# prove the classifier without building anything
scripts/attribute_failure.py --self-test
```

## Cost, stated plainly

Attribution is not free: the base revision has to be built to run the tests there. In CI this happens
**only on failure**, it is bounded to the failing tests, and it is the only *provable* method — a
cheaper heuristic would reintroduce exactly the guessing this removes. The base worktree and its target
dir are created under `TMPDIR` and removed in a `finally`, so a failed attribution does not leave rubble
behind.

## Verified

- `--self-test` PASS — six classifier cases asserted against expectations written out literally (not
  derived from the rule, so the test cannot agree with a broken classifier by construction), plus the
  log parser. Its first run **failed** and caught a real defect: a test that passes on re-run was being
  labelled `PRE-EXISTING`, which is a lie. That is why `NOT-REPRODUCED` exists.
- End-to-end with a stub runner (real worktree, real subprocess, no build): `CAUSED` / `PRE-EXISTING` /
  `NOT-REPRODUCED` all produced correctly, exit 1 with exactly one `CAUSED`, exit 0 with none.
- Unresolvable base revision → `UNKNOWN`, exit 0 — no guess.
- Worktree and temp dirs cleaned up; `git worktree list` shows only the main tree; the working tree was
  unchanged by every run (`git status` identical before and after).
