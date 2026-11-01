# lexicon — W12 release lane

Release-gate table on `758e5bc`, and the operator's release sequence. **Report only.**
No version bump, no tag, no push, no publish was made or attempted.

State this report is anchored to:

| fact | value |
| --- | --- |
| worktree | `/home/aamir/tallow-worktrees/w12/lexicon` |
| branch | `rel/w12-lexicon` (cut from `758e5bc`) |
| HEAD | `758e5bc0d0a88015e0357f233b67af64ab635f50` — `scope(register): grant POST to loopback so self-hosted request paths are reachable`, 2026-11-01 23:00:27 +0000 |
| `git describe --tags` (HEAD) | `v1.7.0-4-g758e5bc` |
| last release tag | `v1.7.0` — an annotated tag (`git cat-file -t` → `tag`) on `71eafe3`; `bebe5e0` is a later, untagged commit |
| toolchain | rustc 1.98.1 (48a229cea 2026-09-01), aarch64 |
| cargo invocations this turn | **0** — reason in §A.4 |
| measured | 2026-11-01 23:0x–23:2x UTC |

Every `rc` and every output line below is from a command executed in this turn on this
tree. Nothing in §A is quoted from a document, a changelog, or a prior report.

---

## A. The release gates, run on `758e5bc`

### A.0 Which gates there are — the brief's "six" is one step, not the gate

The release gate is not six gates. It is the `gate` job of
`.github/workflows/release.yml`, which runs **eight** named steps, and it is preceded on
the publish path by a ninth check (the `release-body` build) and shadowed by a tenth
surface (`tallow gate`, **nine** verbs, plus `test-summary` which the refusal message
names and the dispatcher runs — see `src/gate/mod.rs:62`).

The number **six** is real, but it belongs to one step: `Static gates`
(`.github/workflows/release.yml:60-69`) runs exactly six Python checks. That step is
tabled in §A.1. The remaining gate-job steps are tabled in §A.2, because a release that
only ran the six would still be able to publish a tree whose SBOM drifted, whose
advisories fail, or whose conformance corpus is broken.

### A.1 The six static gates (release.yml `Static gates` step)

| # | gate | command run | rc | exact output line (last line of stdout) |
| --- | --- | --- | --- | --- |
| 1 | panic-policy | `python3 scripts/panic_policy_check.py` | 0 | `PANIC-POLICY GATE: PASS` |
| 2 | claims-ledger | `python3 scripts/claims_ledger_check.py` | 0 | `RESULT: PASS — exit 0` |
| 3 | capability-registry | `python3 scripts/check_capability_registry.py` | 0 | `checked 3 Page entries, 0 mismatches` |
| 4 | ffi-symbols | `python3 scripts/check_ffi_symbols.py` | 0 | `checked 330 runtime FFI fns, 291 emitted symbols, 0 problem(s)` |
| 5 | test-coverage | `python3 scripts/check_test_coverage.py` | 0 | `189 targets: 183 in CI, 6 registered as debt (host 3, perf 3), 0 unaccounted, 0 registry problem(s)` |
| 6 | deny-expiry | `python3 scripts/check_deny_expiry.py` | 0 | `deny-expiry: ok — 29 ignored advisori(es) across 2 file(s), all inside their review deadline as of 2026-11-01` |

All six are green on `758e5bc`. Gate 1's preceding lines also carry per-file call-site
rows (`call-sites  pass   src/interp.rs: 4` …) and gate 2's body prints
`HARD findings: none` / `WARN: none` before its `RESULT:` line — both omitted here only
because the table takes the verdict line.

Gate 3's `3 Page entries` is not a typo: the capability registry it checks is the Page
method registry, and `0 mismatches` over 3 entries is the whole assertion. It is one of
the gates `CHANGELOG.md:208-210` records as unable to fail — see §C.

### A.2 The rest of the release gate

| # | gate (release.yml step) | command run | rc | exact output line |
| --- | --- | --- | --- | --- |
| 7 | version consistency, tag ↔ `Cargo.toml` | the workflow's own shell block, run with `GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v1.7.0` | 0 | `version 1.7.0 consistent with tag v1.7.0` |
| 7b | same block, as the *next* tag would find it | same block, `GITHUB_REF_NAME=v1.7.1` | 1 | `Cargo.toml version '1.7.0' does not match tag 'v1.7.1' — refusing to build a mislabeled release` |
| 8 | SBOM drift | `python3 scripts/sbom-gen.py --check scripts/sbom.snapshot.json` | 0 | `sbom-gen: SBOM drift gate OK — regenerated artifact matches scripts/sbom.snapshot.json` |
| 9 | CBOM drift | `python3 scripts/crypto-inventory.py --check scripts/crypto-inventory.json` | 0 | `crypto-inventory: CBOM drift gate OK — regenerated artifact matches scripts/crypto-inventory.json` |
| 10 | release body (publish precondition) | `python3 scripts/release_body.py v1.7.0 --check` | 0 | `release_body: v1.7.0 OK (3332 chars)` |
| 10b | release body for the release being prepared | `python3 scripts/release_body.py v1.7.1 --check` | 1 | `release_body: no CHANGELOG section for v1.7.1; every release must record what was added and what was fixed` |
| 11 | docs-examples | `python3 scripts/docs_examples.py` | 1 | `docs_examples: no repo tallow binary — build it (cargo build --bin tallow) or set TALLOW_BIN; refusing to fall back to a `tallow` on PATH, which is a different build` |

Row 7b is the useful direction of row 7: the block is green at the tag that exists and
red at the tag the tree would receive today, which is exactly what a version-consistency
gate is for. Row 10b is the same shape for the changelog: the release body for `v1.7.0`
builds, and there is no section for the *next* version yet.

Rows 7–10b are the release-gate steps that are checkable without a compiler.

**Not run, and why** (these are not rows: a row requires a command I ran):

- `.github/workflows/release.yml:71-91` — dependency advisories,
  `cargo deny --all-features check advisories`: needs the advisory DB over the network and
  a dependency-graph resolve. Not run. See §C.3 — it would pass on this tree *by waiver*,
  so a green here would not mean clean.
- `.github/workflows/release.yml:106-110` — full lib suite, `cargo test --lib --locked`:
  **forbidden by the brief** (merge owner's suite).
- `.github/workflows/release.yml:117-123` — conformance corpus, needs
  `cargo build --locked --bin tallow` first.
- `.github/workflows/release.yml:133-174` — the 31 integration suites, which include all
  nine `gate_*_parity` targets: needs a build.

### A.3 The docs_examples open item — mechanism, quoted, classified

**Does the gate run `scripts/docs_examples.py` against `TALLOW_BIN`? No.** That is the
brief's second wrong premise, and it matters, because it changes what a green parity test
proves.

There are two implementations, and neither one shells out to the other:

1. **`tallow gate docs-examples`** (`src/gate/mod.rs:284-315`) is a **Rust port**, not a
   wrapper. It parses its own args (`--bin`, `--only`, and `--check` which is accepted and
   ignored "for CI symmetry, as in the Python"), then calls
   `docs_examples::find_binary(bin, &root)` (`src/gate/docs_examples.rs:184-203`), whose
   resolution order is: explicit `--bin` → `$TALLOW_BIN` → `<crate root>/target/debug/tallow`
   → `<crate root>/target/release/tallow` → `None`. The module doc states the rule:
   *"No PATH fallback. A `tallow` on PATH is a different build."*
2. **`scripts/docs_examples.py`** resolves the same four candidates, relative to the
   current directory, and then, at `scripts/docs_examples.py:80-84`, calls
   `sys.exit("docs_examples: no repo tallow binary — …")`.

`tests/gate_docs_examples_parity.rs` compares the two **outputs**; it does not make one
call the other.

**What each prints when the binary is absent** (both measured, this turn):

```
$ python3 scripts/docs_examples.py
docs_examples: no repo tallow binary — build it (cargo build --bin tallow) or set TALLOW_BIN; refusing to fall back to a `tallow` on PATH, which is a different build
rc=1
```

The Rust gate prints the same sentence to stderr and `return 1`
(`src/gate/mod.rs:301-307`), so the two agree on both streams and on the code — which is
why the parity test would pass on the refusal path. That test's own guard is an `eprintln!`
and never an assertion:

```rust
if !binary_present {
    eprintln!("no repo binary built; the comparison would exercise only the refusal path");
}
```

In this tree the refusal is real: `target/` does not exist at all
(`ls -d target` → `No such file or directory`), and the only `tallow` on the box is
`/root/.local/bin/tallow`, `tallow 1.5.8`. The gate's stated reason for refusing that
binary is on record in the script: measured 2026-10-30, a PATH fallback reported
`expected failure ['E0125'], but did not print` for a spec example that is correct. So the
refusal is not the defect.

**Classification: environment defect.** Three candidates, decided:

- *script defect* — no. Both implementations implement the same resolution order, both
  refuse, both say why, and the refusal is a deliberate, documented decision with a
  measured false-positive that motivated it. Nothing in the script is wrong.
- *genuine product gap* — no, and the distinction matters: the gate **did not run its
  subject**. It did not find the docs examples broken; it found nothing at all. There is
  no evidence either way about whether the 7 executable blocks in this tree pass on
  `758e5bc`.
- *environment defect* — yes. The gate's precondition is an in-tree build
  (`target/debug/tallow` or `target/release/tallow`), and this box has no `target/` for
  this worktree; the one binary available is 1.5.8, a different build that the gate is
  right to reject. Remedy is one command, not a code change:
  `cargo build --bin tallow`, or `TALLOW_BIN=<built path> python3 scripts/docs_examples.py`.

One structural note on the gate itself, which is *not* the open item but is adjacent to
it: `.github/workflows/release.yml` never runs `python3 scripts/docs_examples.py`
directly. It relies on the binary being built by the conformance step (line 121) and on
`--test gate_docs_examples_parity` inside the integration step (line 169) to exercise the
examples. CI (`ci.yml:281`, `ci.yml:286`) runs the build and the script explicitly, in that
order. So the release gate covers docs examples **by step ordering**, not by a step that
says so — and if the ordering ever changes, the parity test goes green on two matching
refusals. That is a gate-definition weakness in `release.yml`, worth a line in the next
release-notes' "what was wrong", not a defect in `docs_examples`.

### A.4 Why zero cargo invocations

The box holds `/run/nixe-heavy-build.lock` with, at the time of this measurement, a
sibling lane's `cargo build --bin tallow` (8+ minutes elapsed) plus three `flock` waiters
queued behind it. A build here would queue silently and then compete for 2 jobs on a tree
with a cold `target/` (no `target/` exists in this worktree) and `rust-sqlite` bundled —
worst case for a lane with a written-report deadline.

Nothing in §A needed cargo: every release-gate step that does not compile was runnable,
and the gate steps that do compile are the four listed as not-run above. So this turn
spends its single cargo budget on nothing rather than on a partial build. **Consequence,
stated plainly: this report carries no `test result:` line, because no test suite was
run.**

---

## B. The operator's release sequence, with this tree's exact values

### B.0 The values

| value | measured | command |
| --- | --- | --- |
| `git describe --tags` @ HEAD | `v1.7.0-4-g758e5bc` | `git describe --tags` |
| `git describe --tags` @ `main` | `v1.7.0-6-gb6d2aaf` | `git describe --tags main` |
| commits `v1.6.0..758e5bc` | **98** | `git rev-list --count v1.6.0..HEAD` |
| commits `v1.7.0..758e5bc` | **4** | `git rev-list --count v1.7.0..HEAD` |
| commits `v1.6.0..v1.7.0` | **94** | `git rev-list --count v1.6.0..v1.7.0` |
| commits `v1.7.0..main` | **6** | `git rev-list --count v1.7.0..main` |
| commits `v1.6.0..main` | **100** | `git rev-list --count v1.6.0..main` |
| local `main` | `b6d2aaf` | `git rev-parse main` |
| `origin/main` | `bebe5e0` | `git rev-parse origin/main` |
| `origin/main..main` | **6 unpushed** | `git rev-list --count origin/main..main` |
| tag `v1.7.0` | annotated tag, object type `tag`, on `71eafe3` | `git cat-file -t v1.7.0` |
| remote | `origin` = `git@github-tallow:aamirmanisa/tallowsphere.git` | `git remote -v` |

The four commits the release would carry past `v1.7.0` (`v1.7.0..758e5bc`):

```
758e5bc scope(register): grant POST to loopback so self-hosted request paths are reachable
7bdf59f test(egress): classify the four files the wave made egress-capable
014bbf8 docs(changelog): record the capability-report fix in v1.7.0
1617d0e fix(capabilities): the report reads native fn declarations, so crypto is no longer under-reported
```

One `fix`, one `docs`, one `test`, one behaviour-narrowing `scope` — no language or ABI
addition. On SemVer that reads as **`v1.7.1`** (patch). The version choice is the
operator's; what is not optional is that the tag and `Cargo.toml` agree, because gate row
7b proves the workflow refuses the build otherwise.

### B.1 Where the version strings live, and where they must move

Exactly **one** version string moves per release, in **two** files:

| file | line | current | must become |
| --- | --- | --- | --- |
| `Cargo.toml` | 3 | `version = "1.7.0"` | `version = "1.7.1"` (the `[package]` version of the root `tallow` crate) |
| `Cargo.lock` | 7384 (entry `name = "tallow"` at 7383) | `version = "1.7.0"` | `version = "1.7.1"` |

Nothing else moves. The twelve workspace members under `crates/` are all at `0.1.0`
(`grep -h '^version' crates/*/Cargo.toml | sort | uniq -c` → `12 version = "0.1.0"`), are
consumed as `path` dependencies (`Cargo.toml:153-175`), and have never been bumped by a
release — `git log --oneline -- crates/tallow-net/Cargo.toml` shows two commits, the
tree's own creation and one earlier import, neither of them a release. The evidence that
the root version is the only one that moves is the release commits themselves:

```
$ git show --stat --oneline 71eafe3
71eafe3 release: v1.7.0 — …
 CHANGELOG.md | 53 ++++++++++++++++++++++++++++++++++++++++++++++++++++++
 Cargo.lock   |  2 +-
 Cargo.toml   |  2 +-

$ git show --stat --oneline eea352d
eea352d release: v1.6.0
 Cargo.lock                 | 2 +-
 Cargo.toml                 | 2 +-
 scripts/sbom.snapshot.json | 4 ++--
```

(`v1.6.0` also moved the SBOM snapshot because its dependency graph had changed. Gate row
8 above says this tree's snapshot is currently in sync, so `v1.7.1` is not expected to
touch it — but re-run `python3 scripts/sbom-gen.py --check scripts/sbom.snapshot.json`
*after* the version edit and before the tag, not before it.)

### B.2 The sequence

Run as the operator, from a clean tree, on `main`. `V=v1.7.1` throughout; change one
variable, not six commands.

```bash
cd /home/aamir/tallow-worktrees/w12/lexicon
V=v1.7.1

# 0. precondition: main is the tree being released, and it is clean
git switch main
git status --short                      # must print nothing
git log --oneline -1                    # b6d2aaf (or later)

# 1. the release commit: version + a changelog section the release gate will accept
#    CHANGELOG.md needs  ## [v1.7.1] — <date> — <title>  with  ### What was wrong
#    and  ### What was fixed  (scripts/release_body.py refuses without both).
sed -i 's/^version = "1.7.0"$/version = "1.7.1"/' Cargo.toml
$EDITOR CHANGELOG.md
git add Cargo.toml CHANGELOG.md Cargo.lock
git commit -F .git/RELEASE_MSG            # message from a file, not -m

# 2. the release gate, in the shape release.yml runs it (no compiler needed)
python3 scripts/panic_policy_check.py
python3 scripts/claims_ledger_check.py
python3 scripts/check_capability_registry.py
python3 scripts/check_ffi_symbols.py
python3 scripts/check_test_coverage.py
python3 scripts/check_deny_expiry.py
python3 scripts/sbom-gen.py --check scripts/sbom.snapshot.json
python3 scripts/crypto-inventory.py --check scripts/crypto-inventory.json
python3 scripts/release_body.py "$V" --check          # must be rc 0 before tagging
grep -m1 '^version' Cargo.toml                         # must print 1.7.1

# 3. the gates that need a compiler (operator's own cargo window, not a lane's)
cargo build --locked --bin tallow
python3 scripts/docs_examples.py                       # the gate this report could not run
cargo test --lib --locked -- --test-threads=2
TALLOW_BIN="$PWD/target/debug/tallow" cargo test --locked --test conformance_runner -- --nocapture
#    …then the 31 integration suites from release.yml:133-174

# 4. OPERATOR-ONLY — irreversible egress begins here
git tag -a "$V" -F .git/TAG_MSG
git push origin main
git push origin "$V"

# 5. the tag fires .github/workflows/release.yml: build 5 targets → DRAFT release.
#    Publishing is a separate, explicit act: workflow_dispatch with inputs.publish=true,
#    and it only runs from a tag.
```

### B.3 Which steps are operator-only, and why

**Only step 4 is operator-only.** Everything in steps 0–3 is reversible: a commit can be
amended or reset, a local tag deleted with `git tag -d`, a pushed tag force-deleted by
someone who owns the remote. What makes step 4 different is not ceremony — it is that the
tag **is** the release's identity and the push is the moment it becomes someone else's
fact:

- `git tag -a` writes a ref that CI treats as an instruction. Pushing it *is* the trigger
  for `on: push: tags: ['v*']` in `release.yml:19-21`; there is no separate "start the
  release" command. A tag pushed by mistake begins five target builds and a draft release
  under a version number that a later, correct tag cannot reuse without a force-push on a
  public ref.
- `git push origin main` publishes the six commits currently unreachable from
  `origin/main` (`origin/main..main` = 6). Until that push, the released tree would not
  exist on the remote at all.
- Both are **egress**: after them the tree is not ours to correct in place. That is the
  boundary this lane's envelope puts at L2→escalate. Step 5's `publish=true` dispatch is
  operator-only for the same reason, plus one more: it is the step that makes the draft
  public, and it is deliberately not something a workflow can reach on its own.

Steps 0–3 are **not** operator-only in principle (any lane could do them in a branch),
but they belong to the operator in practice for one reason: the release commit lands on
`main`, and this lane is forbidden from pushing to `main` at all.

### B.4 Ordering that the sequence depends on

The tag must come **after** the version commit, not before — gate row 7b is the proof: at
`v1.7.1` against the current `Cargo.toml` the workflow's own check prints
`Cargo.toml version '1.7.0' does not match tag 'v1.7.1' — refusing to build a mislabeled
release` and exits 1. Likewise `scripts/release_body.py "$V" --check` (step 2, last line
before the tag) refuses a version with no changelog section, which is why the section is
written in the same commit as the bump rather than after it.

---

## C. What these numbers do NOT certify

Every item here is a thing a green table above could be mistaken for proving.

1. **Nothing about the docs examples on `758e5bc`.** Gate row 11 is `rc 1` and its output
   is a refusal to run, not a finding. The 7 executable blocks in `docs/` and `README.md`
   were not executed. The most recent number anyone has for that gate is *"20 blocks — 7
   executed, 13 skipped with a reason, 0 failed"*, recorded in
   `docs/plans/2026-10-tallow-2.0-feature-backlog.md:649` (G59 row) as **measured
   2026-10-29**, i.e. on a different tree, three days and 4+ commits before this sha. Do
   not carry it forward.
2. **Nothing about the library suite, the conformance corpus, or the 31 integration
   suites on `758e5bc`.** None was run (brief: `cargo test --lib` belongs to the merge
   owner; the other two need a build and the box lock was held). The last library-suite
   number recorded anywhere in the repository is **9,267 passed / 0 failed / 33 ignored,
   153.88 s**, in the `### Verified` block of `[v1.5.7]` (`CHANGELOG.md:317-319`),
   measured **2026-10-25** — six days and roughly 100 commits before this sha.
3. **`deny-expiry` green is not `cargo deny` green, and neither is `deny` clean.** Gate
   row 6 passes because all 29 ignored advisories are *inside* their deadline; that is a
   statement about paperwork, not about the dependency graph. On this tree the three zstd
   advisories are **waived, not fixed**: `deny.toml:34-36` ignores `RUSTSEC-2026-0391`,
   `-0398` and `-0403` under `# review-deadline: 2027-01-31`, with the reasoning that
   `zstd 0.13.4` / `zstd-safe 7.4.0` are the newest published releases and `wreq-util
   3.0.0-rc.14` pins `zstd ^0.13.3` so the crate cannot be upgraded out. `Cargo.lock`
   confirms the tree still carries both lines (`zstd 0.13.4` at 9648 and `zstd 0.14.3` at
   9620; `zstd-safe 7.4.0` and `8.2.0` at 9653/9662). `release.yml:71-91` says in as many
   words that this step exists to make a tag red until zstd moves. **The advisories step
   was not run in this turn; it would pass by waiver, and 2027-01-31 is the date the
   waiver stops passing.**
4. **Nothing about the changelog's own numbers for the shipped release.** `v1.7.0` — the
   release that is currently tagged — has **no `### Verified` section at all**; neither
   does `v1.6.0` or `v1.5.8`. `awk '/^## \[/{v=$2} /^### Verified/{print NR": "v}'`
   puts the last one at line 317, inside `[v1.5.7]` (2026-10-25). Rows 10 and 10b prove
   the release *body* builds (`3332 chars` for `v1.7.0`); they prove nothing was measured
   into it.
5. **Nothing about the six gates' power to fail.** `CHANGELOG.md:208-213` records that
   six of the nine `tallow gate` verbs cannot be made red on today's tree by mutating a
   scratch copy. Green rows 1–6 above are therefore consistent with both "the tree is
   sound" and "the check cannot see this class of defect". The parity suites
   (`tests/gate_*_parity.rs`) prove *binary equals script*, which is not the same claim.
6. **A CI gate is red on this sha and is not in the release gate.** Measured:
   `python3 scripts/check_backlog_evidence.py` → `rc 1`,
   `backlog evidence: 38 DONE rows, 66 path refs, 1 problem(s)` /
   `FAIL G07: src/interp.rs:23748 does not mention 'bind_binding_pattern'`. It is a CI-only
   check (`ci.yml:277`), so the release gate is green while CI is not. Pre-existing —
   `CHANGELOG.md:224-226` records the same G07 failure at an earlier line number
   (`23659`, now `23748`: the row is stale, the target moved).
7. **`census-surface` / `census-page-methods` were checked, and are not release gates.**
   For completeness, both were run and are green: `python3 scripts/census_surface.py` →
   `rc 0`, `checked 300 empty-bodied declarations, 0 unmentioned on both planes, 1 declared
   refusals, 2 dated debt`; `python3 scripts/census_page_methods.py` → `rc 0`,
   `checked 48 Page methods, 47 on both planes, 0 mismatch(es)`. They run in `ci.yml`,
   not in `release.yml`'s gate job. The 2 dated debt rows expire 2027-03-31.
8. **The "local-only (R0)" release identity is unciteable in this tree.**
   `CHANGELOG.md:10` says *"Release identity for V1 is **local-only (R0)** — see
   `docs/release/versioning-policy.md`"*, and that file does not exist:
   `git ls-files docs/release` returns nothing and there is no `docs/release/` directory.
   Everything in §B is therefore derived from `.github/workflows/release.yml`, the
   changelog's format contract, and the release commits themselves — not from a policy
   document, because there isn't one here to read.
9. **A green §B.2 step 2 does not make step 3 optional.** The four compiler-dependent
   gates (lib suite, conformance, integration, docs examples) are where the last three
   releases' real defects were caught — `release.yml:133-139` says so for 1.5.1.

---

## D. Premises in the brief that turned out to be wrong

1. **"main is 758e5bc."** It was, when the lane was cut. It is not now: local `main` is
   `b6d2aaf` (two further commits from sibling lanes, 23:08), and `origin/main` is still
   `bebe5e0` — six commits behind local `main`, so the release push in §B.2 carries six
   commits, not four. `git describe --tags main` = `v1.7.0-6-gb6d2aaf`. My worktree is
   still at `758e5bc` as instructed, so §A is measured on `758e5bc` and §B names both
   shas rather than pretending they are the same tree.
2. **"the six release gates."** Six is the size of one step (`Static gates`), not of the
   gate. The gate job has eight steps; `tallow gate` exposes nine verbs plus
   `test-summary`; and the publish path adds the release-body check. §A.0.
3. **"the gate runs `scripts/docs_examples.py` against `TALLOW_BIN`."** It does not.
   `tallow gate docs-examples` is a Rust port (`src/gate/docs_examples.rs`) that resolves
   the binary itself; the Python script runs separately in CI, and the parity test compares
   their outputs. Both honour `TALLOW_BIN` as the *second* candidate, after `--bin`. §A.3.
4. **"the last release is v1.7.0 (commit 71eafe3)."** True, and worth keeping precise:
   `v1.7.0` is an **annotated** tag (`git cat-file -t v1.7.0` → `tag`) on `71eafe3`, so the
   next tag must also be annotated (`git tag -a`), not lightweight — a lightweight tag
   would be a different kind of object on the same ref namespace that the workflow pulls
   into the release body (`%(taggername)` is empty for one).
5. **"Cargo.toml(s)"** — plural. There is exactly one version string to move, plus the
   lockfile's copy of it. The twelve `crates/*/Cargo.toml` are all `0.1.0` path
   dependencies and no release has ever bumped them. §B.1.

## E. Open work this lane did not do

- Run the four compiler-dependent gates on `758e5bc` — needs one build window on the box,
  which this turn declined to queue for (§A.4). The single most valuable one is
  `python3 scripts/docs_examples.py` after `cargo build --bin tallow`, because it is the
  only gate row that is red for a reason that is not the product.
- `cargo deny --all-features check advisories` — needs the advisory DB and a network
  window; §C.3 predicts the verdict (pass-by-waiver), which is exactly why it should be
  run rather than predicted.
- The `release.yml` docs-examples ordering weakness noted in §A.3 (covered by step order,
  no explicit step) is a two-line workflow fix and belongs to whoever owns the release
  workflow, not to this report.
