# w14 / probe — Windows verdict for v1.7.0, and what the cfg work still misses

Task: tag=probe. Scope: tallowsphere only. No cargo was run in this task; every
number below is read out of the GitHub Actions API or measured locally with
Python over the source tree.

- Tag under test: **v1.7.0 = d3ff51d0212c178251836c7cd7da6e4debe8929f**
  (run head_sha, `git log --oneline -1 v1.7.0` agrees)
- Workflow run: **41389719617** (`event=push`, run_attempt 1, created
  2026-11-02T04:39:55Z)
- 24 jobs. Red: `Test (Windows)` failure, `Browser suites (headless Chrome for
  Testing)` failure, `WordPress fixture (wp_*)` failure. `Contract and CLI
  suites (integration)` was still `in_progress` when queried.
- Local probe worktree HEAD is c895ed5 (`test(wordpress): put the fixture body
  in a Result function so bail typechecks`), one commit **ahead** of the tag; the
  verdict below is for d3ff51d, not for c895ed5.

Reproduce the queries:

    curl -H "Authorization: token $(cat /root/.gh-token-tallow)" \
      https://api.github.com/repos/aamirmanisa/tallowsphere/actions/runs/41389719617/jobs
    curl -sL -H "Authorization: token $(cat /root/.gh-token-tallow)" \
      https://api.github.com/repos/aamirmanisa/tallowsphere/actions/jobs/125099050434/logs

---

## 1. Windows verdict: RED

Job `Test (Windows)` = **125099050434**, `runs-on: windows-latest`.

| step | name | result |
|---|---|---|
| 4 | Swatinem/rust-cache | success |
| 5 | Compile plane (pull requests) | **skipped** (`if: pull_request`; this is a tag push) |
| 7 | **Test** | **failure** — this is the only failing step |
| 15 | Complete job | success |

Failing command (`.github/workflows/ci.yml:164-166`):

    cargo test --locked --lib -- --test-threads=4

Measured tail of the step:

    2026-11-02T04:57:47.6893533Z test result: FAILED. 9506 passed; 37 failed; 33 ignored; 0 measured; 0 filtered out; finished in 278.73s
    2026-11-02T04:57:47.6894133Z error: test failed, to rerun pass `--lib`
    2026-11-02T04:57:48.1167051Z ##[error]Process completed with exit code 1.

So: **exit code 1 on `cargo test --lib`, 37 failures, 9506 passes.** The
compile/warning plane is clean — the Windows crate builds. The tag is red on
Windows because the library is *buildable but not operable* there.

### 1a. The 37 failures are one of exactly two causes

| count | failing group | cause |
|---|---|---|
| 12 | `config::write::tests::*` | owner-only refusal |
| 9 | `config::migrate::tests::*` | owner-only refusal |
| 8 | `vault::identity_keys::tests::*` | owner-only refusal |
| 2 | `cli::secrets_cmd::tests::*` | owner-only refusal |
| 2 | `config::lint::tests::*` | owner-only refusal (consumed as a lint finding) |
| 2 | `logging::tests::*` | owner-only refusal |
| 1 | `config::bundle::tests::import_round_trip_records_history_revision` | owner-only refusal |
| 1 | `scope::tests::test_seam_source_is_cfg_test_gated` | **CRLF-fragile source-text assertion** |

36 + 1 = 37. The full failure list is in the job log under `failures:` at
2026-11-02T04:57:47.6877242Z.

### 1b. Cause A (36/37): the owner-only primitive refuses on non-unix by design

Representative exact messages:

    E7009: config-history location unusable: cannot create history root
    C:\Users\RUNNER~1\AppData\Local\Temp\tallow-config-7952-kb3-corrupt-27\hist:
    cannot create/verify owner-only config directory '...\hist':
    0700 is a POSIX mode and this build has no ACL implementation

    log sink directory '...\tallow-logging-7952-sink' cannot be created
    owner-only (0700) on this platform: no POSIX mode bits and no ACL
    implementation in this build

    C:\...\tallow-secrets-check-7952-...\secrets.json: cannot write a
    credential store on this platform — 0600 cannot be applied (no POSIX mode
    bits, no ACL implementation in this build), so the file would be readable
    by any account the directory ACL admits

    sealed identity key '...\node-identity.key.json': ... (vault::identity_keys)

Code sites (all `#[cfg(not(unix))]` arms that return
`io::ErrorKind::Unsupported`):

- `src/config/write.rs:529-547` — `create_dir_owner_only` non-unix arm; the
  sibling tighten path at `src/config/write.rs:515-524` likewise.
- `src/logging.rs:299-311` — `create_private_dir`; `src/logging.rs:322-338` —
  `open_private_append`.
- `src/cli/secrets_cmd.rs:224` — `save()` refuses before touching the FS;
  `src/cli/secrets_cmd.rs:308` — `restrict_to_owner` non-unix arm.
- `src/vault/identity_keys.rs:762` — documented non-unix stance; refusal
  surfaces as `sealed identity key ... cannot ...` from the log.

The failure is *not* a Windows ACL problem in the sense of "we tried and were
denied": nothing tries. The non-unix arms are deliberate refusals, so on Windows
config history, the credential store, the log sink, and sealed identity keys do
not exist as capabilities at all. Fail-closed is the right instinct for the
secret-bearing paths; the consequence, unstated in the tree, is that Windows
cannot run any of it.

### 1c. Cause B (1/37): `include_str!` compared against a literal `\n`

    thread 'scope::tests::test_seam_source_is_cfg_test_gated' panicked at src\scope.rs:1214:9:
    non-test build must name the absence of the override cell

The assertion is `src/scope.rs:1215`:

    src.contains("#[cfg(not(test))]\nconst TEST_REGISTER_OVERRIDE_ABSENT")

`include_str!` returns the file bytes as checked out. On the Windows runner the
working tree is CRLF, so the `\n`-joined literal never matches. Measured locally
(no cargo needed, this is a pure string test):

    LF file   contains probe: True
    CRLF file contains probe: False
    scope.rs bytes 45253 lines 1238

The repo has **no `.gitattributes`** (no `eol` rule), so nothing pins the
checkout to LF on Windows. Measured:

    $ git ls-files | grep -i gitattributes     # no matches, exit 1
    $ git check-attr eol -- src/scope.rs
    src/scope.rs: eol: unspecified

The Linux leg runs the identical command
(`.github/workflows/ci.yml:114-122`, `cargo test --locked --lib
-- --test-threads=4`) and is green, which isolates the difference to line
endings rather than to code. Label: mechanism proven by local reproducer; the
Windows working-tree CRLF claim is inferred from "same bytes, same assertion,
different result, no eol rule".

Reproducer (Linux, no toolchain):

    python3 -c 'import pathlib;s=pathlib.Path("src/scope.rs").read_text();
    print("#[cfg(not(test))]\nconst TEST_REGISTER_OVERRIDE_ABSENT" in s,
          "#[cfg(not(test))]\nconst TEST_REGISTER_OVERRIDE_ABSENT" in s.replace("\n","\r\n"))'

---

## 2. What the cfg work still misses

The cfg work got the compile plane right (the Windows crate builds cleanly and
37 tests is the only failure surface). Five things remain.

**2.1 The gate sits on the primitive, not on the contract.** There is no
caller-level platform story: nothing states whether config history / credential
store / log sink / sealed keys are *supported* on Windows. The result is a
target that can never be green, so the Windows red carries no regression
information — a new Windows-only regression is indistinguishable from the
standing 37.

**2.2 The crate has two opposite policies for the same concept.**
`src/browser/process.rs:1119-1136` (`create_private_dir`) takes the other
branch: `#[cfg(unix)]` sets 0700, `#[cfg(not(unix))]` falls back to plain
`fs::create_dir` with the contract documented, and every test that asserts mode
bits is `#[cfg(unix)]` (`src/browser/process.rs:2035-2046`,
`:2149-2156`). That module passes on Windows; the other four refuse. So
"owner-only directory" has no single seam — each module decided independently,
and the Windows answer depends on which module you call. Pick one policy (the
browser module's is the one that compiles, runs, and still tells the truth) and
route `config/write.rs`, `logging.rs`, `secrets_cmd.rs` and
`vault/identity_keys.rs` through it.

**2.3 "Cannot verify" is currently reported as "bad".** The refusal travels as
an ordinary `io::Error` into the lint layer: `config::lint::tests::
clean_config_scores_full_marks` fails with

    W7203 ... `file:` target `...\key` sits in `...`; owner-only could not be
    verified — this pl...

and `zero_trust_assessment_rows_cover_ncsc_principles` then fails `left: Gap /
right: Partial`. A platform capability gap is surfaced to the operator as a
security finding and a downgraded assessment row. Those are different states and
must not share a token; the lint/assessment layer needs an explicit
"unverifiable on this platform" severity rather than borrowing a warning.

**2.4 Source-text tests are line-ending-fragile as a class.**
`src/scope.rs:1215` is the instance; there are 54 `include_str!` sites in
`src`+`tests` and this is currently the only one asserting a `\n`-joined
literal, so the fix is two-part: add `.gitattributes` with `* text=auto eol=lf`
(so checkout is deterministic on every OS) and, for the assertion itself,
normalize before comparing (`src.replace("\r\n", "\n")`).

**2.5 The Windows leg never compiles or runs `tests/*.rs`.** On push/tag the
step is `cargo test --lib` only (`ci.yml:164-166`); `cargo check --workspace
--all-targets` is PR-only (`ci.yml:152-154`). Consequences:
`browser_sentinels_live`, `browser_array_parity_cookies` and
`browser_flow_runtime_integration` have **zero** Windows coverage on any tag,
and unix-only code in a test target is not caught by the tag pipeline at all.
The comment at `ci.yml:146-151` ("compile every target on a PR, run the full 9k
suite on main and on tags") is accurate about the lib crate and misleading about
test targets.

---

## 3. Audit of the three browser test files

Short answer: **none of the three uses a unix-only API or a platform-specific
assumption that would break the Windows build.** No `cfg(unix)`, no
`PermissionsExt`, no `/bin/sh`, no symlinks, no `HOME`/`XDG` reads. All three
locate the binary with `env!("CARGO_BIN_EXE_tallow")` (which resolves to a
`.exe` on Windows) and use `127.0.0.1:0` loopback, which is firewall-permitted
by default. The Windows risk in this area is not in these files' own code; it is
that everything they spawn inherits the refused primitives from §1b, and that
nothing runs them on Windows to notice.

### 3.1 `tests/browser_sentinels_live.rs` — two stacked defects, both platform-neutral

Both the brief's diagnosis and one it does not name are present, in this order:

1. **The sentinel namespaces are not visible to the native backend.** The
   program is run by `tallow run` with no plane flag, and the stderr is:

       warning[W0102]: use of possibly undefined variable `DeviceEmulator`
       * native build unavailable (undefined variable: DeviceEmulator — no
         local, constant, function or stdlib namespace of that name is visible
         to the native backend ...)

   Same for `TraceRecorder` and `NetworkInterceptor`. The run therefore silently
   falls back to the interpreter. These tests are named "against a live browser"
   and are supposed to prove the sentinels act rather than report state; in this
   run they exercised the interpreter and never touched the native plane. The
   test never passes `--require-native`, so a native-lowering regression in the
   very code under test is silently downgraded instead of failing.

2. **`scope:register-unreadable` from the relative register path.** After the
   fallback, the first `p.goto("http://127.0.0.1:PORT/")` refuses:

       runtime error: scope:register-unreadable — refused: the register at
       configs/tallow/scope/authorized-hosts.toml could not be read
       (No such file or directory (os error 2)); with no register nothing is
       authorized

   Mechanism: `DEFAULT_REGISTER_PATH` is the relative literal
   `configs/tallow/scope/authorized-hosts.toml` (`src/scope.rs:35`), resolved
   against the process cwd (`src/scope.rs:606`), while the test sets
   `.current_dir(&dir)` to a temp dir (`tests/browser_sentinels_live.rs:56`).
   The script path itself is absolute, so the only reason for the cwd change is
   to relocate `.tallow-traces` (`src/browser/sentinels.rs:517-522`). There is
   no `--register` flag on `run` and no `TALLOW_SCOPE_REGISTER` env override, so
   the test has no way to point at the real register from that cwd.

   Platform note: this is **not** a Windows-only assumption — it fails
   identically on Linux in this run — but it is the one place in the three files
   where the platform matters at all, and only mildly: Rust normalizes `/` in
   relative paths on Windows, so nothing extra breaks; the Windows failure mode
   is byte-for-byte the Linux one.

   Fix options, in order of preference: resolve the register against a stable
   base (manifest/home/env) so deny-by-default does not silently depend on cwd,
   or add an explicit register argument/env for `run` and pass it here. Dropping
   `.current_dir(&dir)` alone would move the trace dir into the repo root.

3. The 3 failures took 0.41 s total for the whole target — the register check
   fires before the target server ever sees a connection, so the fixture's
   connection counter (the actual security evidence) never gets to run.

### 3.2 `tests/browser_array_parity_cookies.rs` — real divergence, platform-neutral

Measured in this run at `tests/browser_array_parity_cookies.rs:90`:

    assertion `left == right` failed: planes disagree:
    native=["0", "1", "1"]
    interp=["0", "1", "3"]

`get_cookies().len` is right at N=0 and N=1 on both planes and wrong at N=3 on
the native plane only — the third cookie is dropped, which is exactly the
"wrong length silently changes behaviour" case the file's header warns about.
The file has no unix-only code and does not change cwd, so the register resolves
from the repo root and this test *does* exercise both planes (it passes
`--require-native` and `--interpret` explicitly). It would reproduce on Windows
unchanged if the target ran there; it does not (§2.5). Nothing in the test needs
platform work; the native lowering does.

### 3.3 `tests/browser_flow_runtime_integration.rs` — harness death, cause not established

The brief's item (c) is real, and the log narrows it further: this is not an
assertion failure.

    2026-11-02T04:52:17.3406413Z  Running tests/browser_flow_runtime_integration.rs (target/debug/deps/browser_flow_runtime_integration-c64a7a175f2af5d3)
    2026-11-02T04:52:17.3406...Z running 5 tests
    2026-11-02T04:52:17.3476255Z error: test failed, to rerun pass `--test browser_flow_runtime_integration`
    2026-11-02T04:52:17.3477938Z   process didn't exit successfully: `.../browser_flow_runtime_integration-c64a7a175f2af5d3 --test-threads=2` (exit status: 1)
    2026-11-02T04:52:17.3478...Z note: test exited abnormally; to see the full output pass --no-capture to the harness.

`running 5 tests` printed, then **zero** per-test lines (`test <name> ... ok`
never appears), process exit status 1, cargo's "exited abnormally" note. The 5
tests are the 4 `#[tokio::test]` cases plus the gated live one
(`:278`, `:321`, `:370`, `:406`, `:461`); the live one early-returns unless
`TALLOW_RUN_BROWSER_LIVE_TESTS` is set, so it cannot be the killer. libtest
prints a test's name *before* running it, so death occurred between harness
start and the first test — i.e. in harness/test-binary setup, not in an
assertion inside any of them.

Not established (and not establishable without cargo, which was out of scope
for this task). Discriminating next step, in this order:

    cargo test --test browser_flow_runtime_integration -- --test-threads=1 --nocapture
    # then, if it still dies silently:
    RUST_BACKTRACE=full cargo test --test browser_flow_runtime_integration -- --test-threads=1

Also worth checking whether it reproduces at all: the log shows six
`chrome-headless-shell` orphans terminated in cleanup, and this target consumes
the most concurrent resources of the browser group. If `--test-threads=1` is
green the cause is resource/setup contention, not the CDP client.

Platform note for this file: no unix-only code; loopback mock CDP; the only
Windows-relevant risk is that `live_browser_launch_new_page_goto_title_data_url`
spawns a real Chrome from `BrowserConfig::default()`, and it is gated off.

---

## 4. Corrections to the brief

- (a) `browser_sentinels_live` does fail with `scope:register-unreadable` — but
  that is the *second* cause. The first, and the reason the tests never reach
  the native plane, is `native build unavailable (undefined variable:
  DeviceEmulator | NetworkInterceptor | TraceRecorder)` followed by a silent
  interpreter fallback. Fixing only the cwd will make these tests green while
  still not testing what their doc comment says they test.
- (b) `browser_array_parity_cookies` — confirmed exactly as stated.
- (c) `browser_flow_runtime_integration` — the target died before any test ran
  ("test exited abnormally", zero per-test output, exit status 1); it is a
  harness/setup death, not a behavioural divergence.
- The brief's framing "red on three browser targets" is right about the intent
  but the Windows job never runs any of them: its failure is the 37 `--lib`
  tests in §1.
