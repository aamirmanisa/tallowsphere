# W13 / tag=lattice — round 2: what the commit changed, and what I left alone

Lane: `rel/w13-lattice` (worktree `/home/aamir/tallow-worktrees/w13/lattice`).
Source commit: `89062c5` — `refuse(perms): 12 cfg(not(unix)) silent-allow stubs become refusals`.
Evidence: `reports/w13-TAG.md` (`c424c58`) is the inventory; this file is the
disposition of it.

Scope: tallowsphere only. **No cargo was run** (brief constraint), so every
verdict here is a source read under the cfg selection — `[read, not executed]`,
not a Windows build observation. Nothing was pushed; the branch is local.

---

## §1 What `89062c5` changed

Twelve `cfg(not(unix))` sites where the unix arm established a `0600`/`0700`/`mlock`
property and the non-unix arm returned success without it, plus the three lint
arms whose constant `0o700` made their own predicate unsatisfiable.

| # (w13-TAG) | site | before | after |
|---|---|---|---|
| 7 | `crates/tallow-crypto/src/mem/wipe.rs` `lock_memory` | `Ok(())` | `Err(CryptoError::Io)` |
| 8 | `src/main.rs` `probe_daemon_state_files` | false `Pass` | `ProbeStatus::Skip` + reason |
| 14 | `src/cli/secrets_cmd.rs` `save` / `restrict_to_owner` | `Ok(())` | pre-write `Err`, then `Err` |
| 15 | `src/config/write.rs` `ensure_dir_secure` | `create_dir_all` | `Err(Unsupported)` |
| 16 | `src/config/write.rs` `tighten_dir` | empty | `Err(Unsupported)` |
| 17 | `src/config/write.rs` `create_dir_owner_only` | `create_dir` | `Err(Unsupported)` |
| 18 | `src/config/write.rs` `atomic_replace` | unmoded open | `Err(ConfigError::Write)` |
| 19 | `src/config/migrate.rs` `atomic_replace_bytes` | `create_dir_all` | `Err(MigrateError::Snapshot)` |
| 20 | `src/config/schema.rs` `read_owner_only_secret` | `is_file()` only | `Err(SecretResolution)` |
| 21 | `src/config/lint.rs` `artifact_mode_finding` | `None` | unverified-permissions finding |
| 22 | `src/logging.rs` `create_private_dir` | `create_dir_all` | `Err(Unsupported)` |
| 23 | `src/logging.rs` `open_private_append` | plain append | `Err(Unsupported)` |
| 26 | `src/vault/identity_keys.rs` `open_sealed_file` | unguarded open | `Err(Unsupported)` |
| 27 | `src/vault/import_export.rs` `write_export_file` | `fs::write` | `Err` |
| 28 | `src/config/lint.rs` `secret_dir_finding` | constant `0o700` | unverified-permissions finding |
| 29 | `src/config/lint.rs` `artifact_dir_finding` | constant `0o700` | unverified-permissions finding |

That is F1, F2, F3 (partly — see §2) and F4 of `w13-TAG.md`.

### What I checked before committing each hunk

A refusal is a compile-time-shaped claim, so each arm was checked against the
error type it has to produce, by reading — not by building:

* `ConfigError::Write { path, message }`, `ConfigError::HistoryPath { message }`,
  `ConfigError::SecretResolution { scheme, detail }` — variants and field names
  read at `src/config/schema.rs:256-296`; `MigrateError::Snapshot { message }` at
  its `atomic_replace_bytes` sibling arms (unchanged, 20 lines above).
* `tighten_dir` has **one** call site (`src/config/write.rs:306`,
  `record_revision`), which was updated in the same hunk to `?` the new
  `Result`.
* `ProbeStatus` is matched exhaustively in exactly one place — `label()`
  (`src/main.rs:19953`); every other use is `== ProbeStatus::Fail` or a
  constructor. `Skip` is a new variant, not a renamed one, and the non-unix probe
  was split into a `cfg(unix)`/`cfg(not(unix))` pair rather than carrying a
  `cfg` arm inside the loop.
* `crates/tallow-crypto/src/mem/wipe.rs` had `#[cfg(unix)]` on `use crate::error::CryptoError;`
  — the non-unix arm now needs it, so the cfg attribute on that import was
  removed. `CryptoError` is still used on unix (`:41`), so the import is not
  unused there.
* `src/vault/import_export.rs` `write_export_file`: the non-unix arm also
  carried the only `plaintext` warning (`eprintln!`). The refusal subsumes it —
  no file is written, so there is nothing to warn about — and `data`/`plaintext`
  are consumed by `let _ = (data, plaintext);` to keep the arm lint-clean.
* The one cosmetic fix: the `restrict_to_owner` message had a run of literal
  spaces from a line wrap; converted to a `\`-continued string.

### Known residue from these edits

Two `unreachable_code` **warnings** can appear on a *non-unix* build
(`src/config/schema.rs`: statements after the diverging non-unix block;
`src/config/schema.rs` `read_owner_only_secret`'s trailing `read_to_string`
path). Unix builds are unaffected — the non-unix blocks are not compiled. CI
does not set `-D warnings` (`.github/workflows/ci.yml:48-50` says so
deliberately), so this is residue to clean, not a gate. It cannot be confirmed
without a `cargo check --target x86_64-pc-windows-msvc`, which this lane forbids.

---

## §2 Stubs I deliberately did NOT change

`w13-TAG.md` (measured at `c424c58`) lists 38 `cfg(not(unix))` sites plus the
whole-file `src/sandbox_runtime_nonunix.rs` module — 39 inventory rows.
`89062c5` nets **+2** fence lines (a new pre-write arm in `secrets_cmd::save`
and the mode-policy arm in `write::atomic_replace`; the probe split moved its
attr rather than adding one), so the tree now carries **40** `cfg(not(unix))`
sites — verified with `grep -rn 'cfg(not(unix))' --include=*.rs src crates | wc -l`.

Of the 39 rows: 5 sites refuse, the whole-file module refuses (5/5), 4 are not
stubs (`N/A`), **16 are covered by `89062c5`**. The remaining **thirteen** are
below, each with the reason it is not a one-line refusal.

### 2.1 Deferred because a refusal is a product regression, not a fail-closed win

**#25 `src/browser/process.rs:1132` `create_private_dir`** — creates
`temp_dir()/tallow-chrome-<pid>-<seq>` with `0700` on unix; non-unix does plain
`create_dir`. This directory is a **Chromium profile**: cookies and session
state land in it. So the gap is real, not cosmetic. But the Windows CDP path is
supported (`launch` only refuses the *pipe* transport — `process.rs:335-346`),
so refusing here deletes the `browser` feature on Windows instead of failing a
single operation closed. The honest non-unix mechanism is an ACL (`icacls`) on
the created directory, which means choosing a Win32-ACL dependency, adding it to
`tallow`'s tree, and proving it on the `test-windows` CI plane. That is a design
change, not a stub flip. **Escalate, do not guess.** My recommendation: add an
`ensure_owner_acl(path)` helper with a real Windows implementation, and make it
refuse only where the ACL call itself fails.

**#10 `crates/tallow-daemon/src/config.rs:146` `read_owner_only_file`** (and
#11 `db.rs:56` `harden_state_file`, #12 `main.rs:52` `tighten_owner_only`,
#13 `sessions.rs:311` `read_sessions`) — the daemon's own bearer-token / DB /
session reads. Same shape as `read_owner_only_secret`, same defect. Not flipped
for two reasons: (a) these are in a **different crate and a different binary**,
whose failure mode is "the daemon does not start at all on Windows", not "one
CLI command refuses" — that is a support decision about whether
`tallow-daemon` ships on Windows, and (b) #11/#12 are *tighten-on-open
remediation* helpers called after a successful open; making them refuse turns a
best-effort repair into a startup failure, which is a different change than the
read-path refusal it looks like. A daemon-scoped round should flip the read path
(#10, #13) and leave #11/#12 as the remediation they are, with a comment.
**This is the largest remaining concentration of the same defect and I am
flagging it rather than absorbing it.**

### 2.2 Deferred because the unix arm gives no stronger guarantee to preserve

**#33 `src/raw_store.rs:68` `freeze`, #34 `src/replication.rs:83` `freeze`** —
both unix arms are already best-effort (`let _ = std::fs::set_permissions(..)`),
so `freeze` does not mean "read-only" on *any* platform. A non-unix refusal
would fail an operation that never had a guarantee, i.e. trade a documented
weakness for a functional break. The fix belongs on the unix side first (make
it propagate), after which the non-unix arm refusing is a small follow-up.

**#35 `src/mesh/journal.rs:190` `sync_dir`** — `Ok(())` without `fsync`. The
adjacent comment (`:184`) states non-unix `rename` is already atomic there; this
is a durability property, not confidentiality and not egress. A refusal would
make journal appends fail on Windows for a property the platform does not
express that way.

**#9 `crates/tallow-crypto/src/mem/wipe.rs` `unlock_memory`** — kept `Ok(())`,
now with a comment saying why: `lock_memory` refuses on this platform, so there
is no lock to release. `Ok` here states a fact about the pages ("they are
swappable, which they already were") rather than certifying a capability. Flipping
it would make `Drop` paths on unix-adjacent builds fail for no gain.

### 2.3 Deferred because a `false` is already the correct answer

**#30 `crates/tallow-copy-engine/src/lib.rs:1437` `is_special`** — returns
`false`. On Windows there is no FIFO/socket source in the POSIX sense; answering
"not special" for a regular file is correct, and distinguishing a reparse point
or device would need `GetFileType`/reparse tags — an implementation, not a
refusal. Refusing would break **every** copy on Windows to protect a case that
cannot occur.

**#31 `src/stdlib/filter.rs:174` `detect_attributes`** — returns
`is_readonly = false`. This is attribute *detection* (metadata), not a policy
gate: the unix arm also answers `false` for an ordinary file. Answering `false`
is not a silent allow of a protected operation.

### 2.4 Deferred because the behaviour is documented, logged, and post-connect

**#32 `src/browser/dpi_bypass.rs:239` `execute_strategy`** — skips `MSG_OOB`
with an `eprintln!` and returns `Ok(())`. It operates on an
**already-connected** `TcpStream` (post-connect packet shaping; it cannot open
anything — it is not on the gate path, which `w13-TAG.md` §1 establishes). The
real defect is that `Ok(())` cannot distinguish "applied" from "partly
skipped", which is an API change (`execute_strategy` has callers) and belongs
with the DPI round, not a refusal sweep.

**#24 `src/main.rs:8730` `append_kt_payload`** — the non-unix arm opens the
transparency-log payload file with plain `OpenOptions` (no `.mode(0o600)`; the
unix arm sets it and re-asserts it). I opened this one, did **not** resolve the
call ordering (`append_kt_payload` runs after the KT chain entry is appended, so
a refusal leaves a chain entry with no payload — an evidence gap with a
different blast radius than refusing a write that has not happened), and the
function is a nested fn inside a large CLI arm in `main.rs`. Per "drop anything
you are not sure of", it stayed out. It needs its own read of the write order
plus a decision on which half is authoritative — **open item, not a silent drop.**

### 2.5 Deferred as out of this round's shape

**F5 `crates/tallow-daemon/src/executor.rs:478`** — an unconditional
`tracing::info!("confined by landlock write-jail")` on a branch made unreachable
on non-Linux only by the preflight at `:86-92`. Logging defect, different crate;
not a `cfg(not(unix))` stub.

**§6 inverse asymmetry (`src/sandbox_runtime.rs:91-108`)** — the **unix**
`run_sandboxed` returns `Ok(())` when Landlock is absent. Not a non-unix stub at
all; it is the more interesting finding (a unix `Ok` that is not evidence of
confinement) and it deserves its own card rather than a drive-by edit in a
permissions sweep. Its sibling `run_sandboxed_rw` is already fail-closed.

**#36-#39** — module swap (`src/lib.rs:172`), type placeholder
(`browser/process.rs:361`), a `#[cfg(test)]`-gated test (`browser/cdp.rs:1549`),
a test helper (`config/lint.rs:1328`). Not stubs.

---

## §3 What is now true, and what is not

True after `89062c5`, by source read:

1. On a build without POSIX mode bits, neither the config kernel
   (`atomic_replace`, `ensure_dir_secure`, `tighten_dir`,
   `create_dir_owner_only`), the config history (`record_revision`), the snapshot
   restore, the credential store, the log sink, the sealed identity key, the
   vault export, nor `file:` secret resolution will create or trust a
   secret-bearing artifact whose containment it cannot establish. Each returns a
   named error in the caller's own error type.
2. `tallow doctor`'s daemon-state probe answers `SKIP` with the missing mechanism
   named, instead of `PASS` with "daemon not provisioned".
3. The three lint checks can no longer report *clean* from zero measurements;
   they report *unverified*.

Not true, and not claimed:

* **No binary was built.** Every claim is `[read, not executed]`. A Windows
  compile could still surface a warning or a cfg-selection error (see §1
  residue). The `test-windows` CI plane is the authority and I did not invoke it.
* **Egress was not touched** — nothing here loosens a gate, and the gate chain
  has no platform cfg at all (`w13-TAG.md` §1), so no gate claim changed.
* **The daemon path is still open** (§2.1): `tallow-daemon`'s token/DB/session
  reads on non-unix still check `is_file()` and nothing else. That is the same
  P2 defect as the ones fixed, in a binary whose Windows support question I am
  not authorised to answer.
* **`browser` run-profile directories are still mode-unprotected off unix**
  (§2.1), and those directories hold cookies.

## §4 Repro

```sh
cd /home/aamir/tallow-worktrees/w13/lattice
git show --stat 89062c5                     # the changed sites
git show 89062c5 -- src/config/write.rs     # one arm, end to end
grep -rn 'cfg(not(unix))' --include=*.rs src crates | wc -l   # 40 (38 at c424c58)
```
