# W13 / tag=lattice — every `cfg(not(unix))` refusing stub, and whether it refuses

Lane: `rel/w13-lattice` @ `7f744ac` (worktree `/home/aamir/tallow-worktrees/w13/lattice`).
Scope: tallowsphere only. **No cargo was invoked** in this lane (brief constraint),
so every verdict below is a *reading of source plus the compiler's own cfg
selection*, not a binary observation. Where a claim would need a Windows run to
be certain, it is labelled `[read, not executed]`.

---

## §1 THE ANSWER TO THE QUESTION THE BRIEF ASKS

> "Check specifically that the egress/scope gate still holds on the stub path, so
> a call that is unix-only cannot become an ungated path on Windows."

**It holds. There is no non-unix stub anywhere on the request→gate path.** The
gate chain contains zero platform conditionals — its only `cfg` attributes are
`cfg(test)` / `cfg(not(test))`:

```
§B1 non-test cfg kinds in gate chain:
$ grep -n 'cfg(unix)\|cfg(windows)\|cfg(not(unix))\|cfg(target_os' \
    src/net/egress.rs src/scope.rs src/runtime/egress_http.rs \
    src/runtime/dns_guard.rs src/gate/capability_registry.rs
(none)

§B2 all cfg kinds present:
$ grep -ho 'cfg([^)]*)' src/scope.rs src/runtime/egress_http.rs src/net/egress.rs | sort | uniq -c
      3 cfg(not(test)
     23 cfg(test)
```

Every module that can open a socket or a request is platform-neutral — the gate
cannot be compiled out on Windows because it was never inside a `cfg(unix)`:

```
§D3 network-capable modules with any platform cfg:
0 src/stdlib/net.rs
0 src/stdlib/ws.rs
0 src/stdlib/http.rs
0 src/runtime/fetch.rs
0 src/runtime/net_ffi.rs
0 src/runtime/dns_guard.rs
0 src/sluice.rs
```

Two files contain both a scope-gate call site and a non-unix stub, so I checked
the ordering by hand rather than assuming the `comm` result was harmless:

```
§D1 files calling the scope gate that also contain a non-unix stub:
src/browser/dpi_bypass.rs
src/main.rs
```

* `src/browser/dpi_bypass.rs` — the stub at `:239` is inside `execute_strategy`
  (`:147`), which takes an **already-connected** `&mut tokio::net::TcpStream`.
  It is post-connect packet shaping; it cannot open anything. The file's only
  network-opening site is the DoH fetch, which gates first at `:401`
  (`if let Err(r) = crate::scope::require(&url, "GET")`), and a source-guard test
  pins that ordering at `:923-930` ("scope::require must run before the DoH client
  is built"). A Windows build skips *one packet action* there, not the gate.
* `src/main.rs` — the stubs are at `:8730` (journal append) and `:20170` (a
  doctor probe). Neither is upstream of a request; the file's gate calls are at
  `:2355` (relay) and elsewhere in the CLI arms.

Positive evidence that the grant requirement itself is not platform-gated: the
tests that prove it carry no `cfg` at all, so they run on every CI plane.

```
§A5 $ grep -rn 'cfg(' tests/effect_rows.rs tests/scope_gate.rs | wc -l
0
§A6 $ grep -n 'declared_row_without_a_grant_is_refused' tests/effect_rows.rs
163:fn declared_row_without_a_grant_is_refused() {
```

The one structural gap I did find is the **inverse** of the brief's worry — see
§6: unix `run_sandboxed` returns `Ok(())` *without* enforcing, while the Windows
stub correctly refuses.

---

## §2 INVENTORY AND METHOD

38 `cfg(not(unix))` sites exist in the tree, plus one whole-file non-unix module
(`src/sandbox_runtime_nonunix.rs`, 5 entry points) that carries no `cfg` of its
own because `src/lib.rs:172-174` selects it with `#[path]`.

```
§A1 $ grep -rn 'cfg(not(unix))' --include=*.rs src crates | wc -l
38
```

The inventory was built by a read-only extractor
(`~/.hermes/profiles/lattice/cache/scratch/scan_stubs.py`, no cargo) that prints
each site with 34 lines of body and the enclosing `fn`. Each site was then read
in full; the heuristic classifier was discarded where it disagreed with the
source (it labelled `src/vault/identity_keys.rs:760` REFUSE because an `Err` arm
appeared 20 lines later — the stub body itself allows).

Verdict vocabulary:
* **REFUSE** — returns `Err`/aborts, and the caller propagates it.
* **SILENT-SKIP** — the unix arm enforces a property (mode, lock, confinement);
  the non-unix arm does nothing and control continues to success.
* **DEFAULT** — returns a fixed value that makes a check pass.
* **EMPTY** — an empty function body.
* **N/A** — not a stub (module swap, type placeholder, test).

---

## §3 VERDICT TABLE (all 38 + the whole-file module)

| # | site | enclosing fn | verdict | sev |
|---|------|--------------|---------|-----|
| 1 | `src/sandbox_runtime_nonunix.rs:18,23,28,37,42` | whole module (5 fns) | **REFUSE** | — |
| 2 | `src/browser/juggler.rs:223` | `JugglerClient::launch` | **REFUSE** | — |
| 3 | `src/browser/process.rs:338` | `launch` | **REFUSE** (pre-spawn) | — |
| 4 | `src/stdlib/process.rs:85` | `child_is_running` | **REFUSE** | — |
| 5 | `crates/tallow-copy-engine/src/lib.rs:1636` | `create_symlink` | **REFUSE** | — |
| 6 | `crates/tallow-daemon/src/executor.rs:478` | `run_tallow_script` | **REFUSE** (preflight) | — |
| 7 | `crates/tallow-crypto/src/mem/wipe.rs:96` | `lock_memory` | SILENT-SKIP + `Ok(())` | **P1** |
| 8 | `src/main.rs:20170` | `probe_daemon_state_files` | EMPTY-SUCCESS (false PASS) | **P1** |
| 9 | `crates/tallow-crypto/src/mem/wipe.rs:129` | `unlock_memory` | SILENT-SKIP + `Ok(())` | P2 |
| 10 | `crates/tallow-daemon/src/config.rs:146` | `read_owner_only_file` | SILENT-SKIP mode | P2 |
| 11 | `crates/tallow-daemon/src/db.rs:56` | `harden_state_file` | EMPTY | P2 |
| 12 | `crates/tallow-daemon/src/main.rs:52` | `tighten_owner_only` | EMPTY | P2 |
| 13 | `crates/tallow-daemon/src/sessions.rs:311` | `read_sessions` | SILENT-SKIP mode | P2 |
| 14 | `src/cli/secrets_cmd.rs:286` | `restrict_to_owner` | SILENT-SKIP + `Ok(())` | P2 |
| 15 | `src/config/write.rs:464` | `ensure_dir_secure` | SILENT-SKIP mode | P2 |
| 16 | `src/config/write.rs:491` | `tighten_dir` | EMPTY | P2 |
| 17 | `src/config/write.rs:501` | `create_dir_owner_only` | SILENT-SKIP mode | P2 |
| 18 | `src/config/write.rs:555` | `atomic_replace` | SILENT-SKIP mode | P2 |
| 19 | `src/config/migrate.rs:1269` | `atomic_replace_bytes` | SILENT-SKIP mode | P2 |
| 20 | `src/config/schema.rs:625` | `read_owner_only_secret` | SILENT-SKIP mode | P2 |
| 21 | `src/config/lint.rs:1090` | `artifact_mode_finding` | SILENT-SKIP | P2 |
| 22 | `src/logging.rs:296` | `create_private_dir` | SILENT-SKIP mode | P2 |
| 23 | `src/logging.rs:317` | `open_private_append` | SILENT-SKIP mode | P2 |
| 24 | `src/main.rs:8730` | `append_kt_payload` | SILENT-SKIP mode | P2 |
| 25 | `src/browser/process.rs:1132` | `create_private_dir` | SILENT-SKIP mode | P2 |
| 26 | `src/vault/identity_keys.rs:760` | `open_sealed_file` | ALLOW (weakened) | **P2** |
| 27 | `src/vault/import_export.rs:913` | `write_export_file` | SILENT-SKIP mode | P2 |
| 28 | `src/config/lint.rs:1116` | `secret_dir_finding` | DEFAULT `0o700` | **P2** |
| 29 | `src/config/lint.rs:1225` | `artifact_dir_finding` | DEFAULT `0o700` | **P2** |
| 30 | `crates/tallow-copy-engine/src/lib.rs:1437` | `is_special` | DEFAULT `false` | P3 |
| 31 | `src/stdlib/filter.rs:174` | `detect_attributes` | DEFAULT `false` | P3 |
| 32 | `src/browser/dpi_bypass.rs:239` | `execute_strategy` | SILENT-SKIP (logged) | P3 |
| 33 | `src/raw_store.rs:68` | `freeze` | EMPTY | P3 |
| 34 | `src/replication.rs:83` | `freeze` | EMPTY | P3 |
| 35 | `src/mesh/journal.rs:190` | `sync_dir` | `Ok(())` no-op | P3 |
| 36 | `src/lib.rs:172` | — | N/A (module swap) | — |
| 37 | `src/browser/process.rs:361` | `launch` | N/A (type placeholder) | — |
| 38 | `src/browser/cdp.rs:1549` | `test_…_non_unix` | N/A (test) | — |
| 39 | `src/config/lint.rs:1328` | `make_secret_file` | N/A (test helper) | — |

Five `cfg(not(unix))` sites and one whole-file refusing module (5 functions)
refuse; twenty-nine sites silently allow, return a default, or are an empty
body; four are not stubs. **No stub on the egress path.** Details follow.

---

## §4 THE REFUSALS (verified: they return `Err`, and the caller propagates)

### 4.1 `sandbox_runtime_nonunix.rs` — 5/5 refuse

The whole module is the non-Unix implementation; `src/lib.rs:169-174` selects it:

```
169| // The real runtime installs seccomp/Landlock from a `pre_exec` hook. Neither
170| // exists on Windows, so that build gets the same five entry points refusing.
171| #[cfg(unix)]
172| pub mod sandbox_runtime;
173| #[cfg(not(unix))]
174| #[path = "sandbox_runtime_nonunix.rs"]
175| pub mod sandbox_runtime;
```

```
$ grep -n 'pub fn\|Err(format' src/sandbox_runtime_nonunix.rs
18:pub fn install_seccomp(_allowed: &[&str], _deny_default: bool) -> Result<(), String> {
19:    Err(format!("install_seccomp: {WHY}"))
23:pub fn install_landlock(_read_paths: &[PathBuf]) -> Result<(), String> {
24:    Err(format!("install_landlock: {WHY}"))
28:pub fn install_landlock_rw(
32:    Err(format!("install_landlock_rw: {WHY}"))
37:pub fn run_sandboxed(_cmd: &mut Command, _read_paths: &[PathBuf]) -> Result<(), String> {
38:    Err(format!("run_sandboxed: {WHY}"))
42:pub fn run_sandboxed_rw(
47:    Err(format!("run_sandboxed_rw: {WHY}"))
```

`WHY` (`:14-15`) is "sandboxing (seccomp-BPF + Landlock) is a Linux kernel
feature; this build targets a platform without it". Verdict **REFUSE, 5/5**. No
`Ok` path exists in the file.

Caller check — the one production caller is compiled only on Linux, so on Windows
there is not even an `Err` to swallow:

```
§C2 $ grep -n -B4 'run_sandboxed(&mut cmd' src/browser/process.rs
633-        // for unusual installs.
634-        #[cfg(target_os = "linux")]
635-        if !browser_landlock_disabled() {
636-            let read_paths = browser_landlock_read_paths(config, &profile_arg);
637:            let _ = crate::sandbox_runtime::run_sandboxed(&mut cmd, &read_paths);
```

The `let _ =` is deliberate and documented at `:626-633`: this Landlock fence is
*additive* browser hardening, not the egress gate (the gate is the zone proxy +
scope register). Because the call is `cfg(target_os = "linux")`, macOS and
Windows never reach it. **Not an ungated path.**

### 4.2 `src/browser/juggler.rs:223` — the Juggler pipe launch

```
223|     #[cfg(not(unix))]
224|     pub fn launch(
225|         config: &BrowserConfig,
226|     ) -> Result<(Child, Self, Option<std::path::PathBuf>), BrowserError> {
227|         let _ = config;
228|         Err(BrowserError::ConnectionFailed(
229|             "the Firefox/Camoufox Juggler transport passes its protocol pipes as \
230|              file descriptors 3 and 4, which requires a Unix-like OS; use the \
231|              Chromium/CDP backend on this platform"
232|                 .to_string(),
233|         ))
234|     }
```

Verdict **REFUSE**. Propagated at the only caller, `src/browser/process.rs:386`
(`let (mut child, juggler, profile_dir) = JugglerClient::launch(config)?;`) — the
`?` returns before any browser is spawned, so no unproxied Firefox can start on
Windows via this path.

### 4.3 `src/browser/process.rs:338` — CDP pipe, rejected before spawn

```
334|         // Pipe transport (Chromium `--remote-debugging-pipe`) is unix-only: it
335|         // needs the child's fds 3/4 wired to real pipes ...
337|         // BEFORE spawning so pipe mode never launches a browser it cannot drive.
338|         #[cfg(not(unix))]
339|         if config.use_pipe {
340|             return Err(BrowserError::ConnectionFailed(
341|                 "--remote-debugging-pipe transport requires unix fd 3/4 wiring \
342|                  and is not supported on this platform; use WebSocket CDP \
343|                  (use_pipe=false)"
```

Verdict **REFUSE**, and it is ordered **before** `cmd.spawn()` (`:641`), so there
is no window in which a pipe-mode browser runs unmanaged.

A test asserts this on the Windows CI plane (`src/browser/cdp.rs:1549-1564`,
`test_connect_pipe_fails_closed_on_non_unix`, `assert!(result.is_err())` and
`err.contains("not supported")`) — **REFUSE, with a test**.

`src/browser/process.rs:361-362` (`let _pipe_io: Option<()> = None;`) is a *type
placeholder* that keeps the later `#[cfg(unix)]` block from referencing an
undefined binding; it holds no security decision. **N/A.**

### 4.4 `src/stdlib/process.rs:85` — no liveness probe

```
85|     #[cfg(not(unix))]
86|     {
87|         Err("Process.is_running: handle is not tracked and this platform has no probe".into())
88|     }
```

Verdict **REFUSE**. It refuses rather than returning the tempting `false`
("assume dead"), which is the right direction: a false "not running" would let a
caller re-spawn over a live process.

### 4.5 `crates/tallow-copy-engine/src/lib.rs:1636` — symlink preserve

```
1636| #[cfg(not(unix))]
1637| fn create_symlink(_target: &Path, link: &Path) -> Result<(), CopyError> {
1638|     Err(unsupported(
1639|         Some(link.to_path_buf()),
1640|         "LinkPolicy::Preserve is not supported on this platform; select LinkPolicy::Follow or Skip",
1641|     ))
```

Verdict **REFUSE**, and it names the remediation in the error. Good pattern.

### 4.6 `crates/tallow-daemon/src/executor.rs:478` — refusal arrives via preflight

The `cfg(not(unix))` line itself is a dead placeholder:

```
478|             #[cfg(not(unix))]
479|             let _ = &write_roots;
480|             tracing::info!(
481|                 "executor: script job '{script_name}' confined by landlock write-jail \
482|                  (roots: {logged_roots:?})"
483|             );
```

Read alone this looks bad: on a non-unix build it would log "confined" while
installing nothing. It is unreachable because the preflight 20 lines above
refuses first:

```
$ sed -n '86,92p' crates/tallow-daemon/src/executor.rs
    #[cfg(not(target_os = "linux"))]
    {
        Err(format!(
            "landlock is Linux-only; refusing to run unconfined — set \
             {SCRIPT_SANDBOX_ENV}=off to opt out explicitly"
        ))
    }
```

`run_tallow_script:456-458` does `landlock_write_jail_supported().map_err(...)?`
before reaching `:478`. Verdict **REFUSE (via preflight)** — but this is the one
site where the *dead* code and the *live* log are both wrong-looking; see F5 in
§5 for the hardening note.

---

## §5 FINDINGS — the stubs that return Ok, a default, or an empty success

### F1 (P1) — `lock_memory` returns `Ok(())` while not locking: a secrecy claim with no mechanism

`crates/tallow-crypto/src/mem/wipe.rs:96-103` (fn at `:72`):

```
 96|     #[cfg(not(unix))]
 97|     {
 98|         // Windows VirtualLock and other platforms: deferred
 99|         let _ = (ptr, len);
100|     }
101|
102|     Ok(())
103| }
```

The unix arm calls `mlock` (and `:129` `munlock`) — on non-unix the body is a
no-op and the function still returns `Ok(())`. This is the exact class my mandate
calls fatal: the caller is told the key page is non-swappable when the OS has made
no such promise, and if the result is `?`-propagated it *certifies* it. Anything
downstream that reasons "key material is locked because `lock_memory` succeeded"
is reasoning from a document, not a mechanism.

`unlock_memory` (`:129-135`) has the same shape but is benign in the safe
direction (a no-op unlock leaves the pages as they were), so it is P2.

Remediation: return `Err("mlock: not implemented on this platform")` from the
non-unix arm, **or** rename to `lock_memory_best_effort() -> bool` so the absence
is in the type. Do not leave a `Ok(())` that means "deferred".

### F2 (P1) — `probe_daemon_state_files` reports PASS without measuring

`src/main.rs:20149-20173` and the decision at `:20185`:

```
20154|         #[cfg(unix)]
20155|         {
20156|             use std::os::unix::fs::PermissionsExt;
20157|             let mode = md.permissions().mode() & 0o777;
20158|             match (classify_daemon_state(name), perms_owner_only(mode)) {
...                     (pushes into `checked` / `offenders` / `advisories`)
20169|         }
20170|         #[cfg(not(unix))]
20171|         {
20172|             let _ = md;
20173|         }
20185|     if checked.is_empty() && advisories.is_empty() {
20186|         return probe_result(
20187|             LABEL,
20188|             ProbeStatus::Pass,
20189|             format!(
20190|                 "advisory: no daemon state under {} (daemon not provisioned)",
```

On non-unix the loop `continue`s past every existing file without pushing
anything, so `checked` and `advisories` are both empty and the probe returns
**`ProbeStatus::Pass` with the message "no daemon state … (daemon not
provisioned)"** — even when `token`, `device_id` and `daemon.db` are all present
and world-readable. The label claims "secret-bearing owner-only"; the non-unix
build certifies that claim having read zero permissions. This is a false PASS in a
compliance surface (`tallow doctor`), which is worse than a FAIL: it removes the
operator's reason to look.

Remediation: return `ProbeStatus::Skip` (or `Advisory`) with
"permission model not applicable on this platform" when the mode could not be
read. A probe that cannot measure must not answer Pass.

### F3 (P2) — twelve sites silently drop owner-only mode; three names are lies

The unix arm sets `0600`/`0700`; the non-unix arm creates the object with the
process default and returns success. The object is labelled owner-only by its
function name, not by its filesystem state:

* `src/config/write.rs:501` `create_dir_owner_only` → `fs::create_dir(dir)`
* `src/config/write.rs:464` `ensure_dir_secure` → `fs::create_dir_all(dir)`
* `src/config/write.rs:491` `tighten_dir` → `let _ = dir;` (no-op)
* `src/config/write.rs:555` `atomic_replace` → `let _ = (perms, secret_bearing);`
* `src/config/migrate.rs:1269` → `fs::create_dir_all(parent)`
* `src/config/schema.rs:625` `read_owner_only_secret` → only `is_file()`
* `src/cli/secrets_cmd.rs:286-288` `restrict_to_owner` → `let _ = path; Ok(())`
* `src/logging.rs:296` `create_private_dir` → `fs::create_dir_all(dir)`
* `src/logging.rs:317` `open_private_append` → plain `OpenOptions` (no `.mode(0o600)`)
* `src/main.rs:8730` `append_kt_payload` → plain `OpenOptions` (no `0o600`)
* `src/browser/process.rs:1132` `create_private_dir` → `fs::create_dir(path)`
* `crates/tallow-daemon/src/{config.rs:146, db.rs:56, main.rs:52, sessions.rs:311}`

`src/cli/secrets_cmd.rs:279-289` is the clearest example — the function's whole
job is the chmod, and on Windows it is `Ok(())`:

```
285|     #[cfg(not(unix))]
286|     let _ = path;
287|     Ok(())
288| }
```

Severity P2 rather than P1 because these are *filesystem* confidentiality, not
egress: no stub here lets a request leave. But per the "who can obtain the grant /
what it can reach / what record it leaves" test, the *record* half fails — a log
sink or a config-history directory that is group-writable on Windows, opened by a
function named `open_private_append`, is an audit-integrity hole. On Windows the
correct mechanism is an ACL, not a mode; the honest non-unix arm today is a
refusal or an explicit "not enforced" in a return value the caller must handle.
At minimum the names must stop asserting a property the arm does not provide.

### F4 (P2) — two lint checks can never fire on Windows (default `0o700`)

`src/config/lint.rs:1116-1119` and `:1225-1228`:

```
1116|         #[cfg(not(unix))]
1117|         {
1118|             0o700
1119|         }
...
1121|     if mode & 0o022 != 0 {          // 0o700 & 0o022 == 0, always
```

The non-unix arm returns a constant `0o700`, and the finding fires only when
`mode & 0o022 != 0`. So `W7203` (`secret_dir_finding`) and the artifact-directory
check return `None` on every Windows path, by construction — the "directory is
writable by group/other, another local account can replace the target" warning is
unreachable there. Same default-value failure mode as F2 in the lint plane: the
check reports clean because it never looked.

`src/config/lint.rs:1090` (`artifact_mode_finding`) is the sibling that skips
outright (`let _ = path;` then `None`).

Remediation: return an `Option` "unmeasurable" and let the caller render an
advisory, rather than a value that satisfies the predicate.

### F5 (P3, hardening) — `executor.rs` dead branch + unconditional "confined" log

`crates/tallow-daemon/src/executor.rs:478-483` logs "confined by landlock
write-jail" on every platform that reaches it. Today it is unreachable on
non-Linux because of the `:86-92` preflight, so it is safe — but the safety is an
invariant held by a *different* function, and the log line is unconditional. If
the preflight is ever relaxed, this becomes a false security log on Windows. Worth
moving the `tracing::info!` inside `#[cfg(target_os = "linux")]`.

### F6 (P3) — evidence artifacts are not made read-only

`src/raw_store.rs:68-72` and `src/replication.rs:83-87`, both `fn freeze`:

```
68|     #[cfg(not(unix))]
69|     {
70|         let _ = path;
71|     }
```

The unix arm `chmod 0444`s a frozen payload; non-unix is a no-op, so the raw-store
and replication-manifest artifacts are mutable on Windows while the API says
`freeze`. Integrity, not egress. Note the unix arm is already best-effort
(`let _ =`), so the guarantee is weak on both planes.

### F7 (P3) — `is_special` returns `false`, so special files are copied as regular ones

`crates/tallow-copy-engine/src/lib.rs:1430-1442`:

```
1437|     #[cfg(not(unix))]
1438|     {
1439|         let _ = ft;
1440|         false
1441|     }
```

On Windows a FIFO/socket/device-like source is therefore classified "not special"
and handed to the normal copy path. Low practical impact (Win32 has no FIFOs in
this sense) but it is a default-value answer where the unix arm answers with a
positive test.

### F8 (P3) — smaller silent allows

* `src/browser/dpi_bypass.rs:239-245` — `MSG_OOB` is skipped with an `eprintln!`
  and `execute_strategy` returns `Ok(())`. Correct-by-design (documented, logged),
  but the return value cannot distinguish "applied" from "skipped", so a caller
  cannot tell a fully-applied strategy from a partly-skipped one.
* `src/stdlib/filter.rs:174-175` — `detect_attributes` returns `is_readonly =
  false` on non-unix.
* `src/mesh/journal.rs:190-193` — `sync_dir` returns `Ok(())` without fsyncing the
  directory (durability only; the non-unix comment at `:184` explains `rename` is
  already atomic there).
* `src/vault/identity_keys.rs:760-769` — `open_sealed_file` on non-unix opens
  without `O_NOFOLLOW` and without `0600`. Not a silent allow on the *symlink*
  question (explicit `symlink_metadata` refusals survive at `:633-647` and
  `:693-698`), but the mode is never tightened (`set_mode` exists only under
  `#[cfg(unix)]` at `:772`, and all four call sites are inside `#[cfg(unix)]`
  blocks), so the sealed identity key file is not owner-only on Windows. The
  pre-check is also a TOCTOU window that `O_NOFOLLOW` closes on unix.

---

## §6 THE INVERSE ASYMMETRY (worth more than any single stub)

`src/sandbox_runtime.rs:91-108` (the **unix** implementation) returns `Ok(())`
even when Landlock is absent:

```
100|         cmd.pre_exec(move || {
101|             // Landlock is best-effort: a kernel without it (pre-5.13) still
102|             // runs the child unconfined rather than failing the exec.
103|             let _ = install_landlock(&read_paths);
104|             Ok(())
105|         });
106|     }
107|     Ok(())
```

So the Windows stub refuses more strictly than the Linux implementation enforces.
That is defensible *because* `run_sandboxed` is additive hardening (the only
caller, `browser/process.rs:637`, discards the result and the gate is elsewhere) —
but it means `run_sandboxed() == Ok(())` is not evidence of confinement on **any**
platform. `run_sandboxed_rw` is the fail-closed sibling (`NotEnforced` →
`Err` at `:165-166`), which is the right shape. Do not let a future caller read
`run_sandboxed`'s `Ok` as a grant.

---

## §7 WHAT I DID **NOT** VERIFY

Labelled honestly, per the output contract:

1. **No Windows binary was built or run.** Every non-unix verdict is
   `[read, not executed]`: it follows from the source under that cfg arm, not from
   an observation. The brief forbids cargo in this lane and this host is Linux
   (a Windows target would need the CI `test-windows` plane).
2. **`cargo check --target x86_64-pc-windows-msvc` was not run**, so I have not
   independently confirmed the non-unix arms *compile* (e.g. that `set_mode` and
   `install_landlock_write_jail` are genuinely absent-not-orphaned on Windows). I
   read the `#[cfg]` placement at each call site and it is consistent, but the
   compile plane is the authority.
3. **No `test result:` line is quoted anywhere** in this report, because no test
   was run. The two test-based claims (§4.3 cdp test, §1 `effect_rows`) are claims
   about *test source that exists and is not platform-gated*, not about a pass.
4. **Policy intent is inferred from names and comments.** Where I say
   `create_dir_owner_only` "lies", I am reading its name against its non-unix
   body; there may be a Windows ACL story elsewhere in the tree that I did not
   find, in which case F3 downgrades to a naming issue. I searched for
   `cfg(windows)` implementations and found only real implementations
   (`src/browser/network_stealth.rs:91` sets TTL on the socket handle;
   `src/pkg/cache.rs:610` uses a symlink or `mklink /J` and errors on failure) —
   no Windows ACL hardening for the paths in F3.

---

## §8 REPRO

Read-only, no cargo. Reproduces every number in this report:

```sh
cd /home/aamir/tallow-worktrees/w13/lattice

# the inventory
grep -rn 'cfg(not(unix))' --include=*.rs src crates | wc -l        # 38
python3 ~/.hermes/profiles/lattice/cache/scratch/scan_stubs.py     # full bodies

# the gate holds
grep -n 'cfg(unix)\|cfg(windows)\|cfg(not(unix))\|cfg(target_os' \
  src/net/egress.rs src/scope.rs src/runtime/egress_http.rs \
  src/runtime/dns_guard.rs src/gate/capability_registry.rs          # (none)
comm -12 <(grep -rl 'scope::require' --include=*.rs src | sort) \
         <(grep -rl 'cfg(not(unix))' --include=*.rs src | sort)     # dpi_bypass.rs, main.rs

# the refusing stubs
grep -n 'pub fn\|Err(format' src/sandbox_runtime_nonunix.rs         # 5/5 Err
sed -n '223,234p' src/browser/juggler.rs                            # Err
sed -n '338,346p' src/browser/process.rs                            # Err, pre-spawn
sed -n '85,88p'   src/stdlib/process.rs                             # Err
sed -n '1636,1642p' crates/tallow-copy-engine/src/lib.rs            # Err

# the P1s
sed -n '96,103p'  crates/tallow-crypto/src/mem/wipe.rs              # Ok(()) without locking
sed -n '20149,20195p' src/main.rs                                   # probe false PASS
```

---

**Bottom line for the tag.** The P0 property holds: a unix-only call cannot become
an ungated egress path on Windows, because the gate has no platform conditionals
and every unix-only *network* entry point returns `Err` before it can do work.
The defects are one plane down: two P1s where an API returns success for a
property it does not provide (`lock_memory`, the daemon-state probe), and a broad
P2 class where `0600`/`0700` is dropped silently under function names that assert
it. None of them is a gate bypass; all of them are the "safety property that lives
in a document" pattern the lane exists to kill.
