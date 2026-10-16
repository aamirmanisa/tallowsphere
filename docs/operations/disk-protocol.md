# Disk Protocol

> status: active 2026-09-16 (F-1 remediation: headroom guard + this protocol).
> Guard source: `scripts/disk_guard.sh` -> installed `/usr/local/sbin/disk-guard.sh`,
> units `disk-guard.service` + `disk-guard.timer` (15 min), alert template
> `disk-guard-alert@.service`. Evidence: `artifacts/to-100-2026-09-16/R5-report.md`.
> Watchdog source: `scripts/hermes_disk_cleanup.sh` -> installed
> `/usr/local/sbin/hermes-disk-cleanup.sh` (timer 30 min). 2026-09-25: extended
> with always-on dead-browser-profile GC (+ stage2-wire incremental) after the
> snap-Chromium profile leak; evidence `artifacts/disk-reclaim-2026-09-25/`.
> 2026-09-28: SAFE item 6 added — Nixe `target/debug/{deps,build}` prune (operator-approved;
> preserves the NEVER-listed root binaries). Evidence `artifacts/disk-alert-2026-09-27/ANALYSIS.md` ROUND 5.
> 2026-09-29: `TallowDiskFillPredicted` headroom-gated to fire only below 40 GiB free (operator
> order — the level-blind slope had paged hourly through healthy-zone build churn, 49–68 GiB free).
> Disk-guard thresholds (85/92%) unchanged. Evidence `artifacts/disk-alert-gate-2026-09-29/RECEIPT.md`.

## Why this exists

- `/` (150G) filled to 100% **twice in 72h** (2026-09-13 evening; 2026-09-15
  01:34-01:38). Impact: ~19.7k journal no-space errors, the Hermes gateway
  failed writes (`OSError: [Errno 28] No space left on device`,
  `failed to write`), and rotated logs were left 0-byte (`auth.log.1`, `btmp.1`).
- The old watchdog (`/usr/local/sbin/hermes-disk-cleanup.sh`) reclaims silently
  and reclaimed only kB-scale trivia while usage climbed 96% -> 100%.
- Fix (this doc + guard): **alert-only** headroom guard at warn >= 85% /
  critical >= 92% on `/`, plus a written protocol for what may and may not be
  reclaimed.
- 2026-09-25: `TallowDiskFillPredicted` (fill-within-4-days) fired with `/` at
  71%. The recurring drain driver was a *snap-Chromium profile leak* — 11.9G of
  dead headless-browser profile dirs that nothing ever cleaned (see "Dead
  browser profiles"), on top of ordinary regenerable churn. 17G reclaimed;
  the leak class now has automated GC so it should not re-fire from this.

## The rule

**Agents report; humans reclaim. Never delete anything to free space.**

- An agent that sees low headroom: measure (`df -h /`, `du -sh <dir>`), alert,
  and report the top consumers. It never runs `rm` / `cargo clean` / `truncate`
  to "help".
- Reclaim is an explicit operator decision, from the SAFE list below only,
  never while a heavy build/collector is running, and never touching the
  NEVER list.
- The only sanctioned automatic reclaimer on this box is
  `hermes-disk-cleanup.sh` (timer, 30 min; log `/var/log/hermes-disk-cleanup.log`)
  and its reach is intentionally limited to regenerable scratch (cargo
  `target/debug/incremental` for Nixe and stage2-wire, old `/tmp` scratch, old
  `/var/tmp/tallow-*`, oversized btmp) plus an always-on, age-gated GC of dead
  browser-profile dirs (see "Dead browser profiles" — operator-approved
  2026-09-25; it runs even below the threshold because it is garbage collection
  of a known leak, not space-pressure deletion). Do not extend its reach
  further without an operator sign-off; if it needs a change, report it.

## Headroom guard

- Thresholds: warn >= 85%, critical >= 92% of `/` (`df -P --output=pcent /`).
  Env knobs `DISK_GUARD_WARN_PCT` / `DISK_GUARD_CRIT_PCT` exist; changing the
  live thresholds means editing the unit (box-local, `/etc/systemd/system/`).
- Alert contents: level, current %, free/size, and a read-only top-consumers
  section (`~/*/target`, `/var/tmp`, `/tmp` — depth-0 `du`, 15s
  timeout each, max 12 lines).
- Alert path (relay-ops pattern, same as `tallow-relay-alert@.service`):
  on threshold the script emits the full alert via
  `systemd-cat -t disk-guard-alert -p <prio>` + `wall`, exits 1 (warn) / 2
  (critical), and systemd's `OnFailure=disk-guard-alert@%n.service` broadcasts
  the short backstop alert.
- Where to look: `journalctl -t disk-guard-alert`,
  `journalctl -u disk-guard.service`, `/var/log/disk-guard.log` (size-capped in
  script + rotated by `/etc/logrotate.d/disk-guard`), `systemctl list-timers disk-guard.timer`.
- Dry-run proof (never fills the disk):
  `DISK_GUARD_FORCE_PCT=93 /usr/local/sbin/disk-guard.sh; echo rc=$?` -> `rc=2` + alert.
  `DISK_GUARD_FORCE_PCT=86 ...` -> `rc=1` + alert. No env -> real reading (`rc=0` below 85%).
- Reinstall after editing the source copy:
  `install -o root -g root -m 0755 ~/Nixe/scripts/disk_guard.sh /usr/local/sbin/disk-guard.sh && systemctl daemon-reload`

## SAFE to prune (operator decision only; estimate first)

Preconditions for any item below: headroom is actually low (`df -h /`), no
build is running (`pgrep -a -f 'cargo|rustc'` should be empty for the affected
repo), the item is not on the NEVER list, and the operator approves.

1. **Cargo incremental caches** (pure rebuild cache; costs build time only):
   - Inspect: `du -sh ~/*/target/debug/incremental 2>/dev/null`
   - Prune (exact, per repo): `rm -rf ~/stage2-wire/target/debug/incremental`
   - This is also what `hermes-disk-cleanup.sh` reclaims automatically; prefer
     letting the watchdog do it during a crunch.
2. **Stale whole target dirs of non-core projects** (full rebuild on next build):
   - Inspect first: `cargo clean --manifest-path ~/stage2-wire/Cargo.toml -n`
     (`-n` = dry-run, supported by cargo 1.98+; prints what would be deleted)
   - Execute only after review: `cargo clean --manifest-path ~/stage2-wire/Cargo.toml`
   - **NEVER** point this at `~/Nixe` (preserved binaries; see NEVER list).
3. **Non-durable `/var/tmp` leftovers** (bench scratch): `tallow-*` dirs older
   than ~3 days that nothing is using.
   - Inspect: `du -sh /var/tmp/tallow-* 2>/dev/null` and
     `ls -l /proc/*/cwd 2>/dev/null | grep -F '/var/tmp/tallow-<name>'` (must be empty)
   - Preferred reclaim: leave it to `hermes-disk-cleanup.sh` (grace > 3 days).
     Manual exact form after the checks: `rm -rf /var/tmp/tallow-<exact-name>`
4. **Old `/tmp` scratch trees** (session artifacts, `*.log` dumps; not system dirs):
   - Inspect: `du -sh /tmp/* 2>/dev/null | sort -rh | head -20`, then the same
     `/proc/*/cwd` in-use check.
   - Keep skip-list: `.X11-unix`, `.XIM-unix`, `.ICE-unix`, `.font-unix`,
     `.Test-unix`, `snap-private-tmp`, `systemd-private-*`, and anything younger
     than ~2 days. Preferred reclaim: `hermes-disk-cleanup.sh`.
   - Exception inside `snap-private-tmp`: dead *browser-profile* dirs
     (`puppeteer_dev_chrome_profile-*`, `playwright_*profile-*`) are GC'd by the
     watchdog — see item 5. That is the only sanctioned touch in there.
5. **Dead browser profiles (snap-Chromium leak)** — automated; manual fallback:
   - Inspect: `du -sh /tmp/snap-private-tmp/snap.*/tmp` (healthy: < ~1G) and
     `ls -d /tmp/snap-private-tmp/snap.*/tmp/puppeteer_dev_chrome_profile-* 2>/dev/null | wc -l`
   - The watchdog GCs dirs older than `PROFILE_GRACE_HOURS` (default 2) whose
     browser process is gone (`pgrep -f "user-data-dir=.*<name>"`, comm
     `*chrome*`). Manual form (run the same two checks first): `rm -rf <exact dirs>`.
   - Never remove a dir still referenced by a live chrome process. The real
     `/tmp/puppeteer_dev_chrome_profile-*` shells are harmless (KBs) and are
     covered by the same GC.

6. **Nixe `target/debug/{deps,build}` prune** (operator-approved 2026-09-28; the only sanctioned
   touch inside `~/Nixe/target`):
   - Class: pure rebuild cache (≈48G `deps` + 1.4G `build` when cold). It is **not** a `cargo
     clean`: the NEVER-listed artifacts (binaries, `*.d`, `libtallow*.{a,rlib}` at the
     `target/debug/` ROOT) are preserved — root binaries are hardlinks (link count 2), so removing
     `deps/` leaves them byte-intact. Never use `cargo clean` for this.
   - Preconditions: no `cargo|rustc` running; no `/proc/*/exe` or `/proc/*/cwd` refs into
     `Nixe/target/debug`; snapshot the root artifact hashes first:
     `find target/debug -maxdepth 1 -type f \( -perm -u+x -o -name '*.d' -o -name '*.a' -o -name '*.rlib' \) -exec sha256sum {} + | sort > before`.
   - Prune (exact): `rm -rf ~/Nixe/target/debug/deps ~/Nixe/target/debug/build`
   - Verify: re-hash → diff vs before must be **identical**; run `target/debug/tallow --version`
     (must print `tallow 1.0.0`, rc=0). Cost: next debug build recompiles the workspace from
     scratch (long); release side untouched.

Other levers that are NOT deletions (use before pruning): cap concurrent heavy
jobs (`CARGO_BUILD_JOBS`, `scripts/ram_guard.sh`), move large generated data to
its owning repo's `artifacts/` instead of `/tmp`//`/var/tmp`, and let journald
stay capped (300M, `journald.conf.d/retention.conf`) — do not hack log configs
to free space.

## NEVER prune (preserve list — regardless of size or pressure)

- `/tmp/tallow-legs/` — leg datasets (deliverable data for R-01). Never touched
  by cleanup scripts, never by agents.
- `~/Nixe/target/debug/` binaries (`tallow`, `tallow-daemon`,
  `tallow-lsp`, `*.d` — preserved artifacts needed to run/verify released
  builds). Consequently: **no `cargo clean` at the Nixe root**, ever — the
  narrower `target/debug/{deps,build}` prune is the sanctioned exception
  (SAFE item 6, operator-approved 2026-09-28; it preserves these artifacts by
  design).
- Repo content: `~/Nixe/**` sources, docs, and evidence
  (including `artifacts/to-100-2026-09-16/**`).
- Active worktrees / in-flight lanes' working trees (e.g. `.scratch/<feature>/`
  work); `git worktree list` currently shows the main `v1` checkout — treat it
  as live.
- `~/Nixe/Tallow` and `~/Tallow` (dirty copies), and
  `/opt/sendtallow` + relay production config.
- Hermes runtime state (`~/.hermes` session/gateway data) — the exact thing
  that broke with ENOSPC; it is small but critical.

## Dead browser profiles (snap-Chromium leak)

Headless Chromium runs from the snap, which remaps the browser's `/tmp` to
`/tmp/snap-private-tmp/snap.chromium/tmp`. Puppeteer/playwright create a
per-launch profile dir under `/tmp` — an empty shell in the real `/tmp` plus the
populated copy under the snap remap (same name, different inode) — and at close
the launcher deletes only the real-`/tmp` shell, so the populated copy leaks
forever (~120M per launch; ~2G/day under browser-heavy waves; 11.9G / 233 dirs
had accumulated by 2026-09-25).

- Detect: `du -sh /tmp/snap-private-tmp/snap.chromium/tmp` — healthy: < ~1G.
- Contain: the watchdog's always-on GC (SAFE item 5).
- Avoidance note: pinning `TMPDIR` for browser runs to a non-`/tmp` path keeps
  the profile out of the snap remap, but runners pin `TMPDIR=/tmp` for Chromium
  stability, so the GC is the maintained fix.

## Escalation ladder

- **>= 85% (warn)**: nothing is broken. Journal/wall warning fires. Reclaim
  from the SAFE list or shed load until < 80%.
- **>= 92% (critical)**: unit is in failed state; act before the next heavy
  build/collector window. Pause heavy lanes, reclaim SAFE items, re-check the
  same hour.
- **100% / Errno 28 (incident)**: capture `df -h /` + the journal window,
  report, then reclaim SAFE items; record the window in the ops trail
  (same shape as `artifacts/nixe-v1-readiness-audit-2026-09-15/` F-1).

## References

- Guard: `/usr/local/sbin/disk-guard.sh` (source `scripts/disk_guard.sh`),
  units `disk-guard.service` / `disk-guard.timer` / `disk-guard-alert@.service`,
  logrotate `/etc/logrotate.d/disk-guard`.
- Watchdog: `/usr/local/sbin/hermes-disk-cleanup.sh` (source
  `scripts/hermes_disk_cleanup.sh`; timer 30 min; `PROFILE_GRACE_HOURS` knob
  for the browser-profile GC).
- Incident evidence: `artifacts/nixe-v1-readiness-audit-2026-09-15/` F-1;
  verification `artifacts/to-100-2026-09-16/R5-report.md`.
