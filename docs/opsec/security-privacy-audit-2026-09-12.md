# Security & Privacy Audit — Consolidated Report

**Box:** `example-host` (Tallow/Nixe box, Hetzner) · **Date:** 2026-09-12 · **Pass window:** 22:03–22:16 UTC
**Mode:** read-only inspection + probe verification; one applied change (§3). Writer: Hermes.
**Companion docs:** [`stealth-scanning-statement-of-intent.md`](./stealth-scanning-statement-of-intent.md) (doctrine/runbook) · [`stealth-hardening-checklist.md`](./stealth-hardening-checklist.md) (execution checklist — C1–C8, H1–H7 landed earlier today) · `research/tallow-security-2026-09-12/` (code/architecture security research program)

**Operating guardrails (unchanged):** read-only, public-data-only collection · robots.txt + `crawl-delay` honored · stop-on-block, **no escalation** · network-level scanning only inside an owner-authorized scope · **no "undetected" claims** — probe-verified statements only ("maximized stealth, leaks closed").

---

## 1 · Executive summary

- **Re-verified fresh:** egress contract **14/14 PASS** · firewall default-deny (v4+v6) · SSH key-only · fail2ban + auditd active · 0 pending security updates · retention + watchdogs live · `postboot-verify: OK`.
- **Applied (only change this pass):** Caddy security headers on `myvapeisland.com` (§3).
- **One state explained & closed:** `tor@default` `enabled-runtime` is the **normal Debian `tor-generator` behavior** — the bring-up edge is regenerated at every boot; verified live. No action (see §5 "don't re-chase").
- **Open items:** SSH MFA (options §5/P1), 2 held apt packages (libgeos / leftover `pgdg` repo), offsite-backup confirmation, CSP evaluation, `tallow-rmdb-update` cadence.

**Requirement coverage:** infra audit → §2 · privacy hardening → §2.4 + §3 · security reinforcement → §2.1–2.3, §5 · stealth/footprint → §2.4–2.5 (claims limited to probes; doctrine governs collection identity) · scraping components → §4 · reporting → this doc.

---

## 2 · Posture by area (fresh evidence, 2026-09-12)

### 2.1 Host & firewall — OK
- nft ruleset: `ip`/`ip6` **INPUT + FORWARD policy drop**; allows loopback, established, TCP **22,80,443**, ICMP; drop logging 5/min.
- Docker paths handled (chains + raw-prefilter drops: imgproxy 8081 loopback-only; docker-port anti-bypass).
- `fail2ban` nft table present; sshd jail active (currently banned: `195.238.176.70`). `ufw` inactive — **by design**, `host-firewall.service` owns the ruleset (§5).
- `auditd` active; 7 opsec watches (`/etc/tor/`, `/etc/ssh/sshd_config*`, `/etc/sysctl.d/`, `host-firewall.sh`, `privacy-retention.sh`, systemd units); audit log caps 50M×4.

### 2.2 Access & accounts — OK (MFA open)
- SSH effective: `PasswordAuthentication no`, `PermitRootLogin without-password`, `KbdInteractiveAuthentication no`, `X11Forwarding no`, `MaxAuthTries 6`; drop-ins `50-cloud-init.conf`, `99-opsec.conf`.
- 1 keypair registered twice (duplicate lines, same fingerprint `SHA256:ykX/OK7sOip1l6a3NEXGVBFWZwbdEbErMZtsbMPKTtA`, comment `hackthecart-deploy` — dedupe candidate); `sudo` group empty; no regular login accounts on the box; console = Hetzner break-glass.
- Brute-force noise: ~4 060 auth-attempt lines / 7 days (internet noise; handled by key-only + fail2ban). **No second factor on SSH — the one real access gap (§5/P1).**

### 2.3 Patch state — OK-ish
- `unattended-upgrades` active · **0** security-pending · `dist-upgrade` holds **2** (`libgeos3.14.1`, `libgeos-c1t64` from leftover `noble-pgdg` repo) · no reboot required · snap `core22/core24` refresh pending (cosmetic).

### 2.4 Privacy / egress — OK (probe-verified)
- Tor **0.4.9.11**; `tor@default` → SOCKS5 `127.0.0.1:9050` (unpinned) + `tor-us` → `9051` (US-pinned) both active; hardened torrc + systemd sandbox drop-ins; bring-up edge generated at boot by `tor-generator` (verified: `/run/systemd/generator/tor.service.wants/tor@default.service`).
- Acceptance battery `tests/egress/check_egress.sh`: **passed=14 failed=0 skipped=0** — compiled & interpreted `fetch()`, stdlib `http.*`, CDP browser (both paths), IPv6/dual-stack arms, `--script` inline-deps path, **malformed-proxy hard refusal** (both paths); direct opt-out control behaves as designed.
- Exit probes this pass: `185.220.100.240`, `204.8.96.86`, `192.42.116.20` — all ≠ box (`203.0.113.1` / `2a01:4f9:c014:1dca::1`).
- Env hygiene: **no `TALLOW_*` leaks** (shell env, `/etc/environment`, `profile.d`, bashrc, profile).
- Browser-zone egress lockdown (`src/browser/zone.rs`): single authoritative predicate; CDP target loopback/pipe-only; source guards block ad-hoc direct clients.
- Retention: `privacy-retention.sh --dry-run` → OK, no prunes due (Hermes logs 14d / transcripts 30d / cron output 7d / tor logs 14d / stale browser profiles 7d); journald cap 300M / 2w (currently 77.5M).

### 2.5 Public surface & TLS — OK (headers hardened this pass)
- Listeners: **public = 22/80/443 only**; loopback = 9050/9051 (tor), 2019 (caddy admin), 8080 (searxng), 8081 (imgproxy), 53 (resolved).
- Caddy serves only `myvapeisland.com` + `www` (static); cert valid to **2026-11-08**; `:80` → `:443` 308; HTTP/2 + alt-svc h3.
- Headers live: `strict-transport-security: max-age=15552000`, `x-frame-options: SAMEORIGIN`, `permissions-policy: camera=(), microphone=(), geolocation=()`, `x-content-type-options: nosniff`, `referrer-policy: strict-origin-when-cross-origin`. `server: Caddy` (no version). CSP deferred (§5/P2).
- Note: homepage response is a **≈16.8 MB single HTML** (`content-length: 16833270`) — performance item, not security.

### 2.6 Watchdogs & scheduled jobs — OK
- `dev-node-guard.timer` (5 min, /dev-node auto-heal), `hermes-healthcheck.timer` (5 min), `egress-battery.timer` (weekly, Mon ~04:36; last run OK = 14/14 via service path), `postboot-verify.sh` → `OK`; `hermes-gateway.service` active.
- `tallow-rmdb-update.service`: enabled → **runs at each boot** (snapshot updated 00:52 today, 680 KB; egress via Tor `socks5h://127.0.0.1:9050` per unit config). Its **weekly timer is disabled** → cadence is currently per-boot, not weekly (P3 decision).

### 2.7 Data at rest — accepted decision (on record)
- Single ext4 root, **no LUKS**; 4 GB swapfile (unencrypted, 1.1 G used). Decision per checklist **M4**: accept — no sensitive data at rest; retention windows + vault + `tallow encrypt-dir` available for artifact dirs. Re-open only if sensitive data lands on disk.
- Backups: `/var/backups` = OS defaults only; **no app backup job on this box** → confirm offsite strategy (§5/P2).

---

## 3 · Changes made — 2026-09-12 (all)

**This pass (22:03–22:16 UTC):**
1. `/etc/caddy/Caddyfile` — added `Strict-Transport-Security "max-age=15552000"`, `X-Frame-Options SAMEORIGIN`, `Permissions-Policy "camera=(), microphone=(), geolocation=()"`.
   - Evidence: diff (3 lines added); `caddy validate` OK; graceful reload; live check = HTTP/2 200 with all five headers, `www` vhost + `:80`→308 redirect verified.
   - Backup: `/etc/caddy/Caddyfile.bak-hermes-audit-20260912`. Rollback: `cp` it back + `systemctl reload caddy`.

**Earlier same-day pass (recorded in the checklist, independently verified there):**
- fail2ban install + sshd jail · auditd + 7 tamper watches + log caps · sysctl hardening (`send_redirects`, IPv6 `accept_redirects`, `rp_filter=1`, `log_martians`) · IPv6 `FORWARD` → DROP · SSH drop-in pins · `postboot-verify.sh` · weekly `egress-battery` timer + script · browser identity config pinned (`~/.tallow/browser/config`, 15 TOMLs) · `/dev` node guard timer.

---

## 4 · Web-scraping components — risk assessment

**Controls in place (verified):**
- Fail-closed egress contract (Tor default; `TALLOW_PROXY` override; direct only via audited explicit opt-out; malformed proxy = hard refusal) — 14/14 battery.
- Browser-zone egress lockdown module; CDP loopback/pipe-only; source guards against ad-hoc direct clients.
- Compiler-level OPSEC gates `E5001–E5004` + `@legal` / `@cra_class` annotations on network paths (`src/opsec_gates.rs`, `src/persona.rs`, `src/fingerprint_policy_pass.rs`).
- `sitescan` refuses any IP outside `authorized_cidr` (network scanning = owner-authorized scopes only).
- robots.txt machinery (`execute_network.rs`: parse + cache; permissive default / `strict` option) + `crawl-delay`; pacing defaults (`TALLOW_FETCH_DELAY_MS ≥ 250`, scanner ≤ 2 rps, backoff + jitter).
- Retention windows; third-party findings → disclosure, not exploitation.

**Risk matrix:**

| # | Risk | Exposure if hit | Control | Residual |
|---|------|-----------------|---------|----------|
| R1 | Attribution — box/operator identity leak | High | Fail-closed Tor egress + 14/14 battery + env hygiene + remote-DNS (`socks5h`) discipline | Tor exit class is visible to targets (`loc=T1`) — a property of the path, not a config bug |
| R2 | Detection (anti-bot / behavioral ML) | Medium (blocks) | Coherent per-session identity, pacing, warmup, real-browser paths | Behavioral scoring approximated; treat heavily-defended targets as likely-flagged; **stop-on-block, no escalation** |
| R3 | ToS / legal exposure | Per-target | Scope discipline: public data, no auth surfaces, read-only, robots | Per-target terms remain an operator responsibility; **concealment is not a legal strategy — compliance and authorization are** |
| R4 | Data protection (scraped content) | Low→Med | Retention windows; minimization; corpus dispositions | Scraped text feeding the AI substrate = **untrusted input** — keep the approval boundary; add a prompt-injection guard pass when wired |
| R5 | Third-party load | Low | Pacing budgets + `crawl-delay` | Keep per-host budgets in run profiles |
| R6 | Supply chain (browser/emulation deps) | Low | Re-run battery after upgrades (maintenance cadence) | JA4/cohort drift — re-pin procedure exists |

**Out of scope by design (policy):** detection-evasion escalation beyond the doctrine · CAPTCHA-solver services · any network-level scan without an owner-authorized scope · any "undetectable" claim.

---

## 5 · Open items & recommendations

- **P1 — SSH MFA (the one real access gap).** Options staged, both testable with rollback:
  - **(A) FIDO2 security key (recommended):** `ssh-keygen -t ed25519-sk -O verify-required` → add pubkey; keep the existing key until verified from a second session; no sshd changes needed.
  - **(B) TOTP (no hardware):** `apt-get install libpam-google-authenticator`; `auth required pam_google_authenticator.so nullok` in `/etc/pam.d/sshd`; drop-in `KbdInteractiveAuthentication yes` + `AuthenticationMethods publickey,keyboard-interactive`; `sshd -t && systemctl reload ssh`; test from a second session; console stays as break-glass. Drop `nullok` once enrolled.
  - Also confirm **Hetzner account 2FA** (the console is the break-glass path).
- **P1 — apply or drop** the 2 held `libgeos*` packages (leftover `noble-pgdg` repo).
- **P2 — backups:** confirm offsite strategy (nothing on-box beyond OS defaults; M1 pack+encrypt note exists in the checklist).
- **P2 — CSP** for `myvapeisland.com`: needs asset inventory + staged testing (report-only first).
- **P3 —** `tallow-rmdb-update` cadence (timer disabled; currently per-boot); homepage size (~16.8 MB); Docker image refresh cadence (`searxng`, `imgproxy`).
- **Already-explained states — don't re-chase in future audits:** `tor@default` `enabled-runtime` (= `tor-generator`, by design); `ufw` inactive (= `host-firewall.service` owns default-deny); no LUKS (= M4 accepted decision); `server: Caddy` without version + deferred CSP (= intentional); empty `sudo` group / no user accounts (= root-key-only by design).
- **Closed items:** checklist Disposition H8–H12 / M1–M8 remain closed — don't reopen without cause.

---

## 6 · Verification log (this pass)

```
check_egress.sh ......... passed=14 failed=0 skipped=0
tor probes .............. 185.220.100.240 / 204.8.96.86 / 192.42.116.20   (≠ box IPs)
nft ruleset ............. INPUT+FORWARD DROP, v4+v6; public 22/80/443 only; docker paths + raw drops OK
sshd -T ................. passwordauthentication=no; permitrootlogin=without-password; x11=no; kbd=no
fail2ban ................ jail sshd; currently banned 195.238.176.70; ~4k attempt lines / 7d
apt .................... 0 security-pending; dist-upgrade: libgeos3.14.1 + libgeos-c1t64
postboot-verify.sh ...... OK
privacy-retention.sh .... dry-run OK (no prunes due); journald 77.5M (cap 300M)
curl (local) ............ myvapeisland.com 200 + new headers; :80 → 308; www OK
caddy validate + reload . OK (graceful)
env hygiene ............. clean (no TALLOW_* exports anywhere)
```

*All commands non-destructive; re-runnable for drift checks. Probe values are point-in-time (Tor exits rotate by design).*

---

## 7 · Resolution log — follow-up pass (2026-09-12, ~22:20–22:55 UTC)

Executes the resolvable items from §5 (supersedes them where noted):

- **[RESOLVED] Held packages** — `libgeos3.14.1` + `libgeos-c1t64` applied; `dist-upgrade` pending = **0**.
- **[RESOLVED] `tallow-rmdb-update` cadence** — weekly timer enabled (`OnCalendar=weekly`, `Persistent=true`); next run Mon 2026-09-14 ~00:30 UTC. Boot refresh retained by design. Last service exit: 0/SUCCESS.
- **[RESOLVED] Docker images** — refreshed; both containers recreated onto current images and verified. Recreate is now scripted (pull → recreate → verify → auto-rollback; previous container kept as `*_prev`):
  - **searxng** → `/opt/searxng/update.sh` (preserves all 4 mounts incl. anonymous volumes + env from `/opt/searxng/env.sh`). Post-update: HTTP 200, JSON API OK (echoed-query verified), bind `127.0.0.1:8080` only, public path closed on v4+v6.
  - **imgproxy** → `/opt/imgproxy/update.sh`. Post-update: health 200.
  - Old images retained for rollback; prune with `docker image prune` once confidence is earned.
- **[RESOLVED] CSP** — live-page asset inventory complete (all-inline page; zero external scripts; 0 external font files). Draft policy + apply/test/rollback steps: `myvapeisland-csp-draft.md` (enforcement staged for a browser pass).
- **[SKIPPED — accepted risk, 2026-09-12]** SSH MFA — decision: stays key-only for now (single keypair, present twice in `authorized_keys`); no second factor. Runbook remains in §5 if revisited later; Hetzner-account 2FA still worth confirming separately.
- **[IN PROGRESS] Backups** — paid offsite (Storage Box / cloud) declined; direction set to **pull-to-home**: server-side staged encrypted archive set (nightly: Hermes state incl. Mnemosyne DB + vault + box configs; weekly: Nixe minus `target/`/caches) + client-side pull into the operator's "nas folder" (likely the Windows box that already reaches the server by SSH). Awaiting device/folder confirmation → then build + restore drill. Until that lands the box still has **no offsite copy** (no git remotes; ~1k uncommitted files).
- **[LEFT AS-IS — user decision, 2026-09-12]** `postgresql@17-main` (failed; teardown leftover). Verified during the decision pass: cluster config + admin user exist, but the data directory is **empty (0 files; entire `/var/lib/postgresql` tree = 4 KB)** and no service on the box uses the stack. Full teardown (packages + `noble-pgdg` repo + empty dirs) offered and **declined — everything stays in place**; the unit will re-attempt and fail at each boot (accepted, harmless). Revisit only if it becomes noise worth removing.

---
*Prepared by Hermes · read-only audit except §3.1; resolution pass §7 · no "undetected" claims; probe-verified statements only.*
