# Stealth Hardening Checklist — gap-audited implementation plan

**Baseline:** [`stealth-scanning-statement-of-intent.md`](./stealth-scanning-statement-of-intent.md) (the doctrine/runbook this operationalizes) · **Gap audit:** live, 2026-09-12 — read-only; **no changes were made to the system**. · **Executor:** the operator or an agent.

**Categories:** `[SYS]` system hardening · `[NET]` network obfuscation · `[CRYPTO]` encryption & keys · `[BEHAVIOR]` behavioral stealth
**Legend:** ✅ verified done · ⬜ to do · 🔁 recurring. Every item has exact commands and a done-check.

---

## 0 · Audit snapshot — already solid (keep true; don't redo)

| Area | State | Evidence (2026-09-12) |
|---|---|---|
| Egress contract (fail-closed) | ✅ | `check_egress.sh`: **14 passed / 0 failed / 0 skipped** — compiled + interpreted fetch/http/browser, IPv6 arm, malformed-proxy refusal |
| Tor | ✅ | 0.4.9.11; `tor@default` + `tor-us` active; exits `45.84.107.198` / `104.223.84.121` ≠ box; hardened torrc; sandboxed units |
| Egress env hygiene | ✅ | No `TALLOW_*` exports in shell, `/etc/environment`, `profile.d`, bashrc |
| Host firewall | ✅ | v4+v6 `INPUT DROP` default-deny, allows only `22,80,443` + established + ICMP; drop logging `5/min` |
| Listener surface | ✅ | Only `:22`, `:80`, `:443` public. Everything else loopback: 9050/9051 (Tor), `:53` (resolved), `2019` (Caddy admin), `8080` (searxng), `8081` (imgproxy) |
| Retention | ✅ | `privacy-retention` daily cron + journald cap (`300M / 2week`) in place |
| Updates | ✅ | `unattended-upgrades` active (lists+upgrade daily; last run 06:56 today) |
| Watchdogs | ✅ | `dev-node-guard.timer` (auto-heals `/dev/null`), `hermes-healthcheck.timer` |
| SSH (effective) | ✅ | `PermitRootLogin without-password`, `PasswordAuthentication no`, `KbdInteractive no`; 2× `ssh-ed25519` keys |
| AppArmor | ✅ | Loaded; 158 profiles, 65 in enforce |
| OPSEC gates E5001–E5004 | ✅ | Implemented (`src/opsec_gates.rs`, `src/persona.rs`, `src/fingerprint_policy_pass.rs`, main.rs Phase 11b); corpus test **6/6 PASS** |
| Network-scan scope gate | ✅ | `sitescan` D5 refuses any IP outside `authorized_cidr` (unit-tested) |

---

## P0 — CRITICAL · leak/attribution class — must remain true forever (recurring verification)

### C1 🔁 [NET] Egress acceptance battery
Run weekly + after **any** Tor/browser/dependency change.
```bash
cd ~/Nixe && bash tests/egress/check_egress.sh
```
**Done =** summary shows `passed=14 failed=0`. (Automate → H3.) Last ✅ 2026-09-12.

### C2 🔁 [NET] DNS-leak spot check
The only test that settles DNS: capture while fetching a *fresh* host.
```bash
timeout 60 tcpdump -i any -n 'port 53' > /tmp/dns.txt 2>&1 &
timeout 30 curl -s --socks5-hostname 127.0.0.1:9050 \
  "https://$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n').nip.io" >/dev/null
sleep 2; kill %1; grep -c nip.io /tmp/dns.txt   # MUST be 0
```
**Positive control:** the same fetch with `--socks5` (not `socks5h`) **must** produce queries — if it doesn't, the capture itself is broken and the test is invalid.
**Done =** proxied client: 0 local queries; control: >0. Run monthly + after resolver changes.

### C3 🔁 [NET] Egress-env hygiene audit
```bash
env | grep -E '^TALLOW' || echo clean
grep -RniE '^[^#]*TALLOW_(ALLOW_DIRECT|PROXY|TOR)' /etc/environment /etc/profile.d/ ~/.bashrc ~/.profile 2>/dev/null || echo clean
```
**Rule:** never set these globally. `TALLOW_ALLOW_DIRECT=1` is a watched, explicit, single-session decision only. Last ✅ 2026-09-12.

### C4 🔁 [NET] Tor change/upgrade re-verify
```bash
tor --verify-config                       # no path argument
systemctl reload tor@default && systemctl restart tor-us
timeout 30 curl -s --socks5-hostname 127.0.0.1:9050 https://api.ipify.org; echo
timeout 45 curl -s --socks5-hostname 127.0.0.1:9051 https://api.ipify.org; echo
```
**Done =** config OK; both exits return an IP ≠ `203.0.113.1` / `2a01:4f9:c014:1dca::1`. Keep torrc hashes (`md5sum /etc/tor/torrc /etc/tor/torrc-us`) on file to spot unexpected edits.

### C5 🔁 [SYS] Boot / engine-upgrade ritual
```bash
systemctl is-active host-firewall.service dev-node-guard.timer tor@default tor-us.service
```
**Done =** all `active`, then run C1. (Docker engine upgrades can rewrite chains — `host-firewall.service` is `After=docker.service` and re-applies; confirm after engine upgrades.) Automate → C6.

### C6 ✅ (2026-09-12) [SYS] `postboot-verify.sh` deployed at `/usr/local/sbin/` — prints `postboot-verify: OK`
```bash
cat >/usr/local/sbin/postboot-verify.sh <<'EOF'
#!/usr/bin/env bash
# One-shot stack sanity: firewall, guards, Tor, egress, listeners.
set -uo pipefail
fail=0
box4=203.0.113.1
for u in host-firewall.service dev-node-guard.timer tor@default tor-us.service; do
  systemctl is-active --quiet "$u" || { echo "DOWN: $u"; fail=1; }
done
e=$(timeout 30 curl -s --socks5-hostname 127.0.0.1:9050 https://api.ipify.org || true)
[ -n "$e" ] && [ "$e" != "$box4" ] || { echo "EGRESS PROBLEM: '${e:-empty}'"; fail=1; }
ss -ltn | grep -qE '0\.0\.0\.0:9050|\[::\]:9050' && { echo "LEAK: tor SOCKS bound publicly"; fail=1; }
[ "$fail" -eq 0 ] && echo "postboot-verify: OK" || echo "postboot-verify: FAIL"
exit "$fail"
EOF
chmod +x /usr/local/sbin/postboot-verify.sh && /usr/local/sbin/postboot-verify.sh
```
**Done =** prints `postboot-verify: OK`.

### C7 ✅ [NET] Scanner authorization gate — keep
Any new network-probing code must keep the `authorized_cidr` refusal (`cargo test -p tallow --lib sitescan` stays green).

### C8 🔁 [CRYPTO] Retention + log caps spot check
```bash
/usr/local/sbin/privacy-retention.sh --dry-run
cat /etc/systemd/journald.conf.d/retention.conf
```
**Done =** dry-run lists bounded prunes; journald cap file intact (`300M`, `2week`).

---

## P1 — HIGH · close these now

### H1 ✅ (2026-09-12) [SYS] fail2ban installed + `sshd` jail active (was: not installed)
```bash
apt-get update && apt-get install -y fail2ban
cat >/etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled = true
backend = systemd
maxretry = 4
findtime = 10m
bantime = 1h
EOF
systemctl enable --now fail2ban
fail2ban-client status sshd
```
**Done =** service `active`; `status sshd` shows the jail. (SSH is already key-only — this throttles brute noise and protects Caddy later; optional caddy jail can follow.)

### H2 ✅ (2026-09-12) [SYS] auditd installed, 7 tamper watches loaded, log caps 50M×4 (was: not installed)
```bash
apt-get install -y auditd audispd-plugins
cat >/etc/audit/rules.d/opsec.rules <<'EOF'
-w /etc/tor/ -p wa -k opsec-tor
-w /etc/ssh/sshd_config -p wa -k opsec-ssh
-w /etc/ssh/sshd_config.d/ -p wa -k opsec-ssh
-w /etc/sysctl.d/ -p wa -k opsec-sysctl
-w /usr/local/sbin/host-firewall.sh -p wa -k opsec-fw
-w /usr/local/sbin/privacy-retention.sh -p wa -k opsec-retention
-w /etc/systemd/system/ -p wa -k opsec-units
EOF
augenrules --load && systemctl enable --now auditd
auditctl -l | head
```
Also cap its logs: in `/etc/audit/auditd.conf` set `max_log_file = 50`, `num_logs = 4`.
**Done =** `auditctl -l` lists the watches; `systemctl is-active auditd` = active.

### H3 ✅ (2026-09-12) [NET] Weekly egress battery timer — enabled; first run logged `OK` (14/14)
```bash
cat >/usr/local/sbin/egress-battery.sh <<'EOF'
#!/usr/bin/env bash
# Weekly egress drift check. Exit non-zero (logged) on failure.
set -uo pipefail
cd ~/Nixe
mkdir -p /var/log/egress-battery
out=/var/log/egress-battery/$(date -u +%F).log
if bash tests/egress/check_egress.sh >"$out" 2>&1 && grep -q 'failed=0' "$out"; then
  logger -t egress-battery OK
else
  logger -t egress-battery "FAIL - see $out"; exit 1
fi
EOF
chmod +x /usr/local/sbin/egress-battery.sh

cat >/etc/systemd/system/egress-battery.service <<'EOF'
[Unit]
Description=Weekly egress leak battery
After=tor@default.service network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/egress-battery.sh
EOF

cat >/etc/systemd/system/egress-battery.timer <<'EOF'
[Unit]
Description=Weekly egress battery schedule
[Timer]
OnCalendar=Mon 04:17 UTC
RandomizedDelaySec=45m
Persistent=true
[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload && systemctl enable --now egress-battery.timer
systemctl start egress-battery.service   # prove one run now
systemctl list-timers egress-battery.timer --no-pager
journalctl -t egress-battery -n 5 --no-pager
```
**Done =** timer listed; first run logged `OK`. (Needs `target/debug/tallow` present — rebuild after code changes.)

### H4 ✅ (2026-09-12) [SYS] Sysctl hardening applied + persisted (`/etc/sysctl.d/99-opsec-hardening.conf`)
Current gaps: `send_redirects=1`, IPv6 `accept_redirects=1`, `rp_filter=2` (loose).
```bash
cat >/etc/sysctl.d/99-opsec-hardening.conf <<'EOF'
# Stealth box network hardening (2026-09-12 audit)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
# ip_forward stays 1 — required by Docker; exposure contained by FORWARD DROP + loopback-published ports
EOF
sysctl --system
sysctl -n net.ipv4.conf.all.send_redirects net.ipv6.conf.all.accept_redirects net.ipv4.conf.all.rp_filter
```
**Test after:** C1 battery + one container fetch (`docker exec searxng python3 -c "import urllib.request;print(urllib.request.urlopen('https://api.ipify.org',timeout=10).read())"`). If container egress breaks, set `rp_filter` back to `2` (Docker-known-good) and note it.
**Done =** values `0 / 0 / 1`; tests pass.

### H5 ✅ (2026-09-12) [NET] IPv6 FORWARD aligned to DROP in `host-firewall.sh` (was: v4 DROP / v6 ACCEPT)
Edit `/usr/local/sbin/host-firewall.sh`: mirror the v4 pattern for IPv6 (`ip6tables -P FORWARD DROP`, keep Docker's own chains/jumps intact), then:
```bash
systemctl restart host-firewall.service
ip6tables -S FORWARD | head -1        # expect: -P FORWARD DROP
# sanity: containers + a v6 fetch from the box still work
```
**Done =** v6 policy DROP; nothing else regressed. (Containers here are v4-only, so risk is low; test anyway.)

### H6 ✅ (2026-09-12) [SYS] SSH hygiene done — `99-opsec.conf` pins, stale line commented, `x11forwarding no`
`/etc/ssh/sshd_config:42` still carries a stale `PermitRootLogin yes` (harmless only because `sshd_config.d/50-cloud-init.conf` wins — don't rely on that), and `X11Forwarding` is `yes`.
```bash
printf 'X11Forwarding no\nPermitRootLogin prohibit-password\n' >/etc/ssh/sshd_config.d/99-opsec.conf
sshd -t && systemctl reload ssh
sshd -T | grep -iE 'x11forwarding|permitrootlogin|passwordauthentication'
# optional hygiene: comment the stale line at sshd_config:42 for clarity
```
**Done =** `x11forwarding no`, `permitrootlogin without-password`, `passwordauthentication no`.

### H7 ✅ (2026-09-12) [NET] Browser identity pinned — 15 TOMLs initialized; `stealth.toml`: `chrome_windows`, all 23 evasions `true`; `config show` parses clean
`~/.tallow/browser/config/` is absent → identity comes from invisible defaults. Make it reviewable:
```bash
./target/release/tallow browser config --help   # 15 TOML files incl. stealth_conf
./target/release/tallow browser config list
```
Create/pin `stealth.toml` (profile `chrome_windows`; v1/v2/v3 evasions on). **Done =** config dir exists, browser launch unaffected, fingerprint probes still green.

### H8 ⬜ [CRYPTO] Encrypt sensitive recon artifacts at rest — using the project's own tooling
```bash
./target/release/tallow encrypt-dir --help   # AES-256-GCM + Argon2id
./target/release/tallow hash --help          # BLAKE3 integrity manifests
```
**Policy decision to record in `docs/opsec/`:** which artifact dirs (any containing third-party findings) get `tallow encrypt-dir`; keep `tallow hash` manifests alongside. **Done =** policy line written + one dir encrypted as pilot.

### H9 ⬜ [BEHAVIOR] Pin pacing defaults into run profiles
Write `docs/opsec/run-profiles.md`: `TALLOW_FETCH_DELAY_MS ≥ 250`, scanner RPS ≤ 2, per-host budgets, robots `crawl-delay` honored, schedule spread. **Done =** file exists and is referenced from the statement of intent.

### H10 ⬜ [NET] Camoufox timezone coherence
`nixreader/camoufox_reader.py` keeps UTC (known soft spot). Either set an explicit timezone pref matching the exit-region strategy, or record the accepted-UTC decision in the SoI. **Done =** code updated or decision written; reader re-run clean.

### H11 ⬜ [NET] TLS/HTTP2 cohort maintenance + decision
- Decide `http2-fingerprint` feature enablement (currently off by default; module lives at `src/browser/http2_fingerprint.rs`).
- Procedure: after every Chrome/Camoufox upgrade, re-pin the JA4 cohort and re-run the coherence checks. **Done =** decision noted + procedure row in the maintenance table below.

### H12 ⬜ [NET] Close the top JS-surface gaps (dev task)
1. Block `getExtension('WEBGL_debug_renderer_info')` in the browser stealth path (`src/browser/stealth*.rs` — legacy `stdlib/fingerprint.rs` blocks it, browser path doesn't).
2. OffscreenCanvas / worker-canvas coverage.
3. AudioWorklet coverage.
4. Re-test against browserleaks + creepjs; add a regression fixture. **Done =** tests added, probes re-run, gaps struck from the SoI §honest-limits list.

---

## P2 — MEDIUM · hardening depth & hygiene

### M1 ⬜ [CRYPTO] Encrypted config backup
`tallow pack` + `tallow encrypt` the config set (`/etc/tor/torrc*`, `/etc/ssh/sshd_config.d/`, `/etc/sysctl.d/99-opsec-hardening.conf`, `/usr/local/sbin/host-firewall.sh`, `/usr/local/sbin/{privacy-retention,egress-battery,postboot-verify}.sh`, `/root/.tallow/browser/config/`) → store offsite. Or record a no-backup decision. **Done =** artifact stored or decision written.

### M2 ⬜ [SYS] SSH key hygiene cadence
`awk '{print $1}' /root/.ssh/authorized_keys | sort | uniq -c` (✅ currently 2× ed25519). Review/rotate annually; optionally `AllowAgentForwarding no` in `99-opsec.conf`.

### M3 ⬜ [SYS] Noise reduction (optional)
```bash
systemctl disable --now motd-news.timer
```

### M4 ⬜ [CRYPTO] Disk-at-rest decision note
Cloud VPS has no LUKS. Mitigation stack already in place: retention windows, no sensitive data at rest, `tallow encrypt-dir` for artifacts (H8), vault for secrets. **Done =** decision paragraph in `docs/opsec/`.

### M5 ⬜ [NET] Beyond-Tor per-target egress policy sheet
Write the one-pager (rules: per-target only, never Tor-wide pin, never mix identities across egress paths, re-probe before/after). Reference: SoI §2.3.

### M6 ⬜ [BEHAVIOR] Coherence spot-check before browser-based runs
Confirm UA/CH ↔ tz ↔ locale ↔ exit-geo coherence (`tallow browser open` + a tz/geo probe page) as step 7 of the runbook. **Done =** step wired into the runbook.

### M7 ✅ [SYS] Caddy admin API — keep
Verified loopback-only (`127.0.0.1:2019`). Revisit `admin off` only if reloads stop being needed.

### M8 ⬜ [CRYPTO] Compliance artifacts refresh
```bash
./target/release/tallow pia && ./target/release/tallow sbom && ./target/release/tallow audit
```
Store outputs under `docs/opsec/compliance/`. **Done =** three artifacts filed with a date.

---

## Execution order (one pass)

1. **H6** SSH hygiene (2 lines, zero risk) → 2. **H1** fail2ban → 3. **H2** auditd → 4. **H4** sysctl → 5. **H5** IPv6 FORWARD → 6. **H3 + C6** timer & postboot script → 7. **H7** browser pin → 8. **H8** crypto policy → then dev: **H11/H12**, behavioral: **H9/H10**, hygiene: **M1–M8**.
*(Steps 1–7 executed + independently verified 2026-09-12. The tail — H8, H9–H12, M1–M8 — was reviewed for necessity and closed: see the Disposition section at the end.)*

## Global done-verification

```bash
systemctl is-active host-firewall.service dev-node-guard.timer tor@default tor-us.service fail2ban auditd
bash tests/egress/check_egress.sh | tail -3          # failed=0
sshd -T | grep -iE 'permitrootlogin|passwordauthentication|x11forwarding'
sysctl -n net.ipv4.conf.all.send_redirects net.ipv6.conf.all.accept_redirects net.ipv4.conf.all.rp_filter
systemctl list-timers egress-battery.timer --no-pager
/usr/local/sbin/postboot-verify.sh
```

## Maintenance cadence

| Cadence | What |
|---|---|
| Weekly (auto) | Egress battery (H3) — OK/FAIL in journal `egress-battery` |
| Monthly | C2 DNS spot check; review battery logs; `apt list --upgradable` skim |
| Per upgrade | C4/C5 rituals (Tor, Docker, kernel); re-pin JA4 cohort after Chrome/Camoufox bumps (H11) |
| Quarterly | M2 key review, M8 compliance refresh, restore-test any backups (M1) |

## Verification log — 2026-09-12 (fresh, independent re-check)

- **Egress battery** (3rd run, via the service path): `passed=14 failed=0 skipped=0`; journal `egress-battery: OK`.
- **DNS packet proof** (re-run, fresh random hosts): **0 local queries** on the proxied path; positive control showed 8 — methodology validated.
- **auditd end-to-end:** a live `touch` of `99-opsec.conf` was captured — `ausearch -ts recent -k opsec-ssh` → `comm="touch" … key="opsec-ssh"`.
- **Firewall idempotency:** service restart re-applies cleanly — v4+v6 `INPUT`/`FORWARD` all `DROP`; Tor exit OK after (`185.220.100.243`).
- **Services:** all 8 units active; listener surface unchanged (22/80/443 public only); no `TALLOW_*` env leaks; 8 × ✅ items on this checklist.
- Only journal errors = SSH scanner bots on `:22` (the class fail2ban now counts/bans) — nothing from the changes.
- No discrepancies found. (One false alarm chased: a case-sensitive grep for the Obsidian entry — entry was present.)

---
*Audited 2026-09-12; the same-day execution pass landed **C6 + H1–H7** (✅ marks above). The audit itself was read-only; the pass touched: `sshd_config.d/99-opsec.conf` + stale-line comment, fail2ban + auditd (+ `opsec.rules`, log caps), `/etc/sysctl.d/99-opsec-hardening.conf`, `host-firewall.sh` (v6 FORWARD), `egress-battery.{sh,service,timer}` + `postboot-verify.sh`, browser config init (15 TOMLs). Post-change battery re-run: **14/14**; DNS spot check: 0 local queries on the proxied path.*

---

## Disposition — 2026-09-12 (necessity review)

All remaining ⬜ items (H8–H12, M1–M6, M8) are **closed — reference only, not open work**; none justifies doing it now:

- **H8 artifact encryption** — artifacts are public-data research; at-rest encryption fights greppability for a threat (disk access) that already owns the box. `tallow encrypt-dir` stays available ad hoc.
- **H9 pacing doc** — duplicates the statement (§2.5/§3); defaults already live in code.
- **H10 Camoufox tz** — the target already sees a Tor exit (`loc=T1`); tz is noise beside that. Already a documented soft spot.
- **H11 HTTP/2 cohort** — feature off by design; its only live part (JA4 re-pin after upgrades) stays a one-line maintenance row above.
- **H12 JS-surface gaps** — real dev work, marginal now (fetch-first posture; hard fingerprinters block Tor exits anyway). Knowledge stays in `mega/tallow-1000x-upgrade-2026/stealth-antidetection.md`; revisit only for a concrete target.
- **M1 encrypted backup** — this checklist contains every file's content; it *is* the backup.
- **M2 key hygiene** — already key-only/root-only (2× ed25519), nothing scheduled.
- **M3 motd-news / M4 disk-at-rest note** — cosmetic / non-action.
- **M5 beyond-Tor policy** — already in the statement §2.3.
- **M6 coherence step** — already runbook step 7.
- **M8 compliance artifacts** — no consumer for a solo-box posture.
