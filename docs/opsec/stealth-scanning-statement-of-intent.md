# Statement of Intent — Stealth Scanning Posture

### OPSEC doctrine & execution runbook for authorized web scanning and reconnaissance

**Stack:** Tallow / Nixe (this box) · **Grounding verified:** 2026-09-12 · **Revision:** v1
**Implementation status:** companion checklist's first pass (**C6 + H1–H7**) **executed + independently verified** (2026-09-12) — statuses + verification log in `stealth-hardening-checklist.md`.
**Read with:** `stealth-hardening-checklist.md` (gap-audited execution plan) · `docs/mega/tallow-1000x-upgrade-2026/stealth-antidetection.md` (capability audit, REAL vs weak vs gated) · `artifacts/tallow_intel_uplift_2026-09-11/impl/A5.2.1_opsec_ruleset.md` (program-level OPSEC gates) · skills `tor-anonymous-stack`, `camoufox-tor`, `tallow-development`.

> **Directive to the executing agent (summary).**
> 1. Confirm scope and authorization before anything else — this posture is for **read-only, public-data** collection; network-level probing requires an owner-authorized scope.
> 2. Configure and verify in layer order: **network → client/browser → behavior**. Never skip a verification step.
> 3. After every configuration change, re-prove egress with a probe. A claim without a probe is not evidence.
> 4. Never describe the posture as "undetected" — the correct claim is **"maximized stealth, leaks closed"** (see §5).

---

## 0 · Core objective

The task has **two distinct goals that are frequently conflated**:

| # | Goal | Question it answers | Primary failure mode |
|---|------|---------------------|----------------------|
| A | **Attribution resistance** | "Can this activity be traced back to the operator or this box?" | An IP/DNS/identity leak — box IP in a target log, a local resolver query, a fingerprint reused across identities. |
| B | **Detection minimization** | "Does the target's anti-bot infrastructure flag, throttle, or block the client?" | A bot signal — IP reputation (datacenter/Tor exit class), TLS/JA3 mismatch, headless markers, inhuman cadence. |

Complete OPSEC = no *leaks* (A) + no *signals* (B). They are enforced by different layers: A is a network/contract problem; B is a client-fingerprint + behavior problem.

**Measurable success criteria** (each provable by probe — §4):

1. No request in any path egresses from the box IP (`203.0.113.1` / `2a01:4f9:c014:1dca::1`).
2. No DNS resolution happens outside the proxy path (zero packets to local port 53 while a fresh host is requested).
3. The client profile is **internally coherent** across UA ↔ TLS ↔ platform ↔ timezone ↔ locale ↔ screen.
4. Access cadence is statistically polite: no constant intervals, no burst-then-silence, per-host budgets respected.
5. One identity per run: circuit family + fingerprint seed + session state are compartmented per task and retired after (§2.17).

**Doctrine (non-negotiable wording):** "maximized stealth, leaks closed — never 'undetected'." Fail closed (if the proxy path is broken, requests fail — they never silently downgrade). Verify **per path**, not per design. **Coherence beats accumulation**: a mismatch between layers is a stronger signal than any single odd-but-coherent value.

**Standing guardrails:** read-only GET-only collection · public data only · no authentication surfaces, no credentials, no writes to targets · network scans only in owner-authorized scopes · robots.txt respected (`crawl-delay` honored) · findings about third parties go to owner disclosure, not exploitation · local retention windows enforced (`privacy-retention.sh`).

---

## 1 · Threat model — who sees what

| Observer | What they can see | Countermeasure (layer) | Residual risk |
|---|---|---|---|
| Local ISP / passive network | Traffic volume & timing to the Tor entry; nothing else | Tor for all egress; circuit padding | Volume/timing metadata to the entry exists |
| Target server operator | Source IP (an exit), headers, rate, request order | Exit rotation + pacing + coherent headers (L1–L3) | The exit is a *Tor exit* — a known, listable class |
| CDN / WAF (Cloudflare, Akamai, DataDome…) | IP reputation (`loc=T1` for Tor), TLS/JA3/JA4, HTTP/2 fingerprint, JS environment, behavior scores | stealth_http / real browsers / Camoufox; pacing; humanize | Tor exits are reputation-blocked by many CDNs; JS challenges may still fire |
| Correlation (any observer, across time) | Reused circuit + fingerprint + session linking two actions | Stream isolation; one persona per build unit; single-use fingerprint seeds; burn plans (§2.17) | Discipline failures link identities |
| Local box compromise | Everything except Tor's internals | Tor sandboxing (systemd drop-ins), default-deny firewall, retention windows | Outside egress OPSEC; handled separately |

---

## 2 · The three technical layers

### L1 — Network-level obfuscation (IP rotation, proxy usage, traffic shaping)

**2.1 Tor baseline — state on this box (verified 2026-09-12).**

- `tor@default` (unpinned — full anonymity set) → SOCKS5 `127.0.0.1:9050`; `tor-us.service` (US-pinned, `ExitNodes {us}` + `StrictNodes 1`) → `127.0.0.1:9051`. Both `active`.
- Hardened torrc (`/etc/tor/torrc` + `/etc/tor/torrc-us`): `ClientOnly 1` · `SocksPolicy accept 127.0.0.1` + `SocksPolicy reject *` · `SafeSocks 1` · `ConnectionPadding 1` + `ReducedConnectionPadding 0` · `AvoidDiskWrites 1`.
- Verify after any change: `tor --verify-config` (**no path argument** — a positional path is treated as an unknown option), then `systemctl reload tor` / `systemctl restart tor-us`, then live probes:

```bash
timeout 30 curl -s --socks5-hostname 127.0.0.1:9050 https://api.ipify.org   # unpinned exit
timeout 45 curl -s --socks5-hostname 127.0.0.1:9051 https://api.ipify.org   # US-pinned exit
```

- There is **no "more hops" knob** — Tor already builds a 3-relay circuit (guard + middle + exit). `EntryNodes`/`ExitNodes` only *constrain which relays* are used and shrink the anonymity set. Never pin a single relay fingerprint.

**2.2 Circuit isolation and rotation ("IP rotation").**

- `IsolateSOCKSAuth` is on by default: **distinct SOCKS credentials on the same port get distinct circuits** (verified: no-creds vs `user:passA` vs `user:passB` → three different exits).
- Rotation discipline: rotate **per task / per batch**, not per request — a stable exit within a session is *more* human than a changing one. Rotate between sessions/identities, not between requests.
- Rotate via (a) a new SOCKS credential (recommended — no control-port access needed), or (b) `NEWNYM` on the control port (rate-limited — do not hammer it).
- **Browser caveat:** Chrome does not support credentialed SOCKS5. Use `TALLOW_TOR=1` (shared circuits) for anything driving a browser; use credentialed `TALLOW_PROXY=socks5h://user:token@127.0.0.1:9050` only for pure `fetch()` collection that wants its own circuits.
- Two-instance design: default = unpinned 9050 (better anonymity). Use 9051 only when a target genuinely needs US geo-coherence. A permanent Tor-wide pin is a deliberate anonymity tradeoff, not a default.

**2.3 Proxy usage — the fail-closed egress contract (single most important rule).**

- Every Tallow path (compiled `fetch`, interpreter `fetch`, `http.*`, stdlib modules, the CDP browser) rides `socks5h://127.0.0.1:9050` **with no environment at all**. `TALLOW_PROXY` overrides; **`TALLOW_ALLOW_DIRECT=1|true|yes` is the only route to a direct connection** (unset / `0` / `false` / junk all keep Tor — a typo cannot open a leak); a malformed `TALLOW_PROXY` refuses instead of egressing direct; there is no fallback if Tor is down.
- **`socks5h`, never `socks5`**, for anything that can do it (ureq/curl) — remote DNS. `socks5://` resolves locally and is broken in ureq — never use it in Tallow envs.
- Beyond Tor (policy-gated): for CDN-hostile targets whose IP reputation blocks Tor exits, the documented step is a *per-target* cleaner egress (residential/rotating proxy) — **never** a Tor-wide pin. Rules: same fail-closed discipline; never mix identities across egress paths; respect the provider's terms and consent rules; re-prove the path before and after.

**2.4 DNS — the classic leak.**

- All DNS must ride the proxy: `socks5h` for CLI/ureq; Camoufox/Playwright uses `socks5` **plus** Firefox pref `network.proxy.socks_remote_dns: True` (it cannot do socks5h).
- In-app scanners use DoH — never plain `:53`.
- Proof (the only test that settles it): packet capture while requesting a *fresh* host (`<random>.nip.io`):

```bash
timeout 60 tcpdump -i any -n -l 'port 53' > /tmp/dns.txt 2>/dev/null &
# run the client against the fresh host, then stop the capture:
grep -c nip.io /tmp/dns.txt     # MUST be 0 for the proxied client
```

Run a `socks5` (local-DNS) positive control beside it — it must show queries, otherwise the capture itself is broken.

**2.5 Traffic shaping (pacing, jitter, budgets).**

- Defaults: `TALLOW_FETCH_DELAY_MS=250` per host (0 disables; keep ≥250 for scanning); scanner governors default **2 rps** (`TALLOW_SITESCAN_RPS`, `GOV_*` envs); retries use exponential backoff **with jitter** (`governed_get`).
- Add: per-host request budgets, concurrency caps, `crawl-delay` honored from robots.txt, schedule spread (never start every sweep at the same hour).
- Tor is slow — set **generous timeouts** rather than tight retries. Timeouts are not evidence of detection.

**2.6 Network verification battery.** `bash tests/egress/check_egress.sh` must be **4/4** (no-env fetch + browser ≠ box IP; `TALLOW_ALLOW_DIRECT=1` == box IP as the positive control; `TALLOW_TOR=1` routes). Plus the two `api.ipify.org` probes (§2.1) and, for Cloudflare targets, `GET https://<target>/cdn-cgi/trace` over Tor — read `ip=` (what the target sees) and note `loc=T1` (the target *knows* it is Tor traffic; that is a reputation gate, not an invisibility coat).

### L2 — Client & browser fingerprint evasion

**2.7 Choosing the rung — cheapest that works; never default to the browser.**

1. Plain `fetch()` — open pages (fastest; still Tor-routed).
2. `stealth_http` — browser-like **TLS/HTTP2** when the target fingerprints raw clients (BoringSSL `Emulation` profiles: Chrome137/136/135/131, Firefox139/136/128, Safari18, Edge134/131; on by default via the `stealth-http` feature). This is the fix for the "JA3 says scripted client" class.
3. `Browser.launch(headless)` + CDP — JS-rendered / softly-gated pages (stealth default-on).
4. Camoufox — patched-Firefox for hard pages (Cloudflare/paywall/JS-heavy); C++-level spoofing — the least-detectable browser path available to us.

**2.8 Headers & HTTP surface.**

- **One pinned, coherent UA per session** — never rotate UA per request (that IS a bot tell).
- The Tallow stealth profile sets `Network.setUserAgentOverride` **with `userAgentMetadata`**, so `Sec-CH-UA*` client hints stay coherent with the JS `navigator.userAgentData`.
- For raw HTTP, use `stealth_http` header ordering/emulation; keep `Accept` / `Accept-Language` / `Accept-Encoding` aligned with the emulated browser and the locale/timezone story (§2.13).

**2.9 TLS / JA3 / JA4 / HTTP2.**

- Raw `ureq`/rustls clients ≈ scripted-bot class. `stealth_http` produces a Chrome-identical ClientHello (real, tested path). The browser path uses real Chrome → real JA3/JA4 — valid only while UA/client-hints version matches the actual Chrome build (`update_chrome_version` keeps them in sync).
- Known gaps to re-check before relying on them (from the stealth audit): `stdlib/tls_profile.rs` / `stdlib/net.rs` JA3/JA4 entries are **data-only** (no handshake — do not present them as active spoofing); the HTTP/2 fingerprint module is **feature-gated OFF by default**; DPI-bypass raw-socket strategies are stubs.
- Pin the JA4 cohort you rely on, and keep a coherence test; drift after browser/dependency upgrades is a real failure mode.

**2.10 Browser path A — Tallow CDP Chrome (stealth default-on).**

- Launch defaults: `--disable-blink-features=AutomationControlled`, software GL (swiftshader), fixed 1920x1080; per-page CDP profile; **main-world** injection (isolated-world injection would leave FingerprintJS/DataDome/PerimeterX/Akamai probes unpatched — main world is deliberate).
- Profile config surface: `~/.tallow/browser/config/{stealth,browser,plugins,privacy,network,tor,…}.toml` — `profile = "chrome_windows"` (also `chrome_linux` / `chrome_macos` / `mobile_*` / `tor` / `custom`) with all 24 evasion toggles on. The directory not existing = defaults in force; write it to *change identity*, not to enable stealth.
- `TALLOW_NO_STEALTH=1` opts out (debugging only).

**2.11 Browser path B — Camoufox (patched Firefox).**

- Runner: `~/.hermes/hermes-agent/venv/bin/python ~/Nixe/nixreader/camoufox_reader.py "<url>"` → `{url, title, content, length, exit_ip}`.
- Config that matters: `proxy={"server": "socks5://127.0.0.1:9050"}` + remote-DNS pref; `headless="virtual"` (real browser on a virtual display — far less detectable than headless); `humanize=True` (human-like mouse/scroll timing); `block_webrtc=True`; `main_world_eval=True`; **`geoip=False` deliberately** (the geoip probe resolves a hostname *outside* the proxy — do not "fix" this); timezone is the known soft spot (keeps UTC unless set explicitly — decide deliberately).
- Camoufox prints a `LeakWarning … geoip=True` recommendation on every run — **expected**; leaving it off is the leak-correct choice here.

**2.12 Canvas / WebGL / audio / fonts — what is actually covered.**

- Canvas: deterministic, content-keyed noise (per-profile seed; stable across reads — engineered against the "stateful PRNG" tell). WebGL: `getParameter` overrides for VENDOR / RENDERER / UNMASKED_*.
- **Documented gaps** (re-check source before trusting; from the audit): `getExtension('WEBGL_debug_renderer_info')` was *not* blocked in the browser path; `OffscreenCanvas` / worker canvases and `AudioWorklet` are unpatched; font *enumeration* is masked but the rasterized glyph set cannot be faked by JS (fundamental limit); WebRTC's JS-`Proxy` wrapper is itself a CreepJS detection vector — prefer `block_webrtc=True` over the wrapper where possible.
- Avoid the legacy `stdlib/fingerprint.rs` engine (weak XOR canvas noise + `Math.random()` audio — non-deterministic and divergent from the browser path).
- WebRTC probe (when checking): host candidates must be mDNS `.local`; the only `srflx` candidate must equal the Tor exit. Any real local/box address = leak — then re-enable `block_webrtc=True`.

**2.13 Coherence — the requirement that ties L2 together.**

UA ↔ platform ↔ timezone ↔ locale ↔ fonts ↔ screen ↔ WebGL ↔ TLS/browser version must all tell **one story**. A Windows UA with Linux fonts, or a UTC timezone with a US exit, is a *stronger* signal than any single weird-but-coherent value. This stack ships coherence machinery — use it: `fingerprint_validator.rs` (`validate`/`auto_fix`) and `fingerprint_coherence.rs` (`CoherenceValidator`: geo ↔ timezone ↔ locale ↔ TLS ↔ UA ↔ screen ↔ touch ↔ GPU), with the `TlsBrowser` enum cross-referencing JA4 vs `Sec-CH-UA`. Program-level gate: `@stealth(profile: …, evasions: …)` is required on any browser-navigation function (E0400/E0401/E0402/E0404).

### L3 — Behavioral layer (timing & interaction)

**2.14 Timing model.**

- **Never constant intervals** (a metronome is the cheapest bot tell). Use jittered, human-shaped delays: log-normal-ish inter-request gaps, occasional longer pauses; dwell time proportional to page size/content; concurrency a human could plausibly produce.
- Budgets: per-host requests per session; spread long sweeps across hours; randomize traversal order where feasible; never fetch a full sitemap in perfect order.
- Lean on the defaults: `TALLOW_FETCH_DELAY_MS` (≥250 ms/host), governor rps ≤2 for recon, `crawl-delay` honored, backoff + jitter on retries.

**2.15 Interaction patterns (browser paths).**

- Camoufox `humanize=True` covers mouse/scroll cadence; Tallow's `behavior.rs` personas (`PersonaBehavior::from_seed`) give deterministic per-persona behavior; `antibot.rs` orchestrates warmup / cookie / rate-limit flows for gated targets.
- At CDP level: prefer natural scroll-and-read patterns over teleports; keep click/keystroke timing noisy; **scanning posture = read-only** — do not submit forms, do not log in, do not click anything with side effects.

**2.16 Session structure.**

- One identity per session: stable exit (circuit family), stable UA/profile, cookie continuity **within** the session; rotate between sessions.
- Warmup for hard targets: enter via a search/referer chain, load a couple of asset requests the way a browser would, then the target page.
- Compartmentation: never let two identities share process state (env, caches, cookies, temp dirs) — that is the composition leak.

**2.17 Program-level OPSEC (the rules that stop silent drift).**

- `@persona(id: …)` — the one identity a build unit acts as; **one persona per program** (E5001: identity mixing is an error).
- `@burn_plan(persona: …)` — disposal contract; burned personas cannot be reused; fingerprints are **single-use** (E5003: seed reuse across personas is an error).
- **E5002** — programs cannot read or set `TALLOW_ALLOW_DIRECT`; the direct-egress opt-out is an operator decision, never a program affordance.
- Escapes are logged (`@opsec_waiver` → W5001), never silent.
- Gate context: `@legal` (E0100) on any network function; `@cra_class` (W1900/E19xx); taint gates (W2201/E2202).

---

## 3 · Step-by-step execution guide (runbook)

**Step 0 — Scope & authorization.** Verify the target is in scope (own asset / public-data collection / owner-authorized). Network-level scanning (ports) requires an explicit authorized CIDR. Confirm the read-only contract up front.

**Step 1 — Network pre-flight.**

```bash
systemctl is-active tor@default tor-us.service
timeout 30 curl -s --socks5-hostname 127.0.0.1:9050 https://api.ipify.org   # must differ from box IPs
```

Assert the exit ≠ `203.0.113.1` and ≠ `2a01:4f9:c014:1dca::1`.

**Step 2 — Egress contract.** Browser paths: `export TALLOW_TOR=1`. Pure fetch with per-task isolation: `export TALLOW_PROXY='socks5h://user:<rotating-token>@127.0.0.1:9050'` (token per task = circuit per task). Never export `TALLOW_ALLOW_DIRECT` except a deliberate, watched debug session.

**Step 3 — DNS proof.** tcpdump test (§2.4). Pass = zero local queries for the fresh host, positive control behaving.

**Step 4 — Client rung selection.** fetch → stealth_http → Tallow browser → Camoufox (§2.7). Pin ONE UA/profile per session. Configure `~/.tallow/browser/config/stealth.toml` only when a non-default identity is needed.

**Step 5 — Pacing.** `TALLOW_FETCH_DELAY_MS=250`+; scanner rps ≤2; per-host budgets; schedule spread.

**Step 6 — Program gates.** `@legal` + `@stealth` + `@cra_class` on the right functions; `@persona` / `@burn_plan` when running as an identity.

**Step 7 — Fingerprint verification (after any change).** TLS probe (browserleaks TLS / tlsfingerprint.io) over the same proxy — expect the emulated browser class, not a raw-client class. JS probes (browserleaks canvas/WebGL, creepjs) — check coherence, watch the §2.12 gaps. WebRTC probe when a browser is used.

**Step 8 — Run discipline.** Read-only GETs; robots honored; watch the error rate (4xx/5xx bursts are signals). If a target pushes back (challenge pages, blocks): step down, slow down — do NOT escalate evasion or add infrastructure mid-run; halt and report.

**Step 9 — After-action.** Retire task-scoped credentials/tokens; rotate circuits for the next task; check retention (`privacy-retention.sh --dry-run`); record probe evidence (exits, pass/fail) with timestamps.

---

## 4 · Verification battery (summary)

| # | Check | Command / probe | Pass condition |
|---|-------|-----------------|----------------|
| 1 | Tor active | `systemctl is-active tor@default tor-us.service` | both `active` |
| 2 | Exit ≠ box | `curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org` | ≠ 203.0.113.1 / IPv6 |
| 3 | Contract battery | `bash tests/egress/check_egress.sh` | 4/4 PASS |
| 4 | DNS | tcpdump on `:53` + fresh host | 0 local queries (positive control shows queries) |
| 5 | Target's view | `GET https://<t>/cdn-cgi/trace` over Tor | `ip=` = exit; `loc=T1` noted |
| 6 | TLS class | TLS probe over the proxy | emulated-browser class |
| 7 | JS env | browserleaks / creepjs | coherent profile; §2.12 gaps acknowledged |
| 8 | WebRTC | ICE probe | host = mDNS `.local`; srflx = exit IP only |
| 9 | Cadence | request log histogram | jittered, no constant intervals, budgets respected |

*Verified at time of writing (2026-09-12): 9050 → `203.55.81.1`, 9051 → `96.44.159.148` — both differ from the box IPs.*

---

## 5 · Honest limits — what none of this beats

- **No configuration makes a client "undetectable".** Fingerprintable surface always remains (canvas/WebGL/audio details, TLS/JA4 of emulators, timer semantics, engine quirks).
- **Tor exits are reputation-blocked by many CDNs** (`loc=T1`) regardless of configuration — a network-layer limit, not a browser defect. Correct claim: "the target sees a Tor exit; it may act on that."
- Emulated TLS ≈ a *pinned cohort* of a real browser class — recognizable as "not the newest stock Chrome" to sharp detectors.
- Behavioral ML (DataDome/PerimeterX-class) scores patterns we can only approximate; treat sustained access to heavily-defended targets as likely-detected even when nothing visibly blocks.
- Some JS challenges remain unsolvable in some configurations — and solving them via third-party solver services is out of scope for an authorized posture.
- **Always report coverage honestly:** which layers were verified, with which probes, and what remained unknown.

---

## 6 · Maintenance

- Re-run the §4 battery after: Tor upgrades, browser upgrades (JA4 drift), stealth-config changes, dependency bumps.
- Keep the four historical leak classes closed (each was a real bug once; guard tests exist): interpreter-browser bypassing Tor · default-direct egress · `socks5` vs `socks5h` DNS · malformed-proxy silent fallback.
- When in doubt, the live services + probes are the truth — this document and the Obsidian notes are mirrors.
