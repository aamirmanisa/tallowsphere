# REA CLI runbook (out-of-process)

REA is used as an **external CLI**, never inside Tallow's runtime. Decision and rationale:
[`docs/decisions/REA-2026-10-14.md`](../decisions/REA-2026-10-14.md).

## 0. Preflight (no egress)

```bash
rea --version                 # expect: rea-agents@6.5.0
rea mcp doctor               # expect 5/5; records the tool digest + protocol
rea doctor                   # 17 checks; failures here name missing engines/tools
```

`rea mcp doctor` is the right check to quote in a handoff: it pins the version, the protocol
revision and the tool digest, so a later run can be shown to be the same build.

## 1. Anonymous plane — the CDP browser must ride Tor

REA drives a Chromium-family browser over CDP. Point it at the box's Tor SOCKS listener and
make sure Chromium cannot shortcut loopback targets:

```bash
--proxy-server="socks5://127.0.0.1:9050" --proxy-bypass-list="<-loopback>"
```

The `<-loopback>` entry is load-bearing: without it Chromium bypasses the proxy for loopback
addresses, so a target that resolves inward escapes the Tor plane silently.

**Prove the plane before capturing anything** — do not assume it. Fetch a Tor exit-echo
endpoint and require `IsTor: true`, then proceed. Claims about anonymity are claims about a
*measured* plane ("the target sees a Tor exit"), never "undetected" or "untraceable"; exits
rotate, so never quote a specific exit IP as current. This is the same discipline as the
`rea-web-recon` skill, which this runbook does not replace.

**Known limit, measured:** this host's deny-by-default SOCKS chokepoint refuses destinations
that are not on its allowlist, returning SOCKS5 reply `0x02` (`connection not allowed by
ruleset`, mapped in `src/cli/veil_cmd.rs`). Loopback is not on the list, so a **local fixture
cannot be fetched through the Tor plane.** Use a public fixture for plane proofs, and keep
local-only work out of REA entirely.

## 2. Capture

Artifacts land under a dated, per-target directory:

```
artifacts/<target>-rea-<date>/
```

Keep the whole directory — the browser profile, the capture, and the exported scripts — so
the capture is reproducible rather than merely reported.

## 3. Verify exported artifacts

Every exported script carries a digest. Cross-check each one against the capture's own
`source_artifacts[].sha256` **before** drawing any conclusion from it, so an artifact that was
edited between capture and analysis is caught by comparison instead of by trust:

```bash
sha256sum artifacts/<target>-rea-<date>/<exported.js>
# then compare with source_artifacts[].sha256 in the capture manifest
```

A mismatch is a finding about the pipeline, not a detail to reconcile by hand.

## 4. What this runbook does NOT authorize

- No credential handling, no authentication surfaces, no login flows — REA is used on public
  surfaces, consistent with `docs/opsec/stealth-scanning-statement-of-intent.md`.
- No reachable-Redis, sandbox-image or allowlist changes as a side effect of a REA run; those
  are separate, explicitly approved changes.
- No REA invocation from inside a Tallow build, test, or runtime path.

## 5. Verification performed (2026-10-15)

The plane this runbook requires was proved, not assumed. Transcript, verbatim:

```
S0) the interpreter resolves (the venv symlink trap)
    /home/user/.hermes/hermes-agent/venv/bin/python3.11 -> .../cpython-3.11-linux-aarch64-gnu/bin/python3.11
    Python 3.11.17

CONTROL) the box's own public IP — the value that must NOT be seen
    203.0.113.1

PROOF 1) Tor-routed reader
    {"url": "https://api.ipify.org?ipify-check", "content": "204.8.96.144",
     "exit_ip": "204.8.96.144", "length": 12}

PROOF 2) the Tor verdict
    {"url": "https://check.torproject.org/api/ip",
     "content": "{\"IsTor\":true,\"IP\":\"185.220.101.34\"}", "length": 36}
```

- **`IsTor: true`** — the Tor Project's own verdict, measured before any capture.
- The exit differs from the box IP, and differs *between the two proofs* (`204.8.96.144` vs
  `185.220.101.34`): circuits rotate per run. **Neither is quoted as a current state** — both are
  observations from this proof, and any IP named "the" exit would be wrong by the next run.

**Scope, stated precisely:** the proof exercises the **box's Tor-routed reader** (the same SOCKS
plane at `127.0.0.1:9050` this runbook's `--proxy-server` points at), which is what establishes that
the plane is live and that `IsTor` is measurable before capturing. It does **not** exercise REA's own
CDP launch with the flag string above — that needs a REA capture invocation, which this session did
not run. The flags and the plane are verified; REA's use of them is not.
