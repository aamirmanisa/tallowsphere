# Incident Runbook (TSK-1106)

This runbook defines operational response for scraper block events and provider outages.

> status: reviewed 2026-09-05 (C6 docs wave) — era label: written for the April 2026 launcher-batch program (TSK-1106, `launch_report.json`/`run_XX` evidence). Incident roles/severity structure remains valid, but it is NOT yet reconciled with the Phase 6/7 local queue/artifact loops.

## Scope

Use this runbook when any of the following occur during a launch or active run:
- sustained `401/403` access blocks on expected data endpoints,
- sustained `429` rate limiting or challenge escalation,
- upstream provider failures (proxy provider, API provider, DNS, or TLS edge),
- broad inability to produce expected run artifacts.

## Severity Levels

| Severity | Definition | Typical triggers | Response target |
|---|---|---|---|
| `SEV-1` | Complete production outage or severe data loss risk | `>=80%` unresolved across active batch, all providers failing, run pipeline halted | Triage start in 5 min, status updates every 15 min |
| `SEV-2` | Major degradation with limited partial success | `40-79%` unresolved, primary provider failing, retries ineffective | Triage start in 15 min, status updates every 30 min |
| `SEV-3` | Localized degradation or recoverable instability | `20-39%` unresolved, one domain or one provider class impacted | Triage start in 30 min, status updates every 60 min |
| `SEV-4` | Minor issue with low operational risk | `<20%` unresolved, isolated transient failures | Handle in normal ops cycle |

## Detection Signals

Trigger an incident when one or more detection rules fire for `>=10` minutes:

- `status_403_rate >= 30%` on targets expected to return data.
- `status_429_rate >= 25%` with increasing retry counts.
- `targets_unresolved >= 40%` at batch aggregate.
- Provider error bursts (`connect timeout`, `TLS failure`, `proxy auth failure`) on `>=30%` of attempts.
- `launch_report.json` indicates missing artifacts in `>=20%` of runs.
- Runtime compatibility error (example: `undefined function: http.batch`) repeats across retries.

## Incident Roles

- `Incident Commander (IC)`: owns severity, timeline, and go/no-go decisions.
- `Operator`: executes containment, rollback, and rerun steps.
- `Comms Owner`: posts updates to stakeholders and maintains status log.
- `Scribe`: captures timestamps, actions, hypotheses, and outcomes.

One person may hold multiple roles for `SEV-3/SEV-4`.

## Immediate Actions (First 15 Minutes)

1. Freeze new launches for affected workloads.
2. Capture evidence bundle:
   - batch root path,
   - `launch_report.json`,
   - one failing `run_XX` folder with `stdout.log` and `stderr.log`,
   - current config manifest and binary path.
3. Assign severity and incident roles.
4. Split diagnosis path:
   - `Block Event Path` for `401/403/429/challenge` heavy failures,
   - `Provider Outage Path` for transport/provider/API failures.
5. Send first incident communication using template below.

## Block Event Path (401/403/429/challenges)

1. Confirm auth/session validity:
   - refresh token/cookies,
   - verify required headers are present.
2. Lower traffic pressure immediately:
   - reduce `Connections` and per-domain concurrency by at least `50%`.
3. Enable backoff hardening:
   - exponential backoff + jitter,
   - cap retry budget.
4. Shift to safer request profile:
   - browser-like headers,
   - domain-specific pacing.
5. If still blocked, execute provider fallback strategy:
   - switch to secondary route/provider for impacted domains only.
6. Re-run a narrow canary set (5-10 targets) before full resume.

## Provider Outage Path (proxy/API/network)

1. Validate provider health quickly:
   - provider status page,
   - auth and quota checks,
   - synthetic request to known healthy endpoint.
2. Isolate fault domain:
   - primary provider only,
   - single region only,
   - network segment only.
3. Activate fallback:
   - switch to secondary provider/config,
   - pin to healthy region,
   - disable non-critical high-cost features.
4. Re-run one worker canary and validate artifact contract.
5. Gradually restore capacity: `1 -> 3 -> 10` workers with checkpoints.

## Rollback Procedures

Use rollback when mitigation does not improve key metrics within one response window.

### Config Rollback

1. Revert to last known-good launcher/config combination.
2. Restore previous concurrency envelope.
3. Re-run canary batch and verify `summary/csv/full` artifacts before wider launch.

### Runtime Rollback

1. Switch from current binary to last validated runtime.
2. Verify runtime capability compatibility using a smoke script.
3. Relaunch one worker; expand only after clean pass.

### Provider Rollback

1. Route traffic back to last stable provider profile.
2. Keep reduced concurrency until error rates stabilize.
3. Maintain elevated monitoring for at least 60 minutes.

## Recovery and Resume Criteria

Resume full-scale launch only when all are true:
- incident severity is downgraded to `SEV-3` or lower,
- unresolved rate remains below `20%` for two consecutive checks,
- no repeated runtime/provider hard failures for 30 minutes,
- canary and partial scale runs satisfy artifact contract.

## Communication Template

Use this template for initial and update messages.

```text
[Incident] <SEV-X> <Short title>
Start Time (local): <YYYY-MM-DD HH:MM>
Owner (IC): <name>
Scope: <batch id, affected domains/providers>
Impact: <success-rate drop, unresolved %, customer/internal effect>
Detected By: <signal/alert>
Current Hypothesis: <block event | provider outage | mixed>
Actions Taken: <top 3 actions with timestamps>
Next Update: <time>
ETA/Confidence: <if known>
```

## Postmortem Checklist

Complete within 48 hours for `SEV-1/SEV-2`; within 5 business days for `SEV-3`.

- [ ] Confirm incident timeline with exact timestamps.
- [ ] Document root cause category: `block-policy`, `provider-outage`, `runtime-mismatch`, or `mixed`.
- [ ] Quantify impact: affected runs, unresolved delta, downtime duration.
- [ ] List what detection signals fired and which failed to fire.
- [ ] Record mitigation steps and which ones were effective.
- [ ] Record rollback decision and outcome.
- [ ] Define preventive actions with owners and due dates.
- [ ] Add/update automated checks or gating scripts if gaps were found.
- [ ] Link artifacts, logs, and relevant config versions.
- [ ] Publish final summary to operations docs and incident tracker.

## Required Evidence for Incident Closure

- `launch_report.json` from impacted batch and recovery batch.
- At least one failing and one recovered `run_XX` artifact set.
- Metrics comparison (before, during, after): unresolved %, success %, retry rate.
- Final communication log and postmortem link.
