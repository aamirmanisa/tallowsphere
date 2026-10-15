# Postmortem — <YYYY-MM-DD> — <short title>

Template: copy to `docs/postmortems/YYYY-MM-DD-<slug>.md` and fill every
section. Write for the next operator, not for blame. Facts over narrative;
pin commands, log lines, and file paths verbatim.

## Incident

- **What happened:** (one paragraph, plain language)
- **Trigger:** (fault-suite scenario id, e.g. `tor-kill-mid-headers`, or `real-misuse`)
- **Detected by:** (suite run / operator / monitor) at `<timestamp UTC>`
- **Severity:** (`critical` data exposure · `high` wrong output · `medium` degraded · `low` cosmetic)

## Detection

- How it was noticed, and how long between onset and detection.
- What signal fired (test name, error string, alert). Quote it.
- What signal SHOULD have fired earlier (gap analysis).

## Timeline

| time (UTC) | event |
|---|---|
| `<hh:mm>` | first fault injected / first anomaly |
| `<hh:mm>` | detected |
| `<hh:mm>` | mitigated |
| `<hh:mm>` | root cause identified |

## Blast radius

- Affected components/paths (repo paths, services, data sets).
- Data classes touched (keys, credentials, user content, metadata).
- Anything that must be treated as compromised until proven otherwise.

## Root cause

- The mechanism, stated as a rule ("X could happen because Y allowed Z").
- Why existing checks did not catch it (be specific about the gap).
- Contributing factors (not excuses): missing test, ambiguous policy, config drift.

## Repairs

- [ ] immediate mitigation (what stopped the bleeding)
- [ ] fix for the root cause (PR/commit ref; do not link a plan, link the change)
- [ ] regression test added (suite scenario id + test name, or new scenario)
- [ ] verification evidence (paste commands + observed output)

## Policy changes

- Rule/policy updates (docs, suite, code policy) and where they were recorded.
- What the suite must now refuse that it previously accepted.
- Follow-ups that are explicitly NOT done yet (owner + tracking id).

## Sign-off

- Author: `@name` · Reviewer: `@name` · Date: `<YYYY-MM-DD>`
- Status: `open` / `mitigated` / `closed`
- Filed per `docs/postmortems/README.md`.
