# Tier gate — progressive-disclosure capability ladder

**Task:** B1.1.3 (O1) · **Status:** v1 — de-drifted 2026-09-12 (U-215) against the wired gate · **Mirrors:** `src/tiers.rs` @ commit `5cf3c14` (B1.1.1; re-verified — no diff to HEAD)
**Source of truth:** if this document and `src/tiers.rs` disagree, **the code wins** and this document is a bug — update both in the same change.

Tallow agents operate at one of four **competence tiers**: a strictly monotone ladder of authority. The `@tier` compile-time gate (§2) enforces the ladder at build time — wired at entry-file scope, import-graph expansion pending (see the §2 status box); the escape-hatch policy (§3) is the only sanctioned way around it; both rest on a **default-deny** posture — an unknown module is denied, never allowed by fallback.

---

## 1 · The ladder

| rank | tier | serde word | authority | introduces | cumulative |
|---|---|---|---|---|---|
| 0 | Scout | `"scout"` | observe — collect and read raw material | 5 | **5** |
| 1 | Analyst | `"analyst"` | assess — derive, grade, corroborate, forecast | 14 | **19** |
| 2 | Operator | `"operator"` | act — personas, replication, disposal, gates | 19 | **38** |
| 3 | VaultAdmin | `"vault_admin"` | custody — vault contents and key material | 2 | **40** |

Each tier's slice is the **full cumulative set** for that tier: it contains every module of all lower tiers (ladder monotonicity, enforced by `tests::ladder_is_monotone`). Promotion never removes an affordance; a demotion never leaves a module reachable above its tier. 40 distinct modules exist across the four slices; `vault` and `key_ledger` are reachable by VaultAdmin and by no lower tier (pinned by `tests::vault_secrets_are_vault_admin_only`).

### 1.1 Module table (mirrors `TIER_MODULES`)

`min. tier` is the lowest tier whose slice contains the module. Because slices are cumulative, a ✓ in a column means the module is in that tier's slice.

| module | min. tier | Scout | Analyst | Operator | VaultAdmin |
|---|---|---|---|---|---|
| `access_class` | analyst | — | ✓ | ✓ | ✓ |
| `agent_ledger` | operator | — | — | ✓ | ✓ |
| `agent_ledger_sqlite` | operator | — | — | ✓ | ✓ |
| `calibration` | analyst | — | ✓ | ✓ | ✓ |
| `canary_monitor` | operator | — | — | ✓ | ✓ |
| `canary_tokens` | operator | — | — | ✓ | ✓ |
| `caveats` | scout | ✓ | ✓ | ✓ | ✓ |
| `claim_typing` | analyst | — | ✓ | ✓ | ✓ |
| `corroboration` | analyst | — | ✓ | ✓ | ✓ |
| `decoy_flags` | operator | — | — | ✓ | ✓ |
| `degraded_gate` | analyst | — | ✓ | ✓ | ✓ |
| `derived_store` | analyst | — | ✓ | ✓ | ✓ |
| `disconfirmation` | analyst | — | ✓ | ✓ | ✓ |
| `fixity` | operator | — | — | ✓ | ✓ |
| `fixity_job` | operator | — | — | ✓ | ✓ |
| `forecast` | analyst | — | ✓ | ✓ | ✓ |
| `gap_register` | analyst | — | ✓ | ✓ | ✓ |
| `harm_review` | operator | — | — | ✓ | ✓ |
| `hndl` | operator | — | — | ✓ | ✓ |
| `injection_scan` | scout | ✓ | ✓ | ✓ | ✓ |
| `key_ledger` | vault_admin | — | — | — | ✓ |
| `ledger_events` | scout | ✓ | ✓ | ✓ | ✓ |
| `ledger_replay` | operator | — | — | ✓ | ✓ |
| `ledger_verify` | operator | — | — | ✓ | ✓ |
| `link_chain` | analyst | — | ✓ | ✓ | ✓ |
| `ops_gate` | operator | — | — | ✓ | ✓ |
| `opsec_gates` | operator | — | — | ✓ | ✓ |
| `persona` | operator | — | — | ✓ | ✓ |
| `premortem` | analyst | — | ✓ | ✓ | ✓ |
| `raw_store` | scout | ✓ | ✓ | ✓ | ✓ |
| `redaction` | operator | — | — | ✓ | ✓ |
| `regrade` | analyst | — | ✓ | ✓ | ✓ |
| `replication` | operator | — | — | ✓ | ✓ |
| `replication_plan` | operator | — | — | ✓ | ✓ |
| `requirements` | analyst | — | ✓ | ✓ | ✓ |
| `retention` | analyst | — | ✓ | ✓ | ✓ |
| `retro` | operator | — | — | ✓ | ✓ |
| `shred` | operator | — | — | ✓ | ✓ |
| `source_registry` | scout | ✓ | ✓ | ✓ | ✓ |
| `vault` | vault_admin | — | — | — | ✓ |

**Counts pinned in code (cumulative):** Scout **5** · Analyst **19** · Operator **38** · VaultAdmin **40**.

### 1.2 Cumulative slices, verbatim

Each list below is exactly `modules_for(Tier::…)` — ASCII-sorted, deduplicated, matching `TIER_MODULES` entry-for-entry.

```
Scout — 5 modules (cumulative):
  caveats, injection_scan, ledger_events, raw_store, source_registry

Analyst — 19 modules (cumulative):
  access_class, calibration, caveats, claim_typing, corroboration, degraded_gate,
  derived_store, disconfirmation, forecast, gap_register, injection_scan, ledger_events,
  link_chain, premortem, raw_store, regrade, requirements, retention, source_registry

Operator — 38 modules (cumulative):
  access_class, agent_ledger, agent_ledger_sqlite, calibration, canary_monitor,
  canary_tokens, caveats, claim_typing, corroboration, decoy_flags, degraded_gate,
  derived_store, disconfirmation, fixity, fixity_job, forecast, gap_register, harm_review,
  hndl, injection_scan, ledger_events, ledger_replay, ledger_verify, link_chain, ops_gate,
  opsec_gates, persona, premortem, raw_store, redaction, regrade, replication,
  replication_plan, requirements, retention, retro, shred, source_registry

VaultAdmin — 40 modules (cumulative):
  access_class, agent_ledger, agent_ledger_sqlite, calibration, canary_monitor,
  canary_tokens, caveats, claim_typing, corroboration, decoy_flags, degraded_gate,
  derived_store, disconfirmation, fixity, fixity_job, forecast, gap_register, harm_review,
  hndl, injection_scan, key_ledger, ledger_events, ledger_replay, ledger_verify, link_chain,
  ops_gate, opsec_gates, persona, premortem, raw_store, redaction, regrade, replication,
  replication_plan, requirements, retention, retro, shred, source_registry, vault
```

### 1.3 What each rung adds

- **Scout** (introduces 5) — `caveats`, `injection_scan`, `ledger_events`, `raw_store`, `source_registry`: read-only observation of collected material.
- **Analyst** (adds 14) — `access_class`, `calibration`, `claim_typing`, `corroboration`, `degraded_gate`, `derived_store`, `disconfirmation`, `forecast`, `gap_register`, `link_chain`, `premortem`, `regrade`, `requirements`, `retention`: assessment and grading.
- **Operator** (adds 19) — `agent_ledger`, `agent_ledger_sqlite`, `canary_monitor`, `canary_tokens`, `decoy_flags`, `fixity`, `fixity_job`, `harm_review`, `hndl`, `ledger_replay`, `ledger_verify`, `ops_gate`, `opsec_gates`, `persona`, `redaction`, `replication`, `replication_plan`, `retro`, `shred`: active operations, disposal, and gates.
- **VaultAdmin** (adds 2) — `key_ledger`, `vault`: custody of secrets.

### 1.4 Authorization query

`module_allowed(tier, module)` is the single authorization query. It returns `true` iff `module` appears in the requesting tier's slice; an **unknown module** (typo, removed, not-yet-classified) is **denied** — never an error, never an allow. Matching is exact (case- and whitespace-sensitive) and callers must not fall back to a broader rule on a miss. `modules_for(tier)` returns the slice; `rank_of` / `is_at_least` give the dense rank (`0..=3`) and the inclusive floor comparison.

---

## 2 · Compile-time `@tier` gate

> **STATUS: implemented — wired at entry-file scope; import-graph expansion pending.** The engine (`src/tier_gate.rs`) and the pass (`src/tier_gate_pass.rs`: per-file annotation scan + build-level runner, T-123) are live: the compiler runs both halves (Phases 28b/28c, `src/main.rs`), and a gate error fails `check` / `build` / `run` like any other policy error. Scope limits today: module references and waiver claims are collected from `@tier(…)` / `@tier_waiver(…)` occurrences in the compiled file's source (the call site passes the single file); multi-file/import-graph collection is the remaining follow-up. Waiver enforcement at the gate covers the *record projection*: record-or-deny, build-unit scope, module list, hard expiry, `E6005` on a missing/expired claim. No waiver record store is wired yet — call sites pass the empty set, so every escape hatch currently denies (**deny-until-record**, §3.6). §3.4–§3.7 (review, renewal caps, refusal log) remain record-system policy, not gate code.

### 2.1 Declaration

- A build unit (program / profile) declares its competence tier once, at program scope: `@tier(scout)`, `@tier(analyst)`, `@tier(operator)`, or `@tier(vault_admin)`. One word from the ladder, matching `Tier::word()`; the build-level scan reads it from the unit's source text — first `@tier` occurrence wins, later duplicates are ignored.
- **Missing declaration ⇒ Scout** (the tightest tier, fewest modules). Default-tightest, matching `module_allowed`'s posture.
- The declaration is read from the gated unit's source at check time (it is not embedded in the built artifact); on a violation the diagnostics name the declared tier and the tier that would minimally permit the module.

### 2.2 Gate rule

- The compiler resolves the build unit's tier and checks each collected module reference against `crate::tiers::module_allowed(declared_tier, module)`. Today's collection: the canonical `@tier(<module>)` annotation words in the unit's source — the current call site passes the single compiled file; full static-reference collection from import resolution is the pending expansion (status box).
- `true` → compile. `false` → **compile error**; the diagnostic names the module, the tier that would minimally permit it (via the `TIER_MODULES` table), and the declared tier, with the remediation options: drop the module, split the build unit, or obtain a recorded escape hatch (§3).
- **Unknown module ⇒ denied** (never error-then-allow). Case- and whitespace-sensitive, exactly as `module_allowed`.
- Diagnostic codes (assigned): `E6001` module not permitted at the declared tier · `E6002` module not in any tier slice · `E6003` invalid `@tier` declaration word · `E6005` claimed waiver record missing or expired; `E6004` reserved (unused). Waiver-use warning: `W6001`.
- Scope: this gate governs which **sensitive modules exist for a given build/profile** (e.g. stealth profiles, vault ops, spawn/`persona`, redaction admin). It **complements — does not replace** — the existing per-function annotation gates `@legal` (`E0100`), `@stealth` (`E0400–E0404`), and `@cra_class` (`W1900`/`E1900–E1903`). Runtime tier checks keep `module_allowed` as the single authorization query (defense in depth; no runtime call site is wired yet): a compile-time pass never authorizes a runtime call whose tier check fails.
- The escape hatch (§3) is the **only** bypass, and it must be explicit and recorded; there is no "trusted build" flag that silently widens a slice.

### 2.3 Acceptance pins (implemented — pinned by tests)

- A Scout build compiles exactly the 5-module Scout slice and errors on Analyst-only modules; likewise 19 / 38 / 40 at each rung.
- Only a `vault_admin` build compiles references to `vault` / `key_ledger`; every lower tier errors (mirrors `vault_secrets_are_vault_admin_only`).
- Missing `@tier` behaves as Scout.
- An unknown/typo'd module name errors (no fallback allow).
- A waiver in force compiles, emits the waiver warning, and fails when the record is missing or expired.

*Pin status (U-215, 2026-09-12): all of the above are enforced by tests — 26 engine tests in `src/tier_gate.rs` + 38 pass/build tests in `src/tier_gate_pass.rs`; `cargo test --lib tier_gate` = 64 passed, 0 failed.*

---

## 3 · Escape-hatch policy

The ladder is the rule; a waiver is a **documented, time-boxed exception**, never a silent bypass. This section is the policy in full: request path, review, time-boxing, renewal, logging, default-deny, and refusals. (Gate-side enforcement today covers the record projection only — record-or-deny, build-unit scope, module list, hard expiry, `E6005` on a missing/expired claim; the review, renewal-cap, and refusal-log stages (§3.4–§3.7) are record-system policy, not gate code. No waiver record store is wired yet, so every escape hatch currently denies — see §2 status box.)

### 3.1 Request path

1. **File** a tier-waiver request as a record with: id, requester, affected build unit(s), current tier, requested reach (the specific module(s) and/or tier), necessity statement, alternatives considered (promote properly / split build / drop module), requested duration, and proposed reviewers.
2. **Review** against the necessity and minimization rules: prefer a single-module exception over a full tier raise; the scope must be exactly one build unit; the duration must be the shortest that works; the elevation must be no wider than the need.
3. **Decide**: **grant** (with mandatory expiry) or **refusal** (§3.7). Every decision is recorded (§3.6).
4. **Reference**: a granted waiver must be referenced next to the `@tier` declaration of the build unit that uses it (`@tier_waiver(id: …)` — implemented: claims are parsed from `@tier_waiver(` occurrences, the `id: <value>` payload is the id, and every claim must resolve to a live record or the gate errors `E6005`), so the build loudly carries its own exception the way `@opsec_waiver` does today.
5. **Honor**: the gate honors only a live, complete, matching grant; anything else **denies**.

### 3.2 Review & approval authority

| reach requested | reviewers | who |
|---|---|---|
| any non-vault raise or module exception (Scout→Analyst, Analyst→Operator, or modules within those slices) | **1** | a reviewer at **Operator rank or above**, at or above the reach being requested |
| **anything including vault-admin capability** — tier VaultAdmin, the `vault` or `key_ledger` modules, or any key-custody surface | **2** | two reviewers, **at least one a VaultAdmin custodian** independent of the requesting unit |

- **No self-approval**: the requester can never be a reviewer, and a reviewer must not benefit from the waiver (no shared build unit, no downstream dependency on the gated module).
- **Two-person vault rule is absolute**: no emergency, urgency, or backfill path may reduce vault-admin review below two people.
- **Emergency path** (non-vault only): one Operator may issue a single-use, 24-hour grant if a second reviewer records confirmation within that window; if confirmation is missing at expiry, the grant lapses and any run/artifact relying on it is invalidated and re-run under the recorded outcome. Emergency use is itself logged and reviewed.

### 3.3 Time-boxing & expiry

- Every grant carries an explicit **`expires_at`**. **No perpetual waivers.**
- Maximum initial term: **30 days** (non-vault) · **7 days** (any vault-admin reach).
- **Expiry is a hard boundary.** At or after `expires_at` the gate denies the raised reach (fail-tight), and a build still carrying the waiver annotation fails its gate check with `E6005` (claimed waiver record missing or expired).
- Expiry is evaluated against a monotonic time derivation stamped by the event ledger; wall-clock rollback does not extend a grant.
- **Consecutive-renewal cap:** at most **2** renewals of the same module + build unit. A third consecutive request is refused unless accompanying a ladder review outcome (promote properly, or re-architect the build). This prevents waiver-as-permanent-backdoor.

### 3.4 Renewal

- Renewal is a **fresh request through the full path** (§3.1): new necessity statement, new review, new expiry. No auto-renewal.
- Renewal must include a **utilization report** for the expiring term: what the build actually needed, incidents, and why the need persists.
- **No retro-renewal**: a lapsed grant leaves a recorded gap; a request after a gap is a fresh request and is annotated as following a gap.
- Vault-admin renewals require the **full two-person review again**, with at least one reviewer who did not approve the previous term.

### 3.5 Mandatory logging / audit trail

- **Every** event is recorded append-only: `REQUEST`, `GRANT`, `REFUSAL`, `RENEWAL`, `EXPIRY`, `REVOCATION`, `EMERGENCY_USE`.
- Record fields: id, requester, module(s), tier before/after, scope (exactly one build unit), necessity, reviewers and their roles, decision, issued/expires timestamps, renewal-chain pointer, incident pointers.
- **Compile-time emission:** while a waiver is in force, the build compiles with the waiver warning `W6001` (mirrors `@opsec_waiver` → `W5001`) — no build uses an exception silently. (The warning fires when the caller supplies the live record; no record store is wired yet, so no in-force waiver can reach the CLI today — see §2 status box.)
- **Runtime logging where applicable:** waiver-gated operations also emit to the event ledger (`ledger_events` surface) so the exception is visible in run-time audit, not only at build time.
- The trail is immutable: corrections are **appended**, never rewritten. A missing or stale record is treated as **absence of grant** — deny.
- **Periodic review:** active waivers are re-listed at least monthly; aggregate counts are the drift signal.

### 3.6 Default-deny posture

Absent a valid, complete, unexpired, recorded grant → **deny**. Unknown module → deny. Missing reviewer signature → deny. Ambiguous scope → deny. Nothing in this policy ever widens a slice implicitly, and no failure mode of the record system yields an allow.

### 3.7 Refusal record-keeping

- Refusals are **first-class records** with the same schema plus a reason category: `need-unproven`, `scope-too-broad`, `duration-too-long`, `insufficient-review`, `vault-two-person-unsatisfiable`, `policy-by-design`.
- Refusals are retained at least as long as grants and are **never deleted to make room** for a later grant; a later grant for the same module references any prior refusal.
- Repeated refusals for the same module trigger a **ladder review**: either the tier model is wrong (fix the table properly) or the build needs restructuring. Refusals are evidence, not noise.

---

## 4 · Failure modes

| # | failure mode | how it shows up | posture / mitigation |
|---|---|---|---|
| 1 | **Fail-open gate** | an unknown/unparseable `@tier` or unknown module quietly passes | default-tightest everywhere: missing declaration ⇒ Scout; unknown module denied; never error-then-allow (mirrors `module_allowed`; pinned by `unknown_module_denied_default_tightest`) |
| 2 | **Enforcement-scope over-trust** *(gate live at entry-file scope)* | someone assumes `@tier` covers more than the wired scope — multi-file builds, full static references, ledger-backed waivers | §2 status box states the scope precisely: the annotation scan and build gate are live; import-graph collection and the waiver record store are pending; module references are checked where collected |
| 3 | **Waiver drift / permanent backdoor** | a short grant renewed forever | hard expiry, 30d/7d caps, 2-renewal ceiling, monthly review |
| 4 | **Missing or stale record** | build references a waiver whose record is lost or expired | record-or-deny: no record, stale record, or failed integrity ⇒ deny |
| 5 | **Clock rollback** | wall clock moved back to extend a grant | expiry from monotonic ledger-stamped derivation, not raw wall clock |
| 6 | **Scope creep** | an approved waiver widened after the fact | granularity is (module set × one build unit × term); any widening is a new request |
| 7 | **Rubber-stamp / self-approval** | requester approves own waiver; vault reach approved solo | no self-approval; separation of duties; two-person vault rule with an independent custodian, absolute |
| 8 | **Tier mispromotion / demotion lag** | demoted agent still compiles against its old slice | the tier is declared per build unit and re-evaluated at every compile; runtime `module_allowed` stays the authorization query (defense in depth) |
| 9 | **Doc-vs-code drift** | this file diverges from `src/tiers.rs` | code is source of truth (header); counts pinned 5/19/38/40; structural invariants tested in `src/tiers.rs` (`ladder_is_monotone`, `tables_non_empty_and_wellformed`); update both in one change |
| 10 | **Log gap** | gate honors a grant that was never recorded | gate honors only matching recorded grants; runtime gets its own waiver events; missing trail counts as no grant |

---

## Appendix · Self-check pins

- Cumulative module counts, re-derived from `TIER_MODULES` in `src/tiers.rs`: **Scout 5 · Analyst 19 · Operator 38 · VaultAdmin 40** (sum of deltas 5+14+19+2 = 40; every list ASCII-sorted and duplicate-free).
- Structural invariants enforced by tests in `src/tiers.rs`: monotone ladder (each rung strictly extends the one below), table↔`Tier::ALL` alignment, vault/`key_ledger` VaultAdmin-only, unknown-module denial, exact-match semantics, serde/Display words pinned (`scout`/`analyst`/`operator`/`vault_admin`).
- This document is the B1.1.3 deliverable, de-drifted against the implementation (U-215, 2026-09-12); the `@tier` gate (engine B1.1.2 + build-level wiring T-123) is implemented and wired at entry-file scope (§2 status box).
