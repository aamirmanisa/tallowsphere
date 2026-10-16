# Persona lifecycle — single-use identities, burn triggers, operator duties (P1 W5-P3)

Scope: what a persona is in this system, the **never-reuse** invariant, how a
burn fires, what a burn records, and what an operator must do (and must not
do). Code of record: `src/persona.rs` (registry + burn adapter),
`src/vault/persona_store.rs` (sealed custody + firewall), `src/cli/canary_cmd.rs`
(`tallow canary burn-cycle` drill).

## The persona

A persona is one identity bundle: `id`, `cover_class`, `compartment`, `legend`
(backstory / contact surface / provenance), one unique `fingerprint_seed`, and
a lifecycle (`Active` → terminal `Burned { at_ms, method, quarantine }`).

The **registry** (`PersonaRegistry`) holds the personas plus the **tainted
(burned) id set** — the never-reuse ledger. The sealed form round-trips the
burned set, so a reloaded registry still refuses burned ids.

## The never-reuse invariant (E5003)

A burned id must never act again. Enforced at every gate (deny-by-default, no
silent repair):

- `assert_reusable(id)` — hard-fail `BurnedReuse` for tainted ids;
- `open_bundle(id)` — the A5.1.2 open-bundle flow refuses burned ids (no
  bundle material is handed out);
- `register(persona)` — refuses a burned id even as a "new" object with a
  fresh seed;
- the vault custody boundary (`unseal_checked` / `load_checked` in
  `src/vault/persona_store.rs`) refuses loads and cross-persona references
  that violate separation, including reachability of burned material.

A second burn is a caller bug and **surfaces** (`AlreadyBurned`) rather than
being silently idempotent.

## Burn triggers (when a persona dies)

`BurnTrigger` is the runtime adapter for the compile-time `@burn_plan`
contract; all three kinds fire the same terminal disposition:

- `PlanReached { plan }` — the plan's scheduled point (e.g. `after: .run`)
  was reached;
- `CanaryAlert { origin, canary }` — a canary/leak alert implicated the
  persona (detection-ops trigger);
- `OperatorDecision { reason }` — an operator ordered the burn.

`registry.burn_on_trigger(id, at_ms, method, quarantine, trigger)` → returns
a `BurnRecord` (audit), and thereafter every gate above refuses the id.

## What a burn records

`BurnRecord` → `to_json()`:
`id`, `at_ms`, `method`, `quarantine`, `trigger`, `trigger_kind`
(`plan_reached` | `canary_alert` | `operator_decision`).

Recorded into the run-evidence JSONL (`TALLOW_RUN_EVIDENCE_DIR`) with
`kind = "persona_burn"`. Method mirrors the corpus burn-plan literal
(`revoke_and_quarantine` default, `revoke_only`, `quarantine_only`);
quarantine is `quarantine` or `none`.

## Operator duties

1. **On a canary/leak alert that implicates a persona: burn it.** Do not wait
   for a second signal; the alert is the trigger.
2. **Burn with the doctrine default** (`RevokeAndQuarantine` + `Quarantine`)
   unless the run's plan says otherwise; state the trigger honestly
   (alert origin/canary, or your reason).
3. **Verify the refusal after burning**: `open_bundle` and `assert_reusable`
   must both refuse (`BurnedReuse`); re-registration must refuse too. If any
   gate still lets the id through, that is an incident — stop and record it.
4. **Rotation = a new persona**, not a revived id: new id, fresh
   `fingerprint_seed`, fresh compartment where the plan says so.
5. **Never** edit/delete the burned set to "unstick" a run; the ledger is the
   point.

## Running the burn-cycle drill

```
tallow canary burn-cycle [--out DIR] [--json]
```

Steps asserted in one run (each recorded): create → use (open bundle) →
canary-alert trigger → burn → refuse (re-use / re-registration / hard-fail /
double burn). Output: `<out>/burn_cycle.json` + run-evidence records
(`persona_burn`, `persona_burn_cycle`). Exit `0` = all refusals held;
`2` = a gate failed to refuse (fail loud — the drill is not evidence if a
persona stays usable after a burn). `64` = usage.

## Honest wiring status (2026-09-16)

- Registry + gates + burn adapter: **implemented and unit-tested**
  (`src/persona.rs` tests; vault custody tests).
- CLI drill (`canary burn-cycle`): **implemented**; run it before trusting a
  fresh build (see `artifacts/…/p1-wave-2026-09-16/` for the wave evidence).
- The **automatic** hook from a live `tallow canary cycle` leak alert into
  `burn_on_trigger` is **not** wired yet — today the burn is executed by the
  operator (drill or a programmatic `burn_on_trigger` call). Treat that as an
  open P2 item, not a guarantee.
- `@burn_plan` plan-point burns remain a compile-time contract
  (`src/opsec_gates.rs`); the runtime adapter above is its execution
  complement.
