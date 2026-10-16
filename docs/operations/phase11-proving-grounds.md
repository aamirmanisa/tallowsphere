# Phase 11 controlled proving grounds

Status: local fixture proof only.

Phase 11 proves that Tallow-produced local artifacts can be interpreted by two downstream product surfaces without expanding to live scraping, production databases, or all-sites rollout.

## Scope

Accepted Phase 11 scope is limited to:

- a tiny Tallow Search route-mix proof over synthetic `fixture://` targets;
- a HackTheCart artifact-to-product import preview fixture;
- hash-checked local artifacts under `artifacts/phase11/controlled-local-proof/phase11-controlled-local-proof-001/`;
- Rust contract tests in the owning subproject workspaces.

## Proof artifacts

Primary proof bundle:

- `artifacts/phase11/controlled-local-proof/phase11-controlled-local-proof-001/tallow-search/route_mix_report.json`
- `artifacts/phase11/controlled-local-proof/phase11-controlled-local-proof-001/tallow-search/local_targets.json`
- `artifacts/phase11/controlled-local-proof/phase11-controlled-local-proof-001/hackthecart/tallow_import_preview.json`
- `artifacts/phase11/controlled-local-proof/phase11-controlled-local-proof-001/hackthecart/import_contract_fixture.json`
- `artifacts/phase11/controlled-local-proof/phase11-controlled-local-proof-001/hash-checks.json`
- `artifacts/phase11/controlled-local-proof/phase11-controlled-local-proof-001/artifact_manifest.json`

The Tallow Search proof records `network_io=none`, `target_scope=fixture-only`, `T4=0`, and `browser_budget_used_count=0`.

The HackTheCart proof records `database_writes=false`, `search_index_writes=false`, `remote_calls=false`, one accepted product preview, and one quarantined invalid fixture row.

## Local commands

Run from the Tallow Search workspace:

```bash
cd ~/Nixe/tallow-search
cargo test -p tallow-search-api --test phase11_route_mix_artifact_contract -- --nocapture
```

Run from the HackTheCart workspace:

```bash
cd ~/Nixe/hackthecart
cargo test -p hackthecart-api --test phase11_tallow_import_contract -- --nocapture
```

Regenerate the proof sub-artifacts with an explicit local output root:

```bash
cd ~/Nixe/tallow-search
PHASE11_PROOF_ROOT=~/Nixe/artifacts/phase11/controlled-local-proof/phase11-controlled-local-proof-001 \
  cargo test -p tallow-search-api --test phase11_route_mix_artifact_contract \
  phase11_route_mix_writes_hash_checked_local_artifacts -- --nocapture

cd ~/Nixe/hackthecart
PHASE11_PROOF_ROOT=~/Nixe/artifacts/phase11/controlled-local-proof/phase11-controlled-local-proof-001 \
  cargo test -p hackthecart-api --test phase11_tallow_import_contract \
  phase11_hackthecart_import_writes_hash_checked_local_artifacts -- --nocapture
```

## Human-gated / non-claims

Phase 11 does not claim:

- live external scraping or crawling;
- production Tallow Search execution readiness;
- production HackTheCart import readiness;
- production database or search-index writes;
- all-sites or full-catalog rollout;
- credential/vault/secret readiness;
- legal/compliance approval for production runs;
- deploy, release, publish, or remote service changes;
- paid API or large benchmark readiness;
- Windows support.

Any move from fixture proof to live runs, production databases, real credentials, or broad rollout requires explicit the operator approval in that session.
