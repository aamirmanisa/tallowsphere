# Cargo.lock scope note

## Decision

Recommendation: treat root `Cargo.lock` as outside the current Codex migration scope checklist, unless a later migration step explicitly changes Rust manifests and intentionally regenerates the lockfile.

## Narrow evidence

- Root lockfile status is currently dirty: `git status --short --untracked-files=no -- Cargo.lock` returned `M Cargo.lock`.
- The current lockfile diff is substantive, not tooling noise: `git diff --stat -- Cargo.lock` reported 70 changed lines with 55 insertions and 15 deletions.
- The visible diff updates application dependencies such as `axum` (`0.7.9` -> `0.8.9`), `axum-core`, `axum-macros`, adds `hyper-tls`, and changes the root `tallow` package dependency set to include `base64`, `blake3`, `reqwest`, and `tempfile` in the lockfile entry.
- Those changes match broader Rust product dependency movement, not editor or Codex-only configuration. They affect runtime/library resolution rather than `docs/codex` content.
- A scoped search in `docs/codex/next-full-work` for `Cargo.lock`, `cargo lock`, `scope`, or `migration` found no existing file content tying the root lockfile to this migration work.
- `git diff -- Cargo.toml` returned no diff, so the dirty lockfile does not currently have a paired manifest change in this workspace slice. That makes it even less appropriate to absorb into a Codex migration checklist item by default.

## Assessment

The root `Cargo.lock` is dirty now, but the evidence points to broader product development or previously generated dependency churn, not Codex configuration work. Pulling it into the Codex migration scope would mix an active Rust dependency change with documentation/process migration work and would increase the chance of unrelated churn.

## Checklist guidance

For the Codex migration checklist item, mark root `Cargo.lock` as out of scope for this migration pass.

Only move it into scope if both conditions become true:

1. A Codex migration task explicitly changes one or more Rust `Cargo.toml` files.
2. The resulting lockfile update is intentionally regenerated and reviewed as part of that same Rust change.
