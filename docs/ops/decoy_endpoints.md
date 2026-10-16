# Decoy endpoints — ops guide

Self-honeypot surfaces rendered by `src/decoy_endpoints.rs` (B5.6). A decoy
endpoint is a plausible-looking page served on **our own** infrastructure
that nothing legitimate should ever reach: any request is signal, and its
embedded canary tokens (`TLW-…`, see `src/canary_tokens.rs`) prove a harvest
if they later surface elsewhere.

## Purpose

- Turn scanners, credential-stuffers, and corpus-harvesting crawlers into
  *detected* events instead of invisible noise.
- Plant tripwires: the page text and attributes carry canary tokens; honeypot
  links (`rel="nofollow"`) point at nested `/trap/…` paths that exist only to
  be followed.
- Feed monitoring: every observed request is recorded in a `HitLog`, so a
  decoy hit is a citable lead, not a hunch.

## Deploy steps

1. Define `DecoySpec`s (id, path, title, `token_count` 1–32). Paths must
   start with `/` and contain no `..`.
2. Validate the whole estate: `validate_all(&specs)` — refuses bad fields and
   duplicate paths (`DupPath`).
3. Render each page: `render_endpoint(&spec)`. Output is deterministic —
   the same spec renders byte-identical HTML, so re-deploys diff cleanly.
4. Serve the HTML at `spec.path` as a static endpoint. **Weak bait first**:
   paths that look like forgotten artifacts (`/analytics/export.csv`,
   `/admin/db-backup.sql`), never anything that could alias a real service.
5. Keep `deploy_doc(&specs)` (deterministic manifest, sorted by id) next to
   the deployment so the served estate is auditable at a glance.
6. Never link decoys from real navigation and never mention them in public
   robots/sitemaps; a decoy that legitimate users find is a support ticket.

## Hit monitoring (HitLog)

- On every request, record: `HitLog::record(endpoint_id, at_ms, source_hint)`
  — `source_hint` should carry the log line / referrer / upstream-proxy id.
- Reads: `HitLog::for_endpoint(id)` returns hits sorted by `(at_ms, insertion
  order)`; `HitLog::count()` is the estate-wide total.
- The log is in-memory and pure (no clock, no IO): persistence is the
  caller's job — append `DecoyHit`s to the ops log/database in the request
  path and rebuild a `HitLog` when reading.
- Triage: zero hits is the expected steady state. Non-zero → treat as a lead:
  correlate `source_hint`, check whether bait was fetched, and decide whether
  the harvesting IP/ASN should be watched (see watchlist/indicator tooling).

## Canary rotation notes

- Tokens are derived per `(id, path, title, index)`: changing any one input
  (e.g. bumping a generation marker in `title`) rotates the entire token set
  for that endpoint — re-render and redeploy together.
- Rotate on: suspected leak, token sighting in the wild, staff change with
  deploy access, or on the same schedule as other planted canaries.
- Keep retired tokens in the hit-record history: a later sighting of an old
  token still maps to the deployment it came from (provenance, not alert
  spam).
- After rotation, verify with `render_endpoint` output that the new page
  still contains `token_count` valid tokens (every `TLW-…` passes
  `canary_tokens::is_valid`) and that trap hrefs are unique.

## Failure modes to avoid

- Deploying overlapping paths (two decoys on one path) — `validate_all`
  refuses this; don't bypass the check.
- Serving decoys on infrastructure where a 404 already conveys the same
  signal — decoy value comes from looking like a *find*.
- Rotating only some endpoints: stale tokens elsewhere re-alert on old
  deployments and add noise.
