# SMB Deal Hunter Scraper Spec

## Goal

Collect public business-for-sale deal records from `https://www.smbdealhunter.xyz/` and linked public detail pages into a normalized JSONL dataset.

## Public Surfaces Confirmed

- `https://www.smbdealhunter.xyz/robots.txt` allows general crawling and disallows `/login`.
- `https://www.smbdealhunter.xyz/sitemap.xml` listed 450 URLs, including 439 `/p/...` post URLs and 332 deal-post candidates, during the May 24, 2026 smoke run.
- Public Beehiiv post HTML includes deal links to `https://app.smbdealhunter.xyz/item-detail?recordId=...`.
- `https://app.smbdealhunter.xyz/robots.txt` has no disallow rules.
- Softr detail page config exposes these public field names: `Name`, `Industry`, `Location`, `Asking Price`, `Cash Flow/EBITDA`, `Revenue`, `Year Established`, `Represented by Broker/Intermediary?`, `Photo`, `Date Added`, `My 2 Cents`, and `Helen's 2 Cents`.

## Compliance Rules

- Respect robots.txt.
- Do not request `/login`.
- Do not bypass paywalls, authentication, Turnstile, or member-only flows.
- Use sitemap-driven discovery instead of brute-force URL guessing.
- Default to one request per second per host.
- Save source URLs and timestamps for auditability.

## Dataset Fields

Each JSONL row should contain:

- `record_id`
- `source_post_url`
- `detail_url`
- `post_title`
- `published_at`
- `name`
- `industry`
- `location`
- `asking_price`
- `cash_flow_ebitda`
- `revenue`
- `year_established`
- `broker_represented`
- `photo_url`
- `date_added`
- `commentary`
- `source_crawled_at`
- `normalized_asking_price_usd`
- `normalized_revenue_usd`
- `normalized_cash_flow_ebitda_usd`
- `asking_price_to_ebitda_multiple`

Optional future fields:

- `source_listing_url`
- `broker_name`
- `listing_status`

## Scraper Architecture

1. Fetch `robots.txt` for both hosts and fail closed on disallowed paths.
2. Fetch `sitemap.xml`.
3. Filter post URLs to `/p/new-deals...` and `/p/new-off-market-businesses...`.
4. Fetch each post HTML with HTTP. The script is structured around a batch-compatible helper; the current interpreter uses a sequential `http.get` shim because `http.batch` checks but is not available in this runtime.
5. Extract all `app.smbdealhunter.xyz/item-detail?recordId=...` links.
6. Deduplicate by `record_id`.
7. Parse fields from the surrounding post HTML.
8. Fetch public Softr detail pages for status/enrichment and record authorization boundaries without bypass attempts.
9. Write businesses/posts JSONL, GraphJSON, skipped/error logs, and a run summary.

## Current Implementation

The production Tallow implementation is at:

`scripts/smbdealhunter_public_pipeline.tl`

It performs robots/sitemap discovery, public post fetches, detail-link extraction, business deduplication, post-level field parsing, public Softr detail status checks, GraphJSON export, and optional authorized Airtable export via the official Airtable REST API.

Outputs:

- `artifacts/smbdealhunter/smbdealhunter_businesses.jsonl`
- `artifacts/smbdealhunter/smbdealhunter_posts.jsonl`
- `artifacts/smbdealhunter/smbdealhunter_graph.json`
- `artifacts/smbdealhunter/smbdealhunter_errors.jsonl`
- `artifacts/smbdealhunter/smbdealhunter_run_summary.json`

Smoke run:

```powershell
$env:SMBDEALHUNTER_SMOKE_LIMIT='2'
$env:SMBDEALHUNTER_CONCURRENCY='1'
$env:SMBDEALHUNTER_REQUEST_DELAY_MS='1000'
cargo run --bin tallow -- run scripts\smbdealhunter_public_pipeline.tl
```

Full public run:

```powershell
Remove-Item Env:\SMBDEALHUNTER_SMOKE_LIMIT -ErrorAction SilentlyContinue
$env:SMBDEALHUNTER_CONCURRENCY='1'
$env:SMBDEALHUNTER_REQUEST_DELAY_MS='1000'
cargo run --bin tallow -- run scripts\smbdealhunter_public_pipeline.tl
```

Authorized Airtable mode is intentionally separate from public scraping. It requires all three environment variables and must use the official Airtable REST API:

- `AIRTABLE_API_TOKEN`
- `AIRTABLE_BASE_ID`
- `AIRTABLE_TABLE_ID_OR_NAME`

When those variables are present, the script pages through Airtable records with the official `offset` parameter and writes:

- `artifacts/smbdealhunter/smbdealhunter_airtable_authorized.jsonl`
- `artifacts/smbdealhunter/smbdealhunter_merged_authorized.jsonl`

## Known Gaps

- Softr detail values may require JavaScript rendering or the platform's public runtime requests; the static HTML reliably exposes schema but may not include every record value.
- Some older posts use different wording, so field extraction should be validated against a sample across 2023-2026.
- The script intentionally does not use credentials or hidden APIs.
- Money normalization currently extracts digits from public money strings. Abbreviated values such as `$1.2M` should be reviewed before relying on numeric multiples.
- `http.batch` is present in existing Tallow scripts and passes checking, but this interpreter run reports it as unavailable. `scripts/smbdealhunter_public_pipeline.tl` uses a sequential `batch_get` shim over `http.get` until the batch backend is wired into this runtime.
- `http.get` supports explicit headers in this runtime, so authorized Airtable mode can send the required bearer token without scraping credentials from the public site.

## Verification Plan

- `cargo run --bin tallow -- check scripts\smbdealhunter_public_pipeline.tl`
- Run a smoke crawl with `SMBDEALHUNTER_SMOKE_LIMIT=2`.
- Validate JSONL and GraphJSON artifacts.
- Compare extracted records against 5 manually inspected recent posts.
- Confirm no requests were made to `/login`.
- Confirm 401/403 responses are classified as authorization boundaries.
- Run the full sitemap crawl after field quality passes.
