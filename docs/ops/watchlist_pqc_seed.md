# PQC watchlist seeding — verified sources, ready to run (B4.2.3)

Status: **ready-to-run** (prepared 2026-09-11). The seeding gesture itself is
a **human step** — this doc makes it mechanical.

`src/watchlist.rs`'s `seed_pqc_milestones()` returns six `(name, source_hint)`
template pairs for post-quantum-migration milestones. The design is
**VERIFY_BEFORE_ADDING**: nothing is ever auto-added at runtime — the operator
picks rows and adds them via `Watchlist::add(...)`. Every hint (now carrying a
concrete, probe-verified URL) still ends with the `VERIFY_BEFORE_ADDING`
("verify before adding") marker: a verified *URL* is not a verified
*milestone status*; the operator still confirms currency and relevance before
adding.

Provenance: live probes through the box Tor stack (SOCKS5 `127.0.0.1:9050`,
verified exit `193.189.100.195` ≠ box IP `203.0.113.1`) on 2026-09-11,
recorded in
`artifacts/tallow_intel_uplift_2026-09-11/impl/B4.2.3_verified_targets.md`.
The same concrete sources ride the seed hints in `src/watchlist.rs`
(`PQC_MILESTONE_SEEDS`).

## Exact `Watchlist::add` shape

Source of truth: `src/watchlist.rs` (`Watchlist::add`):

```rust
pub fn add(
    &mut self,
    name: &str,      // non-empty (empty/whitespace-only rejected); stored verbatim
    source: &str,    // non-empty (empty/whitespace-only rejected); stored verbatim
    cadence_ms: i64, // must be > 0
    tags: &[String],
    now_ms: i64,
) -> Result<&WatchTarget, WatchlistError>
```

Note the argument order: `cadence_ms`, then `tags`, then `now_ms`. Semantics:
adding schedules the target immediately (`next_due_ms = now_ms`);
`mark_checked(id, now_ms)` is the only call that advances the scan clock;
`trigger(id, event, now_ms)` records an event without touching the schedule.

## Verified rows, ready to seed

Suggested cadence: **30 days** (`30 * 24 * 60 * 60 * 1_000 = 2_592_000_000` ms).
Suggested tag: **`"pqc"`** on every row.

| # | Seed name | Verified source (probe 2026-09-11, via Tor) |
|---|---|---|
| 1 | ML-KEM (FIPS 203) deployment in TLS hybrid key exchange | `https://csrc.nist.gov/projects/post-quantum-cryptography` (**200**) + IETF TLS WG `https://datatracker.ietf.org/wg/tls/` (**200**) |
| 2 | ML-DSA (FIPS 204) signing migration for firmware and release artifacts | `https://csrc.nist.gov/` (**200**) |
| 3 | SLH-DSA (FIPS 205) availability in HSM and code-signing stacks | `https://csrc.nist.gov/` (**200**) |
| 4 | CNSA 2.0 transition deadlines for national-security systems | `https://www.nsa.gov/Cybersecurity/Post-Quantum-Cybersecurity/` — **403 via Tor, see caveat** |
| 5 | Legacy algorithm retirement (RSA / ECDSA / ECDH deprecation dates) | `https://csrc.nist.gov/pubs/sp/800/131/a/r2/final` (**200**) |
| 6 | Harvest-now-decrypt-later (HNDL) re-assessment for long-lived secrets | *internal key-inventory review — no URL* |

Rows 1, 2, 3 and 5 are the four verified-reachable web sources. Row 4's URL
is real but Tor-blocked. Row 6 has no URL at all.

### NSA / CNSA-2.0 caveat (row 4)

`nsa.gov` (and `media.defense.gov`, the CNSA 2.0 algorithms PDF) **403s Tor
exits** — reputation-gated, not nonexistent. Reachability from a non-Tor
vantage was **not** tested (egress policy). `https://www.cnss.gov/CNSS/` does
not connect at all (`000`; the site appears retired — treat CNSS advisories
as NSA-domain content, same 403). If row 4 is seeded, do not scan it through
the box Tor stack expecting content: use a non-Tor vantage, or rely on
secondary/aggregator coverage and treat the primary URL as a human-check
link. Do not claim this source as "verified reachable" under the current
egress policy.

## Operator steps

1. **Pick the rows** you want scheduled. The four verified-reachable rows
   (1, 2, 3, 5) are the low-friction default; add row 4 only with the caveat
   above in hand; add row 6 only if you want a scheduled reminder of an
   internal review.
2. **Capture one `now_ms`** for the whole seeding run, e.g. `date +%s` × 1000
   or `SystemTime::now().duration_since(UNIX_EPOCH)`.
3. **Add the rows** with the ready-to-run snippet below (or call
   `Watchlist::add` directly with the same name/source/cadence/tags).
4. **Record the deed:** append a `seeded 2026-…` line to
   `artifacts/tallow_intel_uplift_2026-09-11/impl/B4.2.3_verified_targets.md`
   (that file is the provenance record; this doc is the runbook).
5. **Persistence:** the registry is **in-memory** today (no save/load) —
   don't block seeding on it. If a persisted watchlist location is wanted,
   open a follow-up code ticket; until then, re-seeding after a restart is
   the honest story.

## Ready-to-run snippet

```rust
use tallow::watchlist::Watchlist;

const CADENCE_30D_MS: i64 = 30 * 24 * 60 * 60 * 1_000; // 2_592_000_000

fn seed_pqc_watchlist(
    wl: &mut Watchlist,
    now_ms: i64,
) -> Result<(), tallow::watchlist::WatchlistError> {
    let tags = vec!["pqc".to_string()];

    wl.add(
        "ML-KEM (FIPS 203) deployment in TLS hybrid key exchange",
        "https://csrc.nist.gov/projects/post-quantum-cryptography + https://datatracker.ietf.org/wg/tls/",
        CADENCE_30D_MS,
        &tags,
        now_ms,
    )?;
    wl.add(
        "ML-DSA (FIPS 204) signing migration for firmware and release artifacts",
        "https://csrc.nist.gov/",
        CADENCE_30D_MS,
        &tags,
        now_ms,
    )?;
    wl.add(
        "SLH-DSA (FIPS 205) availability in HSM and code-signing stacks",
        "https://csrc.nist.gov/",
        CADENCE_30D_MS,
        &tags,
        now_ms,
    )?;
    // Row 4 — NSA/CNSA-2.0 caveat: nsa.gov 403s Tor exits; scan from a
    // non-Tor vantage (or treat the URL as a human-check link).
    wl.add(
        "CNSA 2.0 transition deadlines for national-security systems",
        "https://www.nsa.gov/Cybersecurity/Post-Quantum-Cybersecurity/ (403 via Tor — use a non-Tor vantage)",
        CADENCE_30D_MS,
        &tags,
        now_ms,
    )?;
    wl.add(
        "Legacy algorithm retirement (RSA / ECDSA / ECDH deprecation dates)",
        "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final",
        CADENCE_30D_MS,
        &tags,
        now_ms,
    )?;
    // Row 6 (HNDL) is an internal key-inventory review — no URL. Add it only
    // if you want a scheduled reminder, e.g.:
    // wl.add(
    //     "Harvest-now-decrypt-later (HNDL) re-assessment for long-lived secrets",
    //     "operator key-inventory review (internal — no URL)",
    //     CADENCE_30D_MS,
    //     &tags,
    //     now_ms,
    // )?;
    Ok(())
}
```

The same names/URLs come out of `seed_pqc_milestones()` if you prefer to
drive the loop from the template — remember every hint still ends with
`— verify before adding`; strip it or keep it in the stored source, the
operator's call.

## Re-running the probes (when refreshing this doc)

```bash
for u in \
  https://csrc.nist.gov/projects/post-quantum-cryptography \
  https://datatracker.ietf.org/wg/tls/ \
  https://csrc.nist.gov/ \
  https://www.nsa.gov/Cybersecurity/Post-Quantum-Cybersecurity/ \
  https://csrc.nist.gov/pubs/sp/800/131/a/r2/final
do
  printf '%s ' "$(curl -sL -o /dev/null -w '%{http_code}' --socks5-hostname 127.0.0.1:9050 "$u")"
  echo "$u"
done
```

## Coverage

`cargo test --lib -- watchlist` — the seed tests pin the marker on every
hint, the six-seed structure, and the concrete verified URLs
(`seed_pqc_milestones_carry_verified_sources`).
