# Metadata minimization (B7.2.1–B7.2.3)

Scope: the incidental metadata that travels *with* released material —
URLs, names, timestamps, sizes. Field-level redaction
(`src/redaction.rs`) decides **which document fields** leave; this module
(`src/metadata_min.rs`) minimizes the metadata attached to the items that
carry them. Pure, deterministic, no I/O, no clock, no network.

## B7.2.1–B7.2.3 — transforms

| Transform | Function | Rule (pinned) |
|---|---|---|
| URL redaction | `redact_url` | trim outer whitespace, cut at first `?`/`#`, keep `scheme://host/path`; empty (or empty after cut) → `BadInput("url")` |
| Name hashing | `hash_name` | `"n-"` + sha256 hex (64 lowercase chars) of the UTF-8 bytes; byte-exact (no case fold / normalization); empty → `BadInput("name")` |
| Timestamp coarsening | `coarse_timestamp` | floor to the hour via `div_euclid(3_600_000)` (negatives floor toward −∞: `-1 → -3_600_000`; `i64::MIN` saturates) |
| Size padding | `pad_size` | 0 → 0, else next 4096-byte multiple (`1 → 4096`, `4096 → 4096`, `4097 → 8192`); saturates |

## Policy

`MetaPolicy { redact_urls, hash_names, coarse_timestamps, pad_sizes }` —
`MetaPolicy::strict()` = all true; `Default` = all false (verbatim
pass-through). `minimize(&policy, &item)` applies the enabled transforms to
one `MetaItem` (`id` always required — empty → `BadInput("id")`); disabled
transforms copy the field verbatim, including empty name / `Some("")` URL.
`minimize_all` preserves input order; empty slice → `Ok(vec![])`; first
failure aborts the run. Equal names dedupe: `hash_names` maps equal names to
equal `n-<hex>` (deterministic, unsalted).

## Audit — what survives redaction TODAY (`src/redaction.rs`, read-only review)

Facts from the current redaction/release pipeline:

- **Top-level object keys only.** `redact_value` (l.143) applies rules to
  top-level keys of a JSON object; anything nested below a top-level key is
  untouched unless the whole field is removed/hashed.
- **Key names survive `Mask`/`Hash`.** `Remove` (l.159) drops the key
  entirely (existence withheld), but `Mask`/`Hash` keep the key name in the
  released object — field *names* are metadata that survives.
- **Length survives `Mask`** (l.193–204): prefix + `*`s + suffix keeps the
  exact char count of the original string, so the secret's length is
  observable. Non-string values become the literal `"[REDACTED]"` (l.183).
- **Unsalted, joinable pseudonyms.** `Hash` → sha256 hex of the canonical
  serialized value (l.171–176). Stable across releases: equal values link,
  and low-entropy values (dates, pin codes, small id spaces) are
  dictionary-attackable.
- **Release-level metadata is recorded verbatim.** `produce_release`
  (l.246–279) writes `rules_applied` (rule specs carry field names),
  `redacted_fields` (which fields existed), `original_hash` /
  `released_hash` (stable digests — the same original is correlatable across
  releases), and `created_ms` (caller clock, exact ms).
- **Out-of-document metadata is not processed at all.** URLs, file names,
  sizes, and timestamps carried *beside* a document (attachment metadata,
  index rows) never pass through `redact_value`; query strings/fragments,
  name text, exact sizes, and exact creation times survive any release gate
  (`export_gate`, l.307). That gap is what this module closes.

## Limits

- Obfuscation-grade minimization, **not** anonymization: every transform is
  string/arithmetic-level with no cryptographic salt, MAC, or key.
- `hash_name` is unsalted: low-entropy names (common first names, hostnames)
  are brute-forceable from the hash; joinability is by design.
- `redact_url` does no URL parsing/validation — malformed inputs pass
  through with only the cut; userinfo (`user@host`) is preserved; the whole
  query is dropped (no parameter allowlist).
- `coarse_timestamp` is a UTC hour floor with no jitter: the bucket edge
  still reveals up to one hour, and repeated samples can bracket the instant.
- `pad_size` leaks the block count: the true size is known to within 4 KiB;
  `0` stays `0` (emptiness is observable).
- `id` is never transformed — identifier linkability is the caller's
  problem; so is combining policies with `redaction::ReleaseBundle` (the
  release audit should *record* the policy applied — integration follow-up).
- Not wired into `lib.rs` yet (parent does that: `pub mod metadata_min;`).

Verify with: `cargo test --lib metadata_min`.
