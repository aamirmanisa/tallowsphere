# myvapeisland.com — CSP draft (staged, not applied)

**Date:** 2026-09-12 · **Status:** READY TO APPLY after a browser pass · **Source:** live-page inventory (local fetch of `https://myvapeisland.com/`, 16.8 MB single-file HTML)

## Asset inventory (verified)
- **Scripts:** 8 × inline `<script>` blocks (bundler manifest/ext_resources/template + page logic). **Zero external script sources.**
- **Styles:** 4 × inline `<style>` blocks; fonts declared via inline `@font-face` CSS; only `preconnect` links to `fonts.googleapis.com` / `fonts.gstatic.com` (no external font files referenced — 0 `woff/woff2` URLs found).
- **Images:** 18 inline SVGs, 5 `data:` URIs.
- **No forms, no iframes, no analytics/trackers** found in the page.
- Outbound links (Google Maps etc.) are plain anchors — unaffected by CSP.

## Proposed policy

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'
```

- `'unsafe-inline'` for script/style is required (everything is inline). Even so, this blocks: external script/style injection, `object`/`embed`, `base-uri` abuse, form hijacking, third-party framing, and exfiltration via `connect-src` / `img-src`.
- Later hardening option: replace `script-src 'unsafe-inline'` with sha256 hashes of the 8 inline blocks (stable per build; needs a rebuild-time step when the bundler output changes).

## Apply (one line inside the existing `header { }` block in `/etc/caddy/Caddyfile`)

```
Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"
```

Then: `caddy validate --config /etc/caddy/Caddyfile && systemctl reload caddy`

## Test checklist (before declaring done)
1. Hard-reload `https://myvapeisland.com/` in a real browser, devtools open — console must show **zero** CSP violations.
2. Confirm: gate animation, product modal, all images, and fonts render as before.
3. Rollback: remove the line → validate → reload. (Full-header rollback: `/etc/caddy/Caddyfile.bak-hermes-audit-20260912`.)
