# UI Baseline

- Preserve the existing design system and component primitives when they exist.
- Use accessible primitives for keyboard/focus-heavy UI instead of hand-rolled behavior.
- Use `h-dvh` instead of `h-screen`.
- Add `aria-label` to icon-only buttons.
- Prefer one accent color per view; avoid gradients and glow-heavy affordances unless explicitly requested.
- Animate only `transform` and `opacity` unless there is a clear reason not to.
- Keep loading states structural and obvious.
- Keep empty states actionable.

## Brand assets (sendtallow.com) — icon system

- **The mark** is the wordmark's own letter: the display serif "T" in off-white `#f5f5f7`
  on the near-black canvas `#0d0d0f`, rounded tile (rx ≈ 22%), hairline `#2a2a2e`.
  Masters + generators: `Nixe/artifacts/sendtallow-favicon-2026-09-20/` (`assets/`, `design/`).
- **One master, whole family:** `favicon.svg` (tile) · multi-size `favicon.ico` (16/32/48)
  · full-bleed `apple-touch-icon.png` (iOS masks its own corners — never bake rounding)
  · `icon-maskable-*.svg` (glyph inside the 80% safe circle) · mono `safari-pinned-tab.svg`.
- **Social card** `og.png` is 1200×630 and declared as such (`og:image:width/height`);
  source `og.svg` + `assets/og-render.html` (render, then downscale from 2x).
  The card is **type-led** (operator pick): wordmark + domain pill, no mark on the card —
  stacking the mark above the wordmark doubles the T.
- **Quirk:** both repo woff2s (`InstrumentSerif-Regular/-Italic`) contain the *Italic* cut —
  display type is italic by design; don't "fix" it.
- Keep `theme-color` (#fbfbfd/#0d0d0f) and manifest colors (#0d0d0f) in sync with any icon restyle.
