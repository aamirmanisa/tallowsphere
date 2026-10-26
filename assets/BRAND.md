# Visual identity — Tallow extraction engine

The README leads with one claim and one pipeline. The design system exists so that a reader
scanning three screenshots, a table and a code block sees one document rather than four
unrelated pages.

## Tokens

| Token | Dark | Light | Used for |
|---|---|---|---|
| `bg` | `#0D0C0B` | `#FBF8F2` | page/asset background |
| `panel` | `#171513` | `#FFFFFF` | diagram nodes |
| `panel2` | `#1D1A17` | `#F7F2E8` | the node that carries the answer |
| `rule` | `#2E2924` | `#E0D6C4` | hairlines, arrows, grid |
| `text` | `#F4EFE6` | `#17150F` | wordmark, node titles |
| `muted` | `#A79E8F` | `#6B6459` | tagline, secondary labels |
| `faint` | `#6E675D` | `#9A9184` | footnotes, captions |
| `accent` | `#E39B3E` | `#A35C05` | the one emphasis: tallow rendered amber |
| `ok` / `warn` | `#6FAF8A` / `#D2705C` | `#2F7A53` / `#A8402C` | accepted rows / quarantine |

Amber is the only saturated colour. Quarantine is the second colour the system is allowed,
because a rejected row is information the product exists to surface — everything else earns
emphasis with weight or space.

## Type

- **Wordmark and headlines** — Lato Black, converted to outlines.
- **Labels and code in diagrams** — DejaVu Sans Mono, also converted to outlines.
- **Prose** — GitHub's own stack; the README sets no fonts.

Outlines keep the composition identical on a machine that has neither font installed. A label
edited into a `<text>` element will drift.

## Composition

- Hero: 1600 × 420, wordmark at ~2× the tagline, footer rule carrying the three verbs
  (`SCHEMA · EXTRACT · PROVENANCE`).
- Pipeline diagrams: 1500 wide, left-to-right, one row per concept, 30–40 px gutters.
- Every asset ships dark **and** light; the README selects with `<picture>` +
  `prefers-color-scheme`.

## Inventory

| File | What it is |
|---|---|
| `sphere-hero-{dark,light}.png` | README hero |
| `sphere-extract-{dark,light}.png` | schema → rows/quarantine pipeline |
| `sphere-compiler-{dark,light}.png` | source → ELF, with the interpreter as a second plane |
| `src/*.svg` | the editable sources the PNGs are rendered from |
| `src/brand.py` | tokens, text-to-outline conversion, SVG primitives |
| `src/make_assets.py` | regenerates the SVGs and renders the PNGs |

## Regenerating

```console
$ python3 assets/src/make_assets.py sphere
```

`brand.py` reads Lato Black and DejaVu Sans Mono from `/usr/share/fonts`. Rasterising uses
headless Chromium; if it runs under a sandbox that cannot read the checkout (snap Chromium on
this host cannot read `/root`), copy `assets/src/` somewhere it can open and run it there.
