#!/usr/bin/env python3
"""Extract the BBS draft-08 S8.2-S8.4.4 test vectors into a repo fixture.

Section 8.4.4.1 and 8.4.4.2 are separate fixtures that reuse the same names (m_1, SK, PK, header, B,
domain, signature) with DIFFERENT values, so each block is namespaced. Multi-line values in the draft
are wrapped and indented; the parser joins continuation lines and strips whitespace, so no hex is
ever transcribed by eye (a wrapped value is exactly how a 64-char scalar becomes 65).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

DRAFT = Path("/home/user/.hermes/profiles/alden/cache/web/www.ietf.org-2a9f2a6f38.md")
OUT = Path("/home/user/tallow-extraction-engine/tests/fixtures/bbs-bls12381-sha256-8.4.txt")

# (block prefix, heading that starts it)
BLOCKS = [
    ("messages", "8.2.  Messages"),
    ("key", "8.4.1.  Key Pair"),
    ("msgscalars", "8.4.2.  Map Messages to Scalars"),
    ("generators", "8.4.3.  Message Generators"),
    ("sign1", "8.4.4.1.  Valid Single Message Signature"),
    ("sign10", "8.4.4.2.  Valid Multi-Message Signature"),
    ("proofs", "8.4.5.  Proof Fixtures"),
    ("d22_1", "D.2.2.1.  No Header Valid Proof"),
    ("d22_2", "D.2.2.2.  No Presentation Header Valid Proof"),
]
# Headings that must not be treated as fields, and which also END a block (so one section's vectors
# can never leak into another's — S8.3 is the *SHAKE-256* ciphersuite and Appendix D repeats the
# SHA-256 fixtures; mistaking either for S8.4's would silently validate the wrong ciphersuite).
HEADING = re.compile(r"^\d+(\.\d+)*\.\s")
BOUNDARY = re.compile(r"^(\d+(\.\d+)*\.\s|Appendix [A-Z]\.|D\.\d)")
FIELD = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(.*)$')
# The draft also writes `SEED =` / `DST =` with the quoted value on the FOLLOWING line. Missing that
# form silently dropped the proof vectors' SEED and DST — the two inputs CoreProofGen's determinism
# depends on.
FIELD_NAME_ONLY = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*$")
# `revealed_indexes = "[ 0, 2, 4, 6 ]"` — the disclosed message indexes are a bracketed list, not hex,
# so a hex-only extractor drops the single most important input to the proof vectors.
LIST_FIELD = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"\[\s*([0-9,\s]*)\]"\s*$')
# Page furniture interrupts long values (the SEED's closing quote sits after a page break), so it is
# removed before any scanning rather than worked around in the accumulation loop.
PAGE_FURNITURE = re.compile(r"(\[Page \d+\]|^Internet-Draft\b|^Looker, et al\.|\x0c)")


def extract_quoted(pieces: list[str]) -> str:
    """The text between the first and last quote of the accumulated pieces, whitespace removed."""
    joined = "".join(pieces)
    start = joined.find('"')
    if start < 0:
        return ""
    end_quote = joined.rfind('"')
    body = joined[start + 1 : end_quote] if end_quote > start else joined[start + 1 :]
    return re.sub(r"\s+", "", body)


def main() -> int:
    lines = DRAFT.read_text(encoding="utf-8").splitlines()
    text = [line for line in lines if not PAGE_FURNITURE.search(line)]
    starts: list[tuple[str, int]] = []
    for prefix, heading in BLOCKS:
        # Anchor on the LAST occurrence outside the table of contents: the TOC repeats every heading
        # and its lines are recognisable by their dot leaders.
        found = -1
        for i, line in enumerate(text):
            if line.strip().startswith(heading) and ". . ." not in line:
                found = i
        if found < 0:
            print(f"heading not found: {heading}", file=sys.stderr)
            return 1
        starts.append((prefix, found))

    out = [
        "# BBS draft-irtf-cfrg-bbs-signatures-08, ciphersuite BLS12-381-SHA-256 (section 8.4).",
        "# Extracted mechanically from the draft text by scripts/bbs_extract_vectors.py — never typed.",
        "# Lines are 'block.field = hex'. Blocks sign1/sign10 are the two Sign fixtures.",
        "",
    ]
    summary: list[tuple[str, int]] = []
    for index, (prefix, start) in enumerate(starts):
        end = starts[index + 1][1] if index + 1 < len(starts) else len(text)
        i = start + 1
        while i < end:
            if BOUNDARY.match(text[i]):
                break  # the next section begins: this block is over
            match = FIELD.match(text[i])
            name_only = FIELD_NAME_ONLY.match(text[i])
            list_match = LIST_FIELD.match(text[i])
            if list_match:
                name = list_match.group(1)
                indexes = [i.strip() for i in list_match.group(2).split(",") if i.strip()]
                out.append(f"{prefix}.{name} = {','.join(indexes)}")
                summary.append((name, len(indexes)))
                i += 1
                continue
            if name_only or (match and not HEADING.match(text[i])):
                if name_only:
                    name = name_only.group(1)
                    pieces: list[str] = []
                else:
                    assert match is not None
                    name = match.group(1)
                    pieces = ['"' + match.group(2)]
                # Accumulate until the value's quoting closes: a wrapped value's closing quote can sit
                # several lines away, even across a page break.
                while sum(piece.count('"') for piece in pieces) < 2 and i + 1 < end:
                    i += 1
                    pieces.append(text[i])
                value = extract_quoted(pieces)
                # Only hex values are vectors; the draft also prints ASCII constants like "H2G_" and
                # "HM2S_" in the same `name = "..."` shape.
                if value and not re.fullmatch(r"[0-9a-fA-F]+", value):
                    i += 1
                    continue
                out.append(f"{prefix}.{name} = {value}")
                summary.append((name, len(value) // 2))
            i += 1

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(out) + "\n", encoding="utf-8")

    # Print what landed, with byte lengths, so an odd-length value is obvious.
    print(f"wrote {OUT}")
    for line in out[4:]:
        name, value = line.split(" = ", 1)
        if value == "":
            print(f"  {name:22} {'':>4}  (empty)")
        else:
            flag = "" if len(value) % 2 == 0 else "   <-- ODD HEX LENGTH"
            print(f"  {name:22} {len(value) // 2:>4}  {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
