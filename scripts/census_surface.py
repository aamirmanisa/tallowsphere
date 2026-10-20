#!/usr/bin/env python3
"""Census empty-bodied `.tl` declarations against the two execution planes.

A method declared as `fn name(...) -> T { }` in `stdlib/` is a *declaration*: it
has no Tallow body, so the compiler/runtime must supply the behaviour. If neither
`src/codegen.rs` nor `src/interp.rs` mentions the name, the method is
implemented in appearance only — exactly the defect class this repository keeps
finding by hand (three unmangled FFIs, two handlers that could never fire).

Methods with a real body are skipped: their behaviour lives in Tallow source.

Exit code 1 when any declaration is unmentioned on both planes.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STDLIB = ROOT / "stdlib"

# Declarations that are deliberately refused on both planes rather than lowered.
# Each entry must name the refusal so it stays a decision, not a hiding place.
REFUSED = {
    ("Page", "goto_antibot"): "egress is process-level (BrowserConfig.proxy); honest home is BrowserPool.create",
}


def strip_comments(text: str) -> str:
    out = []
    for line in text.splitlines():
        i = line.find("//")
        out.append(line[:i] if i >= 0 else line)
    return "\n".join(out)


def parse_impls(text: str):
    """Yield (type_name, method_name, body_text) for every fn inside an impl block."""
    for m in re.finditer(r"impl\s+(\w+)\s*\{", text):
        ty = m.group(1)
        depth, i = 1, m.end()
        while i < len(text) and depth:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        block = text[m.end(): i - 1]
        for fm in re.finditer(r"\bfn\s+(\w+)\s*\(", block):
            name = fm.group(1)
            j = block.find("{", fm.end())
            if j < 0:
                continue
            d, k = 1, j + 1
            while k < len(block) and d:
                if block[k] == "{":
                    d += 1
                elif block[k] == "}":
                    d -= 1
                k += 1
            yield ty, name, block[j + 1: k - 1]


def main() -> int:
    codegen = strip_comments((ROOT / "src/codegen.rs").read_text(errors="replace"))
    interp = strip_comments((ROOT / "src/interp.rs").read_text(errors="replace"))
    runtime = "\n".join(
        strip_comments(p.read_text(errors="replace"))
        for p in (ROOT / "src/runtime").rglob("*.rs")
    )
    # The interpreter reaches many stdlib methods through
    # src/stdlib/<module>.rs::dispatch_method, not through a literal in
    # interp.rs. That plane counts.
    stdlib_rs = "\n".join(
        strip_comments(p.read_text(errors="replace"))
        for p in (ROOT / "src/stdlib").rglob("*.rs")
    )
    haystack = codegen + "\n" + interp + "\n" + runtime + "\n" + stdlib_rs

    declarations = 0
    unmentioned: list[str] = []
    for tl in sorted(STDLIB.rglob("*.tl")):
        text = strip_comments(tl.read_text(errors="replace"))
        for ty, name, body in parse_impls(text):
            if body.strip():
                continue  # real Tallow body
            declarations += 1
            if (ty, name) in REFUSED:
                continue
            if f'"{name}"' not in haystack and name not in haystack:
                unmentioned.append(f"{tl.relative_to(ROOT)}: {ty}.{name}")

    for line in unmentioned:
        print(f"UNMENTIONED  {line}")
    print(
        f"checked {declarations} empty-bodied declarations, "
        f"{len(unmentioned)} unmentioned on both planes, "
        f"{len(REFUSED)} declared refusals"
    )
    return 1 if unmentioned else 0


if __name__ == "__main__":
    sys.exit(main())
