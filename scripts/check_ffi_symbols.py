#!/usr/bin/env python3
"""Check the FFI boundary between generated code and the runtime archive.

Two failure modes, both silent until link time:

1. A `pub extern "C" fn tallow_*` without `#[unsafe(no_mangle)]` gets a mangled
   Rust symbol, so generated C-style calls cannot resolve it. This actually
   happened to `tallow_page_fill`, `tallow_page_select` and
   `tallow_page_handle_cookie_consent_str`: the codegen arm existed and compiled,
   and only `--require-native` (a real link) exposed it.
2. Codegen emitting `@tallow_<name>` for a name the runtime never defines.

Exit 0 when both hold, 1 otherwise.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNTIME = sorted((ROOT / "src/runtime").glob("**/*.rs"))


def runtime_fns() -> tuple[set[str], list[tuple[str, str]]]:
    defined: set[str] = set()
    unmangled: list[tuple[str, int]] = []
    for path in RUNTIME:
        lines = path.read_text(errors="replace").splitlines()
        for i, line in enumerate(lines):
            m = re.match(r'\s*pub extern "C" fn (tallow_[a-z0-9_]+)', line)
            if not m:
                continue
            name = m.group(1)
            defined.add(name)
            if "no_mangle" not in "\n".join(lines[max(0, i - 6) : i]):
                unmangled.append((f"{path.relative_to(ROOT)}:{i + 1}", name))
    return defined, unmangled


def emitted() -> set[str]:
    codegen = (ROOT / "src/codegen.rs").read_text(errors="replace")
    return set(re.findall(r"@(tallow_[a-z0-9_]+)\(", codegen))


def defined_in_ir() -> set[str]:
    """Some FFI symbols are emitted as LLVM IR in codegen itself rather than
    living in the runtime archive (the async shim, redact_private, replace_all).
    A `define ... @name(` in codegen satisfies the reference."""
    codegen = (ROOT / "src/codegen.rs").read_text(errors="replace")
    llvm = set(re.findall(r"define [^\n]*@(tallow_[a-z0-9_]+)\(", codegen))
    # The async shim is C source embedded in codegen (not LLVM IR, not the archive).
    c_src = set(
        re.findall(
            r"\b(?:void|int|long|char|size_t|bool|double|float)\s*\*?\s*(tallow_[a-z0-9_]+)\s*\(",
            codegen,
        )
    )
    return llvm | c_src


def main() -> int:
    defined, unmangled = runtime_fns()
    wanted = emitted()
    problems = 0

    for where, name in unmangled:
        problems += 1
        print(f"UNMANGLED  {where}: {name} lacks #[unsafe(no_mangle)]")

    # Symbols the codegen emits that no runtime file defines. Some are provided by
    # the C shim or the platform, so compare only against names starting tallow_.
    defined |= defined_in_ir()
    missing = sorted(wanted - defined)
    for name in missing:
        problems += 1
        print(f"UNDEFINED  codegen emits @{name} but no runtime fn defines it")

    print(
        f"checked {len(defined)} runtime FFI fns, {len(wanted)} emitted symbols, "
        f"{problems} problem(s)"
    )
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
