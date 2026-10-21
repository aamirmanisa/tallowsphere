#!/usr/bin/env python3
"""B7 cliff-class audit: is the crypto fast path actually selected?

A "cliff-class" defect is a fast path chosen by a COMPILE-TIME condition rather
than by runtime CPU detection. When the build flag is missing, the code silently
runs a slow fallback: no error, no runtime symptom, identical output bytes.

Measured on this project (2026-10-16, aarch64, 8 MiB x 32 iterations of
AES-256-GCM via crates/tallow-crypto -> libcrux-aesgcm 0.0.8; that backend was
replaced by RustCrypto aes-gcm 0.10 on 2026-10-21, whose numbers are 65.6 vs
128.3 MB/s on the same box -- the check logic here is backend-agnostic):

    no flags                      98.7 MB/s   <- the silent fallback in place
    -C target-feature=+aes       909.3 MB/s   <- 9.2x
    LIBCRUX_DISABLE_SIMD128=1     14.9 MB/s   <- bitsliced, for scale
    +aes AND disabled             14.7 MB/s   <- +aes alone buys nothing

Mechanism: libcrux's AES intrinsics are `#[target_feature(enable = "aes")]`.
A caller compiled WITHOUT `+aes` cannot inline them, so every AES round becomes a
real function call. The runtime check (`libcrux_platform::aes_ni_support()`,
AT_HWCAP on aarch64 / CPUID on x86) reports the feature is present in *all four*
configurations above -- which is exactly why this is silent.

Exit codes: 0 clean; 1 a gap was found; 2 a check could not be evaluated.
An unevaluable check reports 2, never a pass.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Required rustflags per target architecture. aarch64 is DECIDED policy: it is in
# .cargo/config.toml and was measured. x86_64 is the open question this audit
# raises -- adding `+aes` there is a compatibility call (it makes the binary
# require AES-NI), so it is reported as a GAP, not applied behind your back.
REQUIRED_FLAGS = {
    "aarch64": "target-feature=+aes",
    "x86_64": "target-feature=+aes,+avx2",
    "x86": "target-feature=+aes,+avx2",
}

ARCH_OF = re.compile(r"^(aarch64|x86_64|x86|i686|arm|wasm32)")


def arch_of(triple: str) -> str:
    m = ARCH_OF.match(triple)
    if not m:
        return "unknown"
    a = m.group(1)
    return "x86_64" if a == "i686" else a


def load_config(path: Path):
    """Return {triple: [rustflags]} from .cargo/config.toml, or None."""
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        import tomllib  # py3.11+

        data = tomllib.loads(text)
        out = {}
        for triple, tbl in (data.get("target") or {}).items():
            rf = tbl.get("rustflags")
            if isinstance(rf, list):
                out[triple] = rf
            else:
                out[triple] = []
        return out
    except Exception:
        # Minimal fallback: find [target.X] blocks and their rustflags arrays.
        out = {}
        for m in re.finditer(
            r"^\[target\.([A-Za-z0-9_.-]+)\]\s*\n((?:[^\[]|\n)*)", text, re.M
        ):
            triple, body = m.group(1), m.group(2)
            flags = re.search(r"^rustflags\s*=\s*\[(.*?)\]", body, re.M | re.S)
            out[triple] = (
                re.findall(r'"([^"]+)"', flags.group(1)) if flags else []
            )
        return out


def check_config_flags(cfg):
    """Per-arch: does a declared target override carry the required flag?"""
    results = []
    if cfg is None:
        return [("config-flags", "could-not-evaluate", "no .cargo/config.toml")], 2
    rc = 0
    for triple, flags in sorted(cfg.items()):
        arch = arch_of(triple)
        need = REQUIRED_FLAGS.get(arch)
        if need is None:
            results.append(("config-flags", "n-a", f"{triple}: arch {arch} not audited"))
            continue
        joined = " ".join(flags)
        if need in joined:
            results.append(("config-flags", "pass", f"{triple}: carries {need}"))
        else:
            results.append(
                (
                    "config-flags",
                    "GAP",
                    f"{triple}: no '{need}' in rustflags {flags or '(none declared)'}",
                )
            )
            rc = 1
    return results, rc


def shipping_targets(release_workflow: Path):
    if not release_workflow.is_file():
        return None
    text = release_workflow.read_text(encoding="utf-8", errors="replace")
    return sorted(set(re.findall(r"^\s*target:\s*([A-Za-z0-9_.-]+)\s*$", text, re.M)))


def check_shipping_coverage(cfg, release_workflow: Path):
    tgts = shipping_targets(release_workflow)
    if tgts is None:
        return [
            (
                "shipping-coverage",
                "could-not-evaluate",
                f"release workflow not found: {release_workflow}",
            )
        ], 2
    rc = 0
    results = []
    for t in tgts:
        arch = arch_of(t)
        need = REQUIRED_FLAGS.get(arch)
        if need is None:
            results.append(("shipping-coverage", "n-a", f"{t}: arch {arch} not audited"))
            continue
        flags = (cfg or {}).get(t, [])
        if need in " ".join(flags):
            results.append(("shipping-coverage", "pass", f"{t}: {need}"))
        else:
            results.append(
                (
                    "shipping-coverage",
                    "GAP",
                    f"{t} SHIPS without '{need}' -> silent slow path on that platform",
                )
            )
            rc = 1
    return results, rc


def check_rustflags_hazard():
    """An exported RUSTFLAGS makes cargo ignore the [target.*] tables entirely."""
    hits = []
    for root in (REPO / ".github" / "workflows",):
        if not root.is_dir():
            continue
        for f in sorted(root.glob("*.y*ml")):
            for i, line in enumerate(
                f.read_text(encoding="utf-8", errors="replace").splitlines(), 1
            ):
                s = line.strip()
                if s.startswith("#"):
                    continue
                if re.match(r"^(export\s+)?RUSTFLAGS\s*[:=]", s):
                    hits.append(f"{f.relative_to(REPO)}:{i}: {s}")
    if hits:
        return [
            ("rustflags-hazard", "GAP", "RUSTFLAGS is set -- the [target.*] tables are IGNORED: " + "; ".join(hits))
        ], 1
    return [("rustflags-hazard", "pass", "no workflow sets RUSTFLAGS")], 0


def check_binary(binary: Path | None):
    if binary is None:
        return [("binary-evidence", "could-not-evaluate", "no --binary given")], 2
    if not binary.is_file():
        return [("binary-evidence", "could-not-evaluate", f"not a file: {binary}")], 2
    if not shutil_which("objdump"):
        return [("binary-evidence", "could-not-evaluate", "objdump not installed")], 2
    try:
        out = subprocess.run(
            ["objdump", "-d", str(binary)],
            capture_output=True,
            text=True,
            timeout=600,
        ).stdout
    except Exception as e:  # pragma: no cover
        return [("binary-evidence", "could-not-evaluate", f"objdump failed: {e}")], 2
    # Real MNEMONICS, not intrinsic names: objdump prints `aese`/`aesmc` on
    # aarch64 (the `vaeseq_u8` spellings are Rust intrinsic names and never
    # appear in a disassembly) and `aesenc`/`aesenclast` on x86. The first
    # version of this pattern missed aarch64 entirely.
    #
    # One entry per primitive that has a hardware path a build can silently
    # miss. A zero count means the shipped binary cannot be using it.
    insts = {
        "AES": r"\b(?:aeskeygenassist|aesenclast|aesdeclast|vaeseq_u8|vaesmcq_u8"
               r"|aesenc|aesdec|aesimc|aesmc|aese|aesd)\b",
        "SHA256": r"\b(?:sha256rnds2|sha256msg1|sha256msg2|sha256h|sha256h2"
                  r"|sha256su0|sha256su1)\b",
        "PMULL-GHASH": r"\b(?:pmull|pmull2)\b",
    }
    counts = {k: len(re.findall(v, out)) for k, v in insts.items()}
    detail = ", ".join(f"{k}={n}" for k, n in counts.items())
    missing = [k for k, n in counts.items() if n == 0]
    if missing:
        return [
            (
                "binary-evidence",
                "GAP",
                f"{binary.name}: no {'/'.join(missing)} instructions present ({detail})"
                " -- that primitive can only be on a fallback",
            )
        ], 1
    return [("binary-evidence", "pass", f"{binary.name}: {detail}")], 0


def shutil_which(cmd):
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = Path(d) / cmd
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=str(REPO / ".cargo" / "config.toml"))
    ap.add_argument("--release-workflow", default="")
    ap.add_argument("--binary", default="")
    args = ap.parse_args()

    cfg = load_config(Path(args.config))
    rw = Path(args.release_workflow) if args.release_workflow else Path("/nonexistent")

    rows, rc1 = check_config_flags(cfg)
    r2, rc2 = check_shipping_coverage(cfg, rw)
    r3, rc3 = check_rustflags_hazard()
    r4, rc4 = check_binary(Path(args.binary) if args.binary else None)

    rows += r2 + r3 + r4
    # A found gap (1) outranks an unevaluable check (2): if there is something to
    # fix, say so, rather than hiding it behind "incomplete".
    rc = 1 if any(r[1] == "GAP" for r in rows) else (2 if any(r[1] == "could-not-evaluate" for r in rows) else 0)

    width = max(len(r[0]) for r in rows)
    for check, status, msg in rows:
        print(f"  {check.ljust(width)}  {status:4}  {msg}")
    gaps = sum(1 for r in rows if r[1] == "GAP")
    uneval = sum(1 for r in rows if r[1] == "could-not-evaluate")
    print(f"\nFASTPATH AUDIT: {'FAIL' if rc == 1 else ('INCOMPLETE' if rc == 2 else 'PASS')}"
          f"  ({gaps} gap(s), {uneval} unevaluable)")
    return rc


if __name__ == "__main__":
    sys.exit(main())
