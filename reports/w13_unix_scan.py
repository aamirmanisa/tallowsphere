#!/usr/bin/env python3
"""Static reachability scan: unix-only symbols vs cfg gates, for the Windows
`cargo check --workspace --all-targets` plane (tallowsphere @ HEAD).

Method
 1. mask() blanks Rust comments and string/char literal bodies, positions kept,
    so brace matching cannot be fooled by a '}' inside a string.
 2. walk() descends every item at every nesting level. For each item it records
    the attribute list (taken from the ORIGINAL source, so cfg predicates keep
    their string literals) and whether that item is windows-false gated.
 3. A gate is windows-false when a cfg(...) predicate is `unix`,
    `not(windows)`, `target_os = "linux"`, `target_family = "unix"`.
    `cfg(test)` ALONE IS NOT A GATE: --all-targets compiles #[cfg(test)] code.
 4. Each symbol hit is REACHABLE unless some enclosing item is windows-false
    gated. That is a necessary condition for the symbol to be compiled on
    windows-msvc.
"""
import json
import os
import re
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SYM_RE = re.compile(
    r"libc::[A-Za-z_][A-Za-z0-9_]*"
    r"|std::os::unix[A-Za-z0-9_:]*[A-Za-z0-9_]"
    r"|\bos::unix\b"
    r"|\bUnixStream\b|\bUnixListener\b|\bUnixDatagram\b"
    r"|\bif_nametoindex\b|\bsuseconds_t\b|\bsocklen_t\b"
    r"|\bAsRawFd\b|\bFromRawFd\b|\bIntoRawFd\b|\bRawFd\b"
    r"|\bExitStatusExt\b|\bPermissionsExt\b|\bOpenOptionsExt\b"
    r"|\bDirBuilderExt\b|\bFileTypeExt\b|\bMetadataExt\b"
)


def mask(src):
    out = list(src)
    i, n = 0, len(src)

    def blank(a, b):
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]
        if c == "/" and src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif c == "/" and src.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth += 1
                    j += 2
                elif src.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif c == "r" and (i + 1 < n and (src[i + 1] == '"' or src[i + 1] == "#")):
            m = re.match(r'r(#*)"', src[i:])
            if m:
                h = m.group(1)
                end = src.find('"' + h, i + m.end())
                end = n if end < 0 else end + 1 + len(h)
                blank(i, end)
                i = end
            else:
                i += 1
        elif c == '"':
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            blank(i + 1, j - 1)
            i = j
        elif c == "'":
            if i + 2 < n and (src[i + 2] == "'" or src[i + 1] == "\\"):
                j = src.find("'", i + 2)
                if 0 < j - i <= 12:
                    blank(i + 1, j)
                    i = j + 1
                    continue
            i += 1
        else:
            i += 1
    return "".join(out)


def is_windows_false(attr):
    t = re.sub(r"\s+", " ", attr)
    if "#[cfg" not in t:
        return False
    for m in re.finditer(r"#\[cfg\((.*?)\)\]", t):
        body = m.group(1)
        if re.search(r"\bunix\b", body) and "not ( unix" not in body and "not(unix" not in body:
            return True
        if re.search(r"not \(? ?windows", body):
            return True
        if re.search(r'target_os = "linux"', body):
            return True
        if re.search(r'target_family = "unix"', body):
            return True
    return False


def walk(masked, src, lo, hi, parent, out):
    pending = []
    i = lo
    while i < hi:
        c = masked[i]
        if c == "#" and i + 1 < hi and masked[i + 1] == "[":
            j, d = i + 2, 1
            while j < hi and d:
                if masked[j] == "[":
                    d += 1
                elif masked[j] == "]":
                    d -= 1
                j += 1
            pending.append((i, j))
            i = j
            continue
        if c == "{" and pending:
            # `#[cfg(unix)] { ... }` block *expression* statement
            gated = parent or any(is_windows_false(src[a:b]) for a, b in pending)
            k, d = i, 0
            while k < hi:
                if masked[k] == "{":
                    d += 1
                elif masked[k] == "}":
                    d -= 1
                    if d == 0:
                        break
                k += 1
            out.append((i, min(k + 1, hi), gated, "cfg block"))
            walk(masked, src, i + 1, min(k, hi), gated, out)
            i = k + 1
            pending = []
            continue
        if c.isalpha() or c == "_":
            gated = parent or any(is_windows_false(src[a:b]) for a, b in pending)
            j, dp = i, 0
            brace = semi = None
            while j < hi:
                ch = masked[j]
                if ch in "([":
                    dp += 1
                elif ch in ")]":
                    dp -= 1
                elif dp == 0 and ch == "{":
                    brace = j
                    break
                elif dp == 0 and ch == ";":
                    semi = j
                    break
                elif dp == 0 and ch == ",":
                    # `,` ends a match arm ONLY. In a generic parameter list
                    # (`fn f<T, U>() -> R {`) it must not end the item, or the
                    # function body loses its gate.
                    if "=>" in masked[i:j]:
                        semi = j
                        break
                j += 1
            if brace is not None:
                k, d = brace, 0
                while k < hi:
                    if masked[k] == "{":
                        d += 1
                    elif masked[k] == "}":
                        d -= 1
                        if d == 0:
                            break
                    k += 1
                out.append((i, min(k + 1, hi), gated, src[i:brace].strip()[:60]))
                walk(masked, src, brace + 1, min(k, hi), gated, out)
                i = k + 1
                pending = []
                continue
            if semi is not None:
                out.append((i, semi + 1, gated, src[i:semi + 1].strip()[:60]))
                # a `let`/expression statement can carry nested blocks and
                # nested #[cfg] attributes (closures): descend into it
                walk(masked, src, i + 1, semi, gated, out)
                i = semi + 1
                pending = []
                continue
            i += 1
            continue
        if c == ";":
            pending = []
        i += 1


def main():
    files = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in {".git", "target", "vendor"}]
        for f in filenames:
            if f.endswith(".rs"):
                files.append(os.path.join(dirpath, f))
    result = {}
    for path in sorted(files):
        src = open(path, encoding="utf-8", errors="replace").read()
        if "unix" not in src and "libc::" not in src:
            continue
        masked = mask(src)
        starts = [0] + [i + 1 for i, ch in enumerate(src) if ch == "\n"]

        def line_of(off):
            lo, hi = 0, len(starts) - 1
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if starts[mid] <= off:
                    lo = mid
                else:
                    hi = mid - 1
            return lo + 1

        regions = []
        walk(masked, src, 0, len(masked), False, regions)
        hits = []
        for m in SYM_RE.finditer(masked):
            off = m.start()
            line = line_of(off)
            gated = any(b <= off < e and g for b, e, g, _ in regions)
            hits.append({
                "line": line,
                "col": off - starts[line - 1] + 1,
                "sym": m.group(0),
                "reachable": not gated,
                "text": src.splitlines()[line - 1].strip()[:170],
            })
        if hits:
            result[os.path.relpath(path, ROOT)] = hits
    json.dump(result, sys.stdout, indent=1)


if __name__ == "__main__":
    main()
