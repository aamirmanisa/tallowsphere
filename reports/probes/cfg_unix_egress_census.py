#!/usr/bin/env python3
"""Census: egress-capable call sites that a Windows build cannot compile.

Read-only. No cargo, no network. Walks src/**/*.rs, resolves the cfg guard that
owns each line, and reports every line that *invokes* a network-capable
primitive inside a guard whose expression is false on `windows`.

Guard resolution
  A `#[cfg(...)]` attribute applies to the item that follows it.  This script
  finds that item's span by brace/`;` matching from the first non-attribute,
  non-comment line after the attribute (honouring a `#[path = "..."]` sibling
  attribute), and marks every line of the span.

  `#[cfg(...)] mod foo;` marks the module file it resolves to; the mark is then
  propagated transitively to modules *that* file declares (a file compiled only
  under a Unix guard makes its children Unix-only too).

  Attribute expressions are evaluated, not pattern-matched, against three
  synthetic targets:

      linux   : unix=true,  windows=false, target_os="linux",   target_env="gnu"
      macos   : unix=true,  windows=false, target_os="macos",   target_env=""
      windows : unix=false, windows=true,  target_os="windows", target_env="msvc"
      test=false everywhere (production regions only)

      absent_on_windows : true on linux or macos, false on windows
      only_on_windows   : false on linux and macos, true on windows
      both              : present on windows and on a unix target
      neither           : e.g. all(test, unix) -- dropped

Egress predicate: call form, one row per line, first class wins.  Classes are the
coverage gate's needles (tests/egress_gate_coverage.rs) widened by the measures
in reports/egress-surface-inventory.md and reports/quarry-w12.md 4.1-4.11.
"""
import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SRC = os.path.join(ROOT, "src")

INNER_RE = re.compile(r"^\s*#!\[cfg\((?P<expr>.*)\)\]\s*$")
CFG_RE = re.compile(r"^\s*#\[cfg\((?P<expr>.*)\)\]\s*$")
PATH_RE = re.compile(r'^\s*#\[path\s*=\s*"(?P<p>[^"]+)"\]\s*$')

PATTERNS = [
    ("http", re.compile(
        r"(?:egress_http::(?:get|post|put|delete|head|patch|request|agent|agent_with_timeouts|Agent::config_builder)\()"
        r"|(?:ureq::(?:get|post|put|delete|head|patch|request)\()"
        r"|(?:reqwest::(?:blocking::)?(?:get|post|put|delete|head|patch|request)\()"
        r"|(?:reqwest::(?:blocking::)?Client::(?:new|builder)\b)")),
    ("tls", re.compile(r"ClientConnection::new\(|TlsConnector::new\(|TlsConnector::builder\(")),
    ("quic", re.compile(r"quinn::Endpoint::(?:client|server)\(|\.connect\(addr\b")),
    ("tcp", re.compile(r"TcpStream::connect\(|TcpStream::connect_timeout\(|TcpListener::bind\(")),
    ("udp", re.compile(r"\bUdpSocket::bind\(|\.send_to\(")),
    ("ws", re.compile(r"tokio_tungstenite::connect_async|tungstenite::connect")),
    ("raw", re.compile(r"libc::socket\(")),
    ("dns", re.compile(r"lookup_host\(|to_socket_addrs\(|\.lookup_ip\(")),
    ("proc", re.compile(r"Command::new\(")),
]

TARGETS = {
    "linux": {"unix": True, "windows": False, "target_os": "linux", "target_env": "gnu", "test": False},
    "macos": {"unix": True, "windows": False, "target_os": "macos", "target_env": "", "test": False},
    "windows": {"unix": False, "windows": True, "target_os": "windows", "target_env": "msvc", "test": False},
}

TOKEN_RE = re.compile(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*(=\s*"[^"]*")?|\s*([(),])')


def tokenize(expr):
    toks, i = [], 0
    while i < len(expr):
        m = TOKEN_RE.match(expr, i)
        if not m or m.end() == i:
            raise ValueError(f"cannot tokenize at {i!r} in {expr!r}")
        if m.group(1):
            raw = m.group(2)
            toks.append(("id", m.group(1),
                         None if raw is None else raw.split("=", 1)[1].strip().strip('"')))
        else:
            toks.append(("p", m.group(3), None))
        i = m.end()
    return toks


class Parser:
    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None, None)

    def eat(self, val):
        k, v, _ = self.peek()
        if v == val:
            self.i += 1
            return True
        return False

    def expr(self):
        k, name, val = self.peek()
        if k != "id":
            raise ValueError("expected ident")
        self.i += 1
        if self.eat("("):
            args = [self.expr()]
            while self.eat(","):
                args.append(self.expr())
            self.eat(")")
            if name == "all":
                return lambda env: all(a(env) for a in args)
            if name == "any":
                return lambda env: any(a(env) for a in args)
            if name == "not":
                return lambda env: not args[0](env)
            raise ValueError(f"unknown cfg predicate {name}")
        # A predicate the synthetic target does not model (feature = "...")
        # is treated as ENABLED, i.e. platform-agnostic, so the guard is
        # classified by the platform predicates it does carry.
        if val is not None:
            def keyed(env, name=name, val=val):
                if name not in env:
                    return True
                return env[name] == val
            return keyed

        def flag(env, name=name):
            if name not in env:
                return True
            return env[name] is True
        return flag


def classify(expr):
    try:
        fn = Parser(tokenize(expr)).expr()
    except ValueError:
        return "unparsed", {}
    ev = {k: fn(v) for k, v in TARGETS.items()}
    if ev["windows"] and (ev["linux"] or ev["macos"]):
        return "both", ev
    if ev["windows"]:
        return "only_on_windows", ev
    if ev["linux"] or ev["macos"]:
        return "absent_on_windows", ev
    return "neither", ev


def strip_line_comment(line):
    i = line.find("//")
    return line if i < 0 else line[:i]


def find_item_end(lines, start):
    i, depth, seen_open, in_block = start, 0, False, False
    while i < len(lines):
        line = lines[i]
        if in_block:
            if "*/" in line:
                in_block = False
            i += 1
            continue
        if "/*" in line and "*/" not in line:
            in_block = True
            i += 1
            continue
        code = strip_line_comment(line)
        if not seen_open and code.strip().endswith(";") and depth == 0:
            return i, "semi"
        for ch in code:
            if ch == "{":
                depth += 1
                seen_open = True
            elif ch == "}":
                depth -= 1
                if depth == 0 and seen_open:
                    return i, "block"
        i += 1
    return len(lines) - 1, "eof"


MODDECL_RE = re.compile(r"(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*;")


def main():
    files = []
    for dirpath, _dirs, names in os.walk(SRC):
        for n in names:
            if n.endswith(".rs"):
                files.append(os.path.join(dirpath, n))
    files.sort()
    rel_of = {p: os.path.relpath(p, ROOT).replace(os.sep, "/") for p in files}

    marks = {}           # (rel, lineno) -> set(classification)
    guard_of = {}        # (rel, lineno) -> guard expression string
    file_guards = {}     # rel -> (classification, expr, origin)
    pending_mods = []    # (decl_file_rel, module_name, path_attr, cls, expr)

    for path in files:
        rel = rel_of[path]
        lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
        i = 0
        while i < len(lines):
            mi = INNER_RE.match(lines[i])
            if mi:
                c, _ = classify(mi.group("expr"))
                if c in ("absent_on_windows", "only_on_windows"):
                    file_guards[rel] = (c, mi.group("expr"), f"{rel}:{i+1}")
                i += 1
                continue
            m = CFG_RE.match(lines[i])
            if not m:
                i += 1
                continue
            expr = m.group("expr")
            c, _ = classify(expr)
            j = i + 1
            path_attr = None
            while j < len(lines) and (
                lines[j].strip() == ""
                or lines[j].lstrip().startswith("#[")
                or lines[j].lstrip().startswith("//")
            ):
                pm = PATH_RE.match(lines[j])
                if pm:
                    path_attr = pm.group("p")
                j += 1
            if j >= len(lines):
                break
            end, kind = find_item_end(lines, j)
            if c in ("absent_on_windows", "only_on_windows", "both"):
                for k in range(i, end + 1):
                    marks.setdefault((rel, k + 1), set()).add(c)
                    guard_of.setdefault((rel, k + 1), expr)
            if kind == "semi":
                mm = MODDECL_RE.match(lines[j].strip())
                if mm and c in ("absent_on_windows", "only_on_windows"):
                    pending_mods.append((rel, mm.group(1), path_attr, c, expr))
            i = end + 1

    # resolve module declarations to files, then propagate transitively
    by_rel = {rel: p for p, rel in rel_of.items()}
    changed = True
    while changed:
        changed = False
        for decl_rel, name, pattr, cls, expr in pending_mods:
            base = os.path.dirname(by_rel.get(decl_rel, ""))
            cands = []
            if pattr:
                cands.append(os.path.join(base, pattr))
            cands += [os.path.join(base, name + ".rs"), os.path.join(base, name, "mod.rs")]
            for cand in cands:
                r = os.path.relpath(os.path.abspath(cand), ROOT).replace(os.sep, "/")
                if r in by_rel and r not in file_guards:
                    file_guards[r] = (cls, expr, f"{decl_rel}: module decl of `{name}`")
                    changed = True

    # transitive: modules declared inside a guarded file inherit its guard
    for rel in list(file_guards):
        cls, expr, origin = file_guards[rel]
        if cls != "absent_on_windows":
            continue
        text = open(by_rel[rel], encoding="utf-8", errors="replace").read()
        for mm in MODDECL_RE.finditer(text):
            base = os.path.dirname(by_rel[rel])
            for cand in (os.path.join(base, mm.group(1) + ".rs"),
                         os.path.join(base, mm.group(1), "mod.rs")):
                r = os.path.relpath(os.path.abspath(cand), ROOT).replace(os.sep, "/")
                if r in by_rel and r not in file_guards:
                    file_guards[r] = (cls, expr, f"{rel}: inherited via `mod {mm.group(1)};`")

    cut = {}
    for path in files:
        text = open(path, encoding="utf-8", errors="replace").read()
        idx = text.find("#[cfg(test)]")
        cut[rel_of[path]] = 0 if idx < 0 else text[:idx].count("\n") + 1

    rows, require_rows = [], []
    UNIX_API = re.compile(r"std::os::unix|std::os::fd::|AsRawFd::as_raw_fd|os::unix::io::RawFd")
    unix_api_rows = []
    for path in files:
        rel = rel_of[path]
        lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
        limit = cut.get(rel, 0)
        for n, line in enumerate(lines, 1):
            if limit and n > limit:
                continue
            if line.lstrip().startswith("//"):
                continue
            if UNIX_API.search(line):
                classes = marks.get((rel, n), set())
                if "absent_on_windows" in classes:
                    g = "absent_on_windows"
                elif "only_on_windows" in classes:
                    g = "only_on_windows"
                elif "both" in classes:
                    g = "cfg_both"
                elif rel in file_guards:
                    g = file_guards[rel][0]
                else:
                    g = "none"
                unix_api_rows.append({"file": rel, "line": n, "guard": g,
                                      "code": line.strip()[:140]})
    for path in files:
        rel = rel_of[path]
        lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
        limit = cut.get(rel, 0)
        for n, line in enumerate(lines, 1):
            if limit and n > limit:
                continue
            if line.lstrip().startswith("//"):
                continue
            classes = marks.get((rel, n), set())
            if "scope::require" in line:
                require_rows.append({"file": rel, "line": n,
                                     "guard": next(iter(classes), None) if classes else None,
                                     "code": line.strip()[:120]})
            if "neither" in classes:
                continue
            for name, rx in PATTERNS:
                if rx.search(line):
                    if "absent_on_windows" in classes:
                        guard = "absent_on_windows"
                    elif "only_on_windows" in classes:
                        guard = "only_on_windows"
                    elif "both" in classes:
                        guard = "cfg_both"
                    elif rel in file_guards:
                        guard = file_guards[rel][0]
                    else:
                        guard = "none"
                    rows.append({"file": rel, "line": n, "class": name, "guard": guard,
                                 "expr": guard_of.get((rel, n)) or
                                         (file_guards[rel][1] if rel in file_guards else ""),
                                 "code": line.strip()[:170]})
                    break

    out = {"src_files": len(files), "file_guards": file_guards, "rows": rows,
           "requires": require_rows, "unix_api": unix_api_rows}
    dest = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cfg_unix_egress_census.json")
    json.dump(out, open(dest, "w", encoding="utf-8"), indent=1)

    print(f"src files: {len(files)}")
    print(f"egress-capable call sites (production regions): {len(rows)}")
    for g in ("absent_on_windows", "only_on_windows", "cfg_both", "none"):
        print(f"  guard={g}: {len([r for r in rows if r['guard']==g])}")
    print("\nfile-level guards:")
    for rel, v in sorted(file_guards.items()):
        print(f"  {rel}: {v[0]} via `{v[1]}` ({v[2]})")
    print("\n--- sites absent from Windows ---")
    for r in rows:
        if r["guard"] == "absent_on_windows":
            print(f"{r['file']}:{r['line']} [{r['class']}] `{r['expr']}`\n    {r['code']}")
    print("\nunix-only std API uses (std::os::unix / os::fd / AsRawFd):")
    for g in ("absent_on_windows", "only_on_windows", "cfg_both", "none"):
        print(f"  guard={g}: {len([r for r in unix_api_rows if r['guard']==g])}")
    for r in unix_api_rows:
        if r["guard"] == "none":
            print(f"  UNGUARDED {r['file']}:{r['line']}  {r['code']}")
    print("\n--- sites only on Windows ---")
    for r in rows:
        if r["guard"] == "only_on_windows":
            print(f"{r['file']}:{r['line']} [{r['class']}] `{r['expr']}`\n    {r['code']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
