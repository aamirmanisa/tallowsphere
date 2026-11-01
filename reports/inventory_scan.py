#!/usr/bin/env python3
"""Faithful re-implementation of reports/egress-surface-inventory.md's method.

Predicate, per the document's Method section, with the `blocking::` module path
included because `reqwest::blocking::Client::new|builder` is the same primitive
(the published table counted those files, so the original run did include them):

  HTTP: egress_http::<verb>( | ureq::<verb>( | reqwest::[blocking::]Client::new|builder
        | reqwest::<verb>(
  RAW:  TcpStream::connect | UdpSocket::connect | connect_timeout
  NONEG: bind( | Command::new

Gated = production region (before first `#[cfg(test)]`) contains `scope::require`.
Comment lines (//...) are not counted as sites.
"""
import re, subprocess, sys, json

ROOT = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                      capture_output=True, text=True).stdout.strip() or "."
REV = sys.argv[1] if len(sys.argv) > 1 else "HEAD"

VERBS = r"(get|post|put|patch|delete|head|request)"
HTTP = re.compile(
    rf"egress_http::{VERBS}\s*\("
    rf"|egress_http::agent_with_timeouts\s*\("
    rf"|ureq::{VERBS}\s*\("
    rf"|reqwest::(?:blocking::)?Client::(new|builder)"
    rf"|reqwest::{VERBS}\s*\("
)
RAW = re.compile(r"TcpStream::connect|UdpSocket::connect|connect_timeout")
NONEG = re.compile(r"\bbind\s*\(|Command::new")


def ls(rev):
    return subprocess.run(["git", "-C", ROOT, "ls-tree", "-r", "--name-only", rev, "src"],
                          capture_output=True, text=True, check=True).stdout.split()


def read(rev, rel):
    return subprocess.run(["git", "-C", ROOT, "show", f"{rev}:{rel}"],
                          capture_output=True, text=True).stdout


def prod_region(text):
    cut = text.find("#[cfg(test)]")
    return text if cut < 0 else text[:cut]


def scan(rev):
    gated, http, raw, noneg = 0, [], [], []
    for rel in ls(rev):
        if not rel.endswith(".rs"):
            continue
        text = read(rev, rel)
        if not text:
            continue
        prod = prod_region(text)
        if "scope::require" in prod:
            gated += 1
            continue

        def hits(rx):
            return [i for i, ln in enumerate(prod.splitlines(), 1)
                    if rx.search(ln) and not ln.lstrip().startswith("//")]

        h, r, n = hits(HTTP), hits(RAW), hits(NONEG)
        if h:
            http.append((rel, len(h), h))
        if r:
            raw.append((rel, len(r), r))
        if n:
            noneg.append((rel, len(n), n))
    return gated, http, raw, noneg


if __name__ == "__main__":
    gated, http, raw, noneg = scan(REV)
    out = {
        "rev": REV,
        "gated_files": gated,
        "http": {"files": len(http), "sites": sum(n for _, n, _ in http),
                 "rows": {rel: {"sites": n, "lines": lines} for rel, n, lines in http}},
        "raw": {"files": len(raw), "sites": sum(n for _, n, _ in raw),
                "rows": {rel: {"sites": n, "lines": lines} for rel, n, lines in raw}},
        "noneg": {"files": len(noneg), "sites": sum(n for _, n, _ in noneg)},
    }
    print(json.dumps(out, indent=1))
