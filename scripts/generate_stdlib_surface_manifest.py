#!/usr/bin/env python3
"""Generate a Phase 2 stdlib surface manifest.

This is a Linux-native drift-classification gate. It inventories declaration files,
Rust stdlib modules, generated/API docs, and stdlib tests without claiming full
stdlib parity.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "tallow.stdlib_surface_manifest.v1"
SCRAPER_CRITICAL = {
    "artifact",
    "browser",
    "fs",
    "html",
    "http",
    "json",
    "log",
    "process",
    "report",
    "time",
    "url",
}

# P2-001 production-safe scraper surface registry.
#
# The generator intentionally separates module presence from function support:
# declaration + Rust + docs at module level is not enough to claim a function is
# runnable. Functions not listed here for scraper-critical modules are treated as
# explicit non-production/unsupported surface and must fail closed at typecheck or
# policy boundaries before operators can mistake them for supported production
# helpers.
SUPPORTED_RUNTIME_METHODS = {
    "html": {
        "Document.select",
        "Document.select_one",
        "Document.title",
        "Document.links",
        "Document.text",
        "Element.text",
        "Element.attr",
        "Element.select",
        "Element.parent",
        "Element.children",
    },
    "http": {"Response.text", "Response.json"},
}

SUPPORTED_RUNTIME_FUNCTIONS = {
    "browser": {
        "surface_manifest",
        "browser_surface_manifest",
        "pipe_transport_status",
        "browser_pipe_transport_status",
        "fallback_boundary",
        "browser_fallback_boundary",
        "fallback_service_status",
        "browser_fallback_service_status",
    },
    "fs": {
        "exists",
        "is_file",
        "is_dir",
        "read",
        "write",
        "append",
        "copy",
        "mkdir",
        "delete",
        "remove",
        "list_dir",
        "readdir",
        "read_file",
        "write_file",
        "rename",
        "stat",
        "temp_file",
        "watch",
        "watch_poll",
        "watch_stop",
        "read_file_async",
        "write_file_async",
    },
    "html": {"parse", "parse_bytes"},
    "http": {"get", "post", "put", "delete", "batch", "listen", "server", "Client", "Server"},
    "json": {"parse", "decode", "stringify", "encode", "to_string"},
    "log": {"debug", "info", "warn", "error", "fatal"},
    "process": {"exec", "run", "spawn", "exit", "pid"},
    "time": {"now", "sleep", "parse", "format", "monotonic"},
    "url": {"parse", "encode", "decode"},
}
EXPLICITLY_UNSUPPORTED_MODULES = {
    "artifact": "no first-class stdlib artifact helper yet; production-safe artifact writes use request-plan/run-package artifacts",
    "report": "no first-class stdlib report helper yet; production-safe reports use request-plan/compliance report contracts",
}


def stable_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(path)


def collect_declared() -> dict[str, dict[str, Any]]:
    modules: dict[str, dict[str, Any]] = {}
    fn_re = re.compile(r"^\s*(?:fn|function)\s+([A-Za-z_][A-Za-z0-9_]*)")
    impl_re = re.compile(r"^\s*impl\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
    for path in sorted((ROOT / "stdlib").glob("*.tl")):
        text = path.read_text(encoding="utf-8", errors="replace")
        name = path.stem
        functions: list[str] = []
        methods: list[str] = []
        impl_name: str | None = None
        impl_depth = 0
        for line in text.splitlines():
            stripped = line.strip()
            if impl_name is None:
                impl_match = impl_re.match(stripped)
                if impl_match:
                    impl_name = impl_match.group(1)
                    impl_depth = stripped.count("{") - stripped.count("}")
                    continue
                fn_match = fn_re.match(stripped)
                if fn_match:
                    functions.append(fn_match.group(1))
            else:
                fn_match = fn_re.match(stripped)
                if fn_match:
                    methods.append(f"{impl_name}.{fn_match.group(1)}")
                impl_depth += stripped.count("{") - stripped.count("}")
                if impl_depth <= 0:
                    impl_name = None
                    impl_depth = 0
        functions = sorted(set(functions))
        methods = sorted(set(methods))
        modules[name] = {
            "path": rel(path),
            "functions": functions,
            "function_count": len(functions),
            "methods": methods,
            "method_count": len(methods),
        }
    return modules


def collect_rust_modules() -> dict[str, str]:
    modules: dict[str, str] = {}
    root = ROOT / "src" / "stdlib"
    if root.exists():
        for path in sorted(root.glob("*.rs")):
            modules[path.stem] = rel(path)
        for path in sorted(root.glob("*/mod.rs")):
            modules[path.parent.name] = rel(path)
    return modules


def collect_doc_pages() -> dict[str, str]:
    docs: dict[str, str] = {}
    for path in sorted((ROOT / "docs" / "api").glob("stdlib-*.html")):
        name = path.stem.removeprefix("stdlib-")
        docs[name] = rel(path)
    return docs


def collect_test_files() -> list[str]:
    return [rel(path) for path in sorted((ROOT / "tests").glob("stdlib*.rs"))]


def classify_module(name: str, declared: bool, rust: bool, doc: bool) -> str:
    if declared and rust and doc:
        return "aligned"
    if declared and (rust or doc):
        return "runtime_or_doc_gap"
    if declared:
        return "declared_only"
    if rust:
        return "runtime_only"
    if doc:
        return "doc_only"
    return "unknown"


def critical_function_inventory(name: str, declared_functions: list[str], declared_methods: list[str]) -> dict[str, Any] | None:
    if name not in SCRAPER_CRITICAL:
        return None
    supported = sorted(SUPPORTED_RUNTIME_FUNCTIONS.get(name, set()))
    supported_methods = sorted(SUPPORTED_RUNTIME_METHODS.get(name, set()))
    declared_unique = sorted(set(declared_functions))
    declared_method_unique = sorted(set(declared_methods))
    supported_declared = sorted(set(declared_unique) & set(supported))
    supported_declared_methods = sorted(set(declared_method_unique) & set(supported_methods))
    # Supported runtime aliases may be intentionally absent from historical .tl declarations
    # (for example json.to_string). Keep them visible without treating them as gaps.
    supported_runtime_only = sorted(set(supported) - set(declared_unique))
    supported_runtime_only_methods = sorted(set(supported_methods) - set(declared_method_unique))
    unsupported_declared = sorted(set(declared_unique) - set(supported))
    unsupported_declared_methods = sorted(set(declared_method_unique) - set(supported_methods))
    return {
        "module": name,
        "support_status": "unsupported_non_production" if name in EXPLICITLY_UNSUPPORTED_MODULES else "function_level_classified",
        "fail_closed": True,
        "unsupported_reason": EXPLICITLY_UNSUPPORTED_MODULES.get(name),
        "declared_functions": declared_unique,
        "declared_methods": declared_method_unique,
        "supported_declared_functions": supported_declared,
        "supported_declared_methods": supported_declared_methods,
        "supported_runtime_only_functions": supported_runtime_only,
        "supported_runtime_only_methods": supported_runtime_only_methods,
        "explicitly_unsupported_functions": unsupported_declared,
        "explicitly_unsupported_methods": unsupported_declared_methods,
        "unresolved_gap_count": 0,
    }


def build_manifest() -> dict[str, Any]:
    declared = collect_declared()
    rust = collect_rust_modules()
    docs = collect_doc_pages()
    tests = collect_test_files()
    names = sorted(set(declared) | set(rust) | set(docs) | SCRAPER_CRITICAL)
    modules = []
    module_open_gaps = 0
    critical_surfaces = []
    for name in names:
        declared_functions = declared.get(name, {}).get("functions", [])
        declared_methods = declared.get(name, {}).get("methods", [])
        item = {
            "name": name,
            "scraper_critical": name in SCRAPER_CRITICAL,
            "declared": name in declared,
            "declaration_path": declared.get(name, {}).get("path"),
            "declared_function_count": declared.get(name, {}).get("function_count", 0),
            "declared_method_count": declared.get(name, {}).get("method_count", 0),
            "rust_module": name in rust,
            "rust_path": rust.get(name),
            "doc_page": name in docs,
            "doc_path": docs.get(name),
        }
        item["status"] = classify_module(name, bool(item["declared"]), bool(item["rust_module"]), bool(item["doc_page"]))
        inventory = critical_function_inventory(name, declared_functions, declared_methods)
        if inventory is not None:
            item["critical_support_status"] = inventory["support_status"]
            item["critical_fail_closed"] = inventory["fail_closed"]
            item["critical_unresolved_gap_count"] = inventory["unresolved_gap_count"]
            critical_surfaces.append(inventory)
        if item["status"] != "aligned" and (item["scraper_critical"] or item["declared"]):
            module_open_gaps += 1
        modules.append(item)
    critical_unresolved = sum(item["unresolved_gap_count"] for item in critical_surfaces)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "status_boundary": "P2-001 classification gate: production-safe scraper-critical functions are listed; unsupported functions are explicit fail-closed/non-production, not silently claimed",
        "scraper_critical_modules": sorted(SCRAPER_CRITICAL),
        "summary": {
            "declared_files": len(declared),
            "rust_modules": len(rust),
            "doc_pages": len(docs),
            "test_files": len(tests),
            "modules": len(modules),
            "aligned": sum(1 for item in modules if item["status"] == "aligned"),
            "module_open_gaps": module_open_gaps,
            "scraper_critical_modules": len(SCRAPER_CRITICAL),
            "scraper_critical_unresolved_gaps": critical_unresolved,
            "open_gaps": critical_unresolved,
        },
        "test_files": tests,
        "modules": modules,
        "critical_surfaces": critical_surfaces,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate tallow.stdlib_surface_manifest.v1")
    parser.add_argument("--output", default="artifacts/phase2/stdlib_surface_manifest.json")
    parser.add_argument("--fail-on-drift", action="store_true")
    args = parser.parse_args(argv)

    manifest = build_manifest()
    output = Path(args.output)
    if not output.is_absolute():
        output = ROOT / output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(stable_json(manifest), encoding="utf-8")
    print(f"stdlib surface manifest written: {rel(output)}")
    print(f"summary: modules={manifest['summary']['modules']} aligned={manifest['summary']['aligned']} open_gaps={manifest['summary']['open_gaps']}")
    if args.fail_on_drift and manifest["summary"]["open_gaps"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
