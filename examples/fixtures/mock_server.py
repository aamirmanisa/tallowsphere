#!/usr/bin/env python3
"""Loopback-only fixture server for release-quality Tallow examples.

This server binds 127.0.0.1 only. It serves deterministic JSON/HTML and never
contacts public internet or reads secrets.
"""
from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

PRODUCTS = [
    {"name": "Local Mock Granola", "price": {"amount": 4.99, "currency": "USD", "cents": 499}, "url": "/products/granola"},
    {"name": "Fixture Coffee", "price": {"amount": 12.5, "currency": "USD", "cents": 1250}, "url": "/products/coffee"},
]


def product_html(host: str) -> str:
    cards = []
    for product in PRODUCTS:
        cards.append(
            '<article class="product">'
            f'<a href="http://{host}{product["url"]}"><span class="name">{product["name"]}</span></a>'
            f'<span class="price">${product["price"]["amount"]:.2f}</span>'
            '</article>'
        )
    return "<!doctype html><html><head><title>Local products</title></head><body>" + "".join(cards) + "</body></html>"


class FixtureHandler(BaseHTTPRequestHandler):
    server_version = "TallowExampleFixture/1.0"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib callback name
        return

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        self._send(status, json.dumps(payload, sort_keys=True).encode("utf-8"), "application/json")

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        fallback_port = getattr(self.server, "server_port", 18080)
        host = self.headers.get("Host") or f"127.0.0.1:{fallback_port}"
        if self.path.startswith("/status"):
            self._json(200, {"ok": True, "method": "GET", "path": self.path, "fixture": "tallow-examples"})
            return
        if self.path.startswith("/api/products"):
            self._json(200, {"products": [{**p, "url": f"http://{host}{p['url']}"} for p in PRODUCTS]})
            return
        if self.path.startswith("/products"):
            self._send(200, product_html(host).encode("utf-8"), "text/html; charset=utf-8")
            return
        if self.path == "/robots.txt":
            self._send(200, b"User-agent: *\nAllow: /\n", "text/plain")
            return
        if self.path.startswith("/challenge"):
            self._send(200, b"<html><title>Manual gate fixture</title><body>challenge fixture</body></html>", "text/html; charset=utf-8")
            return
        self._json(404, {"ok": False, "error": "not_found", "path": self.path})

    def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length) if length else b""
        try:
            request_json: Any = json.loads(raw.decode("utf-8")) if raw else None
        except json.JSONDecodeError:
            request_json = None
        if self.path.startswith("/graphql"):
            self._json(
                200,
                {
                    "data": {"products": [{"name": p["name"]} for p in PRODUCTS]},
                    "fixture": "tallow-examples",
                    "received_query": bool(isinstance(request_json, dict) and request_json.get("query")),
                },
            )
            return
        self._json(404, {"ok": False, "error": "not_found", "path": self.path})


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the loopback fixture server for Tallow examples")
    parser.add_argument("--port", type=int, default=18080, help="Loopback port; use 0 to allocate a free port")
    args = parser.parse_args()
    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), FixtureHandler)
    url = f"http://127.0.0.1:{httpd.server_port}"
    print(f"tallow examples mock server listening on {url}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
