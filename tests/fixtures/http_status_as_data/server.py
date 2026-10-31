#!/usr/bin/env python3
"""Loopback HTTP fixture used for the assay two-plane 404-as-data audit.

The regression test in tests/http_status_as_data_parity.rs embeds an equivalent
Rust server so CI does not depend on this file. Kept here as the measured
reproduction fixture.

Bind: 127.0.0.1:0 (never a non-loopback socket).
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys
import time


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def _send(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/ok":
            self._send(200, b"ok-body")
        elif path == "/missing":
            self._send(404, b"missing-body")
        elif path == "/boom":
            self._send(500, b"server-error-body")
        elif path == "/go":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        elif path == "/slow":
            time.sleep(3)
            self._send(200, b"slow-body")
        else:
            self._send(404, b"nope")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        path = self.path.split("?", 1)[0]
        if path == "/missing":
            self._send(404, b"post-missing-body")
        else:
            self._send(200, b"post-ok")


def main() -> None:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    host, port = httpd.server_address[:2]
    print(f"{host}:{port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main() or 0)
