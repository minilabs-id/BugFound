"""Offline loopback lab fixture. No external target, no credentials, no state.

Routes:
  GET /reflect?q=<value> -> 200 with the raw value reflected (Tier A canary echo)
  GET /safe?q=<value>    -> 200 without reflection (negative control)
  GET /health            -> 200

This is a wiring fixture for the evaluation harness. It is NOT a benchmark
result and must never be reported as one.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 - stdlib API
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        value = query.get("q", [""])[0]
        if parsed.path == "/reflect":
            self._send(200, "<html>reflected: " + value + "</html>")
        elif parsed.path == "/safe":
            self._send(200, "<html>static page, no reflection</html>")
        elif parsed.path == "/health":
            self._send(200, "ok")
        else:
            self._send(404, json.dumps({"error": "not_found"}))

    def log_message(self, _format: str, *_args: object) -> None:
        return


def start_lab_server():
    """Bind an ephemeral loopback port; return (base_url, shutdown_callable)."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def shutdown() -> None:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    return f"http://127.0.0.1:{server.server_port}", shutdown
