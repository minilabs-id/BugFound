"""Tiny local HTTP target for AgentBug construction evidence only.

It exposes a reflected parameter and a state-changing endpoint so the
`http_request` / `active_scan` tools can be exercised end-to-end under an
explicit local brief that authorizes state changes. Nothing here is sent
anywhere; it only listens on loopback.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import json
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
STATE = {"counter": 0, "notes": []}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status, body, content_type="text/html; charset=utf-8"):
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Local-Lab", "agentbug-construction-evidence")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if parsed.path == "/":
            self._send(200, "<html><title>Local Lab</title><body>Local lab root. Try /search?q=test or /api/items.</body></html>")
        elif parsed.path == "/search":
            q = params.get("q", [""])[0]
            self._send(200, f"<html><title>Search</title><body>You searched for: {q}</body></html>")
        elif parsed.path == "/api/items":
            self._send(200, json.dumps({"items": [1, 2, 3], "counter": STATE["counter"]}), "application/json")
        elif parsed.path == "/state":
            self._send(200, json.dumps(STATE), "application/json")
        else:
            self._send(404, "not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(min(length, 65536)).decode("utf-8", "replace")
        if parsed.path == "/api/items":
            STATE["counter"] += 1
            STATE["notes"].append(body[:200])
            self._send(201, json.dumps({"ok": True, "counter": STATE["counter"]}), "application/json")
        elif parsed.path == "/search":
            self._send(200, f"<html><body>POST search: {body[:200]}</body></html>")
        else:
            self._send(404, "not found")

    def log_message(self, fmt, *args):
        sys.stderr.write("local-lab " + (fmt % args) + "\n")


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"local lab listening on 127.0.0.1:{PORT}")
    server.serve_forever()
