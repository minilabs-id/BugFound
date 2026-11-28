#!/usr/bin/env python3
"""Loopback-only target used by the BugFound agent fixture lab.

Reflects the tool-minted `X-BugFound-Canary` header into the response body so
the `canary_echo` verifier oracle has deterministic, tool-produced bytes.
No external network access; bind is always 127.0.0.1.
"""

from __future__ import annotations

import argparse
import os
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib naming
        canary = self.headers.get("X-BugFound-Canary", "")
        body = (
            "<!doctype html><html><body>"
            "<h1>BugFound local lab target</h1>"
            f"<p>probe-reflection: {canary}</p>"
            + (
                f"<p>{os.environ.get('INJECT_PAYLOAD', '')}</p>"
                if os.environ.get("INJECT_PAYLOAD")
                else ""
            )
            + "</body></html>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
