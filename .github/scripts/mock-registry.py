#!/usr/bin/env python3
"""Mock keypackage/account registry for the chat-cli CI smoketest.

On startup the client registers its keypackage and account bundle. Publishing the
bundle first fetches any existing record, so the stub answers:

  * POST /v0/keypackage, POST /v0/account -> 200 (accept the write)
  * GET  (any)                            -> 404 (nothing published yet)

A 404 is what a fresh account looks like, which the client reads as "no existing
record". This validates nothing — it only unblocks the smoketest; protocol-level
behavior is covered by the workspace tests.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    # Match the client's HTTP/1.1 requests so reqwest frames the response body.
    protocol_version = "HTTP/1.1"

    def _drain(self):
        # Consume the request body so the client's request completes cleanly.
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)

    def _reply(self, status):
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        self._drain()
        self._reply(200)

    def do_GET(self):
        self._drain()
        self._reply(404)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 18080), Handler).serve_forever()
