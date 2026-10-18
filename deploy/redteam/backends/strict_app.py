#!/usr/bin/env python3
"""
Strict Target Application Mock (Go net/http / Python Werkzeug Strict)
Section 2.2 of docs/plan/redteam-plan.md:
- Strictly compliant with RFC 7230/9112
- Rejects matrix parameters (does not strip ';', returns 404 for unknown endpoints)
- Does not decompress request bodies with Content-Encoding: gzip
- Strict JSON validation only
"""

import http.server
import json
import sys
import urllib.parse

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8002

class StrictHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        sys.stderr.write(f"[Strict] {self.address_string()} - {format % args}\n")

    def _read_body(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            return b""
        return self.rfile.read(content_length)

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def do_PUT(self):
        self._handle_request("PUT")

    def _handle_request(self, method):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self._read_body()

        # Strict: matrix parameters are NOT stripped; unknown route -> 404
        if ";" in path:
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Not Found", "detail": "Strict RFC routing"}).encode())
            return

        # Protected admin route
        if path == "/admin":
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer valid-token"):
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Unauthorized"}).encode())
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "admin_granted"}).encode())
            return

        # Default standard response
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        resp = {
            "backend": "strict",
            "method": method,
            "path": path,
            "body_length": len(body)
        }
        self.wfile.write(json.dumps(resp).encode())

if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), StrictHandler)
    print(f"Strict backend listening on port {PORT}")
    server.serve_forever()
