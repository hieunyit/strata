#!/usr/bin/env python3
"""
Permissive Target Application Mock (Spring Boot / Express / ASP.NET Core)
Section 2.2 of docs/plan/redteam-plan.md:
- Supports matrix parameters in URL paths (;param=val)
- Middleware automatically decompresses Content-Encoding: gzip request bodies
- Accepts loose JSON (comments, trailing commas, deep nesting)
- Vulnerable demonstration endpoints (SQLi, XSS, RCE, admin bypass)
"""

import http.server
import json
import re
import sys
import urllib.parse
import zlib

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8001

class PermissiveHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        sys.stderr.write(f"[Permissive] {self.address_string()} - {format % args}\n")

    def _read_body(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            return b""
        raw_body = self.rfile.read(content_length)

        # Permissive feature: automatic gzip decompression
        encoding = self.headers.get("Content-Encoding", "").lower()
        if "gzip" in encoding:
            try:
                decompressed = zlib.decompress(raw_body, 16 + zlib.MAX_WBITS)
                return decompressed
            except Exception as e:
                sys.stderr.write(f"[Permissive] Gzip decompress error: {e}\n")
        return raw_body

    def _normalize_path(self, path):
        # Permissive feature: strip matrix parameters (;key=val)
        # e.g., /admin;jsessionid=123/sensitive-action -> /admin/sensitive-action
        cleaned = re.sub(r";[^/?#]*", "", path)
        return cleaned

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def do_PUT(self):
        self._handle_request("PUT")

    def _handle_request(self, method):
        raw_path = self.path
        parsed_url = urllib.parse.urlparse(raw_path)
        normalized_path = self._normalize_path(parsed_url.path)
        query = urllib.parse.parse_qs(parsed_url.query)
        body = self._read_body()

        # Matrix param smuggling demo
        if normalized_path == "/admin/sensitive-action" or normalized_path == "/admin":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "status": "success",
                "message": "Admin action executed! (Matrix param bypassed WAF)",
                "raw_path": raw_path,
                "normalized_path": normalized_path
            }
            self.wfile.write(json.dumps(resp).encode())
            return

        # SQLi demonstration
        sqli_param = query.get("id", [""])[0] or query.get("q", [""])[0]
        if sqli_param and any(x in sqli_param.lower() for x in ["union", "select", "drop", "or 1=1"]):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "status": "vuln_sqli",
                "query": sqli_param,
                "data": [{"id": 1, "username": "admin", "role": "superadmin"}]
            }
            self.wfile.write(json.dumps(resp).encode())
            return

        # XSS demonstration
        xss_param = query.get("search", [""])[0]
        if xss_param:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(f"<html><body>Search Results: {xss_param}</body></html>".encode())
            return

        # Check body for gzip decompression / loose json
        if body:
            try:
                # Strip comments for loose JSON
                clean_json_str = re.sub(r"/\*.*?\*/", "", body.decode(errors="ignore"))
                parsed_json = json.loads(clean_json_str)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "json_received", "keys": list(parsed_json.keys())}).encode())
                return
            except Exception:
                pass

        # Default standard response
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        resp = {
            "backend": "permissive",
            "method": method,
            "raw_path": raw_path,
            "normalized_path": normalized_path,
            "body_length": len(body)
        }
        self.wfile.write(json.dumps(resp).encode())

if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), PermissiveHandler)
    print(f"Permissive backend listening on port {PORT}")
    server.serve_forever()
