#!/usr/bin/env python3
"""DELIBERATELY VULNERABLE demo web app for the CredGuard lab (LOCAL USE ONLY).

It mimics a "link preview" feature: GET /fetch?url=<URL> makes the SERVER
fetch that URL and return the body. There is no validation of the URL, so an
attacker can point it at the instance metadata service (169.254.169.254) and
make the server hand back its IAM credentials. This is the same Server-Side
Request Forgery (SSRF) pattern behind the Capital One breach (2019).

This app is a target for a defensive tool. Do NOT deploy it anywhere real.
"""
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

HOME = """<!doctype html>
<html><head><title>Link Preview (vulnerable demo)</title></head>
<body style="font-family:sans-serif;max-width:640px;margin:40px auto">
<h2>Link Preview Service</h2>
<p style="color:#b00">DEMO target app &mdash; intentionally vulnerable to SSRF. Local lab only.</p>
<form action="/fetch" method="get">
  <input name="url" size="60" placeholder="https://example.com" value="http://example.com">
  <button type="submit">Preview</button>
</form>
<p>The server fetches the URL you give it and shows the result below.</p>
</body></html>"""


class App(BaseHTTPRequestHandler):
    server_version = "LinkPreview/0.1"

    def _send(self, code, body, ctype="text/html"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            return self._send(200, HOME)
        if parsed.path == "/fetch":
            qs = urllib.parse.parse_qs(parsed.query)
            url = (qs.get("url") or [""])[0]
            if not url:
                return self._send(400, "missing url parameter", "text/plain")
            # VULNERABILITY: the server fetches an attacker-controlled URL with
            # no allowlist / no block on link-local metadata addresses.
            try:
                print(f"[ssrf-app] server-side fetch -> {url}", flush=True)
                with urllib.request.urlopen(url, timeout=5) as r:
                    body = r.read()
                return self._send(200, body, "text/plain")
            except Exception as e:
                return self._send(502, f"fetch failed: {e}", "text/plain")
        return self._send(404, "not found", "text/plain")

    def log_message(self, fmt, *args):
        print("[ssrf-app] %s - %s" % (self.address_string(), fmt % args), flush=True)


if __name__ == "__main__":
    # Bound to localhost so it is reachable only from inside the lab machine.
    # Single-threaded on purpose: keeps one stable PID for clear attribution.
    print("[ssrf-app] listening on http://127.0.0.1:8080  (VULNERABLE demo target)", flush=True)
    HTTPServer(("127.0.0.1", 8080), App).serve_forever()
