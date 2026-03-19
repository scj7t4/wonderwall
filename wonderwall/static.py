"""Static file HTTP server."""

import http.client
import logging
import os
import socket
from functools import partial
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

from wonderwall.proxy import _parse_allowed_hosts

log = logging.getLogger(__name__)

HTTP_PORT = int(os.getenv("HTTP_PORT", "80"))
STATIC_DIR = os.getenv("STATIC_DIR", "./static")
STATIC_DOMAIN = os.getenv("STATIC_DOMAIN", socket.gethostname())
ALLOWED_DOMAINS = _parse_allowed_hosts(os.getenv("ALLOWED_DOMAINS"))  # None = allow any host

_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade",
})


class QuietStaticHandler(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        log.info("HTTP %s %s", self.address_string(), fmt % args)

    def _proxy_request(self, method: str) -> None:
        host_header = self.headers.get("Host", "")
        parts = host_header.split(":", 1)
        hostname = parts[0]
        port = int(parts[1]) if len(parts) == 2 and parts[1].isdigit() else 80

        if ALLOWED_DOMAINS is not None and not any(p.fullmatch(hostname) for p in ALLOWED_DOMAINS):
            log.warning("Proxy domain not allowed: %s", hostname)
            body = b"403 Forbidden\n"
            self.send_response_only(403)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(body)
            return

        forward_headers = {
            k: v for k, v in self.headers.items()
            if k.lower() not in _HOP_BY_HOP
        }
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        try:
            conn = http.client.HTTPConnection(hostname, port, timeout=30)
            conn.request(method, self.path, body=body, headers=forward_headers)
            resp = conn.getresponse()
            self.send_response_only(resp.status)
            has_content_length = False
            for header, value in resp.getheaders():
                lower = header.lower()
                if lower not in _HOP_BY_HOP:
                    self.send_header(header, value)
                if lower == "content-length":
                    has_content_length = True
            if not has_content_length:
                self.close_connection = True
                self.send_header("Connection", "close")
            self.end_headers()
            if method != "HEAD":
                while chunk := resp.read(8192):
                    self.wfile.write(chunk)
            conn.close()
        except OSError as exc:
            log.warning("Proxy upstream error for %s: %s", host_header, exc)
            err_body = b"502 Bad Gateway\n"
            self.send_response_only(502)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(err_body)))
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(err_body)

    def do_GET(self):
        if not STATIC_DOMAIN or self.headers.get("Host", "").split(":")[0] == STATIC_DOMAIN:
            super().do_GET()
        else:
            self._proxy_request("GET")

    def do_HEAD(self):
        if not STATIC_DOMAIN or self.headers.get("Host", "").split(":")[0] == STATIC_DOMAIN:
            super().do_HEAD()
        else:
            self._proxy_request("HEAD")

    def do_POST(self):
        self._proxy_request("POST")

    def do_PUT(self):
        self._proxy_request("PUT")

    def do_DELETE(self):
        self._proxy_request("DELETE")

    def do_PATCH(self):
        self._proxy_request("PATCH")

    def do_OPTIONS(self):
        self._proxy_request("OPTIONS")


def run_static_server():
    os.makedirs(STATIC_DIR, exist_ok=True)
    handler = partial(QuietStaticHandler, directory=STATIC_DIR)
    httpd = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), handler)
    log.info(
        "Static server on :%d serving '%s'", HTTP_PORT, os.path.abspath(STATIC_DIR)
    )
    httpd.serve_forever()
