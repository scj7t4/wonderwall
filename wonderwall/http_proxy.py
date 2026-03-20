"""Static file HTTP server."""

import http.client
import logging
import os
import socket
from functools import partial
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

from wonderwall.https_proxy import _parse_allowed_hosts

log = logging.getLogger(__name__)

HTTP_PORT = int(os.getenv("HTTP_PORT", "80"))
STATIC_DIR = os.getenv("STATIC_DIR", "./static")
STATIC_DOMAIN = os.getenv("STATIC_DOMAIN", socket.gethostname())
ALLOWED_HOSTS = _parse_allowed_hosts(os.getenv("ALLOWED_HOSTS"))  # None = allow any host

_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade",
})


class HttpProxyHandler(SimpleHTTPRequestHandler):
    """HTTP request handler that serves static files for STATIC_DOMAIN and proxies all other requests."""

    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        """Route access log output through the module logger."""
        log.info("HTTP %s %s", self.address_string(), fmt % args)

    def _proxy_request(self, method: str) -> None:
        """Forward an HTTP request to the upstream host named in the Host header."""
        host_header = self.headers.get("Host", "")
        parts = host_header.split(":", 1)
        hostname = parts[0]
        _p = int(parts[1]) if len(parts) == 2 and parts[1].isdigit() else 80
        if not (1 <= _p <= 65535):
            log.warning("Invalid port in Host header: %s", host_header)
            body = b"400 Bad Request\n"
            self.send_response_only(400)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(body)
            return
        port = _p

        if ALLOWED_HOSTS is not None and not any(p.fullmatch(hostname) for p in ALLOWED_HOSTS):
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
        """Serve a static file for STATIC_DOMAIN or proxy GET to the upstream host."""
        if STATIC_DOMAIN and self.headers.get("Host", "").split(":")[0] == STATIC_DOMAIN:
            super().do_GET()
        else:
            self._proxy_request("GET")

    def do_HEAD(self):
        """Serve static file headers for STATIC_DOMAIN or proxy HEAD to the upstream host."""
        if STATIC_DOMAIN and self.headers.get("Host", "").split(":")[0] == STATIC_DOMAIN:
            super().do_HEAD()
        else:
            self._proxy_request("HEAD")

    def do_POST(self):
        """Proxy POST to the upstream host."""
        self._proxy_request("POST")

    def do_PUT(self):
        """Proxy PUT to the upstream host."""
        self._proxy_request("PUT")

    def do_DELETE(self):
        """Proxy DELETE to the upstream host."""
        self._proxy_request("DELETE")

    def do_PATCH(self):
        """Proxy PATCH to the upstream host."""
        self._proxy_request("PATCH")

    def do_OPTIONS(self):
        """Proxy OPTIONS to the upstream host."""
        self._proxy_request("OPTIONS")


def run_static_server():
    """Start the HTTP server and block until it exits."""
    os.makedirs(STATIC_DIR, exist_ok=True)
    handler = partial(HttpProxyHandler, directory=STATIC_DIR)
    httpd = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), handler)
    log.info(
        "Static server on :%d serving '%s'", HTTP_PORT, os.path.abspath(STATIC_DIR)
    )
    httpd.serve_forever()
