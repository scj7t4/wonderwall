"""Static file HTTP server."""

import logging
import os
import socket
from functools import partial
from http.server import HTTPServer, SimpleHTTPRequestHandler

log = logging.getLogger(__name__)

HTTP_PORT = int(os.getenv("HTTP_PORT", "80"))
STATIC_DIR = os.getenv("STATIC_DIR", "./static")
STATIC_DOMAIN = os.getenv("STATIC_DOMAIN", socket.gethostname())


class QuietStaticHandler(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.info("HTTP %s %s", self.address_string(), fmt % args)

    def _check_domain(self) -> bool:
        if not STATIC_DOMAIN:
            return True
        host_header = self.headers.get("Host", "")
        hostname = host_header.split(":")[0]
        if hostname == STATIC_DOMAIN:
            return True
        location = f"https://{host_header}{self.path}"
        self.send_response(301)
        self.send_header("Location", location)
        self.end_headers()
        return False

    def do_GET(self):
        if self._check_domain():
            super().do_GET()

    def do_HEAD(self):
        if self._check_domain():
            super().do_HEAD()


def run_static_server():
    os.makedirs(STATIC_DIR, exist_ok=True)
    handler = partial(QuietStaticHandler, directory=STATIC_DIR)
    httpd = HTTPServer(("0.0.0.0", HTTP_PORT), handler)
    log.info(
        "Static server on :%d serving '%s'", HTTP_PORT, os.path.abspath(STATIC_DIR)
    )
    httpd.serve_forever()
