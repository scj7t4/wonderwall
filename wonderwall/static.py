"""Static file HTTP server."""

import logging
import os
from functools import partial
from http.server import HTTPServer, SimpleHTTPRequestHandler

log = logging.getLogger(__name__)

HTTP_PORT = int(os.getenv("HTTP_PORT", "80"))
STATIC_DIR = os.getenv("STATIC_DIR", "./static")


class QuietStaticHandler(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.info("HTTP %s %s", self.address_string(), fmt % args)


def run_static_server():
    os.makedirs(STATIC_DIR, exist_ok=True)
    handler = partial(QuietStaticHandler, directory=STATIC_DIR)
    httpd = HTTPServer(("0.0.0.0", HTTP_PORT), handler)
    log.info(
        "Static server on :%d serving '%s'", HTTP_PORT, os.path.abspath(STATIC_DIR)
    )
    httpd.serve_forever()
