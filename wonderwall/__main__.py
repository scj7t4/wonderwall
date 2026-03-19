"""
SNI Pass-Through Proxy + Static File Server (asyncio)
======================================================
Port 443 : TLS pass-through, routed by SNI hostname
Port 80  : Plain HTTP static file server

No dependencies beyond the standard library.
"""

import asyncio
import logging
import os
import struct
import threading
from functools import partial
from http.server import HTTPServer, SimpleHTTPRequestHandler

log = logging.getLogger(__name__)


def configure_logger():
    logging.basicConfig(
        format="[%(asctime)s][%(levelname)-8s] %(message)s",
        level=os.getenv("LOG_LEVEL", "INFO"),
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

PROXY_PORT = 443
HTTP_PORT = int(os.getenv("HTTP_PORT", "80"))
STATIC_DIR = os.getenv("STATIC_DIR", "./static")
STATIC_HOSTS = {"mystatic.local"}  # HTTP-only, never TLS proxied
ALLOWED_HOSTS = None  # None = allow any SNI hostname
UPSTREAM_PORT = int(os.getenv("UPSTREAM_PORT", "443"))
PEEK_BYTES = 512


# ─────────────────────────────────────────────
# SNI EXTRACTION
# ─────────────────────────────────────────────


def extract_sni(data: bytes) -> str | None:
    try:
        if len(data) < 5 or data[0] != 0x16:
            return None
        pos = 5
        if data[pos] != 0x01:
            return None
        pos += 4 + 2 + 32  # type, length, version, random
        sid_len = data[pos]
        pos += 1 + sid_len  # session id
        cs_len = struct.unpack("!H", data[pos : pos + 2])[0]
        pos += 2 + cs_len  # cipher suites
        cm_len = data[pos]
        pos += 1 + cm_len  # compression methods
        if pos + 2 > len(data):
            return None
        ext_end = pos + 2 + struct.unpack("!H", data[pos : pos + 2])[0]
        pos += 2
        while pos + 4 <= ext_end:
            ext_type = struct.unpack("!H", data[pos : pos + 2])[0]
            pos += 2
            ext_len = struct.unpack("!H", data[pos : pos + 2])[0]
            pos += 2
            if ext_type == 0x0000:  # SNI extension
                pos += 3  # list length + name type
                name_len = struct.unpack("!H", data[pos : pos + 2])[0]
                pos += 2
                return data[pos : pos + name_len].decode("ascii")
            pos += ext_len
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────
# RELAY + PROXY
# ─────────────────────────────────────────────


async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Forward bytes from reader → writer until EOF."""
    try:
        while data := await reader.read(4096):
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle_tls(client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter):
    addr = client_w.get_extra_info("peername")
    try:
        # Read the first chunk — StreamReader buffers it, so we can prepend it
        # back for the upstream connection using a feeding trick below.
        peeked = await client_r.read(PEEK_BYTES)
        hostname = extract_sni(peeked)

        if not hostname:
            log.warning("%s: no SNI, closing", addr)
            return

        if hostname in STATIC_HOSTS:
            log.warning("%s: %s is HTTP-only, closing", addr, hostname)
            return

        if ALLOWED_HOSTS and hostname not in ALLOWED_HOSTS:
            log.warning("%s: %s not in allowed hosts, closing", addr, hostname)
            return

        log.info("%s → %s", addr, hostname)
        upstream_r, upstream_w = await asyncio.open_connection(hostname, UPSTREAM_PORT)

        # Forward client data upstream. Use write_eof() instead of close() so
        # upstream_r stays open to receive the upstream's response.
        async def client_to_upstream():
            try:
                upstream_w.write(peeked)
                await upstream_w.drain()
                while data := await client_r.read(4096):
                    upstream_w.write(data)
                    await upstream_w.drain()
            except Exception:
                pass
            finally:
                try:
                    upstream_w.write_eof()
                except Exception:
                    pass

        await asyncio.gather(
            client_to_upstream(),
            relay(upstream_r, client_w),
        )

    except Exception as e:
        log.error("%s: %s", addr, e)
    finally:
        client_w.close()


# ─────────────────────────────────────────────
# STATIC FILE SERVER  (plain HTTP, threaded)
# ─────────────────────────────────────────────


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


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────


async def main():
    configure_logger()

    server = await asyncio.start_server(handle_tls, "0.0.0.0", PROXY_PORT)
    log.info("SNI proxy on :%d", PROXY_PORT)

    # Static server runs in its own thread — it's blocking but lightweight
    threading.Thread(target=run_static_server, daemon=True).start()

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
