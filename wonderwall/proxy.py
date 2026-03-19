"""SNI extraction and TLS pass-through proxy."""

import asyncio
import logging
import os
import re
import socket
import struct

log = logging.getLogger(__name__)


def _parse_allowed_hosts(env_val: str | None) -> list[re.Pattern] | None:
    """Parse ALLOWED_HOSTS env var into compiled regex patterns, or None to allow all."""
    if not env_val:
        return None
    return [re.compile(p.strip()) for p in env_val.split(",") if p.strip()]


STATIC_DOMAIN = os.getenv("STATIC_DOMAIN", socket.gethostname())  # HTTP-only host, never TLS proxied
ALLOWED_HOSTS = _parse_allowed_hosts(os.getenv("ALLOWED_HOSTS"))  # None = allow any SNI hostname
UPSTREAM_PORT = int(os.getenv("UPSTREAM_PORT", "443"))
PEEK_BYTES = 512


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

        if STATIC_DOMAIN and hostname == STATIC_DOMAIN:
            log.warning("%s: %s is HTTP-only, closing", addr, hostname)
            return

        if ALLOWED_HOSTS is not None and not any(p.fullmatch(hostname) for p in ALLOWED_HOSTS):
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
