import asyncio
import socket
import threading
import time
from collections import namedtuple
from functools import partial
from http.server import HTTPServer

import pytest

import wonderwall.proxy as proxy_module
from wonderwall.static import QuietStaticHandler


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"Server on port {port} did not start within {timeout}s")


@pytest.fixture()
def static_server(tmp_path, monkeypatch):
    """Starts a real HTTPServer on a random port serving from a temp directory."""
    port = _free_port()
    monkeypatch.setenv("HTTP_PORT", str(port))
    monkeypatch.setenv("STATIC_DIR", str(tmp_path))

    handler = partial(QuietStaticHandler, directory=str(tmp_path))
    server = HTTPServer(("127.0.0.1", port), handler)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _wait_for_port(port)

    ServerInfo = namedtuple("ServerInfo", ["base_url", "root"])
    yield ServerInfo(base_url=f"http://127.0.0.1:{port}", root=tmp_path)

    server.shutdown()
    thread.join(timeout=2.0)


@pytest.fixture()
def proxy_server(monkeypatch):
    """Starts a real SNI proxy backed by an echo upstream, both on random ports."""
    upstream_port = _free_port()
    proxy_port = _free_port()

    monkeypatch.setattr(proxy_module, "UPSTREAM_PORT", upstream_port)
    monkeypatch.setattr(proxy_module, "ALLOWED_HOSTS", {"localhost"})

    loop = asyncio.new_event_loop()
    servers = {}

    async def echo_handler(reader, writer):
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

    async def start():
        servers["upstream"] = await asyncio.start_server(
            echo_handler, "", upstream_port  # all interfaces: works for both 127.0.0.1 and ::1
        )
        servers["proxy"] = await asyncio.start_server(
            proxy_module.handle_tls, "127.0.0.1", proxy_port
        )

    loop.run_until_complete(start())
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    _wait_for_port(proxy_port)

    ProxyInfo = namedtuple("ProxyInfo", ["proxy_port", "upstream_port"])
    yield ProxyInfo(proxy_port=proxy_port, upstream_port=upstream_port)

    async def stop():
        for s in servers.values():
            s.close()
            await s.wait_closed()

    asyncio.run_coroutine_threadsafe(stop(), loop).result(timeout=5.0)
    loop.call_soon_threadsafe(loop.stop)
    thread.join(timeout=2.0)
    loop.close()
