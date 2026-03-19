import socket
import threading
import time
from functools import partial
from http.server import HTTPServer

import pytest

from wonderwall.__main__ import QuietStaticHandler


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

    from collections import namedtuple
    ServerInfo = namedtuple("ServerInfo", ["base_url", "root"])
    yield ServerInfo(base_url=f"http://127.0.0.1:{port}", root=tmp_path)

    server.shutdown()
    thread.join(timeout=2.0)
