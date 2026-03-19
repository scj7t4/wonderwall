"""
Integration tests for the Wonderwall HTTP static file server.

Each test starts a real HTTPServer on a random unprivileged port and uses
`requests` to verify end-to-end behavior.
"""

from concurrent.futures import ThreadPoolExecutor

import requests


class TestStaticFileServing:

    def test_existing_file_returns_200(self, static_server):
        (static_server.root / "hello.txt").write_text("hello world")
        r = requests.get(f"{static_server.base_url}/hello.txt")
        assert r.status_code == 200
        assert r.text == "hello world"

    def test_missing_file_returns_404(self, static_server):
        r = requests.get(f"{static_server.base_url}/nonexistent.txt")
        assert r.status_code == 404

    def test_directory_listing_returns_200(self, static_server):
        (static_server.root / "index.html").write_text("<h1>Hi</h1>")
        # SimpleHTTPRequestHandler may redirect bare "/" — requests follows it
        r = requests.get(f"{static_server.base_url}/")
        assert r.status_code == 200

    def test_directory_listing_contains_filename(self, static_server):
        (static_server.root / "somefile.txt").write_text("data")
        r = requests.get(f"{static_server.base_url}/")
        assert "somefile.txt" in r.text

    def test_nested_file(self, static_server):
        subdir = static_server.root / "sub"
        subdir.mkdir()
        (subdir / "data.json").write_text('{"key": "value"}')
        r = requests.get(f"{static_server.base_url}/sub/data.json")
        assert r.status_code == 200
        assert r.json() == {"key": "value"}

    def test_missing_nested_path_returns_404(self, static_server):
        r = requests.get(f"{static_server.base_url}/sub/missing.txt")
        assert r.status_code == 404

    def test_head_request(self, static_server):
        (static_server.root / "page.html").write_text("<html></html>")
        r = requests.head(f"{static_server.base_url}/page.html")
        assert r.status_code == 200
        assert r.headers.get("Content-Length") is not None
        assert r.content == b""

    def test_large_file(self, static_server):
        data = b"x" * 1_048_576
        (static_server.root / "bigfile.bin").write_bytes(data)
        r = requests.get(f"{static_server.base_url}/bigfile.bin")
        assert r.status_code == 200
        assert len(r.content) == 1_048_576

    def test_empty_file_returns_200(self, static_server):
        (static_server.root / "empty.txt").write_bytes(b"")
        r = requests.get(f"{static_server.base_url}/empty.txt")
        assert r.status_code == 200
        assert r.content == b""

    def test_path_traversal_blocked(self, static_server):
        r = requests.get(f"{static_server.base_url}/../etc/passwd")
        assert r.status_code != 200

    def test_concurrent_requests(self, static_server):
        (static_server.root / "a.txt").write_text("aaa")
        (static_server.root / "b.txt").write_text("bbb")
        urls = [
            f"{static_server.base_url}/a.txt",
            f"{static_server.base_url}/b.txt",
        ]
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(requests.get, urls))
        assert all(r.status_code == 200 for r in responses)
        bodies = {r.text for r in responses}
        assert bodies == {"aaa", "bbb"}
