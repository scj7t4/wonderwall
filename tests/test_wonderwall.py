"""Tests for wonderwall SNI proxy."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import wonderwall.__main__ as ww
from wonderwall.__main__ import (
    QuietStaticHandler,
    configure_logger,
    extract_sni,
    handle_tls,
    relay,
)
from tests.helpers import build_client_hello


# ─────────────────────────────────────────────
# extract_sni
# ─────────────────────────────────────────────


class TestExtractSni:
    def test_returns_sni_hostname(self):
        assert extract_sni(build_client_hello("example.com")) == "example.com"

    def test_returns_subdomain(self):
        assert extract_sni(build_client_hello("api.internal.company.com")) == "api.internal.company.com"

    def test_returns_long_hostname(self):
        hostname = "a" * 200 + ".example.com"
        assert extract_sni(build_client_hello(hostname)) == hostname

    def test_returns_none_for_empty_bytes(self):
        assert extract_sni(b"") is None

    def test_returns_none_for_short_data(self):
        assert extract_sni(b"\x16\x03\x01") is None

    def test_returns_none_if_not_tls_record(self):
        data = build_client_hello("example.com")
        assert extract_sni(b"\x17" + data[1:]) is None  # content type != 0x16

    def test_returns_none_if_not_client_hello(self):
        data = build_client_hello("example.com")
        # Byte 5 is the handshake type; flip it to ServerHello (0x02)
        assert extract_sni(data[:5] + b"\x02" + data[6:]) is None

    def test_returns_none_when_no_extensions(self):
        assert extract_sni(build_client_hello(sni=None, with_extensions=False)) is None

    def test_returns_none_when_extensions_present_but_no_sni(self):
        # Empty extensions list — no SNI extension
        assert extract_sni(build_client_hello(sni=None, with_extensions=True)) is None

    def test_returns_none_for_all_zeros(self):
        assert extract_sni(b"\x00" * 100) is None

    def test_returns_none_for_random_garbage(self):
        assert extract_sni(b"\xff" * 200) is None


# ─────────────────────────────────────────────
# relay
# ─────────────────────────────────────────────


class TestRelay:
    def test_forwards_data_to_writer(self):
        async def _test():
            reader = asyncio.StreamReader()
            reader.feed_data(b"hello world")
            reader.feed_eof()
            writer = MagicMock()
            writer.drain = AsyncMock()
            writer.close = MagicMock()
            await relay(reader, writer)
            writer.write.assert_called_once_with(b"hello world")
            writer.close.assert_called_once()

        asyncio.run(_test())

    def test_forwards_multiple_chunks(self):
        async def _test():
            reader = asyncio.StreamReader()
            reader.feed_data(b"first ")
            reader.feed_data(b"second")
            reader.feed_eof()
            received = []
            writer = MagicMock()
            writer.write = MagicMock(side_effect=received.append)
            writer.drain = AsyncMock()
            writer.close = MagicMock()
            await relay(reader, writer)
            assert b"".join(received) == b"first second"
            writer.close.assert_called_once()

        asyncio.run(_test())

    def test_closes_writer_on_eof_with_no_data(self):
        async def _test():
            reader = asyncio.StreamReader()
            reader.feed_eof()
            writer = MagicMock()
            writer.drain = AsyncMock()
            writer.close = MagicMock()
            await relay(reader, writer)
            writer.write.assert_not_called()
            writer.close.assert_called_once()

        asyncio.run(_test())

    def test_closes_writer_on_read_exception(self):
        async def _test():
            reader = MagicMock()
            reader.read = AsyncMock(side_effect=ConnectionResetError("peer reset"))
            writer = MagicMock()
            writer.close = MagicMock()
            await relay(reader, writer)
            writer.close.assert_called_once()

        asyncio.run(_test())

    def test_still_closes_writer_if_close_raises(self):
        """relay must not propagate exceptions raised by writer.close()."""
        async def _test():
            reader = asyncio.StreamReader()
            reader.feed_eof()
            writer = MagicMock()
            writer.drain = AsyncMock()
            writer.close = MagicMock(side_effect=OSError("already closed"))
            # Should complete without raising
            await relay(reader, writer)

        asyncio.run(_test())


# ─────────────────────────────────────────────
# handle_tls
# ─────────────────────────────────────────────


class TestHandleTls:
    @staticmethod
    def _make_client(data: bytes):
        """Return a (reader, writer) pair pre-loaded with data. Must be called inside an event loop."""
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        writer = MagicMock()
        writer.get_extra_info = MagicMock(return_value=("127.0.0.1", 12345))
        writer.close = MagicMock()
        writer.drain = AsyncMock()
        writer.write = MagicMock()
        return reader, writer

    @staticmethod
    def _upstream_pair():
        upstream_r = asyncio.StreamReader()
        upstream_r.feed_eof()
        upstream_w = MagicMock()
        upstream_w.drain = AsyncMock()
        upstream_w.close = MagicMock()
        upstream_w.write = MagicMock()
        return upstream_r, upstream_w

    def test_closes_when_no_sni(self):
        async def _test():
            reader, writer = self._make_client(b"\x00" * 100)
            await handle_tls(reader, writer)
            writer.close.assert_called_once()

        asyncio.run(_test())

    def test_closes_for_static_host(self):
        async def _test():
            reader, writer = self._make_client(build_client_hello("mystatic.local"))
            original = ww.STATIC_HOSTS
            try:
                ww.STATIC_HOSTS = {"mystatic.local"}
                await handle_tls(reader, writer)
            finally:
                ww.STATIC_HOSTS = original
            writer.close.assert_called_once()

        asyncio.run(_test())

    def test_closes_for_disallowed_host(self):
        async def _test():
            reader, writer = self._make_client(build_client_hello("evil.com"))
            original = ww.ALLOWED_HOSTS
            try:
                ww.ALLOWED_HOSTS = {"good.com"}
                await handle_tls(reader, writer)
            finally:
                ww.ALLOWED_HOSTS = original
            writer.close.assert_called_once()

        asyncio.run(_test())

    def test_allows_any_host_when_allowed_hosts_is_none(self):
        async def _test():
            reader, writer = self._make_client(build_client_hello("anything.com"))
            mock_open = AsyncMock(side_effect=ConnectionRefusedError("no upstream in test"))
            original_allowed, original_static = ww.ALLOWED_HOSTS, ww.STATIC_HOSTS
            try:
                ww.ALLOWED_HOSTS = None
                ww.STATIC_HOSTS = set()
                with patch("asyncio.open_connection", mock_open):
                    await handle_tls(reader, writer)
            finally:
                ww.ALLOWED_HOSTS = original_allowed
                ww.STATIC_HOSTS = original_static
            # Connection was attempted (not blocked by host filtering)
            mock_open.assert_called_once_with("anything.com", ww.UPSTREAM_PORT)

        asyncio.run(_test())

    def test_proxies_host_in_allowed_list(self):
        async def _test():
            reader, writer = self._make_client(build_client_hello("good.com"))
            mock_open = AsyncMock(side_effect=ConnectionRefusedError("no upstream in test"))
            original_allowed, original_static = ww.ALLOWED_HOSTS, ww.STATIC_HOSTS
            try:
                ww.ALLOWED_HOSTS = {"good.com"}
                ww.STATIC_HOSTS = set()
                with patch("asyncio.open_connection", mock_open):
                    await handle_tls(reader, writer)
            finally:
                ww.ALLOWED_HOSTS = original_allowed
                ww.STATIC_HOSTS = original_static
            mock_open.assert_called_once_with("good.com", ww.UPSTREAM_PORT)

        asyncio.run(_test())

    def test_closes_when_upstream_connection_fails(self):
        async def _test():
            reader, writer = self._make_client(build_client_hello("unreachable.com"))
            original_allowed, original_static = ww.ALLOWED_HOSTS, ww.STATIC_HOSTS
            try:
                ww.ALLOWED_HOSTS = None
                ww.STATIC_HOSTS = set()
                with patch(
                    "asyncio.open_connection",
                    side_effect=ConnectionRefusedError("refused"),
                ):
                    await handle_tls(reader, writer)
            finally:
                ww.ALLOWED_HOSTS = original_allowed
                ww.STATIC_HOSTS = original_static
            writer.close.assert_called_once()

        asyncio.run(_test())


# ─────────────────────────────────────────────
# configure_logger
# ─────────────────────────────────────────────


class TestConfigureLogger:
    def test_defaults_to_info_level(self, monkeypatch):
        monkeypatch.delenv("LOG_LEVEL", raising=False)
        with patch("logging.basicConfig") as mock_cfg:
            configure_logger()
        _, kwargs = mock_cfg.call_args
        assert kwargs["level"] == "INFO"

    def test_reads_log_level_from_env(self, monkeypatch):
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")
        with patch("logging.basicConfig") as mock_cfg:
            configure_logger()
        _, kwargs = mock_cfg.call_args
        assert kwargs["level"] == "DEBUG"

    def test_format_includes_levelname(self, monkeypatch):
        monkeypatch.delenv("LOG_LEVEL", raising=False)
        with patch("logging.basicConfig") as mock_cfg:
            configure_logger()
        _, kwargs = mock_cfg.call_args
        assert "%(levelname" in kwargs["format"]


# ─────────────────────────────────────────────
# QuietStaticHandler
# ─────────────────────────────────────────────


class TestQuietStaticHandler:
    def test_log_message_delegates_to_log(self):
        handler = MagicMock(spec=QuietStaticHandler)
        handler.address_string = MagicMock(return_value="1.2.3.4")

        with patch.object(ww, "log") as mock_log:
            QuietStaticHandler.log_message(handler, "%s %s", "GET", "/index.html")

        mock_log.info.assert_called_once_with("HTTP %s %s", "1.2.3.4", "GET /index.html")
