"""Tests for wonderwall entry point (wonderwall/__main__.py)."""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from wonderwall.__main__ import configure_logger, main


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
# main
# ─────────────────────────────────────────────


class TestMain:
    def test_raises_when_dns_ip_missing(self, monkeypatch):
        monkeypatch.delenv("DNS_A_RECORD_IP", raising=False)
        # Patch module-level DNS_A_RECORD_IP to None
        with patch("wonderwall.__main__.DNS_A_RECORD_IP", None):
            with pytest.raises(ValueError, match="DNS_A_RECORD_IP"):
                asyncio.run(main())

    def test_starts_all_services(self, monkeypatch):
        mock_server = MagicMock()
        mock_server.__aenter__ = AsyncMock(return_value=mock_server)
        mock_server.__aexit__ = AsyncMock(return_value=None)
        mock_server.serve_forever = AsyncMock(side_effect=asyncio.CancelledError)

        with (
            patch("wonderwall.__main__.DNS_A_RECORD_IP", "1.2.3.4"),
            patch("asyncio.start_server", AsyncMock(return_value=mock_server)) as mock_start,
            patch("threading.Thread") as mock_thread,
            patch("wonderwall.__main__.configure_logger"),
        ):
            with pytest.raises((asyncio.CancelledError, RuntimeError)):
                asyncio.run(main())

        mock_start.assert_called_once()
        assert mock_thread.call_count == 2
