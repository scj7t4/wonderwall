"""Tests for wonderwall entry point (wonderwall/__main__.py)."""

from unittest.mock import patch

from wonderwall.__main__ import configure_logger


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
