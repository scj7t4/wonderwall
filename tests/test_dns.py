"""Tests for wonderwall DNS server resolution logic."""

import ipaddress
import socket
from unittest.mock import patch

from wonderwall.dns import _resolve_a

INTERNAL_NET = ipaddress.ip_network("172.128.0.0/24")
FALLBACK = "1.2.3.4"


def _gai(ip):
    """Minimal socket.getaddrinfo return value for a single IPv4 address."""
    return [(socket.AF_INET, None, None, None, (ip, 0))]


class TestResolveA:
    def test_returns_internal_ip_when_in_subnet(self):
        with patch("socket.getaddrinfo", return_value=_gai("172.128.0.5")):
            assert _resolve_a("svc.internal", INTERNAL_NET, FALLBACK) == "172.128.0.5"

    def test_returns_fallback_when_external(self):
        with patch("socket.getaddrinfo", return_value=_gai("8.8.8.8")):
            assert _resolve_a("example.com", INTERNAL_NET, FALLBACK) == FALLBACK

    def test_returns_fallback_when_no_subnet_configured(self):
        with patch("socket.getaddrinfo", return_value=_gai("172.128.0.5")):
            assert _resolve_a("svc.internal", None, FALLBACK) == FALLBACK

    def test_returns_fallback_on_dns_error(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror):
            assert _resolve_a("bad.host", INTERNAL_NET, FALLBACK) == FALLBACK

    def test_returns_first_matching_internal_from_multiple_results(self):
        results = _gai("8.8.8.8") + _gai("172.128.0.10")
        with patch("socket.getaddrinfo", return_value=results):
            assert _resolve_a("multi.host", INTERNAL_NET, FALLBACK) == "172.128.0.10"
