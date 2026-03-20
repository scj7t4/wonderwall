"""DNS server — answers all A queries with a configured IP."""

import ipaddress
import logging
import os
import re
import socket

from nserver import A, NameServer, Query
from nserver.application import DirectApplication
from nserver.rules import ALL_QTYPES
from nserver.transport import UDPv4Transport

log = logging.getLogger(__name__)

DNS_PORT = int(os.getenv("DNS_PORT", "53"))
DNS_A_RECORD_IP = os.getenv("DNS_A_RECORD_IP", None)
INTERNAL_SUBNET = os.getenv("INTERNAL_SUBNET", None)


def _resolve_a(name: str, internal_network, fallback_ip: str) -> str:
    """Return the IP for an A record: internal address if it falls in internal_network, else fallback_ip."""
    if not internal_network:
        return fallback_ip
    try:
        results = socket.getaddrinfo(name, None, socket.AF_INET)
        ips = [r[4][0] for r in results]
        log.debug("Resolved %s to %s", name, ips)
        for ip in ips:
            if ipaddress.ip_address(ip) in internal_network:
                log.debug(
                    "%s is in %s, returning internal IP %s", ip, internal_network, ip
                )
                return ip
        log.debug(
            "No resolved IPs in %s, returning fallback %s",
            internal_network,
            fallback_ip,
        )
    except socket.gaierror as e:
        log.debug(
            "Failed to resolve %s: %s, returning fallback %s", name, e, fallback_ip
        )
    return fallback_ip


def _make_catch_all_a(internal_network, fallback_ip):
    """Return a handler that resolves A queries, preferring internal IPs when configured."""
    def catch_all_a(query: Query):
        log.info("Got query for %s", query.name)
        ip = _resolve_a(query.name, internal_network, fallback_ip)
        return A(query.name, ip)
    return catch_all_a


def _catch_all_other(_: Query):
    return None  # NOERROR with empty answer — domain exists, record type unsupported


def run_dns_server():
    ns = NameServer("wonderwall")
    internal_network = (
        ipaddress.ip_network(INTERNAL_SUBNET, strict=False) if INTERNAL_SUBNET else None
    )
    if internal_network is None:
        log.info(
            "INTERNAL_SUBNET not configured, all DNS queries will resolve to DNS_A_RECORD_IP (%s)",
            DNS_A_RECORD_IP,
        )

    ns.rule(re.compile(r".*"), ["A"])(_make_catch_all_a(internal_network, DNS_A_RECORD_IP))
    ns.rule(re.compile(r".*"), ALL_QTYPES)(_catch_all_other)

    app = DirectApplication(ns, UDPv4Transport("0.0.0.0", DNS_PORT))
    log.info("DNS server on :%d, resolving A queries to %s", DNS_PORT, DNS_A_RECORD_IP)
    app.run()
