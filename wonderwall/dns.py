"""DNS server — answers all A queries with a configured IP."""

import logging
import os
import re

from nserver import A, NameServer, Query
from nserver.application import DirectApplication
from nserver.rules import ALL_QTYPES
from nserver.transport import UDPv4Transport

log = logging.getLogger(__name__)

DNS_PORT = int(os.getenv("DNS_PORT", "53"))
DNS_A_RECORD_IP = os.getenv("DNS_A_RECORD_IP", None)


def run_dns_server():
    ns = NameServer("wonderwall")

    @ns.rule(re.compile(r".*"), ["A"])
    def catch_all_a(query: Query):
        log.info("Got query for %s", query.name)
        return A(query.name, DNS_A_RECORD_IP)

    @ns.rule(re.compile(r".*"), ALL_QTYPES)
    def catch_all_other(_: Query):
        return None  # NOERROR with empty answer — domain exists, record type unsupported

    app = DirectApplication(ns, UDPv4Transport("0.0.0.0", DNS_PORT))
    log.info("DNS server on :%d, resolving A queries to %s", DNS_PORT, DNS_A_RECORD_IP)
    app.run()
