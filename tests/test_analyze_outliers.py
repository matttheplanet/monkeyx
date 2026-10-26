"""Tests for _find_outlier_ports in the analyze module.

Outlier ports (open on very few hosts) surface potential dev/forgotten services.
tcpwrapped is nmap's "handshake succeeded but no service banner" state — it's
not a reliable service signal, so it must be excluded from outlier detection.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.analyze import _find_outlier_ports


def _port(host, port, service="", proto="tcp"):
    return {"type": "open_port", "host": host, "port": port,
            "proto": proto, "service": service}


class TestOutlierTcpwrapped:
    def test_tcpwrapped_only_port_is_not_an_outlier(self):
        recs = [_port("10.0.0.1", 8443, "tcpwrapped")]
        assert _find_outlier_ports(recs) == []

    def test_tcpwrapped_host_excluded_from_port_set(self):
        # 9000 is a real service on one host and tcpwrapped on another; only the
        # real host should count, and it stays an outlier (count == 1).
        recs = [_port("10.0.0.1", 9000, "http"),
                _port("10.0.0.2", 9000, "tcpwrapped")]
        outliers = _find_outlier_ports(recs)
        assert len(outliers) == 1
        o = outliers[0]
        assert o["port"] == "9000/tcp"
        assert o["hosts"] == ["10.0.0.1"]
        assert o["count"] == 1
        assert o["service"] == "http"

    def test_tcpwrapped_does_not_pad_below_threshold(self):
        # A real port on 3 hosts is over the default threshold (2) and not an
        # outlier; tcpwrapped hits on other hosts must not change that either way.
        recs = [_port(f"10.0.0.{i}", 443, "https") for i in (1, 2, 3)]
        recs += [_port("10.0.0.9", 443, "tcpwrapped")]
        assert _find_outlier_ports(recs) == []

    def test_case_insensitive(self):
        recs = [_port("10.0.0.1", 8443, "TCPWrapped")]
        assert _find_outlier_ports(recs) == []

    def test_real_outlier_still_detected(self):
        recs = [_port("10.0.0.1", 3000, "ppp")]
        outliers = _find_outlier_ports(recs)
        assert len(outliers) == 1 and outliers[0]["port"] == "3000/tcp"
