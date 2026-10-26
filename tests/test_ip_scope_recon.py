"""Tests for the derived-IP network summary (CDN/third-party sprawl signal).

Complements test_ip_scope.py: authorization can't be inferred from DNS/WHOIS
(a customer's own cloud VMs share their provider's org/ASN), so the tool
surfaces the ambiguity — a wide /16 spread of derived public IPs — rather than
auto-classifying scope.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.target_ledger import TargetLedger, TYPE_IP


def _domain_ledger(tmp_path, domain="example.com"):
    (tmp_path / "dl.txt").write_text(domain + "\n")
    led = TargetLedger(str(tmp_path))
    led.seed_user_inputs(None, str(tmp_path / "dl.txt"), None)
    return led


def test_summary_counts_distinct_16s(tmp_path):
    led = _domain_ledger(tmp_path)
    # Third-party spread (SendGrid/Cloudflare/CloudFront/M365/Adobe), a
    # real-world CDN/SaaS sprawl case — 5 distinct /16s.
    for ip in ["149.72.223.224", "172.64.145.37", "18.245.124.117",
               "52.96.121.146", "198.18.15.131"]:
        led.log_discovery(ip, TYPE_IP, "dnsx_resolve", parent="example.com")
    s = led.derived_ip_network_summary()
    assert s["ip_count"] == 5
    assert s["network_count"] == 5
    assert "149.72.0.0/16" in s["networks"]


def test_summary_ignores_explicit_and_private(tmp_path):
    (tmp_path / "t.txt").write_text("198.18.10.0/24\n8.8.8.8\n")
    led = TargetLedger(str(tmp_path))
    led.seed_user_inputs(str(tmp_path / "t.txt"), None, None)
    # Explicit IPs/CIDRs are not "derived" and must not count.
    led.log_discovery("10.0.0.5", TYPE_IP, "dns_resolve", parent="8.8.8.8")  # private
    s = led.derived_ip_network_summary()
    assert s["ip_count"] == 0
    assert s["network_count"] == 0


def test_domain_only_has_no_authorized_ranges(tmp_path):
    """The condition that makes --ip-scope strict a no-op (and triggers the
    warning): a domain-only run has no authorized IP ranges."""
    led = _domain_ledger(tmp_path)
    assert led._authorized_ip_networks() == []


def test_t_ranges_are_authorized(tmp_path):
    (tmp_path / "t.txt").write_text("198.18.10.0/24\n")
    led = TargetLedger(str(tmp_path))
    led.seed_user_inputs(str(tmp_path / "t.txt"), None, None)
    assert len(led._authorized_ip_networks()) == 1
