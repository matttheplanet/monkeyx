"""nuclei DNS templates report the DNS QUERY NAME as matched-at, not the asset
host. Stored verbatim these pin findings to non-existent hosts. _normalize_dns_host
maps them back to the real asset.

Regression from a real run:
  - ptr-fingerprint gave host '111.7.18.198' (byte-reverse of 198.18.7.111)
  - dmarc/srv gave '_dmarc.example.com' / '_ldap._tcp.example.com'
  - wildcard-dns-detect gave '<rand>-<rand>.example.com'
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from modules.normalize import _normalize_dns_host


@pytest.mark.parametrize("query_name,expected", [
    # reverse-DNS PTR names -> the un-reversed IP
    ("111.7.18.198.in-addr.arpa", "198.18.7.111"),
    ("14.3.18.198.in-addr.arpa", "198.18.3.14"),
    ("1.0.0.127.in-addr.arpa", "127.0.0.1"),
    # service labels -> parent domain
    ("_dmarc.example.com", "example.com"),
    ("_ldap._tcp.example.com", "example.com"),
    ("_sip._udp.example.com", "example.com"),
    # wildcard-detection probe label -> parent
    ("3jn1tz9yyufbn3jtpf6ryoowhk8-3jn1tz9yyufbn3jtpf6ryoowhk8.example.com",
     "example.com"),
    ("3jn1tz9yyufbn3jtpf6ryoowhk8-3jn1tz9yyufbn3jtpf6ryoowhk8.api.acme-corp.example.com",
     "api.acme-corp.example.com"),
    # real hosts / IPs pass through untouched
    ("example.com", "example.com"),
    ("app.example.com", "app.example.com"),
    ("198.18.7.111", "198.18.7.111"),
    ("acme-corp.example.com", "acme-corp.example.com"),  # legit hyphen
    ("", ""),
])
def test_normalize_dns_host(query_name, expected):
    assert _normalize_dns_host(query_name) == expected


def test_ipv6_ptr_unreversed():
    # ::1 in ip6.arpa nibble form
    q = ("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0"
         ".ip6.arpa")
    assert _normalize_dns_host(q) == "::1"


def test_partial_ptr_zone_left_alone():
    # A /24 reverse zone (3 labels) is not a host address — leave it, don't
    # fabricate an IP.
    assert _normalize_dns_host("0.113.203.in-addr.arpa") == "0.113.203.in-addr.arpa"


def test_pipeline_ptr_unreversed_not_phantom_ip(tmp_path):
    # PIPELINE regression: _host_port_from_url runs on matched-at and would match
    # the reversed dotted-quad in '<rev>.in-addr.arpa' as an IP, stripping the
    # arpa suffix so the un-reversal never fired -> phantom reversed-IP host.
    # (The unit test above passed while the real pipeline still produced the
    # phantom.) Assert the full _parse_nuclei_jsonl path yields the real IP.
    import json
    from modules.normalize import _parse_nuclei_jsonl
    p = tmp_path / "scan-nuclei.jsonl"
    p.write_text("\n".join([
        json.dumps({"template-id": "ptr-fingerprint",
                    "matched-at": "111.7.18.198.in-addr.arpa",
                    "info": {"name": "PTR Detected", "severity": "info"}}),
        json.dumps({"template-id": "dmarc-detect",
                    "matched-at": "_dmarc.example.com",
                    "info": {"name": "DMARC", "severity": "info"}}),
        json.dumps({"template-id": "redis-unauth",
                    "matched-at": "198.18.7.111:6379",
                    "info": {"name": "Redis", "severity": "high"}}),
    ]) + "\n")
    by_tmpl = {r["template_id"]: r for r in _parse_nuclei_jsonl(str(p))}
    assert by_tmpl["ptr-fingerprint"]["host"] == "198.18.7.111"   # un-reversed
    assert by_tmpl["dmarc-detect"]["host"] == "example.com"        # label stripped
    assert by_tmpl["redis-unauth"]["host"] == "198.18.7.111"      # host:port intact
    assert by_tmpl["redis-unauth"]["port"] == 6379
