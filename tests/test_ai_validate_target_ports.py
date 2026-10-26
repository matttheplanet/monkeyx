"""ai_validate host/port extraction must survive malformed 'host:port:port'.

Regression (#10): the AI sometimes emits a target like 'host:6379:6379' or
'host:4280:443' (it treats a nuclei matched-at 'host:port' as the host and
re-appends a port). The old extractors only stripped a port when there was
exactly ONE colon, so on these they returned the whole string as the host and
None as the port — nulling the finding_id/port join so 17/18 verdicts never
wrote back to scan.db. Host = first label; port = FIRST port (the real service
port; the appended one is noise). Bare/bracketed IPv6 must be left intact.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import modules.ai_validate as av


class TestExtractHost:
    def test_doubled_port_same(self):
        assert av._extract_host("pentest-ground.com:6379:6379") == "pentest-ground.com"

    def test_doubled_port_mixed(self):
        assert av._extract_host("pentest-ground.com:4280:443") == "pentest-ground.com"

    def test_plain_host_port(self):
        assert av._extract_host("example.com:443") == "example.com"

    def test_bare_host(self):
        assert av._extract_host("example.com") == "example.com"

    def test_url(self):
        assert av._extract_host("https://example.com:8443/x") == "example.com"

    def test_ipv4_doubled_port(self):
        assert av._extract_host("1.2.3.4:80:443") == "1.2.3.4"

    def test_bare_ipv6_preserved(self):
        assert av._extract_host("2001:db8::1") == "2001:db8::1"

    def test_bracket_ipv6(self):
        assert av._extract_host("[2001:db8::1]:443") == "2001:db8::1"

    def test_trailing_type_hint(self):
        assert av._extract_host("referral.example.com (domain)") == "referral.example.com"


class TestExtractPort:
    def test_doubled_port_takes_first(self):
        assert av._extract_port("pentest-ground.com:6379:6379") == 6379

    def test_doubled_port_mixed_takes_first(self):
        # 4280 is the real DVWA port; 443 was spuriously appended.
        assert av._extract_port("pentest-ground.com:4280:443") == 4280

    def test_plain(self):
        assert av._extract_port("example.com:443") == 443

    def test_none_when_absent(self):
        assert av._extract_port("example.com") is None

    def test_url(self):
        assert av._extract_port("https://example.com:8443/x") == 8443

    def test_bare_ipv6_no_port(self):
        assert av._extract_port("2001:db8::1") is None

    def test_bracket_ipv6_port(self):
        assert av._extract_port("[2001:db8::1]:443") == 443
