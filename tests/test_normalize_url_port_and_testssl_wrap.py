"""normalize: infer web ports from scheme (#16) + attribute wrapped testssl
verdicts to their check header (#15).

#16 — nuclei emits most matched-at values as scheme-only URLs
("https://host/path"). `_host_port_from_url` used to return a NULL port for
those, so ~80% of web findings were normalized with no port — orphaning them
from the ports table and from any host:port verdict join, and nulling proto. The
port is now inferred from the scheme (https→443, http→80); a schemeless string
still infers nothing.

#15 — testssl wraps a long result (BEAST lists every weak cipher) so the
VULNERABLE verdict lands on its own deeply-indented continuation line carrying
neither the check name nor its CVE. The parser now tracks the last check header
so the verdict is attributed to BEAST: CVE preserved, mapped severity (low) kept,
instead of a generic "medium VULNERABLE" with the CVE lost.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.normalize import _host_port_from_url, _testssl_severity, _parse_testssl_text


class TestHostPortFromUrl:
    def test_https_infers_443(self):
        assert _host_port_from_url("https://example.com/admin") == ("example.com", 443)

    def test_http_infers_80(self):
        assert _host_port_from_url("http://example.com/") == ("example.com", 80)

    def test_explicit_port_wins(self):
        assert _host_port_from_url("https://example.com:8443/x") == ("example.com", 8443)
        assert _host_port_from_url("http://example.com:8080/") == ("example.com", 8080)

    def test_schemeless_host_infers_nothing(self):
        # nuclei dns-type findings surface a bare host — no port to infer.
        assert _host_port_from_url("pentest-ground.com") == ("pentest-ground.com", None)

    def test_schemeless_host_port_is_split(self):
        # nuclei network/tcp templates emit "host:port" with no scheme (redis,
        # ssh, weblogic). Without the split the port folds into the host and the
        # finding orphans from the ports table + the ai_validate verdict join.
        assert _host_port_from_url("pentest-ground.com:6379") == ("pentest-ground.com", 6379)
        assert _host_port_from_url("duck-store.escape.tech:22") == ("duck-store.escape.tech", 22)

    def test_schemeless_ip_port_is_split(self):
        assert _host_port_from_url("1.2.3.4:6379") == ("1.2.3.4", 6379)

    def test_bare_ipv6_not_split(self):
        # A bare IPv6 has multiple colons — must not be mistaken for host:port.
        assert _host_port_from_url("2001:db8::1") == ("2001:db8::1", None)

    def test_ip_with_port(self):
        assert _host_port_from_url("http://1.2.3.4:81/") == ("1.2.3.4", 81)

    def test_bare_ip_no_scheme(self):
        assert _host_port_from_url("1.2.3.4") == ("1.2.3.4", None)


class TestSeverityNameHint:
    def test_bare_verdict_without_name_is_generic_medium(self):
        # The wrapped verdict line on its own carries no name -> unrecognised.
        assert _testssl_severity("VULNERABLE -- but also supports higher protocols") == "medium"

    def test_name_hint_recovers_beast_low(self):
        assert _testssl_severity(
            "VULNERABLE -- but also supports higher protocols",
            name_hint="BEAST (CVE-2011-3389)") == "low"

    def test_hint_never_manufactures_a_finding(self):
        # A non-finding line stays None even with a scary hint.
        assert _testssl_severity("not vulnerable (OK)", name_hint="Heartbleed (CVE-2014-0160)") is None


# A synthetic testssl block reproducing the BEAST line-wrap seen in the real run:
# the check header (name + CVE, no verdict) then indented cipher-list continuation
# lines, then the deeply-indented VULNERABLE verdict with no name/CVE of its own.
_TESTSSL_BLOCK = """\
 Start 2026-08-27 -->> 1.2.3.4:443 (example.com) <<--
 Testing vulnerabilities

 Heartbleed (CVE-2014-0160)                not vulnerable (OK), no heartbeat extension
 SWEET32 (CVE-2016-2183, CVE-2016-6329)    VULNERABLE, uses 64 bit block ciphers
 BEAST (CVE-2011-3389)                     TLS1: ECDHE-ECDSA-AES128-SHA
                                                 ECDHE-RSA-AES256-SHA
                                                 DES-CBC3-SHA
                                           VULNERABLE -- but also supports higher protocols  TLSv1.1 TLSv1.2 (likely mitigated)
 LUCKY13 (CVE-2013-0169), experimental     potentially VULNERABLE, uses cipher block chaining (CBC)
"""


class TestParseTestsslWrap:
    def _parse(self, tmp_path):
        p = tmp_path / "x-testssl.txt"
        p.write_text(_TESTSSL_BLOCK)
        return _parse_testssl_text(str(p))

    def test_banner_host_port(self, tmp_path):
        recs = self._parse(tmp_path)
        assert recs, "expected findings"
        assert all(r["host"] == "1.2.3.4" and r["port"] == 443 for r in recs)

    def test_beast_verdict_attributed_to_header(self, tmp_path):
        recs = self._parse(tmp_path)
        beast = [r for r in recs if r["cve_id"] == "CVE-2011-3389"]
        assert len(beast) == 1, [r["title"] for r in recs]
        assert beast[0]["severity"] == "low"
        assert beast[0]["title"].startswith("[CVE-2011-3389]")

    def test_section_header_not_a_finding(self, tmp_path):
        recs = self._parse(tmp_path)
        # "Testing vulnerabilities" heading must not become a finding.
        assert not any("Testing vulnerabilities" in r["title"] for r in recs)

    def test_not_vulnerable_header_excluded(self, tmp_path):
        recs = self._parse(tmp_path)
        assert not any(r["cve_id"] == "CVE-2014-0160" for r in recs)  # Heartbleed OK

    def test_self_contained_checks_keep_own_severity(self, tmp_path):
        recs = self._parse(tmp_path)
        by_cve = {r["cve_id"]: r for r in recs}
        assert by_cve["CVE-2016-2183"]["severity"] == "medium"  # SWEET32
        assert by_cve["CVE-2013-0169"]["severity"] == "low"     # LUCKY13

    def test_no_garbage_verdict_claim(self, tmp_path):
        recs = self._parse(tmp_path)
        # The old bug titled a finding "[VULNERABLE -- but also supports ...]".
        assert not any(r["title"].startswith("[VULNERABLE") for r in recs)
