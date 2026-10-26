"""testssl severity must reflect the real-world weight of each named weakness.

Regression: `_testssl_severity` rated EVERY line containing "vulnerable" as
"high". On a real run that turned a wall of CBC/cipher weaknesses (LUCKY13,
BEAST, SWEET32) into 18 "high" findings, burying the genuinely serious ones and
inflating the executive summary. The classifier now maps the well-known
names/CVEs to a defensible severity, defaults an unrecognised vulnerable line to
"medium" (not "high"), and still returns None for OK / not-vulnerable lines.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.normalize import _testssl_severity


class TestKnownVulnsAreNotAllHigh:
    def test_lucky13_is_low(self):
        line = ("LUCKY13 (CVE-2013-0169), experimental   potentially VULNERABLE, "
                "uses cipher block chaining (CBC) ciphers with TLS")
        assert _testssl_severity(line) == "low"

    def test_beast_is_low(self):
        assert _testssl_severity("BEAST (CVE-2011-3389)   VULNERABLE -- but also supported") == "low"

    def test_sweet32_is_medium(self):
        assert _testssl_severity("SWEET32 (CVE-2016-2183, CVE-2016-6329)   VULNERABLE, uses 64 bit block ciphers") == "medium"

    def test_rc4_is_medium(self):
        assert _testssl_severity("RC4 (CVE-2013-2566, CVE-2015-2808)   VULNERABLE (NOT ok)") == "medium"

    def test_heartbleed_stays_high(self):
        # A genuinely serious finding is NOT demoted — this is the signal the
        # blanket-high behaviour was drowning.
        assert _testssl_severity("Heartbleed (CVE-2014-0160)   VULNERABLE (NOT ok)") == "high"

    def test_drown_stays_high(self):
        assert _testssl_severity("DROWN (CVE-2016-0800, CVE-2016-0703)   VULNERABLE") == "high"


class TestProtocolAndCipherTiers:
    def test_sslv3_is_medium(self):
        assert _testssl_severity("SSLv3   offered (NOT ok)") == "medium"

    def test_tls10_is_low(self):
        assert _testssl_severity("TLS 1.0   offered (NOT ok)") == "low"

    def test_export_cipher_is_medium(self):
        assert _testssl_severity("Some EXPORT-grade cipher offered (NOT ok)") == "medium"


class TestNonFindings:
    def test_not_vulnerable_is_none(self):
        assert _testssl_severity("CCS (CVE-2014-0224)   not vulnerable (OK)") is None

    def test_ok_line_is_none(self):
        assert _testssl_severity("TLS_FALLBACK_SCSV (RFC 7507)   downgrade attack prevention supported (OK)") is None

    def test_success_does_not_false_match_ccs(self):
        # bare 'ccs' is a substring of 'success' — must not be mis-scored as the
        # CCS-injection high. This line is not a weakness, so -> None.
        assert _testssl_severity("Handshake test succeeded (OK)") is None


class TestUnknownVulnerableDefault:
    def test_unrecognised_vulnerable_line_defaults_medium(self):
        # Was "high"; an unknown-but-flagged weakness is now conservative-medium.
        assert _testssl_severity("SOMENEWTHING (CVE-2099-9999)   VULNERABLE, details here") == "medium"
