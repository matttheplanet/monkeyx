"""Egress anonymization coverage for ai_analyze.

Regression for a partial leak: finding titles embed client hostnames and raw
host IPs. The documented guarantee is that no client-identifying data reaches
the AI, so _build_host_alias_map must also cover IPs that appear only inside
finding text (not just host keys) before any pass egresses the prompt.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules import ai_analyze


def _host_data():
    # A high-severity CVE finding whose title embeds a client domain AND a
    # resolved IP that is not itself a host key (mirrors testssl SWEET32 output).
    return {"hosts": {
        "victim.example.com": {
            "findings": [{
                "severity": "high",
                "title": "CVE-2016-2183 SWEET32 on victim.example.com (203.0.113.9)",
                "detail": "64-bit block cipher (3DES) offered",
            }],
            "ports": [],
            "web_dirs": [],
            "subdomains": [],
        }
    }}


class TestAliasMapCoverage:
    def test_text_only_ip_is_aliased(self):
        t2a, _ = ai_analyze._build_host_alias_map(_host_data())
        # host key + the domain extracted from the title are covered as before...
        assert "victim.example.com" in t2a
        # ...and the IP that only appears inside the finding text is now aliased.
        assert "203.0.113.9" in t2a


class TestPlaceholderWrapperStrip:
    """Regression: the model wraps host labels in command placeholders like
    `<H1_IP>`; de-alias turns the inner H1 into the real IP, leaving a broken
    `<198.18.7.111_IP>`. deanonymize_obj must unwrap these to bare values so
    the commands in the deliverable are runnable."""

    def test_ip_placeholder_unwrapped_via_dealias(self):
        from core.anonymize import deanonymize_obj
        a2t = {"H1": "198.18.7.111", "D1": "example.com"}
        obj = {"commands": ["redis-cli -h <H1_IP> -p 6379 INFO",
                            "nmap -p 6379 <D1_hostname>"]}
        out = deanonymize_obj(obj, a2t)
        assert out["commands"][0] == "redis-cli -h 198.18.7.111 -p 6379 INFO"
        assert out["commands"][1] == "nmap -p 6379 example.com"
        assert "<" not in " ".join(out["commands"])

    def test_bare_alias_still_dealiased_normally(self):
        from core.anonymize import deanonymize_obj
        a2t = {"H1": "198.18.7.111"}
        assert deanonymize_obj("connect to H1:6379", a2t) == "connect to 198.18.7.111:6379"

    def test_legit_angle_bracket_text_untouched(self):
        # An HTML-ish token without the _IP/_hostname suffix must survive.
        from core.anonymize import deanonymize_obj
        assert deanonymize_obj("<title>Login</title>", {}) == "<title>Login</title>"

    def test_case_insensitive_suffix(self):
        from core.anonymize import _strip_placeholder_wrappers
        assert _strip_placeholder_wrappers("curl http://<10.0.0.1_ip>/") == "curl http://10.0.0.1/"
