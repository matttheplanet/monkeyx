"""Tests for modules.dns_security — SPF/DMARC posture + scope, aligned with the
internet.nl guidance and RFC 7489 organizational-domain inheritance.

Regression coverage for reported false positives:
  1. ~all (SPF softfail) must NOT be flagged (internet.nl accepts ~all and -all).
  2. DMARC p=quarantine must be treated as sufficient.
  3. A subdomain with no _dmarc record inherits the org domain's sp=/p= and must
     not be flagged "missing" when that inherited policy already enforces.
  4. Scope: explicit -d roots are used as-is; third-party apexes aren't invented.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.dns_security import (
    _check_spf,
    _check_dmarc,
    _check_dmarc_fallback,
    _check_open_recursion,
    _check_private_dns,
    _parse_dmarc,
    _org_domain_for,
    _registrable_domain,
    _dmarc_org_domain,
    _load_root_domains,
)
import modules.dns_security as dns_security

import pytest


def _checks(findings):
    return {f["check"] for f in findings}


class TestRegistrableDomain:
    """RFC 7489 org domain = PSL registrable domain (not the immediate parent)."""

    def test_psl_resolution(self):
        pytest.importorskip("tldextract")
        assert _registrable_domain("mail.corp.example.com") == "example.com"
        # Multi-label public suffix must be handled (the whole point of the PSL).
        assert _registrable_domain("a.b.example.co.uk") == "example.co.uk"
        assert _registrable_domain("example.com") == "example.com"

    def test_graceful_without_tldextract(self, monkeypatch):
        # If tldextract is unavailable, return None so callers fall back to the
        # in-scope apex rather than crashing.
        monkeypatch.setattr(dns_security, "_TLD_EXTRACT", None)
        assert _registrable_domain("mail.corp.example.com") is None
        assert _registrable_domain("") is None


class TestDmarcOrgDomainScopeClamp:
    """The DMARC org-domain fallback must stay in scope: the PSL registrable
    domain is used only when it is itself in scope, else the in-scope apex."""

    def test_registrable_in_scope_is_used(self):
        pytest.importorskip("tldextract")
        # Both example.com and sub.example.com in scope; RFC org domain for
        # x.sub.example.com is the registrable example.com, which IS in scope.
        apex = ["example.com", "sub.example.com"]
        assert _dmarc_org_domain("x.sub.example.com", apex) == "example.com"

    def test_out_of_scope_registrable_clamped_to_apex(self):
        pytest.importorskip("tldextract")
        # Only the subdomain-as-root corp.example.com is authorized. The PSL
        # registrable (example.com) is OUT of scope -> must NOT be used; clamp to
        # the in-scope apex so we never query/report example.com.
        apex = ["corp.example.com"]
        assert _dmarc_org_domain("mail.corp.example.com", apex) == "corp.example.com"

    def test_falls_back_to_apex_without_tldextract(self, monkeypatch):
        monkeypatch.setattr(dns_security, "_TLD_EXTRACT", None)
        apex = ["example.com"]
        assert _dmarc_org_domain("mail.example.com", apex) == "example.com"


class TestSPF:
    def test_softfail_not_flagged(self):
        # ~all is a valid posture — no finding (the reported false positive).
        assert _check_spf("ex.com", ["v=spf1 include:_spf.google.com ~all"]) == []

    def test_hardfail_not_flagged(self):
        assert _check_spf("ex.com", ["v=spf1 -all"]) == []

    def test_plus_all_is_critical(self):
        f = _check_spf("ex.com", ["v=spf1 +all"])
        assert len(f) == 1 and f[0]["check"] == "spf_plus_all"
        assert f[0]["severity"] == "CRITICAL"

    def test_neutral_flagged(self):
        f = _check_spf("ex.com", ["v=spf1 ?all"])
        assert _checks(f) == {"spf_neutral"}

    def test_missing_flagged(self):
        f = _check_spf("ex.com", ["some-other-txt"])
        assert _checks(f) == {"spf_missing"}

    def test_multiple_records_flagged(self):
        f = _check_spf("ex.com", ["v=spf1 -all", "v=spf1 ~all"])
        assert "spf_multiple" in _checks(f)


class TestDMARC:
    def test_quarantine_is_sufficient(self):
        # p=quarantine with reporting → no finding (the reported false positive).
        assert _check_dmarc("ex.com", ["v=DMARC1; p=quarantine; rua=mailto:d@ex.com"]) == []

    def test_reject_is_sufficient(self):
        assert _check_dmarc("ex.com", ["v=DMARC1; p=reject; rua=mailto:d@ex.com"]) == []

    def test_none_flagged(self):
        f = _check_dmarc("ex.com", ["v=DMARC1; p=none; rua=mailto:d@ex.com"])
        assert _checks(f) == {"dmarc_none"}

    def test_missing_flagged(self):
        f = _check_dmarc("ex.com", [])
        assert _checks(f) == {"dmarc_missing"}

    def test_no_reporting_is_low(self):
        f = _check_dmarc("ex.com", ["v=DMARC1; p=reject"])
        assert _checks(f) == {"dmarc_no_reporting"}

    def test_invalid_flagged(self):
        f = _check_dmarc("ex.com", ["p=reject; not a dmarc record"])
        assert _checks(f) == {"dmarc_invalid"}


class TestParseDMARC:
    def test_parses_p_and_sp(self):
        p = _parse_dmarc(["v=DMARC1; p=reject; sp=quarantine; rua=mailto:x@ex.com"])
        assert p["p"] == "reject" and p["sp"] == "quarantine" and p["has_reporting"]

    def test_absent_or_invalid(self):
        assert _parse_dmarc([]) is None
        assert _parse_dmarc(["v=spf1 -all"]) is None


class TestDMARCFallback:
    def test_org_quarantine_no_sp_inherits_ok(self):
        # Subdomain with no record inherits org p=quarantine → NOT flagged.
        assert _check_dmarc_fallback(
            "mail.ex.com", "ex.com", ["v=DMARC1; p=quarantine; rua=mailto:x@ex.com"]) == []

    def test_org_reject_inherits_ok(self):
        assert _check_dmarc_fallback(
            "mail.ex.com", "ex.com", ["v=DMARC1; p=reject"]) == []

    def test_org_sp_reject_overrides_p_none(self):
        # sp= wins over p= for subdomains → reject is enforcing → no finding.
        assert _check_dmarc_fallback(
            "mail.ex.com", "ex.com", ["v=DMARC1; p=none; sp=reject"]) == []

    def test_org_p_none_flags_subdomain(self):
        f = _check_dmarc_fallback("mail.ex.com", "ex.com", ["v=DMARC1; p=none"])
        assert _checks(f) == {"dmarc_subdomain_none"}

    def test_org_sp_none_flags_subdomain(self):
        f = _check_dmarc_fallback(
            "mail.ex.com", "ex.com", ["v=DMARC1; p=reject; sp=none"])
        assert _checks(f) == {"dmarc_subdomain_none"}
        assert f[0]["domain"] == "mail.ex.com"

    def test_org_missing_reports_missing(self):
        f = _check_dmarc_fallback("mail.ex.com", "ex.com", [])
        assert _checks(f) == {"dmarc_missing"}


class TestScopeHelpers:
    def test_org_domain_for_longest_match(self):
        orgs = ["ex.com", "corp.ex.com"]
        assert _org_domain_for("a.corp.ex.com", orgs) == "corp.ex.com"
        assert _org_domain_for("a.ex.com", orgs) == "ex.com"
        assert _org_domain_for("other.com", orgs) is None

    def test_third_party_subdomain_out_of_scope(self):
        # A discovered CNAME target under amazonaws.com is not in any -d root.
        assert _org_domain_for("bucket.s3.amazonaws.com", ["ex.com"]) is None

    def test_load_root_domains_uses_entries_as_is(self, tmp_path):
        # Multi-label TLDs must NOT be collapsed to co.uk.
        p = tmp_path / "roots.txt"
        p.write_text("EX.co.uk\n# comment\nex.com.\n\n")
        assert _load_root_domains(str(p)) == ["ex.co.uk", "ex.com"]

    def test_load_root_domains_absent(self):
        assert _load_root_domains(None) is None
        assert _load_root_domains("/no/such/file") is None


class TestOpenRecursion:
    def test_recursion_flagged(self, monkeypatch):
        # Open resolver: answer present, ra set, aa ABSENT (recursed for us).
        monkeypatch.setattr(dns_security, "_dig_answer_and_flags",
                            lambda name, server, timeout=10: (True, {"qr", "rd", "ra"}))
        f = _check_open_recursion("ex.com", ["ns1.ex.com."])
        assert _checks(f) == {"dns_open_recursion"}
        assert f[0]["severity"] == "MEDIUM"
        assert "ns1.ex.com" in f[0]["detail"]

    def test_recursion_not_flagged_when_no_answer(self, monkeypatch):
        monkeypatch.setattr(dns_security, "_dig_answer_and_flags",
                            lambda name, server, timeout=10: (False, {"qr", "rd", "ra"}))
        assert _check_open_recursion("ex.com", ["ns1.ex.com."]) == []

    def test_authoritative_answer_is_not_recursion(self, monkeypatch):
        # Regression: a Cloudflare NS answering one.one.one.one (Cloudflare's own
        # domain) sets aa -> authoritative, NOT open recursion. Must NOT flag.
        monkeypatch.setattr(dns_security, "_dig_answer_and_flags",
                            lambda name, server, timeout=10: (True, {"qr", "aa", "rd", "ra"}))
        assert _check_open_recursion("ex.com", ["crystal.ns.cloudflare.com."]) == []

    def test_no_ra_flag_not_recursion(self, monkeypatch):
        # Answer but recursion NOT available -> not an open resolver.
        monkeypatch.setattr(dns_security, "_dig_answer_and_flags",
                            lambda name, server, timeout=10: (True, {"qr", "rd"}))
        assert _check_open_recursion("ex.com", ["ns1.ex.com."]) == []

    def test_recursion_reported_once_per_ns(self, monkeypatch):
        monkeypatch.setattr(dns_security, "_dig_answer_and_flags",
                            lambda name, server, timeout=10: (True, {"qr", "rd", "ra"}))
        assert len(_check_open_recursion("ex.com", ["ns1.ex.com."])) == 1


class TestPrivateDNS:
    def test_rfc1918_flagged(self):
        f = _check_private_dns("app.ex.com", ["10.1.2.3", "203.0.113.5"], [])
        assert _checks(f) == {"rfc1918_in_public_dns"}
        assert f[0]["severity"] == "LOW"
        assert "10.1.2.3" in f[0]["evidence"]
        assert "203.0.113.5" not in f[0]["evidence"]   # public IP not reported

    def test_all_ranges(self):
        for ip in ("10.0.0.1", "172.16.5.5", "192.168.1.1", "fd00::1"):
            assert _check_private_dns("h.ex.com", [ip], []), ip

    def test_public_only_no_finding(self):
        assert _check_private_dns("ex.com", ["203.0.113.10"], ["2606:4700::1"]) == []

    def test_garbage_ignored(self):
        assert _check_private_dns("ex.com", ["not-an-ip", ""], []) == []


class TestAxfrDelegation:
    def test_soa_mname_parse(self, monkeypatch):
        monkeypatch.setattr(dns_security, "_dig",
            lambda d, rt, server=None, timeout=10:
            ["ns-example.com. hostmaster.example.com. 3 300 120 604800 300"]
            if rt == "SOA" else [])
        assert dns_security._soa_mname("example.com") == "ns-example.com"

    def test_axfr_follows_delegation_to_subzone(self, tmp_path, monkeypatch):
        import json as _json
        from modules.dns_security import run_dns_security
        # Apex on Cloudflare (AXFR refused); delegated subzone internal.example.com
        # on a self-hosted NS where AXFR is open — the apex loop alone would miss it.
        prefix = str(tmp_path / "scan")
        with open(f"{prefix}-dnsx-resolve.txt", "w") as fh:
            fh.write(_json.dumps({"host": "example.com",
                                  "ns": ["crystal.ns.cloudflare.com"]}) + "\n")
            fh.write(_json.dumps({"host": "internal.example.com",
                                  "ns": ["ns1.example.net"]}) + "\n")
        roots = tmp_path / "roots.txt"; roots.write_text("example.com\n")

        monkeypatch.setattr(dns_security, "_dig",
                            lambda d, rt, server=None, timeout=10: [])
        monkeypatch.setattr(dns_security, "_soa_mname", lambda d: None)
        monkeypatch.setattr(dns_security, "_dig_answer_and_flags",
                            lambda n, s, timeout=10: (False, set()))
        # AXFR open ONLY on the subzone's self-hosted NS.
        monkeypatch.setattr(dns_security, "_dig_axfr",
                            lambda zone, ns, timeout=15:
                            zone == "internal.example.com" and ns == "ns1.example.net")

        res = run_dns_security(prefix=prefix, data_prefix=prefix,
                               root_domains_file=str(roots))
        recs = [__import__("json").loads(l)
                for l in open(f"{prefix}-dns-security.jsonl") if l.strip()]
        axfr = [r for r in recs if r["check"] == "axfr_allowed"]
        assert len(axfr) == 1
        assert axfr[0]["domain"] == "internal.example.com"  # caught on the subzone
        assert "ns1.example.net" in axfr[0]["detail"]
        assert axfr[0]["severity"] == "CRITICAL"
