"""Tests for the external-coverage modules added in the 2026-07 build:
Phase A/C ax wrappers' normalize parsers, shodan_enrich (budget/scope/records),
and the shared tool_runners scope layer + Phase F module assessment logic.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import scan_db, tool_runners
from modules import normalize, shodan_enrich, smtp_security


# --------------------------------------------------------------------------- #
# normalize — text parsers for the new tools
# --------------------------------------------------------------------------- #

class TestTestsslParser:
    def test_vuln_and_weak_cipher_become_findings_ok_skipped(self, tmp_path):
        p = tmp_path / "s-testssl.txt"
        p.write_text(
            " Start 2024 -->> 93.184.216.10:443 (example.com) <<--\n"
            " Heartbleed (CVE-2014-0160)   VULNERABLE (NOT ok)\n"
            " SSLv3   offered (NOT ok)\n"
            " TLS 1.2   offered (OK)\n"
        )
        recs = normalize._parse_testssl_text(str(p))
        sevs = {r["severity"] for r in recs}
        assert recs[0]["cve_id"] == "CVE-2014-0160"
        assert recs[0]["severity"] == "high"
        assert "medium" in sevs  # SSLv3
        # The OK line must not produce a finding.
        assert all("TLS 1.2" not in r["title"] for r in recs)
        # host/port parsed from the target banner
        assert all(r["host"] == "93.184.216.10" and r["port"] == 443 for r in recs)

    def test_no_target_banner_yields_nothing(self, tmp_path):
        p = tmp_path / "s-testssl.txt"
        p.write_text(" Heartbleed   VULNERABLE (NOT ok)\n")
        assert normalize._parse_testssl_text(str(p)) == []


class TestWafw00fParser:
    def test_behind_waf_line_parsed(self, tmp_path):
        p = tmp_path / "s-wafw00f.txt"
        p.write_text(
            "[+] The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF.\n"
            "[-] No WAF detected by the generic detection\n"
        )
        recs = normalize._parse_wafw00f_text(str(p))
        assert len(recs) == 1
        assert recs[0]["host"] == "example.com"
        assert "Cloudflare" in recs[0]["waf"]
        assert recs[0]["severity"] == "info"


class TestWebFindingParsers:
    def test_dalfox_poc_is_high(self, tmp_path):
        p = tmp_path / "s-dalfox.txt"
        p.write_text("[POC][G][GET] https://ex.com/?q=1 payload\nnoise\n")
        recs = normalize._parse_dalfox_text(str(p))
        assert recs and recs[0]["severity"] == "high"
        assert recs[0]["type"] == "vulnerability"

    def test_corsy_requires_cors_keyword(self, tmp_path):
        p = tmp_path / "s-corsy.txt"
        p.write_text("https://ex.com  Origin reflected with credentials\n"
                     "https://safe.com  looks fine here\n")
        recs = normalize._parse_corsy_text(str(p))
        assert len(recs) == 1 and recs[0]["host"] == "ex.com"

    def test_mantra_needs_a_url(self, tmp_path):
        p = tmp_path / "s-mantra.txt"
        p.write_text("[+] https://ex.com/app.js AWS_KEY=AKIA\nno url here\n")
        recs = normalize._parse_mantra_text(str(p))
        assert len(recs) == 1 and recs[0]["severity"] == "medium"


class TestClaimForNewTools:
    def test_shodan_uses_shodan_claim(self):
        assert normalize._claim_for(
            {"tool": "shodan", "shodan_claim": "CVE-2021-1"}) == "CVE-2021-1"

    def test_testssl_claim_from_bracket_title(self):
        rec = {"tool": "testssl", "title": "[CVE-2014-0160] Heartbleed"}
        assert normalize._claim_for(rec) == "CVE-2014-0160"


class TestNormalizedFindingsMinted:
    """testssl/wafw00f/dalfox findings must reach scan.db (web UI + ai_validate)."""

    def test_finding_types_mint(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        recs = [
            {"tool": "testssl", "type": "finding", "host": "h.tld", "port": 443,
             "proto": "tcp", "title": "[CVE-2014-0160] x", "severity": "high",
             "cve_id": "CVE-2014-0160"},
            {"tool": "wafw00f", "type": "finding", "host": "h.tld", "port": 443,
             "proto": "tcp", "title": "[waf] behind Cloudflare", "severity": "info"},
        ]
        normalize._mint_findings(recs, db, scan_db._iso_now())
        rows = db._conn.execute("SELECT tool FROM findings ORDER BY tool").fetchall()
        assert [r["tool"] for r in rows] == ["testssl", "wafw00f"]
        db.close()


# --------------------------------------------------------------------------- #
# shodan_enrich
# --------------------------------------------------------------------------- #

def _fake_shodan_fetch(url):
    if "/shodan/host/93.184.216.10" in url:
        return {"ip_str": "93.184.216.10", "ports": [443, 22],
                "hostnames": ["scanme.example.com"], "org": "Acme",
                "vulns": {"cve-2014-0160": {"verified": True, "cvss": 7.5,
                                            "summary": "Heartbleed"}}}
    if "/host/search" in url:
        return {"matches": [{"ip_str": "1.2.3.4", "ports": [80],
                             "vulns": ["CVE-2021-1234"]}]}
    return None


class TestShodanEnrich:
    def _targets(self, tmp_path):
        tf = tmp_path / "targets.txt"
        tf.write_text("93.184.216.10\n10.0.0.5\n8.8.8.0/24\n")  # private + CIDR skipped
        dl = tmp_path / "domains.txt"
        dl.write_text("www.example.com\n")
        return str(tf), str(dl)

    def test_host_only_default_no_credits(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MONKEYX_SHODAN_API_KEY", "k")
        tf, dl = self._targets(tmp_path)
        prefix = str(tmp_path / "scan")
        r = shodan_enrich.run_shodan_enrich(
            prefix=prefix, target=tf, domainlist=dl, _fetch=_fake_shodan_fetch)
        assert r["status"] == "success"
        assert r["credits_used"] == 0          # host lookups are free
        assert r["hosts_looked_up"] == 1       # private + CIDR were skipped
        recs = [json.loads(l) for l in open(prefix + "-shodan.jsonl")]
        types = {x["type"] for x in recs}
        assert "vulnerability" in types        # the CVE became a finding
        assert any(x.get("cve_id") == "CVE-2014-0160" for x in recs)

    def test_searches_respect_budget(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MONKEYX_SHODAN_API_KEY", "k")
        tf, dl = self._targets(tmp_path)
        prefix = str(tmp_path / "scan2")
        r = shodan_enrich.run_shodan_enrich(
            prefix=prefix, target=tf, domainlist=dl, _fetch=_fake_shodan_fetch,
            searches=True, max_query_credits=1)
        assert r["credits_used"] == 1
        assert r["searches_skipped"] >= 1      # budget stopped the rest, honestly

    def test_no_key_skips_cleanly(self, tmp_path, monkeypatch):
        monkeypatch.delenv("MONKEYX_SHODAN_API_KEY", raising=False)
        # Ensure no file key either.
        from core import credentials
        monkeypatch.setattr(credentials, "load_credentials", lambda: {})
        tf, dl = self._targets(tmp_path)
        r = shodan_enrich.run_shodan_enrich(
            prefix=str(tmp_path / "s3"), target=tf, domainlist=dl,
            _fetch=_fake_shodan_fetch)
        assert r["status"] == "skipped"

    def test_present_but_bad_key_warns_not_success(self, tmp_path, monkeypatch):
        # A key EXISTS (passes _provider_available) but every lookup fails — the
        # invalid/revoked-key case, where fetches 401 to None. Producing zero
        # records must report `warning`, not a green success that enriched nothing.
        monkeypatch.setenv("MONKEYX_SHODAN_API_KEY", "bad")
        tf, dl = self._targets(tmp_path)
        r = shodan_enrich.run_shodan_enrich(
            prefix=str(tmp_path / "s5"), target=tf, domainlist=dl,
            _fetch=lambda url: None)        # every call fails (bad key / no data)
        assert r["status"] == "warning"
        assert r["hosts_looked_up"] == 0
        assert "warning" in r

    def test_cache_prevents_second_spend(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MONKEYX_SHODAN_API_KEY", "k")
        tf, dl = self._targets(tmp_path)
        prefix = str(tmp_path / "s4")
        calls = []

        def counting_fetch(url):
            calls.append(url)
            return _fake_shodan_fetch(url)

        shodan_enrich.run_shodan_enrich(prefix=prefix, target=tf, domainlist=dl,
                                        _fetch=counting_fetch, searches=True,
                                        max_query_credits=10)
        first = len(calls)
        # Re-run: cache should satisfy host lookup + searches, no new fetches.
        shodan_enrich.run_shodan_enrich(prefix=prefix, target=tf, domainlist=dl,
                                        _fetch=counting_fetch, searches=True,
                                        max_query_credits=10)
        assert len(calls) == first  # cache hit — no re-billing

    def test_resolved_ips_looked_up_on_domain_only_run(self, tmp_path, monkeypatch):
        # Domain-only run: the plain target file is hostname-collapsed (no IPs),
        # so host lookups only happen via the ledger's bare-IP export.
        monkeypatch.setenv("MONKEYX_SHODAN_API_KEY", "k")
        tf = tmp_path / "targets.txt"
        tf.write_text("scanme.example.com\n")  # hostname-collapsed, no IPs
        tips = tmp_path / "ledger-target-ips.txt"
        tips.write_text("93.184.216.10\tscanme.example.com\n")  # authorized bare IP + provenance
        prefix = str(tmp_path / "s5")
        r = shodan_enrich.run_shodan_enrich(
            prefix=prefix, target=str(tf), domainlist=str(tmp_path / "none.txt"),
            target_ips_file=str(tips), _fetch=_fake_shodan_fetch)
        assert r["status"] == "success"
        assert r["hosts_looked_up"] == 1     # recovered the IP behind the name
        recs = [json.loads(l) for l in open(prefix + "-shodan.jsonl")]
        # Provenance is stamped so a reviewer can tell origin from shared edge.
        assert all(x.get("resolved_from") == "scanme.example.com" for x in recs)

    def test_private_resolved_ip_is_skipped(self, tmp_path, monkeypatch):
        # A resolved IP that is private must not be looked up (defense in depth —
        # export already private-filters, but the module must not trust input).
        monkeypatch.setenv("MONKEYX_SHODAN_API_KEY", "k")
        tf = tmp_path / "targets.txt"
        tf.write_text("host.example.com\n")
        tips = tmp_path / "ledger-target-ips.txt"
        tips.write_text("10.0.0.5\tinternal.example.com\n")  # private
        r = shodan_enrich.run_shodan_enrich(
            prefix=str(tmp_path / "s6"), target=str(tf),
            domainlist=str(tmp_path / "none.txt"),
            target_ips_file=str(tips), _fetch=_fake_shodan_fetch)
        assert r["status"] == "skipped"       # private IP filtered, no domains

    # --- CVE-noise taming (shodan_cve_findings) -------------------------- #

    @staticmethod
    def _mixed_fetch(url):
        # One verified CVE + two unverified (version-inferred) CVEs.
        if "/shodan/host/93.184.216.10" in url:
            return {"ip_str": "93.184.216.10", "ports": [22], "org": "Acme",
                    "vulns": {
                        "cve-2014-0160": {"verified": True, "cvss": 7.5,
                                          "summary": "Heartbleed"},
                        "cve-2023-99998": {"verified": False, "cvss": 9.8},
                        "cve-2011-11111": {"cvss": 5.0},  # no verified key = unverified
                    }}
        return None

    def _one_ip(self, tmp_path):
        tf = tmp_path / "t.txt"; tf.write_text("93.184.216.10\n")
        dl = tmp_path / "d.txt"; dl.write_text("")
        return str(tf), str(dl)

    def test_verified_default_only_verified_cve_is_a_finding(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MONKEYX_SHODAN_API_KEY", "k")
        tf, dl = self._one_ip(tmp_path)
        prefix = str(tmp_path / "v")
        shodan_enrich.run_shodan_enrich(prefix=prefix, target=tf, domainlist=dl,
                                        _fetch=self._mixed_fetch)
        recs = [json.loads(l) for l in open(prefix + "-shodan.jsonl")]
        findings = [r for r in recs if r["type"] == "vulnerability"]
        assert [f["cve_id"] for f in findings] == ["CVE-2014-0160"]   # verified only
        host = next(r for r in recs if r["type"] == "host_info")
        # The unverified ones are context, not findings.
        assert set(host["possible_cves"]) == {"CVE-2023-99998", "CVE-2011-11111"}
        assert "possible_cves=" in host["detail"]

    def test_cve_mode_all_emits_every_cve(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MONKEYX_SHODAN_API_KEY", "k")
        tf, dl = self._one_ip(tmp_path)
        prefix = str(tmp_path / "a")
        shodan_enrich.run_shodan_enrich(prefix=prefix, target=tf, domainlist=dl,
                                        _fetch=self._mixed_fetch,
                                        shodan_cve_findings="all")
        recs = [json.loads(l) for l in open(prefix + "-shodan.jsonl")]
        cves = {r["cve_id"] for r in recs if r["type"] == "vulnerability"}
        assert cves == {"CVE-2014-0160", "CVE-2023-99998", "CVE-2011-11111"}
        host = next(r for r in recs if r["type"] == "host_info")
        assert not host.get("possible_cves")           # all promoted to findings

    def test_cve_mode_none_emits_no_findings(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MONKEYX_SHODAN_API_KEY", "k")
        tf, dl = self._one_ip(tmp_path)
        prefix = str(tmp_path / "n")
        shodan_enrich.run_shodan_enrich(prefix=prefix, target=tf, domainlist=dl,
                                        _fetch=self._mixed_fetch,
                                        shodan_cve_findings="none")
        recs = [json.loads(l) for l in open(prefix + "-shodan.jsonl")]
        assert not [r for r in recs if r["type"] == "vulnerability"]
        host = next(r for r in recs if r["type"] == "host_info")
        assert len(host["possible_cves"]) == 3          # all surfaced as context

    def test_invalid_cve_mode_falls_back_to_verified(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MONKEYX_SHODAN_API_KEY", "k")
        tf, dl = self._one_ip(tmp_path)
        prefix = str(tmp_path / "bad")
        shodan_enrich.run_shodan_enrich(prefix=prefix, target=tf, domainlist=dl,
                                        _fetch=self._mixed_fetch,
                                        shodan_cve_findings="garbage")
        recs = [json.loads(l) for l in open(prefix + "-shodan.jsonl")]
        cves = [r["cve_id"] for r in recs if r["type"] == "vulnerability"]
        assert cves == ["CVE-2014-0160"]                # defaulted to verified


# --------------------------------------------------------------------------- #
# tool_runners scope + Phase F assessment
# --------------------------------------------------------------------------- #

class TestScope:
    def test_fail_closed(self, tmp_path):
        tf = tmp_path / "t.txt"
        tf.write_text("198.18.10.0/24\nmail.example.com\n")
        s = tool_runners.load_scope(str(tf))
        assert s.contains("198.18.10.9")
        assert s.contains("sub.mail.example.com")
        assert not s.contains("8.8.8.8")
        assert not s.contains("evil.com")
        assert not s.contains("")


class TestSmtpAssess:
    def test_auth_without_tls_is_high(self):
        recs = smtp_security._assess(
            "mail.tld", 25, "banner: 220 x\nehlo:\n  250-AUTH LOGIN\n  250-VRFY\n")
        claims = {r["title"].split("]")[0].lstrip("[") for r in recs}
        assert "auth_without_tls" in claims
        assert "vrfy_enabled" in claims
        assert any(r["severity"] == "high" for r in recs)

    def test_starttls_present_no_finding_for_it(self):
        recs = smtp_security._assess(
            "mail.tld", 587, "banner: 220 x\nehlo:\n  250-STARTTLS\n  250-AUTH LOGIN\n")
        claims = {r["title"].split("]")[0].lstrip("[") for r in recs}
        assert "starttls_missing" not in claims
        assert "auth_without_tls" not in claims  # AUTH is fine once STARTTLS offered

    def test_error_probe_yields_nothing(self):
        assert smtp_security._assess("mail.tld", 25, "ERROR: connection refused") == []
