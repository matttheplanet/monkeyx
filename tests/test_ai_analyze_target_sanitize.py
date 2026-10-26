"""ai_analyze must repair spuriously doubled ports and stop overclaiming (#10/#9).

The AI sometimes emits a target like 'host:6379:6379' or 'host:4280:443' — it
treats a nuclei matched-at 'host:port' as the host and re-appends a port. That
produced un-runnable PoC commands AND broke ai_validate's port/finding_id join
(verdicts never wrote back to scan.db), so a later-refuted finding kept reading
as confirmed. `_normalize_target`/`_sanitize_targets` collapse the doubled port
to '<host>:<first-port>' (the real service port; the appended one is noise) in
both the target field and command strings.

Separately (#9): `ai_analyze` runs BEFORE `ai_validate`, so its priority findings
are AI-selected leads, NOT confirmed exploitation. The render must not title them
"Confirmed Vulnerabilities" and must point the reader at the validation verdicts.
"""

import os
import sys
import types
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _load():
    saved = {}
    stub = ["core", "core.credentials", "core.knowledge", "core.ai_provider",
            "core.utils", "core.anonymize"]
    for name in stub:
        saved[name] = sys.modules.get(name)
    try:
        for name in stub:
            sys.modules[name] = types.ModuleType(name)
        sys.modules["core.credentials"].get_ai_provider = lambda *a, **k: None
        sys.modules["core.ai_provider"].AIProvider = object
        sys.modules["core.ai_provider"].display_model_name = lambda *a, **k: "model"
        sys.modules["core.utils"].version_output_path = lambda *a, **k: None
        sys.modules["core.anonymize"].anonymize_text = lambda t, *a, **k: (t, {})
        sys.modules["core.anonymize"].deanonymize_obj = lambda o, *a, **k: o
        sys.modules["core.anonymize"].extract_domains_from_text = lambda *a, **k: set()
        spec = importlib.util.spec_from_file_location(
            "ai_analyze_sanitize_uut",
            os.path.join(os.path.dirname(__file__), "..", "modules", "ai_analyze.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        for name, prev in saved.items():
            if prev is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prev


az = _load()


class TestNormalizeTarget:
    def test_doubled_port_same(self):
        assert az._normalize_target("pentest-ground.com:6379:6379") == "pentest-ground.com:6379"

    def test_doubled_port_mixed_keeps_first(self):
        # 4280 is the real DVWA port; 443 was spuriously appended.
        assert az._normalize_target("pentest-ground.com:4280:443") == "pentest-ground.com:4280"

    def test_ipv4_doubled_port(self):
        assert az._normalize_target("1.2.3.4:80:443") == "1.2.3.4:80"

    def test_plain_host_port_unchanged(self):
        assert az._normalize_target("example.com:443") == "example.com:443"

    def test_bare_host_unchanged(self):
        assert az._normalize_target("example.com") == "example.com"

    def test_url_unchanged(self):
        assert az._normalize_target("https://example.com:8443/x") == "https://example.com:8443/x"

    def test_bracket_ipv6_unchanged(self):
        assert az._normalize_target("[2001:db8::1]:443") == "[2001:db8::1]:443"

    def test_nonstring_passthrough(self):
        assert az._normalize_target(None) is None
        assert az._normalize_target(123) == 123


class TestSanitizeTargets:
    def test_collapses_target_and_commands(self):
        result = {
            "quick_wins": [{
                "target": "pentest-ground.com:6379:6379",
                "commands": [
                    "redis-cli -h pentest-ground.com:6379:6379 INFO",
                    "curl -sk https://pentest-ground.com:4280:443/",
                ],
            }],
            "attack_chains": [],
            "requires_verification": [],
            "cve_research": [],
        }
        az._sanitize_targets(result)
        qw = result["quick_wins"][0]
        assert qw["target"] == "pentest-ground.com:6379"
        assert qw["commands"][0] == "redis-cli -h pentest-ground.com:6379 INFO"
        assert qw["commands"][1] == "curl -sk https://pentest-ground.com:4280/"

    def test_all_categories_walked(self):
        result = {c: [{"target": "h.com:80:80"}] for c in
                  ("quick_wins", "attack_chains", "requires_verification", "cve_research")}
        az._sanitize_targets(result)
        for c in result:
            assert result[c][0]["target"] == "h.com:80"

    def test_plain_targets_untouched(self):
        result = {"quick_wins": [
            {"target": "example.com:443", "commands": ["curl https://example.com:443/"]},
            {"target": "https://example.com/x", "commands": []},
        ]}
        az._sanitize_targets(result)
        assert result["quick_wins"][0]["target"] == "example.com:443"
        assert result["quick_wins"][0]["commands"][0] == "curl https://example.com:443/"
        assert result["quick_wins"][1]["target"] == "https://example.com/x"

    def test_handles_missing_or_malformed(self):
        az._sanitize_targets({})
        az._sanitize_targets({"quick_wins": ["not-a-dict"]})
        az._sanitize_targets({"quick_wins": [{"commands": None}]})
        az._sanitize_targets(None)


class TestRenderHonesty:
    def _md(self, tmp_path):
        data = {
            "recommendations": {
                "quick_wins": [{
                    "target": "pentest-ground.com:6379",
                    "action": "Unauthenticated Redis",
                    "evidence": "redis INFO returned server data",
                    "commands": ["redis-cli -h pentest-ground.com:6379 INFO"],
                }],
                "attack_chains": [],
                "requires_verification": [],
                "cve_research": [],
            },
            "metadata": {
                "generated_at": "2026-08-28T00:00:00Z",
                "ai_provider": "anthropic",
                "ai_model": "model",
                "depth": "standard",
                "hosts_analyzed": 1, "hosts_total": 1,
                "services_analyzed": 0, "services_total": 0,
                "total_ports": 1, "total_findings": 1,
            },
            "attack_paths": [],
            "service_research": [],
            "correlations": [],
        }
        out = str(tmp_path / "ai-analysis.md")
        az._render_markdown(data, out)
        with open(out) as fh:
            return fh.read()

    def test_no_confirmed_vulnerabilities_heading(self, tmp_path):
        assert "### Confirmed Vulnerabilities" not in self._md(tmp_path)

    def test_merged_attack_paths_section_with_confidence_tag(self, tmp_path):
        md = self._md(tmp_path)
        # unified section, with the quick-win rendered as a tagged ranked item
        assert "## Attack Paths" in md
        assert "pentest-ground.com:6379 — Unauthenticated Redis" in md
        # tier-0 quick-win must not claim exploitation (ai_analyze precedes validate)
        assert "high-confidence lead — not exploited" in md
        assert "confirmed — exploitable" not in md
        # the old split headers are gone
        assert "## Priority Findings" not in md
        assert "## Unconfirmed Vulnerabilities" not in md

    def test_points_reader_at_validation_results(self, tmp_path):
        md = self._md(tmp_path)
        assert "Validation Results" in md
        assert "not validated" in md


class TestCapInformationalImpact:
    """Internal-IP / version disclosure are LOW risk, not HIGH/CRITICAL."""

    def test_internal_ip_disclosure_capped_to_low(self):
        res = {"attack_chains": [
            {"target": "H1", "action": "Internal IP address disclosure via error page",
             "impact": "HIGH", "confidence": "HIGH"},
        ]}
        az._cap_informational_impact(res)
        assert res["attack_chains"][0]["impact"] == "LOW"
        assert res["attack_chains"][0]["confidence"] == "MEDIUM"

    def test_version_disclosure_capped(self):
        res = {"attack_chains": [
            {"target": "H2", "action": "Detailed version disclosure in Server banner",
             "impact": "CRITICAL", "confidence": "MEDIUM"},
        ]}
        az._cap_informational_impact(res)
        assert res["attack_chains"][0]["impact"] == "LOW"

    def test_real_exploit_mentioning_internal_ip_not_capped(self):
        # An actual exploit that merely mentions an internal IP must keep its rating.
        res = {"attack_chains": [
            {"target": "H3", "action": "SSRF reaching internal IP metadata endpoint -> cred theft",
             "impact": "CRITICAL", "confidence": "HIGH"},
        ]}
        az._cap_informational_impact(res)
        assert res["attack_chains"][0]["impact"] == "CRITICAL"
        assert res["attack_chains"][0]["confidence"] == "HIGH"

    def test_rce_with_version_not_capped(self):
        res = {"cve_research": [
            {"target": "H4", "action": "RCE via Struts 2.5.12 (CVE-2017-5638)",
             "impact": "CRITICAL"},
        ]}
        az._cap_informational_impact(res)
        assert res["cve_research"][0]["impact"] == "CRITICAL"

    def test_unrelated_finding_untouched(self):
        res = {"quick_wins": [
            {"target": "H5", "action": "Unauthenticated Redis", "impact": "HIGH"},
        ]}
        az._cap_informational_impact(res)
        assert res["quick_wins"][0]["impact"] == "HIGH"
