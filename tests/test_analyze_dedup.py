"""Tests for report deduplication / grouping in the analyze + ai_analyze renderers.

Real reports against CDN/shared-hosting estates produced hundreds of redundant
rows: the same login panel per-port and per-template, the same TRACE finding
across a whole CDN /24, thousands of low/info nuclei rows truncated to a
meaningless "50 shown", and Service Research CVEs listed twice. These tests
lock in the collapsing behavior that fixes each case.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.analyze import (
    _normalize_url,
    _group_login_panels,
    _group_shared_host_ports,
    _network_prefix,
    _render_markdown,
)


class TestNormalizeUrl:
    def test_strips_single_trailing_slash(self):
        assert _normalize_url("https://h/x/") == "https://h/x"

    def test_leaves_bare_host_port(self):
        assert _normalize_url("1.2.3.4:8443") == "1.2.3.4:8443"

    def test_root_slash_collapses_to_scheme_host(self):
        # https://host/ and https://host must dedup together
        assert _normalize_url("https://host/") == _normalize_url("https://host")


class TestGroupLoginPanels:
    def test_collapses_trailing_slash_and_overlapping_templates(self):
        panels = [
            {"url": "https://h:8443/login_up.php", "source": "nuclei",
             "template_id": "plesk-obsidian-login", "title": "Plesk"},
            {"url": "https://h:8443/login_up.php", "source": "nuclei",
             "template_id": "plesk-onyx-login", "title": "Plesk"},
            {"url": "https://x.com/", "source": "nuclei",
             "template_id": "wp-login", "title": "WP"},
            {"url": "https://x.com", "source": "nuclei",
             "template_id": "wp-login", "title": "WP"},
        ]
        grouped = _group_login_panels(panels)
        # 4 rows -> 2 distinct panels
        assert len(grouped) == 2
        plesk = next(g for g in grouped if "8443" in g["url"])
        # both overlapping templates preserved
        assert "plesk-obsidian-login" in plesk["templates"]
        assert "plesk-onyx-login" in plesk["templates"]


class TestNetworkPrefix:
    def test_ipv4_slash24(self):
        assert _network_prefix("198.18.14.99") == "198.18.14.0/24"

    def test_hostname_returns_empty(self):
        assert _network_prefix("host.example.com") == ""


class TestGroupSharedHostPorts:
    def test_groups_cdn_range_and_keeps_singles(self):
        entries = [
            {"host": f"198.18.14.{i}", "port": 443, "service": "http",
             "notes": "TRACE"} for i in range(50, 60)
        ]
        # a lone host on a different net with the same finding stays a single
        entries.append({"host": "8.8.8.8", "port": 443, "service": "http", "notes": "TRACE"})
        groups, singles = _group_shared_host_ports(entries, min_group=5)
        assert len(groups) == 1
        assert groups[0]["prefix"] == "198.18.14.0/24"
        assert groups[0]["count"] == 10
        assert singles == [{"host": "8.8.8.8", "port": 443, "service": "http", "notes": "TRACE"}]

    def test_below_threshold_not_grouped(self):
        entries = [
            {"host": "1.1.1.1", "port": 80, "service": "http", "notes": "TRACE"},
            {"host": "1.1.1.2", "port": 80, "service": "http", "notes": "TRACE"},
        ]
        groups, singles = _group_shared_host_ports(entries, min_group=5)
        assert groups == []
        assert len(singles) == 2


class TestRenderMarkdownIntegration:
    def _render(self, analysis, tmp_path):
        out = str(tmp_path / "analysis.md")
        _render_markdown(analysis, out)
        with open(out) as fh:
            return fh.read()

    def test_login_panels_collapse_note(self, tmp_path):
        analysis = _base_analysis()
        analysis["password_spray"]["login_panels"] = [
            {"url": "https://h:8443/login_up.php", "source": "nuclei",
             "template_id": "plesk-obsidian-login", "title": "Plesk"},
            {"url": "https://h:8443/login_up.php", "source": "nuclei",
             "template_id": "plesk-onyx-login", "title": "Plesk"},
        ]
        md = self._render(analysis, tmp_path)
        assert "### Login Panels" in md
        assert "collapsed to 1 distinct panels" in md
        assert "plesk-obsidian-login; plesk-onyx-login" in md

    def test_misconfigs_show_template_breakdown(self, tmp_path):
        analysis = _base_analysis()
        analysis["nuclei_intel"]["misconfigs"] = (
            [{"host": f"h{i}.com", "template_id": "swagger-api",
              "title": "Public Swagger API", "detail": ""} for i in range(37)]
            + [{"host": f"c{i}.com", "template_id": "composer-config",
                "title": "Composer Config", "detail": ""} for i in range(11)]
        )
        md = self._render(analysis, tmp_path)
        assert "48 low/info detections across 2 template(s)" in md
        assert "| Template | Title | Findings | Hosts |" in md
        assert "| swagger-api | Public Swagger API | 37 | 37 |" in md
        # the old misleading "N more" truncation line is gone
        assert "more |" not in md

    def test_http_methods_group_cdn_range(self, tmp_path):
        analysis = _base_analysis()
        analysis["http_methods"] = [
            {"host": f"198.18.14.{i}", "port": 443, "methods": ["TRACE"]}
            for i in range(50, 62)
        ]
        md = self._render(analysis, tmp_path)
        assert "## Dangerous HTTP Methods" in md
        assert "198.18.14.0/24" in md
        assert "CDN/shared-range group" in md


def _base_analysis():
    """Minimal analysis dict satisfying _render_markdown's required keys."""
    return {
        "metadata": {"generated_at": "2026-07-27T00:00:00+00:00", "prefix": "t"},
        "summary": {
            "total_hosts": 0, "total_open_ports": 0, "unique_ports": 0,
            "unique_services": 0, "unique_service_versions": 0,
            "subdomains_discovered": 0, "directory_hits": 0,
            "nuclei_findings_total": 0, "nuclei_severity_counts": {},
            "bbot_findings_total": 0, "dns_security_findings_total": 0,
            "ports_disappeared_between_scans": 0,
        },
        "password_spray": {"mx_domains": {}, "login_panels": [], "emails": []},
        "port_service_stats": {"port_counts": {}, "service_counts": {},
                               "service_version_counts": []},
        "os_fingerprint": {}, "http_methods": [], "default_creds_anon_access": [],
        "ssl_tls_issues": [], "smb_signing_disabled": [], "sensitive_paths": [],
        "tech_stack": {}, "outlier_ports": [], "scan_comparison": [],
        "nuclei_findings": [], "nuclei_intel": {"misconfigs": [], "exposed_panels": []},
        "bbot_findings": [], "dns_security_findings": [],
    }
