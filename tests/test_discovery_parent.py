"""Tests for parent field in discovery ledger helpers."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.target_ledger import TargetLedger, TYPE_IP, TYPE_URL, TYPE_SUBDOMAIN
from workflows import (
    _extract_discoveries,
    _log_ips_from_file,
    _log_urls_from_file,
    _log_subdomains_from_file,
    _log_ips_from_resolve_report,
    _log_urls_from_ffuf_jsonl,
    _log_urls_from_dirbrute_txt,
    _extract_host_from_url,
    _extract_base_url,
    _infer_parent_domain,
)


def _read_ledger(ledger_path):
    entries = []
    if os.path.exists(ledger_path):
        with open(ledger_path) as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))
    return entries


class TestHelperFunctions:
    def test_extract_host_from_url_standard(self):
        assert _extract_host_from_url("https://example.com/path") == "example.com"

    def test_extract_host_from_url_with_port(self):
        assert _extract_host_from_url("https://example.com:8443/api") == "example.com:8443"

    def test_extract_host_from_url_port_80_omitted(self):
        assert _extract_host_from_url("http://example.com:80/") == "example.com"

    def test_extract_host_from_url_port_443_omitted(self):
        assert _extract_host_from_url("https://example.com:443/") == "example.com"

    def test_extract_host_from_url_invalid(self):
        assert _extract_host_from_url("not a url") is None

    def test_extract_base_url_standard(self):
        assert _extract_base_url("https://example.com/admin/login") == "https://example.com"

    def test_extract_base_url_with_port(self):
        assert _extract_base_url("http://10.0.0.1:8080/api/v1") == "http://10.0.0.1:8080"

    def test_extract_base_url_standard_port(self):
        assert _extract_base_url("https://example.com:443/foo") == "https://example.com"

    def test_infer_parent_domain_subdomain(self):
        assert _infer_parent_domain("api.dev.example.com") == "example.com"

    def test_infer_parent_domain_direct(self):
        assert _infer_parent_domain("www.example.com") == "example.com"

    def test_infer_parent_domain_too_short(self):
        assert _infer_parent_domain("example.com") is None


class TestLogIpsFromFile:
    def test_parent_passed_through(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        ip_file = tmp_path / "hosts.txt"
        ip_file.write_text("10.0.0.1\n10.0.0.2\n")

        _log_ips_from_file(str(ip_file), "ax_tcp_baseline", ledger, parent="/path/to/targets.txt")

        entries = _read_ledger(ledger.path)
        assert len(entries) == 2
        assert entries[0]["parent"] == "/path/to/targets.txt"
        assert entries[1]["parent"] == "/path/to/targets.txt"

    def test_parent_none_by_default(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        ip_file = tmp_path / "hosts.txt"
        ip_file.write_text("10.0.0.1\n")

        _log_ips_from_file(str(ip_file), "ax_naabu", ledger)

        entries = _read_ledger(ledger.path)
        assert entries[0]["parent"] is None


class TestLogUrlsFromFile:
    def test_parent_is_hostname(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        url_file = tmp_path / "urls.txt"
        url_file.write_text("https://app.example.com/login\nhttps://api.example.com:8443/v1\n")

        _log_urls_from_file(str(url_file), "ax_tcp_full", ledger)

        entries = _read_ledger(ledger.path)
        assert len(entries) == 2
        assert entries[0]["parent"] == "app.example.com"
        assert entries[1]["parent"] == "api.example.com:8443"


class TestLogSubdomainsFromFile:
    def test_jsonl_input_field_as_parent(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        sf_file = tmp_path / "subfinder.jsonl"
        sf_file.write_text(
            json.dumps({"host": "api.example.com", "input": "example.com"}) + "\n"
            + json.dumps({"host": "dev.test.io", "input": "test.io"}) + "\n"
        )

        _log_subdomains_from_file(str(sf_file), "subfinder", ledger)

        entries = _read_ledger(ledger.path)
        assert len(entries) == 2
        assert entries[0]["target"] == "api.example.com"
        assert entries[0]["parent"] == "example.com"
        assert entries[1]["target"] == "dev.test.io"
        assert entries[1]["parent"] == "test.io"

    def test_jsonl_infers_parent_when_input_missing(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        sf_file = tmp_path / "subfinder.jsonl"
        sf_file.write_text(json.dumps({"host": "sub.deep.example.com"}) + "\n")

        _log_subdomains_from_file(str(sf_file), "subfinder", ledger)

        entries = _read_ledger(ledger.path)
        assert entries[0]["parent"] == "example.com"

    def test_plain_text_infers_parent(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        sf_file = tmp_path / "subfinder.txt"
        sf_file.write_text("api.example.com\nwww.example.com\n")

        _log_subdomains_from_file(str(sf_file), "subfinder", ledger)

        entries = _read_ledger(ledger.path)
        assert entries[0]["parent"] == "example.com"
        assert entries[1]["parent"] == "example.com"

    def test_two_part_domain_has_no_parent(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        sf_file = tmp_path / "subfinder.txt"
        sf_file.write_text("example.com\n")

        _log_subdomains_from_file(str(sf_file), "subfinder", ledger)

        entries = _read_ledger(ledger.path)
        assert entries[0]["parent"] is None


class TestLogIpsFromResolveReport:
    def test_hostname_as_parent(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        report = tmp_path / "resolve-report.jsonl"
        report.write_text(
            json.dumps({"hostname": "api.example.com", "ip": "10.0.0.1", "status": "resolved"}) + "\n"
            + json.dumps({"hostname": "dev.example.com", "ip": "10.0.0.2", "status": "resolved"}) + "\n"
            + json.dumps({"hostname": "bad.example.com", "ip": None, "status": "nxdomain"}) + "\n"
        )

        _log_ips_from_resolve_report(str(report), "dns_resolve", ledger)

        entries = _read_ledger(ledger.path)
        assert len(entries) == 2
        assert entries[0]["target"] == "10.0.0.1"
        assert entries[0]["parent"] == "api.example.com"
        assert entries[1]["target"] == "10.0.0.2"
        assert entries[1]["parent"] == "dev.example.com"

    def test_skips_non_resolved(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        report = tmp_path / "report.jsonl"
        report.write_text(
            json.dumps({"hostname": "fail.example.com", "ip": None, "status": "nxdomain"}) + "\n"
        )

        _log_ips_from_resolve_report(str(report), "dns_resolve", ledger)

        entries = _read_ledger(ledger.path)
        assert entries == []


class TestLogUrlsFromFfufJsonl:
    def test_base_url_as_parent(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        ffuf_file = tmp_path / "ffuf.jsonl"
        ffuf_file.write_text(
            json.dumps({"url": "http://10.0.0.1:8080/admin"}) + "\n"
            + json.dumps({"url": "https://example.com/secret"}) + "\n"
        )

        _log_urls_from_ffuf_jsonl(str(ffuf_file), "ax_ffuf", ledger)

        entries = _read_ledger(ledger.path)
        assert len(entries) == 2
        assert entries[0]["parent"] == "http://10.0.0.1:8080"
        assert entries[1]["parent"] == "https://example.com"

    def test_input_fuzz_field_as_parent(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        ffuf_file = tmp_path / "ffuf.jsonl"
        ffuf_file.write_text(
            json.dumps({"url": "http://10.0.0.1/admin", "input": {"FUZZ": "http://10.0.0.1"}}) + "\n"
        )

        _log_urls_from_ffuf_jsonl(str(ffuf_file), "ax_ffuf", ledger)

        entries = _read_ledger(ledger.path)
        assert entries[0]["parent"] == "http://10.0.0.1"


class TestLogUrlsFromDirbruteTxt:
    def test_base_url_as_parent(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        ferox_file = tmp_path / "ferox.txt"
        ferox_file.write_text(
            "200      GET       10l       20w     1234c https://example.com/admin\n"
            "301      GET        0l        0w        0c http://10.0.0.1:9090/metrics\n"
        )

        _log_urls_from_dirbrute_txt(str(ferox_file), "ax_feroxbuster", ledger)

        entries = _read_ledger(ledger.path)
        assert len(entries) == 2
        assert entries[0]["parent"] == "https://example.com"
        assert entries[1]["parent"] == "http://10.0.0.1:9090"


class TestExtractDiscoveriesIntegration:
    def test_nmap_passes_target_as_parent(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        # ax_tcp_baseline was consolidated into ax_nmap_tcp (see modules/ax_nmap_tcp.py).
        hosts_file = data_dir / "prefix-tcpscan-alive-hosts.txt"
        hosts_file.write_text("10.0.0.1\n10.0.0.2\n")

        result = {
            "status": "success",
            "output_files": [str(data_dir / "prefix-tcpscan.xml")],
        }
        kwargs = {"target": "/tmp/targets.txt", "data_prefix": str(data_dir / "prefix")}

        _extract_discoveries(result, "ax_nmap_tcp", ledger, str(data_dir / "prefix"), kwargs=kwargs)

        entries = _read_ledger(ledger.path)
        assert len(entries) == 2
        assert all(e["parent"] == "/tmp/targets.txt" for e in entries)

    def test_dns_resolve_uses_report(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        report = tmp_path / "prefix-resolve-report.jsonl"
        report.write_text(
            json.dumps({"hostname": "web.example.com", "ip": "10.0.0.5", "status": "resolved"}) + "\n"
        )

        result = {
            "status": "success",
            "output_files": [str(report), str(tmp_path / "prefix-resolved-targets.txt")],
            "resolved_target_file": str(tmp_path / "prefix-resolved-targets.txt"),
        }

        _extract_discoveries(result, "dns_resolve", ledger, str(tmp_path / "prefix"))

        entries = _read_ledger(ledger.path)
        assert len(entries) == 1
        assert entries[0]["target"] == "10.0.0.5"
        assert entries[0]["parent"] == "web.example.com"

    def test_subfinder_uses_input_field(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        sf_file = tmp_path / "subfinder.jsonl"
        sf_file.write_text(
            json.dumps({"host": "mail.example.com", "input": "example.com"}) + "\n"
        )

        result = {
            "status": "success",
            "output_files": [str(sf_file)],
        }

        _extract_discoveries(result, "subfinder", ledger, str(tmp_path / "prefix"))

        entries = _read_ledger(ledger.path)
        assert entries[0]["parent"] == "example.com"
