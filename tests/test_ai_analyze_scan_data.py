"""Tests for ai_analyze scan-data loading — low/medium signal is preserved.

Sub-high DNS-security findings (weak SPF/DMARC, missing DNSSEC, CAA gaps) are
individually minor but combine into real findings during correlation. The
loader must keep them (like the nuclei/nmap/bbot loaders), dropping only pure
info noise.
"""

import json
import os
import sys
import types
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _load():
    saved = {}
    stub = ["core", "core.credentials", "core.knowledge", "core.ai_provider", "core.utils"]
    for name in stub:
        saved[name] = sys.modules.get(name)
    try:
        for name in stub:
            sys.modules[name] = types.ModuleType(name)
        sys.modules["core.credentials"].get_ai_provider = lambda *a, **k: None
        sys.modules["core.ai_provider"].AIProvider = object
        sys.modules["core.ai_provider"].display_model_name = lambda *a, **k: "model"
        sys.modules["core.utils"].version_output_path = lambda *a, **k: None
        spec = importlib.util.spec_from_file_location(
            "ai_analyze_scan_uut",
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


def _write_dns(tmp_path, records):
    pfx = str(tmp_path / "scan")
    (tmp_path / "scan-dns-security.jsonl").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n")
    return pfx


def test_sub_high_dns_findings_preserved(tmp_path):
    pfx = _write_dns(tmp_path, [
        {"domain": "example.com", "check": "spf_plus_all", "severity": "CRITICAL", "detail": "+all"},
        {"domain": "example.com", "check": "spf_softfail", "severity": "LOW", "detail": "~all", "evidence": "v=spf1 ~all"},
        {"domain": "example.com", "check": "dmarc_weak", "severity": "MEDIUM", "detail": "p=none"},
        {"domain": "example.com", "check": "noise", "severity": "INFO", "detail": "fyi"},
    ])
    data = az._load_scan_data(pfx)
    findings = data["hosts"]["example.com"]["findings"]
    sevs = {f["severity"] for f in findings}
    assert "critical" in sevs
    assert "low" in sevs      # previously dropped
    assert "medium" in sevs   # previously dropped
    assert "info" not in sevs  # info noise still excluded
    # evidence field carried through
    softfail = next(f for f in findings if f["title"] == "spf_softfail")
    assert softfail["evidence"] == "v=spf1 ~all"


def test_findings_sorted_high_severity_first(tmp_path):
    pfx = _write_dns(tmp_path, [
        {"domain": "d", "check": "low1", "severity": "LOW", "detail": ""},
        {"domain": "d", "check": "crit1", "severity": "CRITICAL", "detail": ""},
        {"domain": "d", "check": "med1", "severity": "MEDIUM", "detail": ""},
    ])
    data = az._load_scan_data(pfx)
    order = [f["severity"] for f in data["hosts"]["d"]["findings"]]
    assert order == ["critical", "medium", "low"]  # highest first (prompt-cap safe)


# --- Host-identity consolidation: hostname folds into its resolved in-scope IP.

def _write_files(tmp_path, files: dict):
    pfx = str(tmp_path / "scan")
    for suffix, text in files.items():
        (tmp_path / f"scan{suffix}").write_text(text)
    return pfx


def test_hostname_folds_into_resolved_ip(tmp_path):
    # Same asset scanned as IP and hostname (weburls dual-emit) -> one host.
    nuclei = "\n".join([
        json.dumps({"host": "1.2.3.4", "type": "finding", "severity": "critical",
                    "title": "[cve-x] RCE", "detail": "on 1.2.3.4"}),
        json.dumps({"host": "app.example.com", "type": "finding", "severity": "critical",
                    "title": "[cve-x] RCE", "detail": "on 1.2.3.4"}),
    ]) + "\n"
    resolve = json.dumps({"hostname": "app.example.com", "ip": "1.2.3.4",
                          "in_scope": True}) + "\n"
    pfx = _write_files(tmp_path, {"-nuclei-normalized.jsonl": nuclei,
                                  "-resolve-report.jsonl": resolve})
    data = az._load_scan_data(pfx)
    assert set(data["hosts"]) == {"1.2.3.4"}                 # one host, not two
    assert "app.example.com" in data["hosts"]["1.2.3.4"]["subdomains"]
    # identical dual-emitted finding collapsed to one
    assert len(data["hosts"]["1.2.3.4"]["findings"]) == 1
    assert data["total_findings"] == 1


def test_hostname_kept_when_ip_not_a_scanned_host(tmp_path):
    # A third-party reference whose IP was never scanned stays its own entry.
    nuclei = json.dumps({"host": "hub.docker.com", "type": "finding",
                         "severity": "info", "title": "ref", "detail": ""}) + "\n"
    resolve = json.dumps({"hostname": "hub.docker.com", "ip": "5.6.7.8",
                          "in_scope": True}) + "\n"
    pfx = _write_files(tmp_path, {"-nuclei-normalized.jsonl": nuclei,
                                  "-resolve-report.jsonl": resolve})
    data = az._load_scan_data(pfx)
    assert "hub.docker.com" in data["hosts"]


def test_out_of_scope_resolution_not_folded(tmp_path):
    # vpn.example.com resolves to an internal 10.x (excluded) — must NOT merge
    # onto that address even if it somehow appears as a host key.
    nuclei = json.dumps({"host": "vpn.example.com", "type": "finding",
                         "severity": "high", "title": "t", "detail": ""}) + "\n"
    resolve = json.dumps({"hostname": "vpn.example.com", "ip": "10.66.0.10",
                          "in_scope": False}) + "\n"
    pfx = _write_files(tmp_path, {"-nuclei-normalized.jsonl": nuclei,
                                  "-resolve-report.jsonl": resolve})
    data = az._load_scan_data(pfx)
    assert "vpn.example.com" in data["hosts"]                # left alone


def test_no_resolve_report_leaves_hosts_unchanged(tmp_path):
    nuclei = "\n".join([
        json.dumps({"host": "1.2.3.4", "type": "finding", "severity": "high",
                    "title": "a", "detail": ""}),
        json.dumps({"host": "app.example.com", "type": "finding", "severity": "high",
                    "title": "b", "detail": ""}),
    ]) + "\n"
    pfx = _write_files(tmp_path, {"-nuclei-normalized.jsonl": nuclei})
    data = az._load_scan_data(pfx)
    assert set(data["hosts"]) == {"1.2.3.4", "app.example.com"}
