"""Coverage reconciliation helpers in workflows.py (Phase 2).

Focus on the URL-vs-bare-host matching (the fed side stores URLs for web tools,
tool output reports bare hosts) and the honest "no extractor -> None" contract.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import workflows


def test_coverage_host_key_normalizes_url_and_host():
    k = workflows._coverage_host_key
    assert k("https://a.com") == "a.com"
    assert k("https://b.com:8443") == "b.com"     # non-standard port stripped
    assert k("http://c.com/path?x=1") == "c.com"  # path stripped
    assert k("1.2.3.4:443") == "1.2.3.4"
    assert k("HOST.COM.") == "host.com"           # case + trailing dot
    assert k("bare.host") == "bare.host"
    assert k("") == "" and k(None) == ""


def test_reached_extractor_unknown_module_returns_none():
    # No extractor for this tool -> None so the caller leaves rows 'fed',
    # never guessing no_response.
    assert workflows._reached_hosts_from_output({"output_files": []}, "some_tool") is None


def test_reached_extractor_nuclei_reads_hosts(tmp_path):
    jf = tmp_path / "scan-nuclei.jsonl"
    jf.write_text(
        json.dumps({"host": "a.com", "template-id": "x"}) + "\n"
        + json.dumps({"matched-at": "https://b.com:8443/p", "template-id": "y"}) + "\n"
        + "not json\n"
    )
    got = workflows._reached_hosts_from_output(
        {"output_files": [str(jf)]}, "ax_nuclei")
    assert got == {"a.com", "b.com"}


def test_reached_extractor_httpx_reads_jsonl(tmp_path):
    jf = tmp_path / "scan-httpx.jsonl"
    jf.write_text(
        json.dumps({"url": "https://a.com", "host": "a.com", "status_code": 200}) + "\n"
        + json.dumps({"input": "b.com:8443", "url": "https://b.com:8443"}) + "\n"
    )
    got = workflows._reached_hosts_from_output(
        {"output_files": [str(jf)]}, "ax_httpx")
    assert got == {"a.com", "b.com"}


def test_reached_extractor_nmap_reads_alive_hosts(tmp_path):
    xml = tmp_path / "scan-tcp.xml"
    xml.write_text("<nmaprun/>")
    (tmp_path / "scan-tcp-alive-hosts.txt").write_text("1.2.3.4\n5.6.7.8\n")
    got = workflows._reached_hosts_from_output(
        {"output_files": [str(xml)]}, "ax_nmap_tcp")
    assert got == {"1.2.3.4", "5.6.7.8"}
