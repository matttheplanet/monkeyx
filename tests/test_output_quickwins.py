"""Regression tests for four output-quality fixes found in a real run review.

1. analyze._find_ssl_tls_issues: weak-cipher regex ran against ssl-cert PEM
   bodies and matched the base64 'md5' substring -> bogus "weak cipher on N
   hosts" finding shipped into the AI recon report. Cipher detection must come
   from ssl-enum-ciphers only.
2. jsonl_to_csv._write_consolidated_findings: (a) globbed the raw
   *-dns-security.jsonl in addition to its normalized form -> dns findings
   double-counted with inconsistent severity casing; (b) admitted every
   info-severity open_port/subdomain/script_output row -> 18k info rows buried
   the handful of real findings.
4. ai_analyze md header labeled the all-tools finding count "Nuclei Findings".
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.analyze import _find_ssl_tls_issues
from modules import jsonl_to_csv


# --- Fix 1: SSL false-positive -------------------------------------------- #

# An ssl-cert PEM detail whose base64 body contains a lowercase 'md5'
# substring — this is what tripped the old case-insensitive MD5 match.
_SSL_CERT_DETAIL = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIFAENOPUV4YW1wbGUgRW5lcmd5IFNlcnZpY2VzIENBAAAAAAAAAAA=\n"
    "-----END CERTIFICATE-----"
)


def test_ssl_cert_pem_not_flagged_as_weak_cipher():
    recs = [{
        "type": "script_output", "method": "ssl-cert",
        "host": "203.0.113.9", "port": 443, "detail": _SSL_CERT_DETAIL,
    }]
    issues = _find_ssl_tls_issues(recs)
    # The PEM body must not be reported as a weak cipher/protocol.
    flat = [i for f in issues for i in f["issues"]]
    assert "weak cipher/protocol" not in flat


def test_real_weak_cipher_still_detected_from_enum_ciphers():
    # A genuine weak cipher in ssl-enum-ciphers output MUST still be flagged.
    recs = [{
        "type": "script_output", "method": "ssl-enum-ciphers",
        "host": "10.0.0.1", "port": 443,
        "detail": "TLSv1.0:\n  ciphers:\n    TLS_RSA_WITH_RC4_128_SHA - C\n",
    }]
    issues = _find_ssl_tls_issues(recs)
    flat = [i for f in issues for i in f["issues"]]
    assert "weak cipher/protocol" in flat


def test_cert_hygiene_still_detected_from_ssl_cert():
    # Cert-hygiene issues (expired/self-signed) still come from ssl-cert.
    recs = [{
        "type": "script_output", "method": "ssl-cert",
        "host": "10.0.0.2", "port": 443,
        "detail": "Subject: commonName=x\nThis certificate has expired",
    }]
    issues = _find_ssl_tls_issues(recs)
    flat = [i for f in issues for i in f["issues"]]
    assert "expired certificate" in flat


# --- Fix 3: consolidated findings CSV ------------------------------------- #

def _write_jsonl(path, records):
    with open(path, "w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")


def test_consolidated_findings_excludes_info_noise_and_no_double_count(tmp_path):
    prefix = str(tmp_path / "scan")
    # normalized dns findings (the real ones)
    _write_jsonl(f"{prefix}-dns-security-normalized.jsonl", [
        {"type": "finding", "severity": "high", "host": "a.tld", "title": "dmarc_missing"},
        {"type": "finding", "severity": "low", "host": "b.tld", "title": "spf"},
    ])
    # the RAW dns file also exists (uppercase sev) — must NOT be merged again.
    _write_jsonl(f"{prefix}-dns-security.jsonl", [
        {"type": "finding", "severity": "HIGH", "host": "a.tld", "title": "dmarc_missing"},
    ])
    # nmap normalized: all info-level noise that must be excluded.
    _write_jsonl(f"{prefix}-nmap-normalized.jsonl", [
        {"type": "open_port", "severity": "info", "host": "a.tld", "port": 443},
        {"type": "script_output", "severity": "info", "host": "a.tld", "method": "ssl-cert"},
    ])
    _write_jsonl(f"{prefix}-subfinder-normalized.jsonl", [
        {"type": "subdomain", "severity": "info", "host": "a.tld"},
    ])

    csv_path = jsonl_to_csv._write_consolidated_findings(prefix, str(tmp_path))
    assert csv_path is not None
    import csv as _csv
    with open(csv_path, encoding="utf-8-sig") as fh:
        assert fh.readline().rstrip("\r\n") == "sep=,"
        rows = list(_csv.DictReader(fh))
    # Exactly the 2 real findings — no info noise, no double-counted dns row.
    assert len(rows) == 2
    sevs = sorted(r["severity"] for r in rows)
    assert sevs == ["high", "low"]
    # No uppercase-severity duplicate leaked in from the raw dns file.
    assert all(r["severity"] == r["severity"].lower() for r in rows)


def test_consolidated_findings_finding_types_and_severity(tmp_path):
    # A real finding TYPE is kept regardless of severity (an info-severity
    # nuclei_finding is still a genuine detection). A non-finding type is kept
    # only when it carries a non-info severity, and dropped when info.
    # Distinct discriminators (tool + template_id/method) so the finding_id dedup
    # keeps them as separate findings — this test is about is_finding_record
    # filtering, not the dedup collapse (which is covered elsewhere).
    prefix = str(tmp_path / "scan")
    _write_jsonl(f"{prefix}-nuclei-normalized.jsonl", [
        {"tool": "nuclei", "type": "vulnerability", "severity": "critical",
         "host": "a.tld", "template_id": "rce-1", "title": "rce"},
        {"tool": "nuclei", "type": "nuclei_finding", "severity": "medium",
         "host": "a.tld", "template_id": "med-1", "title": "x"},
        {"tool": "nuclei", "type": "nuclei_finding", "severity": "info",
         "host": "a.tld", "template_id": "tech-1", "title": "tech"},
    ])
    # nmap normalized: an info script_output (context, dropped) + a state-classified
    # vulnerability (kept).
    _write_jsonl(f"{prefix}-nmap-normalized.jsonl", [
        {"tool": "nmap", "type": "script_output", "severity": "info",
         "host": "a.tld", "method": "ssl-cert"},
        {"tool": "nmap", "type": "vulnerability", "severity": "medium",
         "host": "a.tld", "method": "http-vuln-x"},
    ])
    csv_path = jsonl_to_csv._write_consolidated_findings(prefix, str(tmp_path))
    import csv as _csv
    with open(csv_path, encoding="utf-8-sig") as fh:
        assert fh.readline().rstrip("\r\n") == "sep=,"
        rows = list(_csv.DictReader(fh))
    # 3 nuclei findings (all real finding types incl. info) + 1 nmap vuln.
    # The info script_output is context and excluded.
    assert len(rows) == 4
    assert sorted(r["severity"] for r in rows) == ["critical", "info", "medium", "medium"]


def test_raw_tool_csv_skipped_when_normalized_sibling_exists(tmp_path):
    """The bloated raw {prefix}-nuclei.csv (full request/response bodies) must
    NOT be produced when the lean {prefix}-nuclei-normalized.csv is — but a tool
    with no normalized sibling still converts."""
    prefix = str(tmp_path / "scan")
    data_dir = str(tmp_path)
    reports = tmp_path / "reports"
    # raw nuclei (heavy fields) + its normalized sibling
    _write_jsonl(f"{prefix}-nuclei.jsonl", [
        {"host": "a.tld", "template-id": "x", "request": "GET / …",
         "response": "HTTP/1.1 200 …" * 50},
    ])
    _write_jsonl(f"{prefix}-nuclei-normalized.jsonl", [
        {"type": "nuclei_finding", "host": "a.tld", "severity": "low", "title": "x"},
    ])
    # a tool with NO normalized sibling — must still be converted
    _write_jsonl(f"{prefix}-testssl.jsonl", [{"host": "a.tld", "note": "tls1.0"}])

    r = jsonl_to_csv.run_jsonl_to_csv(
        prefix=prefix, data_prefix=prefix,
        reports_prefix=str(reports / "scan"))
    produced = {os.path.basename(p) for p in r["output_files"]}
    assert "scan-nuclei.csv" not in produced          # raw skipped
    assert "scan-nuclei-normalized.csv" in produced    # lean kept
    assert "scan-testssl.csv" in produced              # no-sibling still converts
