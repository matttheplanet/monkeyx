"""The scan-debrief must count EVERY finding-producing tool.

Regression: _parse_findings only read a fixed set of *-normalized.jsonl globs
(nuclei/nessus/bbot/dns_security/nmap), so testssl (which has a normalized JSONL)
and gowitness (which writes findings only to scan.db, via ai_analyze_gowitness)
were silently dropped from the "Findings by Tool" table and the severity totals —
under-counting criticals and highs in the executive summary. testssl is now in
the JSONL set; scan.db-only tools are merged from the DB without double-counting
the JSONL-backed tools.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import scan_db
from modules.summary import _parse_findings


def _seed(output_dir):
    data_dir = os.path.join(output_dir, "data")
    os.makedirs(data_dir)

    with open(os.path.join(data_dir, "scan-testssl-normalized.jsonl"), "w") as f:
        f.write(json.dumps({"tool": "testssl", "type": "vulnerability",
                            "severity": "high", "host": "h.tld", "port": 443,
                            "proto": "tcp", "title": "[SWEET32] 3DES offered"}) + "\n")

    with open(os.path.join(data_dir, "scan-nuclei-normalized.jsonl"), "w") as f:
        f.write(json.dumps({"tool": "nuclei", "type": "nuclei_finding",
                            "severity": "critical", "host": "h.tld", "port": 443,
                            "proto": "tcp", "template_id": "cve-x", "title": "x"}) + "\n")

    # scan.db: a gowitness finding (DB-only) plus the SAME nuclei finding (already
    # counted from JSONL — must NOT be double-counted from the DB).
    db = scan_db.open_db(output_dir)
    db.upsert_finding(finding_id=scan_db.finding_id("h.tld", 443, "tcp", "screenshot"),
                      host="h.tld", port=443, proto="tcp", claim="screenshot",
                      tool="gowitness", type="finding", severity="critical",
                      title="Exposed admin panel", now=scan_db._iso_now())
    db.upsert_finding(finding_id=scan_db.finding_id("h.tld", 443, "tcp", "cve-x"),
                      host="h.tld", port=443, proto="tcp", claim="cve-x",
                      tool="nuclei", type="nuclei_finding", severity="critical",
                      title="x", now=scan_db._iso_now())
    db.close()
    return data_dir


def test_testssl_and_gowitness_counted_without_double_counting(tmp_path):
    output_dir = str(tmp_path / "run")
    os.makedirs(output_dir)
    data_dir = _seed(output_dir)

    stats = {"findings": {"total": 0, "critical": 0, "high": 0,
                          "medium": 0, "low": 0, "info": 0}}
    _parse_findings(data_dir, stats, output_dir)

    by_tool = stats["findings"]["by_tool"]
    assert by_tool["testssl"]["high"] == 1        # JSONL, previously omitted
    assert by_tool["gowitness"]["critical"] == 1  # scan.db only, previously omitted
    # nuclei counted once from JSONL, not doubled by the identical scan.db row.
    assert by_tool["nuclei"]["total"] == 1

    # Totals reflect all tools: nuclei + gowitness criticals, testssl high.
    assert stats["findings"]["critical"] == 2
    assert stats["findings"]["high"] == 1


def test_no_scandb_still_works(tmp_path):
    # A run with only JSONL and no scan.db must still parse (best-effort merge).
    output_dir = str(tmp_path / "run")
    data_dir = os.path.join(output_dir, "data")
    os.makedirs(data_dir)
    with open(os.path.join(data_dir, "scan-testssl-normalized.jsonl"), "w") as f:
        f.write(json.dumps({"tool": "testssl", "type": "vulnerability",
                            "severity": "high", "host": "h.tld", "port": 443,
                            "proto": "tcp", "title": "[SWEET32]"}) + "\n")
    stats = {"findings": {"total": 0, "critical": 0, "high": 0,
                          "medium": 0, "low": 0, "info": 0}}
    _parse_findings(data_dir, stats, output_dir)
    assert stats["findings"]["by_tool"]["testssl"]["high"] == 1
