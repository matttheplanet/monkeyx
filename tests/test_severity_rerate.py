"""MonkeyX severity re-rating: elevate-only, curated, provenance-preserving."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from core.severity_rerate import rerate
from core import scan_db


@pytest.mark.parametrize("claim,tool,exp_sev,exp_src", [
    ("credentials-disclosure", "info", "high", "monkeyx_rule"),   # elevated
    ("xff-403-bypass", "info", "medium", "monkeyx_rule"),
    ("baddns", "medium", "high", "monkeyx_rule"),
    ("credentials-disclosure", "critical", "critical", "tool"),   # never downgrade
    ("unknown-template", "info", "info", "tool"),                 # not in allowlist
    ("CREDENTIALS-DISCLOSURE", "low", "high", "monkeyx_rule"),    # case-insensitive
    (None, "medium", "medium", "tool"),
])
def test_rerate(claim, tool, exp_sev, exp_src):
    sev, src, reason = rerate(claim, tool)
    assert sev == exp_sev and src == exp_src
    assert (reason is not None) == (src == "monkeyx_rule")


def test_upsert_finding_records_rerating(tmp_path):
    db = scan_db.ScanDB(str(tmp_path))
    fid = scan_db.finding_id("h.tld", 443, "tcp", "credentials-disclosure")
    db.upsert_finding(finding_id=fid, host="h.tld", port=443, proto="tcp",
                      claim="credentials-disclosure", tool="nuclei",
                      type="finding", severity="info", title="key in body")
    row = db._conn.execute(
        "SELECT severity, original_severity, severity_source, rerate_reason "
        "FROM findings WHERE finding_id=?", (fid,)).fetchone()
    db.close()
    assert row[0] == "high"          # effective (elevated)
    assert row[1] == "info"          # tool's original preserved
    assert row[2] == "monkeyx_rule"
    assert "credential" in (row[3] or "").lower()


def test_upsert_finding_untouched_when_no_rule(tmp_path):
    db = scan_db.ScanDB(str(tmp_path))
    fid = scan_db.finding_id("h.tld", 80, "tcp", "some-info-template")
    db.upsert_finding(finding_id=fid, host="h.tld", port=80, proto="tcp",
                      claim="some-info-template", tool="nuclei",
                      type="finding", severity="info", title="x")
    row = db._conn.execute(
        "SELECT severity, original_severity, severity_source FROM findings "
        "WHERE finding_id=?", (fid,)).fetchone()
    db.close()
    assert row[0] == "info" and row[1] == "info" and row[2] == "tool"


def test_severity_filter_returns_elevated(tmp_path):
    # /findings?severity=high must now include a MonkeyX-elevated info finding.
    import webserver
    db = scan_db.ScanDB(str(tmp_path))
    db.upsert_finding(finding_id=scan_db.finding_id("h", 443, "tcp", "credentials-disclosure"),
                      host="h", port=443, proto="tcp", claim="credentials-disclosure",
                      tool="nuclei", severity="info", title="k")
    db.close()
    conn = webserver._connect_ro(str(tmp_path))
    try:
        highs = webserver._query_findings(conn, severity="high")
    finally:
        conn.close()
    assert len(highs) == 1
    assert highs[0]["original_severity"] == "info"
    assert highs[0]["severity_source"] == "monkeyx_rule"
