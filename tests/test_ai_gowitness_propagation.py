"""Visual-similarity verdict propagation for ai_analyze_gowitness.

A vulnerable perceptual-hash group is one page repeated across many hosts. Only
the representative screenshot is vision-analyzed, but every member should surface
as (probably) vulnerable: _mint_gowitness_findings mints one scan.db row per
covered host, tagging the non-primary ones inferred-visual-similarity at the same
severity.
"""

import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import modules.ai_analyze_gowitness as gw


def _rows(output_dir):
    conn = sqlite3.connect(os.path.join(output_dir, "scan.db"))
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(
            "SELECT host, port, severity, matched_at, tags, detail FROM findings")]
    finally:
        conn.close()


def test_group_finding_propagates_to_every_member(tmp_path):
    output_dir = str(tmp_path)
    finding = {
        "url": "https://a.example.com",              # analyzed representative
        "title": "Exposed admin panel",
        "category": "admin_interface",
        "severity": "HIGH",
        "description": "Unauthenticated admin console",
        "hosts": [
            "https://a.example.com",                 # primary (same as url)
            "https://b.example.com",                 # inferred
            "http://c.example.com:8080",             # inferred, non-standard port
        ],
        "member_count": 3,
    }
    minted = gw._mint_gowitness_findings([finding], output_dir, now=None)
    assert minted == 3

    rows = {r["host"]: r for r in _rows(output_dir)}
    assert set(rows) == {"a.example.com", "b.example.com", "c.example.com"}

    # Every host inherits the representative's severity.
    assert all(r["severity"] == "high" for r in rows.values())
    assert rows["c.example.com"]["port"] == 8080

    # Primary host is NOT tagged inferred; the others are, with a provenance note.
    assert "inferred-visual-similarity" not in (rows["a.example.com"]["tags"] or "")
    for h in ("b.example.com", "c.example.com"):
        assert "inferred-visual-similarity" in (rows[h]["tags"] or "")
        assert "visual similarity to https://a.example.com" in rows[h]["detail"]


def test_low_and_info_are_minted_ranked_low(tmp_path):
    # New contract: LOW/INFO ARE catalogued (ranked lowest) so attack-surface
    # inventory (generic logins, standard apps) isn't dropped — pure noise is
    # filtered upstream at the interesting/noise gate, not here. One row per host.
    output_dir = str(tmp_path)
    findings = [
        {"url": "https://x.example.com", "category": "login_panel", "severity": "INFO",
         "hosts": ["https://x.example.com", "https://y.example.com"]},
        {"url": "https://z.example.com", "category": "application", "severity": "LOW"},
    ]
    assert gw._mint_gowitness_findings(findings, output_dir, now=None) == 3
    sevs = {r["severity"] for r in _rows(output_dir)}
    assert sevs == {"info", "low"}


def test_unmappable_severity_skipped(tmp_path):
    output_dir = str(tmp_path)
    finding = {"url": "https://x.example.com", "category": "error_page", "severity": ""}
    assert gw._mint_gowitness_findings([finding], output_dir, now=None) == 0
    assert _rows(output_dir) == []


def test_singleton_finding_mints_single_row(tmp_path):
    output_dir = str(tmp_path)
    finding = {
        "url": "https://solo.example.com",
        "category": "login_panel",
        "severity": "MEDIUM",
    }
    assert gw._mint_gowitness_findings([finding], output_dir, now=None) == 1
    rows = _rows(output_dir)
    assert len(rows) == 1
    assert "inferred-visual-similarity" not in (rows[0]["tags"] or "")


def test_non_url_primary_is_skipped_but_hosts_mint(tmp_path):
    output_dir = str(tmp_path)
    finding = {
        "url": "Group #5",                           # synthetic, no hostname
        "category": "admin_interface",
        "severity": "HIGH",
        "hosts": ["https://real.example.com"],
    }
    minted = gw._mint_gowitness_findings([finding], output_dir, now=None)
    assert minted == 1
    rows = _rows(output_dir)
    assert [r["host"] for r in rows] == ["real.example.com"]
