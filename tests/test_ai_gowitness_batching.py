"""Tests for ai_analyze_gowitness map-reduce batching + synthesis.

Coverage guarantee: no silent drop of groups/singletons on big scopes — instead
process everything bounded by a reported cost ceiling, then consolidate.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import modules.ai_analyze_gowitness as gw


# --- pure-helper unit tests ----------------------------------------------- #

def test_dedup_findings_keeps_highest_severity():
    findings = [
        {"url": "http://x/a", "category": "login_panel", "severity": "MEDIUM"},
        {"url": "http://x/a", "category": "login_panel", "severity": "HIGH"},   # dup, higher sev
        {"url": "http://x/b", "category": "admin_interface", "severity": "LOW"},
    ]
    out = gw._dedup_findings(findings)
    assert len(out) == 2
    a = next(f for f in out if f["url"] == "http://x/a")
    assert a["severity"] == "HIGH"


def test_singleton_batch_constant():
    assert gw._SINGLETON_BATCH == 5


class _RecordingAI:
    def __init__(self):
        self.calls = 0

    def query_json(self, system, user, **kw):
        self.calls += 1
        return {"findings": [{"url": "http://x/merged", "category": "admin_interface",
                              "severity": "CRITICAL"}]}


def test_synthesis_skipped_when_under_two():
    ai = _RecordingAI()
    out = gw._synthesize_gowitness_findings(ai, [{"url": "u", "category": "c", "severity": "LOW"}], 8000)
    assert ai.calls == 0
    assert len(out) == 1


def test_synthesis_runs_when_multiple():
    ai = _RecordingAI()
    findings = [
        {"url": "http://x/a", "category": "login_panel", "severity": "HIGH"},
        {"url": "http://x/b", "category": "admin_interface", "severity": "LOW"},
    ]
    out = gw._synthesize_gowitness_findings(ai, findings, 8000)
    assert ai.calls == 1
    assert out == [{"url": "http://x/merged", "category": "admin_interface", "severity": "CRITICAL"}]


# --- end-to-end ceiling / coverage (fakes) -------------------------------- #

class _FakeAI:
    def __init__(self, *a, **k):
        self.name = "anthropic"           # run() gates on the anthropic provider
        self.config = {"model": "fake"}
        self.calls = 0

    def query_json(self, *a, **k):
        self.calls += 1
        return {"findings": []}

    def get_usage_summary(self):
        return {"calls": self.calls, "total_tokens": 0, "total_cost_usd": 0, "cost_unknown": False}


def _groups(n_groups, members_each):
    groups = {}
    for g in range(n_groups):
        members = []
        for m in range(members_each):
            members.append({
                "id": g * 100 + m, "url": f"http://host{g}-{m}/", "response_code": 200,
                "title": f"App {g}", "technologies": ["nginx"], "content_length": 100,
                "filename": f"{g}_{m}.png",
            })
        groups[str(g)] = members
    return groups


def _patch(monkeypatch, tmp_path, groups, group_calls, singleton_counts):
    (tmp_path / "gowitness.sqlite3").write_text("x")
    monkeypatch.setattr(gw, "AIProvider", _FakeAI)
    monkeypatch.setattr(gw, "_find_gowitness_db", lambda *a, **k: str(tmp_path / "gowitness.sqlite3"))
    monkeypatch.setattr(gw, "_load_gowitness_data", lambda p: groups)
    monkeypatch.setattr(gw, "_generate_report", lambda *a, **k: None)
    monkeypatch.setattr(gw, "_mint_gowitness_findings", lambda *a, **k: 0)
    monkeypatch.setattr(gw, "_synthesize_gowitness_findings", lambda ai, f, mt, *a, **k: f)

    def _fake_group(ai, gid, members, db_dir, limits, *a, **k):
        group_calls.append(gid)
        return {"group_assessment": "interesting", "category": "login_panel",
                "severity": "HIGH", "description": "d", "notable_urls": [], "technologies": []}
    monkeypatch.setattr(gw, "_analyze_group", _fake_group)

    def _fake_singletons(ai, entries, db_dir, limits, *a, **k):
        singleton_counts.append(len(entries))
        return []
    monkeypatch.setattr(gw, "_analyze_singletons", _fake_singletons)


def _run_meta(tmp_path, **kwargs):
    pfx = str(tmp_path / "scan")
    result = gw.run_ai_analyze_gowitness(pfx, data_prefix=pfx, reports_prefix=pfx, **kwargs)
    with open(result["json_output"]) as f:
        return json.load(f)["meta"]


def test_all_groups_covered_unlimited(tmp_path, monkeypatch):
    group_calls, singleton_counts = [], []
    _patch(monkeypatch, tmp_path, _groups(5, 2), group_calls, singleton_counts)
    meta = _run_meta(tmp_path, ai_max_groups="unlimited")
    assert len(group_calls) == 5                    # every non-noise group analyzed
    assert meta["groups_dropped"] == 0


def test_group_cap_bounds_and_reports(tmp_path, monkeypatch):
    group_calls, singleton_counts = [], []
    _patch(monkeypatch, tmp_path, _groups(5, 2), group_calls, singleton_counts)
    meta = _run_meta(tmp_path, ai_max_groups=2)
    assert len(group_calls) == 2                    # total-groups cap
    assert meta["groups_dropped"] == 3              # rest reported, not silent


def test_singleton_cap_bounds_and_reports(tmp_path, monkeypatch):
    group_calls, singleton_counts = [], []
    # 12 single-member groups -> 12 singleton candidates; cap 5 -> 7 dropped.
    _patch(monkeypatch, tmp_path, _groups(12, 1), group_calls, singleton_counts)
    meta = _run_meta(tmp_path, ai_max_groups="unlimited", ai_max_singletons=5)
    assert singleton_counts == [5]                  # only the cap analyzed
    assert meta["singletons_dropped"] == 7


def test_interesting_groups_omits_conflicting_severity(tmp_path):
    """#6: the same asset was rated one severity in the re-ranked Findings
    sections and another in 'Interesting Groups'. The groups index must NOT
    restate a per-group severity (findings sections are authoritative)."""
    findings = [{"url": "http://h/", "category": "app", "severity": "CRITICAL",
                 "description": "Juice Shop", "attack_notes": "x"}]
    groups = [{"group_assessment": "interesting", "severity": "HIGH",
               "category": "app", "description": "Juice Shop group",
               "notable_urls": ["http://h/"], "attack_notes": "x"}]
    out = tmp_path / "gw.md"
    meta = {"provider": "p", "model": "m", "total_screenshots": 1,
            "total_groups": 1, "groups_analyzed": 1, "singletons_analyzed": 0}
    gw._generate_report(findings, groups, meta, str(out))
    body = out.read_text()
    ig = body.split("## Interesting Groups")[1].split("## ")[0]
    assert "Severity: HIGH" not in ig           # no conflicting per-group severity
    assert "- Category: app" in ig              # grouping content still present
    assert "Juice Shop group" in ig
    assert "## Critical Findings" in body       # severity lives here


def test_report_surfaces_low_and_info_inventory(tmp_path):
    # LOW/INFO findings (generic logins, standard apps) must be visible, not
    # dropped — counted in the summary and listed in the inventory section.
    findings = [
        {"url": "https://login.example.com", "category": "login_panel",
         "severity": "INFO", "title": "Generic webmail login"},
        {"url": "https://app.example.com", "category": "application",
         "severity": "LOW", "title": "Standard portal"},
    ]
    meta = {"provider": "p", "model": "m", "total_screenshots": 2,
            "total_groups": 2, "groups_analyzed": 2, "singletons_analyzed": 0}
    out = tmp_path / "gw.md"
    gw._generate_report(findings, [], meta, str(out))
    body = out.read_text()
    assert "- **LOW findings:** 1" in body
    assert "- **INFO (attack-surface inventory):** 1" in body
    assert "## Low / Informational (attack-surface inventory)" in body
    assert "login.example.com" in body and "[INFO]" in body
    assert "app.example.com" in body and "[LOW]" in body
