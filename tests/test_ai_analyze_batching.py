"""Tests for ai_analyze host coverage + token-aware call packing.

Model: ai_max_hosts (depth presets + "unlimited") caps the TOTAL hosts analysed;
those hosts are packed into as few context-window-sized AI calls as fit. No
silent under-coverage — everything up to ai_max_hosts is analysed, and a call
split is transparent.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import modules.ai_analyze as az


# --- pure-helper unit tests ----------------------------------------------- #

def test_chunk_covers_everything():
    items = list(range(45))
    chunks = az._chunk(items, 20)
    assert len(chunks) == 3
    assert [x for c in chunks for x in c] == items


def test_context_window_bedrock_vs_direct():
    class _Direct:
        config = {"model": "claude"}
    class _Bedrock:
        config = {"model": "claude", "aws_region": "us-east-1"}
    assert az._context_window(_Direct(), {}) == az.DEFAULT_CONTEXT_WINDOW
    assert az._context_window(_Bedrock(), {}) == az.BEDROCK_CONTEXT_WINDOW
    # explicit override wins over both
    assert az._context_window(_Bedrock(), {"ai_context_window": 500000}) == 500000


def test_context_window_credentials_config_knob():
    # A `context_window` in the provider's credentials.yaml block lifts the
    # Bedrock 200k clamp (for accounts that HAVE the 1M beta) without a per-run
    # flag — but the per-run kwarg still wins over it.
    class _BedrockWith1M:
        config = {"model": "claude", "aws_region": "us-east-1",
                  "context_window": 1_000_000}
    assert az._context_window(_BedrockWith1M(), {}) == 1_000_000
    # per-run kwarg still overrides the configured value
    assert az._context_window(_BedrockWith1M(), {"ai_context_window": 42}) == 42

    # A malformed config value is ignored -> falls back to the Bedrock default.
    class _BedrockBadCfg:
        config = {"model": "claude", "aws_region": "us-east-1",
                  "context_window": "lots"}
    assert az._context_window(_BedrockBadCfg(), {}) == az.BEDROCK_CONTEXT_WINDOW


def test_pack_hosts_by_budget_fills_and_splits():
    hd = {"hosts": {f"h{i}": {"x": "y" * 100} for i in range(10)}}
    ips = list(hd["hosts"])
    per_host = az._host_footprint_chars(hd["hosts"]["h0"])
    # Budget for ~3 hosts per call -> ceil(10/3) = 4 calls, all hosts covered.
    batches = az._pack_hosts(ips, hd, per_host * 3, None)
    assert [ip for b in batches for ip in b] == ips     # nothing dropped
    assert all(len(b) <= 4 for b in batches)
    assert len(batches) >= 3


def test_pack_hosts_manual_override():
    hd = {"hosts": {f"h{i}": {} for i in range(10)}}
    ips = list(hd["hosts"])
    batches = az._pack_hosts(ips, hd, 10 ** 9, hosts_per_call=4)
    assert [len(b) for b in batches] == [4, 4, 2]


def test_pack_hosts_lone_oversize_host_still_kept():
    hd = {"hosts": {"big": {"blob": "z" * 10000}, "small": {}}}
    batches = az._pack_hosts(["big", "small"], hd, 100, None)   # budget < big host
    assert [ip for b in batches for ip in b] == ["big", "small"]  # never dropped


def test_merge_recommendations_unions_and_dedups():
    r1 = {"quick_wins": [{"host": "h1", "action": "x"}], "attack_chains": [],
          "requires_verification": [], "cve_research": []}
    r2 = {"quick_wins": [{"host": "h1", "action": "x"}, {"host": "h2", "action": "y"}],
          "attack_chains": [{"name": "chain"}], "requires_verification": [], "cve_research": []}
    merged = az._merge_recommendations([r1, r2])
    assert len(merged["quick_wins"]) == 2
    assert len(merged["attack_chains"]) == 1


class _RecordingAI:
    def __init__(self):
        self.systems = []

    def query_json(self, system, user, **kw):
        self.systems.append(system)
        return {"quick_wins": [{"host": "synth", "action": "z"}], "attack_chains": [],
                "requires_verification": [], "cve_research": []}


def test_synthesis_skipped_for_single_call():
    ai = _RecordingAI()
    one = {"quick_wins": [{"host": "h1", "action": "a"}], "attack_chains": [],
           "requires_verification": [], "cve_research": []}
    out = az._synthesize_recommendations(ai, [one], {}, {}, 1000)
    assert ai.systems == []
    assert out["quick_wins"] == one["quick_wins"]


def test_synthesis_runs_for_multiple_calls():
    ai = _RecordingAI()
    r1 = {"quick_wins": [{"host": "h1", "action": "a"}], "attack_chains": [],
          "requires_verification": [], "cve_research": []}
    r2 = {"quick_wins": [{"host": "h2", "action": "b"}], "attack_chains": [],
          "requires_verification": [], "cve_research": []}
    out = az._synthesize_recommendations(ai, [r1, r2], {}, {}, 1000)
    assert az.SYSTEM_PROMPT_SYNTHESIS in ai.systems
    assert out["quick_wins"] == [{"host": "synth", "action": "z"}]


# --- end-to-end coverage (fake AI) ---------------------------------------- #

class _FakeAI:
    def __init__(self, *a, **k):
        self.name = "fake"
        self.config = {"model": "fake"}
        self.calls = 0

    def query_json(self, system, user, **kw):
        self.calls += 1
        return {"quick_wins": [], "attack_chains": [], "requires_verification": [],
                "cve_research": [], "services": [], "correlations": []}

    def get_usage_summary(self):
        return {"total_cost_usd": 0, "cost_is_estimate": False, "cost_unknown": False,
                "calls": self.calls, "total_tokens": 0}


def _synthetic_host_data(m):
    hosts = {}
    for i in range(m):
        hosts[f"h{i}"] = {
            "ports": [{"port": 80, "proto": "tcp", "service": "http", "banner": "", "version": ""}],
            "findings": [{"severity": "high", "title": f"f{i}", "detail": ""}],
            "web_dirs": [], "subdomains": [], "web_services": [],
        }
    return {"hosts": hosts, "total_ports": m, "total_findings": m}


def _patch_common(monkeypatch, seen):
    monkeypatch.setattr(az, "AIProvider", _FakeAI)
    monkeypatch.setattr(az, "_correlate_findings", lambda *a, **k: {"correlations": []})
    monkeypatch.setattr(az, "_render_markdown", lambda *a, **k: None)

    def _fake_recs(ai, sr, sub, static, summary, t2a, a2t, max_tokens, kb,
                   kb_refs_out=None, correlation_context="", use_kb=True, log_label=""):
        seen.append(set(sub["hosts"].keys()))
        first = next(iter(sub["hosts"]))
        return {"quick_wins": [{"host": first, "action": "x", "commands": []}],
                "attack_chains": [], "requires_verification": [], "cve_research": []}
    monkeypatch.setattr(az, "_generate_recommendations", _fake_recs)


def test_single_call_covers_all_hosts_under_1m_window(tmp_path, monkeypatch):
    # 45 tiny hosts under a 1M window all fit in ONE call — full coverage, no split.
    seen = []
    monkeypatch.setattr(az, "_load_scan_data", lambda p: _synthetic_host_data(45))
    _patch_common(monkeypatch, seen)
    pfx = str(tmp_path / "scan")
    az.run_ai_analyze(pfx, data_prefix=pfx, reports_prefix=pfx, ai_depth="unlimited")
    assert len(seen) == 1
    assert seen[0] == {f"h{i}" for i in range(45)}


def test_forced_hosts_per_call_covers_all(tmp_path, monkeypatch):
    # ai_hosts_per_call override splits into fixed chunks; still no host dropped.
    seen = []
    monkeypatch.setattr(az, "_load_scan_data", lambda p: _synthetic_host_data(45))
    _patch_common(monkeypatch, seen)
    pfx = str(tmp_path / "scan")
    az.run_ai_analyze(pfx, data_prefix=pfx, reports_prefix=pfx,
                      ai_depth="unlimited", ai_hosts_per_call=20)
    assert len(seen) == 3
    assert set().union(*seen) == {f"h{i}" for i in range(45)}


def test_ai_max_hosts_caps_total_and_reports(tmp_path, monkeypatch):
    # ai_depth=quick -> max_hosts=20 total; 45 hosts -> top 20 analysed, flagged.
    seen = []
    monkeypatch.setattr(az, "_load_scan_data", lambda p: _synthetic_host_data(45))
    _patch_common(monkeypatch, seen)
    pfx = str(tmp_path / "scan")
    result = az.run_ai_analyze(pfx, data_prefix=pfx, reports_prefix=pfx, ai_depth="quick")
    assert len(set().union(*seen)) == 20
    assert result["data_truncated"] is True


def test_correlation_context_formats_relationships():
    corrs = {"correlations": [
        {"title": "Shared Jenkins", "type": "shared_management",
         "hosts": ["H1", "H2"], "implication": "same admin creds likely"},
        {"type": "outlier_host", "hosts": ["H3"], "evidence": "only host with 3389 open"},
    ]}
    ctx = az._correlation_context(corrs)
    assert "Infrastructure Relationships" in ctx
    assert "Shared Jenkins [H1, H2]: same admin creds likely" in ctx
    assert "outlier_host [H3]: only host with 3389 open" in ctx


def test_correlation_context_empty():
    assert az._correlation_context({"correlations": []}) == ""
    assert az._correlation_context({}) == ""


def test_correlations_feed_the_chaining_pass(tmp_path, monkeypatch):
    # Correlations are computed BEFORE recommendations and their summary is passed
    # into the chaining pass, so multi-host chains can build on them.
    seen_ctx = []
    monkeypatch.setattr(az, "_load_scan_data", lambda p: _synthetic_host_data(3))
    monkeypatch.setattr(az, "AIProvider", _FakeAI)
    monkeypatch.setattr(az, "_render_markdown", lambda *a, **k: None)
    monkeypatch.setattr(az, "_correlate_findings", lambda *a, **k: {"correlations": [
        {"title": "Shared stack", "hosts": ["H1", "H2"], "implication": "pivot likely"}]})

    def _capture_recs(ai, sr, sub, static, summary, t2a, a2t, max_tokens, kb,
                      kb_refs_out=None, correlation_context="", use_kb=True, log_label=""):
        seen_ctx.append(correlation_context)
        return {"quick_wins": [], "attack_chains": [], "requires_verification": [],
                "cve_research": []}
    monkeypatch.setattr(az, "_generate_recommendations", _capture_recs)

    pfx = str(tmp_path / "scan")
    az.run_ai_analyze(pfx, data_prefix=pfx, reports_prefix=pfx, ai_depth="unlimited")
    assert seen_ctx and "Infrastructure Relationships" in seen_ctx[0]
    assert "Shared stack [H1, H2]: pivot likely" in seen_ctx[0]


def test_multipass_runs_pure_and_kb_legs_then_reconciles(tmp_path, monkeypatch):
    # --multi-pass: each batch runs recommendations twice (pure, then KB), and
    # BOTH results are handed to the synthesis/reconcile step.
    seen_use_kb = []
    synth_batch_counts = []
    monkeypatch.setattr(az, "_load_scan_data", lambda p: _synthetic_host_data(3))
    monkeypatch.setattr(az, "AIProvider", _FakeAI)
    monkeypatch.setattr(az, "_render_markdown", lambda *a, **k: None)
    monkeypatch.setattr(az, "_correlate_findings", lambda *a, **k: {"correlations": []})

    def _rec(ai, sr, sub, static, summary, t2a, a2t, max_tokens, kb,
             kb_refs_out=None, correlation_context="", use_kb=True, log_label=""):
        seen_use_kb.append(use_kb)
        return {"quick_wins": [], "attack_chains": [], "requires_verification": [], "cve_research": []}
    monkeypatch.setattr(az, "_generate_recommendations", _rec)

    def _synth(ai, batch_results, *a, **k):
        synth_batch_counts.append(len(batch_results))
        return {"quick_wins": [], "attack_chains": [], "requires_verification": [], "cve_research": []}
    monkeypatch.setattr(az, "_synthesize_recommendations", _synth)

    pfx = str(tmp_path / "scan")
    az.run_ai_analyze(pfx, data_prefix=pfx, reports_prefix=pfx,
                      ai_depth="unlimited", ai_multipass=True)
    assert seen_use_kb == [False, True]      # one pure leg, one KB leg
    assert synth_batch_counts == [2]         # both legs reconciled together


def test_render_markdown_shows_kb_usage_and_multipass(tmp_path):
    data = {
        "metadata": {
            "generated_at": "2026-09-02T00:00:00Z", "ai_provider": "anthropic",
            "ai_model": "claude", "depth": "deep", "hosts_analyzed": 1, "hosts_total": 1,
            "services_analyzed": 0, "services_total": 0, "total_ports": 0, "total_findings": 0,
            "kb_references_used": True,
            "multipass": {"enabled": True, "passes": ["recommendations:pure", "recommendations:kb"]},
        },
        "truncation": None, "service_research": [],
        "recommendations": {"quick_wins": [], "attack_chains": [], "requires_verification": [], "cve_research": []},
        "correlations": [],
    }
    out = tmp_path / "ai.md"
    az._render_markdown(data, str(out))
    txt = out.read_text()
    assert "Analysis mode:** multi-pass" in txt
    assert "Knowledge base references used:** yes" in txt
