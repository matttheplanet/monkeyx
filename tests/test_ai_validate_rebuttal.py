"""Tests for the ai_validate adversarial rebuttal pass.

The rebuttal is an independent second agent that tries to overturn a
confirmed/refuted verdict. Reconciliation is conservative: a verdict flips only
to a confirmed/refuted rebuttal conclusion (which, upstream, can only be reached
on an executed command — _guard_verdict downgrades unsupported ones to unclear);
a disagreeing unclear/error rebuttal contests but never flips. These tests pin
the reconcile logic (pure) and the phase orchestration (agent loop mocked — no
API calls).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules import _ai_validate_rebuttal as reb


def _ran(output="220 mail.example.com ESMTP"):
    return {"tool": "netcat_banner", "blocked": False, "output_preview": output}


class TestReconcile:
    def test_agreement_corroborates(self):
        result = {"verdict": "confirmed", "evidence": "banner proves it",
                  "poc_command": "nc host 25", "severity": "high"}
        reb.reconcile(result, {"verdict": "confirmed", "evidence": "agree",
                               "tool_history": [_ran()]})
        assert result["verdict"] == "confirmed"          # unchanged
        assert result["poc_command"] == "nc host 25"     # preserved
        assert result["rebuttal"]["corroborated"] is True
        assert result["rebuttal"]["flipped"] is False
        assert result["rebuttal"]["contested"] is False

    def test_confirmed_flipped_to_refuted(self):
        result = {"verdict": "confirmed", "evidence": "looked bad",
                  "poc_command": "curl http://host/", "severity": "high"}
        reb.reconcile(result, {"verdict": "refuted",
                               "evidence": "it is a CDN default page",
                               "tool_history": [_ran("HTTP/1.1 200 cloudflare")]})
        assert result["verdict"] == "refuted"
        # A confirmed->refuted flip means the old PoC no longer demonstrates anything.
        assert "poc_command" not in result
        assert result["evidence"].startswith("[overturned by rebuttal — was confirmed]")
        assert result["rebuttal"]["flipped"] is True

    def test_refuted_flipped_to_confirmed_carries_poc(self):
        result = {"verdict": "refuted", "evidence": "no relay observed"}
        reb.reconcile(result, {"verdict": "confirmed",
                               "evidence": "external RCPT accepted",
                               "poc_command": "swaks --to x@ext.com",
                               "severity": "critical",
                               "tool_history": [_ran("250 OK")]})
        assert result["verdict"] == "confirmed"
        assert result["poc_command"] == "swaks --to x@ext.com"
        assert result["severity"] == "critical"
        assert result["rebuttal"]["flipped"] is True

    def test_disagreeing_unclear_contests_without_flipping(self):
        result = {"verdict": "confirmed", "evidence": "banner proves it",
                  "poc_command": "nc host 25"}
        reb.reconcile(result, {"verdict": "unclear",
                               "evidence": "could not reproduce",
                               "tool_history": []})
        assert result["verdict"] == "confirmed"          # NOT flipped on speculation
        assert result["poc_command"] == "nc host 25"     # preserved
        assert result["rebuttal"]["contested"] is True
        assert result["rebuttal"]["flipped"] is False

    def test_rebuttal_error_is_noop(self):
        result = {"verdict": "refuted", "evidence": "no relay"}
        reb.reconcile(result, {"verdict": "error", "evidence": "API error",
                               "tool_history": []})
        assert result["verdict"] == "refuted"
        block = result["rebuttal"]
        assert block["flipped"] is False
        assert block["contested"] is False
        assert block["corroborated"] is False


class TestApplyRebuttalPhase:
    def test_only_confirmed_refuted_rebutted_and_usage_aggregated(self, monkeypatch):
        results = [
            {"verdict": "confirmed", "finding": {"target": "1.2.3.4:25"},
             "_usage": {"input_tokens": 10, "output_tokens": 5, "calls": 1}},
            {"verdict": "unclear", "finding": {"target": "1.2.3.4:80"}},
            {"verdict": "refuted", "finding": {"target": "1.2.3.4:443"},
             "_usage": {"input_tokens": 8, "output_tokens": 4, "calls": 1}},
        ]

        # Stub the agent loop: echo the prior verdict (corroborate), with usage.
        def _fake_loop(finding, result, *a, **k):
            return {"verdict": result["verdict"], "evidence": "second look agrees",
                    "tool_history": [_ran()],
                    "_usage": {"input_tokens": 2, "output_tokens": 1, "calls": 1}}

        monkeypatch.setattr(reb, "_run_rebuttal_loop", _fake_loop)

        summary = reb.apply_rebuttal_phase(
            results, evidence_index={}, scope_ips=set(), scope_networks=[],
            scope_hosts=set(), config={}, model="claude-sonnet-4-6")

        assert summary == {"rebutted": 2, "flipped": 0, "contested": 0, "corroborated": 2}
        # The unclear result is skipped entirely (no rebuttal block).
        assert "rebuttal" not in results[1]
        # Rebuttal token usage is folded into the matching result's _usage so the
        # module's aggregate totals include the second pass.
        assert results[0]["_usage"] == {"input_tokens": 12, "output_tokens": 6, "calls": 2}
        assert results[2]["_usage"] == {"input_tokens": 10, "output_tokens": 5, "calls": 2}

    def test_phase_counts_flips_and_contests(self, monkeypatch):
        results = [
            {"verdict": "confirmed", "finding": {"target": "1.2.3.4:80"},
             "poc_command": "curl http://x/"},
            {"verdict": "confirmed", "finding": {"target": "1.2.3.4:81"}},
        ]

        def _fake_loop(finding, result, *a, **k):
            # First finding: overturn with an executed step. Second: contest.
            if result["finding"]["target"].endswith(":80"):
                return {"verdict": "refuted", "evidence": "default page",
                        "tool_history": [_ran("200 nginx welcome")]}
            return {"verdict": "unclear", "evidence": "inconclusive",
                    "tool_history": []}

        monkeypatch.setattr(reb, "_run_rebuttal_loop", _fake_loop)

        summary = reb.apply_rebuttal_phase(
            results, evidence_index={}, scope_ips=set(), scope_networks=[],
            scope_hosts=set(), config={}, model="claude-sonnet-4-6")

        assert summary["rebutted"] == 2
        assert summary["flipped"] == 1
        assert summary["contested"] == 1
        assert results[0]["verdict"] == "refuted"
        assert results[1]["verdict"] == "confirmed"
