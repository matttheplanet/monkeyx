"""Tests for the verdict guard (_guard_verdict / _verdict_has_executed_evidence).

A finding may only be reported confirmed/refuted from evidence the agent actually
gathered. When every validation step was BLOCKED (out of scope / unsafe) — or no
command ran at all — there is no observation to stand on, so a confirmed/refuted
verdict is downgraded to 'unclear'. This stops "confirmed" resting on a step that
never executed.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules import ai_validate as aiv


def _blocked(reason="out of scope: 8.8.8.8"):
    return {"tool": "nmap_scan", "blocked": True,
            "output_preview": f"BLOCKED: {reason}"}


def _ran(output="220 mail.example.com ESMTP"):
    return {"tool": "netcat_banner", "blocked": False, "output_preview": output}


class TestExecutedEvidence:
    def test_all_blocked_is_no_evidence(self):
        assert aiv._verdict_has_executed_evidence([_blocked(), _blocked()]) is False

    def test_empty_history_is_no_evidence(self):
        assert aiv._verdict_has_executed_evidence([]) is False
        assert aiv._verdict_has_executed_evidence(None) is False

    def test_one_executed_step_is_evidence(self):
        assert aiv._verdict_has_executed_evidence([_blocked(), _ran()]) is True


class TestGuardVerdict:
    def test_confirmed_with_only_blocked_steps_downgraded(self):
        v = {"verdict": "confirmed", "evidence": "SMB signing disabled",
             "poc_command": "nmap --script smb2-security-mode 8.8.8.8"}
        aiv._guard_verdict(v, [_blocked()])
        assert v["verdict"] == "unclear"
        assert "auto-downgraded from confirmed" in v["evidence"]
        assert "blocked" in v["evidence"].lower()
        # The unverified PoC must not travel on a downgraded verdict.
        assert "poc_command" not in v

    def test_refuted_with_only_blocked_steps_downgraded(self):
        v = {"verdict": "refuted", "evidence": "no relay"}
        aiv._guard_verdict(v, [_blocked(), _blocked()])
        assert v["verdict"] == "unclear"
        assert "auto-downgraded from refuted" in v["evidence"]

    def test_confirmed_with_no_steps_downgraded(self):
        v = {"verdict": "confirmed", "evidence": "looks bad"}
        aiv._guard_verdict(v, [])
        assert v["verdict"] == "unclear"
        assert "ran no validation checks" in v["evidence"]

    def test_confirmed_with_executed_step_survives(self):
        v = {"verdict": "confirmed", "evidence": "banner proves it",
             "poc_command": "nc mail 25"}
        aiv._guard_verdict(v, [_blocked(), _ran()])
        assert v["verdict"] == "confirmed"
        assert v["poc_command"] == "nc mail 25"      # untouched

    def test_unclear_verdict_untouched(self):
        v = {"verdict": "unclear", "evidence": "inconclusive"}
        aiv._guard_verdict(v, [_blocked()])
        assert v["verdict"] == "unclear"
        assert v["evidence"] == "inconclusive"       # not rewritten

    def test_model_note_preserved_in_downgrade(self):
        v = {"verdict": "confirmed", "evidence": "the panel is exposed"}
        aiv._guard_verdict(v, [_blocked()])
        assert "Model note: the panel is exposed" in v["evidence"]


class TestResolveMaxAttempts:
    def test_default_and_explicit_int(self):
        assert aiv._resolve_max_attempts(aiv.MAX_ATTEMPTS_PER_FINDING) == 6
        assert aiv._resolve_max_attempts(12) == 12      # honored as-is (operator's cost)
        assert aiv._resolve_max_attempts("20") == 20

    def test_unlimited_maps_to_finite_ceiling(self):
        assert aiv._resolve_max_attempts("unlimited") == aiv._ATTEMPTS_UNLIMITED
        assert aiv._resolve_max_attempts("none") == aiv._ATTEMPTS_UNLIMITED
        assert aiv._resolve_max_attempts(0) == aiv._ATTEMPTS_UNLIMITED
        assert aiv._resolve_max_attempts(-5) == aiv._ATTEMPTS_UNLIMITED

    def test_unparseable_falls_back_to_default(self):
        assert aiv._resolve_max_attempts("lots") == 6
        assert aiv._resolve_max_attempts(None) == 6
