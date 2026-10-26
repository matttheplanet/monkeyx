"""Tests for the AI-module evaluation harness + the first corpus case.

These run offline (no API key/network): they score PRE-PRODUCED validated-
findings JSON against a labeled corpus case, proving the scorer works and
catches the failure mode we care about (a validator that confirms on a weak
signal like a CDN-fronted login panel).
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.eval_harness import score, score_case, load_ground_truth, index_predictions

_CASE = os.path.join(os.path.dirname(__file__), "corpus", "cdn-and-origin")
_M365_CASE = os.path.join(os.path.dirname(__file__), "corpus", "m365-external-false-positives")


def test_good_run_scores_perfect():
    """The illustrative 'good' run confirms the expired cert and refutes the
    CDN panel — matching ground truth exactly."""
    produced = os.path.join(_CASE, "expected", "validated-findings.example.json")
    res = score_case(_CASE, produced)
    assert res.total_expected == 2
    assert res.correct == 2
    assert res.accuracy == 1.0
    assert res.precision == 1.0        # no false confirmations
    assert res.recall == 1.0           # caught the real finding
    assert res.false_positive == 0
    assert res.false_negative == 0


def test_false_positive_is_penalized():
    """A validator that wrongly CONFIRMS the CDN admin panel (should be refuted)
    must show up as a false positive with reduced precision."""
    gt = load_ground_truth(_CASE)
    bad_run = [
        {"verdict": "confirmed", "finding": {"target": "198.18.10.10:443", "action": "TLS expired"}},
        {"verdict": "confirmed", "finding": {"target": "198.18.10.11:443", "action": "panel default creds"}},
    ]
    res = score(gt, bad_run)
    assert res.true_positive == 1
    assert res.false_positive == 1     # the CDN panel wrongly confirmed
    assert res.precision == 0.5
    assert res.recall == 1.0           # still found the real one


def test_missed_finding_is_false_negative():
    """A validator that produces no verdict for the real finding scores a
    false negative (recall drop)."""
    gt = load_ground_truth(_CASE)
    partial_run = [
        {"verdict": "refuted", "finding": {"target": "198.18.10.11:443", "action": "panel"}},
    ]
    res = score(gt, partial_run)
    assert res.false_negative == 1     # expired cert never addressed
    assert res.recall == 0.0
    assert {"host": "198.18.10.10", "port": 443, "claim": "expired_tls_cert",
            "expected": "confirmed"} in res.missing


def test_index_predictions_prefers_confirmed():
    """When multiple findings map to one (host, port), confirmed outranks unclear."""
    preds = index_predictions([
        {"verdict": "unclear", "finding": {"target": "1.2.3.4:443"}},
        {"verdict": "confirmed", "finding": {"target": "1.2.3.4:443"}},
    ])
    assert preds["by_hostport"][("1.2.3.4", 443)] == "confirmed"


def test_index_predictions_by_claim_keeps_distinct_verdicts():
    """Two findings on the same host:port with claims keep separate verdicts,
    where the legacy host:port index would merge them into one."""
    preds = index_predictions([
        {"verdict": "confirmed",
         "finding": {"target": "1.2.3.4:443", "claim": "expired_tls_cert"}},
        {"verdict": "refuted",
         "finding": {"target": "1.2.3.4:443", "claim": "admin_panel_default_creds"}},
    ])
    assert preds["by_claim"][("1.2.3.4", 443, "expired_tls_cert")] == "confirmed"
    assert preds["by_claim"][("1.2.3.4", 443, "admin_panel_default_creds")] == "refuted"
    # The legacy view merges them to the most-severe verdict.
    assert preds["by_hostport"][("1.2.3.4", 443)] == "confirmed"


def test_claim_key_distinguishes_same_hostport_opposite_verdicts():
    """Two findings on ONE host:port, opposite verdicts. With claims carried on
    both the labels and the predictions, each is scored on its own — the
    host:port-only key would merge them and mis-score at least one."""
    gt = {
        "expected": [
            {"host": "5.5.5.5", "port": 443, "claim": "expired_tls_cert",
             "verdict": "confirmed"},
            {"host": "5.5.5.5", "port": 443, "claim": "admin_panel_default_creds",
             "verdict": "refuted"},
        ]
    }
    produced = [
        {"verdict": "confirmed",
         "finding": {"target": "5.5.5.5:443", "claim": "expired_tls_cert"}},
        {"verdict": "refuted",
         "finding": {"target": "5.5.5.5:443", "claim": "admin_panel_default_creds"}},
    ]
    res = score(gt, produced)
    assert res.total_expected == 2
    assert res.correct == 2                # both scored on their own claim
    assert res.true_positive == 1          # expired cert confirmed
    assert res.true_negative == 1          # panel correctly refuted
    assert res.false_positive == 0         # NOT merged into a spurious confirm
    assert res.precision == 1.0


def test_legacy_no_claim_still_scores_by_hostport():
    """A produced run with no claim field falls back to (host, port) matching,
    scoring exactly as before the claim key existed."""
    gt = load_ground_truth(_CASE)
    legacy_run = [
        {"verdict": "confirmed", "finding": {"target": "198.18.10.10:443"}},
        {"verdict": "refuted", "finding": {"target": "198.18.10.11:443"}},
    ]
    res = score(gt, legacy_run)
    assert res.correct == 2
    assert res.precision == 1.0
    assert res.recall == 1.0


def test_ground_truth_wellformed():
    """Guard the corpus itself: labels use valid verdicts and required keys."""
    gt = load_ground_truth(_CASE)
    assert gt["expected"]
    for exp in gt["expected"]:
        assert exp["verdict"] in ("confirmed", "refuted", "unclear")
        assert "host" in exp and "claim" in exp


def test_m365_case_wellformed():
    """The m365 false-positive case is well-formed."""
    gt = load_ground_truth(_M365_CASE)
    assert gt["expected"]
    for exp in gt["expected"]:
        assert exp["verdict"] in ("confirmed", "refuted", "unclear")
        assert "host" in exp and "claim" in exp


def test_m365_produced_run_scores_against_labels():
    """The real ai_validate output for this run correctly refutes every labeled
    false positive (7/7). This is a regression guard: if a future change makes the
    validator start CONFIRMING these CDN/misidentification artifacts, precision
    drops and this test fails."""
    produced = os.path.join(_M365_CASE, "produced", "validated-findings.json")
    res = score_case(_M365_CASE, produced)
    assert res.total_expected == 7
    assert res.correct == 7
    assert res.false_positive == 0      # no CDN/edge artifact wrongly confirmed
    assert res.true_negative == 7
