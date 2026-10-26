"""Evaluation harness for the AI analysis/validation modules.

Purpose: turn "we think this change helps" into "we measured it." Without a
labeled corpus, every ai_analyze / ai_validate change is faith-based. This
provides the scoring half; tests/corpus/ provides labeled fixtures.

Design constraints:
- Pure/offline. No API key, no network — it scores ALREADY-PRODUCED module
  output against ground truth, so it runs in CI.
- The expensive step (actually running ai_analyze/ai_validate against a target
  to produce that output) happens separately, out of band, by an operator with
  credentials. The harness just reads the resulting JSON.

A corpus case is a directory:
    case/
      ground_truth.json          # labels (see schema below)
      data/<prefix>-*-normalized.jsonl   # scan snapshot to feed the modules (optional here)

ground_truth.json:
    {
      "name": "expired-cert-behind-cdn",
      "description": "...",
      "expected": [
        {"host": "1.2.3.4", "port": 443, "claim": "expired_cert", "verdict": "confirmed"},
        {"host": "1.2.3.4", "port": 80,  "claim": "default_creds", "verdict": "refuted"}
      ]
    }

Each expected item is keyed by (host, port, claim). `verdict` is the correct
answer a good validator should reach: "confirmed" (truly exploitable/present) or
"refuted" (a false positive that should be knocked down). "unclear" is allowed
as a label for genuinely ambiguous cases.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


VALID_VERDICTS = {"confirmed", "refuted", "unclear"}


@dataclass
class ScoreResult:
    """Confusion-matrix-style score of predicted verdicts vs. ground truth."""
    total_expected: int = 0
    matched: int = 0            # expected items a prediction was found for
    correct: int = 0           # matched AND verdict agrees
    # Confusion for the binary "is this a real, confirmable finding?" question:
    true_positive: int = 0     # gt=confirmed, pred=confirmed
    false_positive: int = 0    # gt=refuted,  pred=confirmed  (validator failed to knock it down)
    true_negative: int = 0     # gt=refuted,  pred=refuted
    false_negative: int = 0    # gt=confirmed, pred!=confirmed (validator missed a real one)
    missing: list = field(default_factory=list)   # expected items with no prediction
    detail: list = field(default_factory=list)     # per-item outcome for reporting

    @property
    def precision(self) -> float:
        denom = self.true_positive + self.false_positive
        return self.true_positive / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.true_positive + self.false_negative
        return self.true_positive / denom if denom else 1.0

    @property
    def accuracy(self) -> float:
        return self.correct / self.total_expected if self.total_expected else 1.0

    def as_dict(self) -> dict:
        return {
            "total_expected": self.total_expected,
            "matched": self.matched,
            "correct": self.correct,
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "accuracy": round(self.accuracy, 3),
            "missing": self.missing,
            "detail": self.detail,
        }


def _norm_host(v) -> str:
    return str(v or "").lower().rstrip(".")


_RANK = {"confirmed": 3, "refuted": 2, "unclear": 1, "error": 0}


def _pred_hostport(finding: dict) -> tuple:
    """(host, port) from a validated-findings finding target."""
    # Deferred import so the harness has no hard dependency on the module.
    from modules.ai_validate import _extract_host, _extract_port
    target = finding.get("target", "")
    return (_norm_host(_extract_host(target)), _extract_port(target))


# Back-compat alias: earlier callers/tests imported _pred_key for the (host,port) key.
_pred_key = _pred_hostport


def index_predictions(validated_findings: list) -> dict:
    """Index predictions for scoring, by two keys of increasing precision.

    Returns {"by_claim": {(host,port,claim): verdict},
             "by_hostport": {(host,port): verdict}}.

    ``by_hostport`` is the legacy view: when several findings collapse to one
    (host, port), the most severe verdict wins (confirmed > refuted > unclear)
    so a confirmation isn't hidden behind an 'unclear'. ``by_claim`` is only
    populated for findings that carry an explicit ``claim`` — it lets score()
    distinguish two findings on the same host:port with opposite verdicts, which
    the host:port key alone silently merges. Findings without a claim contribute
    only to ``by_hostport`` (so real runs that don't emit a claim behave exactly
    as before).
    """
    by_claim: dict[tuple, str] = {}
    by_hostport: dict[tuple, str] = {}
    for item in validated_findings or []:
        if not isinstance(item, dict):
            continue
        finding = item.get("finding") or {}
        hp = _pred_hostport(finding)
        verdict = (item.get("verdict") or "unclear").lower()
        if verdict not in VALID_VERDICTS:
            verdict = "unclear"
        if hp not in by_hostport or _RANK.get(verdict, 0) > _RANK.get(by_hostport[hp], 0):
            by_hostport[hp] = verdict
        claim = finding.get("claim")
        if claim:
            ck = (hp[0], hp[1], str(claim).lower())
            if ck not in by_claim or _RANK.get(verdict, 0) > _RANK.get(by_claim[ck], 0):
                by_claim[ck] = verdict
    return {"by_claim": by_claim, "by_hostport": by_hostport}


def score(ground_truth: dict, validated_findings: list) -> ScoreResult:
    """Score predicted verdicts against a ground_truth spec.

    Matching prefers the precise (host, port, claim) key when the produced run
    carries a claim for that exact triple; otherwise it falls back to the legacy
    (host, port) key. This lets a case with two findings on one host:port and
    opposite verdicts be scored correctly, while runs that emit no claim (or
    whose claim slug differs from the label) score exactly as before.
    """
    preds = index_predictions(validated_findings)
    by_claim = preds["by_claim"]
    by_hostport = preds["by_hostport"]
    res = ScoreResult()

    for exp in ground_truth.get("expected", []):
        res.total_expected += 1
        host = _norm_host(exp.get("host"))
        port = exp.get("port")
        gt = (exp.get("verdict") or "").lower()
        claim = exp.get("claim", "?")

        claim_key = (host, port, str(claim).lower())
        if claim_key in by_claim:
            pred = by_claim[claim_key]
        else:
            pred = by_hostport.get((host, port))
        if pred is None:
            res.missing.append({"host": host, "port": port, "claim": claim, "expected": gt})
            if gt == "confirmed":
                res.false_negative += 1  # a real finding we produced no verdict for
            res.detail.append({"host": host, "port": port, "claim": claim,
                               "expected": gt, "predicted": None, "correct": False})
            continue

        res.matched += 1
        correct = (pred == gt)
        if correct:
            res.correct += 1
        # binary confusion on "confirmed vs not"
        if gt == "confirmed" and pred == "confirmed":
            res.true_positive += 1
        elif gt == "refuted" and pred == "confirmed":
            res.false_positive += 1
        elif gt == "refuted" and pred == "refuted":
            res.true_negative += 1
        elif gt == "confirmed" and pred != "confirmed":
            res.false_negative += 1
        res.detail.append({"host": host, "port": port, "claim": claim,
                           "expected": gt, "predicted": pred, "correct": correct})

    return res


def load_ground_truth(case_dir: str) -> dict:
    with open(os.path.join(case_dir, "ground_truth.json"), encoding="utf-8") as f:
        return json.load(f)


def load_validated_findings(path: str) -> list:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else []


def score_case(case_dir: str, validated_findings_path: str) -> ScoreResult:
    """Convenience: load a case's ground truth + a produced validated-findings
    file and score them together."""
    return score(load_ground_truth(case_dir), load_validated_findings(validated_findings_path))
