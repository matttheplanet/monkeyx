#!/usr/bin/env python3
"""CLI for the AI-module evaluation harness (core/eval_harness.py).

Scores an ai_validate output file against a labeled corpus case and prints
precision / recall / accuracy plus a confusion matrix. Offline — no API key or
network; it only reads already-produced JSON. Producing that JSON (running the
real ai_analyze/ai_validate) is a separate, credentialed step.

Corpus cases live in tests/corpus/<name>/ (a ground_truth.json + a data/ scan
snapshot + an expected/ example run). See docs/AI_SETUP.md → "Evaluating the AI
modules".

Usage:
  # Score a produced validated-findings.json against a named case:
  python3 eval_ai.py --case cdn-and-origin --findings ./run/data/scan-validated-findings.json

  # Point at a case directory directly:
  python3 eval_ai.py --case tests/corpus/cdn-and-origin --findings <file>

  # No --findings: score the case's own expected/ example run (offline sanity check):
  python3 eval_ai.py --case cdn-and-origin

  # Score every corpus case against its expected example (what CI effectively does):
  python3 eval_ai.py --all

  # Machine-readable output:
  python3 eval_ai.py --case cdn-and-origin --json
"""

import argparse
import glob
import json
import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _ROOT)

from core.eval_harness import score_case  # noqa: E402

_CORPUS_DIR = os.path.join(_ROOT, "tests", "corpus")
_EXAMPLE_REL = os.path.join("expected", "validated-findings.example.json")


def _resolve_case_dir(case: str) -> str:
    """Accept a bare case name (cdn-and-origin) or a path to the case dir."""
    if os.path.isdir(case):
        return case
    candidate = os.path.join(_CORPUS_DIR, case)
    if os.path.isdir(candidate):
        return candidate
    sys.exit(f"[!] Case not found: {case} (looked in {_CORPUS_DIR})")


def _default_findings(case_dir: str) -> str:
    """The case's own illustrative 'good' run, used when --findings is omitted."""
    path = os.path.join(case_dir, _EXAMPLE_REL)
    if not os.path.isfile(path):
        sys.exit(f"[!] No --findings given and no example run at {path}")
    return path


def _print_result(name: str, res) -> None:
    d = res.as_dict()
    print(f"\n=== {name} ===")
    print(f"  expected={d['total_expected']}  matched={d['matched']}  correct={d['correct']}")
    print(f"  precision={d['precision']}  recall={d['recall']}  accuracy={d['accuracy']}")
    print(f"  TP={d['true_positive']}  FP={d['false_positive']}  "
          f"TN={d['true_negative']}  FN={d['false_negative']}")
    if d["missing"]:
        print(f"  missing (no verdict produced): {len(d['missing'])}")
        for m in d["missing"]:
            print(f"    - {m['host']}:{m['port']} [{m.get('claim','?')}] expected={m['expected']}")
    wrong = [x for x in d["detail"] if x["predicted"] is not None and not x["correct"]]
    if wrong:
        print(f"  wrong verdicts: {len(wrong)}")
        for x in wrong:
            print(f"    - {x['host']}:{x['port']} [{x.get('claim','?')}] "
                  f"expected={x['expected']} predicted={x['predicted']}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Score ai_validate output against a labeled corpus case.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--case", help="Corpus case name or directory.")
    g.add_argument("--all", action="store_true",
                   help="Score every corpus case against its expected/ example run.")
    ap.add_argument("--findings",
                    help="Produced validated-findings JSON to score (defaults to the "
                         "case's expected/ example run when omitted).")
    ap.add_argument("--json", action="store_true", help="Emit JSON instead of a table.")
    args = ap.parse_args()

    results = {}
    if args.all:
        if args.findings:
            ap.error("--findings cannot be combined with --all")
        cases = sorted(d for d in glob.glob(os.path.join(_CORPUS_DIR, "*"))
                       if os.path.isdir(d))
        if not cases:
            sys.exit(f"[!] No corpus cases found in {_CORPUS_DIR}")
        for case_dir in cases:
            name = os.path.basename(case_dir)
            example = os.path.join(case_dir, _EXAMPLE_REL)
            if not os.path.isfile(example):
                print(f"[*] Skipping {name} (no example run)")
                continue
            results[name] = score_case(case_dir, example)
    else:
        case_dir = _resolve_case_dir(args.case)
        name = os.path.basename(case_dir.rstrip("/"))
        findings = args.findings or _default_findings(case_dir)
        results[name] = score_case(case_dir, findings)

    if args.json:
        print(json.dumps({k: v.as_dict() for k, v in results.items()}, indent=2))
    else:
        for name, res in results.items():
            _print_result(name, res)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
