# Corpus case: cdn-and-origin

A small labeled evaluation case for the AI analysis/validation modules.

Scenario: two hosts on a public /24 the operator scoped via `-t`.
- `198.18.10.10` — a real origin server: nginx with an **expired TLS cert** on 443
  (a genuine, confirmable finding) and an SSH banner on 22 (info, not a vuln).
- `198.18.10.11` — a host whose 443 is a **CDN edge** fronting a login page. A
  scanner flagged an "admin panel detect" template, but the panel merely EXISTS
  behind auth — it is NOT a confirmable default-creds/bypass finding. A good
  validator should **refute** it rather than confirm on the weak signal.

## Files
- `ground_truth.json` — the correct verdicts a good validator should reach.
- `data/scan-*-normalized.jsonl` — the scan snapshot to feed ai_analyze/ai_validate.
- `expected/validated-findings.example.json` — an ILLUSTRATIVE "good" run output,
  used by the offline harness test (no API key needed). Replace with a real
  ai_validate run to measure the live modules.

## How to use for a real measurement (out of band, needs credentials)
1. Run the pipeline against a target that reproduces this shape (or replay this
   snapshot into an output dir).
2. `ai_validate` produces `<prefix>-validated-findings.json`.
3. Score it: `core/eval_harness.score_case(case_dir, produced_json)`.
4. Compare precision/recall across module changes — a change is an improvement
   only if it holds or raises recall while raising precision (fewer false
   confirmations like the CDN panel).
