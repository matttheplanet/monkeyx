# Corpus case: m365-external-false-positives

`ai_analyze` recommendations validated by `ai_validate` against an M365 / CDN-heavy
attack surface. Derived from a real external engagement, then **anonymized** — hostnames
and IPs are replaced with `example.*` / RFC 5737 documentation addresses while the
evidence shape (certs, banners, error pages) is preserved so the case still exercises
the validator faithfully.

## Why this case exists

Every labeled item is a **false positive a good validator must refute** — a service
misidentification or CDN/edge artifact that a naive validator would confirm on a weak signal:

- an nmap **services-db port label** (`oracleas-https` on 7443) mistaken for a real product,
- a **CDN/edge cert + generic error page** (Salesforce edge, Cloudflare challenge, UltraDNS
  redirector) mistaken for an exposed admin panel / ADFS / WebLogic,
- a **clean TLS config** mistaken for a weak-cipher downgrade,
- an **M365 cloud SMTP endpoint** mistaken for an on-prem Exchange open relay.

This exercises the precision axis: does the agent knock down plausible-but-wrong findings
instead of confirming them?

## Ground truth is independent of the agent's own verdict

Labels in `ground_truth.json` were assigned by reading each transcript's **raw evidence**
(certs, response bodies, testssl output) and deciding the *correct* answer — NOT by copying
what the agent concluded. If ground truth were a copy of the prediction, scoring would be
circular and measure nothing. (It happens the agent got these 7 right, so the produced fixture
scores 7/7 — that's a regression guard, not a tautology.)

## Layout

```
ground_truth.json                 # 7 labeled items (all refuted) — read by the harness
unlabeled_staging.json            # 6 inconclusive items for operator review (NOT read by harness)
produced/validated-findings.json  # the ai_validate output for this run, anonymized (the fixture scored)
```

## The 6 staged items — need your call

The same run produced 6 `unclear` results (agent hit `MAX_ATTEMPTS_PER_FINDING`, or was
scope-blocked from a DNS lookup). Their *correct* verdict is a security judgment call, so they
are staged in `unlabeled_staging.json` rather than guessed. Notable: the
`referral.example.com` DMARC item is very likely **confirmed** — the deterministic `dns_security`
module recorded `dmarc_missing` as HIGH, but `ai_validate` couldn't prove it because scope
blocked the `_dmarc` lookup. That's a valuable case (deterministic module succeeded where the
agent could not). Decide each, then move it into `ground_truth.json`'s `expected` array.

## Scoring

```bash
python3 -c "from core.eval_harness import score_case; \
  print(score_case('tests/corpus/m365-external-false-positives', \
  'tests/corpus/m365-external-false-positives/produced/validated-findings.json').as_dict())"
```

Current: 7/7 correct, 7 true-negatives (no confirmed cases yet — precision/recall are trivially
1.0 until a confirmed case is added — a genuine weak-crypto or exposed-service finding is
good confirmable material).
