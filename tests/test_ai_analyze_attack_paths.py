"""ai_analyze report merges the four recommendation buckets into ONE ranked,
de-duplicated 'Attack Paths' playbook — confirmed quick-wins first, then high-
then medium-confidence chains, then detected-unverified, then CVE leads. The
JSON buckets are UNCHANGED (ai_validate/focus still read them); only the report
and the ranking helper are new.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules import ai_analyze as a


_RECS = {
    "quick_wins": [
        {"target": "H1:6379", "action": "Redis unauth",
         "evidence": "nuclei redis-unauth", "commands": ["redis-cli -h H1 info"]},
    ],
    "attack_chains": [
        # same host+action as the quick win -> must dedup to the quick win (tier 0)
        {"target": "H1:6379", "action": "Redis unauth", "confidence": "HIGH",
         "impact": "CRITICAL", "commands": ["a", "b"]},
        {"target": "H2:445", "action": "SMB relay", "confidence": "MEDIUM",
         "impact": "HIGH", "commands": ["s1", "s2", "s3"]},
    ],
    "requires_verification": [
        {"target": "H3:8080", "action": "Jenkins panel", "commands": ["curl H3"]},
    ],
    "cve_research": [
        {"target": "H4:443", "action": "CVE-2021-1", "commands": ["curl H4"]},
    ],
}


def test_merge_ranks_and_dedups():
    paths = a._merge_attack_paths(_RECS)
    # H1 appeared in two buckets -> collapsed to one
    assert len(paths) == 4
    order = [(p["target"], p["_tier"]) for p in paths]
    assert order == [("H1:6379", 0), ("H2:445", 2), ("H3:8080", 3), ("H4:443", 4)]
    # the deduped H1 kept its tier-0 framing (high-confidence lead), not the
    # chain. It must NOT claim exploitation — ai_analyze precedes ai_validate.
    assert paths[0]["_status"].startswith("high-confidence lead")
    assert "exploited" not in paths[0]["_status"] or "not exploited" in paths[0]["_status"]
    # chain is flagged multi-step; a single-command quick-win is not
    assert paths[1]["_multi"] is True
    assert paths[0]["_multi"] is False


def test_merge_empty_is_empty():
    assert a._merge_attack_paths({}) == []
    assert a._merge_attack_paths({"quick_wins": [], "attack_chains": []}) == []


def test_tier_within_chains_splits_by_confidence():
    recs = {"attack_chains": [
        {"target": "A", "action": "x", "confidence": "HIGH", "commands": []},
        {"target": "B", "action": "y", "confidence": "MEDIUM", "commands": []},
    ]}
    paths = a._merge_attack_paths(recs)
    tiers = {p["target"]: p["_tier"] for p in paths}
    assert tiers["A"] == 1 and tiers["B"] == 2   # HIGH ranks above MEDIUM
