"""Exclusions must survive --continue/--resume without re-passing --exclude.

Regression (review H2): exclusion RULES weren't persisted, only the resulting
scope="excluded" rows. continue/resume rebuild scope via load_from_disk()'s
fixpoint, which with empty exclusions re-admitted previously-excluded targets
and scanned them. Fix: persist the raw rules to scan.db and re-seed them
(seed_persisted_exclusions) BEFORE the fixpoint.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.target_ledger import TargetLedger, TYPE_IP, TYPE_DOMAIN


def test_ip_exclusion_persists_across_continue(tmp_path):
    (tmp_path / "t.txt").write_text("1.2.3.4\n1.2.3.5\n")
    (tmp_path / "excl.txt").write_text("1.2.3.5\n")

    # Run 1 — exclude 1.2.3.5 (persists the rule to scan.db).
    l1 = TargetLedger(str(tmp_path))
    l1.seed_user_inputs(str(tmp_path / "t.txt"), None, None)
    l1.seed_exclusions(str(tmp_path / "excl.txt"))
    assert l1.is_excluded("1.2.3.5", TYPE_IP)
    assert "1.2.3.5" not in l1._in_scope_ips
    assert "1.2.3.4" in l1._in_scope_ips

    # Run 2 — continue WITHOUT re-passing --exclude: a fresh ledger on the same
    # scan.db must reload the rule and keep 1.2.3.5 out of scope.
    l2 = TargetLedger(str(tmp_path))
    assert l2.seed_persisted_exclusions() >= 1          # reloaded from scan.db
    l2.load_from_disk()
    assert l2.is_excluded("1.2.3.5", TYPE_IP)
    assert "1.2.3.5" not in l2._in_scope_ips            # did NOT re-enter scope
    assert "1.2.3.4" in l2._in_scope_ips                # the rest still in-scope


def test_all_rule_kinds_round_trip(tmp_path):
    (tmp_path / "excl.txt").write_text(
        "10.0.0.0/24\n"               # CIDR
        "9.9.9.9\n"                   # bare IP
        "legacy.example.com\n"        # domain (+ subdomains)
        "*.staging.example.com\n"     # wildcard (subdomains only)
        "https://x.example.com/admin\n")  # URL (exact)
    l1 = TargetLedger(str(tmp_path))
    l1.seed_exclusions(str(tmp_path / "excl.txt"))

    l2 = TargetLedger(str(tmp_path))
    assert l2.seed_persisted_exclusions() == 5
    assert l2.is_excluded("10.0.0.50", TYPE_IP)                 # inside the CIDR
    assert l2.is_excluded("9.9.9.9", TYPE_IP)
    assert l2.is_excluded("legacy.example.com", TYPE_DOMAIN)
    assert l2.is_excluded("sub.legacy.example.com", TYPE_DOMAIN)
    assert l2.is_excluded("a.staging.example.com", TYPE_DOMAIN)  # wildcard subdomain
    assert not l2.is_excluded("staging.example.com", TYPE_DOMAIN)  # bare domain NOT excluded by *.


def test_no_persisted_exclusions_is_noop(tmp_path):
    # A run that never had exclusions: seed_persisted_exclusions returns 0 and
    # leaves scope untouched.
    (tmp_path / "t.txt").write_text("1.2.3.4\n")
    l1 = TargetLedger(str(tmp_path))
    l1.seed_user_inputs(str(tmp_path / "t.txt"), None, None)
    l2 = TargetLedger(str(tmp_path))
    assert l2.seed_persisted_exclusions() == 0
    l2.load_from_disk()
    assert "1.2.3.4" in l2._in_scope_ips
