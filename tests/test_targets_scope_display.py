"""The targets view shows an IP's in_scope as host-authorization, not the raw
structural flag.

A name-derived IP (resolved from a -d/-url host) is kept in the ledger's
in-scope set so its HOSTNAME gets scanned (name-safe), but it is never
port-scanned as a bare IP. So the targets view must present it as NOT in-scope
(scope_class name-safe) — only IPs authorized at -t level (channel 't') show
in_scope. Names keep their raw name-safe in-scope (a subdomain IS scanned by
name). This is display-only: the underlying in-scope set / scanning is unchanged.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import scan_db
import webserver   # imports fine without fastapi (that is lazy in serve())


def test_name_safe_ip_shown_out_of_scope(tmp_path):
    db = scan_db.open_db(str(tmp_path))
    db.upsert_target(target="198.18.4.154", target_type="ip", scope="explicit",
                     in_scope=True, channel="t")          # -t IP -> host-full
    db.upsert_target(target="198.18.10.9", target_type="ip", scope="derived",
                     in_scope=True, channel="dl")         # -d-derived -> name-safe
    db.upsert_target(target="10.0.0.5", target_type="ip", scope="derived",
                     in_scope=True, channel="ul")         # -url-derived -> name-safe
    db.upsert_target(target="api.example.com", target_type="subdomain",
                     scope="derived", in_scope=True, channel="dl")
    rows = {r["target"]: r for r in webserver._query_targets(db._conn)}
    db.close()

    assert rows["198.18.4.154"]["in_scope"] == 1          # -t IP stays in-scope
    assert rows["198.18.4.154"]["scope_class"] == "host-full"
    assert rows["198.18.10.9"]["in_scope"] == 0            # -d-derived IP -> out
    assert rows["198.18.10.9"]["scope_class"] == "name-safe"
    assert rows["10.0.0.5"]["in_scope"] == 0              # -url-derived IP -> out
    # The subdomain is still in-scope (scanned by its name).
    assert rows["api.example.com"]["in_scope"] == 1


def test_excluded_host_full_ip_stays_out(tmp_path):
    # A host-full (-t) IP that was excluded stays out — the display override only
    # forces name-safe IPs out, it never promotes an excluded one in.
    db = scan_db.open_db(str(tmp_path))
    db.upsert_target(target="1.2.3.4", target_type="ip", scope="excluded",
                     in_scope=False, channel="t")
    rows = {r["target"]: r for r in webserver._query_targets(db._conn)}
    db.close()
    assert rows["1.2.3.4"]["in_scope"] == 0
