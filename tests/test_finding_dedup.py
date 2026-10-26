"""IP↔hostname finding dedup for presentation (weburls dual-emit).

The same finding minted on a bare IP and on a hostname that resolves to it must
collapse to ONE presented finding — hostname primary, IP alongside — without
touching scan.db and without merging distinct vhosts on a shared IP.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.scan_db import (dedup_ip_hostname_findings, host_ip_maps_from_parents,
                          ScanDB)


def _f(host, claim="cve-x", port=6379, proto="tcp", sev="high"):
    return {"host": host, "claim": claim, "port": port, "proto": proto,
            "severity": sev, "title": claim}


def test_dual_emit_collapses_hostname_primary():
    rows = [_f("198.18.7.111"), _f("example.com")]
    out = dedup_ip_hostname_findings(rows, {"example.com": "198.18.7.111"})
    assert len(out) == 1
    assert out[0]["host"] == "example.com"          # hostname primary
    assert out[0]["ip"] == "198.18.7.111"          # IP alongside


def test_shared_ip_distinct_vhosts_kept():
    rows = [_f("10.0.0.1"), _f("a.example.com"), _f("b.example.com")]
    m = {"a.example.com": "10.0.0.1", "b.example.com": "10.0.0.1"}
    out = dedup_ip_hostname_findings(rows, m)
    hosts = sorted(r["host"] for r in out)
    assert hosts == ["a.example.com", "b.example.com"]   # both vhosts kept, IP dropped
    assert all(r["ip"] == "10.0.0.1" for r in out)


def test_ip_only_finding_kept():
    rows = [_f("203.0.113.9")]
    out = dedup_ip_hostname_findings(rows, {})
    assert len(out) == 1 and out[0]["host"] == "203.0.113.9" and out[0]["ip"] == "203.0.113.9"


def test_different_claim_or_port_not_merged():
    rows = [_f("1.2.3.4", claim="a"), _f("h.tld", claim="b"),
            _f("1.2.3.4", port=80), _f("h.tld", port=443)]
    out = dedup_ip_hostname_findings(rows, {"h.tld": "1.2.3.4"})
    assert len(out) == 4                              # nothing shares (claim,port,proto)


def test_map_from_target_parents(tmp_path):
    db = ScanDB(str(tmp_path))
    # dnsx re-logs an IP with each resolved hostname as a parent (this is the
    # row shape the map reads); a file-path/URL parent must be ignored.
    db._conn.executemany(
        "INSERT INTO target_parents (target, target_type, parent) VALUES (?,?,?)",
        [("198.18.7.111", "ip", "example.com"),
         ("198.18.7.111", "ip", "data/ledger/ledger-targets.txt"),  # noise
         ("example.com", "subdomain", "example.net")])                  # not ip-target
    db._conn.commit()
    h2i, i2h = host_ip_maps_from_parents(db._conn)
    db.close()
    assert h2i.get("example.com") == "198.18.7.111"
    assert "example.com" in i2h.get("198.18.7.111", set())
    assert "example.net" not in h2i                       # subdomain-target row ignored
