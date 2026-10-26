"""Stage 2: TargetLedger dual-writes to scan.db, preserving scope parity.

The critical invariant: the set of targets flagged in_scope=1 in scan.db must
EXACTLY equal the ledger's in-memory in-scope union — including after an
out-of-order-parent load_from_disk (a child written before its parent), which is
the whole reason the load-time fixpoint exists.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.target_ledger import (
    TargetLedger, NO_OP_LEDGER, TYPE_IP, TYPE_DOMAIN, TYPE_SUBDOMAIN, TYPE_URL,
    SCOPE_EXPLICIT,
)
from core import scan_db


def _memory_in_scope(ledger):
    return (ledger._in_scope_ips | ledger._in_scope_domains
            | ledger._in_scope_urls)


def _write(tmp_path, name, lines):
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n")
    return str(p)


class TestLedgerMirror:
    def test_targets_and_ports_mirrored(self, tmp_path):
        led = TargetLedger(str(tmp_path))
        led.seed_user_inputs(None, None, None)  # no-op, just exercises path
        led.log_discovery("1.2.3.4", TYPE_IP, "user_input")  # explicit-ish
        led.log_port("1.2.3.4", 443, "tcp", "ax_nmap_tcp",
                     service="https", product="nginx", version="1.24")

        db = scan_db.open_db(str(tmp_path))
        t = db._conn.execute(
            "SELECT * FROM targets WHERE target='1.2.3.4'").fetchone()
        assert t is not None and t["target_type"] == "ip"
        p = db._conn.execute(
            "SELECT * FROM ports WHERE host='1.2.3.4' AND port=443").fetchone()
        assert p["product"] == "nginx" and p["version"] == "1.24"
        db.close()

    def test_mx_domain_mirrored(self, tmp_path):
        led = TargetLedger(str(tmp_path))
        led.log_mx_domain("example.com", ["mx1.example.net", "mx2.example.net"])
        db = scan_db.open_db(str(tmp_path))
        row = db._conn.execute(
            "SELECT * FROM mx_domains WHERE domain='example.com'").fetchone()
        assert json.loads(row["mx_hosts"]) == ["mx1.example.net", "mx2.example.net"]
        db.close()

    def test_scope_parity_live_run(self, tmp_path):
        # example.com explicit -> api.example.com subdomain -> 10.0.0.5 IP.
        led = TargetLedger(str(tmp_path))
        led._explicit_domains.add("example.com")
        led._add_to_all("example.com", TYPE_DOMAIN)
        led._add_to_in_scope("example.com", TYPE_DOMAIN)
        led.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                          parent="example.com")
        led.log_discovery("198.18.10.10", TYPE_IP, "dns_resolve",
                          parent="api.example.com")
        led.sync_scope_to_db()

        db = scan_db.open_db(str(tmp_path))
        assert db.in_scope_targets() == _memory_in_scope(led)
        db.close()

    def test_internal_only_subdomain_demoted_from_scope(self, tmp_path):
        # A subdomain of an explicit domain that resolves ONLY to a private IP is
        # an internal-only name (split-horizon / internal-DNS leakage), not an
        # external target — it must NOT be in_scope. A sibling resolving to a
        # public IP stays in scope; an unresolved subdomain stays in scope; the
        # explicit domain is never demoted.
        led = TargetLedger(str(tmp_path))
        led._explicit_domains.add("example.com")
        led._add_to_all("example.com", TYPE_DOMAIN)
        led._add_to_in_scope("example.com", TYPE_DOMAIN)
        led.log_discovery("dev-admin.example.com", TYPE_SUBDOMAIN, "subfinder",
                          parent="example.com")
        led.log_discovery("192.168.50.25", TYPE_IP, "dns_resolve",
                          parent="dev-admin.example.com")
        led.log_discovery("fews.example.com", TYPE_SUBDOMAIN, "subfinder",
                          parent="example.com")
        led.log_discovery("198.18.7.111", TYPE_IP, "dns_resolve",
                          parent="fews.example.com")
        led.log_discovery("mail.example.com", TYPE_SUBDOMAIN, "subfinder",
                          parent="example.com")  # unresolved
        led.sync_scope_to_db()

        db = scan_db.open_db(str(tmp_path))
        in_scope = db.in_scope_targets()
        db.close()
        assert "dev-admin.example.com" not in in_scope    # internal-only -> out
        assert "fews.example.com" in in_scope             # public -> in
        assert "mail.example.com" in in_scope             # unresolved -> in
        assert "example.com" in in_scope                  # explicit -> in
        # The private IP itself is also out of scope (the IP-level companion).
        assert "192.168.50.25" not in in_scope

    def test_scope_parity_after_out_of_order_load(self, tmp_path):
        # Hand-write a ledger JSONL where the CHILD appears BEFORE its parent —
        # the exact case a single in-order pass would miss and the fixpoint fixes.
        path = os.path.join(str(tmp_path), "discovery-ledger.jsonl")
        with open(path, "w") as f:
            # child first (its parent hasn't been "seen" yet)
            f.write(json.dumps({"target": "198.18.10.10", "type": "ip",
                                "source": "dns_resolve", "scope": "derived",
                                "parent": "api.example.com"}) + "\n")
            f.write(json.dumps({"target": "api.example.com", "type": "subdomain",
                                "source": "subfinder", "scope": "derived",
                                "parent": "example.com"}) + "\n")
            # explicit root last
            f.write(json.dumps({"target": "example.com", "type": "domain",
                                "source": "user_input", "scope": "explicit",
                                "parent": None}) + "\n")

        led = TargetLedger(str(tmp_path))
        led.load_from_disk()  # runs the fixpoint AND sync_scope_to_db()

        # All three are in-scope via the parent chain despite the file order.
        mem = _memory_in_scope(led)
        assert "example.com" in mem
        assert "api.example.com" in mem
        assert "198.18.10.10" in mem

        # DB parity: the persisted in_scope set equals the in-memory union.
        db = scan_db.open_db(str(tmp_path))
        assert db.in_scope_targets() == mem
        db.close()

    def test_subdomains_persist_as_subdomain_type_not_phantom_domains(self, tmp_path):
        # Regression: _all_domains conflates domains + subdomains, and
        # sync_scope_to_db used to force EVERY member to TYPE_DOMAIN — minting a
        # phantom 'domain' row for each subdomain and double-counting targets.
        led = TargetLedger(str(tmp_path))
        led._explicit_domains.add("example.com")
        led._add_to_all("example.com", TYPE_DOMAIN)
        led._add_to_in_scope("example.com", TYPE_DOMAIN)
        led.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                          parent="example.com")
        led.log_discovery("www.example.com", TYPE_SUBDOMAIN, "subfinder",
                          parent="example.com")
        led.sync_scope_to_db()

        db = scan_db.open_db(str(tmp_path))
        rows = {(r["target"], r["target_type"])
                for r in db._conn.execute("SELECT target, target_type FROM targets")}
        # Each subdomain appears exactly ONCE, as a subdomain — no phantom domain row.
        assert ("api.example.com", TYPE_SUBDOMAIN) in rows
        assert ("www.example.com", TYPE_SUBDOMAIN) in rows
        assert ("api.example.com", TYPE_DOMAIN) not in rows
        assert ("www.example.com", TYPE_DOMAIN) not in rows
        # The real domain persists as a domain.
        assert ("example.com", TYPE_DOMAIN) in rows
        # Total row count == distinct targets (no duplication).
        assert len(rows) == 3
        db.close()

    def test_subdomain_type_survives_db_reload(self, tmp_path):
        # A load_from_db → sync round-trip must not re-conflate subdomains into
        # domains (i.e. _subdomain_targets is repopulated from persisted types).
        led = TargetLedger(str(tmp_path))
        led._explicit_domains.add("example.com")
        led._add_to_all("example.com", TYPE_DOMAIN)
        led._add_to_in_scope("example.com", TYPE_DOMAIN)
        led.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                          parent="example.com")
        led.sync_scope_to_db()
        led.close()

        led2 = TargetLedger(str(tmp_path))
        led2.load_from_db()
        led2.sync_scope_to_db()  # re-assert; must preserve subdomain type
        db = scan_db.open_db(str(tmp_path))
        rows = {(r["target"], r["target_type"])
                for r in db._conn.execute("SELECT target, target_type FROM targets")}
        assert ("api.example.com", TYPE_SUBDOMAIN) in rows
        assert ("api.example.com", TYPE_DOMAIN) not in rows
        db.close()

    def test_noop_ledger_has_sync_and_no_db(self, tmp_path):
        # Contract guard: _NoOpLedger must expose sync_scope_to_db/close and no DB.
        assert hasattr(NO_OP_LEDGER, "sync_scope_to_db")
        assert hasattr(NO_OP_LEDGER, "close")
        NO_OP_LEDGER.sync_scope_to_db()  # no-op, must not raise
        NO_OP_LEDGER.close()             # no-op, must not raise
        assert not os.path.exists(scan_db.db_path_for(str(tmp_path)))

    def test_close_checkpoints_and_is_idempotent(self, tmp_path):
        led = TargetLedger(str(tmp_path))
        led.log_discovery("1.2.3.4", TYPE_IP, "user_input")
        led.close()
        wal = scan_db.db_path_for(str(tmp_path)) + "-wal"
        assert not os.path.exists(wal) or os.path.getsize(wal) == 0
        led.close()  # second close must not raise
        # Row is readable from a fresh handle after checkpoint.
        db = scan_db.open_db(str(tmp_path))
        assert "1.2.3.4" in {r["target"] for r in
                             db._conn.execute("SELECT target FROM targets")}
        db.close()


class TestSyncFidelity:
    """Stage B: sync_scope_to_db persists multi-parent, source, discovered_at,
    excluded scope, and stamps the ledger-authoritative marker."""

    def test_all_parents_persisted(self, tmp_path):
        led = TargetLedger(str(tmp_path))
        led._explicit_domains.add("example.com")
        led._add_to_all("example.com", TYPE_DOMAIN)
        led._add_to_in_scope("example.com", TYPE_DOMAIN)
        # One IP discovered from TWO hostnames -> two parents.
        led.log_discovery("a.example.com", TYPE_SUBDOMAIN, "subfinder", parent="example.com")
        led.log_discovery("b.example.com", TYPE_SUBDOMAIN, "subfinder", parent="example.com")
        led.log_discovery("198.18.10.10", TYPE_IP, "dns_resolve", parent="a.example.com")
        led.log_discovery("198.18.10.10", TYPE_IP, "dns_resolve", parent="b.example.com")
        led.sync_scope_to_db()
        led.close()

        db = scan_db.open_db(str(tmp_path))
        parents = {r["parent"] for r in db.iter_target_parents()
                   if r["target"] == "198.18.10.10"}
        assert parents == {"a.example.com", "b.example.com"}
        db.close()

    def test_source_and_discovered_at_persisted(self, tmp_path):
        led = TargetLedger(str(tmp_path))
        led.log_discovery("9.9.9.9", TYPE_IP, "ax_naabu", parent=None)
        led.sync_scope_to_db()
        led.close()
        db = scan_db.open_db(str(tmp_path))
        row = db._conn.execute(
            "SELECT source, discovered_at FROM targets WHERE target='9.9.9.9'").fetchone()
        assert row["source"] == "ax_naabu"
        assert row["discovered_at"]  # a real ISO timestamp, not null
        db.close()

    def test_excluded_scope_persisted(self, tmp_path, monkeypatch):
        led = TargetLedger(str(tmp_path))
        # Seed an exclusion for a domain, then log it as discovered.
        led._excluded_domains.add("evil.example.com")
        led.log_discovery("evil.example.com", TYPE_DOMAIN, "subfinder")
        led.sync_scope_to_db()
        led.close()
        db = scan_db.open_db(str(tmp_path))
        row = db._conn.execute(
            "SELECT scope, in_scope FROM targets WHERE target='evil.example.com'").fetchone()
        assert row["scope"] == "excluded"
        assert row["in_scope"] == 0
        db.close()

    def test_marker_stamped_after_sync(self, tmp_path):
        led = TargetLedger(str(tmp_path))
        led.log_discovery("1.1.1.1", TYPE_IP, "user_input")
        led.sync_scope_to_db()
        led.close()
        db = scan_db.open_db(str(tmp_path))
        assert db.is_ledger_authoritative() is True
        db.close()

    def test_channel_persisted_and_promotion_reflected(self, tmp_path):
        # A -d name resolving to an IP OUTSIDE any -t range stays name-safe (dl);
        # a -d name resolving INTO a -t range is ownership-promoted to host-full
        # (t). sync_scope_to_db must persist the promotion-aware channel so the
        # viewer's access column matches what actually gets port-scanned.
        led = TargetLedger(str(tmp_path))
        led.seed_user_inputs(
            _write(tmp_path, "t.txt", ["198.18.10.0/24"]),
            _write(tmp_path, "d.txt", ["example.com"]),
            None)
        led.log_discovery("owned.example.com", TYPE_SUBDOMAIN, "subfinder",
                          parent="example.com")
        led.log_discovery("shared.example.com", TYPE_SUBDOMAIN, "subfinder",
                          parent="example.com")
        led.log_discovery("198.18.10.9", TYPE_IP, "dns_resolve",
                          parent="owned.example.com")   # inside -t → promoted
        led.log_discovery("8.8.8.9", TYPE_IP, "dns_resolve",
                          parent="shared.example.com")  # outside -t → name-safe
        led.sync_scope_to_db()
        led.close()

        db = scan_db.open_db(str(tmp_path))
        ch = {r["target"]: r["channel"] for r in
              db._conn.execute("SELECT target, channel FROM targets")}
        db.close()
        assert ch["198.18.10.9"] == "t"       # promoted into -t range
        assert ch["8.8.8.9"] == "dl"     # shared infra, name-safe only
        assert ch["example.com"] == "dl"

    def test_widened_port_fields_persisted(self, tmp_path):
        led = TargetLedger(str(tmp_path))
        led.log_port("1.2.3.4", 443, "tcp", "ax_nmap_tcp", service="https",
                     tunnel="ssl", reason="syn-ack", method="probed",
                     confidence="10", extra="TLSv1.3")
        led.close()
        db = scan_db.open_db(str(tmp_path))
        row = db._conn.execute(
            "SELECT * FROM ports WHERE host='1.2.3.4' AND port=443").fetchone()
        assert row["tunnel"] == "ssl" and row["reason"] == "syn-ack"
        assert row["method"] == "probed" and row["extra"] == "TLSv1.3"
        db.close()
