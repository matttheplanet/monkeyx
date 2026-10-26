"""Stage C: TargetLedger.load_from_db() rebuilds in-memory state from scan.db.

The linchpin test: a ledger rebuilt from the DB must match one rebuilt from the
same run's JSONL (load_from_disk) across every in-memory structure — including
multi-parent (get_ip_to_hostnames) and ports. Plus the clean-break guard: a DB
with no ledger_authoritative marker refuses to load.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.target_ledger import (
    TargetLedger, RunPredatesDbMigration,
    TYPE_IP, TYPE_DOMAIN, TYPE_SUBDOMAIN, TYPE_URL,
)
from core import scan_db


def _seed_a_run(output_dir):
    """Populate a ledger via live writes (JSONL + DB dual-write), like a real run.

    Chain: example.com (explicit) -> a/b.example.com (subdomains) ->
    198.18.10.10 (IP resolved from BOTH a and b -> multi-parent) -> a URL + ports.
    Returns the live ledger's state snapshot BEFORE close (the ground truth the
    run actually held in memory).
    """
    led = TargetLedger(output_dir)
    led._explicit_domains.add("example.com")
    led._add_to_all("example.com", TYPE_DOMAIN)
    led._add_to_in_scope("example.com", TYPE_DOMAIN)
    # Persist the explicit root itself as a target row.
    led._write_entry({"target": "example.com", "type": TYPE_DOMAIN,
                      "source": "user_input", "scope": "explicit",
                      "discovered_at": scan_db._iso_now(), "parent": None})
    led.log_discovery("a.example.com", TYPE_SUBDOMAIN, "subfinder", parent="example.com")
    led.log_discovery("b.example.com", TYPE_SUBDOMAIN, "subfinder", parent="example.com")
    led.log_discovery("198.18.10.10", TYPE_IP, "dns_resolve", parent="a.example.com")
    led.log_discovery("198.18.10.10", TYPE_IP, "dns_resolve", parent="b.example.com")
    led.log_discovery("https://a.example.com/admin", TYPE_URL, "nmap",
                      parent="a.example.com")
    led.log_port("198.18.10.10", 443, "tcp", "ax_nmap_tcp", service="https",
                 product="nginx", version="1.24", tunnel="ssl", reason="syn-ack")
    led.log_mx_domain("example.com", ["mx1.example.net"])
    led.sync_scope_to_db()   # stamps the authoritative marker
    live = _state(led)
    led.close()
    return live


def _state(led):
    """Snapshot the in-memory structures we care about, as comparable values."""
    return {
        "all_ips": set(led._all_ips),
        "all_urls": set(led._all_urls),
        "all_domains": set(led._all_domains),
        "in_scope_ips": set(led._in_scope_ips),
        "in_scope_urls": set(led._in_scope_urls),
        "in_scope_domains": set(led._in_scope_domains),
        "explicit_domains": set(led._explicit_domains),
        "parents": {k: set(v) for k, v in led._parents_by_target.items()},
        "ports": {h: {k: dict(v) for k, v in ports.items()}
                  for h, ports in led._ports.items()},
        "mx": dict(led._mx_domains),
        "ip_to_hostnames": led.get_ip_to_hostnames(),
    }


class TestLoadFromDbEquivalence:
    def test_matches_live_run_state(self, tmp_path):
        # load_from_db must reproduce the LIVE run's in-memory state exactly.
        # (We compare against the live state, not a load_from_disk reload, because
        # the JSONL is actually LOSSIER for multi-parent — see the next test.)
        run = str(tmp_path / "r"); os.makedirs(run)
        live = _seed_a_run(run)

        from_db = TargetLedger(run)
        from_db.load_from_db()
        loaded = _state(from_db)
        for key in live:
            assert loaded[key] == live[key], \
                f"mismatch in {key}: {loaded[key]!r} != {live[key]!r}"
        from_db.close()

    def test_load_from_disk_recovers_multiparent_from_db(self, tmp_path):
        # Regression (Fix #2): the JSONL keeps only the FIRST parent — a
        # re-discovery with a new parent early-returns in log_discovery before
        # writing a 2nd JSONL line. load_from_disk must merge the FULL parent set
        # back from scan.db so a JSONL reload is no longer lossy, and so the
        # end-of-load sync_scope_to_db DELETE-insert writes the union back rather
        # than clobbering scan.db down to the single reloaded parent.
        # Separate dirs so the two loaders don't share a scan.db.
        run_disk = str(tmp_path / "disk"); os.makedirs(run_disk)
        run_db = str(tmp_path / "db"); os.makedirs(run_db)
        _seed_a_run(run_disk)
        _seed_a_run(run_db)

        from_disk = TargetLedger(run_disk)
        from_disk.load_from_disk()
        from_db = TargetLedger(run_db)
        from_db.load_from_db()

        disk_parents = set(from_disk.get_ip_to_hostnames().get("198.18.10.10", []))
        db_parents = set(from_db.get_ip_to_hostnames().get("198.18.10.10", []))
        assert db_parents == {"a.example.com", "b.example.com"}
        # Fixed: load_from_disk now recovers BOTH parents from scan.db.
        assert disk_parents == {"a.example.com", "b.example.com"}
        from_disk.close(); from_db.close()

    def test_load_from_disk_syncs_full_parent_set_back_to_db(self, tmp_path):
        # Regression (Fix #2), the clobber half: load_from_disk ends by calling
        # sync_scope_to_db, which DELETE-inserts target_parents. If the merge
        # above hadn't run, that write would shrink scan.db to the single JSONL
        # parent. Assert the round-trip PRESERVES both parents on disk.
        run = str(tmp_path / "r"); os.makedirs(run)
        _seed_a_run(run)

        reloaded = TargetLedger(run)
        reloaded.load_from_disk()   # merges from DB, then syncs the union back
        reloaded.close()

        # Re-open scan.db directly and confirm both parents persisted.
        db = scan_db.open_db(run)
        rows = [r for r in db.iter_target_parents()
                if r["target"] == "198.18.10.10"]
        assert {r["parent"] for r in rows} == {"a.example.com", "b.example.com"}
        db.close()

    def test_multi_parent_survives_db_load(self, tmp_path):
        run = str(tmp_path / "r"); os.makedirs(run)
        _seed_a_run(run)
        led = TargetLedger(run)
        led.load_from_db()
        # The IP resolved from two hostnames must map back to BOTH.
        assert set(led.get_ip_to_hostnames().get("198.18.10.10", [])) == {
            "a.example.com", "b.example.com"}
        led.close()

    def test_ports_and_widened_fields_survive(self, tmp_path):
        run = str(tmp_path / "r"); os.makedirs(run)
        _seed_a_run(run)
        led = TargetLedger(run)
        led.load_from_db()
        info = led._ports["198.18.10.10"][(443, "tcp")]
        assert info["service"] == "https" and info["product"] == "nginx"
        assert info["tunnel"] == "ssl" and info["reason"] == "syn-ack"
        led.close()


class TestCrashRecoveryScopeFixpoint:
    """A SIGKILL before the run's sync_scope_to_db can leave a derived child's
    persisted in_scope stale-False (it was mirrored before its parent was
    granted scope). load_from_db re-resolves scope when the prior run didn't end
    cleanly, and trusts the flags when it did.
    """

    def _corrupt_child_scope(self, run):
        # Flip the subdomain child's persisted in_scope to a stale False, as a
        # crash mid-fixpoint would leave it.
        db = scan_db.open_db(run)
        db._conn.execute(
            "UPDATE targets SET in_scope=0 WHERE target=? AND target_type=?",
            ("a.example.com", TYPE_SUBDOMAIN))
        db._conn.commit()
        return db

    def test_dirty_shutdown_reresolves_stale_child_scope(self, tmp_path):
        run = str(tmp_path / "r"); os.makedirs(run)
        _seed_a_run(run)                    # correct, authoritative DB
        db = self._corrupt_child_scope(run)
        db.mark_run_dirty()                 # simulate crash: no clean shutdown
        db.close()

        led = TargetLedger(run)
        led.load_from_db()
        # The fixpoint promoted the stale child back into scope...
        assert "a.example.com" in led._in_scope_domains
        led.mark_clean_shutdown()           # a clean end now persists the heal
        led.close()

        # ...and re-persisted it, so a subsequent clean load trusts the flag.
        led2 = TargetLedger(run)
        led2.load_from_db()
        assert "a.example.com" in led2._in_scope_domains
        led2.close()

    def test_clean_shutdown_trusts_persisted_flags(self, tmp_path):
        # Fast path: a clean prior run is trusted verbatim — no fixpoint runs, so
        # a (deliberately wrong) persisted flag is left as-is. This is what makes
        # the clean path O(n) instead of O(n^2).
        run = str(tmp_path / "r"); os.makedirs(run)
        _seed_a_run(run)
        db = self._corrupt_child_scope(run)
        db.mark_run_clean()                 # claim a clean shutdown
        db.close()

        led = TargetLedger(run)
        led.load_from_db()
        assert "a.example.com" not in led._in_scope_domains
        led.close()

    def test_absent_marker_reresolves(self, tmp_path):
        # A pre-marker authoritative DB (clean_shutdown never written) is treated
        # as unclean and re-resolved — the safe default.
        run = str(tmp_path / "r"); os.makedirs(run)
        _seed_a_run(run)                    # never sets clean_shutdown
        db = self._corrupt_child_scope(run)
        db.close()

        led = TargetLedger(run)
        assert led._db.was_clean_shutdown() is False
        led.load_from_db()
        assert "a.example.com" in led._in_scope_domains
        led.close()


class TestCleanBreakGuard:
    def test_unmarked_db_raises(self, tmp_path):
        run = str(tmp_path / "r"); os.makedirs(run)
        # Create a scan.db but never stamp the authoritative marker.
        db = scan_db.open_db(run)
        db.upsert_target(target="1.1.1.1", target_type="ip", scope="derived")
        db.close()
        led = TargetLedger(run)
        with pytest.raises(RunPredatesDbMigration):
            led.load_from_db()
        led.close()

    def test_no_db_raises(self, tmp_path):
        # A ledger with no output_dir has no DB at all.
        led = TargetLedger("")
        with pytest.raises(RunPredatesDbMigration):
            led.load_from_db()
