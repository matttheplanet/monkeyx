"""Tests for core/scan_db.py — the per-engagement SQLite store.

Covers the invariants the migration depends on: schema/migration idempotency
(so --continue/--resume can reopen the same file), finding_id stability and
normalization (so normalize and ai_validate mint the same id from the same
finding), upsert-on-continue NOT clobbering triage state, ports last-write-wins,
and the module_runs cumulative semantics.
"""

import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import scan_db


class TestFindingId:
    def test_stable_and_normalized(self):
        # Trailing dot + case must not change the id.
        a = scan_db.finding_id("EXAMPLE.com.", 443, "TCP", "tls-version")
        b = scan_db.finding_id("example.com", 443, "tcp", "tls-version")
        assert a == b
        assert len(a) == 12 and all(c in "0123456789abcdef" for c in a)

    def test_recipe_matches_sha1(self):
        import hashlib
        expected = hashlib.sha1(b"example.com|443|tcp|CVE-2019-9874").hexdigest()[:12]
        assert scan_db.finding_id("example.com", 443, "tcp", "CVE-2019-9874") == expected

    def test_none_port_and_proto(self):
        # None port -> "", None proto -> "" : still deterministic, distinct from 0.
        import hashlib
        expected = hashlib.sha1(b"host.tld|||dmarc_missing").hexdigest()[:12]
        assert scan_db.finding_id("host.tld", None, None, "dmarc_missing") == expected

    def test_claim_distinguishes_same_host_port(self):
        one = scan_db.finding_id("h", 443, "tcp", "cve-a")
        two = scan_db.finding_id("h", 443, "tcp", "cve-b")
        assert one != two

    def test_norm_host_matches_eval_harness(self):
        from core.eval_harness import _norm_host
        for v in ("HOST.", "Host.Example.COM.", "", None):
            assert scan_db.norm_host(v) == _norm_host(v)


class TestEngagementIdentity:
    """meta.engagement_uuid is DB-level and stable — the key a future rollup
    joins on. It must survive a reopen (--continue/--resume mints a new run_id
    but the DB keeps its original id)."""

    def test_generates_uuid_when_none_supplied(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        u = db.stamp_identity(engagement_uuid=None, output_prefix="run-a")
        assert u and db.get_meta("engagement_uuid") == u
        assert db.get_meta("created_at")            # stamped
        assert db.get_meta("output_prefix") == "run-a"
        db.close()

    def test_uuid_is_first_wins_across_reopen(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        u1 = db.stamp_identity(engagement_uuid=None)
        created = db.get_meta("created_at")
        db.close()
        # Reopen and supply a DIFFERENT id (simulates the API's new per-run id
        # on --continue) — the original must be preserved.
        db = scan_db.open_db(str(tmp_path))
        u2 = db.stamp_identity(engagement_uuid="different-run-id", output_prefix="run-b")
        assert u2 == u1
        assert db.get_meta("created_at") == created          # not re-stamped
        assert db.get_meta("output_prefix") == "run-b"        # prefix DOES refresh
        db.close()

    def test_injected_id_is_used_on_fresh_db(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        u = db.stamp_identity(engagement_uuid="api-run-id-123")
        assert u == "api-run-id-123"
        db.close()


class TestModuleCoverage:
    """module_coverage: append-only 'module was fed these targets', with
    run_seq history so a --continue re-run adds a batch rather than overwriting."""

    def test_records_rows_and_skips_blanks(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        n = db.record_coverage(module="ax_nuclei", targets=["a", "  ", "b", ""],
                               target_type="url", run_seq=1, step_index=2)
        assert n == 2  # blanks skipped
        rows = db._conn.execute(
            "SELECT module, target, target_type, run_seq, status FROM module_coverage "
            "ORDER BY target").fetchall()
        assert [r["target"] for r in rows] == ["a", "b"]
        assert rows[0]["status"] == "fed" and rows[0]["run_seq"] == 1
        db.close()

    def test_history_preserved_across_run_seq(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        db.record_coverage(module="m", targets=["x"], target_type="target", run_seq=1)
        db.record_coverage(module="m", targets=["x"], target_type="target", run_seq=2)
        rows = db._conn.execute(
            "SELECT run_seq FROM module_coverage WHERE target='x' ORDER BY run_seq"
        ).fetchall()
        assert [r["run_seq"] for r in rows] == [1, 2]  # both runs kept
        db.close()

    def test_empty_targets_is_noop(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        assert db.record_coverage(module="m", targets=[], target_type="target") == 0
        assert db.record_coverage(module="m", targets=None, target_type="target") == 0
        db.close()

    def test_current_run_seq_does_not_allocate(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        assert db.current_run_seq() == 0        # nothing allocated yet
        assert db.next_run_seq() == 1           # tracker allocates
        assert db.current_run_seq() == 1        # read, unchanged
        assert db.current_run_seq() == 1        # still 1 (no increment)
        db.close()

    def _statuses(self, db, module):
        return {r["target"]: r["status"] for r in db._conn.execute(
            "SELECT target, status FROM module_coverage WHERE module=?", (module,))}

    def test_reconcile_marks_reached_and_no_response(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        db.record_coverage(module="m", targets=["a", "b", "c"], target_type="url",
                           run_seq=1, step_index=5)
        n = db.reconcile_coverage(module="m", run_seq=1, step_index=5, reached=["a", "b"])
        assert n == 3
        s = self._statuses(db, "m")
        assert s == {"a": "reached", "b": "reached", "c": "no_response"}
        db.close()

    def test_reconcile_all_failed(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        db.record_coverage(module="m", targets=["a", "b"], target_type="target",
                           run_seq=1, step_index=2)
        db.reconcile_coverage(module="m", run_seq=1, step_index=2, all_failed=True)
        assert set(self._statuses(db, "m").values()) == {"step_failed"}
        db.close()

    def test_reconcile_is_idempotent_and_scoped(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        # two runs of the same module; reconcile only run 1
        db.record_coverage(module="m", targets=["a"], target_type="url", run_seq=1, step_index=5)
        db.record_coverage(module="m", targets=["a"], target_type="url", run_seq=2, step_index=5)
        db.reconcile_coverage(module="m", run_seq=1, step_index=5, reached=["a"])
        # re-reconcile run 1: nothing left in 'fed' -> 0 rows touched
        assert db.reconcile_coverage(module="m", run_seq=1, step_index=5, reached=["a"]) == 0
        # run 2 untouched (still fed)
        run2 = db._conn.execute(
            "SELECT status FROM module_coverage WHERE run_seq=2").fetchone()["status"]
        assert run2 == "fed"
        db.close()


class TestSchema:
    def test_creates_file_and_tables(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        assert db is not None
        assert os.path.exists(scan_db.db_path_for(str(tmp_path)))
        conn = sqlite3.connect(db.path)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"findings", "validations", "targets", "ports", "mx_domains",
                "progress_events", "module_runs", "meta",
                "target_parents", "web_endpoints"} <= tables
        db.close()

    def test_reopen_is_idempotent(self, tmp_path):
        db1 = scan_db.open_db(str(tmp_path))
        db1.upsert_finding(finding_id="abc", host="h", port=1, proto="tcp",
                           claim="c", tool="nuclei")
        db1.close()
        # Reopen the same dir — must not error and must preserve rows.
        db2 = scan_db.open_db(str(tmp_path))
        assert db2.get_finding("abc") is not None
        db2.close()

    def test_open_db_none_for_empty_dir(self):
        assert scan_db.open_db("") is None

    def test_close_checkpoints_wal_so_db_is_self_contained(self, tmp_path):
        # After close(), all committed data must live in scan.db itself — a
        # consumer opening it WITHOUT the -wal sidecar (e.g. from a results zip)
        # must still see everything.
        db = scan_db.open_db(str(tmp_path))
        db.upsert_finding(finding_id="z", host="h", port=1, proto="tcp",
                          claim="c", tool="nuclei", severity="high")
        db.close()

        path = scan_db.db_path_for(str(tmp_path))
        wal = path + "-wal"
        # TRUNCATE checkpoint empties the WAL (file may remain but is 0 bytes).
        assert not os.path.exists(wal) or os.path.getsize(wal) == 0

        # Open in isolation (no reliance on sidecars) and confirm the row is there.
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT severity FROM findings WHERE finding_id='z'").fetchone()
        assert row is not None and row["severity"] == "high"
        conn.close()

    def test_migration_adds_missing_column(self, tmp_path, monkeypatch):
        # Simulate a real forward migration: a full v1 DB written by today's
        # code, then a future release adds a column via _ADDED_COLUMNS. Reopening
        # the old file must ALTER it in and preserve existing rows.
        db1 = scan_db.open_db(str(tmp_path))
        db1.upsert_finding(finding_id="old", host="h", port=1, proto="tcp",
                           claim="c", tool="nuclei", severity="high")
        db1.close()

        monkeypatch.setattr(scan_db, "_ADDED_COLUMNS",
                            (("findings", "extra_note", "TEXT"),))
        db = scan_db.open_db(str(tmp_path))
        cols = {r["name"] for r in db._conn.execute("PRAGMA table_info(findings)")}
        assert "extra_note" in cols
        # Existing row survives the migration with its data intact.
        row = db.get_finding("old")
        assert row is not None and row["severity"] == "high"
        # Idempotent: reopening again with the column present is a no-op.
        db.close()
        db2 = scan_db.open_db(str(tmp_path))
        assert "extra_note" in {
            r["name"] for r in db2._conn.execute("PRAGMA table_info(findings)")}
        db2.close()


class TestUpsertFinding:
    def test_continue_does_not_clobber_triage(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        db.upsert_finding(finding_id="f1", host="h", port=443, proto="tcp",
                          claim="cve-x", tool="nuclei", severity="high",
                          title="orig")
        # An operator/agent sets state.
        db.set_verdict("f1", "confirmed")
        db._conn.execute("UPDATE findings SET triage_status='triaged', "
                         "false_positive=1, notes='checked' WHERE finding_id='f1'")
        db._conn.commit()

        # A --continue re-normalize re-inserts the same finding with richer detail.
        db.upsert_finding(finding_id="f1", host="h", port=443, proto="tcp",
                          claim="cve-x", tool="nuclei", severity="critical",
                          title="updated", detail="new evidence")

        row = db.get_finding("f1")
        # Triage state preserved...
        assert row["verdict"] == "confirmed"
        assert row["triage_status"] == "triaged"
        assert row["false_positive"] == 1
        assert row["notes"] == "checked"
        # ...evidence fields refreshed.
        assert row["severity"] == "critical"
        assert row["title"] == "updated"
        assert row["detail"] == "new evidence"
        db.close()

    def test_first_seen_stays_last_seen_moves(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        db.upsert_finding(finding_id="f", host="h", port=1, proto="tcp",
                          claim="c", tool="nuclei", now="2026-01-01T00:00:00+00:00")
        db.upsert_finding(finding_id="f", host="h", port=1, proto="tcp",
                          claim="c", tool="nuclei", now="2026-02-02T00:00:00+00:00")
        row = db.get_finding("f")
        assert row["first_seen"] == "2026-01-01T00:00:00+00:00"
        assert row["last_seen"] == "2026-02-02T00:00:00+00:00"
        db.close()

    def test_host_stored_normalized(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        db.upsert_finding(finding_id="f", host="HOST.EXAMPLE.com.", port=1,
                          proto="tcp", claim="c", tool="nuclei")
        assert db.get_finding("f")["host"] == "host.example.com"
        db.close()


class TestPorts:
    def test_last_write_wins_only_overwrites_nonempty(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        db.upsert_port(host="h", port=443, proto="tcp")  # bare
        db.upsert_port(host="h", port=443, proto="tcp", product="nginx",
                       version="1.24")
        # A later bare re-scan must NOT blank out the enriched fields.
        db.upsert_port(host="h", port=443, proto="tcp")
        row = db._conn.execute(
            "SELECT * FROM ports WHERE host='h' AND port=443 AND proto='tcp'"
        ).fetchone()
        assert row["product"] == "nginx"
        assert row["version"] == "1.24"
        db.close()


class TestValidations:
    def test_record_with_and_without_finding_id(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        # A non-NULL finding_id must reference a real findings row (FK enforced),
        # which is exactly the exact-join contract: normalize mints it first.
        db.upsert_finding(finding_id="f1", host="h", port=443, proto="tcp",
                          claim="c", tool="nuclei")
        db.record_validation(finding_id="f1", host="h", port=443,
                             verdict="confirmed", evidence="ev")
        # The ambiguous case: no join -> NULL finding_id is allowed.
        db.record_validation(finding_id=None, host="h", port=8443,
                             verdict="unclear", action="test something")
        rows = db._conn.execute(
            "SELECT finding_id, verdict FROM validations ORDER BY id").fetchall()
        assert rows[0]["finding_id"] == "f1" and rows[0]["verdict"] == "confirmed"
        assert rows[1]["finding_id"] is None and rows[1]["verdict"] == "unclear"
        db.close()

    def test_orphan_finding_id_rejected(self, tmp_path):
        # FK guards against a validation pointing at a non-existent finding.
        db = scan_db.open_db(str(tmp_path))
        import pytest
        with pytest.raises(sqlite3.IntegrityError):
            db.record_validation(finding_id="does-not-exist", host="h", port=1,
                                 verdict="confirmed")
        db.close()

    def test_set_port_verdict_lands_on_port(self, tmp_path):
        # A port-scoped recommendation verdict (no exact finding) surfaces on the
        # ports row, mirroring findings.verdict.
        db = scan_db.open_db(str(tmp_path))
        db.upsert_port(host="H.TLD", port=587, proto="tcp", service="smtp")
        n = db.set_port_verdict(host="h.tld", port=587, proto="tcp",
                                verdict="refuted", evidence="O365 cloud, not on-prem")
        assert n == 1
        row = db._conn.execute(
            "SELECT verdict, verdict_evidence FROM ports "
            "WHERE host='h.tld' AND port=587 AND proto='tcp'").fetchone()
        assert row["verdict"] == "refuted"
        assert "O365" in row["verdict_evidence"]
        # record_validation persists proto for the ports join.
        db.record_validation(finding_id=None, host="h.tld", port=587, proto="tcp",
                             verdict="refuted", action="Test Exchange SMTP")
        v = db._conn.execute("SELECT host, port, proto, verdict FROM validations").fetchone()
        assert (v["host"], v["port"], v["proto"], v["verdict"]) == ("h.tld", 587, "tcp", "refuted")
        db.close()

    def test_set_port_verdict_missing_port_updates_nothing(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        assert db.set_port_verdict(host="nope", port=1, proto="tcp",
                                   verdict="unclear") == 0
        db.close()

    def test_findings_at_host_port(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        db.upsert_finding(finding_id="a", host="h", port=443, proto="tcp",
                          claim="c1", tool="nuclei")
        db.upsert_finding(finding_id="b", host="h", port=443, proto="tcp",
                          claim="c2", tool="nuclei")
        db.upsert_finding(finding_id="c", host="h", port=80, proto="tcp",
                          claim="c3", tool="nuclei")
        assert {r["finding_id"] for r in db.findings_at("h", 443)} == {"a", "b"}
        assert {r["finding_id"] for r in db.findings_at("h", 80)} == {"c"}
        db.close()


class TestModuleRuns:
    def test_cumulative_count_and_latest_status(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        db.bump_module_run("ax_nuclei", "success", "2026-01-01T10:00:00+00:00")
        db.bump_module_run("ax_nuclei", "success", "2026-03-03T10:00:00+00:00")
        # An out-of-order (earlier) event must not overwrite the latest status.
        db.bump_module_run("ax_nuclei", "failed", "2026-02-02T10:00:00+00:00")
        row = db._conn.execute(
            "SELECT * FROM module_runs WHERE module='ax_nuclei'").fetchone()
        assert row["runs"] == 3
        assert row["last_run"] == "2026-03-03T10:00:00+00:00"
        assert row["last_status"] == "success"
        db.close()


class TestTargets:
    def test_upsert_and_in_scope_set(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        db.upsert_target(target="1.2.3.4", target_type="ip", scope="explicit",
                         in_scope=True)
        db.upsert_target(target="9.9.9.9", target_type="ip", scope="derived",
                         in_scope=False)
        assert db.in_scope_targets() == {"1.2.3.4"}
        # Flipping in_scope to True is authoritative on re-upsert.
        db.upsert_target(target="9.9.9.9", target_type="ip", in_scope=True)
        assert db.in_scope_targets() == {"1.2.3.4", "9.9.9.9"}
        db.close()

    def test_channel_persisted_and_coalesced(self, tmp_path):
        # v7: the authorization channel is stored on the target row and, like
        # scope, COALESCEd on re-upsert so a later channel-less write can't null
        # it (the viewer's access column reads this).
        db = scan_db.open_db(str(tmp_path))
        db.upsert_target(target="1.2.3.4", target_type="ip", scope="explicit",
                         in_scope=True, channel="t")
        row = db._conn.execute(
            "SELECT channel FROM targets WHERE target='1.2.3.4'").fetchone()
        assert row["channel"] == "t"
        # A re-upsert with no channel preserves the recorded value.
        db.upsert_target(target="1.2.3.4", target_type="ip", in_scope=True)
        row = db._conn.execute(
            "SELECT channel FROM targets WHERE target='1.2.3.4'").fetchone()
        assert row["channel"] == "t"
        db.close()

    def test_channel_column_migrates_onto_pre_v7_db(self, tmp_path):
        # A targets table created before the channel column existed must gain it
        # on reopen, with existing rows preserved and channel NULL until rewritten.
        import sqlite3
        path = scan_db.db_path_for(str(tmp_path))
        conn = sqlite3.connect(path)
        conn.execute(
            "CREATE TABLE targets (target TEXT, target_type TEXT, source TEXT, "
            "scope TEXT, in_scope INTEGER NOT NULL DEFAULT 0, parent TEXT, "
            "discovered_at TEXT, PRIMARY KEY (target, target_type))")
        conn.execute(
            "INSERT INTO targets (target, target_type, in_scope) VALUES "
            "('1.2.3.4', 'ip', 1)")
        conn.commit()
        conn.close()

        db = scan_db.open_db(str(tmp_path))
        cols = {r["name"] for r in db._conn.execute("PRAGMA table_info(targets)")}
        assert "channel" in cols
        row = db._conn.execute(
            "SELECT in_scope, channel FROM targets WHERE target='1.2.3.4'").fetchone()
        assert row["in_scope"] == 1 and row["channel"] is None
        db.close()


class TestSchemaV2:
    """Stage A: schema v2 additive changes — new tables, widened columns,
    v1->v2 self-heal, meta version bump, and the authoritative marker."""

    def test_schema_version_current(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        assert scan_db.SCHEMA_VERSION == 9
        assert db.get_meta("schema_version") == "9"
        db.close()

    def test_target_parents_replace_semantics(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        db.replace_target_parents("10.0.0.5", "ip", {"a.example.com", "b.example.com"})
        rows = {r["parent"] for r in db.iter_target_parents()}
        assert rows == {"a.example.com", "b.example.com"}
        # Replace with a new set — old parents are gone, new ones present.
        db.replace_target_parents("10.0.0.5", "ip", {"c.example.com"})
        rows = {r["parent"] for r in db.iter_target_parents()}
        assert rows == {"c.example.com"}
        # Empty/None parents are skipped.
        db.replace_target_parents("10.0.0.5", "ip", {"", None, "d.example.com"})
        rows = {r["parent"] for r in db.iter_target_parents()}
        assert rows == {"d.example.com"}
        db.close()

    def test_web_endpoint_upsert_and_nonempty_overwrite(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        db.upsert_web_endpoint(host="h.tld", url="https://h.tld/", port=443,
                               scheme="https", status_code=200, webserver="nginx",
                               tech='["nginx"]', cdn=True)
        # A later bare re-scan must not blank enriched fields.
        db.upsert_web_endpoint(host="h.tld", url="https://h.tld/")
        row = db._conn.execute(
            "SELECT * FROM web_endpoints WHERE url='https://h.tld/'").fetchone()
        assert row["webserver"] == "nginx"
        assert row["status_code"] == 200
        assert row["tech"] == '["nginx"]'
        assert row["cdn"] == 0  # cdn is authoritative (last write = default False)
        db.close()

    def test_widened_ports_round_trip(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        db.upsert_port(host="h", port=443, proto="tcp", service="https",
                       tunnel="ssl", reason="syn-ack", method="probed",
                       confidence="10", extra="TLSv1.3")
        row = db._conn.execute(
            "SELECT * FROM ports WHERE host='h' AND port=443").fetchone()
        assert row["tunnel"] == "ssl" and row["reason"] == "syn-ack"
        assert row["method"] == "probed" and row["confidence"] == "10"
        assert row["extra"] == "TLSv1.3"
        db.close()

    def test_widened_findings_round_trip(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        db.upsert_finding(finding_id="f1", host="h", port=443, proto="tcp",
                          claim="cve-x", tool="nuclei", hostname="h.tld",
                          template="cves/2019/CVE-2019-9874.yaml",
                          description="desc", cwe_id="CWE-502",
                          matcher_name="status")
        row = db.get_finding("f1")
        assert row["hostname"] == "h.tld"
        assert row["template"] == "cves/2019/CVE-2019-9874.yaml"
        assert row["description"] == "desc"
        assert row["cwe_id"] == "CWE-502"
        assert row["matcher_name"] == "status"
        db.close()

    def test_target_discovered_at_keep_earliest(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        db.upsert_target(target="1.1.1.1", target_type="ip", scope="derived",
                         discovered_at="2026-01-01T00:00:00+00:00")
        db.upsert_target(target="1.1.1.1", target_type="ip", scope="derived",
                         discovered_at="2026-02-02T00:00:00+00:00")
        row = db._conn.execute(
            "SELECT discovered_at FROM targets WHERE target='1.1.1.1'").fetchone()
        assert row["discovered_at"] == "2026-01-01T00:00:00+00:00"
        db.close()

    def test_authoritative_marker(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        assert db.is_ledger_authoritative() is False
        db.mark_ledger_authoritative()
        assert db.is_ledger_authoritative() is True
        db.close()
        # Marker persists across reopen.
        db2 = scan_db.open_db(str(tmp_path))
        assert db2.is_ledger_authoritative() is True
        db2.close()

    def test_v1_db_self_heals_to_v2(self, tmp_path):
        # Build a v1-shaped DB by hand (old columns only, no new tables),
        # reopen with v2 code, and confirm ALTERs + tables + version bump.
        path = scan_db.db_path_for(str(tmp_path))
        conn = sqlite3.connect(path)
        # Real v1 findings/ports shapes (the base _DDL indexes host,port and
        # verdict, so a fake v1 must carry those columns too).
        conn.executescript("""
            CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE ports (host TEXT NOT NULL, port INTEGER NOT NULL,
                proto TEXT NOT NULL DEFAULT 'tcp', state TEXT, service TEXT,
                product TEXT, version TEXT, banner TEXT, source TEXT,
                updated_at TEXT, PRIMARY KEY (host, port, proto));
            CREATE TABLE findings (finding_id TEXT PRIMARY KEY, host TEXT NOT NULL,
                port INTEGER, proto TEXT, claim TEXT NOT NULL, tool TEXT NOT NULL,
                type TEXT, severity TEXT, title TEXT, detail TEXT, matched_at TEXT,
                cve_id TEXT, tags TEXT, source_file TEXT, first_seen TEXT,
                last_seen TEXT, verdict TEXT,
                triage_status TEXT NOT NULL DEFAULT 'new',
                false_positive INTEGER NOT NULL DEFAULT 0, notes TEXT);
        """)
        conn.execute("INSERT INTO meta VALUES('schema_version','1')")
        conn.execute("INSERT INTO ports(host,port,proto,service) "
                     "VALUES('h',443,'tcp','https')")
        conn.execute("INSERT INTO findings(finding_id,host,port,proto,claim,tool,severity) "
                     "VALUES('old','h',443,'tcp','c','nuclei','high')")
        conn.commit()
        conn.close()

        db = scan_db.open_db(str(tmp_path))
        # version bumped to current (ON CONFLICT DO UPDATE, not IGNORE)
        assert db.get_meta("schema_version") == "9"
        # new tables created
        tables = {r["name"] for r in db._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"target_parents", "web_endpoints", "module_coverage"} <= tables
        # widened columns ALTERed in
        pcols = {r["name"] for r in db._conn.execute("PRAGMA table_info(ports)")}
        assert {"tunnel", "reason", "method", "confidence", "extra"} <= pcols
        # v4 port-verdict columns self-heal onto an old ports table
        assert {"verdict", "verdict_evidence"} <= pcols
        fcols = {r["name"] for r in db._conn.execute("PRAGMA table_info(findings)")}
        assert {"hostname", "template", "description", "cwe_id", "matcher_name"} <= fcols
        vcols = {r["name"] for r in db._conn.execute("PRAGMA table_info(validations)")}
        assert "proto" in vcols  # v4 validations.proto self-heals
        wcols = {r["name"] for r in db._conn.execute("PRAGMA table_info(web_endpoints)")}
        assert "screenshot" in wcols  # v5 web_endpoints.screenshot self-heals
        # existing rows preserved
        assert db.get_finding("old")["severity"] == "high"
        db.close()


class TestPruneFindingsBySource:
    """prune_findings_by_source keeps re-mints idempotent (ai_analyze_gowitness
    re-run): rows from the given source not re-minted this run are dropped, other
    sources are never touched, and triage on kept rows survives (upsert does)."""

    def _mint(self, db, fid, claim, source, sev="medium"):
        db.upsert_finding(finding_id=fid, host="h", port=443, proto="tcp",
                          claim=claim, tool="gowitness", type="finding",
                          severity=sev, title=claim, detail="d",
                          source_file=source)

    def test_prunes_only_unkept_rows_of_that_source(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        src = "ai-gowitness-analysis.json"
        self._mint(db, "keep1", "gowitness:panel", src)
        self._mint(db, "stale1", "gowitness:old-category", src)   # disappears next run
        # a different source must be untouched
        self._mint(db, "nuclei1", "cve-x", "scan-nuclei.jsonl")
        pruned = db.prune_findings_by_source(src, {"keep1"})
        assert pruned == 1
        assert db.get_finding("keep1") is not None
        assert db.get_finding("stale1") is None
        assert db.get_finding("nuclei1") is not None   # other source untouched
        db.close()

    def test_empty_keep_set_clears_the_source(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        src = "ai-gowitness-analysis.json"
        self._mint(db, "a", "gowitness:a", src)
        self._mint(db, "b", "gowitness:b", src)
        assert db.prune_findings_by_source(src, set()) == 2
        assert db.get_finding("a") is None and db.get_finding("b") is None
        db.close()

    def test_rerun_with_same_keys_no_duplicates(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        src = "ai-gowitness-analysis.json"
        self._mint(db, "f1", "gowitness:panel", src)
        # simulate a re-run: same key re-minted, prune keeps it
        self._mint(db, "f1", "gowitness:panel", src, sev="high")
        db.prune_findings_by_source(src, {"f1"})
        rows = db._conn.execute(
            "SELECT count(*) FROM findings WHERE source_file = ?", (src,)).fetchone()
        assert rows[0] == 1   # no duplicate
        db.close()
