"""Tests for core.progress ProgressTracker."""

import json
import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.progress import ProgressTracker, NO_OP_TRACKER
from core import scan_db


def _read_events(path):
    events = []
    with open(path, "r") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


class TestProgressTracker:
    def test_step_started_writes_event(self, tmp_path):
        tracker = ProgressTracker(str(tmp_path), total_steps=3)
        event = tracker.step_started("ax_tcp_baseline")

        assert event["event"] == "step_started"
        assert event["step"] == "ax_tcp_baseline"
        assert event["index"] == 1
        assert event["total_steps"] == 3
        assert "started_at" in event

        events = _read_events(tracker.path)
        assert len(events) == 1
        assert events[0]["step"] == "ax_tcp_baseline"

    def test_step_completed_writes_event(self, tmp_path):
        tracker = ProgressTracker(str(tmp_path), total_steps=2)
        started = tracker.step_started("ax_nuclei")
        tracker.step_completed("ax_nuclei", started, {
            "module": "ax_nuclei",
            "status": "success",
            "output_files": ["/tmp/nuclei.jsonl"],
        })

        events = _read_events(tracker.path)
        assert len(events) == 2
        completed = events[1]
        assert completed["event"] == "step_completed"
        assert completed["step"] == "ax_nuclei"
        assert completed["output_files"] == ["/tmp/nuclei.jsonl"]
        assert completed["duration_seconds"] >= 0

    def test_step_failed_writes_event(self, tmp_path):
        tracker = ProgressTracker(str(tmp_path), total_steps=1)
        started = tracker.step_started("bad_module")
        tracker.step_failed("bad_module", started, "something broke")

        events = _read_events(tracker.path)
        assert len(events) == 2
        failed = events[1]
        assert failed["event"] == "step_failed"
        assert failed["error"] == "something broke"

    def test_parallel_group_events(self, tmp_path):
        tracker = ProgressTracker(str(tmp_path), total_steps=4)
        group = tracker.parallel_group_started(["ax_nuclei", "ax_gowitness"])

        s1 = tracker.step_started("ax_nuclei", parallel_group=True)
        tracker.step_completed("ax_nuclei", s1, {"output_files": []})
        s2 = tracker.step_started("ax_gowitness", parallel_group=True)
        tracker.step_completed("ax_gowitness", s2, {"output_files": []})

        tracker.parallel_group_completed(group)

        events = _read_events(tracker.path)
        assert events[0]["event"] == "parallel_group_started"
        assert events[0]["steps"] == ["ax_nuclei", "ax_gowitness"]
        assert events[-1]["event"] == "parallel_group_completed"
        assert events[1]["parallel_group"] is True

    def test_index_increments(self, tmp_path):
        tracker = ProgressTracker(str(tmp_path), total_steps=3)
        e1 = tracker.step_started("a")
        e2 = tracker.step_started("b")
        e3 = tracker.step_started("c")

        assert e1["index"] == 1
        assert e2["index"] == 2
        assert e3["index"] == 3

    def test_thread_safety(self, tmp_path):
        tracker = ProgressTracker(str(tmp_path), total_steps=10)
        errors = []

        def write_events(name):
            try:
                for _ in range(5):
                    started = tracker.step_started(name, parallel_group=True)
                    tracker.step_completed(name, started, {"output_files": []})
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=write_events, args=(f"mod_{i}",)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        events = _read_events(tracker.path)
        assert len(events) == 40  # 4 threads * 5 iterations * 2 events each
        for e in events:
            json.loads(json.dumps(e))  # all events are valid JSON

    def test_noop_tracker_returns_dict(self):
        event = NO_OP_TRACKER.step_started("test")
        assert isinstance(event, dict)
        assert "started_at" in event

    def test_partial_file_readable(self, tmp_path):
        tracker = ProgressTracker(str(tmp_path), total_steps=2)
        tracker.step_started("a")

        # Append a partial line to simulate crash
        with open(tracker.path, "a") as fh:
            fh.write('{"event": "step_start')

        # Tolerant reader (skips a truncated trailing line from a crash mid-write)
        events = []
        with open(tracker.path, "r") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        assert len(events) == 1  # only the complete line


class TestScanDbMirror:
    """Stage 1: ProgressTracker dual-writes events into scan.db, non-fatally."""

    def _open(self, tmp_path):
        return scan_db.open_db(str(tmp_path))

    def test_events_mirrored_row_count_matches_jsonl(self, tmp_path):
        tracker = ProgressTracker(str(tmp_path), total_steps=2)
        s1 = tracker.step_started("ax_nuclei")
        tracker.step_completed("ax_nuclei", s1, {"status": "success"})
        s2 = tracker.step_started("bad")
        tracker.step_failed("bad", s2, "boom")

        jsonl_lines = _read_events(tracker.path)
        db = self._open(tmp_path)
        rows = db._conn.execute("SELECT COUNT(*) c FROM progress_events").fetchone()
        assert rows["c"] == len(jsonl_lines) == 4
        # Flattened columns are populated and raw round-trips.
        r = db._conn.execute(
            "SELECT * FROM progress_events WHERE event='step_failed'").fetchone()
        assert r["step"] == "bad" and r["error"] == "boom"
        assert json.loads(r["raw"])["event"] == "step_failed"
        db.close()

    def test_module_runs_cumulative_matches_history(self, tmp_path):
        # ax_nuclei succeeds twice, gowitness fails once.
        t = ProgressTracker(str(tmp_path), total_steps=3)
        for _ in range(2):
            s = t.step_started("ax_nuclei")
            t.step_completed("ax_nuclei", s, {"status": "success"})
        s = t.step_started("ax_gowitness")
        t.step_failed("ax_gowitness", s, "no urls")

        db = self._open(tmp_path)
        rows = {r["module"]: r for r in db._conn.execute("SELECT * FROM module_runs")}
        assert rows["ax_nuclei"]["runs"] == 2
        assert rows["ax_nuclei"]["last_status"] == "success"
        assert rows["ax_gowitness"]["runs"] == 1
        assert rows["ax_gowitness"]["last_status"] == "failed"
        db.close()

    def test_parallel_group_events_do_not_create_module_rows(self, tmp_path):
        # parallel_group_* events have no 'step' -> must not spawn module_runs rows.
        t = ProgressTracker(str(tmp_path), total_steps=2)
        g = t.parallel_group_started(["a", "b"])
        t.parallel_group_completed(g)
        db = self._open(tmp_path)
        assert db._conn.execute(
            "SELECT COUNT(*) c FROM module_runs").fetchone()["c"] == 0
        # But the group events themselves are still recorded.
        assert db._conn.execute(
            "SELECT COUNT(*) c FROM progress_events").fetchone()["c"] == 2
        db.close()

    def test_mirror_failure_is_non_fatal(self, tmp_path, monkeypatch):
        t = ProgressTracker(str(tmp_path), total_steps=1)

        def boom(*a, **k):
            raise RuntimeError("db down")

        monkeypatch.setattr(t._db, "record_progress_event", boom)
        # Must not raise; JSONL still written.
        s = t.step_started("x")
        t.step_completed("x", s, {"status": "success"})
        assert len(_read_events(t.path)) == 2


class TestScanDbClose:
    def test_close_checkpoints_wal_and_idempotent(self, tmp_path):
        t = ProgressTracker(str(tmp_path), total_steps=1)
        s = t.step_started("x")
        t.step_completed("x", s, {"status": "success"})
        t.close()
        wal = scan_db.db_path_for(str(tmp_path)) + "-wal"
        assert not os.path.exists(wal) or os.path.getsize(wal) == 0
        t.close()  # idempotent
        # Events survive in the self-contained db.
        db = scan_db.open_db(str(tmp_path))
        assert db._conn.execute(
            "SELECT COUNT(*) c FROM progress_events").fetchone()["c"] == 2
        db.close()

    def test_noop_tracker_close(self):
        NO_OP_TRACKER.close()  # must not raise


class TestFleetScaledEvent:
    def test_fleet_scaled_writes_event_and_mirrors_to_db(self, tmp_path):
        tracker = ProgressTracker(str(tmp_path), total_steps=5)
        tracker.fleet_scaled(from_nodes=2, to_nodes=4, reason="urls grew to 2400",
                             old_fleet="monkeyx-a", new_fleet="monkeyx-b")
        tracker.fleet_scaled(from_nodes=4, to_nodes=1, reason="targets reduced to 5",
                             old_fleet="monkeyx-b", new_fleet="monkeyx-c")
        tracker.close()

        events = [e for e in _read_events(tracker.path) if e["event"] == "fleet_scaled"]
        assert len(events) == 2
        up, down = events
        assert up["direction"] == "up" and up["from_nodes"] == 2 and up["to_nodes"] == 4
        assert up["reason"] == "urls grew to 2400"
        assert up["old_fleet"] == "monkeyx-a" and up["new_fleet"] == "monkeyx-b"
        assert down["direction"] == "down" and down["from_nodes"] == 4 and down["to_nodes"] == 1

        # Mirrored into scan.db progress_events (event name + full JSON in raw).
        import sqlite3
        conn = sqlite3.connect(scan_db.db_path_for(str(tmp_path)))
        rows = conn.execute(
            "SELECT event, raw FROM progress_events WHERE event='fleet_scaled' ORDER BY id"
        ).fetchall()
        conn.close()
        assert len(rows) == 2
        assert '"direction":"up"' in rows[0][1] and '"to_nodes":4' in rows[0][1]

    def test_noop_tracker_fleet_scaled_is_safe(self):
        NO_OP_TRACKER.fleet_scaled(from_nodes=2, to_nodes=4, reason="x",
                                  old_fleet="a", new_fleet="b")  # must not raise
