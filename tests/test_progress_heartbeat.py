"""Console heartbeat: ProgressTracker.status_snapshot + HeartbeatPrinter."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.progress import ProgressTracker, HeartbeatPrinter, NO_OP_TRACKER


def test_snapshot_tracks_running_and_completed(tmp_path):
    t = ProgressTracker(str(tmp_path), total_steps=3)
    e1 = t.step_started("ax_nmap_tcp")
    e2 = t.step_started("ax_nuclei")
    elapsed, done, total, running = t.status_snapshot()
    assert total == 3
    assert done == 0
    assert running == ["ax_nmap_tcp", "ax_nuclei"]
    assert elapsed >= 0.0

    t.step_completed("ax_nmap_tcp", e1, {"status": "success"})
    elapsed, done, total, running = t.status_snapshot()
    assert done == 1
    assert running == ["ax_nuclei"]

    t.step_failed("ax_nuclei", e2, "boom")
    _, done, _, running = t.status_snapshot()
    assert done == 2
    assert running == []


def test_snapshot_unknown_completion_does_not_raise(tmp_path):
    # A completion for a step that was never marked running must not blow up.
    t = ProgressTracker(str(tmp_path), total_steps=1)
    t.step_completed("never_started", {"started_at": None}, {})
    _, done, _, running = t.status_snapshot()
    assert done == 1
    assert running == []


def test_noop_tracker_snapshot():
    assert NO_OP_TRACKER.status_snapshot() == (0.0, 0, 0, [])


def test_heartbeat_prints_then_stops(tmp_path, capsys):
    t = ProgressTracker(str(tmp_path), total_steps=2)
    t.step_started("ax_nmap_tcp")
    hb = HeartbeatPrinter(t, interval=0.05)
    hb.start()
    time.sleep(0.2)
    hb.stop()
    out = capsys.readouterr().out
    assert "running: ax_nmap_tcp" in out
    assert "/2 steps done" in out
    # No further output after stop().
    time.sleep(0.15)
    assert capsys.readouterr().out == ""


def test_heartbeat_silent_before_first_interval(tmp_path, capsys):
    # First line only after one full interval — short runs print nothing.
    t = ProgressTracker(str(tmp_path), total_steps=1)
    hb = HeartbeatPrinter(t, interval=10.0)
    hb.start()
    time.sleep(0.05)
    hb.stop()
    assert capsys.readouterr().out == ""
