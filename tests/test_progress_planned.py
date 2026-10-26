"""The live Overview should list modules that are queued but not yet started.

ProgressTracker emits a run_planned event with the ordered plan; the webserver
rebuild seeds those as 'pending' and overlays started/completed/failed.
"""

import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import scan_db
from core.progress import ProgressTracker
import webserver


def _progress(tmp_path):
    conn = sqlite3.connect(scan_db.db_path_for(str(tmp_path)))
    conn.row_factory = sqlite3.Row
    try:
        return webserver._step_progress(conn)
    finally:
        conn.close()


def test_planned_but_unstarted_modules_show_pending(tmp_path):
    t = ProgressTracker(str(tmp_path), total_steps=4)
    t.run_planned(["subfinder", ["ax_nuclei", "ax_gowitness"], "normalize"])
    ev = t.step_started("subfinder")
    t.step_completed("subfinder", ev, {"output_files": []})
    t.close()

    steps = _progress(tmp_path)["steps"]
    by = {s["module"]: s["status"] for s in steps}
    assert by.get("subfinder") == "completed"          # ran
    assert by.get("ax_nuclei") == "pending"            # queued
    assert by.get("ax_gowitness") == "pending"
    assert by.get("normalize") == "pending"
    # started steps come first, queued ones after, in plan order.
    assert steps[0]["module"] == "subfinder"
    assert [s["module"] for s in steps if s["status"] == "pending"] == \
        ["ax_nuclei", "ax_gowitness", "normalize"]


def test_pending_do_not_inflate_done_or_current(tmp_path):
    t = ProgressTracker(str(tmp_path), total_steps=4)
    t.run_planned(["subfinder", "ax_nuclei", "ax_gowitness", "normalize"])
    ev = t.step_started("subfinder")
    t.step_completed("subfinder", ev, {"output_files": []})
    t.close()

    prog = _progress(tmp_path)
    assert prog["done"] == 1 and prog["total"] == 4
    # "current" must never be a queued step.
    assert prog["current"]["status"] != "pending"


def test_backward_compatible_without_run_planned(tmp_path):
    # No run_planned event -> only started steps appear (legacy behavior).
    t = ProgressTracker(str(tmp_path), total_steps=3)
    ev = t.step_started("subfinder")
    t.step_completed("subfinder", ev, {"output_files": []})
    t.close()

    steps = _progress(tmp_path)["steps"]
    assert [s["module"] for s in steps] == ["subfinder"]
    assert all(s["status"] != "pending" for s in steps)
