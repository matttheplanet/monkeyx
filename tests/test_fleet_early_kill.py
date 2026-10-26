"""The fleet must be killed as soon as the last fleet-requiring step is done —
BEFORE the trailing local steps (normalize/analyze/ai_*) run — so it doesn't
idle (billing) through them. Regression: the early-kill was gated on `cleanup`,
but every CLI entry point calls run_modules(cleanup=False), so it never fired
and the fleet stayed up for the whole local tail.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import workflows as wf


def _run(tmp_path, monkeypatch, *, cleanup, keep_fleet):
    events = []
    monkeypatch.setattr(wf, "run_module",
                        lambda name, _dry_run=False, **kw: events.append(("run", name))
                        or {"module": name, "status": "success", "output_files": []})
    monkeypatch.setattr(wf, "kill_fleet",
                        lambda name, **k: events.append(("kill", name)) or True)
    # Early-kill refreshes the session via core.fleet.iauth before killing.
    import core.fleet as fleet
    monkeypatch.setattr(fleet, "iauth", lambda account=None: None)

    # ax_httpx needs a fleet; normalize is local (_NO_FLEET_MODULES) and runs after.
    steps = [wf.ModuleStep("ax_httpx"), wf.ModuleStep("normalize")]
    wf.run_modules(steps, cleanup=cleanup, scaler=None,
                   output_dir=str(tmp_path), prefix=str(tmp_path / "run"),
                   fleet="testfleet", keep_fleet=keep_fleet, dry_run=False)
    return events


def test_fleet_killed_before_local_tail_even_with_cleanup_false(tmp_path, monkeypatch):
    events = _run(tmp_path, monkeypatch, cleanup=False, keep_fleet=False)
    assert ("kill", "testfleet") in events, f"fleet never killed early: {events}"
    # The kill must land before normalize (the local tail), not after the run.
    kill_i = events.index(("kill", "testfleet"))
    norm_i = events.index(("run", "normalize"))
    assert kill_i < norm_i, f"fleet not killed before the local tail: {events}"


def test_keep_fleet_suppresses_early_kill(tmp_path, monkeypatch):
    events = _run(tmp_path, monkeypatch, cleanup=False, keep_fleet=True)
    assert not any(e[0] == "kill" for e in events), f"killed despite --keep-fleet: {events}"
