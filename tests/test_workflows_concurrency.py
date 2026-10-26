"""Regression tests for background-module concurrency safety in run_modules.

The background-module path (_BACKGROUND_MODULES) runs a step in a thread while
the main loop keeps going. Two shared-state hazards were fixed:
  1. results was mutated from the thread while the main loop read results[-1].
     _run_sequential_step now RETURNS its result so callers never fish it out
     of the shared list, and the background thread merges under a lock.
  2. fleet_killed_early used a lock-free check-then-set (double kill_fleet risk).

These tests pin the return contract (1). The lock discipline (2) is a closure
inside run_modules; its atomic-once behavior is covered by the pattern test.
"""

import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import workflows as wf


def test_run_sequential_step_returns_result(monkeypatch):
    """_run_sequential_step must return the module result (not None) so the main
    loop and background thread can read their own result instead of results[-1]."""
    monkeypatch.setattr(
        wf, "run_module",
        lambda name, _dry_run=False, **kw: {"module": name, "status": "success", "output_files": []},
    )
    step = wf.ModuleStep(name="analyze")  # no REQUIRED_INPUTS
    results = []
    ret = wf._run_sequential_step(step, {"prefix": "/tmp/x"}, results,
                                  ledger=wf.NO_OP_LEDGER, data_dir=None, dry_run=True)
    assert isinstance(ret, dict)
    assert ret.get("module") == "analyze"
    # Still appended to the shared list (backward compatible).
    assert results and results[-1] is ret


def test_run_sequential_step_returns_skip_result(monkeypatch):
    """The runtime-input skip path must also return its (skipped) result."""
    # Force a module with a required input that isn't available.
    monkeypatch.setitem(wf.MODULE_REQUIREMENTS, "needs_target_xyz", frozenset({"target"}))
    step = wf.ModuleStep(name="needs_target_xyz")
    results = []
    ret = wf._run_sequential_step(step, {"prefix": "/tmp/x"}, results,
                                  ledger=wf.NO_OP_LEDGER, data_dir=None, dry_run=True)
    assert isinstance(ret, dict)
    assert ret.get("status") == "skipped"
    assert results and results[-1] is ret


def test_parallel_member_exception_is_recorded_failed(monkeypatch):
    """A parallel-group member that RAISES must produce a result with
    status='failed' — otherwise _completion_exit_code counts it as success and the
    run exits 0 with a crashed module (the exit-code-contract bug)."""
    def _run(name, _dry_run=False, **kw):
        if name == "boom":
            raise RuntimeError("tool blew up")
        return {"module": name, "status": "success", "output_files": []}
    monkeypatch.setattr(wf, "run_module", _run)

    group = wf.ParallelGroup(steps=[wf.ModuleStep("analyze"), wf.ModuleStep("boom")])
    results = []
    wf._run_parallel_group(group, {"prefix": "/tmp/x"}, results,
                           ledger=wf.NO_OP_LEDGER, data_dir=None, dry_run=True)
    failed = [r for r in results if r.get("status") == "failed"]
    assert any(r.get("module") == "boom" for r in failed), \
        f"raising member not recorded as failed: {results}"


def test_lock_guarded_appends_lose_nothing():
    """Models the background-thread + main-loop shared-results discipline:
    concurrent extend() under one lock must not drop entries."""
    lock = threading.Lock()
    shared = []

    def worker(n):
        local = [{"i": n}]
        with lock:
            shared.extend(local)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(200)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(shared) == 200
    assert {r["i"] for r in shared} == set(range(200))


def test_atomic_check_and_set_fires_once():
    """Models fleet_killed_early: an atomic check-and-set must fire the action
    exactly once even under many concurrent callers."""
    lock = threading.Lock()
    fired = {"flag": False}
    actions = []

    def kill_once():
        with lock:
            if fired["flag"]:
                return
            fired["flag"] = True
        actions.append(1)

    threads = [threading.Thread(target=kill_once) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(actions) == 1
