"""Ctrl+C during a parallel group must not leave a member marked success.

Workers keep running to completion when the main thread is interrupted, so a
tool that exits 0 on SIGINT (e.g. nuclei via ax) could record
step_completed(success). The group is incomplete and re-runs atomically on
resume, so every member must be overridden to failed.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import workflows
from workflows import ModuleStep, ParallelGroup, NO_OP_LEDGER


class _Tracker:
    """Records the sequence of status events per step."""
    def __init__(self):
        self.events = []  # (name, status)

    def parallel_group_started(self, names):
        return object()

    def parallel_group_completed(self, token):
        pass

    def step_started(self, name, parallel_group=False):
        return object()

    def step_completed(self, name, started, result):
        self.events.append((name, "completed"))

    def step_failed(self, name, started, msg):
        self.events.append((name, "failed"))


def test_interrupted_parallel_group_marks_all_members_failed(monkeypatch):
    tracker = _Tracker()

    # ax_gowitness returns success; ax_nuclei is interrupted (KeyboardInterrupt
    # propagates out of the worker -> future.result() re-raises in the main thread).
    def fake_run_module(name, _dry_run=False, **kwargs):
        if name == "ax_nuclei":
            raise KeyboardInterrupt()
        return {"module": name, "status": "success", "output_files": []}

    monkeypatch.setattr(workflows, "run_module", fake_run_module)
    # Bypass the input-requirement skip so both steps actually run run_module.
    monkeypatch.setattr(workflows, "_check_runtime_inputs", lambda reqs, kw: [])

    group = ParallelGroup(steps=[ModuleStep(name="ax_gowitness"),
                                 ModuleStep(name="ax_nuclei")])

    import pytest
    with pytest.raises(KeyboardInterrupt):
        workflows._run_parallel_group(
            group, {"prefix": "x"}, [], step_index=0, tracker=tracker,
            ledger=NO_OP_LEDGER, scope_filter="none", data_dir=None, dry_run=False)

    # The LAST recorded status for every member must be "failed" — including
    # ax_gowitness, whose worker recorded success before the override.
    last = {}
    for name, status in tracker.events:
        last[name] = status
    assert last.get("ax_gowitness") == "failed"
    assert last.get("ax_nuclei") == "failed"
