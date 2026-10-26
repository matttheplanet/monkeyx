"""Tests for multi-workflow resolution preserving structure and per-step args.

Selecting several workflows must concatenate their rich step lists (parallel
groups + per-step args intact) and dedup across the combined list — rather than
flattening to bare module names (which silently dropped both structure and args,
e.g. standard's ax_masscan ports:all / ax_nmap_tcp ports:open reverting to
the modules' defaults).
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from workflows import (
    get_resolved_workflow_rich,
    get_resolved_workflows_rich,
    WORKFLOWS,
    ModuleStep,
    ParallelGroup,
)


def _find_module_args(steps, name):
    for s in steps:
        if isinstance(s, ParallelGroup):
            r = _find_module_args(s.steps, name)
            if r is not None:
                return r
        elif isinstance(s, ModuleStep) and s.name == name:
            return s.args
    return None


def _flat_names(steps):
    out = []
    for s in steps:
        if isinstance(s, ParallelGroup):
            out.extend(m.name for m in s.steps)
        elif isinstance(s, ModuleStep):
            out.append(s.name)
    return out


def _step_index(steps, name):
    """Index of the step (or the group containing it) that holds `name`."""
    for i, s in enumerate(steps):
        if isinstance(s, ModuleStep) and s.name == name:
            return i
        if isinstance(s, ParallelGroup) and any(m.name == name for m in s.steps):
            return i
    return -1


def test_snmp_sweep_runs_after_udp_scan_not_in_its_group():
    # snmp_sweep needs UDP/161 from ax_nmap_udp; a same-group snmp_sweep snapshots
    # its inputs before the UDP scan populates them and silently no-ops. Guard
    # standard + deep: snmp_sweep must NOT share a parallel group with ax_nmap_udp
    # and must be ordered strictly after it.
    for wf in ("standard", "deep"):
        steps = get_resolved_workflow_rich(wf)
        for s in steps:
            if isinstance(s, ParallelGroup):
                names = {m.name for m in s.steps}
                assert not ({"snmp_sweep", "ax_nmap_udp"} <= names), (
                    f"{wf}: snmp_sweep must not be in the same parallel group as "
                    f"ax_nmap_udp")
        udp_i = _step_index(steps, "ax_nmap_udp")
        snmp_i = _step_index(steps, "snmp_sweep")
        assert udp_i != -1 and snmp_i != -1 and snmp_i > udp_i, (
            f"{wf}: snmp_sweep ({snmp_i}) must come after ax_nmap_udp ({udp_i})")


def test_single_element_list_equals_single_resolver():
    """A one-element list matches the single-workflow resolver output."""
    assert _flat_names(get_resolved_workflows_rich(["standard"])) == \
        _flat_names(get_resolved_workflow_rich("standard"))


def test_combined_preserves_parallel_groups():
    combined = get_resolved_workflows_rich(["standard", "fast"])
    # standard has parallel groups — they must survive concatenation.
    assert any(isinstance(s, ParallelGroup) for s in combined)


def test_combined_preserves_per_step_args():
    """standard sets ax_nmap_tcp ports:open (sweep-then-verify) — that arg must survive."""
    combined = get_resolved_workflows_rich(["standard", "fast"])
    args = _find_module_args(combined, "ax_nmap_tcp")
    assert args is not None
    assert args.get("ports") == "open"


def test_combined_dedups_across_workflows():
    from workflows import _REPEATABLE_STEPS
    combined = get_resolved_workflows_rich(["standard", "standard"])
    names = _flat_names(combined)
    # No NON-repeatable module appears twice even though standard was listed
    # twice. Repeatable modules (normalize) are intentionally exempt from dedup
    # so they can mint scan.db findings at several points in a run.
    non_repeatable = [n for n in names if n not in _REPEATABLE_STEPS]
    assert len(non_repeatable) == len(set(non_repeatable))


def test_normalize_runs_once_at_end():
    # The intermediate (progressive scan.db) normalize passes were dropped — on
    # large data sets re-normalizing mid-run isn't worth the cost. Each built-in
    # workflow now normalizes exactly once, at the end, before the analysis block.
    # normalize stays exempt from dedup (see _REPEATABLE_STEPS) so a user can
    # still add extra passes via -m / a custom workflow.
    from workflows import get_resolved_workflow
    assert get_resolved_workflow("standard").count("normalize") == 1
    assert get_resolved_workflow("deep").count("normalize") == 1
    assert get_resolved_workflow("fast").count("normalize") == 1


def test_order_is_significant():
    a = _flat_names(get_resolved_workflows_rich(["standard", "fast"]))
    b = _flat_names(get_resolved_workflows_rich(["fast", "standard"]))
    # Same module set, but concatenation order differs -> different sequence.
    assert set(a) == set(b)
    assert a != b


def test_empty_list_is_empty():
    assert get_resolved_workflows_rich([]) == []


def test_unknown_workflow_raises_valueerror():
    """The resolver raises on an unknown name (what main() must catch cleanly)."""
    with pytest.raises(ValueError, match="Unknown workflow"):
        get_resolved_workflows_rich(["deeep"])  # typo of 'deep'


def test_workflows_membership_flags_typo_accepts_real():
    """main() gates on `w not in WORKFLOWS` before resolving — verify that check
    catches a typo and accepts the real name, so users get a clean error + list
    instead of a traceback."""
    assert "deeep" not in WORKFLOWS            # the mistyped name
    assert "deep" in WORKFLOWS                 # the real workflow
    # every shipped workflow name is resolvable (guards the list shown to users)
    for name in WORKFLOWS:
        assert get_resolved_workflows_rich([name]) is not None
