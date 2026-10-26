"""Tests for --no-subdomain-enum (warn-and-skip enum modules)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from monkeyx import _filter_subdomain_enum
from workflows import ModuleStep, ParallelGroup


def _names(items):
    out = []
    for i in items:
        if isinstance(i, ModuleStep):
            out.append(i.name)
        elif isinstance(i, ParallelGroup):
            out.extend(s.name for s in i.steps)
        elif isinstance(i, str):
            out.append(i)
    return out


def test_removes_enum_modules_sequential():
    items = [ModuleStep(name="subfinder"), ModuleStep(name="dnsx_resolve"),
             ModuleStep(name="ax_nuclei")]
    filtered, skipped = _filter_subdomain_enum(items)
    assert "subfinder" in skipped
    assert "subfinder" not in _names(filtered)
    # non-enum name modules survive
    assert "dnsx_resolve" in _names(filtered)
    assert "ax_nuclei" in _names(filtered)


def test_removes_enum_from_parallel_group():
    items = [ParallelGroup(steps=[ModuleStep(name="ax_subfinder"),
                                   ModuleStep(name="bbot_passive"),
                                   ModuleStep(name="dns_security")])]
    filtered, skipped = _filter_subdomain_enum(items)
    assert set(skipped) == {"ax_subfinder", "bbot_passive"}
    # dns_security (name-class, non-enum) survives in the group
    assert _names(filtered) == ["dns_security"]


def test_all_enum_parallel_group_dropped():
    items = [ParallelGroup(steps=[ModuleStep(name="ax_subfinder"),
                                   ModuleStep(name="ax_amass")]),
             ModuleStep(name="ax_nuclei")]
    filtered, skipped = _filter_subdomain_enum(items)
    assert set(skipped) == {"ax_subfinder", "ax_amass"}
    assert _names(filtered) == ["ax_nuclei"]


def test_string_items_supported():
    items = ["subfinder", "ax_nuclei"]
    filtered, skipped = _filter_subdomain_enum(items)
    assert skipped == ["subfinder"]
    assert filtered == ["ax_nuclei"]


def test_puredns_bruteforce_is_enum():
    items = [ModuleStep(name="ax_puredns_bruteforce")]
    filtered, skipped = _filter_subdomain_enum(items)
    assert skipped == ["ax_puredns_bruteforce"]
    assert filtered == []


def test_no_enum_modules_is_noop():
    items = [ModuleStep(name="ax_nuclei"), ModuleStep(name="dnsx_resolve")]
    filtered, skipped = _filter_subdomain_enum(items)
    assert skipped == []
    assert _names(filtered) == ["ax_nuclei", "dnsx_resolve"]
