"""feroxbuster tuning-flag builder — bounds the recursion/runtime so a wildcard
/ soft-404 host can't make feroxbuster run forever. Flags are validated (ints
cast, time_limit format-checked) so nothing shell-unsafe survives.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.ax_feroxbuster import _ferox_flags


def test_defaults_bound_recursion_and_runtime():
    f = _ferox_flags({})
    assert "--depth 2" in f
    assert "--time-limit 15m" in f
    assert "--auto-bail" in f
    # optional caps are off by default
    assert "--scan-limit" not in f and "--threads" not in f and "--rate-limit" not in f


def test_tuning_disabled_emits_nothing():
    assert _ferox_flags({"tuning": False}) == ""


def test_overrides_and_optional_caps():
    f = _ferox_flags({"depth": 3, "time_limit": "2h", "auto_bail": False,
                      "scan_limit": 4, "threads": 20, "rate_limit": 100})
    assert "--depth 3" in f and "--time-limit 2h" in f
    assert "--auto-bail" not in f
    assert "--scan-limit 4" in f and "--threads 20" in f and "--rate-limit 100" in f


def test_invalid_values_fall_back_or_drop():
    # bad depth -> default; bad time_limit -> dropped; shell metachars can't survive
    f = _ferox_flags({"depth": "; rm -rf /", "time_limit": "$(evil)"})
    assert "--depth 2" in f          # non-int depth falls back to default
    assert "--time-limit" not in f   # malformed time_limit is dropped
    assert ";" not in f and "$" not in f and "rm" not in f


def test_depth_zero_omits_flag():
    f = _ferox_flags({"depth": 0})
    assert "--depth" not in f
