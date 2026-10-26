"""A module that fails to import must be surfaced, not silently dropped.

Auto-discovery runs at import time (before the CLI configures logging), so a
broken module that raises on import used to vanish from AVAILABLE_MODULES with no
visible trace: a later request for it looked identical to a typo. We now record
the failure in FAILED_MODULE_IMPORTS and, when the module is requested, tell the
operator it FAILED TO LOAD rather than that it's unknown.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

import workflows


def test_failed_import_gives_distinct_error(monkeypatch):
    # Simulate a module that exists on disk but blew up on import.
    monkeypatch.setitem(workflows.FAILED_MODULE_IMPORTS,
                        "brokenmod", "ImportError: no module named lxml")
    with pytest.raises(ValueError) as exc:
        workflows.run_module("brokenmod")
    msg = str(exc.value)
    assert "FAILED TO LOAD" in msg
    assert "brokenmod" in msg
    # It must NOT be reported as merely unknown.
    assert "Unknown module" not in msg


def test_genuinely_unknown_module_still_unknown():
    with pytest.raises(ValueError) as exc:
        workflows.run_module("definitely_not_a_real_module_xyz")
    assert "Unknown module" in str(exc.value)
