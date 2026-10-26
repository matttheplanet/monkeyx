"""Verify that public API symbols are importable."""

import pytest


def test_core_imports():
    from core import (
        iauth, initialize_fleet,
        bash_command, validate_file, get_current_date,
    )
    assert callable(iauth)
    assert callable(initialize_fleet)
    assert callable(bash_command)
    assert callable(validate_file)
    assert callable(get_current_date)


def test_workflow_imports():
    from workflows import (
        AVAILABLE_MODULES,
        MODULE_REQUIREMENTS,
        WORKFLOWS,
        run_modules,
        run_workflow,
        get_resolved_workflow,
        get_resolved_workflow_rich,
        validate_module_inputs,
        ModuleStep,
        ParallelGroup,
    )
    assert isinstance(AVAILABLE_MODULES, dict)
    assert isinstance(MODULE_REQUIREMENTS, dict)
    assert isinstance(WORKFLOWS, dict)
    assert callable(run_modules)
    assert callable(run_workflow)
    assert callable(get_resolved_workflow)
    assert callable(get_resolved_workflow_rich)
    assert callable(validate_module_inputs)


def test_checkpoint_imports():
    from core.checkpoint import (
        Checkpoint,
        EXIT_CODE_PAUSED,
        CHECKPOINT_FILENAME,
        serialize_steps,
        deserialize_steps,
    )
    assert callable(Checkpoint)
    assert EXIT_CODE_PAUSED == 42
    assert callable(serialize_steps)
    assert callable(deserialize_steps)


def test_parsers_import():
    bs4 = pytest.importorskip("bs4")
    from core.nmap_service_parse import nmap_to_tcphosts, nmap_to_udphosts
    assert callable(nmap_to_tcphosts)
    assert callable(nmap_to_udphosts)


def test_monkeyx_import():
    import monkeyx
    assert hasattr(monkeyx, 'main')
