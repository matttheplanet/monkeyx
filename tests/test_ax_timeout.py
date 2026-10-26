"""Tests for the opt-in per-command timeout in ax wrapper modules.

Default is no limit (historical behavior). A timeout is resolved only from an
explicit arg, then modules.<name>.timeout, then fleet.ax_timeout. On expiry the
step is reported failed (so a hung fleet node can't wedge a parallel group)."""
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import modules._ax_common as axc


def _input_file(tmp_path):
    f = tmp_path / "domains.txt"
    f.write_text("example.com\n")
    return str(f)


def test_resolve_timeout_default_none(monkeypatch):
    monkeypatch.setattr(axc, "get_module_defaults", lambda name: {})
    monkeypatch.setattr(axc, "load_fleet_config", lambda: {})
    assert axc._resolve_timeout("ax_subfinder", None) is None


def test_resolve_timeout_priority(monkeypatch):
    monkeypatch.setattr(axc, "get_module_defaults",
                        lambda name: {"timeout": 600})
    monkeypatch.setattr(axc, "load_fleet_config", lambda: {"ax_timeout": 999})
    # explicit arg wins over everything
    assert axc._resolve_timeout("ax_subfinder", 120) == 120.0
    # then per-module config
    assert axc._resolve_timeout("ax_subfinder", None) == 600.0


def test_resolve_timeout_global_fallback(monkeypatch):
    monkeypatch.setattr(axc, "get_module_defaults", lambda name: {})
    monkeypatch.setattr(axc, "load_fleet_config", lambda: {"ax_timeout": 900})
    assert axc._resolve_timeout("ax_subfinder", None) == 900.0


def test_resolve_timeout_invalid_ignored(monkeypatch):
    monkeypatch.setattr(axc, "get_module_defaults",
                        lambda name: {"timeout": "soon"})
    monkeypatch.setattr(axc, "load_fleet_config", lambda: {})
    assert axc._resolve_timeout("ax_subfinder", None) is None
    # non-positive is treated as no limit
    assert axc._resolve_timeout("ax_subfinder", 0) is None
    assert axc._resolve_timeout("ax_subfinder", -5) is None


def test_run_passes_resolved_timeout_to_bash_command(monkeypatch, tmp_path):
    monkeypatch.setattr(axc, "get_module_defaults",
                        lambda name: {"timeout": 300})
    monkeypatch.setattr(axc, "load_fleet_config", lambda: {})
    seen = {}

    def fake_bash(cmd, timeout=None):
        seen["cmd"] = cmd
        seen["timeout"] = timeout

    monkeypatch.setattr(axc, "bash_command", fake_bash)
    axc.run_ax_module(
        module_name="ax_subfinder", ax_module="subfinder",
        input_file=_input_file(tmp_path), prefix=str(tmp_path / "out"),
        fleet="f", output_suffix="-subfinder.txt", input_kind="domainlist")
    assert seen["timeout"] == 300.0


def test_timeout_expiry_fails_step(monkeypatch, tmp_path):
    monkeypatch.setattr(axc, "get_module_defaults",
                        lambda name: {"timeout": 5})
    monkeypatch.setattr(axc, "load_fleet_config", lambda: {})

    def fake_bash(cmd, timeout=None):
        raise subprocess.TimeoutExpired(cmd, timeout)

    monkeypatch.setattr(axc, "bash_command", fake_bash)
    result = axc.run_ax_module(
        module_name="ax_amass", ax_module="amass",
        input_file=_input_file(tmp_path), prefix=str(tmp_path / "out"),
        fleet="f", output_suffix="-amass.txt", input_kind="domainlist")
    assert result["status"] == "failed"
    assert "timed out" in result["error"]
    assert result["output_files"] == []
