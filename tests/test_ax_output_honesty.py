"""Tests: a module that ran but collected no output is reported as a warning
(not a clean success) so fleet reach/collection failures aren't masked and real
findings (e.g. nuclei against a live target) aren't silently dropped.

The zero-byte->warning downgrade now lives in ONE place — workflows.run_module —
so it applies to every module uniformly. Individual modules just declare their
output_files and return success; the engine decides whether that output is real.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import modules._ax_common as axc
import modules.ax_nuclei as axn
import workflows


# ---- module layer: modules report success + declare their output_files ------
# (empty/missing detection is the engine's job now, not the module's)

def _run_ax(tmp_path, monkeypatch, writer):
    monkeypatch.setattr(axc, "get_module_defaults", lambda name: {})
    monkeypatch.setattr(axc, "load_fleet_config", lambda: {})
    prefix = str(tmp_path / "out")
    monkeypatch.setattr(axc, "bash_command",
                        lambda cmd, timeout=None: writer(f"{prefix}-x.txt"))
    in_file = tmp_path / "in.txt"
    in_file.write_text("http://example.com\n")
    return axc.run_ax_module(
        module_name="ax_wafw00f", ax_module="wafw00f",
        input_file=str(in_file), prefix=prefix,
        fleet="f", output_suffix="-x.txt", input_kind="url_file")


def test_run_ax_module_declares_output_and_returns_success(tmp_path, monkeypatch):
    result = _run_ax(tmp_path, monkeypatch,
                     writer=lambda p: open(p, "w").close())  # empty file
    assert result["status"] == "success"
    assert result["output_files"] == [f"{tmp_path / 'out'}-x.txt"]


def test_nuclei_declares_output_and_returns_success(tmp_path, monkeypatch):
    url_file = tmp_path / "urls.txt"
    url_file.write_text("http://198.18.6.173:3000\n")
    prefix = str(tmp_path / "out")
    monkeypatch.setattr(axn, "ax_local_config", lambda tool: "")
    monkeypatch.setattr(axn, "bash_command",
                        lambda cmd: open(f"{prefix}-nuclei.jsonl", "w").close())
    result = axn.run_ax_nuclei(prefix=prefix, fleet="f", url_file=str(url_file),
                               data_prefix=prefix)
    assert result["status"] == "success"
    assert result["output_files"] == [f"{prefix}-nuclei.jsonl"]


# ---- engine layer: run_module downgrades empty output to warning ------------

def _run_module_with(monkeypatch, result):
    """Register a fake module returning `result` and run it through run_module."""
    monkeypatch.setitem(workflows.AVAILABLE_MODULES, "fake_mod", lambda **kw: result)
    return workflows.run_module("fake_mod")


def test_missing_output_downgraded_to_warning(monkeypatch, tmp_path):
    res = _run_module_with(monkeypatch, {
        "module": "fake_mod", "status": "success",
        "output_files": [str(tmp_path / "does-not-exist.jsonl")]})
    assert res["status"] == "warning"
    assert "no output" in res["warning"]


def test_empty_output_downgraded_to_warning(monkeypatch, tmp_path):
    f = tmp_path / "out.jsonl"
    f.write_text("")  # zero bytes
    res = _run_module_with(monkeypatch, {
        "module": "fake_mod", "status": "success", "output_files": [str(f)]})
    assert res["status"] == "warning"


def test_empty_output_directory_downgraded_to_warning(monkeypatch, tmp_path):
    # gowitness case: output is a directory that ends up empty.
    d = tmp_path / "gowitness"
    d.mkdir()
    res = _run_module_with(monkeypatch, {
        "module": "fake_mod", "status": "success", "output_files": [str(d)]})
    assert res["status"] == "warning"


def test_nonempty_output_stays_success(monkeypatch, tmp_path):
    f = tmp_path / "out.jsonl"
    f.write_text('{"template-id":"x"}\n')
    res = _run_module_with(monkeypatch, {
        "module": "fake_mod", "status": "success", "output_files": [str(f)]})
    assert res["status"] == "success"


def test_directory_with_a_nonempty_file_stays_success(monkeypatch, tmp_path):
    d = tmp_path / "gowitness"
    d.mkdir()
    (d / "shot.png").write_bytes(b"\x89PNG\r\n")
    res = _run_module_with(monkeypatch, {
        "module": "fake_mod", "status": "success", "output_files": [str(d)]})
    assert res["status"] == "success"


def test_partial_output_stays_success(monkeypatch, tmp_path):
    # Only warn when EVERYTHING is empty — a legit-empty helper file alongside a
    # populated main output (e.g. nmap's per-service host lists) must not warn.
    empty = tmp_path / "ftp-hosts.txt"
    empty.write_text("")
    full = tmp_path / "scan.xml"
    full.write_text("<nmaprun/>")
    res = _run_module_with(monkeypatch, {
        "module": "fake_mod", "status": "success",
        "output_files": [str(empty), str(full)]})
    assert res["status"] == "success"


def test_no_declared_output_stays_success(monkeypatch):
    # Modules that attach results to the ledger declare no files — nothing to
    # measure, so they are left as success.
    res = _run_module_with(monkeypatch, {
        "module": "fake_mod", "status": "success", "output_files": []})
    assert res["status"] == "success"


def test_dry_run_never_downgrades(monkeypatch, tmp_path):
    monkeypatch.setitem(workflows.AVAILABLE_MODULES, "fake_mod",
                        lambda **kw: {"module": "fake_mod", "status": "success",
                                      "output_files": [str(tmp_path / "nope")]})
    # _PASSTHROUGH_DRY_RUN modules run for real; a non-passthrough name takes the
    # synthetic branch, so patch generate_synthetic_output via the module.
    monkeypatch.setattr("core.dry_run.generate_synthetic_output",
                        lambda name, **kw: {"module": name, "status": "success",
                                            "output_files": [str(tmp_path / "nope")]})
    res = workflows.run_module("fake_mod", _dry_run=True)
    assert res["status"] == "success"


def test_failed_status_not_touched(monkeypatch, tmp_path):
    res = _run_module_with(monkeypatch, {
        "module": "fake_mod", "status": "failed", "error": "boom",
        "output_files": [str(tmp_path / "nope")]})
    assert res["status"] == "failed"
