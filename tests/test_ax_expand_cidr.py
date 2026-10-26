"""Every ax scanner that accepts IP/CIDR targets must pass --expand-cidr, so a
CIDR is expanded and distributed ACROSS the fleet instead of being pinned to a
single node. Regression: ax_masscan omitted it, so `-t <cidr>` ran the whole
range on one node.
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

# ax modules whose REQUIRED_INPUTS include "target" (IP/CIDR file).
_TARGET_SCANNERS = ["ax_masscan", "ax_naabu", "ax_nmap_tcp", "ax_nmap_udp"]
_MOD_DIR = os.path.join(os.path.dirname(__file__), "..", "modules")


@pytest.mark.parametrize("mod", _TARGET_SCANNERS)
def test_ax_scan_command_passes_expand_cidr(mod):
    src = open(os.path.join(_MOD_DIR, f"{mod}.py")).read()
    # Find the actual `ax scan '{target}' ...` command line (not log messages).
    scan_lines = [ln for ln in src.splitlines()
                  if "ax scan '{target}'" in ln]
    assert scan_lines, f"{mod}: no `ax scan '{{target}}'` command found"
    for ln in scan_lines:
        assert "--expand-cidr" in ln, f"{mod}: ax scan command missing --expand-cidr: {ln.strip()}"


def test_masscan_command_includes_expand_cidr(monkeypatch, tmp_path):
    import modules.ax_masscan as m
    captured = {}
    monkeypatch.setattr(m, "bash_command", lambda cmd, *a, **k: captured.setdefault("cmd", cmd))
    tgt = tmp_path / "targets.txt"
    tgt.write_text("140.95.0.0/16\n")
    res = m.run_ax_masscan(str(tgt), str(tmp_path / "out"), "myfleet")
    assert res["status"] == "success"
    assert "--expand-cidr" in captured["cmd"]
    assert "-m masscan" in captured["cmd"]
