"""Tests: ax_nmap_udp tuning knobs (max_retries/min_rate/timing/host_timeout),
mirroring the tcp command tests, incl. injection guards. Captures the `ax scan …`
string without running anything.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

import modules.ax_nmap_udp as udp


def _run(monkeypatch, **kwargs):
    cap = {}
    monkeypatch.setattr(udp, "bash_command", lambda cmd, *a, **k: cap.__setitem__("cmd", cmd))
    monkeypatch.setattr(udp, "merge_nmap_folder", lambda *a, **k: {})
    monkeypatch.setattr(udp, "uncovered_ip_targets", lambda *a, **k: [])
    monkeypatch.setattr("core.nmap_service_parse.nmap_to_udphosts", lambda *a, **k: None)
    udp.run_ax_nmap_udp(target="t.txt", prefix="/tmp/x", fleet="f", **kwargs)
    return cap["cmd"]


def test_defaults(monkeypatch):
    cmd = _run(monkeypatch)
    assert "-sU" in cmd and "--open" in cmd
    assert "--max-retries 2" in cmd          # low by default (UDP retransmits)
    assert "-T4 --open --defeat-rst-ratelimit" in cmd
    assert "--host-timeout 60m" in cmd
    assert "--min-rate" not in cmd


def test_custom_knobs(monkeypatch):
    cmd = _run(monkeypatch, max_retries=1, timing="T3", host_timeout="600s", min_rate=300)
    assert "--max-retries 1" in cmd
    assert "-T3 --open" in cmd
    assert "--host-timeout 600s" in cmd
    assert "--min-rate 300" in cmd


@pytest.mark.parametrize("kw", [
    {"max_retries": "$(id)"},
    {"timing": "T4;id"},
    {"host_timeout": "10m;id"},
    {"min_rate": "300;id"},
])
def test_injection_rejected(monkeypatch, kw):
    with pytest.raises(ValueError):
        _run(monkeypatch, **kw)
