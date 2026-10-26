"""Tests: the ax_nmap_tcp command builder honors the tuning knobs and rejects
injection. Captures the `ax scan …` string (bash_command is patched) without
running anything.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

import modules.ax_nmap_tcp as tcp


def _capture(monkeypatch):
    cap = {}
    monkeypatch.setattr(tcp, "bash_command", lambda cmd, *a, **k: cap.__setitem__("cmd", cmd))
    monkeypatch.setattr(tcp, "merge_nmap_folder", lambda *a, **k: {})
    monkeypatch.setattr(tcp, "nmap_to_tcphosts", lambda *a, **k: None)
    monkeypatch.setattr(tcp, "uncovered_ip_targets", lambda *a, **k: [])
    return cap


def _run(monkeypatch, **kwargs):
    cap = _capture(monkeypatch)
    tcp.run_ax_nmap_tcp(target="t.txt", prefix="/tmp/x", fleet="f", **kwargs)
    return cap["cmd"]


# ---- defaults ---------------------------------------------------------------

def test_defaults(monkeypatch):
    cmd = _run(monkeypatch)
    assert "-sV --version-intensity 5" in cmd
    assert "--max-retries 3" in cmd
    assert "-T4 --defeat-rst-ratelimit" in cmd
    assert "--host-timeout 60m" in cmd
    assert "--script=default,reverse-index" in cmd
    assert "vuln and safe" not in cmd      # vuln scripts OFF by default
    assert "--min-rate" not in cmd         # adaptive unless set


# ---- opt-in vuln scripts ----------------------------------------------------

def test_vuln_scripts_opt_in(monkeypatch):
    assert "'vuln and safe'" in _run(monkeypatch, vuln_scripts=True)

def test_vuln_scripts_string_true(monkeypatch):
    assert "vuln and safe" in _run(monkeypatch, vuln_scripts="true")


# ---- version intensity ------------------------------------------------------

def test_version_intensity_custom(monkeypatch):
    assert "--version-intensity 3" in _run(monkeypatch, version_intensity=3)

def test_version_light_has_no_intensity(monkeypatch):
    cmd = _run(monkeypatch, version="light")
    assert "--version-light" in cmd and "--version-intensity" not in cmd

def test_version_none(monkeypatch):
    assert "-sV" not in _run(monkeypatch, version="none")


# ---- timing knobs -----------------------------------------------------------

def test_min_rate_when_set(monkeypatch):
    assert "--min-rate 500" in _run(monkeypatch, min_rate=500)

def test_timing_and_timeout_and_retries(monkeypatch):
    cmd = _run(monkeypatch, timing="T3", host_timeout="600s", max_retries=2)
    assert "-T3 --defeat-rst-ratelimit" in cmd
    assert "--host-timeout 600s" in cmd
    assert "--max-retries 2" in cmd


# ---- injection guards (never reach the command string) ----------------------

@pytest.mark.parametrize("kw", [
    {"version_intensity": "7;id"},
    {"max_retries": "$(touch /tmp/x)"},
    {"timing": "T4;id"},
    {"host_timeout": "30m;id"},
    {"min_rate": "500;id"},
])
def test_injection_rejected(monkeypatch, kw):
    with pytest.raises(ValueError):
        _run(monkeypatch, **kw)
