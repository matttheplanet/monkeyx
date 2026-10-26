"""Tests: the directly-shelling web modules pass a wall-clock timeout to
bash_command (so a hung node can't block forever), and bbot's auto-computed
timeouts are floored and ceilinged.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import modules.ax_gowitness as gw
import modules.ax_ffuf as ffuf
import modules.ax_feroxbuster as ferox
import modules._bbot_common as bbot_common
import modules.bbot_recon as recon
import modules.bbot_code as code


def _urlfile(tmp_path):
    p = tmp_path / "urls.txt"
    p.write_text("http://10.0.0.1\nhttp://10.0.0.2\n")
    return str(p)


# ---- wall-clock timeout is passed to bash_command ---------------------------

def test_gowitness_default_timeout(tmp_path, monkeypatch):
    cap = {}
    monkeypatch.setattr(gw, "bash_command", lambda cmd, *a, **k: cap.update(k))
    gw.run_ax_gowitness(prefix="/tmp/x", fleet="f", url_file=_urlfile(tmp_path))
    assert cap.get("timeout") == 3600

def test_gowitness_explicit_timeout(tmp_path, monkeypatch):
    cap = {}
    monkeypatch.setattr(gw, "bash_command", lambda cmd, *a, **k: cap.update(k))
    gw.run_ax_gowitness(prefix="/tmp/x", fleet="f", url_file=_urlfile(tmp_path), timeout=120)
    assert cap.get("timeout") == 120

def test_gowitness_threads_cap(tmp_path, monkeypatch):
    cap = {}
    monkeypatch.setattr(gw, "bash_command", lambda cmd, *a, **k: cap.__setitem__("cmd", cmd))
    gw.run_ax_gowitness(prefix="/tmp/x", fleet="f", url_file=_urlfile(tmp_path))
    assert "-m gowitness --threads 2" in cap["cmd"]        # default cap for 2GB nodes
    gw.run_ax_gowitness(prefix="/tmp/x", fleet="f", url_file=_urlfile(tmp_path), threads=4)
    assert "--threads 4" in cap["cmd"]

def test_ffuf_default_timeout(tmp_path, monkeypatch):
    cap = {}
    monkeypatch.setattr(ffuf, "bash_command", lambda cmd, *a, **k: cap.update(k))
    ffuf.run_ax_ffuf(prefix="/tmp/x", fleet="f", url_file=_urlfile(tmp_path))
    assert cap.get("timeout") == 3600

def test_feroxbuster_default_timeout(tmp_path, monkeypatch):
    cap = {}
    monkeypatch.setattr(ferox, "bash_command", lambda cmd, *a, **k: cap.update(k))
    ferox.run_ax_feroxbuster(prefix="/tmp/x", fleet="f", url_file=_urlfile(tmp_path))
    assert cap.get("timeout") == 3600


# ---- bbot timeout floor + ceiling -------------------------------------------

def test_bbot_default_timeout_is_not_none():
    # The 'run forever' trap: `timeout or DEFAULT_TIMEOUT` must not fall to None.
    assert bbot_common.DEFAULT_TIMEOUT == 1800


def test_bbot_recon_timeout_ceiling(monkeypatch):
    cap = {}
    monkeypatch.setattr(recon, "collect_bbot_targets", lambda **k: [f"h{i}.com" for i in range(5000)])
    monkeypatch.setattr(recon, "run_bbot_flags", lambda *a, **k: cap.update(k) or {
        "module": "bbot_recon", "status": "success", "output_files": []})
    recon.run_bbot_recon(domainlist="d.txt")
    assert cap.get("timeout") == 14400        # 5000*5=25000 capped to 14400


def test_bbot_code_timeout_ceiling(monkeypatch):
    cap = {}
    monkeypatch.setattr(code, "collect_bbot_targets", lambda **k: [f"h{i}.com" for i in range(1000)])
    monkeypatch.setattr(code, "run_bbot_flags", lambda *a, **k: cap.update(k) or {
        "module": "bbot_code", "status": "success", "output_files": []})
    code.run_bbot_code(domainlist="d.txt")
    assert cap.get("timeout") == 14400        # 1000*60=60000 capped to 14400
