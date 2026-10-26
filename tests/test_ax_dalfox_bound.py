"""ax_dalfox must be bounded: it was an unbounded 4.5h runaway (743 URLs -> 2
findings) because it passed no dalfox flags and no timeout. Defaults now skip
BAV + dictionary-mining, cap workers + per-request timeout, and set a wall-clock
backstop; all overridable via monkeyx.config modules.ax_dalfox / kwargs.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import core.config as config
import modules._ax_common as axc
import modules.ax_dalfox as dalfox


def _run(monkeypatch, tmp_path, **kwargs):
    cap = {}
    def _fake(cmd, timeout=None, **k):
        cap["cmd"] = cmd; cap["timeout"] = timeout
    monkeypatch.setattr(axc, "bash_command", _fake)
    monkeypatch.setattr(axc, "get_module_defaults", lambda n: {})
    monkeypatch.setattr(axc, "load_fleet_config", lambda: {})
    uf = tmp_path / "urls.txt"; uf.write_text("https://a.tld/?x=1\nhttps://b.tld/?y=2\n")
    dalfox.run_ax_dalfox(prefix=str(tmp_path / "run"), fleet="f",
                         url_file=str(uf), data_prefix=str(tmp_path / "run"), **kwargs)
    return cap


def test_defaults_bounded(monkeypatch, tmp_path):
    cap = _run(monkeypatch, tmp_path)
    assert "-m dalfox" in cap["cmd"]
    assert "--extra-args '" in cap["cmd"]
    for f in ("--skip-bav", "--skip-mining-dict", "--worker 30", "--timeout 5"):
        assert f in cap["cmd"], f"missing {f}: {cap['cmd']}"
    assert cap["timeout"] == dalfox.DEFAULT_TIMEOUT       # wall-clock backstop applied


def test_kwargs_override(monkeypatch, tmp_path):
    cap = _run(monkeypatch, tmp_path, worker=8, req_timeout=3, skip_bav=False)
    assert "--worker 8" in cap["cmd"] and "--timeout 3" in cap["cmd"]
    assert "--skip-bav" not in cap["cmd"]                 # opted out
    assert "--skip-mining-dict" in cap["cmd"]             # still on


def test_tuning_false_runs_raw(monkeypatch, tmp_path):
    cap = _run(monkeypatch, tmp_path, tuning=False)
    assert "--extra-args" not in cap["cmd"]               # no dalfox flags
    assert cap["timeout"] == dalfox.DEFAULT_TIMEOUT       # backstop still applies


def test_config_timeout_overrides_backstop(monkeypatch, tmp_path):
    cap = {}
    monkeypatch.setattr(axc, "bash_command",
                        lambda cmd, timeout=None, **k: cap.update(timeout=timeout))
    monkeypatch.setattr(axc, "get_module_defaults",
                        lambda n: {"timeout": 600} if n == "ax_dalfox" else {})
    monkeypatch.setattr(axc, "load_fleet_config", lambda: {})
    uf = tmp_path / "u.txt"; uf.write_text("https://a.tld/?x=1\n")
    dalfox.run_ax_dalfox(prefix=str(tmp_path / "r"), fleet="f", url_file=str(uf))
    assert cap["timeout"] == 600                          # config wins over DEFAULT_TIMEOUT
