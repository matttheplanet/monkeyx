"""bbot_dast must enable fuzzing via the `lightfuzz` PRESET (-p), not via
require-flags (-rf active loud). The old require-flags approach was AND-matched
by bbot, so the non-existent `loud` flag dropped EVERY module (scan did nothing,
silently) and even on bbot 3.0 it dropped generic_ssrf + the passive extraction
chain. See the module docstring.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import modules.bbot_dast as dast
import modules._bbot_common as bc


def _run(monkeypatch, tmp_path):
    cap = {}
    monkeypatch.setattr(bc, "bash_command",
                        lambda cmd, *a, **k: cap.__setitem__("cmd", cmd))
    monkeypatch.setattr(bc, "_collect_output",
                        lambda *a, **k: {"events": 0, "findings": 0, "output_file": ""})
    url = tmp_path / "u.txt"
    url.write_text("http://live.example/\n")
    res = dast.run_bbot_dast(prefix=str(tmp_path / "run"), url_file=str(url))
    return cap["cmd"], res


def test_dast_uses_lightfuzz_preset_not_require_flags(monkeypatch, tmp_path):
    cmd, res = _run(monkeypatch, tmp_path)
    assert res["status"] == "success"
    assert "-p lightfuzz" in cmd           # preset enables fuzz submodules + crawl deps
    assert "-m generic_ssrf" in cmd        # added explicitly (not in the preset)


def test_dast_enables_bounded_spider(monkeypatch, tmp_path):
    cmd, _ = _run(monkeypatch, tmp_path)
    # The preset warns the spider should be enabled; we turn on a bounded crawl.
    assert "-c web.spider_distance=2 web.spider_depth=4" in cmd


def test_dast_no_longer_excludes_dns_or_portscan(monkeypatch, tmp_path):
    # The lightfuzz preset enables neither, so the old -em excludes were no-ops.
    cmd, _ = _run(monkeypatch, tmp_path)
    assert "-em" not in cmd
    assert "dnsbrute" not in cmd and "portscan" not in cmd


def test_dast_spider_depth_overridable(monkeypatch, tmp_path):
    cap = {}
    monkeypatch.setattr(bc, "bash_command",
                        lambda cmd, *a, **k: cap.__setitem__("cmd", cmd))
    monkeypatch.setattr(bc, "_collect_output",
                        lambda *a, **k: {"events": 0, "findings": 0, "output_file": ""})
    url = tmp_path / "u.txt"; url.write_text("http://live.example/\n")
    dast.run_bbot_dast(prefix=str(tmp_path / "run"), url_file=str(url),
                       spider_distance=0, spider_depth=1)
    assert "-c web.spider_distance=0 web.spider_depth=1" in cap["cmd"]


def test_dast_drops_the_broken_require_flags_mechanism(monkeypatch, tmp_path):
    cmd, _ = _run(monkeypatch, tmp_path)
    assert "-rf" not in cmd                # no require-flags (AND-matched -> dropped everything)
    assert "loud" not in cmd               # the bogus flag that matched no module is gone
    assert "lightfuzz generic_ssrf" not in cmd  # not jammed together under one -m


def test_dast_no_targets_is_graceful(monkeypatch, tmp_path):
    # No url_file / open_ports -> nothing to fuzz -> clean failure, no bbot run.
    monkeypatch.setattr(bc, "bash_command",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not run bbot")))
    res = dast.run_bbot_dast(prefix=str(tmp_path / "run"))
    assert res["status"] == "failed" and res["output_files"] == []
