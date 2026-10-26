"""ax_linkfinder output is now wired into the URL-ingestion path.

Its output is a DIRECTORY of per-target files whose lines mix absolute URLs and
relative endpoints. Only absolute http(s) URLs are logged to the ledger
(scannable); relative paths are skipped (no reliable base to attribute them to).
Deduped across files. (linkfinder was removed from the deep workflow but stays
available via -m, and now its results feed downstream when it runs.)
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import workflows
from core.target_ledger import TYPE_URL


class _FakeLedger:
    def __init__(self):
        self.logged = []

    def log_discovery(self, target, target_type, source, parent=None):
        self.logged.append((target, target_type, parent))


def _mk_linkfinder_dir(tmp_path):
    d = tmp_path / "scan-linkfinder"
    d.mkdir()
    (d / "host1.txt").write_text(
        "https://api.example.com/v1/users\n"
        "/relative/only\n"
        '"https://cdn.example.com/app.js"\n'
        "../also/relative\n")
    (d / "host2.txt").write_text(
        "http://example.com/login\n"
        "https://api.example.com/v1/users\n")   # dup across files
    return str(d)


def test_ingests_absolute_urls_skips_relatives_dedups(tmp_path):
    led = _FakeLedger()
    workflows._log_urls_from_linkfinder_dir(_mk_linkfinder_dir(tmp_path),
                                            "ax_linkfinder", led)
    urls = sorted(u for u, _t, _p in led.logged)
    assert urls == [
        "http://example.com/login",
        "https://api.example.com/v1/users",   # deduped to one
        "https://cdn.example.com/app.js",
    ]
    assert all(t == TYPE_URL for _u, t, _p in led.logged)
    # host attributed as parent
    by_url = {u: p for u, _t, p in led.logged}
    assert by_url["https://cdn.example.com/app.js"] == "cdn.example.com"


def test_linkfinder_wired_into_ingestion_dispatch(tmp_path):
    # The dispatcher routes a successful ax_linkfinder result (output_files = the
    # dir) to the walker. Guards against the module dropping off the list again.
    led = _FakeLedger()
    result = {"status": "success", "output_files": [_mk_linkfinder_dir(tmp_path)]}
    workflows._extract_discoveries(result, "ax_linkfinder", led, str(tmp_path))
    assert len(led.logged) == 3


def test_linkfinder_not_in_deep_workflow():
    import yaml
    here = os.path.dirname(__file__)
    deep = yaml.safe_load(open(os.path.join(here, "..", "workflows", "deep.yaml")))
    flat = []
    for s in deep["steps"]:
        if isinstance(s, str):
            flat.append(s)
        elif isinstance(s, dict) and "parallel" in s:
            flat += [x if isinstance(x, str) else x.get("name") for x in s["parallel"]]
        elif isinstance(s, dict):
            flat.append(s.get("name"))
    assert "ax_linkfinder" not in flat
