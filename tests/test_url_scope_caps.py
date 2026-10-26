"""Opt-in `--url-max-per-host` bounds crawled URLs at the SOURCE (not just the
export): the ledger-ingestion sink (crawled URLs -> derived targets) and the
normalize web_dirs sink. Default (None) = unlimited, nothing changes. Plus
`ax_katana` exposes katana's own crawl-bounding options so the crawl itself can
be limited. Regression target: a wildcard scope where katana emitted ~1M URLs
-> 1.1M ledger targets / web_dirs / 7.9M coverage rows / 3.3GB scan.db.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

import workflows as w
from modules.ax_katana import _katana_extra_args
from modules.normalize import run_normalize
from core import scan_db


class _FakeLedger:
    def __init__(self):
        self.logged = []

    def log_discovery(self, url, ttype, module, parent=None):
        self.logged.append(url)


def _write_crawl(path):
    with open(path, "w", encoding="utf-8") as f:
        for i in range(5):
            f.write(f"http://a.example.com/{i}\n")
        for i in range(3):
            f.write(f"http://b.example.com/{i}\n")


# --- ingestion sink (ledger targets) ---------------------------------------

def test_ingestion_cap_off_by_default(tmp_path):
    f = tmp_path / "k.txt"
    _write_crawl(str(f))
    led = _FakeLedger()
    w._log_urls_from_file(str(f), "ax_katana", led)        # no cap
    assert len(led.logged) == 8                            # everything promoted


def test_ingestion_cap_first_n_per_host(tmp_path):
    f = tmp_path / "k.txt"
    _write_crawl(str(f))
    led = _FakeLedger()
    w._log_urls_from_file(str(f), "ax_katana", led, max_per_host=2)
    assert len(led.logged) == 4                            # 2 per host:port
    assert set(led.logged) == {
        "http://a.example.com/0", "http://a.example.com/1",
        "http://b.example.com/0", "http://b.example.com/1"}


# --- web_dirs sink (normalize) ---------------------------------------------

def _web_dir_count(output_dir):
    db = scan_db.open_db(str(output_dir))
    try:
        return db._conn.execute("SELECT COUNT(*) FROM web_dirs").fetchone()[0]
    finally:
        db.close(checkpoint=False)


def _run_with(tmp_path, **kw):
    data = tmp_path / "output" / "data"
    data.mkdir(parents=True)
    prefix = str(data / "s")
    _write_crawl(f"{prefix}-katana.txt")
    run_normalize(prefix, data_prefix=prefix, **kw)
    return tmp_path / "output"


def test_webdirs_cap_off_by_default(tmp_path):
    assert _web_dir_count(_run_with(tmp_path)) == 8


def test_webdirs_cap_first_n_per_host(tmp_path):
    assert _web_dir_count(_run_with(tmp_path, url_max_per_host=2)) == 4


# --- katana crawl options (bound the crawl itself, validated) --------------

def test_katana_extra_args_none_when_unset():
    assert _katana_extra_args({}) is None


def test_katana_extra_args_builds_validated_flags():
    assert _katana_extra_args({"depth": 2, "crawl_duration": "10m", "field_scope": "rdn"}) \
        == "-depth 2 -crawl-duration 10m -field-scope rdn"


@pytest.mark.parametrize("bad", [
    {"depth": 0}, {"depth": 99}, {"depth": "; rm -rf /"},
    {"crawl_duration": "10x"}, {"crawl_duration": "5m; evil"},
    {"field_scope": "bogus"},
])
def test_katana_extra_args_rejects_bad_values(bad):
    with pytest.raises(ValueError):
        _katana_extra_args(bad)
