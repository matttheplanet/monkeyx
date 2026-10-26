"""Katana/gau crawled URLs must land in scan.db's web_dirs table so the web
viewer's Directories view shows them. Regression: a deep run crawled 54 URLs
with katana but the Web Directories section was empty because only
ffuf/feroxbuster ever populated web_dirs.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.normalize import _parse_crawled_urls, run_normalize
from core import scan_db


def test_parse_crawled_urls_keeps_paths_skips_roots(tmp_path):
    f = tmp_path / "x-katana.txt"
    f.write_text(
        "http://example.com:445\n"            # bare root — skipped
        "https://example.com\n"               # bare root — skipped
        "http://198.18.0.58:8080/login.php\n"
        "https://example.com/admin-old/\n"
        "http://198.18.0.58:8080/login.php\n"  # dup — skipped
        "ftp://nope/x\n",                       # non-http — skipped
        encoding="utf-8")
    recs = _parse_crawled_urls(str(f), "katana")
    urls = {r["url"] for r in recs}
    assert urls == {"http://198.18.0.58:8080/login.php",
                    "https://example.com/admin-old/"}
    for r in recs:
        assert r["type"] == "dir_hit" and r["tool"] == "katana"
    # host/port resolved for the viewer
    byurl = {r["url"]: r for r in recs}
    assert byurl["http://198.18.0.58:8080/login.php"]["port"] == 8080
    assert byurl["https://example.com/admin-old/"]["port"] == 443


def test_run_normalize_mints_katana_into_web_dirs(tmp_path):
    output_dir = tmp_path / "run"
    data_dir = output_dir / "data"
    data_dir.mkdir(parents=True)
    prefix = str(data_dir / "2026-09-22")
    with open(f"{prefix}-katana.txt", "w", encoding="utf-8") as fh:
        fh.write("http://198.18.0.58:8080/login.php\n"
                 "https://example.com/admin-old/\n")

    run_normalize(prefix, data_prefix=prefix)

    db = scan_db.open_db(str(output_dir))
    rows = [dict(r) for r in db._conn.execute(
        "SELECT host, url, tool FROM web_dirs ORDER BY url")]
    db.close(checkpoint=False)
    assert len(rows) == 2
    assert all(r["tool"] == "katana" for r in rows)
    assert {r["url"] for r in rows} == {
        "http://198.18.0.58:8080/login.php",
        "https://example.com/admin-old/"}
