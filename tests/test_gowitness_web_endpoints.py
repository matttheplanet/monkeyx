"""gowitness metadata → web_endpoints.

A URL that only gowitness saw (no httpx fingerprint) should surface in the web
view WITH gowitness's title / HTTP status / detected technologies, not as a
blank screenshot-only row. httpx-fingerprinted rows keep their own data (only
the screenshot is attached).
"""

import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.normalize import _link_gowitness_screenshots
from core import scan_db


def _make_gowitness_db(output_dir):
    gw_dir = os.path.join(output_dir, "reports", "gowitness")
    os.makedirs(gw_dir, exist_ok=True)
    # A screenshot file must exist on disk for the row to be linked.
    shot = "screenshot.jpeg"
    with open(os.path.join(gw_dir, shot), "wb") as fh:
        fh.write(b"\xff\xd8\xff")  # minimal JPEG magic
    db_path = os.path.join(gw_dir, "gowitness.sqlite3")
    conn = sqlite3.connect(db_path)
    conn.executescript(
        "CREATE TABLE results (id INTEGER PRIMARY KEY, url TEXT, final_url TEXT, "
        "filename TEXT, perception_hash_group_id INTEGER, title TEXT, "
        "response_code INTEGER, failed INTEGER);"
        "CREATE TABLE technologies (id INTEGER PRIMARY KEY, result_id INTEGER, value TEXT);"
    )
    conn.execute(
        "INSERT INTO results VALUES (1, ?, ?, ?, ?, ?, ?, 0)",
        ("https://only-gowitness.example.com/", "https://only-gowitness.example.com/",
         shot, 7, "Admin Portal", 200))
    conn.execute("INSERT INTO technologies (result_id, value) VALUES (1, 'nginx'), (1, 'PHP')")
    conn.commit()
    conn.close()
    return db_path


def test_gowitness_only_url_gets_title_status_tech(tmp_path):
    output_dir = str(tmp_path)
    _make_gowitness_db(output_dir)
    db = scan_db.open_db(output_dir)
    assert db is not None
    try:
        _link_gowitness_screenshots(output_dir, db)
        row = db._conn.execute(
            "SELECT title, status_code, tech, screenshot FROM web_endpoints "
            "WHERE url = ?", ("https://only-gowitness.example.com/",)).fetchone()
    finally:
        db.close(checkpoint=False)

    assert row is not None, "gowitness-only URL should create a web_endpoints row"
    title, status_code, tech, screenshot = row
    assert title == "Admin Portal"
    assert status_code == 200
    assert tech and "nginx" in tech and "PHP" in tech
    assert screenshot and screenshot.endswith("screenshot.jpeg")


def test_httpx_row_not_clobbered_by_gowitness(tmp_path):
    output_dir = str(tmp_path)
    _make_gowitness_db(output_dir)
    db = scan_db.open_db(output_dir)
    assert db is not None
    try:
        # Pre-seed an httpx-fingerprinted row for the same URL with its own title.
        db.upsert_web_endpoint(host="only-gowitness.example.com",
                               url="https://only-gowitness.example.com/",
                               status_code=403, title="httpx title")
        _link_gowitness_screenshots(output_dir, db)
        row = db._conn.execute(
            "SELECT title, status_code, screenshot FROM web_endpoints "
            "WHERE url = ?", ("https://only-gowitness.example.com/",)).fetchone()
    finally:
        db.close(checkpoint=False)

    title, status_code, screenshot = row
    # httpx's authoritative fingerprint is preserved; only the screenshot attaches.
    assert title == "httpx title"
    assert status_code == 403
    assert screenshot and screenshot.endswith("screenshot.jpeg")
