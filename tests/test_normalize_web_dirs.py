"""ffuf / feroxbuster content-discovery hits are parsed with explicit
url/status/size fields and minted into scan.db's web_dirs table (deduped on
(url, tool)) so the web viewer can browse them.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules import normalize
from core import scan_db


class TestParserFields:
    def test_ffuf_jsonl_carries_explicit_fields(self, tmp_path):
        p = tmp_path / "scan-ffuf.jsonl"
        p.write_text(json.dumps(
            {"url": "https://h.tld/admin", "status": 403, "length": 128, "words": 10}) + "\n")
        recs = normalize._parse_ffuf_jsonl(str(p))
        assert len(recs) == 1
        r = recs[0]
        assert r["type"] == "dir_hit" and r["tool"] == "ffuf"
        assert r["url"] == "https://h.tld/admin"
        assert r["status_code"] == 403 and r["size"] == 128 and r["words"] == 10

    def test_ffuf_report_objects_concatenated_on_one_line(self, tmp_path):
        # ax's `-oJ` writes ffuf `-of json` REPORT objects (hits nested in
        # `results`), one per fleet target, concatenated with no newlines. The
        # old per-line json.loads threw on the whole blob and silently dropped
        # every hit. Regression: all hits across all reports must be recovered.
        def report(target_hits):
            return json.dumps({
                "commandline": "ffuf -u http://h.tld/FUZZ -of json",
                "time": "2026-09-08T21:18:06Z",
                "results": [
                    {"input": {"FUZZ": h}, "url": f"http://h.tld/{h}",
                     "status": sc, "length": ln, "words": w}
                    for (h, sc, ln, w) in target_hits
                ],
            })
        blob = report([("wp-admin", 301, 320, 20), ("index.html", 200, 185, 14)]) \
            + report([("robots.txt", 200, 40, 3)])          # no separator
        p = tmp_path / "scan-ffuf.jsonl"
        p.write_text(blob)
        recs = normalize._parse_ffuf_jsonl(str(p))
        assert len(recs) == 3
        urls = {r["url"] for r in recs}
        assert urls == {"http://h.tld/wp-admin", "http://h.tld/index.html",
                        "http://h.tld/robots.txt"}
        wp = next(r for r in recs if r["url"].endswith("wp-admin"))
        assert wp["status_code"] == 301 and wp["size"] == 320 and wp["words"] == 20
        assert all(r["type"] == "dir_hit" and r["tool"] == "ffuf" for r in recs)

    def test_ffuf_empty_report_yields_nothing(self, tmp_path):
        p = tmp_path / "scan-ffuf.jsonl"
        p.write_text(json.dumps({"commandline": "ffuf ...", "results": []}))
        assert normalize._parse_ffuf_jsonl(str(p)) == []

    def test_feroxbuster_text_columns_parsed(self, tmp_path):
        p = tmp_path / "scan-feroxbuster.txt"
        # feroxbuster columnar text: status method  Nl  Nw  Nc  url
        p.write_text("200      GET        3l        9w      120c https://h.tld/api\n")
        recs = normalize._parse_dirbrute_file(str(p), "feroxbuster")
        assert len(recs) == 1
        r = recs[0]
        assert r["url"] == "https://h.tld/api" and r["status_code"] == 200
        assert r["size"] == 120 and r["words"] == 9 and r["lines"] == 3


class TestMintWebDirs:
    def test_mint_dedups_on_url_tool_and_skips_non_hits(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        recs = [
            {"type": "dir_hit", "tool": "ffuf", "host": "h.tld", "port": 443,
             "url": "https://h.tld/a", "status_code": 200, "size": 50, "words": 5},
            {"type": "dir_hit", "tool": "ffuf", "host": "h.tld", "port": 443,
             "url": "https://h.tld/a", "status_code": 200, "size": 50, "words": 5},  # dup
            {"type": "dir_hit", "tool": "feroxbuster", "host": "h.tld",
             "url": "https://h.tld/a", "status_code": 200},  # same url, diff tool -> kept
            {"type": "open_port", "tool": "nmap", "host": "h.tld"},          # ignored
            {"type": "dir_hit", "tool": "ffuf", "url": None},                # no url -> skipped
        ]
        normalize._mint_web_dirs(recs, db, scan_db._iso_now())
        rows = list(db._conn.execute(
            "SELECT url, tool, status_code, size FROM web_dirs ORDER BY tool"))
        db.close(checkpoint=False)
        # ffuf/a (deduped to one) + feroxbuster/a = 2 rows
        assert len(rows) == 2
        assert sorted(r[1] for r in rows) == ["feroxbuster", "ffuf"]
        ffuf_row = [r for r in rows if r[1] == "ffuf"][0]
        assert ffuf_row[2] == 200 and ffuf_row[3] == 50

    def test_host_derived_from_url_when_missing(self, tmp_path):
        db = scan_db.open_db(str(tmp_path))
        normalize._mint_web_dirs(
            [{"type": "dir_hit", "tool": "ffuf", "url": "https://derived.tld/x",
              "status_code": 200}], db, scan_db._iso_now())
        host = db._conn.execute(
            "SELECT host FROM web_dirs WHERE url=?", ("https://derived.tld/x",)).fetchone()[0]
        db.close(checkpoint=False)
        assert host == "derived.tld"
