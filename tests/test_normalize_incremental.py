"""normalize is incremental: a workflow runs it several times (early mint, after
nuclei, after bbot_dast, final), and re-parsing a multi-GB katana.txt / nuclei
output on every pass was the dominant wall-clock cost. A tool whose raw input
set is byte-identical to the previous pass (and whose output still exists) is
skipped — no re-parse, no re-mint — while its already-minted rows persist.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.normalize import run_normalize
from core import scan_db


def _web_dir_count(output_dir):
    db = scan_db.open_db(str(output_dir))
    try:
        return db._conn.execute("SELECT COUNT(*) FROM web_dirs").fetchone()[0]
    finally:
        db.close(checkpoint=False)


def test_normalize_skips_unchanged_tool_then_reparses_on_change(tmp_path):
    output_dir = tmp_path / "run"
    data_dir = output_dir / "data"
    data_dir.mkdir(parents=True)
    prefix = str(data_dir / "2026-10-13")
    katana = f"{prefix}-katana.txt"

    with open(katana, "w", encoding="utf-8") as fh:
        fh.write("http://198.18.0.58:8080/login.php\n"
                 "https://example.com/admin-old/\n")

    # Pass 1: parses + mints.
    r1 = run_normalize(prefix, data_prefix=prefix)
    assert r1["tool_counts"].get("katana") == 2
    assert _web_dir_count(output_dir) == 2
    assert os.path.exists(output_dir / ".normalize-state.json")

    # Pass 2: input unchanged -> skipped (not in tool_counts), still success, and
    # the already-minted rows are untouched (skip is not data loss).
    r2 = run_normalize(prefix, data_prefix=prefix)
    assert "katana" not in r2["tool_counts"]
    assert r2["status"] == "success"
    assert _web_dir_count(output_dir) == 2

    # Pass 3: raw file grows -> re-parsed.
    with open(katana, "a", encoding="utf-8") as fh:
        fh.write("https://example.com/dashboard/\n")
    r3 = run_normalize(prefix, data_prefix=prefix)
    assert r3["tool_counts"].get("katana") == 3
    assert _web_dir_count(output_dir) == 3


def test_missing_scan_db_forces_remint_even_when_raw_unchanged(tmp_path):
    output_dir = tmp_path / "run"
    data_dir = output_dir / "data"
    data_dir.mkdir(parents=True)
    prefix = str(data_dir / "2026-10-13")
    with open(f"{prefix}-katana.txt", "w", encoding="utf-8") as fh:
        fh.write("http://198.18.0.58:8080/login.php\n")

    run_normalize(prefix, data_prefix=prefix)
    assert _web_dir_count(output_dir) == 1

    # Drop scan.db but leave the raw file + state untouched. The next pass must
    # NOT skip (it would otherwise leave the rebuilt DB empty).
    os.remove(scan_db.db_path_for(str(output_dir)))
    r = run_normalize(prefix, data_prefix=prefix)
    assert r["tool_counts"].get("katana") == 1
    assert _web_dir_count(output_dir) == 1
