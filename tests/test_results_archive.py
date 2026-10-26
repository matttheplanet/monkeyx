"""Tests for the results-zip builder (monkeyx._create_results_archive)."""

import os
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import monkeyx


def test_scan_db_sidecars_excluded_from_archive(tmp_path):
    # A checkpointed scan.db is self-contained; its WAL/SHM sidecars must NOT be
    # bundled (a live sidecar makes a read-only unzip fail to open the WAL db).
    (tmp_path / "scan.db").write_text("db")
    (tmp_path / "scan.db-wal").write_text("wal")
    (tmp_path / "scan.db-shm").write_text("shm")
    (tmp_path / "report.html").write_text("<html></html>")

    monkeyx._create_results_archive(str(tmp_path), "scan")

    zip_path = tmp_path / "scan-results.zip"
    assert zip_path.exists()
    with zipfile.ZipFile(zip_path) as z:
        names = set(z.namelist())
    assert "scan.db" in names
    assert "report.html" in names
    assert "scan.db-wal" not in names
    assert "scan.db-shm" not in names
