"""Guard: a --continue run that produces scanner output but skips normalize.

This is the exact failure that silently dropped 8,916 nuclei results in a real
engagement — a --continue ran `ax_nuclei -> ai_analyze -> ai_validate` without
`normalize`, so the nuclei output never became findings / reached scan.db / the
report. _warn_if_normalize_missing surfaces both that run-plan gap and the
staleness case (raw output on disk newer than the last normalize). It only
warns — it never blocks (the operator may be re-running a single step).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import monkeyx


def test_scanner_without_normalize_warns(capsys, tmp_path):
    monkeyx._warn_if_normalize_missing(
        ["ax_nuclei", "ai_analyze", "ai_validate"], str(tmp_path))
    out = capsys.readouterr().out
    assert "WARNING" in out
    assert "ax_nuclei" in out
    assert "normalize" in out
    # Prints an actionable recovery command.
    assert "jsonl_to_csv" in out


def test_scanner_with_normalize_is_silent(capsys, tmp_path):
    monkeyx._warn_if_normalize_missing(
        ["ax_nuclei", "normalize", "jsonl_to_csv"], str(tmp_path))
    assert capsys.readouterr().out == ""


def test_non_scanner_modules_are_silent(capsys, tmp_path):
    # ai_analyze/ai_validate alone don't produce normalize-consumable output.
    monkeyx._warn_if_normalize_missing(["ai_analyze", "ai_validate"], str(tmp_path))
    assert capsys.readouterr().out == ""


def test_stale_raw_output_warns_even_without_scanner(capsys, tmp_path):
    # A PRIOR run left raw nuclei output newer than the last normalized file, and
    # this continue doesn't normalize -> warn about staleness.
    data = tmp_path
    norm = data / "scan-nuclei-normalized.jsonl"
    norm.write_text("{}\n")
    raw = data / "scan-nuclei.jsonl"
    raw.write_text("{}\n")
    # Make the raw file newer than the normalized one.
    old = norm.stat().st_mtime
    os.utime(raw, (old + 100, old + 100))

    monkeyx._warn_if_normalize_missing(["ai_analyze"], str(data))
    out = capsys.readouterr().out
    assert "WARNING" in out
    assert "stale" in out.lower()


def test_no_stale_warning_when_normalized_is_current(capsys, tmp_path):
    data = tmp_path
    raw = data / "scan-nuclei.jsonl"
    raw.write_text("{}\n")
    norm = data / "scan-nuclei-normalized.jsonl"
    norm.write_text("{}\n")
    old = raw.stat().st_mtime
    os.utime(norm, (old + 100, old + 100))  # normalized is newer -> fine

    monkeyx._warn_if_normalize_missing(["ai_analyze"], str(data))
    assert capsys.readouterr().out == ""


def test_normalize_in_run_suppresses_stale_warning(capsys, tmp_path):
    # If normalize IS in the run, staleness is about to be fixed -> no warning.
    data = tmp_path
    norm = data / "scan-nuclei-normalized.jsonl"
    norm.write_text("{}\n")
    raw = data / "scan-nuclei.jsonl"
    raw.write_text("{}\n")
    old = norm.stat().st_mtime
    os.utime(raw, (old + 100, old + 100))

    monkeyx._warn_if_normalize_missing(["normalize"], str(data))
    assert capsys.readouterr().out == ""
