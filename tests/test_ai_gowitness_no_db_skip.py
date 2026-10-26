"""Regression: ai_analyze_gowitness must SKIP (not hard-fail) when there is no
gowitness.sqlite3 — e.g. a deep run with no URLs where ax_gowitness was skipped
("missing inputs: urls") so no screenshots were ever produced. Previously this
raised RuntimeError -> step_failed -> the whole run flipped to
completed_with_errors. It should return status 'skipped' instead, and must not
require an AI provider/API key to reach that decision.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import modules.ai_analyze_gowitness as gw


def test_skips_gracefully_when_no_gowitness_db(tmp_path, monkeypatch):
    # Fail loudly if the AI provider is touched — the skip must happen first.
    def _boom(*a, **k):
        raise AssertionError("AIProvider must not be constructed when no DB exists")
    monkeypatch.setattr(gw, "AIProvider", _boom)

    # output_dir = dirname(dirname(data_prefix)); leave it empty (no DB anywhere).
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    data_prefix = str(data_dir / "scan")

    result = gw.run_ai_analyze_gowitness(prefix=data_prefix, data_prefix=data_prefix)

    assert result["status"] == "skipped"
    assert result["module"] == "ai_analyze_gowitness"
    assert result["output_files"] == []
    assert "warning" in result  # explains why nothing was analyzed
