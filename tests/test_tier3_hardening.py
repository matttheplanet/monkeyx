"""Tier-3 pre-release hardening: severity clamp (#13), auth-timeout log level
(#19), and an honest README (#12).

#13 — nuclei emits 'unknown' for templates whose author left severity unset.
Left verbatim it leaked a non-canonical value into findings, while summary
tallied it as info and focus ranked it at the info tier — so normalize was the
lone source storing 'unknown'. It now clamps to the canonical set at mint time.

#19 — iauth() never raises and the run continues on any existing Axiom session,
so an auth timeout is non-fatal. Logging it at ERROR misrepresented a soft,
optional condition; it is now a WARNING.

#12 — report.html does NOT embed screenshot thumbnails (it carries a written AI
screenshot analysis; the images are separate files), and the Focus "Start Here"
list only appears when the focus module ran. The root README used to promise
both unconditionally.
"""

import json
import logging
import os
import subprocess
import sys
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# --------------------------------------------------------------------------- #
# #13 — severity clamp
# --------------------------------------------------------------------------- #
from modules.normalize import _clamp_severity, _parse_nuclei_jsonl


class TestSeverityClamp:
    def test_canonical_preserved(self):
        for s in ("critical", "high", "medium", "low", "info"):
            assert _clamp_severity(s) == s

    def test_case_and_whitespace_normalized(self):
        assert _clamp_severity("  HIGH ") == "high"

    def test_unknown_becomes_info(self):
        assert _clamp_severity("unknown") == "info"

    def test_empty_and_none_become_info(self):
        assert _clamp_severity(None) == "info"
        assert _clamp_severity("") == "info"

    def test_arbitrary_string_becomes_info(self):
        assert _clamp_severity("catastrophic") == "info"

    def test_nuclei_jsonl_clamps_unknown(self, tmp_path):
        p = tmp_path / "x-nuclei.jsonl"
        p.write_text("\n".join(json.dumps(o) for o in [
            {"template-id": "exposed-mcp-server", "matched-at": "https://h/x",
             "info": {"severity": "unknown", "name": "Exposed MCP"}},
            {"template-id": "cve-2021-1", "matched-at": "https://h/y",
             "info": {"severity": "critical", "name": "Real"}},
        ]) + "\n")
        recs = _parse_nuclei_jsonl(str(p))
        sevs = {r["template_id"]: r["severity"] for r in recs}
        assert sevs["exposed-mcp-server"] == "info"   # was 'unknown'
        assert sevs["cve-2021-1"] == "critical"       # untouched


# --------------------------------------------------------------------------- #
# #19 — auth timeout is a WARNING, not an ERROR
# --------------------------------------------------------------------------- #
from core.fleet import iauth


class TestAuthTimeoutLogLevel:
    def test_timeout_logs_warning_not_error(self, caplog):
        caplog.set_level(logging.DEBUG, logger="monkeyx.core.fleet")
        with mock.patch("subprocess.run",
                        side_effect=subprocess.TimeoutExpired(cmd="ax", timeout=60)):
            iauth("validaccount")  # never raises
        recs = [r for r in caplog.records if r.name == "monkeyx.core.fleet"]
        assert any(r.levelno == logging.WARNING and "timed out" in r.getMessage()
                   for r in recs), "timeout should log at WARNING"
        assert not any(r.levelno >= logging.ERROR for r in recs), \
            "auth timeout must not log at ERROR (it is non-fatal)"

    def test_nonzero_exit_still_error(self, caplog):
        # A genuine credential/exit failure remains an ERROR — only the timeout
        # was downgraded.
        caplog.set_level(logging.DEBUG, logger="monkeyx.core.fleet")
        fake = mock.Mock(returncode=1, stderr="bad account")
        with mock.patch("subprocess.run", return_value=fake):
            iauth("validaccount")
        assert any(r.levelno == logging.ERROR for r in caplog.records
                   if r.name == "monkeyx.core.fleet")


# --------------------------------------------------------------------------- #
# #12 — README describes report.html honestly
# --------------------------------------------------------------------------- #
import re

from modules.summary import _README_TEXT

# The README is line-wrapped with indentation, so a phrase can straddle a
# newline + leading spaces. Collapse runs of whitespace before substring checks.
_README_FLAT = re.sub(r"\s+", " ", _README_TEXT)


class TestReadmeHonesty:
    def test_no_thumbnail_claim(self):
        # report.html embeds no screenshot images (only a written analysis).
        assert "thumbnail" not in _README_TEXT.lower()

    def test_states_images_are_not_embedded(self):
        assert "does NOT embed the screenshot images themselves" in _README_FLAT

    def test_start_here_is_conditional(self):
        # The Focus list only appears when the focus module ran — not promised
        # unconditionally.
        assert '"Start Here" focus list' in _README_FLAT
        assert "appear when the run produced them" in _README_FLAT

    def test_still_points_at_gowitness_images(self):
        assert "gowitness/" in _README_TEXT
