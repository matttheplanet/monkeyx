"""SMB-signing-not-required relay targets render a real port, not ':None'.

smb2-security-mode is a HOST-level NSE script, so its normalized record has
port=None. The finding must default to SMB's 445 (regression: it rendered
'198.18.7.111:None' in the analyze report).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.analyze import _find_smb_signing_disabled, _render_markdown
from test_analyze_dedup import _base_analysis


def _rec(host, port, detail):
    return {"type": "script_output", "method": "smb2-security-mode",
            "host": host, "port": port, "detail": detail}


def test_host_level_smb_record_defaults_to_445():
    recs = [_rec("198.18.7.111", None,
                 "Message signing enabled but not required")]
    findings = _find_smb_signing_disabled(recs)
    assert findings and findings[0]["port"] == 445
    assert findings[0]["host"] == "198.18.7.111"


def test_explicit_port_preserved():
    recs = [_rec("10.0.0.5", 139, "message signing disabled")]
    assert _find_smb_signing_disabled(recs)[0]["port"] == 139


def test_render_has_no_none_port(tmp_path):
    analysis = _base_analysis()
    analysis["smb_signing_disabled"] = [
        {"host": "198.18.7.111", "port": None, "detail": "signing not required"}]
    out = str(tmp_path / "a.md")
    _render_markdown(analysis, out)
    md = open(out).read()
    assert "198.18.7.111**:445" in md
    assert ":None" not in md
