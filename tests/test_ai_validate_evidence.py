"""Tests for ai_validate raw-evidence injection (#9).

ai_validate should reason over the ORIGINAL normalized scanner records for a
finding's host, not just ai_analyze's prose summary. These cover host/port
extraction, index build, and finding->evidence matching.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _load():
    # ai_validate imports cleanly under the test deps (requirements.txt installs
    # anthropic[bedrock]); a plain import is more robust than stubbing core, which
    # broke once ai_validate began importing core.scan_db + modules.normalize.
    from modules import ai_validate
    return ai_validate


aiv = _load()


class TestHostPortExtraction:
    def test_host_forms(self):
        assert aiv._extract_host("10.0.0.1:443") == "10.0.0.1"
        assert aiv._extract_host("https://api.example.com:8443/x") == "api.example.com"
        assert aiv._extract_host("example.com") == "example.com"
        assert aiv._extract_host("[2606:4700::1]:443") == "2606:4700::1"
        assert aiv._extract_host("") is None

    def test_strips_trailing_type_annotation(self):
        # The AI annotates some targets with a trailing "(domain)"/"(ip)" hint.
        # It must be stripped so the host resolves (else the validation's
        # finding_id is orphaned).
        assert aiv._extract_host("referral.example.com (domain)") == "referral.example.com"
        assert aiv._extract_host("1.2.3.4 (ip)") == "1.2.3.4"
        assert aiv._extract_host("api.example.com:443 (subdomain)") == "api.example.com"

    def test_port_forms(self):
        assert aiv._extract_port("10.0.0.1:443") == 443
        assert aiv._extract_port("https://api.example.com:8443/x") == 8443
        assert aiv._extract_port("example.com") is None
        assert aiv._extract_port("[2606:4700::1]:443") == 443


class TestEvidenceIndex:
    def _write(self, tmp_path, recs):
        pfx = str(tmp_path / "scan")
        (tmp_path / "scan-nuclei-normalized.jsonl").write_text(
            "\n".join(json.dumps(r) for r in recs) + "\n")
        return pfx

    def test_index_keyed_by_host(self, tmp_path):
        pfx = self._write(tmp_path, [
            {"host": "10.0.0.1", "port": 443, "tool": "nuclei", "title": "x"},
            {"host": "other.com", "port": 22, "tool": "nmap", "title": "y"},
        ])
        idx = aiv._load_evidence_index(pfx)
        assert set(idx) == {"10.0.0.1", "other.com"}

    def test_evidence_prefers_matching_port_and_trims(self, tmp_path):
        pfx = self._write(tmp_path, [
            {"host": "10.0.0.1", "port": 80, "tool": "nmap", "type": "open_port",
             "severity": "info", "title": "80 open", "detail": "x" * 9999},
            {"host": "10.0.0.1", "port": 443, "tool": "nuclei", "type": "finding",
             "severity": "high", "title": "panel", "template-id": "admin-panel",
             "matched-at": "https://10.0.0.1/admin"},
        ])
        idx = aiv._load_evidence_index(pfx)
        ev = aiv._evidence_for_finding({"target": "10.0.0.1:443"}, idx)
        assert ev[0]["port"] == 443                      # matching port first
        assert ev[0].get("template-id") == "admin-panel"  # source identifiers kept
        # detail is trimmed
        long_rec = next(e for e in ev if e.get("port") == 80)
        assert len(long_rec["detail"]) <= 500

    def test_unknown_host_returns_empty(self, tmp_path):
        pfx = self._write(tmp_path, [{"host": "10.0.0.1", "port": 443, "tool": "nuclei", "title": "x"}])
        idx = aiv._load_evidence_index(pfx)
        assert aiv._evidence_for_finding({"target": "9.9.9.9:443"}, idx) == []

    def test_empty_index_when_no_files(self, tmp_path):
        assert aiv._load_evidence_index(str(tmp_path / "nope")) == {}
        assert aiv._evidence_for_finding({"target": "x"}, {}) == []
