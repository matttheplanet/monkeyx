"""Human-facing finding counts must agree with scan.db (the source of truth).

Regression: normalize's `*-normalized.jsonl` can carry the SAME finding more than
once (the raw tool re-emitted a match), but scan.db's findings primary key
collapses those to one row. The report generators counted the raw JSONL rows, so
summary.md / analysis.md / findings-all.csv reported ~2x the finding total the
viewer showed. All three now dedup by the shared `finding_id` (via
`normalize.dedup_findings`), so their counts converge on scan.db's.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import scan_db
from modules.normalize import dedup_findings
from modules.summary import _parse_findings
from modules.jsonl_to_csv import _write_consolidated_findings
from modules.analyze import run_analyze


def _dup_nuclei(n):
    # The SAME finding (host+port+proto+template_id) emitted n times.
    return [{"tool": "nuclei", "type": "nuclei_finding", "severity": "high",
             "host": "h.tld", "port": 443, "proto": "tcp",
             "template_id": "cve-x", "title": "x"} for _ in range(n)]


class TestDedupFindings:
    def test_collapses_identical_finding_ids(self):
        out = dedup_findings(_dup_nuclei(5))
        assert len(out) == 1

    def test_keeps_distinct_findings(self):
        recs = [
            {"tool": "nuclei", "type": "nuclei_finding", "host": "h.tld",
             "port": 443, "proto": "tcp", "template_id": "a"},
            {"tool": "nuclei", "type": "nuclei_finding", "host": "h.tld",
             "port": 443, "proto": "tcp", "template_id": "b"},
        ]
        assert len(dedup_findings(recs)) == 2

    def test_hostless_records_are_all_kept(self):
        # No host -> no finding_id -> must never be merged into one another.
        recs = [{"tool": "nuclei", "type": "nuclei_finding", "template_id": "a"},
                {"tool": "nuclei", "type": "nuclei_finding", "template_id": "a"}]
        assert len(dedup_findings(recs)) == 2

    def test_matches_scan_db_key(self):
        # dedup key == the finding_id scan.db would mint for the same record.
        rec = _dup_nuclei(1)[0]
        kept = dedup_findings(_dup_nuclei(3))
        assert len(kept) == 1
        expected = scan_db.finding_id("h.tld", 443, "tcp", "cve-x")
        from modules.normalize import finding_key
        assert finding_key(rec) == expected


class TestSummaryCountsDeduped:
    def test_duplicate_nuclei_rows_counted_once(self, tmp_path):
        output_dir = str(tmp_path / "run")
        data_dir = os.path.join(output_dir, "data")
        os.makedirs(data_dir)
        with open(os.path.join(data_dir, "scan-nuclei-normalized.jsonl"), "w") as f:
            for r in _dup_nuclei(5):
                f.write(json.dumps(r) + "\n")

        stats = {"findings": {"total": 0, "critical": 0, "high": 0,
                              "medium": 0, "low": 0, "info": 0}}
        _parse_findings(data_dir, stats, output_dir)
        assert stats["findings"]["total"] == 1
        assert stats["findings"]["high"] == 1
        assert stats["findings"]["by_tool"]["nuclei"]["total"] == 1


class TestConsolidatedCsvDeduped:
    def test_findings_all_csv_has_one_row_per_finding(self, tmp_path):
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        prefix = str(data_dir / "scan")
        with open(f"{prefix}-nuclei-normalized.jsonl", "w") as f:
            for r in _dup_nuclei(4):
                f.write(json.dumps(r) + "\n")
        reports_dir = str(tmp_path / "reports")
        os.makedirs(reports_dir)

        csv_path = _write_consolidated_findings(prefix, reports_dir)
        assert csv_path is not None
        with open(csv_path, encoding="utf-8-sig") as fh:
            lines = [ln for ln in fh.read().splitlines() if ln.strip()]
        # sep= line + header + exactly one data row
        assert lines[0].startswith("sep=")
        data_rows = lines[2:]
        assert len(data_rows) == 1


class TestAnalyzeNucleiTotalDeduped:
    def test_analysis_json_total_is_deduped(self, tmp_path):
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        prefix = str(data_dir / "scan")
        with open(f"{prefix}-nuclei-normalized.jsonl", "w") as f:
            for r in _dup_nuclei(6):
                f.write(json.dumps(r) + "\n")

        run_analyze(prefix, reports_prefix=prefix)
        with open(f"{prefix}-analysis.json", encoding="utf-8") as fh:
            analysis = json.load(fh)
        assert analysis["summary"]["nuclei_findings_total"] == 1
        assert analysis["summary"]["nuclei_severity_counts"] == {"high": 1}
