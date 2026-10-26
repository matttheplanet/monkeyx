"""A module fed no in-scope targets must read as SKIPPED, not a clean success.

Regression (URL-only run review): host-class port scans (ax_nmap_tcp/udp) ran
on a `-url`-only engagement, were fed nothing (host channel gets no URL targets),
returned status "skipped" — but the progress tracker relabeled every non-failure
"success", so the debrief reported them as succeeded and analyze showed "0 open
ports", reading as "scanned, found nothing" rather than "never scanned". The
tracker now preserves the module's outcome and the debrief lists skipped modules
separately.

Also: dnsx_resolve now extracts hostnames from the URL list so a URL-only run
actually resolves the names behind its web surface (resolved-targets.txt was
shipping empty).
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.progress import ProgressTracker
from modules.summary import (
    _load_from_progress_file, _analyze_module_results, _build_module_history,
)
from modules.dnsx_resolve import _hostnames_from_url_file


def _empty_stats():
    return {"modules": {"succeeded": [], "failed": [], "empty_output": [], "skipped": []},
            "warnings": []}


class TestProgressPreservesStatus:
    def test_skipped_status_is_recorded(self, tmp_path):
        t = ProgressTracker(str(tmp_path), total_steps=2)
        s = t.step_started("ax_nmap_tcp")
        t.step_completed("ax_nmap_tcp", s,
                         {"status": "skipped", "warning": "empty input", "output_files": []})
        t.close()
        events = [json.loads(l) for l in open(os.path.join(tmp_path, "progress.jsonl"))]
        done = [e for e in events if e["event"] == "step_completed"][0]
        assert done["status"] == "skipped"
        assert done["warning"] == "empty input"

    def test_success_status_default(self, tmp_path):
        t = ProgressTracker(str(tmp_path), total_steps=1)
        s = t.step_started("ax_nuclei")
        t.step_completed("ax_nuclei", s, {"status": "success", "output_files": ["x"]})
        t.close()
        events = [json.loads(l) for l in open(os.path.join(tmp_path, "progress.jsonl"))]
        done = [e for e in events if e["event"] == "step_completed"][0]
        assert done["status"] == "success"


class TestDebriefSeparatesSkipped:
    def _write_progress(self, tmp_path, lines):
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        (tmp_path / "progress.jsonl").write_text("".join(json.dumps(l) + "\n" for l in lines))
        return str(data_dir)

    def test_skipped_not_counted_as_succeeded_progress_path(self, tmp_path):
        data_dir = self._write_progress(tmp_path, [
            {"event": "step_started", "step": "ax_nmap_tcp"},
            {"event": "step_completed", "step": "ax_nmap_tcp", "status": "skipped"},
            {"event": "step_started", "step": "ax_nuclei"},
            {"event": "step_completed", "step": "ax_nuclei", "status": "success"},
        ])
        stats = _empty_stats()
        _load_from_progress_file(data_dir, stats)
        assert stats["modules"]["skipped"] == ["ax_nmap_tcp"]
        assert stats["modules"]["succeeded"] == ["ax_nuclei"]

    def test_later_real_run_promotes_out_of_skipped(self, tmp_path):
        # If a --continue run actually feeds the module, last-write-wins clears skip.
        data_dir = self._write_progress(tmp_path, [
            {"event": "step_started", "step": "ax_nmap_tcp"},
            {"event": "step_completed", "step": "ax_nmap_tcp", "status": "skipped"},
            {"event": "step_started", "step": "ax_nmap_tcp"},
            {"event": "step_completed", "step": "ax_nmap_tcp", "status": "success"},
        ])
        stats = _empty_stats()
        _load_from_progress_file(data_dir, stats)
        assert stats["modules"]["skipped"] == []
        assert stats["modules"]["succeeded"] == ["ax_nmap_tcp"]

    def test_skipped_in_results_path(self, tmp_path):
        # The in-memory results path (when the run's result dicts are available).
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir)
        stats = _empty_stats()
        results = [
            {"module": "ax_nmap_tcp", "status": "skipped", "warning": "empty input"},
            {"module": "ax_nuclei", "status": "success", "output_files": []},
        ]
        _analyze_module_results(results, data_dir, stats)
        assert stats["modules"]["skipped"] == ["ax_nmap_tcp"]
        assert stats["modules"]["succeeded"] == ["ax_nuclei"]


class TestWarningEmptyOutputHonesty:
    """A module that ran but produced no output (status 'warning') must NOT be
    reported as a clean success — it belongs in empty_output / Needs Attention.

    Regression (21-sept-deep1 review): nmap TCP+UDP returned empty output
    (status 'warning'), but the summary showed them as 'success' and the debrief
    counted them as succeeded, hiding that no ports were scanned.
    """

    def _write_progress(self, tmp_path, lines):
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        (tmp_path / "progress.jsonl").write_text(
            "".join(json.dumps(l) + "\n" for l in lines))
        return str(data_dir)

    def test_warning_not_counted_as_succeeded_progress_path(self, tmp_path):
        data_dir = self._write_progress(tmp_path, [
            {"event": "step_started", "step": "ax_nmap_tcp"},
            {"event": "step_completed", "step": "ax_nmap_tcp", "status": "warning"},
            {"event": "step_started", "step": "ax_nuclei"},
            {"event": "step_completed", "step": "ax_nuclei", "status": "success"},
        ])
        stats = _empty_stats()
        _load_from_progress_file(data_dir, stats)
        assert stats["modules"]["succeeded"] == ["ax_nuclei"]
        assert [i["name"] for i in stats["modules"]["empty_output"]] == ["ax_nmap_tcp"]

    def test_warning_in_results_path(self, tmp_path):
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir)
        stats = _empty_stats()
        results = [
            {"module": "ax_nmap_tcp", "status": "warning",
             "warning": "ax_nmap_tcp: ran but produced no output — verify"},
            {"module": "ax_nuclei", "status": "success", "output_files": []},
        ]
        _analyze_module_results(results, data_dir, stats)
        assert stats["modules"]["succeeded"] == ["ax_nuclei"]
        eo = stats["modules"]["empty_output"]
        assert len(eo) == 1 and eo[0]["name"] == "ax_nmap_tcp"
        assert "ran but produced no output" in eo[0]["reason"]

    def test_module_history_preserves_warning_status(self, tmp_path):
        (tmp_path / "progress.jsonl").write_text("".join(json.dumps(l) + "\n" for l in [
            {"event": "step_started", "step": "ax_nmap_tcp"},
            {"event": "step_completed", "step": "ax_nmap_tcp", "status": "warning",
             "finished_at": "2026-09-21T17:07:54Z"},
        ]))
        stats = _empty_stats()
        stats["module_history"] = []
        _build_module_history(str(tmp_path), stats)
        hist = {h["name"]: h["last_status"] for h in stats["module_history"]}
        assert hist["ax_nmap_tcp"] == "warning"   # NOT "success"


class TestDnsxUrlHostnames:
    def test_extracts_hosts_from_urls(self, tmp_path):
        uf = tmp_path / "urls.txt"
        uf.write_text(
            "https://app.example.com/login\n"
            "http://api.example.com:8080/v1\n"
            "shop.example.com\n"
            "http://203.0.113.9/\n"      # IP literal -> skipped
            "# comment\n"
            "\n"
        )
        hosts = _hostnames_from_url_file(str(uf))
        assert hosts == {"app.example.com", "api.example.com", "shop.example.com"}

    def test_missing_file_is_empty(self):
        assert _hostnames_from_url_file(None) == set()
        assert _hostnames_from_url_file("/nonexistent/urls.txt") == set()
