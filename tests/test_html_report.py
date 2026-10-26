"""Tests for the consolidated HTML report + its output-dir-root front-door copy.

generate_html_report writes reports/report.html AND copies it to the output-dir
root as the human entry point. The root copy is best-effort — a copy failure must
not fail the run.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.html_report import generate_html_report


def _make_output_dir(tmp_path, md=True):
    output_dir = tmp_path / "run"
    reports = output_dir / "reports"
    reports.mkdir(parents=True)
    if md:
        (reports / "summary.md").write_text("# Scan Debrief\n\nGenerated: now\n")
    return str(output_dir)


class TestRootCopy:
    def test_report_written_to_reports_and_root(self, tmp_path):
        output_dir = _make_output_dir(tmp_path)
        result = generate_html_report(output_dir)
        assert result == os.path.join(output_dir, "reports", "report.html")

        root_copy = os.path.join(output_dir, "report.html")
        assert os.path.exists(root_copy)
        assert os.path.exists(result)
        # byte-identical copy
        assert open(root_copy, "rb").read() == open(result, "rb").read()

    def test_root_copy_overwrites_stale(self, tmp_path):
        output_dir = _make_output_dir(tmp_path)
        # a stale root copy from a prior run
        with open(os.path.join(output_dir, "report.html"), "w") as f:
            f.write("STALE")
        generate_html_report(output_dir)
        text = open(os.path.join(output_dir, "report.html")).read()
        assert "STALE" not in text
        assert "Scan Debrief" in text

    def test_no_md_returns_none_and_no_root_copy(self, tmp_path):
        output_dir = _make_output_dir(tmp_path, md=False)
        assert generate_html_report(output_dir) is None
        assert not os.path.exists(os.path.join(output_dir, "report.html"))

    def test_stale_root_report_removed_when_no_report_produced(self, tmp_path):
        # A prior run left a root report.html; this run has no markdown to render.
        # The stale front-door copy must be removed so it can't look current.
        output_dir = _make_output_dir(tmp_path, md=False)
        stale = os.path.join(output_dir, "report.html")
        with open(stale, "w") as f:
            f.write("OLD REPORT FROM A PRIOR RUN")
        assert generate_html_report(output_dir) is None
        assert not os.path.exists(stale)

    def test_no_reports_dir_removes_stale_root_report(self, tmp_path):
        # Even if reports/ is gone entirely, a stale root copy is cleaned up.
        output_dir = str(tmp_path / "run")
        os.makedirs(output_dir)
        stale = os.path.join(output_dir, "report.html")
        with open(stale, "w") as f:
            f.write("OLD")
        assert generate_html_report(output_dir) is None
        assert not os.path.exists(stale)

    def test_copy_failure_is_non_fatal(self, tmp_path, monkeypatch):
        import modules.html_report as hr
        output_dir = _make_output_dir(tmp_path)

        def boom(src, dst):
            raise OSError("read-only root")

        monkeypatch.setattr(hr.shutil, "copy2", boom)
        # Must still return the canonical reports/report.html and not raise.
        result = generate_html_report(output_dir)
        assert result == os.path.join(output_dir, "reports", "report.html")
        assert os.path.exists(result)
        assert not os.path.exists(os.path.join(output_dir, "report.html"))


class TestSectionOrder:
    def test_focus_matches_date_prefixed_basename(self):
        # Real prefixes are date-based (e.g. 2026-07-29-focus.md); the segment
        # before "focus" is numeric, so the alpha-guard in _matches_section_key
        # doesn't trip and the section is recognized (not dumped to the tail).
        from modules.html_report import _matches_section_key
        assert _matches_section_key("focus", "2026-07-29-focus.md")
        assert _matches_section_key("focus", "2026-07-29-1-focus.md")

    def test_focus_orders_immediately_after_summary(self):
        from modules.html_report import _order_sections
        files = [
            "/o/reports/2026-07-29-ai-analysis.md",
            "/o/reports/2026-07-29-focus.md",
            "/o/reports/2026-07-29-summary.md",
            "/o/reports/2026-07-29-validation-report.md",
        ]
        titles = [t for t, _ in _order_sections(files)]
        assert titles[0] == "Scan Debrief"
        assert titles[1] == "Focus — Start Here"
        # focus sits above analysis/validation, not dumped to the unknown tail.
        assert titles.index("Focus — Start Here") < titles.index("Validation Results")


class TestAIFailureBanner:
    """When ai_analyze failed this run, the AI Analysis section must carry a
    failure banner — its markdown is written even on failure and otherwise looks
    like a clean 'no findings' result."""

    def _setup(self, tmp_path, progress_events):
        output_dir = tmp_path / "run"
        reports = output_dir / "reports"
        reports.mkdir(parents=True)
        (reports / "summary.md").write_text("# Scan Debrief\n\nGenerated: now\n")
        (reports / "2026-09-18-ai-analysis.md").write_text(
            "# AI Analysis\n\nNo confirmed vulnerabilities or attack paths identified.\n"
        )
        prog = output_dir / "progress.jsonl"
        with open(prog, "w") as f:
            for ev in progress_events:
                f.write(json.dumps(ev) + "\n")
        return str(output_dir)

    def test_banner_shown_when_ai_analyze_failed(self, tmp_path):
        output_dir = self._setup(tmp_path, [
            {"event": "step_failed", "step": "ai_analyze",
             "error": "ai_analyze: all AI provider calls failed — see errors.log."},
        ])
        generate_html_report(output_dir)
        html = open(os.path.join(output_dir, "reports", "report.html")).read()
        assert "AI analysis did not complete" in html
        assert "all AI provider calls failed" in html

    def test_no_banner_when_ai_analyze_succeeded(self, tmp_path):
        output_dir = self._setup(tmp_path, [
            {"event": "step_completed", "step": "ai_analyze", "status": "success"},
        ])
        generate_html_report(output_dir)
        html = open(os.path.join(output_dir, "reports", "report.html")).read()
        assert "AI analysis did not complete" not in html

    def test_no_banner_when_no_progress_file(self, tmp_path):
        # Directly-invoked report with no progress.jsonl must not crash or warn.
        output_dir = tmp_path / "run"
        reports = output_dir / "reports"
        reports.mkdir(parents=True)
        (reports / "2026-09-18-ai-analysis.md").write_text("# AI Analysis\n\nok\n")
        generate_html_report(str(output_dir))
        html = open(os.path.join(str(output_dir), "reports", "report.html")).read()
        assert "AI analysis did not complete" not in html
