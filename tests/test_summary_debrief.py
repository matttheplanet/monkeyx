"""Tests for the scan-debrief summary: failed-module listing + run-history table.

The debrief (reports/summary.md, which feeds the consolidated HTML report) must:
- list which modules FAILED (not just which succeeded), and
- show a cumulative per-module run history — how many times each module ran and
  the timestamp of its last run — sourced from the append-only progress.jsonl,
  which accumulates across --continue/--resume runs against the same output dir.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.summary import (
    _collect_stats, _write_markdown_report, _fmt_duration, _print_terminal_summary,
)


def test_fmt_duration_scales_units():
    assert _fmt_duration(0) == "0s"
    assert _fmt_duration(45) == "45s"
    assert _fmt_duration(125) == "2m 05s"
    assert _fmt_duration(3785) == "1h 03m"
    assert _fmt_duration(None) == "-"
    assert _fmt_duration("nope") == "-"


def _write_progress(output_dir, events):
    path = os.path.join(output_dir, "progress.jsonl")
    with open(path, "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")


def _make_output_dir(tmp_path):
    output_dir = tmp_path / "run"
    (output_dir / "data").mkdir(parents=True)
    (output_dir / "reports").mkdir(parents=True)
    return str(output_dir)


class TestModuleHistory:
    def test_counts_runs_and_last_timestamp(self, tmp_path):
        output_dir = _make_output_dir(tmp_path)
        _write_progress(output_dir, [
            {"event": "step_completed", "step": "ax_nuclei",
             "finished_at": "2026-07-25T10:00:00+00:00", "duration_seconds": 10},
            {"event": "step_completed", "step": "ax_nuclei",
             "finished_at": "2026-07-27T12:30:00+00:00", "duration_seconds": 185.4},
            {"event": "step_failed", "step": "ax_gowitness",
             "started_at": "2026-07-27T12:34:15+00:00",
             "finished_at": "2026-07-27T12:35:00+00:00", "error": "boom"},
        ])

        stats = _collect_stats(os.path.join(output_dir, "data"), output_dir, [])
        history = {h["name"]: h for h in stats["module_history"]}

        assert history["ax_nuclei"]["runs"] == 2
        # Last run is the later of the two completions.
        assert history["ax_nuclei"]["last_run"] == "2026-07-27T12:30:00+00:00"
        assert history["ax_nuclei"]["last_status"] == "success"
        # Runtime tracks the most recent run's duration (recorded directly).
        assert history["ax_nuclei"]["last_duration"] == 185.4

        assert history["ax_gowitness"]["runs"] == 1
        assert history["ax_gowitness"]["last_status"] == "failed"
        # step_failed carries no duration_seconds -> derived from the timestamps.
        assert history["ax_gowitness"]["last_duration"] == 45.0

    def test_history_renders_table(self, tmp_path):
        output_dir = _make_output_dir(tmp_path)
        _write_progress(output_dir, [
            {"event": "step_completed", "step": "ax_nuclei",
             "finished_at": "2026-07-27T12:30:00+00:00", "duration_seconds": 185},
        ])
        stats = _collect_stats(os.path.join(output_dir, "data"), output_dir, [])
        md_path = os.path.join(output_dir, "reports", "summary.md")
        _write_markdown_report(stats, md_path)

        with open(md_path) as fh:
            md = fh.read()

        assert "## Module Run History" in md
        assert "| Module | Times Run | Run Time | Last Run | Last Status |" in md
        assert "ax_nuclei" in md
        assert "2026-07-27 12:30 UTC" in md
        assert "3m 05s" in md  # per-module runtime column rendered

    def test_terminal_shows_per_module_run_times(self, tmp_path, capsys):
        output_dir = _make_output_dir(tmp_path)
        _write_progress(output_dir, [
            {"event": "step_completed", "step": "ax_nuclei",
             "finished_at": "2026-07-27T12:30:00+00:00", "duration_seconds": 185},
            {"event": "step_failed", "step": "ax_gowitness",
             "started_at": "2026-07-27T12:34:15+00:00",
             "finished_at": "2026-07-27T12:35:00+00:00", "error": "boom"},
        ])
        stats = _collect_stats(os.path.join(output_dir, "data"), output_dir, [])
        _print_terminal_summary(stats)
        out = capsys.readouterr().out

        assert "Module Run Times" in out
        assert "ax_nuclei" in out and "3m 05s" in out
        # Slowest-first ordering: ax_nuclei (185s) before ax_gowitness (45s).
        assert out.index("ax_nuclei") < out.index("ax_gowitness")
        # Non-success status is annotated.
        assert "(failed)" in out

    def test_no_progress_file_no_history(self, tmp_path):
        output_dir = _make_output_dir(tmp_path)
        stats = _collect_stats(os.path.join(output_dir, "data"), output_dir, [])
        assert stats["module_history"] == []


class TestFailedModuleListing:
    def test_failed_modules_listed_in_markdown(self, tmp_path):
        output_dir = _make_output_dir(tmp_path)
        results = [
            {"module": "ax_nuclei", "status": "success", "output_files": []},
            {"module": "ax_gowitness", "status": "failed", "error": "URL file missing"},
        ]
        stats = _collect_stats(os.path.join(output_dir, "data"), output_dir, results)
        md_path = os.path.join(output_dir, "reports", "summary.md")
        _write_markdown_report(stats, md_path)

        with open(md_path) as fh:
            md = fh.read()

        # Failed modules are named in the Execution block; succeeded modules are
        # NOT re-listed here (the Execution count + Module Run History cover them).
        assert "**Succeeded:**" not in md
        assert "**Failed:** ax_gowitness" in md
        # And the failed module still appears with its error under Needs Attention.
        assert "### Failed Modules" in md
        assert "URL file missing" in md

    def test_no_failed_line_when_all_succeed(self, tmp_path):
        output_dir = _make_output_dir(tmp_path)
        results = [{"module": "ax_nuclei", "status": "success", "output_files": []}]
        stats = _collect_stats(os.path.join(output_dir, "data"), output_dir, results)
        md_path = os.path.join(output_dir, "reports", "summary.md")
        _write_markdown_report(stats, md_path)

        with open(md_path) as fh:
            md = fh.read()

        assert "**Failed:**" not in md


class TestReadmeOrientation:
    """generate_summary drops a README.txt front-door guide at the output root."""

    def test_readme_written_with_report_pointer(self, tmp_path):
        from modules.summary import generate_summary
        output_dir = _make_output_dir(tmp_path)
        generate_summary(output_dir, [])
        readme = os.path.join(output_dir, "README.txt")
        assert os.path.exists(readme)
        text = open(readme).read()
        assert "report.html" in text
        assert "OPEN THIS" in text
        # names the standard folders so the layout is navigable
        assert "reports/" in text and "data/" in text and "logs/" in text

    def test_readme_overwritten_not_appended(self, tmp_path):
        from modules.summary import generate_summary
        output_dir = _make_output_dir(tmp_path)
        generate_summary(output_dir, [])
        first = open(os.path.join(output_dir, "README.txt")).read()
        generate_summary(output_dir, [])
        second = open(os.path.join(output_dir, "README.txt")).read()
        assert first == second  # idempotent, not doubled

    def test_readme_failure_is_non_fatal(self, tmp_path):
        import modules.summary as summary
        # A non-writable/nonexistent target must be swallowed, not raised.
        summary._write_readme(os.path.join(str(tmp_path), "does", "not", "exist"))


class TestPrioritiesBanner:
    """Focus items are still parsed into stats['priorities'] from *-focus.json,
    but the 'Priorities — Start Here' banner was removed from the debrief report
    (the Focus module/focus.json remains the source of truth for ranking)."""

    def _write_focus(self, output_dir, payload):
        path = os.path.join(output_dir, "data", "2026-07-29-focus.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)

    def test_no_priorities_banner_even_when_focus_ran(self, tmp_path):
        output_dir = _make_output_dir(tmp_path)
        self._write_focus(output_dir, {
            "count": 3, "confirmed": 1, "focus": [
                {"rank": 1, "target": "10.0.0.5:445", "severity": "medium",
                 "verdict": "confirmed", "title": "SMB signing disabled"},
            ]})
        stats = _collect_stats(os.path.join(output_dir, "data"), output_dir, [])
        md_path = os.path.join(output_dir, "reports", "summary.md")
        _write_markdown_report(stats, md_path)
        md = open(md_path).read()
        assert "Priorities — Start Here" not in md

    def test_top_capped_at_five(self, tmp_path):
        output_dir = _make_output_dir(tmp_path)
        items = [{"rank": i, "target": f"h{i}:80", "severity": "low",
                  "verdict": "unverified", "title": f"f{i}"} for i in range(1, 11)]
        self._write_focus(output_dir, {"count": 10, "confirmed": 0, "focus": items})
        stats = _collect_stats(os.path.join(output_dir, "data"), output_dir, [])
        assert len(stats["priorities"]["top"]) == 5
        assert stats["priorities"]["count"] == 10

    def test_no_banner_without_focus(self, tmp_path):
        output_dir = _make_output_dir(tmp_path)
        stats = _collect_stats(os.path.join(output_dir, "data"), output_dir, [])
        md_path = os.path.join(output_dir, "reports", "summary.md")
        _write_markdown_report(stats, md_path)
        md = open(md_path).read()
        assert "Priorities — Start Here" not in md

    def test_malformed_focus_json_is_non_fatal(self, tmp_path):
        output_dir = _make_output_dir(tmp_path)
        with open(os.path.join(output_dir, "data", "x-focus.json"), "w") as fh:
            fh.write("{not valid json")
        stats = _collect_stats(os.path.join(output_dir, "data"), output_dir, [])
        assert stats["priorities"]["top"] == []


def test_skipped_host_class_shows_dash_t_remediation(tmp_path):
    from modules.summary import _collect_stats, _write_markdown_report
    output_dir = _make_output_dir(tmp_path)
    results = [
        {"module": "ax_httpx", "status": "success", "output_files": []},
        {"module": "ax_nmap_tcp", "status": "skipped", "error": "Missing inputs: targets"},
        {"module": "ssh_audit_scan", "status": "skipped",
         "warning": "no in-scope SSH (port 22) endpoints found"},
    ]
    stats = _collect_stats(os.path.join(output_dir, "data"), output_dir, results)
    md_path = os.path.join(output_dir, "reports", "summary.md")
    _write_markdown_report(stats, md_path)
    md = open(md_path).read()
    assert "Skipped (fed no in-scope targets)" in md
    assert "-t <ips/cidrs>" in md            # remediation shown for host-class skip
    assert "name-safe scope" in md


def test_no_remediation_when_only_nonhost_skipped(tmp_path):
    from modules.summary import _collect_stats, _write_markdown_report
    output_dir = _make_output_dir(tmp_path)
    results = [
        {"module": "ai_analyze", "status": "skipped", "error": "Missing inputs"},
    ]
    stats = _collect_stats(os.path.join(output_dir, "data"), output_dir, results)
    md_path = os.path.join(output_dir, "reports", "summary.md")
    _write_markdown_report(stats, md_path)
    md = open(md_path).read()
    assert "-t <ips/cidrs>" not in md        # no host-class module skipped


def test_debrief_renders_attack_surface_from_analysis_json(tmp_path):
    import json as _json
    from modules.summary import _collect_stats, _write_markdown_report
    output_dir = _make_output_dir(tmp_path)
    # analyze emits the overview to analysis.json (no longer to analysis.md).
    with open(os.path.join(output_dir, "data", "run-analysis.json"), "w") as fh:
        _json.dump({
            "summary": {"unique_ports": 3, "unique_services": 2},
            "port_service_stats": {
                "port_counts": {"443": 5, "22": 2},
                "service_version_counts": [
                    {"service": "http", "product": "nginx", "version": "1.25", "count": 5},
                ]},
            "os_fingerprint": {"Linux 6.x": ["h1", "h2"]},
        }, fh)
    stats = _collect_stats(os.path.join(output_dir, "data"), output_dir, [])
    md_path = os.path.join(output_dir, "reports", "summary.md")
    _write_markdown_report(stats, md_path)
    md = open(md_path).read()
    assert "## Attack Surface" in md
    assert "Service / Version Inventory" in md and "nginx" in md
    assert "OS Fingerprinting" in md and "Linux 6.x" in md
    assert "| 443 | 5 |" in md
    assert "3 ports, 2 services" in md          # folded into Scope


def test_debrief_no_attack_surface_without_analysis_json(tmp_path):
    from modules.summary import _collect_stats, _write_markdown_report
    output_dir = _make_output_dir(tmp_path)
    stats = _collect_stats(os.path.join(output_dir, "data"), output_dir, [])
    md_path = os.path.join(output_dir, "reports", "summary.md")
    _write_markdown_report(stats, md_path)
    assert "## Attack Surface" not in open(md_path).read()


def test_analysis_md_drops_moved_sections_but_json_keeps_them(tmp_path):
    """analyze.md must NOT render the moved sections; analysis.json must still
    carry the data for the debrief + machines."""
    import json as _json
    from modules import analyze
    data = tmp_path / "data"; data.mkdir()
    prefix = str(data / "run")
    with open(f"{prefix}-nmap-normalized.jsonl", "w") as fh:
        fh.write(_json.dumps({"tool": "nmap", "type": "open_port", "host": "10.0.0.5",
                              "port": 443, "proto": "tcp", "service": "http",
                              "product": "nginx", "version": "1.25",
                              "severity": "info", "title": "TCP/443"}) + "\n")
    res = analyze.run_analyze(prefix, data_prefix=prefix)
    md = open([f for f in res["output_files"] if f.endswith(".md")][0]).read()
    js = _json.load(open([f for f in res["output_files"] if f.endswith(".json")][0]))
    assert "## Summary" not in md and "Service/Version Inventory" not in md
    assert "OS Fingerprinting" not in md and "Port Statistics" not in md
    assert js["port_service_stats"]["service_version_counts"]   # data retained in json


# --- coverage gaps: host-channel denominator (not all ledger IPs) ----------

from modules.summary import _check_coverage


def _snap(tmp_path, name, n):
    d = tmp_path / "step-snapshots"
    d.mkdir(exist_ok=True)
    (d / name).write_text("".join(f"10.0.0.{i}\n" for i in range(n)))


def test_coverage_gap_ignores_name_safe_ips(tmp_path):
    # 40 host IPs fed, 40 host-authorized in ledger -> NO gap, even though the
    # ledger has 1000 IPs total (960 name-safe resolved from -d/-url that nmap is
    # correctly never fed). The old code compared against all 1000 and cried wolf.
    _snap(tmp_path, "003-ax_nmap_tcp-target.txt", 40)
    stats = {"targets": {"ips": 1000, "ips_host": 40, "urls": 0}, "coverage": []}
    _check_coverage(str(tmp_path), stats)
    assert stats["coverage"] == []   # 40/40 host IPs -> no false gap


def test_coverage_gap_reports_real_host_drop(tmp_path):
    # 40 host-authorized, only 35 fed -> a REAL 5-host gap (exclusion/filter).
    _snap(tmp_path, "003-ax_nmap_tcp-target.txt", 35)
    stats = {"targets": {"ips": 1000, "ips_host": 40, "urls": 0}, "coverage": []}
    _check_coverage(str(tmp_path), stats)
    assert len(stats["coverage"]) == 1
    msg = stats["coverage"][0]
    assert "35/40 host-authorized IPs" in msg and "5 in-scope host targets not scanned" in msg
