"""The scan debrief reports run-level stats: total fleet nodes + total run time.

Nodes come from the axiom source-IP file (ax-ls'd live instances, one per node);
duration is the span of all progress.jsonl timestamps (covers --continue/--resume).
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.summary import _collect_stats, _write_markdown_report


def _mk(tmp_path):
    out = tmp_path / "run"
    (out / "data").mkdir(parents=True)
    (out / "reports").mkdir(parents=True)
    (out / "logs").mkdir(parents=True)
    return out


def _progress(out, events):
    with open(out / "progress.jsonl", "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")


def test_fleet_nodes_and_runtime_collected(tmp_path):
    out = _mk(tmp_path)
    _progress(out, [
        {"event": "step_started", "step": "ax_nmap_tcp",
         "started_at": "2026-09-24T20:00:00+00:00"},
        {"event": "step_completed", "step": "ax_nuclei",
         "finished_at": "2026-09-24T22:30:00+00:00"},   # 2.5h span
    ])
    (out / "logs" / "2026-09-24-1-axiom-source-ips.txt").write_text(
        "198.18.17.68\n198.18.18.141\n10.0.0.9\n")

    stats = _collect_stats(str(out / "data"), str(out), [])
    assert stats["run"]["fleet_nodes"] == 3
    assert stats["run"]["duration_hours"] == 2.5
    assert stats["run"]["duration_human"] == "2h 30m"

    md_path = str(out / "reports" / "summary.md")
    _write_markdown_report(stats, md_path)
    md = open(md_path).read()
    assert "| Fleet nodes | 3 |" in md
    assert "| Total run time | 2.5 h (2h 30m) |" in md


def test_local_run_omits_fleet_row(tmp_path):
    # No source-IP file (local-only run) -> no fleet-nodes row, but run time
    # still reported from progress.jsonl.
    out = _mk(tmp_path)
    _progress(out, [
        {"event": "step_started", "step": "normalize",
         "started_at": "2026-09-24T20:00:00+00:00"},
        {"event": "step_completed", "step": "normalize",
         "finished_at": "2026-09-24T20:06:00+00:00"},
    ])
    stats = _collect_stats(str(out / "data"), str(out), [])
    assert stats["run"]["fleet_nodes"] is None
    assert stats["run"]["duration_hours"] == 0.1        # 6 min
    md_path = str(out / "reports" / "summary.md")
    _write_markdown_report(stats, md_path)
    md = open(md_path).read()
    assert "Fleet nodes" not in md
    assert "| Total run time | 0.1 h (0h 6m) |" in md


def test_cost_compute_section_from_cost_json(tmp_path):
    out = _mk(tmp_path)
    _progress(out, [
        {"event": "step_started", "started_at": "2026-09-24T20:00:00+00:00"},
        {"event": "step_completed", "finished_at": "2026-09-24T21:47:00+00:00"},
    ])
    (out / "logs" / "1-axiom-source-ips.txt").write_text("1.1.1.1\n2.2.2.2\n")
    json.dump({
        "run_duration_s": 6420,
        "fleet": {"name": "f", "nodes": 2, "instance_type": "e2-medium",
                  "uptime_s": 6400, "node_hours": 3.56},
        "ai": {"calls": 5, "input_tokens": 40000, "output_tokens": 17486,
               "total_cost_usd": 0.5592, "cost_is_estimate": True,
               "cost_unknown": False, "providers": ["anthropic"],
               "models": ["bedrock"]},
    }, open(out / "logs" / "cost-summary.json", "w"))

    stats = _collect_stats(str(out / "data"), str(out), [])
    md_path = str(out / "reports" / "summary.md")
    _write_markdown_report(stats, md_path)
    md = open(md_path).read()
    assert "## Cost & Compute" in md
    assert "| Instance type | e2-medium |" in md
    assert "| Cloud instance-hours (node-hours) | 3.56 |" in md
    assert "| AI cost | $0.5592 (est.) |" in md
    assert "| AI tokens | 57,486 |" in md
    assert "node-hours × the hourly price of `e2-medium`" in md


def test_no_progress_no_runtime(tmp_path):
    out = _mk(tmp_path)
    stats = _collect_stats(str(out / "data"), str(out), [])
    assert stats["run"]["duration_hours"] is None
    md_path = str(out / "reports" / "summary.md")
    _write_markdown_report(stats, md_path)
    assert "Total run time" not in open(md_path).read()
