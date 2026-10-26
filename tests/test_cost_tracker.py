"""CostTracker: node-hours + AI cost aggregation, the structured to_dict(), and
the stable cost-summary.json sibling the scan debrief reads."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import core.config as config
from core.cost_tracker import CostTracker


def _tracker_with_fleet(nodes=2, hours=1.0):
    ct = CostTracker()
    ct.fleet_started("myfleet", nodes)
    # Control uptime deterministically instead of wall-clock.
    g = ct._fleet_generations[-1]
    g["start"] = 1000.0
    g["end"] = 1000.0 + hours * 3600
    return ct


def test_node_hours_and_to_dict(monkeypatch):
    monkeypatch.setattr(config, "load_fleet_config", lambda: {"instance_type": "e2-medium"})
    ct = _tracker_with_fleet(nodes=2, hours=1.5)
    ct.record_ai_usage({"provider": "anthropic", "model": "bedrock", "calls": 3,
                        "input_tokens": 40000, "output_tokens": 10000,
                        "total_tokens": 50000, "total_cost_usd": 0.55,
                        "cost_is_estimate": True})
    assert round(ct.get_fleet_node_hours(), 2) == 3.0    # 1.5h * 2 nodes

    d = ct.to_dict()
    assert d["fleet"]["nodes"] == 2
    assert d["fleet"]["node_hours"] == 3.0
    assert d["fleet"]["instance_type"] == "e2-medium"
    assert d["ai"]["total_cost_usd"] == 0.55
    assert d["ai"]["input_tokens"] + d["ai"]["output_tokens"] == 50000
    assert d["ai"]["providers"] == ["anthropic"]


def test_write_emits_stable_json_sibling(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "load_fleet_config", lambda: {})
    ct = _tracker_with_fleet(nodes=3, hours=2.0)
    logs = tmp_path / "logs"
    logs.mkdir()
    txt = logs / "costs-20260101-000000.txt"
    ct.write(str(txt))

    assert txt.exists()
    js = logs / "cost-summary.json"
    assert js.exists()
    d = json.loads(js.read_text())
    assert d["fleet"]["node_hours"] == 6.0           # 2h * 3 nodes
    assert d["fleet"]["instance_type"] is None        # unset in config
    # Node-hours also present in the human txt.
    assert "Node-hours:     6.00" in txt.read_text()


def test_local_only_run_has_no_fleet(monkeypatch):
    monkeypatch.setattr(config, "load_fleet_config", lambda: {})
    ct = CostTracker()   # never called fleet_started
    assert ct.to_dict()["fleet"] is None


def test_autoscale_generations_sum_node_hours(monkeypatch):
    monkeypatch.setattr(config, "load_fleet_config", lambda: {})
    ct = CostTracker()
    ct.fleet_started("fleet-a", 2)
    ct.fleet_scaled("fleet-b", 4)
    ct.fleet_stopped()
    # Deterministic times: gen-a ran 1h @2 nodes, gen-b ran 2h @4 nodes.
    a, b = ct._fleet_generations
    a["start"], a["end"] = 0.0, 3600.0
    b["start"], b["end"] = 3600.0, 3600.0 + 2 * 3600
    assert round(ct.get_fleet_node_hours(), 2) == 2.0 + 8.0     # 1h*2 + 2h*4
    assert round(ct.get_fleet_duration_s() / 3600, 2) == 3.0    # total uptime

    d = ct.to_dict()["fleet"]
    assert d["scaled"] is True
    assert d["nodes"] == 4                       # peak, not initial
    assert d["name"] == "fleet-b"                # latest generation
    assert [g["nodes"] for g in d["generations"]] == [2, 4]
    assert d["node_hours"] == 10.0


def test_fleet_scaled_without_prior_start_opens_generation(monkeypatch):
    monkeypatch.setattr(config, "load_fleet_config", lambda: {})
    ct = CostTracker()
    ct.fleet_scaled("fleet-x", 3)                # no prior fleet_started
    assert len(ct._fleet_generations) == 1
    assert ct._fleet_generations[0]["nodes"] == 3


def test_scaled_generations_in_txt_report(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "load_fleet_config", lambda: {})
    ct = CostTracker()
    ct.fleet_started("fleet-a", 2)
    ct.fleet_scaled("fleet-b", 4)
    ct.fleet_stopped()
    a, b = ct._fleet_generations
    a["start"], a["end"] = 0.0, 3600.0
    b["start"], b["end"] = 3600.0, 3600.0 + 3600
    logs = tmp_path / "logs"; logs.mkdir()
    txt = logs / "costs.txt"
    ct.write(str(txt))
    body = txt.read_text()
    assert "auto-scaled across 2 generations" in body
    assert "fleet-a: 2 nodes" in body and "fleet-b: 4 nodes" in body
    assert "Peak nodes:     4" in body
