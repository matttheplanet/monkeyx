"""FleetScaler workload sizing: URL-driven steps size by URL count, not IPs.

Regression: a scan with few IPs but thousands of URLs stayed tiny through the
web-scan steps because the scaler was only ever fed the IP count. nuclei on 2400
URLs ran on a 4-node fleet sized for ~3 IPs.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import core.fleet as fleet
from core.fleet import (
    FleetScaler, NoOpScaler, compute_optimal_nodes, compute_initial_nodes,
)


class _Scaler(FleetScaler):
    """FleetScaler that records scale requests instead of touching a cloud."""
    def __init__(self, nodes, max_nodes=50):
        super().__init__("f0", nodes, max_nodes=max_nodes)
        self.scaled_to = []
    def _scale(self, new_nodes, reason):
        self.scaled_to.append((new_nodes, reason))
        self.current_nodes = new_nodes


def _fixed_ratios(monkeypatch, tpn=60, upn=150):
    monkeypatch.setattr(fleet, "_per_node_ratios", lambda: (tpn, upn))


def test_url_step_sizes_by_url_count(monkeypatch):
    _fixed_ratios(monkeypatch)
    s = _Scaler(nodes=2)
    # 3 IPs, 2400 URLs, URL-scanning step -> 2400/150 = 16 nodes.
    assert s.check_and_scale(ip_count=3, url_count=2400, has_url_step=True) is True
    assert s.scaled_to[-1][0] == 16
    assert "urls" in s.scaled_to[-1][1]


def test_url_count_ignored_for_ip_step(monkeypatch):
    _fixed_ratios(monkeypatch)
    s = _Scaler(nodes=2)
    # Same URLs present, but an nmap-class step (has_url_step=False) -> IP-driven,
    # 3 IPs -> 1 node optimal -> no scale up (and not a >50% shrink from 2).
    assert s.check_and_scale(ip_count=3, url_count=2400, has_url_step=False) is False


def test_mixed_group_takes_max(monkeypatch):
    _fixed_ratios(monkeypatch)
    s = _Scaler(nodes=2)
    # 300 IPs (300/60=5) vs 2400 URLs (16) -> max = 16.
    s.check_and_scale(ip_count=300, url_count=2400, has_url_step=True)
    assert s.scaled_to[-1][0] == 16


def test_respects_max_nodes(monkeypatch):
    _fixed_ratios(monkeypatch)
    s = _Scaler(nodes=2, max_nodes=10)
    s.check_and_scale(ip_count=1, url_count=9000, has_url_step=True)  # would be 60
    assert s.scaled_to[-1][0] == 10


def test_compute_optimal_nodes_per_node_arg():
    assert compute_optimal_nodes(2400, per_node=150) == 16
    assert compute_optimal_nodes(2400, per_node=60) == 40
    assert compute_optimal_nodes(0, per_node=150) == 1     # min_nodes floor


def test_config_overrides_ratios(monkeypatch):
    import core.config as config
    monkeypatch.setattr(config, "load_fleet_config",
                        lambda: {"targets_per_node": 30, "urls_per_node": 300})
    tpn, upn = fleet._per_node_ratios()
    assert (tpn, upn) == (30, 300)


def test_noop_scaler_never_scales():
    assert NoOpScaler("f", 2).check_and_scale(3, 9999, True) is False


# --- compute_initial_nodes: sizing the opening fleet from the workload --------

def _write(path, lines):
    path.write_text("\n".join(lines) + "\n")
    return str(path)


def test_initial_nodes_sizes_from_target_ips(monkeypatch, tmp_path):
    _fixed_ratios(monkeypatch)
    tf = _write(tmp_path / "targets.txt", [f"198.18.10.{i}" for i in range(1, 121)])
    # 120 IPs / 60 per node -> 2 nodes.
    assert compute_initial_nodes(target_file=tf, max_nodes=50) == 2


def test_initial_nodes_sizes_from_urls(monkeypatch, tmp_path):
    _fixed_ratios(monkeypatch)
    uf = _write(tmp_path / "urls.txt",
                [f"https://example.com/{i}" for i in range(300)])
    # 300 URLs / 150 per node -> 2 nodes (no IPs).
    assert compute_initial_nodes(url_file=uf, max_nodes=50) == 2


def test_initial_nodes_respects_max_nodes(monkeypatch, tmp_path):
    _fixed_ratios(monkeypatch)
    tf = _write(tmp_path / "targets.txt", [f"45.33.{a}.{b}"
                for a in range(4) for b in range(1, 256)])  # ~1020 IPs -> 17
    assert compute_initial_nodes(target_file=tf, max_nodes=10) == 10


def test_initial_nodes_floor_is_one(monkeypatch, tmp_path):
    _fixed_ratios(monkeypatch)
    # No inputs at all -> never below 1 node.
    assert compute_initial_nodes(max_nodes=50) == 1


def test_initial_nodes_from_existing_ledger(monkeypatch, tmp_path):
    _fixed_ratios(monkeypatch)
    # Seed a real on-disk ledger (as a prior run would leave for continue/resume),
    # then size from it via existing_ledger_dir (load_from_disk path).
    from core.target_ledger import TargetLedger
    tf = _write(tmp_path / "t.txt", [f"198.18.10.{i}" for i in range(1, 121)])
    led = TargetLedger(str(tmp_path))
    led.seed_user_inputs(tf, None, None)
    assert os.path.exists(os.path.join(str(tmp_path), "discovery-ledger.jsonl"))
    assert compute_initial_nodes(existing_ledger_dir=str(tmp_path), max_nodes=50) == 2


def test_scale_up_failure_registers_new_fleet_and_keeps_old(monkeypatch):
    # A failed new-fleet spin-up must (1) register the new fleet for teardown so
    # its partially-provisioned instances aren't orphaned, and (2) NOT kill the
    # old fleet — the scan keeps running on it (no revert-onto-a-dying-fleet).
    monkeypatch.setattr(fleet, "initialize_fleet",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("spin-up failed")))
    killed = []
    monkeypatch.setattr(fleet, "kill_fleet", lambda f, **k: killed.append(f) or True)
    monkeypatch.setattr(fleet, "iauth", lambda account=None: None)

    s = FleetScaler("monkeyx-old", 2, max_nodes=50)
    s._scale(8, reason="targets grew")

    # Stayed on the old fleet, node count unchanged.
    assert s.current_fleet == "monkeyx-old"
    assert s.current_nodes == 2
    # The new fleet is tracked for teardown; the old fleet was NOT retired/killed.
    assert any(f.startswith("monkeyx-") and f != "monkeyx-old" for f in s._retired_fleets)
    assert "monkeyx-old" not in s._retired_fleets
    assert s._kill_threads == []        # no background kill of the old fleet started
    assert killed == []                 # old fleet never killed


def test_cleanup_keep_current_spares_active_fleet(monkeypatch):
    # Regression: _scale registers the active (new) fleet in _retired_fleets for
    # orphan-safety, so cleanup under --keep-fleet must spare the current fleet
    # while still killing genuinely-retired (scaled-away) fleets.
    monkeypatch.setattr(fleet, "iauth", lambda account=None: None)
    monkeypatch.setattr(fleet, "_remaining_instances", lambda f: (True, 1))
    killed = []
    monkeypatch.setattr(fleet, "kill_fleet", lambda f, **k: killed.append(f) or True)
    s = FleetScaler("monkeyx-new", 4)
    s.current_fleet = "monkeyx-new"
    s._retired_fleets = ["monkeyx-old", "monkeyx-new"]   # as _scale leaves it post-scale
    orphaned = s.cleanup(keep_current=True)
    assert "monkeyx-new" not in killed     # the fleet --keep-fleet protects: spared
    assert "monkeyx-old" in killed         # scaled-away fleet: still torn down
    assert orphaned == []


def test_cleanup_default_kills_all_retired(monkeypatch):
    monkeypatch.setattr(fleet, "iauth", lambda account=None: None)
    monkeypatch.setattr(fleet, "_remaining_instances", lambda f: (True, 1))
    killed = []
    monkeypatch.setattr(fleet, "kill_fleet", lambda f, **k: killed.append(f) or True)
    s = FleetScaler("monkeyx-new", 4)
    s.current_fleet = "monkeyx-new"
    s._retired_fleets = ["monkeyx-old", "monkeyx-new"]
    s.cleanup()  # keep_current defaults False -> both killed (final fleet torn down)
    assert "monkeyx-new" in killed and "monkeyx-old" in killed


def test_scale_emits_progress_event(monkeypatch):
    # Exercise the REAL _scale success path (cloud calls stubbed) and confirm it
    # emits a fleet_scaled event to the injected progress tracker.
    monkeypatch.setattr(fleet, "initialize_fleet", lambda *a, **k: None)
    monkeypatch.setattr(fleet, "kill_fleet", lambda *a, **k: True)
    monkeypatch.setattr(fleet, "iauth", lambda account=None: None)
    monkeypatch.setattr(fleet, "_remaining_instances", lambda f: (True, 0))

    class _FakeTracker:
        def __init__(s): s.calls = []
        def fleet_scaled(s, **kw): s.calls.append(kw)

    s = FleetScaler("monkeyx-old", 2, max_nodes=50)
    s.progress_tracker = _FakeTracker()
    s._scale(8, reason="urls grew to 1200")
    s.cleanup()

    assert len(s.progress_tracker.calls) == 1
    ev = s.progress_tracker.calls[0]
    assert ev["from_nodes"] == 2 and ev["to_nodes"] == 8
    assert ev["reason"] == "urls grew to 1200"
    assert ev["old_fleet"] == "monkeyx-old" and ev["new_fleet"] == s.current_fleet


def test_scale_without_tracker_is_safe(monkeypatch):
    monkeypatch.setattr(fleet, "initialize_fleet", lambda *a, **k: None)
    monkeypatch.setattr(fleet, "kill_fleet", lambda *a, **k: True)
    monkeypatch.setattr(fleet, "iauth", lambda account=None: None)
    monkeypatch.setattr(fleet, "_remaining_instances", lambda f: (True, 0))
    s = FleetScaler("f", 2)                 # progress_tracker stays None
    s._scale(4, reason="targets grew to 300")   # must not raise
    s.cleanup()
    assert s.current_nodes == 4


def test_cleanup_reports_orphans(monkeypatch):
    # Retired fleets still present + kill can't confirm -> returned as orphans so
    # the run loop can warn loudly instead of silently leaking.
    monkeypatch.setattr(fleet, "iauth", lambda account=None: None)
    monkeypatch.setattr(fleet, "_remaining_instances", lambda f: (True, 3))
    monkeypatch.setattr(fleet, "kill_fleet", lambda f, account=None: False)
    s = FleetScaler("f0", 2, account="acct")
    s._retired_fleets = ["monkeyx-old1", "monkeyx-old2"]
    assert set(s.cleanup()) == {"monkeyx-old1", "monkeyx-old2"}


def test_cleanup_clean_returns_empty(monkeypatch):
    monkeypatch.setattr(fleet, "iauth", lambda account=None: None)
    monkeypatch.setattr(fleet, "_remaining_instances", lambda f: (True, 0))
    monkeypatch.setattr(fleet, "kill_fleet", lambda f, account=None: True)
    s = FleetScaler("f0", 2)
    s._retired_fleets = ["monkeyx-old1"]
    assert s.cleanup() == []


def test_noop_scaler_cleanup_returns_empty_list():
    assert NoOpScaler("f", 2).cleanup() == []
