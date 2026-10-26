"""Sweep-then-verify: a fast masscan/naabu sweep finds open ports, then
ax_nmap_tcp with ports:open runs its full -sV/NSE command on ONLY those ports,
on ONLY the responsive hosts — instead of grinding all 65k ports on every host
(which on a 2k-IP scope took ~25h). Covers the ledger exports, the nmap 'open'
sentinel, and the workflow wiring that feeds it.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.target_ledger import TargetLedger
from modules.ax_nmap_tcp import _read_swept_ports, run_ax_nmap_tcp
import workflows
from workflows import _member_kwargs, ModuleStep, ParallelGroup


def _ledger_with_ports(tmp_path):
    led = TargetLedger(str(tmp_path))
    led.seed_user_inputs(None, None, None)
    for ip in ("1.2.3.4", "5.6.7.8", "9.9.9.9"):
        led._in_scope_ips.add(ip)
        led._explicit_ips.add(ip)          # host-authorized (channel t)
    led._ports["1.2.3.4"] = {(22, "tcp"): 1, (443, "tcp"): 1}
    led._ports["5.6.7.8"] = {(80, "tcp"): 1, (161, "udp"): 1}   # udp must not count for tcp
    # 9.9.9.9 has no open ports -> not a live host
    return led


def test_read_swept_ports_filters_and_joins(tmp_path):
    f = tmp_path / "p.txt"
    f.write_text("443\n22\n80\n99999\nbad\n\n")
    assert _read_swept_ports(str(f)) == "22,80,443"
    assert _read_swept_ports("/does/not/exist") == ""


def test_ledger_exports_union_and_live_hosts(tmp_path):
    led = _ledger_with_ports(tmp_path)
    union = tmp_path / "union.txt"
    live = tmp_path / "live.txt"
    assert led.export_port_list(str(union), proto="tcp", scope_filter="strict", host_only=True) == 3
    assert led.export_live_host_targets(str(live), proto="tcp", scope_filter="strict", host_only=True) == 2
    assert sorted(union.read_text().split()) == ["22", "443", "80"]
    hosts = set(live.read_text().split())
    assert hosts == {"1.2.3.4", "5.6.7.8"}      # 9.9.9.9 (no ports) excluded


def test_nmap_ports_open_skips_when_no_sweep(tmp_path):
    # ports=open with no swept-open ports available -> skip cleanly, no scan.
    r = run_ax_nmap_tcp(target=str(tmp_path / "t.txt"), prefix=str(tmp_path / "o"),
                        fleet="f", ports="open")
    assert r["status"] == "skipped"


def test_sweep_toggle_on_is_noop():
    import monkeyx
    steps = [ModuleStep("ax_masscan", {"ports": "all"}),
             ParallelGroup([ModuleStep("ax_nmap_tcp", {"ports": "open"}),
                            ModuleStep("shodan_enrich", {})])]
    out, changed = monkeyx._apply_sweep_toggle(steps, True)
    assert not changed and out is steps


def test_sweep_toggle_off_drops_masscan_and_flips_nmap():
    import monkeyx
    steps = [ModuleStep("ax_masscan", {"ports": "all"}),
             ParallelGroup([ModuleStep("ax_nmap_tcp", {"ports": "open"}),
                            ModuleStep("shodan_enrich", {})]),
             ModuleStep("ax_httpx", {})]
    out, changed = monkeyx._apply_sweep_toggle(steps, False)
    assert changed
    names = [s.name if isinstance(s, ModuleStep) else "group" for s in out]
    assert "ax_masscan" not in names                      # sweep dropped
    group = next(s for s in out if isinstance(s, ParallelGroup)) if any(isinstance(s, ParallelGroup) for s in out) else None
    nmap = next(m for m in group.steps if m.name == "ax_nmap_tcp")
    assert nmap.args["ports"] == monkeyx._SWEEP_OFF_PORTS   # open -> direct top-1000
    assert any(m.name == "shodan_enrich" for m in group.steps)  # siblings kept


def test_sweep_enabled_cli_flag_wins():
    import monkeyx
    class A:  # --no-sweep set
        no_sweep = True
    assert monkeyx._sweep_enabled(A()) is False


def test_member_kwargs_wires_open_ports_and_live_hosts(tmp_path):
    led = _ledger_with_ports(tmp_path)
    data_dir = str(tmp_path)
    step = ModuleStep(name="ax_nmap_tcp", args={"ports": "open"})
    base = {"target": str(tmp_path / "orig-targets.txt"), "scope_filter": "strict"}
    merged = _member_kwargs(step, base, data_dir, ledger=led)
    assert merged.get("ports") == "open"
    assert merged.get("open_ports_list_file", "").endswith("ledger-open-ports-list.txt")
    assert merged.get("target", "").endswith("ledger-live-hosts.host.txt")
    # the wired files actually contain the swept data
    assert sorted(open(merged["open_ports_list_file"]).read().split()) == ["22", "443", "80"]
    assert set(open(merged["target"]).read().split()) == {"1.2.3.4", "5.6.7.8"}
