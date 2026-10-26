"""Connect-scan (-sT) fallback: a SYN scan silently under-reports hosts that
filter/rate-limit SYN probes (or when the fleet nmap lost raw-socket privilege)
— they come back "up" with 0 open ports. Opt-in, ax_nmap_tcp re-scans ONLY those
hosts with a full TCP connect() and folds the recovered ports into the merged XML
so they reach the ledger + downstream service modules in the same run.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import modules.ax_nmap_tcp as tcp
from core import scanning


_XML = """<?xml version="1.0"?><nmaprun>
 <host><status state="up"/><address addr="1.1.1.1" addrtype="ipv4"/>
   <ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host>
 <host><status state="up"/><address addr="2.2.2.2" addrtype="ipv4"/>
   <ports><port protocol="tcp" portid="80"><state state="filtered"/></port></ports></host>
 <host><status state="down"/><address addr="3.3.3.3" addrtype="ipv4"/></host>
</nmaprun>"""

# A completed-but-empty host (has <extraports>) vs a TRUNCATED host (up, no ports,
# no <extraports> — cut off by --host-timeout before tallying).
_XML_TRUNC = """<?xml version="1.0"?><nmaprun>
 <host><status state="up"/><address addr="9.9.9.1" addrtype="ipv4"/>
   <ports><extraports state="filtered" count="65535"/></ports></host>
 <host><status state="up"/><address addr="9.9.9.2" addrtype="ipv4"/></host>
 <host><status state="up"/><address addr="9.9.9.3" addrtype="ipv4"/>
   <ports><port protocol="tcp" portid="443"><state state="open"/></port>
   <extraports state="closed" count="999"/></ports></host>
</nmaprun>"""


def test_hosts_up_without_open_ports(tmp_path):
    p = tmp_path / "m.xml"
    p.write_text(_XML)
    # 1.1.1.1 has an open port; 3.3.3.3 is down; only 2.2.2.2 is up-but-0-open.
    assert scanning.hosts_up_without_open_ports(str(p)) == ["2.2.2.2"]


def test_hosts_scan_truncated(tmp_path):
    p = tmp_path / "t.xml"
    p.write_text(_XML_TRUNC)
    # 9.9.9.1 completed-but-empty (has <extraports>) -> NOT truncated.
    # 9.9.9.2 up, no ports, no <extraports> -> TRUNCATED.
    # 9.9.9.3 has an open port -> NOT truncated.
    assert scanning.hosts_scan_truncated(str(p)) == ["9.9.9.2"]


def _setup(monkeypatch, tmp_path, candidates):
    cmds = []
    monkeypatch.setattr(tcp, "bash_command", lambda cmd, *a, **k: cmds.append(cmd))
    monkeypatch.setattr(tcp, "merge_nmap_folder", lambda *a, **k: {})
    monkeypatch.setattr(tcp, "nmap_to_tcphosts", lambda *a, **k: None)
    monkeypatch.setattr(tcp, "uncovered_ip_targets", lambda *a, **k: [])
    monkeypatch.setattr(tcp, "hosts_up_without_open_ports", lambda *a, **k: candidates)
    prefix = str(tmp_path / "x")
    with open(f"{prefix}-tcpscan.xml", "w") as fh:   # has_output = True
        fh.write("<nmaprun/>")
    return cmds, prefix


def test_fallback_off_by_default(monkeypatch, tmp_path):
    cmds, prefix = _setup(monkeypatch, tmp_path, ["198.18.1.9"])
    tcp.run_ax_nmap_tcp(target="t.txt", prefix=prefix, fleet="f")
    assert len(cmds) == 1 and "-sT" not in cmds[0]   # no retry unless opted in


def test_fallback_runs_when_enabled(monkeypatch, tmp_path):
    cmds, prefix = _setup(monkeypatch, tmp_path, ["198.18.1.9"])
    tcp.run_ax_nmap_tcp(target="t.txt", prefix=prefix, fleet="f", connect_fallback=True)
    assert len(cmds) == 2
    assert "-sS" in cmds[0] and "-sT" in cmds[1]
    assert "tcpscan-retry-targets.txt" in cmds[1]
    assert os.path.exists(f"{prefix}-tcpscan-retry-targets.txt")


def test_fallback_bounded_by_max_hosts(monkeypatch, tmp_path):
    cmds, prefix = _setup(monkeypatch, tmp_path, ["a", "b", "c"])
    tcp.run_ax_nmap_tcp(target="t.txt", prefix=prefix, fleet="f",
                        connect_fallback=True, connect_fallback_max_hosts=2)
    assert len(cmds) == 1   # 3 candidates > cap of 2 -> skipped


def test_fallback_not_rerun_for_sT_primary(monkeypatch, tmp_path):
    cmds, prefix = _setup(monkeypatch, tmp_path, ["198.18.1.9"])
    tcp.run_ax_nmap_tcp(target="t.txt", prefix=prefix, fleet="f",
                        connect_fallback=True, scan_type="sT")
    assert len(cmds) == 1   # primary already -sT; no point re-scanning


def test_truncated_host_raises_warning(monkeypatch, tmp_path):
    cmds, prefix = _setup(monkeypatch, tmp_path, [])
    # A host whose scan was cut off (host-timeout) — no ports collected.
    monkeypatch.setattr(tcp, "hosts_scan_truncated", lambda *a, **k: ["198.18.9.26"])
    res = tcp.run_ax_nmap_tcp(target="t.txt", prefix=prefix, fleet="f")
    assert res["status"] == "warning"
    assert res["truncated_targets"] == ["198.18.9.26"]
    assert "TRUNCATED" in res["warning"] and "198.18.9.26" in res["warning"]
