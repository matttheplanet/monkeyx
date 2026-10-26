"""Degraded-scan detection: a full TCP scan that returns hosts-up-but-no-ports
(broken/blocked fleet nmap) must be flagged, not read as a closed network.

Regression from a real engagement: 1039 hosts "up", 2 open ports total — the
port scan silently collected nothing, and every downstream layer (service
inventory, ssh/smtp/snmp, nuclei service templates) went dark while reports
presented it as a clean, closed surface.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import core.scanning as scanning


def _xml(hosts):
    """hosts = list of (state, [open_port,...]); build a minimal nmap XML."""
    out = ['<?xml version="1.0"?><nmaprun>']
    for i, (state, ports) in enumerate(hosts):
        out.append(f'<host><status state="{state}"/>'
                   f'<address addr="10.0.0.{i}" addrtype="ipv4"/><ports>')
        for p in ports:
            out.append(f'<port portid="{p}"><state state="open"/></port>')
        out.append('</ports></host>')
    out.append('</nmaprun>')
    return "".join(out)


def _write(tmp_path, hosts):
    p = tmp_path / "scan.xml"
    p.write_text(_xml(hosts))
    return str(p)


def test_health_counts(tmp_path):
    path = _write(tmp_path, [("up", [80, 443]), ("up", []), ("down", []), ("up", [22])])
    h = scanning.port_scan_health(path)
    assert h["host_records"] == 4
    assert h["hosts_up"] == 3
    assert h["hosts_with_open_ports"] == 2
    assert h["open_ports"] == 3


def test_degraded_when_hosts_up_but_no_ports(tmp_path):
    # 1000 up, 1 with a port -> the real failure signature.
    hosts = [("up", [80])] + [("up", []) for _ in range(999)]
    h = scanning.port_scan_health(_write(tmp_path, hosts))
    degraded, reason = scanning.port_scan_degraded(h)
    assert degraded is True
    assert "LIKELY INCOMPLETE" in reason


def test_healthy_scan_not_flagged(tmp_path):
    hosts = [("up", [80, 443]) for _ in range(40)]
    h = scanning.port_scan_health(_write(tmp_path, hosts))
    assert scanning.port_scan_degraded(h) == (False, "")


def test_tiny_scope_not_flagged(tmp_path):
    # 3 up, 0 ports — below min_hosts, must not false-alarm.
    h = scanning.port_scan_health(_write(tmp_path, [("up", []), ("up", []), ("up", [])]))
    assert scanning.port_scan_degraded(h)[0] is False


def test_missing_xml_is_safe():
    assert scanning.port_scan_health("/no/such.xml")["hosts_up"] == 0
    assert scanning.port_scan_degraded({"hosts_up": 0, "hosts_with_open_ports": 0})[0] is False
