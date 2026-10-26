"""Tests for the snmp_sweep UDP-port feed.

Bug: export_open_ports was TCP-only, so snmp_sweep (UDP/161) never saw its hosts
and always skipped even when the scan found 161/udp. Fix: a proto-aware export +
a udp_open_ports_file the module reads.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.target_ledger import TargetLedger
import modules.snmp_sweep as snmp


def test_export_open_ports_separates_tcp_and_udp(tmp_path):
    (tmp_path / "t.txt").write_text("198.18.10.10\n")
    led = TargetLedger(str(tmp_path))
    led.seed_user_inputs(str(tmp_path / "t.txt"), None, None)
    led.log_port("198.18.10.10", 80, "tcp", "ax_nmap_tcp")
    led.log_port("198.18.10.10", 161, "udp", "ax_nmap_udp")

    tcp_out, udp_out = str(tmp_path / "tcp.txt"), str(tmp_path / "udp.txt")
    led.export_open_ports(tcp_out, "none")                       # default proto = tcp
    led.export_open_ports(udp_out, "none", proto_filter="udp")

    tcp, udp = open(tcp_out).read(), open(udp_out).read()
    assert "80" in tcp and "161" not in tcp     # TCP file: no UDP 161
    assert "161" in udp and "80" not in udp     # UDP file: the SNMP port


class _AllInScope:
    def contains(self, host):
        return True


def _patch_runners(monkeypatch, response_by_community):
    monkeypatch.setattr(snmp.tool_runners, "load_scope", lambda target, prefix: _AllInScope())
    monkeypatch.setattr(snmp.tool_runners, "tool_available", lambda name: True)
    monkeypatch.setattr(snmp.tool_runners, "snmp_walk",
                        lambda host, community: response_by_community.get(community, ""))


def test_snmp_sweep_reads_udp_file(tmp_path, monkeypatch):
    udp_file = tmp_path / "ledger-open-ports-udp.txt"
    udp_file.write_text("198.18.10.10\t161\n")
    _patch_runners(monkeypatch, {"public": "iso.3.6.1.2.1.1.1.0 = STRING: Test Router"})

    pfx = str(tmp_path / "scan")
    res = snmp.run_snmp_sweep(prefix=pfx, data_prefix=pfx, udp_open_ports_file=str(udp_file))

    assert res["status"] == "success"
    assert res["findings"] == 1
    out = f"{pfx}-snmp-sweep.jsonl"
    assert os.path.exists(out)
    rec = json.loads(open(out).read().splitlines()[0])
    assert rec["port"] == 161 and rec["proto"] == "udp"


def test_snmp_sweep_reads_udp_snmp_hosts_file(tmp_path, monkeypatch):
    # The UDP scan's purpose-built list ({prefix}-udp-snmp-hosts.txt, "ip:port")
    # is authoritative even when the ledger port export missed the UDP port.
    pfx = str(tmp_path / "scan")
    (tmp_path / "scan-udp-snmp-hosts.txt").write_text("198.18.10.10:161\n")
    _patch_runners(monkeypatch, {"public": "iso.3.6.1.2.1.1.1.0 = STRING: Test Router"})

    res = snmp.run_snmp_sweep(prefix=pfx, data_prefix=pfx)  # no ledger port file at all

    assert res["status"] == "success"
    assert res["findings"] == 1
    rec = json.loads(open(f"{pfx}-snmp-sweep.jsonl").read().splitlines()[0])
    assert rec["host"] == "198.18.10.10" and rec["port"] == 161


def test_community_override_from_config(tmp_path, monkeypatch):
    # A custom community not in the built-in defaults is tried when supplied via
    # the `communities` override (list or CSV), and its response is flagged.
    udp_file = tmp_path / "ledger-open-ports-udp.txt"
    udp_file.write_text("198.18.10.10\t161\n")
    tried = []
    monkeypatch.setattr(snmp.tool_runners, "load_scope",
                        lambda target, prefix: _AllInScope())
    monkeypatch.setattr(snmp.tool_runners, "tool_available", lambda name: True)

    def _walk(host, community):
        tried.append(community)
        return "iso.3.6.1.2.1.1.1.0 = STRING: X" if community == "s3cret" else ""
    monkeypatch.setattr(snmp.tool_runners, "snmp_walk", _walk)

    pfx = str(tmp_path / "scan")
    res = snmp.run_snmp_sweep(prefix=pfx, data_prefix=pfx,
                              udp_open_ports_file=str(udp_file),
                              communities="s3cret")
    assert res["findings"] == 1
    assert tried == ["s3cret"]   # only the override tried, not the 19 defaults


def test_tcp_only_file_still_skips(tmp_path, monkeypatch):
    # Regression: the TCP open-ports file never carries 161, so with only that
    # file (no udp variant) snmp_sweep correctly finds nothing and skips.
    tcp_file = tmp_path / "ledger-open-ports.txt"
    tcp_file.write_text("198.18.10.10\t80,443\n")
    _patch_runners(monkeypatch, {"public": "iso.3.6.1.2.1.1.1.0 = STRING: x"})

    pfx = str(tmp_path / "scan")
    res = snmp.run_snmp_sweep(prefix=pfx, data_prefix=pfx, open_ports_file=str(tcp_file))
    assert res["status"] == "skipped"
