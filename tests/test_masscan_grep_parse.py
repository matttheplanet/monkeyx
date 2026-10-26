"""ax_masscan now uses the greppable (-oG) variant, not XML, because XML on a
large/all-ports sweep balloons to tens of GB. `_log_ports_from_masscan_grep`
stream-parses the greppable format and applies a per-host tarpit cap so a
SYN-proxy that answers every port doesn't poison the nmap `ports: open` verify
step (or bloat the ledger).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import workflows as wf


class _FakeLedger:
    def __init__(self):
        self.ports = []        # (host, port, proto)
        self.alive = []        # host

    def log_port(self, host, port, proto, source_module=None, **k):
        self.ports.append((host, port, proto))

    def log_discovery(self, host, dtype=None, source_module=None, *a, **k):
        self.alive.append(host)


def _write(tmp_path, body):
    p = tmp_path / "scan-masscan.txt"
    p.write_text(body)
    return str(p)


def test_parses_greppable_open_ports(tmp_path):
    # Real masscan -oG lines are tab-separated and start with Timestamp:, not Host:
    body = (
        "# Masscan 1.3.2 scan initiated\n"
        "Timestamp: 1792527276\tHost: 1.2.3.4 ()\tPorts: 80/open/tcp//http//\n"
        "Timestamp: 1792527276\tHost: 1.2.3.4 ()\tPorts: 443/open/tcp//https//\n"
        "Timestamp: 1792527277\tHost: 5.6.7.8 ()\tPorts: 53/open/udp//domain//\n"
        "# end\n"
    )
    led = _FakeLedger()
    wf._log_ports_from_masscan_grep(_write(tmp_path, body), "ax_masscan", led)
    assert set(led.ports) == {
        ("1.2.3.4", 80, "tcp"),
        ("1.2.3.4", 443, "tcp"),
        ("5.6.7.8", 53, "udp"),
    }
    # both hosts logged alive
    assert set(led.alive) == {"1.2.3.4", "5.6.7.8"}


def test_ignores_closed_and_malformed(tmp_path):
    body = (
        "Timestamp: 1\tHost: 1.1.1.1 ()\tPorts: 22/closed/tcp//ssh//\n"
        "Timestamp: 1\tHost: 1.1.1.1 ()\tPorts: 22/open/tcp//ssh//\n"
        "garbage line\n"
        "Timestamp: 1\tHost: 1.1.1.1 ()\tno-ports-field-here\n"
    )
    led = _FakeLedger()
    wf._log_ports_from_masscan_grep(_write(tmp_path, body), "ax_masscan", led)
    assert led.ports == [("1.1.1.1", 22, "tcp")]


def test_tarpit_host_ports_dropped_but_still_alive(tmp_path):
    cap = wf._MASSCAN_TARPIT_PORT_CAP
    lines = ["Timestamp: 1\tHost: 9.9.9.9 ()\tPorts: %d/open/tcp//x//\n" % p
             for p in range(1, cap + 50)]
    # a normal host alongside the tarpit must survive untouched
    lines.append("Timestamp: 1\tHost: 2.2.2.2 ()\tPorts: 80/open/tcp//http//\n")
    led = _FakeLedger()
    wf._log_ports_from_masscan_grep(_write(tmp_path, "".join(lines)), "ax_masscan", led)
    # tarpit host: NO ports ingested
    assert all(host != "9.9.9.9" for host, _, _ in led.ports)
    # normal host: kept
    assert ("2.2.2.2", 80, "tcp") in led.ports
    # tarpit still recorded as alive (honest coverage)
    assert "9.9.9.9" in led.alive


def test_missing_file_is_safe(tmp_path):
    led = _FakeLedger()
    wf._log_ports_from_masscan_grep(str(tmp_path / "nope.txt"), "ax_masscan", led)
    assert led.ports == [] and led.alive == []


def test_cap_is_config_overridable(tmp_path, monkeypatch):
    import core.config as cfg
    monkeypatch.setattr(cfg, "load_scan_config", lambda: {"masscan_tarpit_port_cap": 2})
    body = "".join("Timestamp: 1\tHost: 3.3.3.3 ()\tPorts: %d/open/tcp//x//\n" % p
                   for p in (80, 443, 8080))  # 3 ports > cap of 2 -> tarpit
    led = _FakeLedger()
    wf._log_ports_from_masscan_grep(_write(tmp_path, body), "ax_masscan", led)
    assert all(host != "3.3.3.3" for host, _, _ in led.ports)
    assert "3.3.3.3" in led.alive


def test_cap_zero_disables_guard(tmp_path, monkeypatch):
    import core.config as cfg
    monkeypatch.setattr(cfg, "load_scan_config", lambda: {"masscan_tarpit_port_cap": 0})
    body = "".join("Timestamp: 1\tHost: 4.4.4.4 ()\tPorts: %d/open/tcp//x//\n" % p
                   for p in range(1, 2000))  # huge, but guard off -> all kept
    led = _FakeLedger()
    wf._log_ports_from_masscan_grep(_write(tmp_path, body), "ax_masscan", led)
    assert len([1 for host, _, _ in led.ports if host == "4.4.4.4"]) == 1999


def test_parser_returns_stats(tmp_path):
    body = (
        "Timestamp: 1\tHost: 1.1.1.1 ()\tPorts: 80/open/tcp//http//\n"
        "Timestamp: 1\tHost: 1.1.1.1 ()\tPorts: 443/open/tcp//https//\n"
    )
    led = _FakeLedger()
    stats = wf._log_ports_from_masscan_grep(_write(tmp_path, body), "ax_masscan", led)
    assert stats == {"ingested": 2, "tarpits": 0, "hosts": 1}


# --- run-level warning escalation via _extract_discoveries -------------------

def _masscan_result(txt_path):
    return {"module": "ax_masscan", "status": "success", "output_files": [txt_path]}


def test_mass_tarpit_sweep_escalates_to_warning(tmp_path, monkeypatch):
    import core.config as cfg
    monkeypatch.setattr(cfg, "load_scan_config", lambda: {"masscan_tarpit_port_cap": 2})
    # one host, 3 ports > cap 2 -> tarpit -> 0 usable ingested
    body = "".join("Timestamp: 1\tHost: 7.7.7.7 ()\tPorts: %d/open/tcp//x//\n" % p
                   for p in (80, 443, 8080))
    p = _write(tmp_path, body)
    result = _masscan_result(p)
    wf._extract_discoveries(result, "ax_masscan", _FakeLedger(), str(tmp_path / "pfx"))
    assert result["status"] == "warning"
    assert "0 usable" in result["warning"]


def test_partial_tarpit_sweep_warns_but_keeps_ports(tmp_path, monkeypatch):
    import core.config as cfg
    monkeypatch.setattr(cfg, "load_scan_config", lambda: {"masscan_tarpit_port_cap": 2})
    body = (
        # tarpit host (3 ports > cap)
        "Timestamp: 1\tHost: 7.7.7.7 ()\tPorts: 80/open/tcp//x//\n"
        "Timestamp: 1\tHost: 7.7.7.7 ()\tPorts: 443/open/tcp//x//\n"
        "Timestamp: 1\tHost: 7.7.7.7 ()\tPorts: 8080/open/tcp//x//\n"
        # clean host
        "Timestamp: 1\tHost: 8.8.8.8 ()\tPorts: 22/open/tcp//ssh//\n"
    )
    result = _masscan_result(_write(tmp_path, body))
    led = _FakeLedger()
    wf._extract_discoveries(result, "ax_masscan", led, str(tmp_path / "pfx"))
    assert result["status"] == "warning"
    assert ("8.8.8.8", 22, "tcp") in led.ports      # clean host kept
    assert all(h != "7.7.7.7" for h, _, _ in led.ports)


def test_clean_sweep_stays_success(tmp_path):
    body = (
        "Timestamp: 1\tHost: 8.8.8.8 ()\tPorts: 22/open/tcp//ssh//\n"
        "Timestamp: 1\tHost: 9.9.9.9 ()\tPorts: 443/open/tcp//https//\n"
    )
    result = _masscan_result(_write(tmp_path, body))
    wf._extract_discoveries(result, "ax_masscan", _FakeLedger(), str(tmp_path / "pfx"))
    assert result["status"] == "success"
    assert "warning" not in result
