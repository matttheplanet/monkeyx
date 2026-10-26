"""Regression: a module that completes with status "warning" must still have
its collected discoveries ingested into the ledger.

Real bug: ax_nmap_tcp returned "warning" (some in-scope hosts uncovered) despite
finding 43 open TCP ports on 22 hosts. _extract_discoveries gated ingestion on
status == "success", so every one of those ports was dropped from the ledger and
scan.db — which also starved httpx/nuclei/gowitness/ssh_audit of those targets.
A warning means "results present, with a caveat"; it must not discard the
results that WERE collected. Only "failed"/"skipped" skip ingestion.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import workflows

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="203.0.113.9" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8443">
        <state state="open" reason="syn-ack"/>
        <service name="https-alt" product="nginx" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


class _FakeLedger:
    def __init__(self):
        self.ports = []

    def log_port(self, *, host, port, proto, source_module, **kw):
        self.ports.append((host, port, proto, source_module))


def _write_xml(tmp_path):
    p = tmp_path / "run-tcpscan.xml"
    p.write_text(NMAP_XML)
    return str(p)


def _run(tmp_path, status):
    led = _FakeLedger()
    result = {"status": status, "output_files": [_write_xml(tmp_path)]}
    workflows._extract_discoveries(result, "ax_nmap_tcp", led, str(tmp_path), kwargs={})
    return led


def test_warning_status_still_ingests_ports(tmp_path):
    led = _run(tmp_path, "warning")
    assert ("203.0.113.9", 8443, "tcp", "ax_nmap_tcp") in led.ports


def test_success_status_ingests_ports(tmp_path):
    assert _run(tmp_path, "success").ports


def test_failed_status_drops_ingest(tmp_path):
    assert _run(tmp_path, "failed").ports == []


def test_skipped_status_drops_ingest(tmp_path):
    assert _run(tmp_path, "skipped").ports == []
