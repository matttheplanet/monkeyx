"""A corrupt nmap XML can leak NSE script output (e.g. the multi-line vulners
CVE blob) INTO the service `name` attribute. Observed in a real deep run:
198.18.16.160:445 came back as
    <service name="8E68-...&#x9;9.3&#x9;https://vulners.com/...&#xa;..."
             product="Samba smbd" version="4.19.5-Ubuntu" .../>
so the whole exploit list landed in scan.db's ports.service column and the
report's ports table. Guard: the parse side drops any service `name` that isn't
a plausible short service token; product/version/banner still populate.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.nmap_service_parse import clean_service_name


def test_clean_service_name_keeps_real_tokens():
    for good in ("http", "ssh", "https", "microsoft-ds", "netbios-ssn",
                 "ms-wbt-server", "ssl/https", "ms-sql-s"):
        assert clean_service_name(good) == good


def test_clean_service_name_drops_leaked_script_output():
    blob = ("8E68-8D182C3DAD5C\t9.3\thttps://vulners.com/githubexploit/x\t"
            "*EXPLOIT*\n    \tCVE-2026-35414\t8.1\thttps://vulners.com/cve/x")
    assert clean_service_name(blob) == ""
    assert clean_service_name("") == ""
    assert clean_service_name("a" * 200) == ""
    assert clean_service_name("has space") == ""


_CORRUPT_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="198.18.16.160" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="8E68-X&#x9;9.3&#x9;https://vulners.com/x&#x9;*EXPLOIT*&#xa;    &#x9;CVE-2026-35414" product="Samba smbd" version="4.19.5-Ubuntu" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class _FakeLedger:
    def __init__(self):
        self.calls = []

    def log_port(self, **kwargs):
        self.calls.append(kwargs)


def test_workflows_port_logging_drops_garbage_service(tmp_path):
    from workflows import _log_ports_from_nmap_xml
    xml = tmp_path / "tcpscan.xml"
    xml.write_text(_CORRUPT_XML, encoding="utf-8")
    ledger = _FakeLedger()
    _log_ports_from_nmap_xml(str(xml), "ax_nmap_tcp", ledger)
    assert len(ledger.calls) == 1
    call = ledger.calls[0]
    assert call["service"] == ""                       # garbage dropped
    assert call["product"] == "Samba smbd"             # real fingerprint kept
    assert call["banner"] == "Samba smbd 4.19.5-Ubuntu"


def test_normalize_parse_drops_garbage_service(tmp_path):
    from modules.normalize import _parse_nmap_xml
    xml = tmp_path / "tcpscan.xml"
    xml.write_text(_CORRUPT_XML, encoding="utf-8")
    recs = [r for r in _parse_nmap_xml(str(xml)) if r["type"] == "open_port"]
    assert len(recs) == 1
    assert recs[0]["service"] == ""
    assert recs[0]["product"] == "Samba smbd"
    # title falls back to the port-only form when the service token is gone
    assert recs[0]["title"] == "TCP/445 open"
