"""NSE script output must be ONE row per script per host:port, not one per elem.

Regression for the ssl-cert fan-out: nmap's structured <table>/<elem> tree for a
single certificate (subject fields, each X509 extension's name/value/critical,
key params, ...) was emitted as a separate script_output record per leaf elem.
One real scan produced 13,375 ssl-cert rows from 394 open ports — a single
cert exploded into ~280 fragment rows. Each script result is ONE logical
finding; we now emit one record carrying the script's full `output` text.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import defusedxml.ElementTree as ET

from modules.normalize import _emit_script_records, _parse_nmap_xml


_SSL_CERT_SCRIPT = """
<script id="ssl-cert" output="Subject: commonName=example.com/organizationName=Example Inc&#10;Issuer: commonName=CA&#10;Public Key type: rsa&#10;Not valid after: 2033-01-01">
  <table key="subject">
    <elem key="commonName">example.com</elem>
    <elem key="organizationName">Example Inc</elem>
    <elem key="countryName">US</elem>
  </table>
  <table key="issuer">
    <elem key="commonName">CA</elem>
  </table>
  <table key="extensions">
    <table>
      <elem key="name">X509v3 Key Usage</elem>
      <elem key="value">Digital Signature</elem>
      <elem key="critical">true</elem>
    </table>
    <table>
      <elem key="name">X509v3 Basic Constraints</elem>
      <elem key="value">CA:FALSE</elem>
    </table>
  </table>
</script>
"""


def test_ssl_cert_emits_single_record():
    script_el = ET.fromstring(_SSL_CERT_SCRIPT)
    records = []
    _emit_script_records(records, script_el, "1.2.3.4", "example.com", 443, "tcp",
                         "scan.xml")
    # Exactly one row for the whole certificate — not one per <elem>.
    assert len(records) == 1
    rec = records[0]
    assert rec["type"] == "script_output"
    assert rec["method"] == "ssl-cert"
    assert rec["host"] == "1.2.3.4" and rec["port"] == 443
    # The full human-readable output is preserved for downstream substring search.
    assert "commonName=example.com" in rec["detail"]
    assert "Not valid after" in rec["detail"]


def test_fallback_reconstructs_from_elems_when_no_output_attr():
    # A script with no `output` attribute must still yield ONE row, rebuilt from
    # its elems, not one row per elem.
    xml = (
        '<script id="custom-script">'
        '<elem key="a">1</elem><elem key="b">2</elem><elem>bare</elem>'
        '</script>'
    )
    script_el = ET.fromstring(xml)
    records = []
    _emit_script_records(records, script_el, "1.2.3.4", None, 80, "tcp", "scan.xml")
    assert len(records) == 1
    assert records[0]["detail"] == "a=1; b=2; bare"


def test_empty_script_emits_nothing():
    script_el = ET.fromstring('<script id="empty" output=""></script>')
    records = []
    _emit_script_records(records, script_el, "1.2.3.4", None, 80, "tcp", "scan.xml")
    assert records == []


def test_prefers_ipv4_address_over_mac(tmp_path):
    # A host whose FIRST <address> is a MAC must still be keyed by its IPv4 addr.
    # The old `a or b` idiom always fell through to the first address because an
    # <address> leaf element is falsy.
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    p = tmp_path / "tcp.xml"
    p.write_text(xml)
    records = _parse_nmap_xml(str(p))
    assert records
    assert all(r["host"] == "1.2.3.4" for r in records)


def test_full_host_xml_one_row_per_script(tmp_path):
    # End-to-end through _parse_nmap_xml: a host with one open port carrying two
    # scripts yields one open_port row + exactly two script_output rows.
    xml = f"""<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <hostnames><hostname name="example.com"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" tunnel="ssl"/>
        {_SSL_CERT_SCRIPT}
        <script id="http-title" output="Example Domain"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    p = tmp_path / "tcp.xml"
    p.write_text(xml)
    records = _parse_nmap_xml(str(p))
    by_type = {}
    for r in records:
        by_type.setdefault(r["type"], []).append(r)
    assert len(by_type.get("open_port", [])) == 1
    # Two scripts -> two rows (not ~280).
    assert len(by_type.get("script_output", [])) == 2
    methods = sorted(r["method"] for r in by_type["script_output"])
    assert methods == ["http-title", "ssl-cert"]


# --- State-aware NSE classification (vuln vs context) --------------------- #

from modules.normalize import _classify_nse_script, _nse_vuln_state


def _script(xml):
    return ET.fromstring(xml)


class TestNseClassification:
    def test_vulnerable_state_becomes_vulnerability(self):
        s = _script('<script id="ssl-ccs-injection" output="VULNERABLE">'
                    '<table key="CVE-2014-0224"><elem key="state">VULNERABLE</elem>'
                    '</table></script>')
        assert _nse_vuln_state(s) == "VULNERABLE"
        assert _classify_nse_script(s) == ("vulnerability", "medium")

    def test_likely_vulnerable_is_low(self):
        s = _script('<script id="http-slowloris-check" output="x">'
                    '<table><elem key="state">LIKELY VULNERABLE</elem></table></script>')
        assert _classify_nse_script(s) == ("vulnerability", "low")

    def test_not_vulnerable_stays_info(self):
        # A vuln script that CLEARED the host must NOT become a finding.
        s = _script('<script id="ssl-ccs-injection" output="Not vulnerable">'
                    '<table><elem key="state">NOT VULNERABLE</elem></table></script>')
        assert _nse_vuln_state(s) == "NOT VULNERABLE"
        assert _classify_nse_script(s) == ("script_output", "info")

    def test_no_state_elem_is_info_context(self):
        # Pure-info scripts (ssl-cert, http-title) carry no state elem -> context.
        s = _script('<script id="ssl-cert" output="Subject: commonName=x"/>')
        assert _nse_vuln_state(s) is None
        assert _classify_nse_script(s) == ("script_output", "info")

    def test_emit_marks_vulnerability_record(self):
        recs = []
        s = _script('<script id="http-vuln-cve2011-3192" output="Apache DoS">'
                    '<table><elem key="state">VULNERABLE</elem></table></script>')
        _emit_script_records(recs, s, "1.2.3.4", None, 80, "tcp", "x.xml")
        assert len(recs) == 1
        r = recs[0]
        assert r["type"] == "vulnerability"
        assert r["severity"] == "medium"
        assert r["nse_state"] == "VULNERABLE"
        assert "http-vuln-cve2011-3192" in r["title"]

    def test_emit_info_script_has_no_nse_state(self):
        recs = []
        s = _script('<script id="http-title" output="Example Domain"/>')
        _emit_script_records(recs, s, "1.2.3.4", None, 80, "tcp", "x.xml")
        assert recs[0]["type"] == "script_output"
        assert recs[0]["severity"] == "info"
        assert "nse_state" not in recs[0]
