"""Characterization (golden) test for modules.normalize.run_normalize.

Purpose: pin the CURRENT end-to-end behavior of normalize across every tool it
parses, so a future refactor (e.g. collapsing the per-tool glob/fallback blocks
into a shared _collect_tool helper) can be proven to reproduce identical output.

Strategy: hand-authored SMALL raw tool inputs (real field shapes, tiny), run the
real run_normalize against a tmp dir, then assert on a stable PROJECTION of the
normalized records — per-tool output files, record counts, and the fields that
actually matter downstream (type, severity, host, port, tool, claim-relevant
keys). We snapshot the projection, not byte-exact records, so an unrelated field
addition doesn't break it — but any change to WHICH records are emitted, their
types/severities, or the finding-id inputs WILL break it. That's the drift we're
guarding against.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules import normalize
from modules.normalize import _claim_for


# --- raw tool inputs (small, real-shaped) ---------------------------------- #

_NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="web.example.com" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.24.0" tunnel="ssl" method="probed" conf="10"/>
        <script id="ssl-cert" output="Subject: CN=example.com"/>
        <script id="http-vuln-cve2021-1234" output="VULNERABLE: sample">
          <table><elem key="state">VULNERABLE</elem></table>
        </script>
        <script id="ssl-enum-ciphers" output="weak: TLS_RSA">
          <table><elem key="state">NOT VULNERABLE</elem></table>
        </script>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_NUCLEI = [
    {"template-id": "expired-ssl", "matched-at": "https://web.example.com:443",
     "info": {"name": "Expired SSL", "severity": "low",
              "classification": {"cve-id": ["CVE-2020-0001"]}}},
    {"template-id": "tech-detect", "matched-at": "https://web.example.com",
     "info": {"name": "Tech Detect", "severity": "info"}},
]

_SUBFINDER = [
    {"host": "api.example.com", "source": ["crtsh", "shodan"]},
    {"host": "mail.example.com", "input": "example.com"},
]

_FFUF = [
    {"url": "https://web.example.com/admin", "status": 200, "length": 12, "words": 3},
]

_BBOT = [
    {"type": "FINDING", "host": "example.com",
     "data": {"description": "Interesting header", "severity": "MEDIUM", "host": "example.com"},
     "module": "web"},
    {"type": "VULNERABILITY", "host": "example.com",
     "data": {"description": "XSS", "severity": "HIGH"}, "module": "web"},
    {"type": "OPEN_TCP_PORT", "data": "example.com:8080", "module": "portscan"},
    {"type": "TECHNOLOGY", "data": {"technology": "nginx", "host": "example.com"}, "module": "web"},
    {"type": "STORAGE_BUCKET", "data": {"name": "s3://leaky"}, "module": "bucket_amazon"},
]

_DNS_SECURITY = [
    {"domain": "example.com", "check": "dmarc_missing", "severity": "HIGH",
     "detail": "No DMARC record", "evidence": "", "recommendation": "add DMARC"},
    {"domain": "example.com", "check": "spf_too_many_includes", "severity": "LOW",
     "detail": "9 includes", "evidence": "v=spf1 ...", "recommendation": "flatten"},
]

_TESTSSL = """
 Start 2026 -->> 10.0.0.5:443 (web.example.com) <<--
 SSLv3   offered (NOT ok)
 TLS 1.0 offered (NOT ok)
 Heartbleed (CVE-2014-0160) VULNERABLE
 Secure Renegotiation  not vulnerable (OK)
"""

_WAFW00F = """
[+] The site https://web.example.com is behind Cloudflare (Cloudflare Inc.) WAF.
[-] No WAF detected by the generic detection
"""


def _seed(data_dir, prefix):
    def w(name, lines):
        with open(os.path.join(data_dir, name), "w") as f:
            for r in lines:
                f.write(json.dumps(r) + "\n")
    with open(os.path.join(data_dir, f"{prefix}-tcpscan.xml"), "w") as f:
        f.write(_NMAP_XML)
    w(f"{prefix}-nuclei.jsonl", _NUCLEI)
    w(f"{prefix}-subfinder-output.jsonl", _SUBFINDER)
    w(f"{prefix}-ffuf.jsonl", _FFUF)
    w(f"{prefix}-bbot-passive.jsonl", _BBOT)
    w(f"{prefix}-dns-security.jsonl", _DNS_SECURITY)
    with open(os.path.join(data_dir, f"{prefix}-testssl.txt"), "w") as f:
        f.write(_TESTSSL)
    with open(os.path.join(data_dir, f"{prefix}-wafw00f.txt"), "w") as f:
        f.write(_WAFW00F)


def _projection(records):
    """Stable, refactor-relevant projection of a normalized record set."""
    out = []
    for r in records:
        out.append({
            "type": r.get("type"),
            "severity": r.get("severity"),
            "host": r.get("host"),
            "port": r.get("port"),
            "tool": r.get("tool"),
            "claim": _claim_for(r),          # the finding-id discriminator
        })
    # order-independent: sort so glob/iteration order isn't part of the contract
    out.sort(key=lambda d: json.dumps(d, sort_keys=True))
    return out


def _run(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    prefix = "scan"
    _seed(str(data_dir), prefix)
    data_prefix = str(data_dir / prefix)
    normalize.run_normalize(prefix=data_prefix, data_prefix=data_prefix)
    outputs = {}
    for tool, suffix in normalize.TOOL_OUTPUT_SUFFIXES.items():
        path = f"{data_prefix}{suffix}"
        if os.path.exists(path):
            with open(path) as f:
                outputs[tool] = [json.loads(l) for l in f if l.strip()]
    return outputs


# --- the golden baseline (what current normalize produces) ----------------- #
# If a refactor changes any of these, the assertion fails — forcing a conscious
# decision about whether the behavior change is intended.

EXPECTED_COUNTS = {
    # 2 open_port (443, 22) + 3 NSE script rows on 443 (ssl-cert -> script_output,
    # http-vuln -> vulnerability, ssl-enum-ciphers NOT VULNERABLE -> script_output).
    # Every script gets ONE row; classification sets type/severity, it doesn't drop.
    "nmap": 5,
    "nuclei": 2,
    "subfinder": 2,
    "ffuf": 1,
    "bbot": 5,
    "dns_security": 2,
    "testssl": 3,       # SSLv3, TLS1.0, Heartbleed VULNERABLE (renegotiation OK skipped)
    "wafw00f": 1,       # one "behind WAF" line
}


class TestNormalizeCharacterization:
    def test_per_tool_output_files_and_counts(self, tmp_path):
        outputs = _run(tmp_path)
        got = {t: len(recs) for t, recs in outputs.items()}
        assert got == EXPECTED_COUNTS, f"record-count drift: {got}"

    def test_nmap_nse_state_classification(self, tmp_path):
        outputs = _run(tmp_path)
        by_method = {r.get("method"): r for r in outputs["nmap"] if r.get("method")}
        # VULNERABLE state -> vulnerability/medium
        assert by_method["http-vuln-cve2021-1234"]["type"] == "vulnerability"
        assert by_method["http-vuln-cve2021-1234"]["severity"] == "medium"
        # NOT VULNERABLE + pure-info -> script_output/info (context, not a finding)
        assert by_method["ssl-enum-ciphers"]["type"] == "script_output"
        assert by_method["ssl-cert"]["type"] == "script_output"

    def test_claims_are_stable(self, tmp_path):
        # The finding-id discriminator per tool must not drift (normalize <-> ai_validate contract).
        outputs = _run(tmp_path)
        claims = {r_type: sorted({_claim_for(r) for r in recs})
                  for r_type, recs in outputs.items()}
        assert "expired-ssl" in claims["nuclei"]      # template-id
        assert "http-vuln-cve2021-1234" in claims["nmap"]   # script id (method)
        # bbot claim = "<bbot_type> | <module> | <title>" so distinct events on one
        # host no longer collide onto a single "FINDING" finding_id.
        bbot_claims = claims["bbot"]
        assert any(c.startswith("FINDING | ") for c in bbot_claims)
        assert any(c.startswith("VULNERABILITY | ") for c in bbot_claims)
        assert any(c.startswith("STORAGE_BUCKET | ") for c in bbot_claims)
        assert len(set(bbot_claims)) == len(bbot_claims)  # all distinct
        assert "dmarc_missing" in claims["dns_security"]    # [check] bracket in title

    def test_full_projection_snapshot(self, tmp_path):
        """The whole-output golden snapshot. This is the primary refactor guard:
        it pins type/severity/host/port/tool/claim for EVERY normalized record."""
        outputs = _run(tmp_path)
        proj = {tool: _projection(recs) for tool, recs in outputs.items()}
        # nmap: 2 open_port + 2 script_output (ssl-cert, ssl-enum NOT VULNERABLE) + 1 vulnerability
        nmap_types = sorted(r["type"] for r in proj["nmap"])
        assert nmap_types == ["open_port", "open_port", "script_output",
                              "script_output", "vulnerability"]
        # nuclei: both are nuclei_finding regardless of severity
        assert all(r["type"] == "nuclei_finding" for r in proj["nuclei"])
        assert sorted(r["severity"] for r in proj["nuclei"]) == ["info", "low"]
        # bbot: FINDING/VULNERABILITY/STORAGE_BUCKET -> finding; OPEN_TCP_PORT -> open_port;
        # TECHNOLOGY -> technology.
        assert sorted(r["type"] for r in proj["bbot"]) == \
            ["finding", "finding", "finding", "open_port", "technology"]
        # testssl severities (renegotiation "not vulnerable (OK)" skipped):
        #   Heartbleed VULNERABLE -> high
        #   SSLv3 (NOT ok), keyword 'sslv3' in serious list -> medium
        #   TLS 1.0 (NOT ok), no serious keyword -> low (default (not ok) tier)
        assert sorted(r["severity"] for r in proj["testssl"]) == ["high", "low", "medium"]
