"""Service-vs-portscan reconciliation: when a scanner (nuclei) reaches a service
on host:port the TCP port scan never reported — on a host-full (`-t`) target —
the port scan is incomplete for that host (SYN filtering / rate-limiting), which
makes its findings non-deterministic across runs. analyze must surface that.

Real case: example.com -> 198.18.1.9 (a `-t` target). nmap found 0 open TCP
ports on it, yet nuclei found ssh/ftp/redis/smb/smtp there in one run and nothing
in the next (90 -> 35 findings). Scope/commands were identical; the host filters.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import scan_db
from modules import analyze


def _seed_db(output_dir):
    db = scan_db.ScanDB(str(output_dir))
    # Two host-full (-t) in-scope IPs.
    db.upsert_target(target="198.18.1.9", target_type="ip", in_scope=True, channel="t")
    db.upsert_target(target="198.18.9.26", target_type="ip", in_scope=True, channel="t")
    # A name-only (resolved) IP that is NOT port-scanned by design.
    db.upsert_target(target="10.9.9.9", target_type="ip", in_scope=True, channel="dl")
    # Ports the scan DID report: 45.77 only has UDP/161; 207.148 has TCP/8080.
    db.upsert_port(host="198.18.1.9", port=161, proto="udp", state="open")
    db.upsert_port(host="198.18.9.26", port=8080, proto="tcp", state="open")
    # hostname -> IP mapping (dnsx re-logs the IP with the hostname as a parent).
    db.replace_target_parents("198.18.1.9", "ip", ["example.com"])
    db.replace_target_parents("10.9.9.9", "ip", ["name-only.example"])
    db.close()


def test_helper_flags_only_unscanned_hostfull_ports(tmp_path):
    _seed_db(tmp_path)
    nuclei = [
        {"matched_at": "example.com:6379", "template_id": "exposed-redis"},
        {"matched_at": "example.com:22", "template_id": "openssh-detect"},
        {"matched_at": "example.com:161", "template_id": "snmpv1-detect"},   # in ports (udp) -> skip
        {"matched_at": "http://198.18.9.26:8080", "template_id": "tech-detect"},  # scanned -> skip
        {"matched_at": "http://example.com", "template_id": "waf-detect"},    # no explicit port -> skip
        {"matched_at": "name-only.example:3306", "template_id": "mysql-detect"},  # not host-full -> skip
    ]
    db = scan_db.open_db(str(tmp_path))
    try:
        missed = analyze._services_outside_portscan(nuclei, db._conn, scan_db)
    finally:
        db.close(checkpoint=False)
    assert missed == {"198.18.1.9": [22, 6379]}


def test_parse_explicit_host_port():
    assert analyze._parse_explicit_host_port("example.com:6379") == ("example.com", 6379)
    assert analyze._parse_explicit_host_port("http://10.0.0.1:3000/x") == ("10.0.0.1", 3000)
    assert analyze._parse_explicit_host_port("http://host") == (None, None)   # no explicit port
    assert analyze._parse_explicit_host_port("") == (None, None)


def test_run_analyze_sets_note_and_banner(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    prefix = str(data / "run")
    _seed_db(tmp_path)
    with open(f"{prefix}-nmap-normalized.jsonl", "w") as fh:
        fh.write(json.dumps({"tool": "nmap", "type": "open_port", "host": "198.18.9.26",
                             "port": 8080, "proto": "tcp", "severity": "info"}) + "\n")
    with open(f"{prefix}-nuclei-normalized.jsonl", "w") as fh:
        for r in [{"tool": "nuclei", "type": "finding", "host": "example.com",
                   "matched_at": "example.com:6379", "template_id": "exposed-redis",
                   "severity": "high"},
                  {"tool": "nuclei", "type": "finding", "host": "example.com",
                   "matched_at": "example.com:21", "template_id": "ftp-anon",
                   "severity": "medium"}]:
            fh.write(json.dumps(r) + "\n")

    res = analyze.run_analyze(prefix, data_prefix=prefix)
    assert res["status"] == "success"
    out = json.load(open(res["output_files"][0]))
    note = out["metadata"]["port_scan_incomplete_note"]
    assert note and "198.18.1.9" in note and "21" in note and "6379" in note

    md = open(f"{prefix.replace('/data/', '/reports/')}-analysis.md").read() \
        if os.path.exists(f"{prefix.replace('/data/', '/reports/')}-analysis.md") else ""
    # analyze writes the report next to reports_prefix; fall back to scanning any .md
    if not md:
        import glob
        for p in glob.glob(str(tmp_path / "**" / "*-analysis.md"), recursive=True):
            md = open(p).read()
    assert "Port-scan coverage gap" in md


def test_records_scanner_ports_into_inventory(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    prefix = str(data / "run")
    # Seed: host-full IP with a REAL nmap port (source nmap) + a hostname->IP map.
    db = scan_db.ScanDB(str(tmp_path))
    db.upsert_target(target="198.18.1.9", target_type="ip", in_scope=True, channel="t")
    db.upsert_port(host="198.18.1.9", port=8080, proto="tcp", state="open",
                   service="http-proxy", source="nmap")
    db.replace_target_parents("198.18.1.9", "ip", ["example.com"])
    # An httpx live endpoint on a port nmap never recorded (via the hostname).
    db.upsert_web_endpoint(host="example.com", url="https://example.com",
                           port=443, scheme="https", status_code=200)
    db.close()

    with open(f"{prefix}-nmap-normalized.jsonl", "w") as fh:
        fh.write(json.dumps({"tool": "nmap", "type": "open_port", "host": "198.18.1.9",
                             "port": 8080, "proto": "tcp", "severity": "info"}) + "\n")
    with open(f"{prefix}-nuclei-normalized.jsonl", "w") as fh:
        for r in [{"tool": "nuclei", "type": "finding", "host": "example.com",
                   "matched_at": "example.com:6379", "template_id": "exposed-redis",
                   "severity": "high"},
                  {"tool": "nuclei", "type": "finding", "host": "example.com",
                   "matched_at": "example.com:8080", "template_id": "tech-detect",
                   "severity": "info"}]:  # 8080 already in ports -> must NOT duplicate/clobber
            fh.write(json.dumps(r) + "\n")

    res = analyze.run_analyze(prefix, data_prefix=prefix)
    assert res["status"] == "success"

    db = scan_db.open_db(str(tmp_path))
    try:
        rows = {(h, p): (svc, src) for h, p, svc, src in db._conn.execute(
            "SELECT host, port, service, source FROM ports").fetchall()}
    finally:
        db.close(checkpoint=False)

    # nuclei-found redis:6379 recorded, tagged + service-hinted.
    assert rows[("198.18.1.9", 6379)] == ("redis", "nuclei")
    # httpx live endpoint 443 recorded via hostname->IP mapping.
    assert rows[("198.18.1.9", 443)] == ("https", "httpx")
    # Pre-existing nmap port NOT clobbered (nuclei also "saw" 8080).
    assert rows[("198.18.1.9", 8080)] == ("http-proxy", "nmap")
