"""analyze's "Subdomains discovered" / "Web content hits" summary counts must
come from scan.db (the source of truth), not the per-tool JSONL.

Regression: a real run reported "Subdomains discovered: 0" and "Directory
brute-force hits: 0" while scan.db held 14 subdomains and 45 crawled web_dirs —
because the counters read subfinder-only / ffuf+ferox-only JSONL. subfinder can
produce nothing while dnsx/bbot discover subdomains, and katana/gau crawl content
into web_dirs alongside ffuf/feroxbuster.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import scan_db
from modules import analyze


def _write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def test_counts_come_from_scandb_not_subfinder_ffuf(tmp_path):
    output_dir = tmp_path
    data = output_dir / "data"
    data.mkdir()
    prefix = str(data / "run")

    # A minimal nmap-normalized file so analyze doesn't early-exit; NO subfinder
    # or ffuf/ferox JSONL — exactly the run shape that reported 0/0.
    _write_jsonl(f"{prefix}-nmap-normalized.jsonl", [
        {"tool": "nmap", "type": "open_port", "host": "10.0.0.5", "port": 443,
         "proto": "tcp", "severity": "info", "title": "TCP/443 open"},
    ])

    # scan.db holds subdomains (discovered by dnsx/bbot) and crawled web_dirs.
    db = scan_db.ScanDB(str(output_dir))
    for sub in ("api.example.com", "dev.example.com", "mail.example.com"):
        db.upsert_target(target=sub, target_type="subdomain", scope="derived",
                         in_scope=True)
    db.upsert_web_dir(url="https://api.example.com/login", tool="katana",
                      host="api.example.com")
    db.upsert_web_dir(url="https://api.example.com/admin/", tool="katana",
                      host="api.example.com")
    db.close()

    res = analyze.run_analyze(prefix, data_prefix=prefix)
    assert res["status"] == "success"
    out = json.load(open(res["output_files"][0]))
    summary = out["summary"]
    assert summary["subdomains_discovered"] == 3   # from scan.db, not 0
    assert summary["directory_hits"] == 2          # katana web_dirs, not 0


def test_falls_back_to_jsonl_when_no_scandb(tmp_path):
    output_dir = tmp_path
    data = output_dir / "data"
    data.mkdir()
    prefix = str(data / "run")
    _write_jsonl(f"{prefix}-nmap-normalized.jsonl", [
        {"tool": "nmap", "type": "open_port", "host": "10.0.0.5", "port": 80,
         "proto": "tcp", "severity": "info", "title": "TCP/80 open"},
    ])
    _write_jsonl(f"{prefix}-subfinder-normalized.jsonl", [
        {"tool": "subfinder", "type": "subdomain", "host": "a.example.com"},
        {"tool": "subfinder", "type": "subdomain", "host": "b.example.com"},
    ])
    # No scan.db created -> fall back to the subfinder JSONL count.
    res = analyze.run_analyze(prefix, data_prefix=prefix)
    out = json.load(open(res["output_files"][0]))
    assert out["summary"]["subdomains_discovered"] == 2


def test_port_scan_degraded_banner_from_web_vs_ports(tmp_path):
    """analyze must banner when the web layer proves many live hosts but the
    ports table is ~empty — the silent port-scan-failure signature."""
    output_dir = tmp_path
    data = output_dir / "data"; data.mkdir()
    prefix = str(data / "run")
    # nmap-normalized present but with ~no open ports (the failure shape).
    _write_jsonl(f"{prefix}-nmap-normalized.jsonl", [
        {"tool": "nmap", "type": "open_port", "host": "10.0.0.5", "port": 443,
         "proto": "tcp", "severity": "info", "title": "TCP/443 open"},
    ])
    db = scan_db.ScanDB(str(output_dir))
    # 20 live web hosts, but the ports table stays essentially empty.
    for i in range(20):
        db.upsert_web_endpoint(host=f"h{i}.example.com",
                               url=f"https://h{i}.example.com", port=443,
                               status_code=200)
    db.close()

    res = analyze.run_analyze(prefix, data_prefix=prefix)
    md = open([f for f in res["output_files"] if f.endswith(".md")][0]).read()
    assert "PORT SCAN LIKELY INCOMPLETE" in md
    assert "20 host(s) are live on the web" in md


def test_no_banner_when_ports_healthy(tmp_path):
    output_dir = tmp_path
    data = output_dir / "data"; data.mkdir()
    prefix = str(data / "run")
    _write_jsonl(f"{prefix}-nmap-normalized.jsonl", [
        {"tool": "nmap", "type": "open_port", "host": "10.0.0.5", "port": 443,
         "proto": "tcp", "severity": "info", "title": "TCP/443 open"},
    ])
    db = scan_db.ScanDB(str(output_dir))
    for i in range(5):   # small live count, below the >=10 trigger
        db.upsert_web_endpoint(host=f"h{i}.example.com",
                               url=f"https://h{i}.example.com", port=443,
                               status_code=200)
    db.close()
    res = analyze.run_analyze(prefix, data_prefix=prefix)
    md = open([f for f in res["output_files"] if f.endswith(".md")][0]).read()
    assert "PORT SCAN LIKELY INCOMPLETE" not in md


def test_name_only_scope_note(tmp_path):
    """Domain-only run: in-scope IPs are name-safe (channel 'dl'), no ports —
    analyze must disclose 'no port scan; re-run with -t' (calm note, not the
    degraded alarm)."""
    output_dir = tmp_path
    data = output_dir / "data"; data.mkdir()
    prefix = str(data / "run")
    _write_jsonl(f"{prefix}-nmap-normalized.jsonl", [])   # nmap skipped -> empty
    db = scan_db.ScanDB(str(output_dir))
    for i in range(5):
        db.upsert_target(target=f"10.0.0.{i}", target_type="ip", scope="derived",
                         in_scope=True, channel="dl")     # name-safe only
    db.close()
    res = analyze.run_analyze(prefix, data_prefix=prefix)
    md = open([f for f in res["output_files"] if f.endswith(".md")][0]).read()
    assert "No port scan" in md and "name-only scope" in md
    assert "-t <ips/cidrs>" in md
    assert "RESULTS UNRELIABLE" not in md                 # not the failure alarm


def test_no_scope_note_when_host_full_targets_present(tmp_path):
    output_dir = tmp_path
    data = output_dir / "data"; data.mkdir()
    prefix = str(data / "run")
    _write_jsonl(f"{prefix}-nmap-normalized.jsonl", [])
    db = scan_db.ScanDB(str(output_dir))
    db.upsert_target(target="10.0.0.9", target_type="ip", scope="explicit",
                     in_scope=True, channel="t")          # host-full present
    db.close()
    res = analyze.run_analyze(prefix, data_prefix=prefix)
    md = open([f for f in res["output_files"] if f.endswith(".md")][0]).read()
    assert "name-only scope" not in md
