"""The debrief's Scope table In-Scope column must reflect scan.db's resolved
`in_scope` flag, NOT the ledger's provenance `scope`.

Regression: the discovery-ledger JSONL only records `scope`
(explicit/derived/excluded), so counting `scope != excluded` marked every
DERIVED target in-scope — e.g. a run with 3 explicit -t IPs + 1 derived IP that
resolves out of scope reported "4 total / 4 in-scope" when only 3 were in scope
(and only 3 were scanned). summary now reads scan.db's in_scope.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.target_ledger import TargetLedger, TYPE_IP, TYPE_SUBDOMAIN
from modules import summary


def _build_run(tmp_path):
    output_dir = str(tmp_path / "run")
    os.makedirs(os.path.join(output_dir, "data"))
    t = tmp_path / "t.txt"
    t.write_text("198.18.4.154\n198.18.16.160\n198.18.0.58\n")   # 3 explicit -t IPs
    dom = tmp_path / "dom.txt"
    dom.write_text("example.com\n")
    L = TargetLedger(output_dir)
    L.seed_user_inputs(str(t), str(dom), None)
    L.log_discovery("dev-admin.example.com", TYPE_SUBDOMAIN, "subfinder",
                    parent="example.com")
    # Derived, private (internal-DNS leakage) -> resolves OUT of scope.
    L.log_discovery("192.168.50.25", TYPE_IP, "dnsx_resolve",
                    parent="dev-admin.example.com")
    L.sync_scope_to_db()
    L.export_discovery_ledger()
    L.close()
    return output_dir


def test_in_scope_ip_count_uses_scandb_flag(tmp_path):
    output_dir = _build_run(tmp_path)
    stats = summary._collect_stats(os.path.join(output_dir, "data"), output_dir, [])
    t = stats["targets"]
    assert t["ips_total"] == 4          # 3 explicit + 1 derived, all recorded
    assert t["ips"] == 3                # only the 3 -t IPs resolve in-scope


def test_scope_table_renders_corrected_counts(tmp_path):
    output_dir = _build_run(tmp_path)
    stats = summary._collect_stats(os.path.join(output_dir, "data"), output_dir, [])
    md_path = os.path.join(output_dir, "reports", "summary.md")
    os.makedirs(os.path.dirname(md_path), exist_ok=True)
    summary._write_markdown_report(stats, md_path)
    md = open(md_path).read()
    # Total 4, In-Scope 3 for IPs.
    assert "| IPs | 4 | 3 |" in md


def test_name_derived_public_ip_not_counted_in_scope(tmp_path):
    # A PUBLIC IP derived from a -d subdomain is name-safe (scanned via its
    # hostname, never as a bare IP), so it must NOT count as an in-scope IP —
    # only host-authorized (-t / channel 't') IPs do. Matches the targets view.
    output_dir = str(tmp_path / "run")
    os.makedirs(os.path.join(output_dir, "data"))
    t = tmp_path / "t.txt"
    t.write_text("198.18.4.154\n")                 # 1 explicit -t IP (host-full)
    dom = tmp_path / "dom.txt"
    dom.write_text("example.com\n")
    L = TargetLedger(output_dir)
    L.seed_user_inputs(str(t), str(dom), None)
    L.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder", parent="example.com")
    L.log_discovery("198.18.10.9", TYPE_IP, "dnsx_resolve", parent="api.example.com")
    L.sync_scope_to_db()
    L.export_discovery_ledger()
    L.close()

    stats = summary._collect_stats(os.path.join(output_dir, "data"), output_dir, [])
    assert stats["targets"]["ips_total"] == 2      # -t IP + name-derived IP
    assert stats["targets"]["ips"] == 1            # only the -t IP is host-in-scope
    assert stats["targets"]["subdomains"] == 1     # subdomain stays in-scope (name)
