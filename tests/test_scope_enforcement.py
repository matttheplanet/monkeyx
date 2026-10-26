"""End-to-end enforcement tests for the input-channel scope model.

These exercise the real workflow regeneration + per-module remap so the
security boundary is proven where it actually runs, not just in the ledger unit.

Core invariants:
  - A -d-only derived host NEVER appears in a HOST-class module's target file.
  - A -d name resolving into a -t range DOES (ownership promotion).
  - NAME-class modules still see the full in-scope name set (no over-restriction).
  - Exclusions beat everything.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import workflows
from core.target_ledger import (
    TargetLedger, TYPE_IP, TYPE_DOMAIN, TYPE_SUBDOMAIN,
)


def _seed(tmp_path, targets=None, domains=None, urls=None, ip_scope="provenance"):
    tf = df = uf = None
    if targets is not None:
        tf = tmp_path / "t.txt"; tf.write_text("\n".join(targets) + "\n")
    if domains is not None:
        df = tmp_path / "d.txt"; df.write_text("\n".join(domains) + "\n")
    if urls is not None:
        uf = tmp_path / "u.txt"; uf.write_text("\n".join(urls) + "\n")
    led = TargetLedger(str(tmp_path))
    led.set_ip_scope_mode(ip_scope)
    led.seed_user_inputs(str(tf) if tf else None,
                         str(df) if df else None,
                         str(uf) if uf else None)
    return led


def _regen(led, tmp_path):
    """Run the real regeneration; return base_kwargs it populated."""
    base = {"prefix": "scan", "data_prefix": str(tmp_path / "scan")}
    workflows._regenerate_target_files(led, base, str(tmp_path), "strict")
    return base


def _read(path):
    if not os.path.exists(path):
        return []
    return [l.strip() for l in open(path) if l.strip()]


def _host_target_lines(module, base, tmp_path):
    """What `module` actually receives as its `target` file after gating."""
    kw = workflows._host_scoped_kwargs(module, base, str(tmp_path))
    return _read(kw.get("target", ""))


# NOTE: RFC5737 doc ranges (198.51.100/24, 203.0.113/24) are is_private=True in
# Python's ipaddress, so the private-IP filter drops them. These tests use
# genuinely-global addresses (93.184.216.x, 192.0.66.0/24) so the export path
# behaves as it would for real public targets.

def test_dl_only_host_excluded_from_host_module(tmp_path):
    led = _seed(tmp_path, domains=["example.com"])
    led.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                      parent="example.com")
    led.log_discovery("93.184.216.50", TYPE_IP, "dns_resolve",
                      parent="api.example.com")
    base = _regen(led, tmp_path)

    # HOST-class (nmap) must NOT see the dl-derived host/IP.
    nmap_lines = _host_target_lines("ax_nmap_tcp", base, tmp_path)
    assert "93.184.216.50" not in nmap_lines
    assert "api.example.com" not in nmap_lines
    # With only dl input, the host-scoped target file is empty.
    assert nmap_lines == []


def test_name_module_sees_dl_host(tmp_path):
    led = _seed(tmp_path, domains=["example.com"])
    led.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                      parent="example.com")
    led.log_discovery("93.184.216.50", TYPE_IP, "dns_resolve",
                      parent="api.example.com")
    base = _regen(led, tmp_path)

    # NAME-class (dnsx_resolve) is NOT remapped — sees the normal target file.
    kw = workflows._host_scoped_kwargs("dnsx_resolve", base, str(tmp_path))
    assert kw.get("target") == base.get("target")
    assert "api.example.com" in _read(kw["target"])


def test_dl_name_resolving_into_t_range_is_host_scanned(tmp_path):
    """Ownership promotion: a -d name whose IP lands in a -t CIDR is fully
    authorized, so a host module may scan it."""
    led = _seed(tmp_path, targets=["192.0.66.0/24"], domains=["example.com"])
    led.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                      parent="example.com")
    led.log_discovery("192.0.66.50", TYPE_IP, "dns_resolve",
                      parent="api.example.com")
    base = _regen(led, tmp_path)

    nmap_lines = _host_target_lines("ax_nmap_tcp", base, tmp_path)
    # The host is in -t space, so it is scannable (exported as the hostname).
    assert "api.example.com" in nmap_lines or "192.0.66.50" in nmap_lines


def test_t_host_always_scanned(tmp_path):
    led = _seed(tmp_path, targets=["host.example.com"])
    led.log_discovery("93.184.216.7", TYPE_IP, "dns_resolve",
                      parent="host.example.com")
    base = _regen(led, tmp_path)
    nmap_lines = _host_target_lines("ax_nmap_tcp", base, tmp_path)
    # Host-class scans collapse to unique IPs, so a resolved -t host is scanned
    # via its IP (not once per hostname); an unresolved one would fall back to
    # the name. Either way it is always represented.
    assert "93.184.216.7" in nmap_lines or "host.example.com" in nmap_lines


def test_exclusion_beats_t(tmp_path):
    led = _seed(tmp_path, targets=["93.184.216.5", "93.184.216.6"])
    excl = tmp_path / "x.txt"; excl.write_text("93.184.216.5\n")
    led.seed_exclusions(str(excl))
    base = _regen(led, tmp_path)
    nmap_lines = _host_target_lines("ax_nmap_tcp", base, tmp_path)
    assert "93.184.216.5" not in nmap_lines
    assert "93.184.216.6" in nmap_lines


def test_passive_module_not_remapped(tmp_path):
    led = _seed(tmp_path, domains=["example.com"])
    base = _regen(led, tmp_path)
    kw = workflows._host_scoped_kwargs("normalize", base, str(tmp_path))
    assert kw.get("target") == base.get("target")


def test_shodan_enrich_host_gated(tmp_path):
    """shodan_enrich is HOST-class (bare-IP lookups) — a dl-only IP must not
    reach its target-IP file."""
    led = _seed(tmp_path, domains=["example.com"])
    led.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                      parent="example.com")
    led.log_discovery("93.184.216.77", TYPE_IP, "dns_resolve",
                      parent="api.example.com")
    base = _regen(led, tmp_path)
    kw = workflows._host_scoped_kwargs("shodan_enrich", base, str(tmp_path))
    ip_file = kw.get("target_ips_file", "")
    lines = _read(ip_file)
    assert all("93.184.216.77" not in l for l in lines)
