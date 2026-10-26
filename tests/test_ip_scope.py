"""Tests for the ip_scope authorization gate (provenance vs strict).

Scope has two independent axes: traceability (--scope-filter) and IP
authorization (--ip-scope). A discovered hostname/URL is authorized by NAME;
a discovered BARE IP with no authorized hostname is authorized only if it falls
within the -t IP ranges when --ip-scope=strict. This prevents scanning a shared
/ CDN IP that an in-scope hostname happens to resolve to.

Uses PUBLIC IPs on purpose: RFC1918 AND the TEST-NET documentation ranges
(203.0.113/24, 198.51.100/24, 192.0.2/24) are stripped by the private-IP export
filter before the ip_scope gate runs, so they can't exercise it.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.target_ledger import TargetLedger, TYPE_IP, TYPE_SUBDOMAIN, TYPE_URL


def _read(path):
    with open(path) as f:
        return sorted(line.strip() for line in f if line.strip())


def _seed(tmp_path, mode, targets_text=None, domains_text=None):
    if targets_text is not None:
        (tmp_path / "t.txt").write_text(targets_text)
    if domains_text is not None:
        (tmp_path / "d.txt").write_text(domains_text)
    ledger = TargetLedger(str(tmp_path))
    ledger.set_ip_scope_mode(mode)
    ledger.seed_user_inputs(
        str(tmp_path / "t.txt") if targets_text is not None else None,
        str(tmp_path / "d.txt") if domains_text is not None else None,
        None,
    )
    return ledger


def test_strict_drops_bare_ip_outside_authorized_range(tmp_path):
    ledger = _seed(tmp_path, "strict", targets_text="198.18.10.0/24\n")
    # in-range bare IP (authorized) and out-of-range CDN IP (not), both bare.
    ledger.log_discovery("198.18.10.9", TYPE_IP, "dns_resolve", parent="198.18.10.0/24")
    ledger.log_discovery("104.16.5.5", TYPE_IP, "ax_naabu", parent="198.18.10.0/24")

    out = str(tmp_path / "o.txt")
    ledger.export_targets(out, scope_filter="strict")
    lines = _read(out)
    assert "198.18.10.9" in lines          # inside authorized range -> kept
    assert "104.16.5.5" not in lines      # outside -> dropped under strict


def test_provenance_keeps_bare_ip_outside_range(tmp_path):
    ledger = _seed(tmp_path, "provenance", targets_text="198.18.10.0/24\n")
    ledger.log_discovery("104.16.5.5", TYPE_IP, "ax_naabu", parent="198.18.10.0/24")

    out = str(tmp_path / "o.txt")
    ledger.export_targets(out, scope_filter="strict")
    assert "104.16.5.5" in _read(out)     # legacy behavior: kept


def test_strict_keeps_cidr_discovered_ip_with_nonscope_parent(tmp_path):
    """Fix #1: a bare IP found alive INSIDE a -t CIDR is owned address space.

    nmap/naabu log alive IPs with the target FILE PATH as their parent (not the
    CIDR string), and that file path is not itself an in-scope entry — so the
    parent-chain grant fails and, before the fix, the IP never entered
    _in_scope_ips. Its open ports were then silently dropped from the strict
    host-only export that feeds ssh_audit_scan/snmp_sweep/smtp_security and the
    targeted port re-scans. The _ip_in_t_range grant fixes it; an IP OUTSIDE the
    range is still dropped.
    """
    ledger = _seed(tmp_path, "strict", targets_text="198.18.10.0/24\n")
    file_parent = str(tmp_path / "data" / "ledger-targets.txt.host.txt")
    ledger.log_discovery("198.18.10.9", TYPE_IP, "ax_nmap_tcp", parent=file_parent)
    ledger.log_discovery("104.16.5.5", TYPE_IP, "ax_nmap_tcp", parent=file_parent)
    ledger.log_port("198.18.10.9", 22, "tcp", "ax_nmap_tcp", service="ssh")
    ledger.log_port("104.16.5.5", 22, "tcp", "ax_nmap_tcp", service="ssh")

    # The in-range IP is now in-scope; the out-of-range straggler is not.
    assert "198.18.10.9" in ledger._in_scope_ips
    assert "104.16.5.5" not in ledger._in_scope_ips

    out = str(tmp_path / "ports.txt")
    ledger.export_open_ports(out, scope_filter="strict", host_only=True)
    hosts = {line.split("\t")[0] for line in _read(out)}
    assert "198.18.10.9" in hosts        # owned -> ports feed the rescan/audit
    assert "104.16.5.5" not in hosts    # outside -t -> still dropped


def test_named_target_authorized_by_name_regardless_of_ip(tmp_path):
    """A hostname the ledger maps to an out-of-range IP still exports (as the
    hostname) — you're scanning the vhost you were authorized for, not the IP."""
    ledger = _seed(tmp_path, "strict", targets_text="198.18.10.0/24\napi.example.com\n")
    # api.example.com (explicit name) resolves to a CDN IP outside the range.
    ledger.log_discovery("104.16.5.5", TYPE_IP, "dns_resolve", parent="api.example.com")

    out = str(tmp_path / "o.txt")
    ledger.export_targets(out, scope_filter="strict")
    lines = _read(out)
    assert "api.example.com" in lines     # named -> authorized by name
    assert "104.16.5.5" not in lines      # the bare CDN IP itself is not scanned


def test_strict_is_noop_without_authorized_ranges(tmp_path):
    """Domain-only run (no IP ranges in -t): strict has no IP boundary, so a
    discovered bare IP (found by a non-resolve module, no hostname mapping) is
    still exported rather than dropped."""
    ledger = _seed(tmp_path, "strict", domains_text="example.com\n")
    # A bare IP with no hostname mapping (CIDR/None parent) — exports as a bare
    # IP, so it exercises the gate directly rather than substituting a hostname.
    ledger.log_discovery("198.18.10.9", TYPE_IP, "ax_naabu", parent=None)
    assert ledger.get_ip_to_hostnames().get("198.18.10.9") is None  # truly bare

    out = str(tmp_path / "o.txt")
    # scope_filter=none isolates the IP-authorization gate from traceability.
    ledger.export_targets(out, scope_filter="none")
    # No -t ranges => _ip_authorized returns True for everything => IP kept.
    assert "198.18.10.9" in _read(out)


def test_ip_authorized_helper():
    import ipaddress
    ledger = TargetLedger.__new__(TargetLedger)  # no I/O
    ledger._ip_scope_mode = "strict"
    nets = [ipaddress.ip_network("198.18.10.0/24")]
    assert ledger._ip_authorized("198.18.10.9", nets) is True
    assert ledger._ip_authorized("104.16.5.5", nets) is False
    # no authorized ranges -> everything authorized (no-op)
    assert ledger._ip_authorized("104.16.5.5", []) is True
    # provenance mode -> always authorized
    ledger._ip_scope_mode = "provenance"
    assert ledger._ip_authorized("104.16.5.5", nets) is True


def test_invalid_mode_rejected(tmp_path):
    import pytest
    ledger = TargetLedger(str(tmp_path))
    with pytest.raises(ValueError):
        ledger.set_ip_scope_mode("bogus")


class TestStrictResolved:
    """strict-resolved additionally gates NAMES by where they resolve, closing
    the strict footgun where an -t hostname resolving out of range is still
    scanned via its name. Fail-closed: unresolved names are dropped."""

    def _ledger(self, tmp_path, mode="strict-resolved"):
        # -t: an in-scope CIDR + two hostnames (one resolves in-range, one out).
        (tmp_path / "t.txt").write_text("198.18.10.0/24\napp.example.com\nmail.example.com\n")
        led = TargetLedger(str(tmp_path))
        led.set_ip_scope_mode(mode)
        led.seed_user_inputs(str(tmp_path / "t.txt"), None, None)
        led.log_discovery("198.18.10.10", TYPE_IP, "dns_resolve", parent="app.example.com")   # in range
        led.log_discovery("198.18.11.7", TYPE_IP, "dns_resolve", parent="mail.example.com")  # out of range
        return led

    def test_name_resolving_out_of_range_dropped_from_targets(self, tmp_path):
        led = self._ledger(tmp_path)
        out = str(tmp_path / "o.txt")
        led.export_targets(out, "none")
        lines = _read(out)
        assert "app.example.com" in lines          # resolves in-range -> kept
        assert "mail.example.com" not in lines      # resolves out-of-range -> dropped
        assert "198.18.10.0/24" in lines

    def test_strict_keeps_out_of_range_name(self, tmp_path):
        # Contrast: plain strict authorizes names by name (the documented footgun).
        led = self._ledger(tmp_path, mode="strict")
        out = str(tmp_path / "o.txt")
        led.export_targets(out, "none")
        assert "mail.example.com" in _read(out)

    def test_hostname_ip_authorized_helper(self):
        import ipaddress
        led = TargetLedger.__new__(TargetLedger)
        led._ip_scope_mode = "strict-resolved"
        nets = [ipaddress.ip_network("198.18.10.0/24")]
        h2i = {"in.example.com": ["198.18.10.9"],
               "out.example.com": ["198.18.11.7"],
               "mixed.example.com": ["198.18.10.9", "198.18.11.7"]}
        assert led._hostname_ip_authorized("in.example.com", nets, h2i) is True
        assert led._hostname_ip_authorized("out.example.com", nets, h2i) is False
        assert led._hostname_ip_authorized("mixed.example.com", nets, h2i) is False  # any out -> deny
        assert led._hostname_ip_authorized("unresolved.example.com", nets, h2i) is False  # fail-closed
        # no authorized ranges -> no-op (True)
        assert led._hostname_ip_authorized("out.example.com", [], h2i) is True

    def test_url_gated_by_host_resolution(self, tmp_path):
        led = self._ledger(tmp_path)
        led.log_discovery("https://app.example.com/x", TYPE_URL, "ax_ffuf", parent="app.example.com")
        led.log_discovery("https://mail.example.com/y", TYPE_URL, "ax_ffuf", parent="mail.example.com")
        out = str(tmp_path / "u.txt")
        led.export_urls(out, "none")
        urls = _read(out)
        assert "https://app.example.com/x" in urls
        assert "https://mail.example.com/y" not in urls


class TestExportTargetIps:
    """export_target_ips emits authorized BARE IPs (for resolver-less tools like
    shodan_enrich) under the SAME scope_filter + ip_scope gates as export_targets
    — never a superset of what the scanners were allowed to hit."""

    def _rows(self, path):
        # {ip: [hostnames]} from the `ip\thost1,host2` / `ip` format.
        out = {}
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split("\t", 1)
                out[parts[0]] = parts[1].split(",") if len(parts) == 2 else []
        return out

    def test_recovers_ip_behind_in_scope_name(self, tmp_path):
        # Domain-only run: name resolves to a public IP. export_targets collapses
        # to the hostname; export_target_ips must surface the bare IP + provenance.
        ledger = _seed(tmp_path, "provenance", domains_text="example.com\n")
        ledger.log_discovery("scanme.example.com", TYPE_SUBDOMAIN, "subfinder", parent="example.com")
        ledger.log_discovery("198.18.10.10", TYPE_IP, "dns_resolve", parent="scanme.example.com")

        out = str(tmp_path / "ips.txt")
        n = ledger.export_target_ips(out, scope_filter="strict")
        rows = self._rows(out)
        assert n == 1
        assert "198.18.10.10" in rows
        assert rows["198.18.10.10"] == ["scanme.example.com"]  # provenance stamped

    def test_strict_drops_bare_ip_outside_range(self, tmp_path):
        # Identical gate to export_targets: an out-of-range bare IP is dropped.
        ledger = _seed(tmp_path, "strict", targets_text="198.18.10.0/24\n")
        ledger.log_discovery("198.18.10.9", TYPE_IP, "ax_naabu", parent=None)
        ledger.log_discovery("104.16.5.5", TYPE_IP, "ax_naabu", parent=None)

        out = str(tmp_path / "ips.txt")
        ledger.export_target_ips(out, scope_filter="none")
        rows = self._rows(out)
        assert "198.18.10.9" in rows        # in authorized range -> kept
        assert "104.16.5.5" not in rows    # outside -t -> dropped under strict

    def test_strict_resolved_drops_name_resolving_out_of_range(self, tmp_path):
        # strict-resolved gates names by where they resolve — the bare IP behind
        # an out-of-range name must NOT leak into the IP list either.
        (tmp_path / "t.txt").write_text("198.18.10.0/24\napp.example.com\nmail.example.com\n")
        led = TargetLedger(str(tmp_path))
        led.set_ip_scope_mode("strict-resolved")
        led.seed_user_inputs(str(tmp_path / "t.txt"), None, None)
        led.log_discovery("198.18.10.10", TYPE_IP, "dns_resolve", parent="app.example.com")
        led.log_discovery("198.18.11.7", TYPE_IP, "dns_resolve", parent="mail.example.com")

        out = str(tmp_path / "ips.txt")
        led.export_target_ips(out, scope_filter="none")
        rows = self._rows(out)
        assert "198.18.10.10" in rows       # app resolves in-range -> kept
        assert "198.18.11.7" not in rows  # mail resolves out-of-range -> dropped

    def test_exclusion_wins(self, tmp_path):
        ledger = _seed(tmp_path, "provenance", targets_text="198.18.10.0/24\n")
        ledger.log_discovery("198.18.10.9", TYPE_IP, "ax_naabu", parent=None)
        (tmp_path / "excl.txt").write_text("198.18.10.9\n")
        ledger.seed_exclusions(str(tmp_path / "excl.txt"))

        out = str(tmp_path / "ips.txt")
        ledger.export_target_ips(out, scope_filter="none")
        assert "198.18.10.9" not in self._rows(out)  # excluded IP never exported

    def test_private_ip_filtered(self, tmp_path):
        ledger = _seed(tmp_path, "provenance", domains_text="example.com\n")
        ledger.log_discovery("10.0.0.5", TYPE_IP, "dns_resolve", parent="example.com")
        out = str(tmp_path / "ips.txt")
        n = ledger.export_target_ips(out, scope_filter="none")
        assert n == 0                       # RFC1918 stripped by private filter
