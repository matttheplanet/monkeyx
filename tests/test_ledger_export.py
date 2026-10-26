"""Tests for ledger export, scope inheritance, snapshot, and resume."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.target_ledger import (
    TargetLedger, NO_OP_LEDGER, LedgerSnapshot,
    TYPE_IP, TYPE_DOMAIN, TYPE_SUBDOMAIN, TYPE_URL,
)


def _read_lines(path):
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]


class TestExportTargets:
    # NOTE: these use PUBLIC IPs on purpose. Private/RFC1918 addresses are
    # filtered out of exports by design (external-only scanning,
    # _PRIVATE_FILTER_ENABLED), so scope-filter behavior must be exercised with
    # routable addresses. See test_private_ips_filtered_from_export below.
    def test_export_explicit_ips(self, tmp_path):
        targets = tmp_path / "targets.txt"
        targets.write_text("93.184.216.34\n93.184.216.35\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(str(targets), None, None)

        out = str(tmp_path / "ledger-targets.txt")
        count = ledger.export_targets(out, scope_filter="strict")
        assert count == 2
        lines = _read_lines(out)
        assert "93.184.216.34" in lines
        assert "93.184.216.35" in lines

    def test_strict_excludes_out_of_scope_ips(self, tmp_path):
        targets = tmp_path / "targets.txt"
        targets.write_text("93.184.216.34\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(str(targets), None, None)
        # Discovered public IP with no in-scope parent
        ledger.log_discovery("99.99.99.99", TYPE_IP, "ax_naabu")

        out = str(tmp_path / "ledger-targets.txt")
        count = ledger.export_targets(out, scope_filter="strict")
        assert count == 1
        lines = _read_lines(out)
        assert "93.184.216.34" in lines
        assert "99.99.99.99" not in lines

    def test_warn_includes_all(self, tmp_path):
        targets = tmp_path / "targets.txt"
        targets.write_text("93.184.216.34\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(str(targets), None, None)
        ledger.log_discovery("99.99.99.99", TYPE_IP, "ax_naabu")

        out = str(tmp_path / "ledger-targets.txt")
        count = ledger.export_targets(out, scope_filter="warn")
        assert count == 2

    def test_none_includes_all(self, tmp_path):
        targets = tmp_path / "targets.txt"
        targets.write_text("93.184.216.34\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(str(targets), None, None)
        ledger.log_discovery("99.99.99.99", TYPE_IP, "ax_naabu")

        out = str(tmp_path / "ledger-targets.txt")
        count = ledger.export_targets(out, scope_filter="none")
        assert count == 2

    def test_private_ips_filtered_from_export(self, tmp_path):
        """RFC1918 addresses are logged but never exported (external-only scanning)."""
        targets = tmp_path / "targets.txt"
        targets.write_text("93.184.216.34\n10.0.0.1\n192.168.1.5\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(str(targets), None, None)

        out = str(tmp_path / "ledger-targets.txt")
        # Even under 'none' (no scope filtering), private IPs are dropped.
        count = ledger.export_targets(out, scope_filter="none")
        lines = _read_lines(out)
        assert "93.184.216.34" in lines
        assert "10.0.0.1" not in lines
        assert "192.168.1.5" not in lines
        assert count == 1

    def test_private_ip_check_handles_ipv6_and_cidr(self):
        """_is_private_ip must not raise TypeError on IPv6 or CIDRs (subnet_of
        raises TypeError across address families)."""
        from core.target_ledger import _is_private_ip
        # Public IPv6 CIDR previously crashed (v6 net vs v4 CGNAT via subnet_of).
        assert _is_private_ip("2606:4700::/32") is False
        assert _is_private_ip("2606:4700::1") is False
        assert _is_private_ip("::1") is True          # loopback
        assert _is_private_ip("fe80::/10") is True     # link-local
        assert _is_private_ip("10.0.0.0/8") is True    # RFC1918
        assert _is_private_ip("100.64.0.0/10") is True  # CGNAT
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("garbage") is False

    def test_exclusion_mixed_family_no_crash(self, tmp_path):
        """An IPv6 exclusion network must not crash is_excluded() when checking
        an IPv4 CIDR target (mixed-family subnet_of raises TypeError)."""
        excl = tmp_path / "excl.txt"
        excl.write_text("2606:4700::/32\n")
        ledger = TargetLedger(str(tmp_path))
        ledger.seed_exclusions(str(excl))
        # Mixed family: v4 CIDR against v6 exclusion — must return False, not raise.
        assert ledger.is_excluded("10.0.0.0/24", TYPE_IP) is False
        # Same-family match still works.
        assert ledger.is_excluded("2606:4700::1", TYPE_IP) is True


class TestExportUrls:
    def test_export_explicit_urls(self, tmp_path):
        urls = tmp_path / "urls.txt"
        urls.write_text("https://app.example.com\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(None, None, str(urls))

        out = str(tmp_path / "ledger-urls.txt")
        count = ledger.export_urls(out, scope_filter="strict")
        assert count == 1
        lines = _read_lines(out)
        assert "https://app.example.com" in lines

    def test_url_on_in_scope_host_is_in_scope(self, tmp_path):
        domains = tmp_path / "domains.txt"
        domains.write_text("example.com\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(None, str(domains), None)
        ledger.log_discovery("https://app.example.com/api", TYPE_URL, "ax_tcp_full",
                             parent="app.example.com")

        out = str(tmp_path / "ledger-urls.txt")
        count = ledger.export_urls(out, scope_filter="strict")
        assert count == 1

    def test_url_on_out_of_scope_host_excluded_strict(self, tmp_path):
        domains = tmp_path / "domains.txt"
        domains.write_text("example.com\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(None, str(domains), None)
        ledger.log_discovery("https://evil.attacker.com/x", TYPE_URL, "ax_ffuf")

        out = str(tmp_path / "ledger-urls.txt")
        count = ledger.export_urls(out, scope_filter="strict")
        assert count == 0


class TestExportDomains:
    def test_export_includes_subdomains_of_explicit(self, tmp_path):
        domains = tmp_path / "domains.txt"
        domains.write_text("example.com\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(None, str(domains), None)
        ledger.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                             parent="example.com")
        ledger.log_discovery("mail.example.com", TYPE_SUBDOMAIN, "subfinder",
                             parent="example.com")

        out = str(tmp_path / "ledger-domains.txt")
        count = ledger.export_domains(out, scope_filter="strict")
        assert count == 3
        lines = _read_lines(out)
        assert "example.com" in lines
        assert "api.example.com" in lines
        assert "mail.example.com" in lines

    def test_strict_excludes_unrelated_subdomains(self, tmp_path):
        domains = tmp_path / "domains.txt"
        domains.write_text("example.com\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(None, str(domains), None)
        ledger.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                             parent="example.com")
        ledger.log_discovery("evil.other.com", TYPE_SUBDOMAIN, "subfinder")

        out = str(tmp_path / "ledger-domains.txt")
        count = ledger.export_domains(out, scope_filter="strict")
        assert count == 2
        lines = _read_lines(out)
        assert "evil.other.com" not in lines


class TestScopeInheritanceChain:
    def test_full_chain_domain_to_subdomain_to_ip_to_url(self, tmp_path):
        """example.com → api.example.com → 93.184.216.5 → https://93.184.216.5:8080/admin

        Uses a public IP: the private-IP filter would otherwise drop an RFC1918
        address from the target export regardless of scope inheritance.
        """
        domains = tmp_path / "domains.txt"
        domains.write_text("example.com\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(None, str(domains), None)

        # Subfinder discovers subdomain
        ledger.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                             parent="example.com")
        # dns_resolve resolves it to an IP
        ledger.log_discovery("93.184.216.5", TYPE_IP, "dns_resolve",
                             parent="api.example.com")
        # nmap finds a URL on that IP
        ledger.log_discovery("https://93.184.216.5:8080/admin", TYPE_URL, "ax_tcp_full",
                             parent="93.184.216.5")

        # All should be in-scope under strict
        targets_out = str(tmp_path / "targets.txt.out")
        urls_out = str(tmp_path / "urls.txt.out")
        domains_out = str(tmp_path / "domains.txt.out")

        assert ledger.export_targets(targets_out, "strict") == 1
        assert ledger.export_urls(urls_out, "strict") == 1
        assert ledger.export_domains(domains_out, "strict") == 2

        # export_targets prefers the hostname where the IP has a known mapping
        # (so nmap records the hostname), so the target line is the subdomain.
        assert "api.example.com" in _read_lines(targets_out)
        assert "https://93.184.216.5:8080/admin" in _read_lines(urls_out)

    def test_orphan_ip_not_in_scope(self, tmp_path):
        """IP discovered without in-scope parent stays out of strict export."""
        domains = tmp_path / "domains.txt"
        domains.write_text("example.com\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(None, str(domains), None)
        ledger.log_discovery("192.168.1.1", TYPE_IP, "ax_naabu", parent=None)

        out = str(tmp_path / "targets.txt.out")
        assert ledger.export_targets(out, "strict") == 0

    def test_ip_with_out_of_scope_parent_not_in_scope(self, tmp_path):
        domains = tmp_path / "domains.txt"
        domains.write_text("example.com\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(None, str(domains), None)
        # evil.com is not explicit
        ledger.log_discovery("evil.com", TYPE_SUBDOMAIN, "subfinder")
        ledger.log_discovery("99.99.99.99", TYPE_IP, "dns_resolve", parent="evil.com")

        out = str(tmp_path / "targets.txt.out")
        assert ledger.export_targets(out, "strict") == 0


class TestSnapshot:
    def test_snapshot_is_immutable(self, tmp_path):
        targets = tmp_path / "targets.txt"
        targets.write_text("10.0.0.1\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(str(targets), None, None)

        snap = ledger.snapshot()
        assert "10.0.0.1" in snap.ips
        assert "10.0.0.1" in snap.in_scope_ips

        # Adding more to ledger doesn't affect snapshot
        ledger.log_discovery("10.0.0.2", TYPE_IP, "ax_naabu")
        assert "10.0.0.2" not in snap.ips

    def test_snapshot_contains_all_types(self, tmp_path):
        targets = tmp_path / "targets.txt"
        targets.write_text("10.0.0.1\n")
        domains = tmp_path / "domains.txt"
        domains.write_text("example.com\n")
        urls = tmp_path / "urls.txt"
        urls.write_text("https://app.example.com\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(str(targets), str(domains), str(urls))

        snap = ledger.snapshot()
        assert "10.0.0.1" in snap.ips
        assert "example.com" in snap.domains
        assert "https://app.example.com" in snap.urls


class TestLoadFromDisk:
    def test_rebuild_state_from_jsonl(self, tmp_path):
        targets = tmp_path / "targets.txt"
        targets.write_text("10.0.0.1\n")
        domains = tmp_path / "domains.txt"
        domains.write_text("example.com\n")

        # First session: seed and discover
        ledger1 = TargetLedger(str(tmp_path))
        ledger1.seed_user_inputs(str(targets), str(domains), None)
        ledger1.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                              parent="example.com")
        ledger1.log_discovery("198.18.10.5", TYPE_IP, "dns_resolve",
                              parent="api.example.com")

        # Second session: load from disk (simulating resume)
        ledger2 = TargetLedger(str(tmp_path))
        ledger2.load_from_disk()

        # Should have rebuilt all state
        assert "10.0.0.1" in ledger2._all_ips
        assert "198.18.10.5" in ledger2._all_ips
        assert "api.example.com" in ledger2._all_domains
        assert "example.com" in ledger2._explicit_domains

        # Scope inheritance should be rebuilt
        assert "198.18.10.5" in ledger2._in_scope_ips
        assert "api.example.com" in ledger2._in_scope_domains

        # Deduplication should work
        ledger2.log_discovery("198.18.10.5", TYPE_IP, "ax_tcp_baseline")
        # Should not add duplicate entry
        with open(ledger2.path) as f:
            lines = [l for l in f if l.strip()]
        ip_entries = [json.loads(l) for l in lines if json.loads(l).get("target") == "198.18.10.5"]
        assert len(ip_entries) == 1

    def test_load_out_of_order_scope_propagation(self, tmp_path):
        """Child entries written before their parents must still inherit scope
        on load (parallel groups can interleave writes; the JSONL is not
        guaranteed parent-before-child). Uses a fully-reversed chain."""
        path = tmp_path / "discovery-ledger.jsonl"
        # Written child-first: url <- ip <- subdomain <- explicit domain
        rows = [
            {"target": "https://93.184.216.5:8080/admin", "type": TYPE_URL,
             "scope": "derived", "source": "ax_nmap_tcp", "parent": "93.184.216.5"},
            {"target": "93.184.216.5", "type": TYPE_IP,
             "scope": "derived", "source": "dns_resolve", "parent": "api.example.com"},
            {"target": "api.example.com", "type": TYPE_SUBDOMAIN,
             "scope": "derived", "source": "subfinder", "parent": "example.com"},
            {"target": "example.com", "type": TYPE_DOMAIN,
             "scope": "explicit", "source": "user_input", "parent": None},
        ]
        path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.load_from_disk()

        # Every link of the chain should be in-scope despite reverse write order.
        assert "example.com" in ledger._in_scope_domains
        assert "api.example.com" in ledger._in_scope_domains
        assert "93.184.216.5" in ledger._in_scope_ips
        assert "https://93.184.216.5:8080/admin" in ledger._in_scope_urls

    def test_load_out_of_order_orphan_stays_out(self, tmp_path):
        """An entry whose parent chain never reaches an explicit target must
        NOT become in-scope, even after the fixpoint pass."""
        path = tmp_path / "discovery-ledger.jsonl"
        rows = [
            {"target": "9.9.9.9", "type": TYPE_IP, "scope": "derived",
             "source": "dns_resolve", "parent": "evil.attacker.com"},
            {"target": "evil.attacker.com", "type": TYPE_SUBDOMAIN,
             "scope": "derived", "source": "subfinder", "parent": None},
            {"target": "example.com", "type": TYPE_DOMAIN, "scope": "explicit",
             "source": "user_input", "parent": None},
        ]
        path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.load_from_disk()

        assert "example.com" in ledger._in_scope_domains
        assert "9.9.9.9" not in ledger._in_scope_ips
        assert "evil.attacker.com" not in ledger._in_scope_domains

    def test_load_nonexistent_file_no_error(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        ledger.load_from_disk()  # should not raise
        assert len(ledger._all_ips) == 0


class TestExclusions:
    """The exclusion engine is security-critical: exclusions must ALWAYS win,
    and the matching rules (plain-name vs *.wildcard vs CIDR vs URL) are subtle.
    """

    def _ledger_with_exclusions(self, tmp_path, lines):
        excl = tmp_path / "excl.txt"
        excl.write_text("\n".join(lines) + "\n")
        ledger = TargetLedger(str(tmp_path))
        ledger.seed_exclusions(str(excl))
        return ledger

    def test_plain_hostname_matches_itself_and_subdomains(self, tmp_path):
        led = self._ledger_with_exclusions(tmp_path, ["legacy.example.com"])
        assert led.is_excluded("legacy.example.com", TYPE_DOMAIN) is True
        assert led.is_excluded("api.legacy.example.com", TYPE_SUBDOMAIN) is True
        # Not a suffix match on unrelated domains
        assert led.is_excluded("example.com", TYPE_DOMAIN) is False
        assert led.is_excluded("notlegacy.example.com", TYPE_DOMAIN) is False

    def test_wildcard_matches_subdomains_only_not_bare(self, tmp_path):
        led = self._ledger_with_exclusions(tmp_path, ["*.staging.example.com"])
        assert led.is_excluded("app.staging.example.com", TYPE_SUBDOMAIN) is True
        # Bare domain is NOT excluded by a *.wildcard
        assert led.is_excluded("staging.example.com", TYPE_DOMAIN) is False

    def test_cidr_and_ip_exclusion(self, tmp_path):
        led = self._ledger_with_exclusions(tmp_path, ["192.168.99.0/24", "10.0.0.42"])
        assert led.is_excluded("192.168.99.5", TYPE_IP) is True
        assert led.is_excluded("10.0.0.42", TYPE_IP) is True
        assert led.is_excluded("10.0.0.43", TYPE_IP) is False

    def test_url_host_inherits_exclusion(self, tmp_path):
        led = self._ledger_with_exclusions(tmp_path, ["legacy.example.com"])
        # A URL whose host is excluded is itself excluded.
        assert led.is_excluded("https://legacy.example.com/admin", TYPE_URL) is True
        assert led.is_excluded("https://api.legacy.example.com/x", TYPE_URL) is True

    def test_exact_url_exclusion(self, tmp_path):
        led = self._ledger_with_exclusions(tmp_path, ["https://x.example.com/admin"])
        assert led.is_excluded("https://x.example.com/admin", TYPE_URL) is True
        # Different path on same host is not the exact URL (host itself not excluded)
        assert led.is_excluded("https://x.example.com/other", TYPE_URL) is False

    def test_exclusion_beats_explicit_and_blocks_export(self, tmp_path):
        """Exclusions override user-provided (-t) targets and are never exported."""
        targets = tmp_path / "targets.txt"
        targets.write_text("93.184.216.34\n93.184.216.99\n")
        excl = tmp_path / "excl.txt"
        excl.write_text("93.184.216.99\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_exclusions(str(excl))
        ledger.seed_user_inputs(str(targets), None, None)

        out = str(tmp_path / "ledger-targets.txt")
        ledger.export_targets(out, scope_filter="none")
        lines = _read_lines(out)
        assert "93.184.216.34" in lines
        assert "93.184.216.99" not in lines  # excluded, even though user-provided

    def test_comments_and_blanks_ignored(self, tmp_path):
        led = self._ledger_with_exclusions(
            tmp_path, ["# a comment", "", "  ", "legacy.example.com"])
        assert led.is_excluded("legacy.example.com", TYPE_DOMAIN) is True

    def test_excluded_ip_carved_out_of_larger_cidr(self, tmp_path):
        """Excluding a single IP must subtract it from a larger in-scope CIDR,
        not leave the whole CIDR exportable (authorization-boundary fix)."""
        import ipaddress
        targets = tmp_path / "targets.txt"
        targets.write_text("93.184.216.0/30\n")  # public /30 -> .0 .1 .2 .3
        excl = tmp_path / "excl.txt"
        excl.write_text("93.184.216.1\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_exclusions(str(excl))
        ledger.seed_user_inputs(str(targets), None, None)

        out = str(tmp_path / "ledger-targets.txt")
        ledger.export_targets(out, scope_filter="none")

        covered = set()
        for line in _read_lines(out):
            for a in ipaddress.ip_network(line):
                covered.add(str(a))
        assert "93.184.216.1" not in covered           # excluded host removed
        assert {"93.184.216.0", "93.184.216.2", "93.184.216.3"} <= covered  # rest kept

    def test_excluded_subnet_carved_out_of_larger_cidr(self, tmp_path):
        import ipaddress
        targets = tmp_path / "targets.txt"
        targets.write_text("93.184.216.0/24\n")
        excl = tmp_path / "excl.txt"
        excl.write_text("93.184.216.0/26\n")  # exclude first quarter

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_exclusions(str(excl))
        ledger.seed_user_inputs(str(targets), None, None)

        out = str(tmp_path / "ledger-targets.txt")
        ledger.export_targets(out, scope_filter="none")

        covered = set()
        for line in _read_lines(out):
            for a in ipaddress.ip_network(line):
                covered.add(str(a))
        # None of the excluded /26 should survive; the rest of the /24 should.
        assert not any(f"93.184.216.{i}" in covered for i in range(64))
        assert "93.184.216.64" in covered
        assert "93.184.216.255" in covered


class TestNoOpLedger:
    def test_export_returns_zero(self):
        assert NO_OP_LEDGER.export_targets("/dev/null") == 0
        assert NO_OP_LEDGER.export_urls("/dev/null") == 0
        assert NO_OP_LEDGER.export_domains("/dev/null") == 0

    def test_snapshot_returns_empty(self):
        snap = NO_OP_LEDGER.snapshot()
        assert isinstance(snap, LedgerSnapshot)
        assert len(snap.ips) == 0

    def test_load_from_disk_no_error(self):
        NO_OP_LEDGER.load_from_disk()


class TestExportDiscoveryLedgerFromDb:
    """Stage D: export_discovery_ledger() regenerates discovery-ledger.jsonl from
    scan.db, faithfully enough that a load_from_disk of the export matches a
    load_from_db of the same run."""

    def _seed(self, output_dir):
        led = TargetLedger(output_dir)
        led._explicit_domains.add("example.com")
        led._add_to_all("example.com", TYPE_DOMAIN)
        led._add_to_in_scope("example.com", TYPE_DOMAIN)
        led._write_entry({"target": "example.com", "type": TYPE_DOMAIN,
                          "source": "user_input", "scope": "explicit",
                          "discovered_at": "2026-01-01T00:00:00+00:00", "parent": None})
        led.log_discovery("a.example.com", TYPE_SUBDOMAIN, "subfinder", parent="example.com")
        led.log_discovery("198.18.10.10", TYPE_IP, "dns_resolve", parent="a.example.com")
        led.log_port("198.18.10.10", 443, "tcp", "ax_nmap_tcp", service="https",
                     product="nginx", tunnel="ssl")
        led.log_mx_domain("example.com", ["mx1.example.net"])
        led.sync_scope_to_db()
        led.close()

    def test_export_round_trips_through_load_from_disk(self, tmp_path):
        run = str(tmp_path / "r"); os.makedirs(run)
        self._seed(run)

        # Ground truth: rebuild from the DB.
        from_db = TargetLedger(run)
        from_db.load_from_db()
        db_ips = set(from_db._all_ips); db_domains = set(from_db._all_domains)
        db_inscope = (from_db._in_scope_ips | from_db._in_scope_domains
                      | from_db._in_scope_urls)
        db_ports = {h: set(p) for h, p in from_db._ports.items()}
        db_mx = dict(from_db._mx_domains)
        from_db.close()

        # Export from the DB, overwriting the live JSONL, then reload from disk.
        exporter = TargetLedger(run)
        exporter.export_discovery_ledger()
        exporter.close()

        reloaded = TargetLedger(run)
        reloaded.load_from_disk()
        assert set(reloaded._all_ips) == db_ips
        assert set(reloaded._all_domains) == db_domains
        assert (reloaded._in_scope_ips | reloaded._in_scope_domains
                | reloaded._in_scope_urls) == db_inscope
        assert {h: set(p) for h, p in reloaded._ports.items()} == db_ports
        assert dict(reloaded._mx_domains) == db_mx
        reloaded.close()

    def test_exported_jsonl_is_valid_and_has_all_entry_types(self, tmp_path):
        run = str(tmp_path / "r"); os.makedirs(run)
        self._seed(run)
        led = TargetLedger(run)
        led.export_discovery_ledger()
        led.close()

        entries = [json.loads(l) for l in _read_lines(
            os.path.join(run, "discovery-ledger.jsonl"))]
        types = {e["type"] for e in entries}
        assert {"domain", "subdomain", "ip", "port", "mx_domain"} <= types
        # port entry carries the widened fields
        port = next(e for e in entries if e["type"] == "port")
        assert port["service"] == "https" and port["tunnel"] == "ssl"
        # mx entry carries mx_hosts
        mx = next(e for e in entries if e["type"] == "mx_domain")
        assert mx["mx_hosts"] == ["mx1.example.net"]

    def test_noop_ledger_export_is_safe(self):
        NO_OP_LEDGER.export_discovery_ledger()  # must not raise


class TestExportMxDomains:
    """export_mx_domains feeds ledger-mx-domains.txt (analyze + SMTP modules), so
    it must be gated like every other exporter: exclusions always win, and an
    affirmatively out-of-scope domain is dropped. A domain the ledger never
    tracked as a discovery has unknown scope and is kept (fail-open) so the
    analyze consumer isn't silently regressed."""

    def test_excluded_mx_domain_dropped(self, tmp_path):
        led = TargetLedger(str(tmp_path))
        led._explicit_domains.add("example.com")
        led._add_to_all("example.com", TYPE_DOMAIN)
        led._add_to_in_scope("example.com", TYPE_DOMAIN)
        led.log_mx_domain("example.com", ["mx1.example.net"])
        led.log_mx_domain("evil.example.com", ["mx.evil.net"])
        (tmp_path / "excl.txt").write_text("evil.example.com\n")
        led.seed_exclusions(str(tmp_path / "excl.txt"))

        out = str(tmp_path / "mx.txt")
        led.export_mx_domains(out, scope_filter="strict")
        assert _read_lines(out) == ["example.com"]  # excluded domain never written
        led.close()

    def test_out_of_scope_mx_domain_dropped_under_strict(self, tmp_path):
        led = TargetLedger(str(tmp_path))
        led._explicit_domains.add("example.com")
        led._add_to_all("example.com", TYPE_DOMAIN)
        led._add_to_in_scope("example.com", TYPE_DOMAIN)
        # Known to the ledger but NOT in scope -> affirmatively out of scope.
        led._add_to_all("other.com", TYPE_DOMAIN)
        led.log_mx_domain("example.com", ["mx1.example.net"])
        led.log_mx_domain("other.com", ["mx.other.net"])

        out = str(tmp_path / "mx.txt")
        led.export_mx_domains(out, scope_filter="strict")
        assert _read_lines(out) == ["example.com"]
        # scope_filter=none keeps everything not excluded.
        led.export_mx_domains(out, scope_filter="none")
        assert set(_read_lines(out)) == {"example.com", "other.com"}
        led.close()

    def test_untracked_mx_domain_kept_fail_open(self, tmp_path):
        # MX domains are logged straight from dnsx and may not appear in the
        # domain sets; unknown scope must not drop them (analyze relies on them).
        led = TargetLedger(str(tmp_path))
        led.log_mx_domain("mail.example.com", ["mx1.example.net"])
        out = str(tmp_path / "mx.txt")
        led.export_mx_domains(out, scope_filter="strict")
        assert _read_lines(out) == ["mail.example.com"]
        led.close()


class TestWildcardMarkerSuppression:
    """bbot's synthetic `_wildcard.*` catch-all marker must never enter the
    ledger or any export (it is not a real host)."""

    def test_wildcard_marker_dropped_from_domains(self, tmp_path):
        domains = tmp_path / "domains.txt"
        domains.write_text("foo.com\n")

        led = TargetLedger(str(tmp_path))
        led.seed_user_inputs(None, str(domains), None)
        led.log_discovery("real.foo.com", TYPE_SUBDOMAIN, "bbot_recon", parent="foo.com")
        led.log_discovery("_wildcard.foo.com", TYPE_SUBDOMAIN, "bbot_recon", parent="foo.com")

        out = str(tmp_path / "ledger-domains.txt")
        led.export_domains(out, scope_filter="strict")
        lines = _read_lines(out)
        assert "real.foo.com" in lines
        assert "_wildcard.foo.com" not in lines
        led.close()

    def test_wildcard_marker_url_form_dropped(self, tmp_path):
        led = TargetLedger(str(tmp_path))
        led.seed_user_inputs(None, None, None)
        # URL form of the marker must also be rejected.
        led.log_discovery("http://_wildcard.foo.com/app", TYPE_URL, "bbot_recon")
        out = str(tmp_path / "ledger-urls.txt")
        led.export_urls(out, scope_filter="none")
        assert "_wildcard.foo.com" not in "\n".join(_read_lines(out))
        led.close()

    def test_normal_underscore_label_not_dropped(self, tmp_path):
        # Only the literal `_wildcard` label is dropped — other underscore
        # names (e.g. DMARC/service records bbot may surface) are kept.
        domains = tmp_path / "domains.txt"
        domains.write_text("foo.com\n")
        led = TargetLedger(str(tmp_path))
        led.seed_user_inputs(None, str(domains), None)
        led.log_discovery("_dmarc.foo.com", TYPE_SUBDOMAIN, "bbot_recon", parent="foo.com")
        out = str(tmp_path / "ledger-domains.txt")
        led.export_domains(out, scope_filter="strict")
        assert "_dmarc.foo.com" in _read_lines(out)
        led.close()


class TestDerivedPrivateIpNotInScope:
    """A hostname resolving to a private/internal IP (split-horizon / internal-DNS
    leakage) must NOT be marked in-scope via parent inheritance — it's not an
    authorized external target, and exports already strip private IPs. The web
    view reads this flag, so it was showing derived RFC1918 IPs as in-scope."""

    def _ledger(self, tmp_path):
        t = tmp_path / "t.txt"; t.write_text("198.18.10.1\n")
        d = tmp_path / "d.txt"; d.write_text("example.com\n")
        led = TargetLedger(str(tmp_path))
        led.seed_user_inputs(str(t), str(d), None)
        led.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder", parent="example.com")
        return led

    def test_derived_private_ip_not_in_scope(self, tmp_path):
        led = self._ledger(tmp_path)
        led.log_discovery("192.168.50.25", TYPE_IP, "dnsx_resolve", parent="api.example.com")
        led.log_discovery("172.20.0.15", TYPE_IP, "dnsx_resolve", parent="api.example.com")
        assert "192.168.50.25" not in led._in_scope_ips
        assert "172.20.0.15" not in led._in_scope_ips

    def test_derived_public_ip_still_in_scope(self, tmp_path):
        led = self._ledger(tmp_path)
        led.log_discovery("198.18.10.5", TYPE_IP, "dnsx_resolve", parent="api.example.com")
        assert "198.18.10.5" in led._in_scope_ips        # public derived -> provenance keeps it

    def test_explicit_private_ip_still_in_scope(self, tmp_path):
        # An explicitly-provided private -t IP is a deliberate internal-scan choice.
        t = tmp_path / "t.txt"; t.write_text("10.10.0.5\n")
        led = TargetLedger(str(tmp_path))
        led.seed_user_inputs(str(t), None, None)
        assert "10.10.0.5" in led._in_scope_ips
