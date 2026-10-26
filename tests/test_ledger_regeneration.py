"""Tests for ledger-driven target file regeneration in workflows.

Uses PUBLIC IPs throughout: private/RFC1918 addresses are filtered out of exports
by design (external-only scanning, _PRIVATE_FILTER_ENABLED in core.target_ledger),
so regeneration behavior must be exercised with routable addresses.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.target_ledger import TargetLedger, TYPE_IP, TYPE_URL, TYPE_SUBDOMAIN
from core.output_layout import ledger_file
from workflows import _regenerate_target_files


def _read_lines(path):
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]


class TestRegenerateTargetFiles:
    def test_exports_ips_to_target_kwarg(self, tmp_path):
        targets = tmp_path / "targets.txt"
        targets.write_text("93.184.216.34\n93.184.216.35\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(str(targets), None, None)

        data_dir = str(tmp_path / "data")
        kwargs = {"prefix": "/fake"}

        _regenerate_target_files(ledger, kwargs, data_dir, scope_filter="strict")

        assert kwargs["target"] == ledger_file(data_dir, "ledger-targets.txt")
        lines = _read_lines(kwargs["target"])
        assert "93.184.216.34" in lines
        assert "93.184.216.35" in lines

    def test_exports_urls_to_url_file_kwarg(self, tmp_path):
        urls = tmp_path / "urls.txt"
        urls.write_text("https://app.example.com\nhttps://api.example.com\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(None, None, str(urls))

        data_dir = str(tmp_path / "data")
        kwargs = {"prefix": "/fake"}

        _regenerate_target_files(ledger, kwargs, data_dir, scope_filter="strict")

        assert kwargs["url_file"] == ledger_file(data_dir, "ledger-urls.txt")
        lines = _read_lines(kwargs["url_file"])
        assert len(lines) == 2

    def test_exports_domains_to_domainlist_kwarg(self, tmp_path):
        domains = tmp_path / "domains.txt"
        domains.write_text("example.com\ntest.org\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(None, str(domains), None)

        data_dir = str(tmp_path / "data")
        kwargs = {"prefix": "/fake"}

        _regenerate_target_files(ledger, kwargs, data_dir, scope_filter="strict")

        assert kwargs["domainlist"] == ledger_file(data_dir, "ledger-domains.txt")
        lines = _read_lines(kwargs["domainlist"])
        assert "example.com" in lines
        assert "test.org" in lines

    def test_does_not_override_when_empty(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        # No seeding — ledger is empty

        data_dir = str(tmp_path / "data")
        kwargs = {"prefix": "/fake", "target": "/original/targets.txt"}

        _regenerate_target_files(ledger, kwargs, data_dir, scope_filter="strict")

        # Should keep original since ledger has nothing
        assert kwargs["target"] == "/original/targets.txt"

    def test_strict_filters_out_of_scope(self, tmp_path):
        targets = tmp_path / "targets.txt"
        targets.write_text("93.184.216.34\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(str(targets), None, None)
        ledger.log_discovery("99.99.99.99", TYPE_IP, "ax_naabu")  # out of scope

        data_dir = str(tmp_path / "data")
        kwargs = {"prefix": "/fake"}

        _regenerate_target_files(ledger, kwargs, data_dir, scope_filter="strict")

        lines = _read_lines(kwargs["target"])
        assert "93.184.216.34" in lines
        assert "99.99.99.99" not in lines

    def test_warn_includes_all(self, tmp_path):
        targets = tmp_path / "targets.txt"
        targets.write_text("93.184.216.34\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(str(targets), None, None)
        ledger.log_discovery("99.99.99.99", TYPE_IP, "ax_naabu")

        data_dir = str(tmp_path / "data")
        kwargs = {"prefix": "/fake"}

        _regenerate_target_files(ledger, kwargs, data_dir, scope_filter="warn")

        lines = _read_lines(kwargs["target"])
        assert "93.184.216.34" in lines
        assert "99.99.99.99" in lines

    def test_snapshot_mode(self, tmp_path):
        targets = tmp_path / "targets.txt"
        targets.write_text("93.184.216.34\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(str(targets), None, None)

        snap = ledger.snapshot()

        # Add more AFTER snapshot
        ledger.log_discovery("93.184.216.99", TYPE_IP, "ax_naabu", parent="93.184.216.34")

        data_dir = str(tmp_path / "data")
        kwargs = {"prefix": "/fake"}

        _regenerate_target_files(ledger, kwargs, data_dir, scope_filter="strict", snapshot=snap)

        lines = _read_lines(kwargs["target"])
        assert "93.184.216.34" in lines
        # Should NOT include the IP added after snapshot
        assert "93.184.216.99" not in lines

    def test_snapshot_seeds_open_ports_kwargs(self, tmp_path):
        """Parallel-group (snapshot) export must seed open_ports_file /
        udp_open_ports_file into base_kwargs, exactly like the sequential path.

        Regression: HOST-class port consumers (ax_nuclei, ssh_audit_scan,
        smtp_security) live in parallel groups in the deep workflow. When the
        snapshot path failed to seed these kwargs, _host_scoped_kwargs (which only
        remaps an ALREADY-set kwarg) left them None, so the modules silently
        skipped with "no in-scope open ports" even though ports were discovered.
        """
        targets = tmp_path / "targets.txt"
        targets.write_text("93.184.216.34\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(str(targets), None, None)
        ledger.log_port("93.184.216.34", 22, "tcp", "ax_nmap_tcp")
        ledger.log_port("93.184.216.34", 161, "udp", "ax_nmap_udp")

        snap = ledger.snapshot()

        data_dir = str(tmp_path / "data")
        kwargs = {"prefix": "/fake"}

        _regenerate_target_files(ledger, kwargs, data_dir, scope_filter="strict", snapshot=snap)

        assert kwargs["open_ports_file"] == ledger_file(data_dir, "ledger-open-ports.txt")
        assert kwargs["udp_open_ports_file"] == ledger_file(data_dir, "ledger-open-ports-udp.txt")
        tcp_lines = _read_lines(kwargs["open_ports_file"])
        assert any("93.184.216.34" in ln and "22" in ln for ln in tcp_lines)
        udp_lines = _read_lines(kwargs["udp_open_ports_file"])
        assert any("93.184.216.34" in ln and "161" in ln for ln in udp_lines)

    def test_snapshot_carves_excluded_ip_from_cidr(self, tmp_path):
        """Parallel-group (snapshot) export must apply the SAME exclusion
        carve-out as sequential export — an excluded IP inside a larger CIDR
        must not leak to parallel modules. (Regression: the snapshot path once
        reimplemented export policy and dropped this.)"""
        import ipaddress
        targets = tmp_path / "targets.txt"
        targets.write_text("8.8.8.0/30\n")
        excl = tmp_path / "excl.txt"
        excl.write_text("8.8.8.1\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_exclusions(str(excl))
        ledger.seed_user_inputs(str(targets), None, None)

        snap = ledger.snapshot()
        data_dir = str(tmp_path / "data")
        kwargs = {"prefix": "/fake"}
        _regenerate_target_files(ledger, kwargs, data_dir, scope_filter="none", snapshot=snap)

        covered = set()
        for line in _read_lines(kwargs["target"]):
            for a in ipaddress.ip_network(line):
                covered.add(str(a))
        assert "8.8.8.1" not in covered
        assert {"8.8.8.0", "8.8.8.2", "8.8.8.3"} <= covered

    def test_snapshot_filters_private_url_host(self, tmp_path):
        """Parallel-group (snapshot) export must drop URLs whose host is a
        private/non-routable IP, matching sequential export."""
        domains = tmp_path / "domains.txt"
        domains.write_text("example.com\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(None, str(domains), None)
        ledger.log_discovery("http://127.0.0.1/admin", TYPE_URL, "ax_ffuf", parent="example.com")
        ledger.log_discovery("https://app.example.com/x", TYPE_URL, "ax_ffuf", parent="example.com")

        snap = ledger.snapshot()
        data_dir = str(tmp_path / "data")
        kwargs = {"prefix": "/fake"}
        _regenerate_target_files(ledger, kwargs, data_dir, scope_filter="none", snapshot=snap)

        urls = _read_lines(kwargs["url_file"]) if "url_file" in kwargs else []
        assert "http://127.0.0.1/admin" not in urls

    def test_creates_data_dir_if_missing(self, tmp_path):
        targets = tmp_path / "targets.txt"
        targets.write_text("93.184.216.34\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(str(targets), None, None)

        data_dir = str(tmp_path / "nested" / "data")
        kwargs = {"prefix": "/fake"}

        _regenerate_target_files(ledger, kwargs, data_dir, scope_filter="strict")

        assert os.path.isdir(data_dir)
        assert os.path.exists(kwargs["target"])


class TestRegenerationWithDiscoveryChain:
    def test_discovered_targets_appear_in_next_regeneration(self, tmp_path):
        """Simulates: seed IPs → nmap discovers URLs → next step gets expanded URL list."""
        targets = tmp_path / "targets.txt"
        targets.write_text("93.184.216.34\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(str(targets), None, None)

        data_dir = str(tmp_path / "data")
        kwargs = {"prefix": "/fake"}

        # First regeneration: only IPs
        _regenerate_target_files(ledger, kwargs, data_dir, scope_filter="strict")
        assert "url_file" not in kwargs  # no URLs yet

        # Simulate nmap discovering a URL on the in-scope IP
        ledger.log_discovery("https://93.184.216.34:8080/app", TYPE_URL, "ax_tcp_full",
                             parent="93.184.216.34")

        # Second regeneration: should now include the URL
        _regenerate_target_files(ledger, kwargs, data_dir, scope_filter="strict")
        assert "url_file" in kwargs
        lines = _read_lines(kwargs["url_file"])
        assert "https://93.184.216.34:8080/app" in lines
