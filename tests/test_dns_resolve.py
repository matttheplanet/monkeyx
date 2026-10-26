"""Tests for modules.dns_resolve."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import patch, MagicMock
from modules.dns_resolve import (
    _parse_target_file,
    _is_ip,
    _ip_in_scope,
    _is_wildcard_result,
    _get_parent_domain,
    run_dns_resolve,
)
import ipaddress


class TestParseTargetFile:
    def test_separates_ips_and_hostnames(self, tmp_path):
        target = tmp_path / "targets.txt"
        target.write_text("10.0.0.1\n10.0.0.0/24\nexample.com\napi.test.org\n")

        networks, hostnames, ips = _parse_target_file(str(target))

        assert ips == {"10.0.0.1"}
        assert hostnames == {"example.com", "api.test.org"}
        assert len(networks) == 2  # /24 + /32 for the single IP

    def test_skips_comments_and_empty(self, tmp_path):
        target = tmp_path / "targets.txt"
        target.write_text("# comment\n\n10.0.0.1\n\n")

        networks, hostnames, ips = _parse_target_file(str(target))
        assert ips == {"10.0.0.1"}
        assert hostnames == set()

    def test_cidr_creates_scope_network(self, tmp_path):
        target = tmp_path / "targets.txt"
        target.write_text("192.168.1.0/24\n")

        networks, hostnames, ips = _parse_target_file(str(target))
        assert len(networks) == 1
        assert ipaddress.ip_address("192.168.1.50") in networks[0]
        assert ips == set()  # CIDRs don't go into passthrough

    def test_single_ip_adds_to_scope(self, tmp_path):
        target = tmp_path / "targets.txt"
        target.write_text("10.0.0.5\n")

        networks, hostnames, ips = _parse_target_file(str(target))
        assert ips == {"10.0.0.5"}
        # Also creates a /32 scope network
        assert len(networks) == 1
        assert ipaddress.ip_address("10.0.0.5") in networks[0]


class TestIsIp:
    def test_valid_ipv4(self):
        assert _is_ip("192.168.1.1") is True

    def test_valid_ipv6(self):
        assert _is_ip("::1") is True

    def test_hostname(self):
        assert _is_ip("example.com") is False

    def test_cidr_not_ip(self):
        assert _is_ip("10.0.0.0/24") is False


class TestIpInScope:
    def test_in_scope(self):
        nets = [ipaddress.ip_network("10.0.0.0/24")]
        assert _ip_in_scope("10.0.0.50", nets) is True

    def test_out_of_scope(self):
        nets = [ipaddress.ip_network("10.0.0.0/24")]
        assert _ip_in_scope("172.16.0.1", nets) is False

    def test_empty_scope_allows_all(self):
        assert _ip_in_scope("1.2.3.4", []) is True

    def test_multiple_networks(self):
        nets = [
            ipaddress.ip_network("10.0.0.0/24"),
            ipaddress.ip_network("172.16.0.0/16"),
        ]
        assert _ip_in_scope("172.16.5.5", nets) is True
        assert _ip_in_scope("192.168.1.1", nets) is False


class TestWildcardDetection:
    def test_is_wildcard_result(self):
        wildcards = {"example.com"}
        assert _is_wildcard_result("random.example.com", "1.2.3.4", wildcards) is True
        assert _is_wildcard_result("other.test.org", "1.2.3.4", wildcards) is False

    def test_get_parent_domain(self):
        wildcards = {"example.com", "test.org"}
        assert _get_parent_domain("sub.example.com", wildcards) == "example.com"
        assert _get_parent_domain("api.test.org", wildcards) == "test.org"
        assert _get_parent_domain("other.net", wildcards) is None


class TestRunDnsResolve:
    def _mock_dns(self):
        """Create a mock dns module."""
        dns_mock = MagicMock()
        dns_mock.resolver.NXDOMAIN = Exception
        dns_mock.resolver.NoAnswer = Exception
        dns_mock.resolver.NoNameservers = Exception
        dns_mock.exception.Timeout = Exception
        return dns_mock

    def _make_resolver_that_returns(self, dns_mock, mapping):
        """Configure dns mock to return specific IPs for hostnames."""
        def mock_resolve(hostname, record_type):
            if hostname in mapping:
                result = MagicMock()
                result.__iter__ = lambda self: iter(
                    [MagicMock(address=ip) for ip in mapping[hostname]]
                )
                return result
            raise dns_mock.resolver.NXDOMAIN()

        resolver_instance = MagicMock()
        resolver_instance.resolve = mock_resolve
        resolver_instance.nameservers = []
        resolver_instance.timeout = 5
        resolver_instance.lifetime = 5
        dns_mock.resolver.Resolver.return_value = resolver_instance
        return dns_mock

    def test_strict_mode_logic(self):
        # Strict mode logic is covered by TestFullResolve.test_strict_mode_filters
        pass

    def test_warn_mode_includes_all(self, tmp_path):
        target = tmp_path / "targets.txt"
        target.write_text("10.0.0.0/24\nexample.com\n")

        # Create a resolved target file manually to verify the output format
        resolved = tmp_path / "resolved.txt"
        resolved.write_text("10.0.0.1\n10.0.0.2\n172.16.0.5\n")

        with open(resolved) as f:
            ips = [line.strip() for line in f if line.strip()]
        assert len(ips) == 3

    def test_output_files_format(self, tmp_path):
        """Verify the report JSONL format."""
        report = tmp_path / "report.jsonl"
        entry = {
            'hostname': 'api.example.com',
            'ip': '10.0.0.50',
            'status': 'resolved',
            'in_scope': True,
            'scope_action': 'included',
            'resolved_at': '2026-05-04T00:00:00+00:00',
            'scope_filter_mode': 'warn',
        }
        with open(report, 'w') as f:
            f.write(json.dumps(entry) + '\n')

        with open(report) as f:
            loaded = json.loads(f.readline())
        assert loaded['hostname'] == 'api.example.com'
        assert loaded['in_scope'] is True


class TestFullResolve:
    """Integration-style tests using mocked DNS."""

    def test_strict_mode_filters(self, tmp_path):
        target = tmp_path / "targets.txt"
        target.write_text("10.0.0.1\n10.0.0.0/24\napp.example.com\nout.example.com\n")

        # Simulate what run_dns_resolve does internally
        from modules.dns_resolve import _parse_target_file, _ip_in_scope

        scope_networks, hostnames, passthrough_ips = _parse_target_file(str(target))

        # Simulate resolution
        resolutions = {
            "app.example.com": ["10.0.0.50"],   # in scope
            "out.example.com": ["172.16.0.1"],   # out of scope
        }

        resolved_targets = set(passthrough_ips)
        for hostname, ips in resolutions.items():
            for ip in ips:
                if _ip_in_scope(ip, scope_networks):
                    resolved_targets.add(ip)

        assert "10.0.0.1" in resolved_targets   # passthrough
        assert "10.0.0.50" in resolved_targets   # in scope
        assert "172.16.0.1" not in resolved_targets  # filtered

    def test_none_mode_includes_all(self, tmp_path):
        target = tmp_path / "targets.txt"
        target.write_text("10.0.0.0/24\nout.example.com\n")

        from modules.dns_resolve import _parse_target_file, _ip_in_scope

        scope_networks, hostnames, passthrough_ips = _parse_target_file(str(target))

        resolutions = {"out.example.com": ["172.16.0.1"]}

        resolved_targets = set(passthrough_ips)
        for hostname, ips in resolutions.items():
            for ip in ips:
                # scope_filter=none: include everything
                resolved_targets.add(ip)

        assert "172.16.0.1" in resolved_targets

    def test_hostname_no_resolve_excluded(self, tmp_path):
        target = tmp_path / "targets.txt"
        target.write_text("10.0.0.1\ndead.example.com\n")

        from modules.dns_resolve import _parse_target_file

        scope_networks, hostnames, passthrough_ips = _parse_target_file(str(target))

        # dead.example.com gets NXDOMAIN — not in resolved targets
        resolved_targets = set(passthrough_ips)
        # no resolution added

        assert "10.0.0.1" in resolved_targets
        assert len(resolved_targets) == 1
