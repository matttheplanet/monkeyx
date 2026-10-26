"""Tests for core.target_ledger TargetLedger."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.target_ledger import (
    TargetLedger, NO_OP_LEDGER, _classify_target,
    TYPE_IP, TYPE_DOMAIN, TYPE_SUBDOMAIN, TYPE_URL,
    SCOPE_EXPLICIT, SCOPE_DERIVED,
)


def _read_entries(path):
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


class TestClassifyTarget:
    def test_ipv4(self):
        assert _classify_target("192.168.1.1") == TYPE_IP

    def test_cidr(self):
        assert _classify_target("10.0.0.0/24") == TYPE_IP

    def test_ipv6_colon(self):
        assert _classify_target("::1") == TYPE_IP

    def test_domain(self):
        assert _classify_target("example.com") == TYPE_DOMAIN

    def test_hostname(self):
        assert _classify_target("api.example.com") == TYPE_DOMAIN

    def test_high_octet_still_ip(self):
        assert _classify_target("255.255.255.0") == TYPE_IP

    def test_not_ip_if_octet_too_high(self):
        assert _classify_target("999.1.1.1") == TYPE_DOMAIN


class TestTargetLedger:
    def test_seed_targets_file(self, tmp_path):
        targets = tmp_path / "targets.txt"
        targets.write_text("10.0.0.1\n10.0.0.2\nexample.com\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(str(targets), None, None)

        entries = _read_entries(ledger.path)
        assert len(entries) == 3
        assert entries[0]["target"] == "10.0.0.1"
        assert entries[0]["type"] == TYPE_IP
        assert entries[0]["scope"] == SCOPE_EXPLICIT
        assert entries[0]["source"] == "user_input"
        assert entries[2]["target"] == "example.com"
        assert entries[2]["type"] == TYPE_DOMAIN

    def test_seed_domains_file(self, tmp_path):
        domains = tmp_path / "domains.txt"
        domains.write_text("example.com\ntest.org\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(None, str(domains), None)

        entries = _read_entries(ledger.path)
        assert len(entries) == 2
        assert all(e["type"] == TYPE_DOMAIN for e in entries)
        assert all(e["scope"] == SCOPE_EXPLICIT for e in entries)

    def test_seed_urls_file(self, tmp_path):
        urls = tmp_path / "urls.txt"
        urls.write_text("https://app.example.com\nhttp://api.test.org:8080\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(None, None, str(urls))

        entries = _read_entries(ledger.path)
        assert len(entries) == 2
        assert all(e["type"] == TYPE_URL for e in entries)
        assert all(e["scope"] == SCOPE_EXPLICIT for e in entries)

    def test_seed_skips_comments_and_empty(self, tmp_path):
        targets = tmp_path / "targets.txt"
        targets.write_text("# comment\n\n10.0.0.1\n\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(str(targets), None, None)

        entries = _read_entries(ledger.path)
        assert len(entries) == 1

    def test_log_discovery_deduplicates(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        ledger.log_discovery("10.0.0.5", TYPE_IP, "ax_tcp_baseline")
        ledger.log_discovery("10.0.0.5", TYPE_IP, "ax_tcp_full")

        entries = _read_entries(ledger.path)
        assert len(entries) == 1
        assert entries[0]["source"] == "ax_tcp_baseline"

    def test_same_target_different_type_not_deduped(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        ledger.log_discovery("example.com", TYPE_DOMAIN, "user_input")
        ledger.log_discovery("example.com", TYPE_SUBDOMAIN, "subfinder")

        entries = _read_entries(ledger.path)
        assert len(entries) == 2

    def test_derived_scope_for_discovered_ip(self, tmp_path):
        targets = tmp_path / "targets.txt"
        targets.write_text("10.0.0.1\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(str(targets), None, None)
        ledger.log_discovery("10.0.0.99", TYPE_IP, "ax_tcp_full")

        entries = _read_entries(ledger.path)
        assert entries[0]["scope"] == SCOPE_EXPLICIT
        assert entries[1]["scope"] == SCOPE_DERIVED

    def test_explicit_scope_for_known_ip(self, tmp_path):
        targets = tmp_path / "targets.txt"
        targets.write_text("10.0.0.1\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(str(targets), None, None)
        # If a module "rediscovers" a user-provided IP, it's deduplicated
        ledger.log_discovery("10.0.0.1", TYPE_IP, "ax_naabu")

        entries = _read_entries(ledger.path)
        assert len(entries) == 1  # deduped

    def test_subdomain_scope_with_parent_domain(self, tmp_path):
        domains = tmp_path / "domains.txt"
        domains.write_text("example.com\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(None, str(domains), None)
        ledger.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder")

        entries = _read_entries(ledger.path)
        sub = entries[1]
        assert sub["type"] == TYPE_SUBDOMAIN
        assert sub["scope"] == SCOPE_DERIVED
        assert sub["source"] == "subfinder"

    def test_log_discoveries_batch(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        discoveries = [
            ("10.0.0.1", TYPE_IP),
            ("10.0.0.2", TYPE_IP),
            ("https://10.0.0.1:443", TYPE_URL),
        ]
        ledger.log_discoveries(discoveries, "ax_tcp_baseline")

        entries = _read_entries(ledger.path)
        assert len(entries) == 3
        assert all(e["source"] == "ax_tcp_baseline" for e in entries)

    def test_parent_field(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        ledger.log_discovery("api.example.com", TYPE_SUBDOMAIN, "subfinder",
                             parent="example.com")

        entries = _read_entries(ledger.path)
        assert entries[0]["parent"] == "example.com"

    def test_noop_ledger_does_nothing(self, tmp_path):
        NO_OP_LEDGER.seed_user_inputs("fake", "fake", "fake")
        NO_OP_LEDGER.log_discovery("x", "ip", "test")
        NO_OP_LEDGER.log_discoveries([("x", "ip")], "test")
        # No exceptions, no files created

    def test_explicit_url_scope(self, tmp_path):
        urls = tmp_path / "urls.txt"
        urls.write_text("https://known.example.com\n")

        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs(None, None, str(urls))
        # New URL discovered by scanning
        ledger.log_discovery("https://new.example.com:8080", TYPE_URL, "ax_tcp_full")

        entries = _read_entries(ledger.path)
        assert entries[0]["scope"] == SCOPE_EXPLICIT
        assert entries[1]["scope"] == SCOPE_DERIVED

    def test_missing_file_no_error(self, tmp_path):
        ledger = TargetLedger(str(tmp_path))
        ledger.seed_user_inputs("/nonexistent/targets.txt", None, None)
        assert not os.path.exists(ledger.path)
