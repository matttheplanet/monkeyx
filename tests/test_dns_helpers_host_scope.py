"""Tests for the `host_scope` marker in dns_helpers resolve output.

`write_resolve_outputs` decides `in_scope` against the -t IP/CIDR ranges. With no
-t (domain-only run) there is no host scope to test, so every resolved IP is
reported in_scope — but only in the NAME-SAFE sense (in scope by the name that
resolved to it, NOT port-scannable). The `host_scope` field ("t-range" vs "none")
records which basis applied so the report isn't misread as a host-scope grant.
"""

import ipaddress
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import dns_helpers


def _records():
    return [{"host": "api.example.com", "a": ["203.0.113.9"]}]


def _read_report(prefix):
    path = f"{prefix}-resolve-report.jsonl"
    return [json.loads(l) for l in open(path) if l.strip()]


def test_host_scope_none_when_no_t_range(tmp_path):
    prefix = str(tmp_path / "out")
    dns_helpers.write_resolve_outputs(
        prefix, "dnsx_resolve", passthrough_ips=set(),
        dnsx_records=_records(), scope_networks=[], scope_filter="strict")
    resolved = _read_report(prefix)
    assert resolved, "expected at least one report entry"
    # No -t range -> name-safe basis; in_scope is cosmetically True but host_scope
    # tells the reader it is not a host-scan authorization.
    for e in resolved:
        assert e["host_scope"] == "none"
    only = [e for e in resolved if e["status"] == "resolved"][0]
    assert only["in_scope"] is True


def test_host_scope_t_range_when_t_supplied(tmp_path):
    prefix = str(tmp_path / "out")
    nets = [ipaddress.ip_network("203.0.113.0/24")]
    dns_helpers.write_resolve_outputs(
        prefix, "dnsx_resolve", passthrough_ips=set(),
        dnsx_records=_records(), scope_networks=nets, scope_filter="strict")
    resolved = [e for e in _read_report(prefix) if e["status"] == "resolved"]
    assert resolved and all(e["host_scope"] == "t-range" for e in resolved)
    # Inside the -t range -> genuinely in-scope.
    assert resolved[0]["in_scope"] is True


def test_host_scope_none_on_no_answer_and_ptr(tmp_path):
    prefix = str(tmp_path / "out")
    records = [{"host": "dead.example.com", "a": []}]   # no A record
    dns_helpers.write_resolve_outputs(
        prefix, "dnsx_resolve", passthrough_ips={"203.0.113.1"},
        dnsx_records=records, scope_networks=[], scope_filter="strict",
        ptr_map={"203.0.113.1": ["host1.example.com"]})
    entries = _read_report(prefix)
    # Every entry (no_answer + ptr) carries the name-safe basis.
    assert entries and all(e["host_scope"] == "none" for e in entries)
    assert any(e["status"] == "ptr" for e in entries)
    assert any(e["status"] == "no_answer" for e in entries)
