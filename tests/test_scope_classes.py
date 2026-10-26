"""Tests for the module scope classification registry.

The registry is a security boundary, so these tests assert two things:
  1. Every discoverable module is explicitly classified (no silent fall-through
     to the HOST default for a module we shipped).
  2. The dangerous-vs-safe assignments are what we intend (port scanners are
     HOST; web modules are NAME; a name-blind service probe is HOST).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from core import scope_classes as sc


def _discovered_module_names():
    import workflows
    return set(workflows.AVAILABLE_MODULES.keys())


def test_every_module_is_explicitly_classified():
    """No shipped module should rely on the fail-safe HOST default.

    The default exists to protect against a module someone forgets to classify,
    but everything in-tree must be a deliberate choice — otherwise a name-safe
    module silently becomes over-restrictive and a reviewer can't tell intent
    from accident.
    """
    known = (sc._HOST_MODULES | sc._NAME_MODULES | sc._PASSIVE_MODULES
             | sc._HOST_AGENT_MODULES | sc._DISCOVERY_HELPER_PHANTOMS)
    unclassified = sorted(m for m in _discovered_module_names() if m not in known)
    assert not unclassified, (
        "these discovered modules are not in the scope registry (they would "
        f"fall back to the HOST default): {unclassified}"
    )


def test_ai_validate_is_host_failsafe():
    """ai_validate runs an agent that can invoke nmap/netcat/etc., so whole-
    module gating must treat it as HOST — never name-safe."""
    assert sc.scope_class("ai_validate") == sc.SCOPE_HOST


def test_unknown_module_defaults_to_host():
    assert sc.scope_class("some_module_that_does_not_exist") == sc.SCOPE_HOST


def test_module_level_override_wins():
    class FakeMod:
        SCOPE_CLASS = "name"
    # Even a name we'd normally call HOST is overridden by the module attribute.
    assert sc.scope_class("ax_nmap_tcp", FakeMod) == sc.SCOPE_NAME


def test_invalid_override_ignored():
    class FakeMod:
        SCOPE_CLASS = "banana"
    assert sc.scope_class("ax_nmap_tcp", FakeMod) == sc.SCOPE_HOST


@pytest.mark.parametrize("module", [
    "ax_nmap_tcp", "ax_nmap_udp", "ax_masscan", "ax_naabu",
    "ssh_audit_scan", "snmp_sweep", "smtp_security", "shodan_enrich",
    "dns_resolve",
    # ax_nuclei scans raw IP:port service endpoints (name-blind) alongside web
    # URLs, so it is HOST-class (its url_file stays full; open_ports_file is -t-only).
    "ax_nuclei",
])
def test_host_modules(module):
    assert sc.scope_class(module) == sc.SCOPE_HOST


@pytest.mark.parametrize("module", [
    "ax_httpx", "ax_gowitness", "ax_katana", "ax_ffuf",
    "ax_feroxbuster", "ax_testssl", "ax_wafw00f", "ax_wpscan",
    "subfinder", "ax_subfinder", "ax_amass", "ax_puredns_bruteforce",
    "dnsx_resolve", "dns_security",
])
def test_name_modules(module):
    assert sc.scope_class(module) == sc.SCOPE_NAME


@pytest.mark.parametrize("module", [
    "normalize", "analyze", "ai_analyze", "focus", "html_report", "summary",
])
def test_passive_modules(module):
    assert sc.scope_class(module) == sc.SCOPE_PASSIVE


def test_name_blind_service_probes_are_host_not_name():
    """The core option-1 invariant: a hostname-fed but name-blind protocol
    (SSH/SNMP/raw SMTP) must be HOST, because on a shared IP it hits the box,
    not a name-routed tenant."""
    for m in ("ssh_audit_scan", "snmp_sweep", "smtp_security"):
        assert sc.scope_class(m) == sc.SCOPE_HOST


def test_enum_modules_are_name_class():
    for m in sc.ENUM_MODULES:
        assert sc.scope_class(m) == sc.SCOPE_NAME
        assert sc.is_enum_module(m)


def test_invasive_modules_flagged():
    assert sc.is_invasive_module("ax_dalfox")
    assert sc.is_invasive_module("bbot_dast")
    assert not sc.is_invasive_module("ax_httpx")
