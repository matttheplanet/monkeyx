"""Tests for the ai_validate per-command channel ceiling.

ai_validate runs both name-safe tools (curl/nuclei) and host-touching tools
(nmap/nc/snmp). The full in-scope set authorizes name-safe tools; host-touching
tools are additionally restricted to the -t-authorized host_scope.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.ai_validate import (
    _is_safe_command, _tool_is_host_touching, _parse_host_scope,
)

# Full in-scope set: a -t IP plus a -d host (name-safe only).
FULL_IPS = {"93.184.216.5"}
FULL_NETS = []
FULL_HOSTS = {"app.example.com", "web.example.com"}

# Host scope: only the -t IP is host-scannable (app.example.com is -d-only).
HOST_IPS = {"93.184.216.5"}
HOST_NETS = []
HOST_HOSTS = set()   # no -t hostnames
HOST_SCOPE = (HOST_IPS, HOST_NETS, HOST_HOSTS)


def test_tool_classification():
    assert _tool_is_host_touching("nmap_scan")
    assert _tool_is_host_touching("netcat_banner")
    assert _tool_is_host_touching("snmp_check")
    assert _tool_is_host_touching("testssl_check")
    assert not _tool_is_host_touching("curl_request")
    assert not _tool_is_host_touching("nuclei_scan")
    assert not _tool_is_host_touching("dig_lookup")


def test_unknown_tool_is_host_touching_failsafe():
    assert _tool_is_host_touching("some_new_tool")


def test_name_safe_tool_allowed_against_dl_host():
    """curl against a -d host is fine — it's addressed by Host/SNI."""
    argv = ["curl", "-sk", "-X", "GET", "https://app.example.com"]
    safe, reason = _is_safe_command(
        argv, FULL_IPS, FULL_NETS, FULL_HOSTS,
        tool_name="curl_request", host_scope=HOST_SCOPE)
    assert safe, reason


def test_host_tool_blocked_against_dl_host():
    """nmap against a -d-only host must be blocked — it would sweep the box."""
    argv = ["nmap", "--open", "-sV", "app.example.com"]
    safe, reason = _is_safe_command(
        argv, FULL_IPS, FULL_NETS, FULL_HOSTS,
        tool_name="nmap_scan", host_scope=HOST_SCOPE)
    assert not safe
    assert "host-scope" in reason


def test_host_tool_allowed_against_t_ip():
    """nmap against the -t IP is allowed."""
    argv = ["nmap", "--open", "-sV", "93.184.216.5"]
    safe, reason = _is_safe_command(
        argv, FULL_IPS, FULL_NETS, FULL_HOSTS,
        tool_name="nmap_scan", host_scope=HOST_SCOPE)
    assert safe, reason


def test_host_tool_blocked_when_no_host_scope():
    """Fail-safe: no host scope => host-touching tools blocked entirely."""
    argv = ["nmap", "--open", "-sV", "93.184.216.5"]
    safe, reason = _is_safe_command(
        argv, FULL_IPS, FULL_NETS, FULL_HOSTS,
        tool_name="nmap_scan", host_scope=(set(), [], set()))
    assert not safe
    assert "host-scope" in reason


def test_out_of_scope_still_blocked_first():
    """The existing full-scope check still applies before the channel gate."""
    argv = ["curl", "-sk", "https://evil.com"]
    safe, reason = _is_safe_command(
        argv, FULL_IPS, FULL_NETS, FULL_HOSTS,
        tool_name="curl_request", host_scope=HOST_SCOPE)
    assert not safe
    assert "out of scope" in reason


def test_backward_compatible_without_tool_name():
    """Legacy call (no tool_name) applies only the full-scope check."""
    argv = ["nmap", "--open", "93.184.216.5"]
    safe, reason = _is_safe_command(argv, FULL_IPS, FULL_NETS, FULL_HOSTS)
    assert safe, reason


def test_parse_host_scope_reads_host_files(tmp_path):
    data_dir = tmp_path
    ledger = data_dir / "ledger"
    ledger.mkdir()
    (ledger / "ledger-targets.host.txt").write_text("93.184.216.5\nhost.example.com\n")
    (ledger / "ledger-target-ips.host.txt").write_text("93.184.216.5\tapp.example.com\n")
    ips, nets, hosts = _parse_host_scope(str(data_dir / "scan"))
    assert "93.184.216.5" in ips
    assert "host.example.com" in hosts


def test_parse_host_scope_empty_when_absent(tmp_path):
    ips, nets, hosts = _parse_host_scope(str(tmp_path / "scan"))
    assert ips == set() and nets == [] and hosts == set()
