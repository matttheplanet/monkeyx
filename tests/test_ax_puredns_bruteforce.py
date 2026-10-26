"""Tests for modules.ax_puredns_bruteforce."""

import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.ax_puredns_bruteforce import run_ax_puredns_bruteforce


def test_uses_axiom_puredns_module_and_extracts_hosts(tmp_path):
    domainlist = tmp_path / "domains.txt"
    domainlist.write_text("example.com\n")
    prefix = str(tmp_path / "scan")
    output_file = tmp_path / "scan-puredns-bruteforce.txt"

    def fake_bash_command(command, timeout=None):
        assert "-m puredns-bruteforce" in command
        assert "-m puredns_bruteforce" not in command
        assert timeout == 1800   # 1 domain -> 30 min floor
        output_file.write_text("www.example.com\napi.example.com\nwww.example.com\n")

    with patch("modules.ax_puredns_bruteforce.bash_command", side_effect=fake_bash_command):
        result = run_ax_puredns_bruteforce(str(domainlist), prefix, "matt")

    assert result["status"] == "success"
    assert result["discovered_count"] == 2
    hosts_file = tmp_path / "scan-puredns-bruteforce-sorted.txt"
    assert result["discovered_hosts_file"] == str(hosts_file)
    assert hosts_file.read_text() == "api.example.com\nwww.example.com\n"


import subprocess
from modules.ax_puredns_bruteforce import _puredns_timeout


class TestPurednsTimeout:
    def test_floor_for_few_domains(self):
        assert _puredns_timeout(1) == 1800
        assert _puredns_timeout(10) == 1800        # 10*60=600 < 1800 floor

    def test_scales_with_domains(self):
        assert _puredns_timeout(60) == 3600         # 60*60
        assert _puredns_timeout(90) == 5400

    def test_capped_at_two_hours(self):
        assert _puredns_timeout(1000) == 7200       # cap

    def test_override_wins_and_zero_disables(self):
        assert _puredns_timeout(1000, override=600) == 600
        assert _puredns_timeout(1000, override=0) is None      # 0 => no timeout
        assert _puredns_timeout(5, override="bad") == 1800     # invalid -> default


def test_timeout_is_clean_failure_not_hang(tmp_path):
    domainlist = tmp_path / "domains.txt"
    domainlist.write_text("a.com\nb.com\n")
    prefix = str(tmp_path / "scan")

    def boom(command, timeout=None):
        raise subprocess.TimeoutExpired(command, timeout)

    with patch("modules.ax_puredns_bruteforce.bash_command", side_effect=boom):
        result = run_ax_puredns_bruteforce(str(domainlist), prefix, "matt")

    assert result["status"] == "failed"
    assert "timeout" in result["error"].lower() and "resolver" in result["error"].lower()
