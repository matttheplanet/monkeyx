"""Service Inventory rendering (deterministic, no AI).

The former LLM "service research" pass (version->CVE recall) was removed; the
report now carries a plain deterministic Service Inventory built from scan data:
service/version/port and a host count. No CVE column, no per-service CVE blocks.
The Hosts column is dropped when no service has host attribution.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.ai_analyze import _render_markdown


def _base_data(services):
    return {
        "metadata": {
            "generated_at": "2026-07-27T00:00:00+00:00", "ai_provider": "x",
            "ai_model": "m", "depth": "deep", "hosts_analyzed": 1, "hosts_total": 1,
            "services_analyzed": 1, "services_total": 1, "total_ports": 1,
            "total_findings": 0, "data_truncated": False,
        },
        "attack_paths": {"confirmed_vulnerabilities": [], "attack_chains": [],
                         "unconfirmed": [], "cve_research": []},
        "infrastructure_relationships": [],
        "service_inventory": services,
    }


def _render(data):
    out = tempfile.mktemp(suffix=".md")
    _render_markdown(data, out)
    with open(out) as fh:
        return fh.read()


def test_inventory_no_hosts_omits_hosts_column():
    data = _base_data([
        {"service": "OpenSSH", "version": "7.4", "port": 22, "hosts": []},
    ])
    md = _render(data)
    assert "## Service Inventory" in md
    # No host attribution anywhere -> Hosts column omitted
    assert "| Service | Version | Port |" in md
    assert "| OpenSSH | 7.4 | 22 |" in md
    # No CVE column in the deterministic inventory
    assert "CVEs" not in md


def test_inventory_hosts_column_returns_with_attribution():
    data = _base_data([
        {"service": "OpenSSH", "version": "7.4", "port": 22, "hosts": ["a.com", "b.com"]},
    ])
    md = _render(data)
    assert "| Service | Version | Port | Hosts |" in md
    assert "| OpenSSH | 7.4 | 22 | 2 |" in md


def test_inventory_empty_states_none():
    md = _render(_base_data([]))
    assert "*No services identified.*" in md
