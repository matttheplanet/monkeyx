"""Step snapshots must record EXACTLY the input files a module was fed — the
port/IP/root-domain file a service module reads, not the target/url files it
ignores; and nothing at all for passive modules.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import workflows


def _snapshot(tmp_path, module, step=1, **files):
    """Create the given input files, snapshot, and return the resulting filenames."""
    kwargs = {}
    for key, name in files.items():
        p = tmp_path / name
        p.write_text("row\n")
        kwargs[key] = str(p)
    workflows._snapshot_module_inputs(str(tmp_path), step, module, kwargs)
    snapdir = tmp_path / "step-snapshots"
    return sorted(os.listdir(snapdir)) if snapdir.exists() else []


def test_snmp_sweep_snapshots_udp_ports_not_targets(tmp_path):
    files = _snapshot(tmp_path, "snmp_sweep",
                      udp_open_ports_file="ledger-open-ports-udp.host.txt",
                      target="ledger-targets.host.txt",
                      url_file="ledger-urls.txt")
    assert files == ["step-001-snmp_sweep-open-ports-udp.txt"]  # only its real input


def test_ssh_audit_snapshots_open_ports(tmp_path):
    files = _snapshot(tmp_path, "ssh_audit_scan",
                      open_ports_file="ledger-open-ports.host.txt",
                      target="ledger-targets.host.txt")
    assert files == ["step-001-ssh_audit_scan-open-ports.txt"]


def test_shodan_snapshots_target_ips(tmp_path):
    files = _snapshot(tmp_path, "shodan_enrich",
                      target_ips_file="ledger-target-ips.host.txt",
                      url_file="ledger-urls.txt")
    assert files == ["step-001-shodan_enrich-target-ips.txt"]


def test_passive_module_snapshots_nothing(tmp_path):
    files = _snapshot(tmp_path, "normalize",
                      target="ledger-targets.txt", url_file="ledger-urls.txt")
    assert files == []


def test_web_scanner_snapshots_the_url_file_it_was_handed(tmp_path):
    # A heavy web scanner is handed the (possibly pruned) URL file — that's what
    # the snapshot must capture, so it reflects the live subset when pruning is on.
    files = _snapshot(tmp_path, "ax_nuclei",
                      url_file="ledger-urls-live.txt",
                      target="ledger-targets.txt")
    assert "step-001-ax_nuclei-urls.txt" in files
