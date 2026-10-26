"""ax_nuclei scans web URLs AND -t-authorized IP:port endpoints in one pass.

After consolidating the former ax_nuclei_network into ax_nuclei, the single
module must build its target list from both url_file (name-safe web surface) and
open_ports_file (host-scoped IP:port service endpoints), and skip honestly when
neither is available.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import modules.ax_nuclei as axn


def _read(path):
    with open(path) as f:
        return [l.strip() for l in f if l.strip()]


def _patch(monkeypatch, prefix):
    monkeypatch.setattr(axn, "ax_local_config", lambda tool: "")
    # bash_command is patched to just create the declared output file.
    monkeypatch.setattr(axn, "bash_command",
                        lambda cmd: open(f"{prefix}-nuclei.jsonl", "w").close())


def test_scans_both_urls_and_ip_ports(tmp_path, monkeypatch):
    prefix = str(tmp_path / "out")
    url_file = tmp_path / "urls.txt"
    url_file.write_text("http://198.18.8.5:3000\nhttp://198.18.8.5:8080\n")
    ports = tmp_path / "open-ports.host.txt"
    ports.write_text("198.18.5.101\t22,6379\n198.18.2.195\t53\n")

    _patch(monkeypatch, prefix)
    result = axn.run_ax_nuclei(prefix=prefix, fleet="f", url_file=str(url_file),
                               data_prefix=prefix, open_ports_file=str(ports))
    assert result["status"] == "success"
    assert result["output_files"] == [f"{prefix}-nuclei.jsonl"]

    targets = _read(f"{prefix}-nuclei-targets.txt")
    assert "http://198.18.8.5:3000" in targets      # web URL
    assert "198.18.5.101:22" in targets             # IP:port service endpoint
    assert "198.18.5.101:6379" in targets
    assert "198.18.2.195:53" in targets


def test_ip_ports_only_no_urls(tmp_path, monkeypatch):
    # A -t-only run with open ports but no URLs still scans the endpoints.
    prefix = str(tmp_path / "out")
    ports = tmp_path / "open-ports.host.txt"
    ports.write_text("198.18.5.101\t22\n")
    _patch(monkeypatch, prefix)
    result = axn.run_ax_nuclei(prefix=prefix, fleet="f", url_file="/does/not/exist",
                               data_prefix=prefix, open_ports_file=str(ports))
    assert result["status"] == "success"
    assert _read(f"{prefix}-nuclei-targets.txt") == ["198.18.5.101:22"]


def test_skips_when_nothing_to_scan(tmp_path, monkeypatch):
    prefix = str(tmp_path / "out")
    _patch(monkeypatch, prefix)
    result = axn.run_ax_nuclei(prefix=prefix, fleet="f", url_file="/does/not/exist",
                               data_prefix=prefix)
    assert result["status"] == "skipped"
    assert result["output_files"] == []
