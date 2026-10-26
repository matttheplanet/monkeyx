"""Tests: the nmap modules judge success on OUTPUT PRESENCE, not ax's exit code.

ax scan can exit non-zero from a cosmetic cleanup step (`tput init` failing in a
non-TTY subprocess) even when the scan + result download fully succeeded. The
module must not discard a complete result on the exit code alone — it keeps the
output (status 'warning') if results landed, and only reports 'failed' when the
command errored AND nothing came back.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import modules.ax_nmap_tcp as tcp


def _patch(monkeypatch, *, scan_raises, write_output, prefix):
    """Wire the module's externals: bash_command (the scan), the merge, the parse."""
    def fake_bash(cmd, *a, **k):
        if scan_raises:
            raise Exception("exit status 2")  # simulate the tput-init exit leak

    def fake_merge(pfx, folder, title):
        if write_output:
            with open(f"{pfx}-{folder}.xml", "w") as fh:
                fh.write('<?xml version="1.0"?><nmaprun><host>'
                         '<address addr="10.0.0.1" addrtype="ipv4"/></host></nmaprun>')
        return {"merged_hosts": 1 if write_output else 0, "dropped_hosts": []}

    monkeypatch.setattr(tcp, "bash_command", fake_bash)
    monkeypatch.setattr(tcp, "merge_nmap_folder", fake_merge)
    monkeypatch.setattr(tcp, "nmap_to_tcphosts", lambda *a, **k: None)
    monkeypatch.setattr(tcp, "uncovered_ip_targets", lambda *a, **k: [])


def test_nonzero_exit_but_output_present_keeps_results(tmp_path, monkeypatch):
    prefix = str(tmp_path / "scan")
    _patch(monkeypatch, scan_raises=True, write_output=True, prefix=prefix)
    result = tcp.run_ax_nmap_tcp(target=str(tmp_path / "t.txt"), prefix=prefix, fleet="f")
    # Kept, not discarded: warning (not failed), and the XML is still an output.
    assert result["status"] == "warning"
    assert f"{prefix}-tcpscan.xml" in result["output_files"]
    assert "exited non-zero" in result["warning"]


def test_nonzero_exit_and_no_output_is_failed(tmp_path, monkeypatch):
    prefix = str(tmp_path / "scan")
    _patch(monkeypatch, scan_raises=True, write_output=False, prefix=prefix)
    result = tcp.run_ax_nmap_tcp(target=str(tmp_path / "t.txt"), prefix=prefix, fleet="f")
    # Command errored AND nothing landed -> a real failure.
    assert result["status"] == "failed"
    assert result["output_files"] == []


def test_clean_exit_with_output_is_success(tmp_path, monkeypatch):
    prefix = str(tmp_path / "scan")
    _patch(monkeypatch, scan_raises=False, write_output=True, prefix=prefix)
    result = tcp.run_ax_nmap_tcp(target=str(tmp_path / "t.txt"), prefix=prefix, fleet="f")
    assert result["status"] == "success"
