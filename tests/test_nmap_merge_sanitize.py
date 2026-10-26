"""Tests: nmap per-host XML is sanitized before merge, and a host lost in the
merge is reported (not silently dropped).

Regression: nmap -sV emits binary service banners (e.g. Samba) that land in the
per-host XML as numeric refs to illegal codepoints (`&#x2;`). That makes the file
non-well-formed, so axiom's nMap_Merger.py throws on it and drops the whole host
from the merged output — while ax_nmap_tcp still reports "success". The dropped
host's ports never reach the ledger, so every downstream module silently misses it.
"""

import os
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import core.scanning as scanning

_POISONED_HOST = (
    '<?xml version="1.0"?><nmaprun><host>'
    '<address addr="10.0.0.1" addrtype="ipv4"/>'
    '<ports><port portid="445" protocol="tcp"><state state="open"/>'
    '<service name="&#xc0;O&#xe5;&#x2;" product="Samba"/></port></ports>'
    '</host></nmaprun>'
)
_CLEAN_HOST = (
    '<?xml version="1.0"?><nmaprun><host>'
    '<address addr="10.0.0.2" addrtype="ipv4"/>'
    '<ports><port portid="80" protocol="tcp"><state state="open"/></port></ports>'
    '</host></nmaprun>'
)


def test_sanitize_removes_illegal_ref_keeps_legal():
    out = scanning._sanitize_xml_text('a&#x2;b&#xc0;c&#0;d')
    # &#x2; (STX) and &#0; (NUL) are illegal XML chars -> dropped; &#xc0; kept.
    assert out == 'ab&#xc0;cd'


def test_sanitize_removes_raw_control_bytes():
    assert scanning._sanitize_xml_text('a\x02b\x00c\td') == 'abc\td'  # keep tab


def test_poisoned_per_host_file_is_recovered(tmp_path):
    folder = tmp_path / "scan-tcpscan"
    folder.mkdir()
    p = folder / "10.0.0.1.xml"
    p.write_text(_POISONED_HOST, encoding="utf-8")
    # Before: not well-formed.
    try:
        ET.parse(str(p)); parsed_before = True
    except ET.ParseError:
        parsed_before = False
    assert not parsed_before
    fixed = scanning._sanitize_xml_files(str(folder))
    assert fixed == 1
    # After: parses, host + port intact.
    assert scanning._addrs_in_xml(str(p)) == {"10.0.0.1"}


def _write_folder(tmp_path):
    folder = tmp_path / "scan-tcpscan"
    folder.mkdir()
    (folder / "10.0.0.1.xml").write_text(_POISONED_HOST, encoding="utf-8")
    (folder / "10.0.0.2.xml").write_text(_CLEAN_HOST, encoding="utf-8")
    return folder


def test_merge_reports_dropped_host(tmp_path, monkeypatch):
    _write_folder(tmp_path)
    merged = str(tmp_path / "scan-tcpscan.xml")

    # Simulate a merger that only emits the clean host (drops 10.0.0.1).
    def fake_merge(cmd, *a, **k):
        with open(merged, "w", encoding="utf-8") as fh:
            fh.write(_CLEAN_HOST)
    monkeypatch.setattr(scanning, "bash_command", fake_merge)

    info = scanning.merge_nmap_folder(str(tmp_path / "scan"), "tcpscan", "TCP")
    assert info["dropped_hosts"] == ["10.0.0.1"]
    assert info["expected_hosts"] == 2 and info["merged_hosts"] == 1


def _write_merged(tmp_path, ips):
    p = tmp_path / "merged.xml"
    root = ET.Element("nmaprun")
    for ip in ips:
        h = ET.SubElement(root, "host")
        ET.SubElement(h, "status", state="up")
        ET.SubElement(h, "address", addr=ip, addrtype="ipv4")
    ET.ElementTree(root).write(str(p))
    return str(p)


def test_uncovered_flags_fed_ip_absent_from_results(tmp_path):
    tf = tmp_path / "targets.txt"
    tf.write_text("198.18.5.101\n198.18.8.5\n198.18.2.195\n")
    # Merge is missing 198.18.5.101 (the dropped-host scenario).
    merged = _write_merged(tmp_path, ["198.18.8.5", "198.18.2.195"])
    assert scanning.uncovered_ip_targets(str(tf), merged) == ["198.18.5.101"]


def test_uncovered_empty_when_all_present(tmp_path):
    tf = tmp_path / "targets.txt"
    tf.write_text("10.0.0.1\n10.0.0.2\n")
    merged = _write_merged(tmp_path, ["10.0.0.1", "10.0.0.2"])
    assert scanning.uncovered_ip_targets(str(tf), merged) == []


def test_uncovered_skips_hostnames_and_cidrs(tmp_path):
    # A scanned-but-no-open-ports host still emits a <host> record (so it's in
    # merged); hostnames/CIDRs are not reconciled and must not false-positive.
    tf = tmp_path / "targets.txt"
    tf.write_text("web.example.com\n10.0.0.0/24\n10.0.0.1\n")
    merged = _write_merged(tmp_path, ["10.0.0.1"])
    assert scanning.uncovered_ip_targets(str(tf), merged) == []


def test_uncovered_empty_without_target_file(tmp_path):
    merged = _write_merged(tmp_path, ["10.0.0.1"])
    assert scanning.uncovered_ip_targets(str(tmp_path / "nope.txt"), merged) == []


def test_merge_no_drop_when_all_present(tmp_path, monkeypatch):
    _write_folder(tmp_path)
    merged = str(tmp_path / "scan-tcpscan.xml")

    def fake_merge(cmd, *a, **k):
        # Emit both hosts (as a real merger would after sanitize).
        root = ET.Element("nmaprun")
        for ip in ("10.0.0.1", "10.0.0.2"):
            h = ET.SubElement(root, "host")
            ET.SubElement(h, "address", addr=ip, addrtype="ipv4")
        ET.ElementTree(root).write(merged)
    monkeypatch.setattr(scanning, "bash_command", fake_merge)

    info = scanning.merge_nmap_folder(str(tmp_path / "scan"), "tcpscan", "TCP")
    assert info["dropped_hosts"] == []
    assert info["merged_hosts"] == 2
